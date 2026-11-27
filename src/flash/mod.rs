// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `sxprov flash`: installs GrapheneOS on
//! one phone with the official `flash-all.sh` of a verified factory image.
//! `sxprov` only prepares, selects the phone with `ANDROID_SERIAL`, watches
//! and checks; the flash sequence is the script's.
//!
//! Order, each step checked before the next:
//!
//! 1. one device with the serial in adb state `device`; the image's codename
//!    is the phone's; no delivery record (unless `--test-device`); no
//!    messenger set up by a customer
//! 2. what will happen, in plain words; typed `WIPE` (`--yes` only with
//!    `--test-device`)
//! 3. the image present and verified, otherwise fetched (`--dry-run` stops
//!    here and prints the plan)
//! 4. OEM unlocking on (adb UI automation, or the operator)
//! 5. `adb reboot bootloader`; the serial in fastboot; refused if more than
//!    one device is in fastboot mode
//! 6. `fastboot flashing unlock` if locked, confirmed on the phone
//! 7. the official script, unchanged, its output in a masked log
//! 8. `fastboot flashing lock`, confirmed on the phone
//! 9. the operator starts the phone, sets it up and allows USB debugging
//! 10. attestation as `verify`, the GrapheneOS key of this codename, the
//!     flashed version, bootloader locked; the `flashes` record

pub mod devopts;
mod resume;
pub mod standin;
mod steps;

#[cfg(test)]
mod tests;

use crate::activation::rng::{bytes, Rand};
use crate::activation::store::{Flash, Store};
use crate::config::Config;
use crate::deliver::phone::Phone;
use crate::deliver::{find_target, open_store, provider, Out, Ui};
use crate::device::{self, parse::Mode, Tools};
use crate::exit;
use crate::grapheneos::channel::Channels;
use crate::grapheneos::image::{self, top_folder, ImageCache};
use crate::grapheneos::status::{self, Installed};
use crate::grapheneos::{boot_key, valid_channel, valid_version, Http};
use crate::util::{fmt_unix, hex, mask_serial};
use crate::verify_run::{self, TrustMaterial};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub const MSG_UNLOCK: &str =
    "On the phone: press volume down to select Unlock the bootloader, then press power.";
pub const MSG_LOCK: &str =
    "On the phone: press volume down to select Lock the bootloader, then press power.";
pub const MSG_SETUP: &str = "On the phone: with Start selected in the bootloader menu, press power to start GrapheneOS. Complete the setup; on the last setup screen leave the preset switch as it is, so that OEM unlocking is turned off again. Then enable Developer options (Settings > About phone > tap Build number 7 times), turn on USB debugging (Settings > System > Developer options) and allow this computer when the phone asks.";

/// How often and how long to wait for the phone.
#[derive(Debug, Clone, Copy)]
pub struct Polls {
    pub interval: Duration,
    /// Polls until the serial shows in fastboot after `reboot bootloader`.
    pub fastboot_appear: u32,
    /// Polls until the unlock is confirmed on the phone.
    pub unlock: u32,
    pub lock: u32,
    /// Polls until the phone is set up and in adb state `device`.
    pub setup: u32,
    /// The time limit of the unlock and lock waits, in seconds (the config
    /// key `flash_confirm_timeout_secs`), and of the setup wait.
    pub confirm_secs: u64,
    pub setup_secs: u64,
    /// Every this many polls a `waiting_for_user` event with the time left.
    pub report_every: u32,
}

impl Polls {
    /// Polls every 2 seconds, a report every 30 seconds.
    pub fn real(confirm_secs: u64) -> Polls {
        let interval = 2u64;
        let confirm = confirm_secs.div_ceil(interval).max(1) as u32;
        Polls {
            interval: Duration::from_secs(interval),
            fastboot_appear: 90,
            unlock: confirm,
            lock: confirm,
            setup: 1800,
            confirm_secs,
            setup_secs: 3600,
            report_every: (30 / interval) as u32,
        }
    }

    /// Seconds left before poll `i` of `polls` in a wait of `total` seconds.
    pub fn left(total: u64, i: u32, polls: u32) -> u64 {
        if polls == 0 {
            return 0;
        }
        total.saturating_sub(total * i as u64 / polls as u64)
    }
}

pub struct FlashEnv<'a> {
    pub cfg: &'a Config,
    pub tools: Tools,
    pub ui: &'a mut dyn Ui,
    pub now: &'a dyn Fn() -> u64,
    pub challenge: &'a mut dyn FnMut() -> Result<Vec<u8>, String>,
    pub rng: &'a mut dyn Rand,
    pub sleep: &'a dyn Fn(Duration),
    pub trust: Option<&'a TrustMaterial>,
    pub stale_confirmed: bool,
    /// None: offline (cache only).
    pub http: Option<&'a dyn Http>,
    /// `allowed_signers` text for factory images (the pinned key).
    pub signers: &'a str,
    /// Codename to verified boot key hash (the pinned table).
    pub boot_keys: Vec<(String, String)>,
    /// WSL with the Windows `fastboot.exe`: the CRLF stand-in.
    pub standin: bool,
    pub polls: Polls,
    pub ui_retries: u32,
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Private directory for the `fastboot` tool folder.
    pub work_dir: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct FlashArgs {
    pub serial: String,
    pub channel: Option<String>,
    pub version: Option<String>,
    pub test_device: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
    /// Continue from a phone already in fastboot mode (`--resume`).
    pub resume: bool,
}

struct Failure {
    code: i32,
    step: u8,
    msg: String,
}

fn fail<T>(step: u8, code: i32, msg: impl Into<String>) -> Result<T, Failure> {
    Err(Failure {
        code,
        step,
        msg: msg.into(),
    })
}

/// Text lines, or one JSON object per line with `--json`.
struct Say<'o, 'w> {
    o: &'o mut Out<'w>,
    json: bool,
}

impl Say<'_, '_> {
    fn step(&mut self, n: u8, title: &str) {
        if self.json {
            self.o
                .line(json!({"event": "step", "step": n, "title": title}).to_string());
        } else {
            self.o.line(format!("step {n}: {title}"));
        }
    }
    fn info(&mut self, text: impl AsRef<str>) {
        if self.json {
            self.o
                .line(json!({"event": "info", "text": text.as_ref()}).to_string());
        } else {
            self.o.line(format!("  {}", text.as_ref()));
        }
    }
    /// An instruction for the operator, shown as it is.
    fn operator(&mut self, text: &str) {
        if self.json {
            self.o
                .line(json!({"event": "operator", "text": text}).to_string());
        } else {
            self.o.line(format!("\n>>> {text}\n"));
        }
    }
    fn event(&mut self, v: serde_json::Value) {
        if self.json {
            self.o.line(v.to_string());
        }
    }
    /// The operator is waiting: `action` names the manual step, `left` the
    /// seconds before the wait gives up.
    fn waiting(&mut self, action: &str, left: u64, text: &str) {
        if self.json {
            self.o.line(
                json!({"event": "waiting_for_user", "state": "waiting_for_user", "action": action,
                       "remaining_secs": left, "message": text})
                .to_string(),
            );
        } else {
            self.o.line(format!(
                "  waiting for you on the phone ({action}): {}m{:02}s left",
                left / 60,
                left % 60
            ));
        }
    }
}

pub fn flash(env: &mut FlashEnv, out: &mut dyn Write, a: &FlashArgs) -> i32 {
    let mut o = Out::new(out, &a.serial);
    let json = a.json;
    let mut say = Say { o: &mut o, json };
    if a.serial.is_empty() {
        say.info("flash needs --serial SERIAL");
        return exit::USAGE;
    }
    if a.yes && !a.test_device {
        say.info("--yes replaces the typed WIPE only together with --test-device");
        return exit::USAGE;
    }
    if a.resume && a.dry_run {
        say.info("--resume continues a flash; it cannot be combined with --dry-run");
        return exit::USAGE;
    }
    if let Some(v) = &a.version {
        if !valid_version(v) {
            say.info(format!(
                "--version must be ten digits (YYYYMMDDNN), got {v:?}"
            ));
            return exit::USAGE;
        }
    }
    let channel = a
        .channel
        .clone()
        .unwrap_or_else(|| env.cfg.grapheneos_channel.clone());
    if !valid_channel(&channel) {
        say.info(format!(
            "--channel must be stable, beta or alpha, got {channel:?}"
        ));
        return exit::USAGE;
    }
    if env.trust.is_none() && !a.dry_run {
        say.info("flash: no trust material loaded for the attestation after the flash");
        return exit::TRUST_MISSING;
    }
    let mut store = match open_store(env.cfg) {
        Ok(s) => s,
        Err((c, e)) => {
            say.info(format!("flash: {e}"));
            return c;
        }
    };
    let started = (env.now)();
    let mut rec = Flash {
        flash_id: bytes::<16>(env.rng).map(|b| hex(&b)).unwrap_or_default(),
        serial: a.serial.clone(),
        serial_masked: mask_serial(&a.serial),
        codename: String::new(),
        test_device: a.test_device,
        old_version: None,
        old_build_type: None,
        new_version: String::new(),
        new_build_type: String::new(),
        channel: channel.clone(),
        image_sha256: String::new(),
        verified_boot_key: None,
        attestation: None,
        started_at: fmt_unix(started),
        ended_at: None,
        result: "in progress".into(),
        failure: None,
        durations: BTreeMap::new(),
        resumed_at_step: None,
        sxprov_version: Some(crate::names::version_tag()),
    };
    let mut run = Run {
        env,
        a,
        say: &mut say,
        rec: &mut rec,
        store: &store,
        channel,
        reached: 0,
        unpacked: None,
        installed: None,
        unlocked_once: false,
    };
    let result = if a.resume { run.go_resume() } else { run.go() };
    let wiped = run.unlocked_once;
    let unpacked = run.unpacked.clone();
    drop(run);
    let now = (env.now)();
    rec.durations
        .insert("total".into(), now.saturating_sub(started));
    if a.dry_run {
        return match result {
            Ok(()) => exit::OK,
            Err(f) => {
                say.info(format!(
                    "flash --dry-run stopped at step {}: {}",
                    f.step, f.msg
                ));
                f.code
            }
        };
    }
    rec.ended_at = Some(fmt_unix(now));
    let code = match &result {
        Ok(()) => {
            rec.result = "flashed".into();
            exit::OK
        }
        Err(f) => {
            rec.result = format!("failed at step {}", f.step);
            rec.failure = Some(say.o.scrub(&f.msg));
            if json {
                say.event(json!({"event": "failed", "step": f.step, "message": f.msg}));
            } else {
                say.o
                    .line(format!("\nFLASH FAILED at step {}: {}", f.step, f.msg));
            }
            say.info(state_hint(f.step, wiped, unpacked.as_ref()));
            f.code
        }
    };
    store.data.flashes.push(rec.clone());
    if let Err(e) = store.save(env.rng) {
        say.info(format!(
            "flash: the record could not be saved: {e}. Note the flash by hand."
        ));
        return exit::STORE;
    }
    say.event(
        json!({"event": "record", "flash_id": rec.flash_id, "result": rec.result,
                     "version": rec.new_version, "build_type": rec.new_build_type,
                     "durations": rec.durations}),
    );
    if !json {
        say.o.line(format!(
            "flash record saved: {} result {}",
            rec.flash_id, rec.result
        ));
    }
    code
}

/// What state the phone is in after a failure at `step`, and what to do.
fn state_hint(step: u8, wiped: bool, unpacked: Option<&PathBuf>) -> String {
    let s = match step {
        1..=3 => "Nothing was changed on the phone.".to_string(),
        4 => "Nothing was changed on the phone except perhaps the OEM unlocking switch. Turn it on and run flash again.".into(),
        5 => "The phone may be in the bootloader, still locked, its data intact. To go back: fastboot -s <serial> reboot. Disconnect any other phone in fastboot mode and run flash again.".into(),
        6 => "The phone is in the bootloader and still LOCKED (data intact) unless the unlock was confirmed late. On the phone choose \"Do not unlock the bootloader\", or run flash again and confirm in time.".into(),
        7 => format!(
            "The phone is UNLOCKED and only partly flashed; its data is wiped. It is in the bootloader. Run the official script again by hand from {}: ANDROID_SERIAL=<serial> bash flash-all.sh (with fastboot in PATH), then fastboot -s <serial> flashing lock and confirm on the phone.",
            unpacked.map(|p| p.display().to_string()).unwrap_or_else(|| "the unpacked image".into())
        ),
        8 => "GrapheneOS is flashed but the bootloader is STILL UNLOCKED. Run fastboot -s <serial> flashing lock and confirm on the phone. Do not use the phone unlocked.".into(),
        9 => "GrapheneOS is flashed and the bootloader is locked. Finish the setup on the phone, allow USB debugging, then run sxprov verify --serial <serial>.".into(),
        _ => "GrapheneOS is flashed and locked, but the phone does not attest as this GrapheneOS build. Do not deliver it; check it with sxprov verify.".into(),
    };
    if wiped && step < 7 {
        format!("{s} (The bootloader unlock wiped the phone's data.)")
    } else {
        s
    }
}

struct Run<'e, 'a, 's, 'o, 'w> {
    env: &'e mut FlashEnv<'a>,
    a: &'e FlashArgs,
    say: &'s mut Say<'o, 'w>,
    rec: &'e mut Flash,
    store: &'e Store,
    channel: String,
    /// The last step that started.
    reached: u8,
    unpacked: Option<PathBuf>,
    installed: Option<Installed>,
    /// The bootloader unlock was confirmed (the phone's data is wiped).
    unlocked_once: bool,
}

impl Run<'_, '_, '_, '_, '_> {
    fn phone(&self) -> Phone<'_> {
        Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        }
    }

    fn start(&mut self, n: u8, title: &str) {
        self.reached = n;
        self.say.step(n, title);
    }

    fn time(&mut self, key: &str, since: u64) {
        let d = (self.env.now)().saturating_sub(since);
        self.rec.durations.insert(key.into(), d);
    }

    fn go(&mut self) -> Result<(), Failure> {
        let codename = self.step1()?;
        let (version, build_type) = self.target(&codename)?;
        self.rec.new_version = version.clone();
        self.rec.new_build_type = build_type.clone();
        self.step2(&codename, &version, &build_type)?;
        let v = self.step3(&codename, &version)?;
        self.rec.image_sha256 = v.sha256.clone();
        if self.a.dry_run {
            self.plan(&codename, &version);
            return Ok(());
        }
        self.step4()?;
        self.step5(&codename)?;
        self.step6()?;
        self.step7(&codename, &version)?;
        self.step8()?;
        let target = self.step9()?;
        self.step10(&codename, &version, target)
    }

    fn step1(&mut self) -> Result<String, Failure> {
        self.start(1, "device");
        let t = find_target(&self.env.tools, &self.a.serial)
            .or_else(|e| fail(1, exit::FLASH_REFUSED, e))?;
        let props = self
            .phone()
            .getprops()
            .or_else(|e| fail(1, exit::FLASH_REFUSED, e))?;
        let inst = Installed::from_props(&props);
        let Some(codename) = inst.codename.clone() else {
            return fail(1, exit::FLASH_REFUSED, "the phone reports no codename");
        };
        self.rec.codename = codename.clone();
        self.say.info(format!(
            "{} in state device: {} ({codename})",
            mask_serial(&t.serial),
            props.get("ro.product.model").cloned().unwrap_or_default()
        ));
        if boot_key(&self.env.boot_keys, &codename).is_none() {
            return fail(
                1,
                exit::FLASH_REFUSED,
                format!(
                    "no pinned GrapheneOS verified boot key for {codename}; flashing it is refused"
                ),
            );
        }
        let records = self
            .store
            .data
            .deliveries
            .iter()
            .filter(|d| d.serial == self.a.serial)
            .count();
        if records > 0 {
            if !self.a.test_device {
                return fail(
                    1,
                    exit::FLASH_REFUSED,
                    format!("this phone has {records} delivery record(s) in the admin store; flashing would wipe a delivered phone. Refused (a test phone needs --test-device)"),
                );
            }
            self.say.info(format!(
                "{records} delivery record(s) for this phone: flashed anyway (--test-device); the delivery is lost"
            ));
        }
        // Every installed messenger, whatever its package name: the packages
        // of this phone's delivery records, a fixed `messenger_package`, and
        // every app that offers the activation provider.
        let cfg = self.env.cfg;
        let mut known: Vec<String> = self
            .store
            .data
            .deliveries
            .iter()
            .filter(|d| d.serial == self.a.serial)
            .map(|d| d.messenger_package.clone())
            .collect();
        known.extend(cfg.fixed_messenger().map(str::to_string));
        let known: Vec<&str> = known.iter().map(String::as_str).collect();
        let found = crate::installed::messengers(&self.env.tools, &self.a.serial, cfg, &known)
            .or_else(|e| fail(1, exit::FLASH_REFUSED, e))?;
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        for pkg in &found {
            let st = p
                .provider_call(&cfg.provider_authority(pkg), "status", None)
                .and_then(|m| provider::status(&m))
                .or_else(|e| {
                    fail(
                        1,
                        exit::FLASH_REFUSED,
                        format!("{pkg} is installed but its state cannot be read ({e}); refusing, a customer's phone is never wiped"),
                    )
                })?;
            if st.setup_done {
                return fail(
                    1,
                    exit::FLASH_REFUSED,
                    format!("{pkg} reports setup=done: a customer's phone; never wiped"),
                );
            }
            self.say.info(format!("{pkg} installed, setup=open"));
        }
        self.rec.old_version = inst
            .looks_grapheneos()
            .then(|| inst.version.clone())
            .flatten();
        self.installed = Some(inst);
        Ok(codename)
    }
}
