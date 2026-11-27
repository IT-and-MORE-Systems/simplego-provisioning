// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `sxprov deliver`, `undeliver` and `handover`.
//!
//! A delivery turns a phone that runs GrapheneOS with a locked bootloader
//! into a delivered SimpleGo phone, each step checked before the next, and
//! records it in the encrypted admin store. Order, with the rule **no app
//! is installed before the network lock is active**, except the lock
//! itself:
//!
//! 1. exactly one device with the serial, in adb state `device`
//! 2. hardened tier: attestation as `verify` (OS PASS); normal tier: basic
//!    checks and a typed confirmation
//! 3. a messenger set up by a customer (`setup=done`) is never touched
//! 4. the APK files: package, version code, SHA-256, signer digest, and the
//!    `autoVerify` web hosts (app link verification)
//! 5. app link verification off: the verifier disabled (`applinks`)
//! 6. Orbot (optional): install, battery exception
//! 7. with the SimpleX app: the network lock (`lock`), Orbot's VPN for the
//!    apps already there, the always-on VPN with lockdown, proven before
//!    anything else is installed; without it: Orbot for SOCKS only
//! 8. the messenger: `adb install`, battery exception
//! 9. the F-Droid client and the normal SimpleX app, installed and not
//!    started (`simplex`, `appsteps`)
//! 10. the two apps added to the lock's VPN, the lock proven again
//! 11. the F-Droid client's first start, its SOCKS proxy, SimpleX's
//!     repository added
//! 12. activation file and code from the `issue` logic, then the transfer
//! 13. the system calculator hidden
//! 14. final check, with the installed signers read through the package
//!     manager (agent) and from the installed `base.apk`, the lock and the
//!     app link proof
//! 15. the fleet record
//!
//! The code reaches the phone only as the `--arg` of one `content call`. It
//! is shown once through `Ui::show_code`, never written to disk, never
//! logged; every other output line is scrubbed of it and of the full serial.

pub mod applinks;
mod appsteps;
pub mod lock;
pub mod orbot;
pub mod phone;
pub mod provider;
pub mod simplex;
pub mod undo;

#[cfg(test)]
mod tests;

use crate::activation::code::Code;
use crate::activation::directory::parse_directory_file;
use crate::activation::features::parse_features_file;
use crate::activation::issue::{self, parse_servers_file, parse_support_file, Request};
use crate::activation::keys::{is_test_key, KeyFile, Signer};
use crate::activation::payload::{is_valid_customer_ref, DeviceClass, NetworkMode};
use crate::activation::rng::{bytes, Rand};
use crate::activation::store::{self, Delivery, OrbotRecord, Store};
use crate::apk::{self, ApkInfo};
use crate::config::Config;
use crate::device::{self, parse::Listed, parse::Mode, Tools};
use crate::grapheneos::status::{self as os_status, Installed, OsStatus, Outcome};
use crate::grapheneos::Http;
use crate::util::{fmt_unix, hex, mask_serial};
use crate::verify_run::{self, TrustMaterial};
use crate::{exit, warning};
use phone::Phone;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// What the operator is asked. The terminal implementation reads without
/// echo; a test delivery reads the passphrase from a file. The admin store
/// asks for nothing: it opens with its store key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    SigningKeyPassphrase,
}

impl Secret {
    pub fn prompt(self) -> &'static str {
        match self {
            Secret::SigningKeyPassphrase => "passphrase of the activation signing key: ",
        }
    }
    /// The option that gives it from a file in a test run.
    pub fn test_flag(self) -> &'static str {
        match self {
            Secret::SigningKeyPassphrase => "--test-key-passphrase-file FILE",
        }
    }
}

pub trait Ui {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String>;
    /// A typed confirmation: true only if `word` is typed in full. Err if
    /// there is no terminal to ask.
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String>;
    /// The one place the activation code is shown.
    fn show_code(&mut self, code: &str);
}

pub struct Env<'a> {
    pub cfg: &'a Config,
    pub tools: Tools,
    pub ui: &'a mut dyn Ui,
    pub now: &'a dyn Fn() -> u64,
    pub challenge: &'a mut dyn FnMut() -> Result<Vec<u8>, String>,
    pub rng: &'a mut dyn Rand,
    pub sleep: &'a dyn Fn(Duration),
    /// Needed for the hardened tier; loaded by the caller.
    pub trust: Option<&'a TrustMaterial>,
    pub stale_confirmed: bool,
    /// Private directory for the pulled `base.apk` copies.
    pub work_dir: PathBuf,
    /// Seconds to wait for Orbot screens and the SOCKS listener.
    pub ui_retries: u32,
    /// The GrapheneOS status of the phone (channel files over Tor or cached).
    /// None: not looked up (the status line says so).
    pub os_status: Option<&'a dyn Fn(&Installed) -> OsStatus>,
    /// Downloads over Tor (SimpleX's repository). None: offline.
    pub http: Option<&'a dyn Http>,
}

#[derive(Debug, Clone, Default)]
pub struct DeliverArgs {
    pub serial: String,
    pub apk: PathBuf,
    pub customer_ref: String,
    pub network_mode: String,
    pub servers: PathBuf,
    pub support: PathBuf,
    pub key: PathBuf,
    pub orbot_apk: Option<PathBuf>,
    pub normal_tier: bool,
    pub dry_run: bool,
    pub reinstall: bool,
    pub accept_unverified_messenger: bool,
    pub test_delivery: bool,
    /// Deliver a phone more than `max_os_age_days` behind the stable channel.
    pub allow_outdated_os: bool,
    /// The F-Droid client APK: with it, the delivery installs the normal
    /// SimpleX app from SimpleX's repository and sets up Orbot's VPN.
    pub fdroid_apk: Option<PathBuf>,
    /// One JSON object per line instead of text.
    pub json: bool,
    /// `--features FILE` (format document section 12.1).
    pub features: Option<PathBuf>,
    /// `--directory FILE` (section 12.2).
    pub directory: Option<PathBuf>,
}

/// The refusal of section 12.4: nothing issued, the phone left as it is.
fn file_import_refusal(why: &str) -> String {
    format!(
        "{why}, but this messenger build cannot import the activation file (its status does not report {}=yes), and a code-only activation would not apply it. Nothing was issued: no file, no code, no fleet log entry. The phone is left with the network lock and the apps installed so far; undo it with `sxprov undeliver` (test phones) or as described in docs/USAGE.md before delivering again",
        phone::FILE_IMPORT_CAPABILITY
    )
}

#[derive(Debug)]
pub struct Failure {
    pub code: i32,
    /// The delivery step, for the record (`failed at step N`).
    pub step: u8,
    pub msg: String,
}

fn fail<T>(step: u8, code: i32, msg: impl Into<String>) -> Result<T, Failure> {
    Err(Failure {
        code,
        step,
        msg: msg.into(),
    })
}

/// Output with the full serial and the code removed from every line.
pub struct Out<'a> {
    w: &'a mut dyn Write,
    serial: String,
    masked: String,
    secrets: Vec<(Zeroizing<String>, String)>,
    /// `--json`: every line an event (`info` for plain text lines).
    pub json: bool,
}

impl<'a> Out<'a> {
    pub fn new(w: &'a mut dyn Write, serial: &str) -> Out<'a> {
        Out {
            w,
            serial: serial.to_string(),
            masked: mask_serial(serial),
            secrets: Vec::new(),
            json: false,
        }
    }
    pub fn hide(&mut self, secret: &str, shown_as: &str) {
        if !secret.is_empty() {
            self.secrets
                .push((Zeroizing::new(secret.to_string()), shown_as.to_string()));
        }
    }
    pub fn scrub(&self, s: &str) -> String {
        let mut s = if self.serial.is_empty() {
            s.to_string()
        } else {
            s.replace(&self.serial, &self.masked)
        };
        for (secret, shown) in &self.secrets {
            s = s.replace(secret.as_str(), shown);
        }
        s
    }
    pub fn line(&mut self, s: impl AsRef<str>) {
        let t = self.scrub(s.as_ref());
        if self.json {
            let t = t.trim();
            if !t.is_empty() {
                let _ = writeln!(self.w, "{}", json!({"event": "info", "text": t}));
            }
        } else {
            let _ = writeln!(self.w, "{t}");
        }
    }
    /// A JSON event (scrubbed); nothing in text mode.
    pub fn event(&mut self, v: serde_json::Value) {
        if self.json {
            let t = self.scrub(&v.to_string());
            let _ = writeln!(self.w, "{t}");
        }
    }
    /// The start of a step.
    pub fn step(&mut self, n: u8, title: &str) {
        self.step_in(n, title, None);
    }
    /// The start of a step that a console groups (`console_step`).
    pub fn step_in(&mut self, n: u8, title: &str, console: Option<&str>) {
        if self.json {
            let mut v = json!({"event": "step", "step": n, "state": "running", "title": title});
            if let Some(c) = console {
                v["console_step"] = json!(c);
            }
            self.event(v);
        } else {
            self.line(format!("step {n}: {title}"));
        }
    }
}

/// Store and signing key, opened before the first step of a real delivery
/// so that a wrong passphrase stops before anything is written.
pub struct Session {
    pub store: Store,
    pub signer: Signer,
}

pub fn store_path(cfg: &Config) -> Result<PathBuf, String> {
    match &cfg.admin_store_path {
        Some(p) => Ok(p.clone()),
        None => store::default_path()
            .ok_or_else(|| "HOME is not set; set admin_store_path in the config".into()),
    }
}

/// Takes the store lock, then opens the store with the store key next to
/// it; nothing is asked.
pub fn open_store(cfg: &Config) -> Result<Store, (i32, String)> {
    let path = store_path(cfg).map_err(|e| (exit::STORE, e))?;
    let lock = Store::lock_for_open(&path).map_err(|e| (exit::STORE, e.to_string()))?;
    Store::open_locked(lock, &crate::activation::storekey::Creds::system())
        .map(|(s, _)| s)
        .map_err(|e| (exit::STORE, e.to_string()))
}

/// The signing key rules of a delivery: a real delivery refuses the TEST
/// ONLY key; a test delivery needs the config switch and refuses every key
/// that is not the TEST ONLY key. The key must be passphrase protected.
pub fn read_key(cfg: &Config, path: &Path, test_delivery: bool) -> Result<KeyFile, (i32, String)> {
    let kf = KeyFile::read(path).map_err(|e| (exit::SIGNING_KEY, e))?;
    let test = is_test_key(&kf.public);
    if test_delivery {
        if !cfg.allow_test_key_for_test_deliveries {
            return Err((
                exit::SIGNING_KEY,
                "--test-delivery needs allow_test_key_for_test_deliveries = true in the config"
                    .into(),
            ));
        }
        if !test {
            return Err((
                exit::SIGNING_KEY,
                "--test-delivery is refused with a real signing key; it signs only with the TEST ONLY key".into(),
            ));
        }
    } else if test {
        return Err((
            exit::SIGNING_KEY,
            "refusing the TEST ONLY signing key for a real delivery (use --test-delivery on a test phone)".into(),
        ));
    }
    if !kf.is_encrypted() {
        return Err((
            exit::SIGNING_KEY,
            "the activation signing key must be passphrase protected (ssh-keygen -p)".into(),
        ));
    }
    Ok(kf)
}

fn now_str(env: &Env) -> String {
    fmt_unix((env.now)())
}

/// Step 1: exactly one listed device with this serial, in state `device`.
/// Other devices are ignored and never addressed.
pub fn find_target(tools: &Tools, serial: &str) -> Result<Listed, String> {
    let out = device::adb_devices(tools)?;
    let listed = device::parse::parse_adb_devices(&out);
    let m: Vec<&Listed> = listed.iter().filter(|d| d.serial == serial).collect();
    match m.as_slice() {
        [d] if d.mode == Mode::Adb => Ok((*d).clone()),
        [d] => Err(format!(
            "device {} is in state {}; it must be `device` (booted, unlocked, USB debugging authorised)",
            mask_serial(serial),
            d.mode.as_str()
        )),
        [] => Err(format!("no connected device has the serial {}", mask_serial(serial))),
        _ => Err(format!("the serial {} is listed more than once", mask_serial(serial))),
    }
}

struct Inputs {
    req: Request,
    network_mode: NetworkMode,
}

fn read_inputs(a: &DeliverArgs) -> Result<Inputs, (i32, String)> {
    if !is_valid_customer_ref(&a.customer_ref) {
        return Err((
            exit::USAGE,
            "customer reference: only A-Z a-z 0-9 -, 1 to 32 characters".into(),
        ));
    }
    let network_mode = NetworkMode::parse(&a.network_mode).map_err(|e| (exit::USAGE, e))?;
    let read = |p: &Path| {
        std::fs::read_to_string(p).map(Zeroizing::new).map_err(|e| {
            (
                exit::ACTIVATION_INPUT,
                format!("cannot read {}: {e}", p.display()),
            )
        })
    };
    let (smp, xftp) =
        parse_servers_file(&read(&a.servers)?).map_err(|e| (exit::ACTIVATION_INPUT, e))?;
    let support_address =
        parse_support_file(&read(&a.support)?).map_err(|e| (exit::ACTIVATION_INPUT, e))?;
    let req = Request {
        customer_ref: a.customer_ref.clone(),
        device_class: DeviceClass::Phone,
        network_mode,
        smp,
        xftp,
        support_address,
        serial: Some(a.serial.clone()),
        features: match &a.features {
            Some(p) => {
                Some(parse_features_file(&read(p)?).map_err(|e| (exit::ACTIVATION_INPUT, e))?)
            }
            None => None,
        },
        directory: match &a.directory {
            Some(p) => {
                Some(parse_directory_file(&read(p)?).map_err(|e| (exit::ACTIVATION_INPUT, e))?)
            }
            None => None,
        },
    };
    issue::precheck(&req, crate::activation::payload::Kind::Activation)
        .map_err(|e| (exit::ACTIVATION_INPUT, e))?;
    Ok(Inputs { req, network_mode })
}

fn new_record(env: &mut Env, a: &DeliverArgs, mode: NetworkMode, messenger: &str) -> Delivery {
    let id = bytes::<16>(env.rng).map(|b| hex(&b)).unwrap_or_default();
    Delivery {
        delivery_id: id,
        serial: a.serial.clone(),
        serial_masked: mask_serial(&a.serial),
        device_class: DeviceClass::Phone,
        tier: if a.normal_tier {
            "normal-phone tier".into()
        } else {
            "hardened".into()
        },
        test: a.test_delivery,
        model: None,
        os_build: None,
        security_patch: None,
        attestation: "not run".into(),
        messenger_package: messenger.to_string(),
        sxprov_version: Some(crate::names::version_tag()),
        messenger_version_code: None,
        messenger_version_name: None,
        messenger_apk_sha256: None,
        messenger_signer_sha256: None,
        messenger_verified: false,
        reinstall: a.reinstall,
        orbot: None,
        fdroid: None,
        simplex_app: None,
        simplex_repo: None,
        vpn: None,
        lock: None,
        app_links: None,
        os_status: None,
        file_id: None,
        network_mode: mode,
        file_transferred: false,
        features_profile: None,
        features_fixed: None,
        directory_role: None,
        code_masked: None,
        calculator_disabled: None,
        customer_ref: a.customer_ref.clone(),
        started_at: now_str(env),
        ended_at: None,
        result: "in progress".into(),
        failure: None,
        undone_at: None,
        handover_at: None,
    }
}

/// Runs a delivery. Every line goes to `out`, scrubbed. Returns the exit code.
pub fn deliver(env: &mut Env, out: &mut dyn Write, a: &DeliverArgs) -> i32 {
    let mut o = Out::new(out, &a.serial);
    o.json = a.json;
    deliver_inner(env, a, &mut o)
}

fn deliver_inner(env: &mut Env, a: &DeliverArgs, o: &mut Out) -> i32 {
    let inputs = match read_inputs(a) {
        Ok(i) => i,
        Err((c, e)) => {
            o.line(format!("deliver: {e}"));
            return c;
        }
    };
    if a.orbot_apk.is_some() && env.cfg.orbot_digest().is_none() {
        o.line(
            "deliver: --orbot-apk is refused: orbot_signing_cert_sha256 is not set in the config",
        );
        return exit::DELIVERY_APK;
    }
    if a.fdroid_apk.is_some() {
        let why = if a.orbot_apk.is_none() {
            Some("--fdroid-apk needs --orbot-apk: the SimpleX app reaches the network only through Orbot's VPN")
        } else if a.normal_tier {
            Some("--fdroid-apk is for GrapheneOS phones (the hardened tier); the four-app VPN names GrapheneOS apps")
        } else if env.cfg.fdroid_digest().is_none() {
            Some("--fdroid-apk is refused: fdroid_signing_cert_sha256 is not set in the config")
        } else if env.cfg.simplex_pins().is_none() {
            Some("--fdroid-apk is refused: simplex_app_signing_cert_sha256 and simplex_repo_fingerprint must be set")
        } else {
            None
        };
        if let Some(w) = why {
            o.line(format!("deliver: {w}"));
            return exit::DELIVERY_APK;
        }
    }
    if !a.normal_tier && env.trust.is_none() {
        o.line("deliver: no trust material loaded for the attestation");
        return exit::TRUST_MISSING;
    }
    // The messenger package of this delivery comes from its APK (one name
    // per delivery), checked against the config before anything else.
    let messenger = match messenger_of(env.cfg, &a.apk) {
        Ok(p) => p,
        Err(e) => {
            o.line(format!("deliver: {e}"));
            return exit::DELIVERY_APK;
        }
    };
    // The agent is installed in step 2, before the network lock: read its
    // app link hosts with the same reader before anything reaches the phone.
    let agent_links = match agent_link_check(env.cfg) {
        Ok(line) => line,
        Err(e) => {
            o.line(format!("deliver: {e}"));
            return exit::DELIVERY_APK;
        }
    };
    let mut session = None;
    if !a.dry_run {
        let kf = match read_key(env.cfg, &a.key, a.test_delivery) {
            Ok(k) => k,
            Err((c, e)) => {
                o.line(format!("deliver: {e}"));
                return c;
            }
        };
        let st = match open_store(env.cfg) {
            Ok(s) => s,
            Err((c, e)) => {
                o.line(format!("deliver: {e}"));
                return c;
            }
        };
        // Before the signing key passphrase: how --features changes the
        // customer's stored profile (section 12.1).
        for l in issue::features_change(&st.data, &inputs.req) {
            o.line(format!("feature profile change: {l}"));
        }
        let pass = match env.ui.secret(Secret::SigningKeyPassphrase) {
            Ok(p) => p,
            Err(e) => {
                o.line(format!("deliver: {e}"));
                return exit::SIGNING_KEY;
            }
        };
        let signer = match kf.unlock(Some(&pass)) {
            Ok(s) => s,
            Err(e) => {
                o.line(format!("deliver: {e}"));
                return exit::SIGNING_KEY;
            }
        };
        drop(pass);
        session = Some(Session { store: st, signer });
    }
    if a.test_delivery {
        o.line("TEST DELIVERY: signed with the TEST ONLY key, the activation code is the fixed lab code of test phones (shown once at the activation), the record is marked test");
    }
    let mut rec = new_record(env, a, inputs.network_mode, &messenger);
    let mut d = Delivery_ {
        env,
        a,
        o,
        rec: &mut rec,
        session: session.as_mut(),
        req: inputs.req,
        agent_links,
        apk: None,
        orbot: None,
        fdroid: None,
        sx: None,
        target: None,
        code_shown: false,
    };
    let result = d.run();
    let code_shown = d.code_shown;
    drop(d);
    if a.dry_run {
        return match result {
            Ok(()) => exit::OK,
            Err(f) => {
                o.event(json!({"event": "failed", "step": f.step, "message": f.msg}));
                o.line(format!(
                    "deliver --dry-run stopped at step {}: {}",
                    f.step, f.msg
                ));
                f.code
            }
        };
    }
    rec.ended_at = Some(now_str(env));
    let code = match &result {
        Ok(()) => {
            rec.result = "delivered".into();
            if rec.messenger_verified {
                exit::OK
            } else {
                exit::UNVERIFIED
            }
        }
        Err(f) => {
            rec.result = format!("failed at step {}", f.step);
            rec.failure = Some(o.scrub(&f.msg));
            o.event(
                json!({"event": "failed", "step": f.step, "state": "failed", "message": f.msg}),
            );
            o.line(format!("\nDELIVERY FAILED at step {}: {}", f.step, f.msg));
            o.line(undo_hint(f.step, &rec, code_shown));
            f.code
        }
    };
    let Some(s) = session.as_mut() else {
        return code;
    };
    s.store.data.deliveries.push(rec.clone());
    if let Err(e) = s.store.save(env.rng) {
        o.line(format!(
            "deliver: the fleet record could not be saved: {e}. Note the delivery by hand."
        ));
        return exit::STORE;
    }
    o.event(json!({"event": "record", "delivery_id": rec.delivery_id, "result": rec.result}));
    o.line(format!(
        "fleet record saved: delivery {} result {}",
        rec.delivery_id, rec.result
    ));
    code
}

/// The package of the messenger APK, if the config allows it
/// (`messenger_package`, `messenger_package_pattern`).
fn messenger_of(cfg: &Config, apk_path: &Path) -> Result<String, String> {
    let i = apk::inspect(apk_path).map_err(|e| format!("{}: {e}", apk_path.display()))?;
    cfg.check_messenger_package(&i.package)
        .map_err(|e| format!("{}: {e}", apk_path.display()))?;
    Ok(i.package)
}

/// The attestation agent's web link filters: it is installed
/// before the network lock (step 2), so it may declare no `autoVerify` web
/// host and no unresolved reference. Returns the line step 4 prints.
fn agent_link_check(cfg: &Config) -> Result<String, String> {
    let path = Path::new(&cfg.agent_apk);
    let i = apk::inspect(path).map_err(|e| format!("agent APK: {e}"))?;
    let (hosts, unresolved) = (i.auto_verify_hosts(), i.unresolved_links());
    if !hosts.is_empty() || !unresolved.is_empty() {
        return Err(format!(
            "the agent APK {} declares app link hosts or unresolved references ({}); it is installed before the network lock and is refused",
            path.display(),
            hosts
                .iter()
                .chain(unresolved.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(format!(
        "  agent {}: no autoVerify web hosts (read before step 2, where it is installed first)",
        i.package
    ))
}

fn undo_hint(step: u8, rec: &Delivery, code_shown: bool) -> String {
    let mut s = String::from("Done so far: ");
    s.push_str(match step {
        1..=4 => "nothing was written to the phone.",
        5 => "the app link verifier may be disabled; nothing was installed.",
        6 => "the app link verifier is disabled; Orbot may be partly installed.",
        7 => "only Orbot is installed; its VPN or the lockdown may be partly set up. No other app was installed.",
        8 => "Orbot is set up (with the network lock, if this delivery has one); the messenger install may have started.",
        9 => "Orbot and the messenger are installed; the F-Droid client and the SimpleX app may be partly installed.",
        10 => "the apps are installed; Orbot's app list may be partly changed.",
        11 => "the apps are installed and Orbot is set up; the F-Droid client may be partly set up.",
        12 => "the apps are installed and set up; the activation may not be set.",
        13 => {
            "the messenger is installed and activated; the system calculator may still be visible."
        }
        _ => "every write step ran; a final check failed.",
    });
    if step >= 5 {
        s.push_str(if rec.test {
            " On this test phone, run `sxprov undeliver --serial SERIAL --test-device` and deliver again."
        } else {
            " Do not hand the phone over. Remove the messenger (`adb uninstall`) and deliver again; see the section Delivery in docs/USAGE.md."
        });
    }
    if step >= 13 && code_shown {
        s.push_str(" The activation code shown above is set on the phone.");
    }
    s
}

/// The state of one delivery run.
struct Delivery_<'e, 'a, 'o, 'w> {
    env: &'e mut Env<'a>,
    a: &'e DeliverArgs,
    o: &'o mut Out<'w>,
    rec: &'e mut Delivery,
    session: Option<&'e mut Session>,
    req: Request,
    /// The agent's app link line, read before step 1.
    agent_links: String,
    apk: Option<ApkInfo>,
    orbot: Option<ApkInfo>,
    fdroid: Option<ApkInfo>,
    sx: Option<appsteps::SxPlan>,
    target: Option<Listed>,
    code_shown: bool,
}

impl Delivery_<'_, '_, '_, '_> {
    fn phone(&self) -> Phone<'_> {
        Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        }
    }

    /// The activation provider's authority of this delivery's messenger.
    fn authority(&self) -> String {
        self.env.cfg.provider_authority(&self.rec.messenger_package)
    }

    fn run(&mut self) -> Result<(), Failure> {
        self.step1_device()?;
        self.step2_tier()?;
        self.step3_customer_phone()?;
        self.step4_apks()?;
        if self.a.dry_run {
            self.print_plan();
            return Ok(());
        }
        self.step5_app_links()?;
        self.step6_orbot()?;
        self.step7_orbot_setup()?;
        self.step8_install()?;
        self.require_file_import(8)?;
        self.step9_apps()?;
        self.step10_lock_apps()?;
        self.step11_fdroid()?;
        self.step12_activation()?;
        self.step13_calculator()?;
        self.step14_final()?;
        Ok(())
    }

    fn step1_device(&mut self) -> Result<(), Failure> {
        self.o.step(1, "device");
        let t = find_target(&self.env.tools, &self.a.serial)
            .or_else(|e| fail(1, exit::DELIVERY_REFUSED, e))?;
        self.o.line(format!(
            "  {} in state device ({})",
            mask_serial(&t.serial),
            t.attrs.get("model").cloned().unwrap_or_default()
        ));
        self.target = Some(t);
        Ok(())
    }

    fn step2_tier(&mut self) -> Result<(), Failure> {
        let target = self.target.clone().expect("step 1 ran");
        if self.a.normal_tier {
            self.o.step(2, "normal-phone tier, basic checks only");
            let p = self.phone();
            let props = p
                .getprops()
                .or_else(|e| fail(2, exit::DELIVERY_REFUSED, e))?;
            let android = props
                .get("ro.build.version.release")
                .filter(|v| !v.is_empty())
                .cloned();
            let Some(android) = android else {
                return fail(
                    2,
                    exit::DELIVERY_REFUSED,
                    "the phone reports no Android version",
                );
            };
            p.packages(None).or_else(|e| {
                fail(
                    2,
                    exit::DELIVERY_REFUSED,
                    format!("package manager not reachable: {e}"),
                )
            })?;
            self.rec.model = props.get("ro.product.model").cloned();
            self.rec.os_build = props.get("ro.build.id").cloned();
            self.rec.security_patch = props.get("ro.build.version.security_patch").cloned();
            self.rec.attestation = "not run (normal-phone tier)".into();
            self.os_age(&Installed::from_props(&props))?;
            self.o
                .line(format!("  Android {android}, package manager reachable"));
            self.o.line(warning::NORMAL_TIER_WARNING);
            self.o.line(
                "Missing on this phone: no hardened OS, no bootloader lock, no attestation, Google services present.",
            );
            let ok = self
                .env
                .ui
                .confirm(
                    "NORMAL TIER",
                    "Type NORMAL TIER to deliver to this normal phone: ",
                )
                .or_else(|e| {
                    fail(
                        2,
                        exit::DELIVERY_REFUSED,
                        format!("normal tier needs a typed confirmation: {e}"),
                    )
                })?;
            if !ok {
                return fail(
                    2,
                    exit::DELIVERY_REFUSED,
                    "normal tier not confirmed; nothing was written",
                );
            }
            return Ok(());
        }
        self.o.step(
            2,
            "attestation (as `verify`; the agent is installed and removed again)",
        );
        let challenge = (self.env.challenge)().or_else(|e| fail(2, exit::DEVICE, e))?;
        let trust = self.env.trust.expect("checked before");
        let at = verify_run::attest(
            &self.env.tools,
            &target,
            self.env.cfg,
            trust,
            challenge,
            (self.env.now)(),
            self.env.stale_confirmed,
            None,
        )
        .or_else(|(c, e)| fail(2, c, e))?;
        for l in &at.log {
            self.o.line(format!("  agent: {l}"));
        }
        for c in &at.report.checks {
            self.o.line(format!("  [{}] {}", c.status.label(), c.title));
        }
        self.rec.model = at.info.model.clone();
        self.rec.os_build = at.info.build_id.clone();
        self.rec.security_patch = at.info.security_patch.clone();
        self.rec.attestation = at.report.overall_label.clone();
        self.o
            .line(format!("  RESULT: {}", at.report.overall_label));
        self.os_age(&at.info.os)?;
        if !at.os_pass() {
            let hint = if at.report.tier == crate::verify::Tier::NormalPhone {
                " (this is not a hardened phone; a normal phone needs --normal-tier)"
            } else {
                ""
            };
            return fail(
                2,
                exit::DELIVERY_REFUSED,
                format!(
                    "attestation did not give OS PASS: {}{hint}",
                    at.report.overall_label
                ),
            );
        }
        Ok(())
    }

    /// The GrapheneOS status lines and the age rule: refused when the phone
    /// is more than `max_os_age_days` behind the stable channel, unless
    /// `--allow-outdated-os`. An unknown status (offline, nothing cached)
    /// is shown, not refused.
    fn os_age(&mut self, inst: &Installed) -> Result<(), Failure> {
        let Some(f) = self.env.os_status else {
            self.o.line("  GrapheneOS status: not looked up");
            return Ok(());
        };
        let st = f(inst);
        let now = (self.env.now)();
        for l in os_status::lines(&st, now) {
            self.o.line(format!("  {l}"));
        }
        self.rec.os_status = Some(format!(
            "{} {}: {}",
            inst.version.as_deref().unwrap_or("?"),
            st.build_type_label,
            st.result
        ));
        let max = self.env.cfg.max_os_age_days;
        if st.outcome == Outcome::UpdateAvailable && st.days_behind_stable.unwrap_or(0) > max {
            if self.a.allow_outdated_os {
                self.o.line(format!(
                    "  WARNING: {} days behind the stable channel (max_os_age_days {max}); delivered anyway (--allow-outdated-os)",
                    st.days_behind_stable.unwrap_or(0)
                ));
            } else {
                return fail(
                    2,
                    exit::DELIVERY_REFUSED,
                    format!(
                        "the phone is {} days behind the stable channel (max_os_age_days {max}); update it (sxprov flash) or give --allow-outdated-os",
                        st.days_behind_stable.unwrap_or(0)
                    ),
                );
            }
        }
        Ok(())
    }

    fn step3_customer_phone(&mut self) -> Result<(), Failure> {
        self.o.step(3, "messenger state");
        let pkg = self.rec.messenger_package.clone();
        let cfg = self.env.cfg;
        // Every installed messenger counts, whatever its package name: the
        // apps that offer the activation provider, and this delivery's one.
        let found = crate::installed::messengers(&self.env.tools, &self.a.serial, cfg, &[&pkg])
            .or_else(|e| fail(3, exit::DELIVERY_REFUSED, e))?;
        if found.is_empty() {
            self.o.line(format!(
                "  {pkg} not installed, no other messenger installed"
            ));
            return Ok(());
        }
        let p = self.phone();
        for m in &found {
            let st = p
                .provider_call(&cfg.provider_authority(m), "status", None)
                .and_then(|x| provider::status(&x))
                .or_else(|e| {
                    fail(
                        3,
                        exit::DELIVERY_REFUSED,
                        format!("{m} is installed but its state cannot be read ({e}); refusing, a customer's installation is never touched"),
                    )
                })?;
            if st.setup_done {
                return fail(
                    3,
                    exit::DELIVERY_REFUSED,
                    format!("{m} is installed and set up by a customer (setup=done); refusing, nothing was written"),
                );
            }
            if *m != pkg {
                return fail(
                    3,
                    exit::DELIVERY_REFUSED,
                    format!("another messenger, {m}, is installed (setup=open); undeliver it first, refusing"),
                );
            }
        }
        if !self.a.reinstall {
            return fail(
                3,
                exit::DELIVERY_REFUSED,
                format!("{pkg} is already installed (setup=open); give --reinstall to replace it"),
            );
        }
        self.o.line(format!(
            "  {pkg} installed, setup=open: reinstall (--reinstall)"
        ));
        Ok(())
    }

    fn step4_apks(&mut self) -> Result<(), Failure> {
        self.o.step(4, "APK files");
        let line = self.agent_links.clone();
        self.o.line(line);
        let cfg = self.env.cfg;
        let path = self.a.apk.to_string_lossy().to_string();
        let i = apk::inspect(&self.a.apk).or_else(|e| fail(4, exit::DELIVERY_APK, e))?;
        if i.package != self.rec.messenger_package {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "{path}: package {} is not {}",
                    i.package, self.rec.messenger_package
                ),
            );
        }
        self.rec.messenger_version_code = Some(i.version_code);
        self.rec.messenger_version_name = i.version_name.clone();
        self.rec.messenger_apk_sha256 = Some(i.sha256.clone());
        self.rec.messenger_signer_sha256 = Some(i.signer_sha256.clone());
        self.o.line(format!(
            "  messenger {} versionCode {} ({}), {} bytes, SHA-256 {}",
            i.package,
            i.version_code,
            i.version_name.as_deref().unwrap_or("?"),
            i.size,
            i.sha256
        ));
        self.o.line(format!(
            "  signer ({}) SHA-256 {}",
            i.scheme, i.signer_sha256
        ));
        if let Some(w) = i.key_warning() {
            self.o.line(format!("  WARNING: {w}"));
        }
        match cfg.messenger_digest() {
            Some(want) => {
                if hex(&want) != i.signer_sha256 {
                    return fail(
                        4,
                        exit::DELIVERY_APK,
                        format!(
                            "the APK is signed by {}, not by the configured messenger signer {}",
                            i.signer_sha256,
                            hex(&want)
                        ),
                    );
                }
                self.rec.messenger_verified = true;
                self.o
                    .line("  signer matches messenger_signing_cert_sha256");
            }
            None => {
                if !self.a.accept_unverified_messenger {
                    return fail(
                        4,
                        exit::DELIVERY_APK,
                        "messenger_signing_cert_sha256 is not set (no release signing identity pinned yet); \
                         deliver only with --accept-unverified-messenger",
                    );
                }
                self.o.line("  messenger UNVERIFIED: no signer pinned (accepted with --accept-unverified-messenger)");
            }
        }
        self.step4_link_hosts(&i, "messenger")?;
        self.note_link_hosts(&i);
        self.apk = Some(i);
        if let Some(op) = &self.a.orbot_apk {
            let oi =
                apk::inspect(op).or_else(|e| fail(4, exit::DELIVERY_APK, format!("Orbot: {e}")))?;
            if oi.package != cfg.orbot_package {
                return fail(
                    4,
                    exit::DELIVERY_APK,
                    format!(
                        "Orbot APK: package {} is not {}",
                        oi.package, cfg.orbot_package
                    ),
                );
            }
            let want = cfg.orbot_digest().map(|d| hex(&d)).unwrap_or_default();
            if oi.signer_sha256 != want {
                return fail(
                    4,
                    exit::DELIVERY_APK,
                    format!(
                        "the Orbot APK is signed by {}, not by the configured Orbot signer {want}",
                        oi.signer_sha256
                    ),
                );
            }
            self.o.line(format!(
                "  Orbot {} versionCode {} ({}), SHA-256 {}, signer matches orbot_signing_cert_sha256",
                oi.package,
                oi.version_code,
                oi.version_name.as_deref().unwrap_or("?"),
                oi.sha256
            ));
            if let Some(w) = oi.key_warning() {
                self.o.line(format!("  WARNING: Orbot: {w}"));
            }
            // The lock provider is installed before the lock is on: it may
            // declare no app link host at all.
            let (hosts, unresolved) = (oi.auto_verify_hosts(), oi.unresolved_links());
            if self.vpn_mode() && (!hosts.is_empty() || !unresolved.is_empty()) {
                return fail(
                    4,
                    exit::DELIVERY_APK,
                    format!(
                        "the network lock provider Orbot declares app link hosts or unresolved references ({}); it is installed before the lock and is refused",
                        hosts.iter().chain(unresolved.iter()).cloned().collect::<Vec<_>>().join(", ")
                    ),
                );
            }
            self.step4_link_hosts(&oi, "Orbot")?;
            self.orbot = Some(oi);
        }
        self.step4_simplex()
    }

    fn print_plan(&mut self) {
        let cfg = self.env.cfg;
        let s = mask_serial(&self.a.serial);
        let pkg = &self.rec.messenger_package.clone();
        let uri = phone::activation_uri(&self.authority());
        let file_uri = phone::activation_file_uri(&self.authority());
        let r = if self.a.reinstall { "-r " } else { "" };
        let v = applinks::VERIFIER;
        let vpn = self.a.fdroid_apk.is_some();
        let mut l = vec![
            "DRY RUN: steps 1 to 4 ran read only; nothing below is sent, nothing is stored."
                .to_string(),
            "step 5 (app link verification off, before any install):".into(),
            format!("  adb -s {s} shell pm list packages; adb -s {s} shell pm list packages -d"),
            format!("  adb -s {s} shell pm disable-user --user 0 {v}; adb -s {s} shell pm list packages -d"),
        ];
        if let Some(op) = &self.a.orbot_apk {
            let opkg = &cfg.orbot_package;
            l.extend([
                "step 6 (Orbot):".to_string(),
                format!("  adb -s {s} shell pm list packages"),
                format!("  adb -s {s} install {r}{}", op.display()),
                format!("  adb -s {s} shell dumpsys package {opkg}"),
                format!("  adb -s {s} shell pm grant {opkg} android.permission.POST_NOTIFICATIONS"),
                format!("  adb -s {s} shell appops set {opkg} SCHEDULE_EXACT_ALARM allow; adb -s {s} shell appops get {opkg} SCHEDULE_EXACT_ALARM"),
                format!("  adb -s {s} shell dumpsys deviceidle whitelist +{opkg}; adb -s {s} shell dumpsys deviceidle whitelist"),
            ]);
            let flow = if vpn {
                orbot::FLOW_VPN_SETTINGS
            } else {
                orbot::FLOW
            };
            l.extend([
                if vpn {
                    "step 7 (the network lock, before any other app is installed: Orbot's VPN for the apps already there, lockdown, proven):".to_string()
                } else {
                    "step 7 (Orbot, SOCKS only):".to_string()
                },
                format!("  adb -s {s} shell appops get {opkg} ACTIVATE_VPN; settings get secure always_on_vpn_app and always_on_vpn_lockdown (as found)"),
                format!("  adb -s {s} shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER {opkg}"),
                format!("  adb -s {s} shell am start -n <launcher activity>"),
                format!(
                    "  UI steps ({} steps, each screen read with: uiautomator dump {d}, cat {d}, rm -f {d}; taps with input tap X Y):",
                    flow.len(),
                    d = orbot::DUMP_PATH
                ),
            ]);
            for st in flow {
                l.push(format!("    {}", describe_step(st)));
            }
            if vpn {
                let first: Vec<&str> = lock::first_apps()
                    .iter()
                    .filter_map(|p| simplex::label_of(p))
                    .collect();
                l.extend([
                    format!("    app list: exactly {} checked (search field, check boxes), others unchecked", first.join(", ")),
                    format!("  adb -s {s} shell appops set {opkg} ACTIVATE_VPN allow (the VPN consent, before Orbot starts: no dialog)"),
                ]);
                for st in orbot::FLOW_VPN_CONNECT {
                    l.push(format!("    {}", describe_step(st)));
                }
                l.extend([
                    format!("  adb -s {s} shell pm list packages -U; adb -s {s} shell dumpsys connectivity (the VPN carries exactly {})", first.join(", ")),
                    format!("  adb -s {s} shell am start -a android.settings.VPN_SETTINGS --activity-clear-task, then:"),
                ]);
                for st in simplex::LOCKDOWN_ON {
                    l.push(format!("    {}", describe_step(st)));
                }
                l.extend([
                    format!("  the lock proven: adb -s {s} shell settings get secure always_on_vpn_app; settings get secure always_on_vpn_lockdown"),
                    format!("  adb -s {s} shell dumpsys vpn_management (the newest mode change: lockdown=true alwaysOn=true)"),
                    format!("  adb -s {s} shell dumpsys connectivity (filtering rules: every app uid but Orbot's blocked; the VPN's uid list)"),
                    "  not proven: the delivery stops here, no other app is installed".into(),
                ]);
            }
            l.push(format!(
                "  adb -s {s} shell cat /proc/net/tcp; adb -s {s} shell cat /proc/net/tcp6 (until a listener on 127.0.0.1:{} shows)",
                orbot::SOCKS_PORT
            ));
        } else {
            l.push("steps 6 and 7: no --orbot-apk, Orbot skipped".into());
        }
        l.extend([
            "step 8 (the messenger):".to_string(),
            format!("  adb -s {s} install {r}{}", self.a.apk.display()),
            format!("  adb -s {s} shell pm list packages"),
            format!("  adb -s {s} shell dumpsys package {pkg}"),
            format!("  adb -s {s} shell dumpsys deviceidle whitelist +{pkg}"),
            format!("  adb -s {s} shell dumpsys deviceidle whitelist"),
        ]);
        if vpn {
            let f = &cfg.fdroid_package;
            let opkg = &cfg.orbot_package;
            let labels: Vec<&str> = appsteps::vpn_packages(cfg)
                .iter()
                .filter_map(|p| simplex::label_of(p))
                .collect();
            l.extend([
                "step 9 (F-Droid client and SimpleX app, not started):".to_string(),
                format!("  adb -s {s} install <F-Droid client APK>; adb -s {s} install -i {f} <SimpleX APK from the index>"),
                format!("  adb -s {s} shell dumpsys package {f}; adb -s {s} shell dumpsys package {} (versionCode, notLaunched, installer)", cfg.simplex_app_package),
                format!("  adb -s {s} shell dumpsys deviceidle whitelist +{f}; adb -s {s} shell dumpsys deviceidle whitelist +{}", cfg.simplex_app_package),
                "step 10 (the two apps added to the network lock's VPN):".into(),
                format!("  adb -s {s} shell am start -n <launcher activity of {opkg}>, then:"),
            ]);
            for st in orbot::FLOW_VPN_APPS_OPEN {
                l.push(format!("    {}", describe_step(st)));
            }
            l.push(format!(
                "    app list: exactly {} checked",
                labels.join(", ")
            ));
            for st in orbot::FLOW_VPN_APPS_CLOSE {
                l.push(format!("    {}", describe_step(st)));
            }
            l.push(format!("  the lock proven again (as in step 7, no newer mode change in adb -s {s} shell dumpsys vpn_management)"));
            l.push(format!("step 11 (F-Droid client, first start inside the VPN): adb -s {s} shell pm grant {f} android.permission.POST_NOTIFICATIONS; dumpsys package {f} (notLaunched); am start -n <launcher activity of {f}>, then:"));
            for st in simplex::FDROID_PROXY {
                l.push(format!("    {}", describe_step(st)));
            }
            l.push(format!(
                "  adb -s {s} shell am start -a android.intent.action.VIEW -d '{}' -n {f}/org.fdroid.MainActivity, then:",
                simplex::repo_intent_uri(&cfg.simplex_repo_url, &cfg.simplex_repo_fingerprint).unwrap_or_default()
            ));
            l.push(format!("    wait up to {} s (fdroid_repo_wait_secs) for SimpleX's repository on the Add repository screen and, after the tap, in the client; after {} s without it the intent once more; after \"Error connecting to the repository\": back key and the intent again, at most 3 tries", cfg.fdroid_repo_wait_secs, simplex::REPO_RESEND_AFTER_SECS));
            for st in simplex::FDROID_TAP_ADD {
                l.push(format!("    {}", describe_step(st)));
            }
        } else {
            l.push("steps 9 to 11: no --fdroid-apk, the SimpleX app skipped".into());
        }
        l.extend([
            "step 12:".to_string(),
            format!("  issue the activation file and code (customer {}, {}, signing key passphrase asked)", self.a.customer_ref, self.a.network_mode),
            format!("  adb -s {s} shell content call --uri {uri} --method status"),
            format!("  if status names {}=yes: adb -s {s} shell content write --uri {file_uri} < file (standard input)", phone::FILE_IMPORT_CAPABILITY),
            format!("  adb -s {s} shell content call --uri {uri} --method activate --arg <code, shown once, not here>"),
            format!("  adb -s {s} shell content call --uri {uri} --method status"),
            "step 13:".into(),
            format!("  adb -s {s} shell pm list packages"),
            format!("  adb -s {s} shell pm disable-user --user 0 {}", cfg.system_calculator_package),
            format!("  adb -s {s} shell pm list packages -d"),
            "step 14:".into(),
            format!("  adb -s {s} shell content call --uri {uri} --method status"),
            format!("  adb -s {s} shell dumpsys deviceidle whitelist"),
            format!("  adb -s {s} shell pm list packages -d"),
        ]);
        if !self.a.normal_tier {
            l.extend([
                format!("  attestation again as in step 2: adb -s {s} shell getprop"),
                format!("  agent: adb -s {s} install -r <agent>, am instrument ..., adb -s {s} uninstall {}", cfg.agent_package),
            ]);
        }
        l.extend([
            format!("  the messenger's signer: adb -s {s} shell pm path {pkg}; adb -s {s} pull <base.apk> <private temporary file>; adb -s {s} shell dumpsys package {pkg} (signature and versionCode)"),
        ]);
        if self.a.orbot_apk.is_some() {
            l.push(format!("  adb -s {s} shell pm path {}; adb -s {s} pull <base.apk> <private temporary file>", cfg.orbot_package));
        }
        if vpn {
            l.extend([
                "  F-Droid client and SimpleX app: the signer through the package manager (dumpsys package) and the pulled base.apk".to_string(),
                format!("  adb -s {s} shell pm path {}; adb -s {s} pull <base.apk> <private temporary file>", cfg.fdroid_package),
                format!("  adb -s {s} shell pm path {}; adb -s {s} pull <base.apk> <private temporary file>", cfg.simplex_app_package),
                format!("  adb -s {s} shell dumpsys package {} (stopped, notLaunched, installer); the lock proven again (settings, dumpsys vpn_management, dumpsys connectivity, /proc/net/tcp and tcp6)", cfg.simplex_app_package),
                format!("  adb -s {s} shell am start -S -n <launcher activity of {}> (not a Calculator alias), then the repository list and SimpleX's fingerprint on the screen (reads as above):", cfg.fdroid_package),
            ]);
            for st in simplex::FDROID_REPO_LISTED {
                l.push(format!("    {}", describe_step(st)));
            }
        }
        l.extend([
            format!("  app links: adb -s {s} shell pm get-app-links --user 0 <each installed app with autoVerify hosts> (no host verified or approved)"),
            format!("  adb -s {s} shell pm list packages -U; adb -s {s} shell cat /proc/net/tcp and /proc/net/tcp6 ({v}: no socket outside loopback)"),
            format!("  adb -s {s} shell dumpsys jobscheduler {v} (read only, for the record); adb -s {s} shell pm list packages -d ({v} still disabled)"),
            "step 15: fleet record in the admin store".into(),
        ]);
        // The dry run reads no store: only --features and --directory.
        match self.file_import_needed() {
            Some(why) => l.push(format!(
                "file import: {why}. It needs a messenger that reports {}=yes in status; that is unknown until the messenger is installed. Without it the delivery stops after step 8 (and again at step 12) with nothing issued. A stored profile of the customer is not read in a dry run.",
                phone::FILE_IMPORT_CAPABILITY
            )),
            None => l.push("file import: --features fixes no switch and there is no --directory; a stored profile of the customer is not read in a dry run and is checked after step 8 of the delivery".into()),
        }
        for x in l {
            self.o.line(x);
        }
    }

    /// Why this delivery needs the file import (section 12.4): a feature
    /// profile that fixes a switch, or a directory entry. A real delivery
    /// takes the profile from `--features` or the store, a dry run only
    /// from `--features`.
    fn file_import_needed(&self) -> Option<String> {
        let features = match self.session.as_ref() {
            Some(s) => issue::features_for(&s.store.data, &self.req),
            None => self.req.features.clone(),
        };
        let mut why = Vec::new();
        if let Some(f) = features.filter(|f| f.fixes_any()) {
            why.push(format!(
                "customer {}'s feature profile fixes {}",
                self.req.customer_ref,
                f.fixed()
            ));
        }
        if let Some(d) = &self.req.directory {
            why.push(format!(
                "this phone has a directory entry (role {}, {} group(s))",
                d.role.as_str(),
                d.groups.len()
            ));
        }
        (!why.is_empty()).then(|| why.join(" and "))
    }

    /// After step 8 (the messenger answers `status` once installed) and
    /// again in step 12: a delivery that needs the file import stops when
    /// the messenger does not report it, before anything is issued.
    fn require_file_import(&mut self, step: u8) -> Result<(), Failure> {
        let Some(why) = self.file_import_needed() else {
            return Ok(());
        };
        let auth = self.authority();
        let p = self.phone();
        let st = p
            .provider_call(&auth, "status", None)
            .and_then(|m| provider::status(&m))
            .or_else(|e| fail(step, exit::DELIVERY_FAILED, e))?;
        if !st.file_import {
            return fail(step, exit::DELIVERY_FAILED, file_import_refusal(&why));
        }
        self.o.line(format!(
            "  file import: {why}; the messenger reports {}=yes",
            phone::FILE_IMPORT_CAPABILITY
        ));
        Ok(())
    }

    fn step8_install(&mut self) -> Result<(), Failure> {
        self.o.step(8, "messenger install");
        self.require_lock(8)?;
        let pkg = self.rec.messenger_package.clone();
        let want = self.apk.clone().expect("step 4 ran");
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        p.install(&self.a.apk.to_string_lossy(), self.a.reinstall)
            .or_else(|e| fail(8, exit::DELIVERY_FAILED, e))?;
        if !p
            .installed(&pkg)
            .or_else(|e| fail(8, exit::DELIVERY_FAILED, e))?
        {
            return fail(
                8,
                exit::DELIVERY_FAILED,
                format!("{pkg} is not listed after the install"),
            );
        }
        let info = p
            .package_info(&pkg)
            .or_else(|e| fail(8, exit::DELIVERY_FAILED, e))?
            .unwrap_or_default();
        if info.version_code != Some(want.version_code) {
            return fail(
                8,
                exit::DELIVERY_FAILED,
                format!(
                    "installed versionCode {:?} differs from the APK's {}",
                    info.version_code, want.version_code
                ),
            );
        }
        self.o.line(format!(
            "  {pkg} installed, versionCode {}",
            want.version_code
        ));
        p.whitelist_add(&pkg)
            .or_else(|e| fail(8, exit::DELIVERY_FAILED, e))?;
        if !p
            .whitelisted(&pkg)
            .or_else(|e| fail(8, exit::DELIVERY_FAILED, e))?
        {
            return fail(
                8,
                exit::DELIVERY_FAILED,
                "battery exception not listed after setting it",
            );
        }
        self.o
            .line("  battery exception set (deviceidle whitelist)");
        Ok(())
    }

    fn step6_orbot(&mut self) -> Result<(), Failure> {
        let Some(oi) = self.orbot.clone() else {
            self.o.step(6, "Orbot not given, skipped");
            return Ok(());
        };
        self.o.step_in(6, "Orbot install", Some(lock::CONSOLE_STEP));
        let opkg = self.env.cfg.orbot_package.clone();
        let op = self.a.orbot_apk.clone().expect("orbot given");
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let before = p
            .installed(&opkg)
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, e))?;
        if before && !self.a.reinstall {
            return fail(
                6,
                exit::DELIVERY_FAILED,
                format!("{opkg} is already installed on this phone; remove it or give --reinstall"),
            );
        }
        p.install(&op.to_string_lossy(), before)
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, format!("Orbot: {e}")))?;
        let rec = OrbotRecord {
            package: opkg.clone(),
            version_code: oi.version_code,
            version_name: oi.version_name.clone(),
            apk_sha256: oi.sha256.clone(),
            signer_sha256: oi.signer_sha256.clone(),
            installed_by_delivery: !before,
            socks_listening: false,
            found_switches: Vec::new(),
            found_vpn_apps: Vec::new(),
        };
        self.rec.orbot = Some(rec);
        let info = p
            .package_info(&opkg)
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, e))?
            .unwrap_or_default();
        if info.version_code != Some(oi.version_code) {
            return fail(
                6,
                exit::DELIVERY_FAILED,
                "installed Orbot versionCode differs from the APK's",
            );
        }
        self.o.line(format!(
            "  {opkg} installed, versionCode {}",
            oi.version_code
        ));
        // No dialog for the notification permission (Android 13 and later).
        if let Err(e) = p.shell(&[
            "pm",
            "grant",
            &opkg,
            "android.permission.POST_NOTIFICATIONS",
        ]) {
            self.o
                .line(format!("  note: notification permission not granted: {e}"));
        }
        // Power User Mode (SOCKS without VPN) needs exact alarms and asks to
        // leave battery optimisation; both are set here, so no dialog shows.
        p.appops_allow(&opkg, "SCHEDULE_EXACT_ALARM")
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, format!("Orbot: {e}")))?;
        self.o
            .line("  Orbot: exact alarms allowed (app op SCHEDULE_EXACT_ALARM)");
        p.whitelist_add(&opkg)
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, e))?;
        if !p
            .whitelisted(&opkg)
            .or_else(|e| fail(6, exit::DELIVERY_FAILED, e))?
        {
            return fail(
                6,
                exit::DELIVERY_FAILED,
                format!("{opkg} is not listed in the deviceidle whitelist"),
            );
        }
        self.o
            .line("  Orbot: battery exception set (deviceidle whitelist)");
        Ok(())
    }

    fn step7_orbot_setup(&mut self) -> Result<(), Failure> {
        if self.orbot.is_none() {
            self.o.step(7, "Orbot not given, skipped");
            return Ok(());
        }
        if self.vpn_mode() {
            return self.step7_lock();
        }
        self.o.step(7, "Orbot set-up (SOCKS only, never VPN mode)");
        let opkg = self.env.cfg.orbot_package.clone();
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        orbot::launch(&p, &opkg).or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        let mut log = Vec::new();
        let sleep = self.env.sleep;
        let retries = self.env.ui_retries;
        {
            let mut ui = orbot::Ui {
                phone: &p,
                sleep,
                retries,
                log: &mut log,
                what: "Orbot set-up",
                found: Vec::new(),
            };
            let r = ui.run(orbot::FLOW);
            for l in &log {
                self.o.line(format!("  orbot: {l}"));
            }
            r.or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        }
        let mut seen = false;
        let mut read_error = None;
        for i in 0..=retries {
            let (v4, v6) = (
                p.shell(&["cat", "/proc/net/tcp"]),
                p.shell(&["cat", "/proc/net/tcp6"]),
            );
            if let (Err(e), Err(_)) = (&v4, &v6) {
                read_error = Some(e.clone());
            }
            let (v4, v6) = (v4.unwrap_or_default(), v6.unwrap_or_default());
            if orbot::listening(&v4, orbot::SOCKS_PORT) || orbot::listening(&v6, orbot::SOCKS_PORT)
            {
                seen = true;
                break;
            }
            if i < retries {
                (self.env.sleep)(Duration::from_secs(1));
            }
        }
        if !seen {
            return fail(
                7,
                exit::DELIVERY_FAILED,
                match read_error {
                    Some(e) => format!("Orbot: /proc/net/tcp cannot be read on the phone: {e}"),
                    None => format!(
                        "Orbot: no listener on 127.0.0.1:{} after connecting",
                        orbot::SOCKS_PORT
                    ),
                },
            );
        }
        if let Some(r) = self.rec.orbot.as_mut() {
            r.socks_listening = true;
        }
        self.o.line(format!(
            "  Orbot connected: listener on 127.0.0.1:{}",
            orbot::SOCKS_PORT
        ));
        Ok(())
    }

    fn step12_activation(&mut self) -> Result<(), Failure> {
        self.o.step(12, "activation");
        let auth = self.authority();
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let st = p
            .provider_call(&auth, "status", None)
            .and_then(|m| provider::status(&m))
            .or_else(|e| fail(12, exit::DELIVERY_FAILED, e))?;
        if st.setup_done {
            return fail(
                12,
                exit::DELIVERY_FAILED,
                "the provider reports setup=done; refusing",
            );
        }
        if !st.file_import {
            if let Some(why) = self.file_import_needed() {
                return fail(12, exit::DELIVERY_FAILED, file_import_refusal(&why));
            }
        }
        let s = self.session.as_mut().expect("real delivery has a session");
        let now = fmt_unix((self.env.now)());
        let issued = if self.a.test_delivery {
            issue::activation_test_delivery(
                &mut s.store.data,
                &self.req,
                &s.signer,
                self.env.rng,
                &now,
            )
        } else {
            issue::activation(&mut s.store.data, &self.req, &s.signer, self.env.rng, &now)
        }
        .or_else(|e| fail(12, exit::DELIVERY_FAILED, e))?;
        let code: &Code = issued.code.as_ref().expect("activation has a code");
        let canon = Zeroizing::new(String::from_utf8_lossy(code.canonical()).to_string());
        let display = code.display();
        let masked = code.masked();
        self.o.hide(&canon, &masked);
        self.o.hide(&display, &masked);
        self.rec.file_id = Some(issued.issue.file_id.clone());
        self.rec.code_masked = Some(masked.clone());
        self.rec.features_profile = issued.issue.features_profile.clone();
        self.rec.features_fixed = issued.issue.features_fixed.clone();
        self.rec.directory_role = issued.issue.directory_role;
        if let Some(fp) = &issued.issue.features_profile {
            self.o.line(format!(
                "  features_profile {fp}, features_fixed {}",
                issued.issue.features_fixed.as_deref().unwrap_or("")
            ));
        }
        if let Some(r) = issued.issue.directory_role {
            self.o.line(format!(
                "  directory: role {} (no names or links are stored)",
                r.as_str()
            ));
        }
        self.o.line(format!(
            "  issued: file_id {}, customer {}, {}, sequence {}, key_id {}, recorded in the store",
            issued.issue.file_id,
            issued.issue.customer_ref,
            issued.issue.network_mode.as_str(),
            issued.issue.sequence,
            issued.issue.key_id
        ));
        if st.file_import {
            p.provider_write_file(&auth, &issued.file)
                .or_else(|e| fail(12, exit::DELIVERY_FAILED, e))?;
            self.o.line(format!(
                "  file sent over standard input ({} bytes)",
                issued.file.len()
            ));
        }
        let r = p
            .provider_call(&auth, "activate", Some(&canon))
            .and_then(|m| provider::result_ok(&m));
        // Scrubbed by `Out` before printing; the code never reaches a log.
        r.or_else(|e| fail(12, exit::DELIVERY_FAILED, e))?;
        self.env.ui.show_code(&display);
        self.code_shown = true;
        let st = p
            .provider_call(&auth, "status", None)
            .and_then(|m| provider::status(&m))
            .or_else(|e| fail(12, exit::DELIVERY_FAILED, e))?;
        if !st.activation {
            return fail(
                12,
                exit::DELIVERY_FAILED,
                "status reports activation=no after activate",
            );
        }
        if st.file_import {
            if st.file_id.as_deref() != Some(&issued.issue.file_id)
                || st.network_mode.as_deref() != Some(issued.issue.network_mode.as_str())
            {
                return fail(
                    12,
                    exit::DELIVERY_FAILED,
                    format!(
                        "status reports file_id {:?} and network_mode {:?}, not the issued file",
                        st.file_id, st.network_mode
                    ),
                );
            }
            self.rec.file_transferred = true;
            self.o.line(format!(
                "  file imported: file_id {}, network_mode {}",
                issued.issue.file_id,
                issued.issue.network_mode.as_str()
            ));
        } else {
            self.o
                .line("  activation code set (code only): this app build has no file import.");
            self.o.line(
                "  The phone uses its built-in servers. Its configuration file was NOT transferred and must reach \
                 it later (open point: file transfer at provisioning); the record says file_transferred=false.",
            );
        }
        Ok(())
    }

    fn step13_calculator(&mut self) -> Result<(), Failure> {
        self.o.step(13, "system calculator");
        let calc = self.env.cfg.system_calculator_package.clone();
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let all = p
            .packages(None)
            .or_else(|e| fail(13, exit::DELIVERY_FAILED, e))?;
        if !all.contains(&calc) {
            if self.a.normal_tier {
                self.o.line(format!(
                    "  WARNING: {calc} is not installed; nothing hidden (normal tier, continuing). \
                     Set system_calculator_package if this phone has another calculator."
                ));
                return Ok(());
            }
            return fail(
                13,
                exit::DELIVERY_FAILED,
                format!("{calc} is not installed on this phone (system_calculator_package)"),
            );
        }
        let disabled = p
            .packages(Some("-d"))
            .or_else(|e| fail(13, exit::DELIVERY_FAILED, e))?;
        if disabled.contains(&calc) {
            self.o.line(format!("  {calc} already disabled"));
            return Ok(());
        }
        p.disable_user(&calc)
            .or_else(|e| fail(13, exit::DELIVERY_FAILED, e))?;
        let disabled = p
            .packages(Some("-d"))
            .or_else(|e| fail(13, exit::DELIVERY_FAILED, e))?;
        if !disabled.contains(&calc) {
            return fail(
                13,
                exit::DELIVERY_FAILED,
                format!("{calc} is not listed as disabled"),
            );
        }
        self.rec.calculator_disabled = Some(calc.clone());
        self.o.line(format!("  {calc} disabled for user 0"));
        Ok(())
    }

    /// The signer of the installed `base.apk`, read from a copy pulled into
    /// the private work directory with the same reader as the file check.
    fn installed_base_apk_signer(&self, package: &str) -> Result<String, String> {
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let paths = p.apk_paths(package)?;
        let base = paths
            .iter()
            .find(|x| x.ends_with("/base.apk"))
            .ok_or(format!("pm path {package} names no base.apk"))?;
        let local = self.env.work_dir.join(format!("{package}-base.apk"));
        let _ = std::fs::remove_file(&local);
        let r = p
            .pull(base, &local.to_string_lossy())
            .and_then(|_| apk::signer_digest(&local));
        let _ = std::fs::remove_file(&local);
        r
    }

    fn step14_final(&mut self) -> Result<(), Failure> {
        self.o.step(14, "final check");
        let cfg = self.env.cfg;
        let pkg = self.rec.messenger_package.clone();
        let auth = self.authority();
        let want = self.apk.clone().expect("step 4 ran");
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let st = p
            .provider_call(&auth, "status", None)
            .and_then(|m| provider::status(&m))
            .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
        if !st.activation || st.setup_done {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "status is activation={} setup={}, expected activation=yes setup=open",
                    if st.activation { "yes" } else { "no" },
                    if st.setup_done { "done" } else { "open" }
                ),
            );
        }
        self.o.line("  status: activation=yes, setup=open");
        // Section 12.1: the app reports what it applied; a difference fails.
        if let (Some(want), true) = (&self.rec.features_profile, self.rec.file_transferred) {
            let wf = self.rec.features_fixed.clone().unwrap_or_default();
            if st.features_profile.as_deref() != Some(want.as_str())
                || st.features_fixed.as_deref() != Some(wf.as_str())
            {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!(
                        "the messenger reports features_profile {:?} and features_fixed {:?}, not the issued {want} and {wf:?}",
                        st.features_profile, st.features_fixed
                    ),
                );
            }
            self.o.line(format!(
                "  feature profile applied: features_profile {want}, features_fixed {wf}"
            ));
        }
        if !p
            .whitelisted(&pkg)
            .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?
        {
            return fail(14, exit::DELIVERY_CHECK, "battery exception missing");
        }
        self.o.line("  battery exception present");
        if let Some(calc) = &self.rec.calculator_disabled {
            let d = p
                .packages(Some("-d"))
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
            if !d.contains(calc) {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!("{calc} is no longer disabled"),
                );
            }
            self.o.line(format!("  {calc} disabled"));
        }
        // Hardened tier: the attestation again. The agent attests only; the
        // installed messenger is read below without it.
        if !self.a.normal_tier {
            let target = self.target.clone().expect("step 1 ran");
            let challenge = (self.env.challenge)().or_else(|e| fail(14, exit::DEVICE, e))?;
            let at = verify_run::attest(
                &self.env.tools,
                &target,
                cfg,
                self.env.trust.expect("hardened"),
                challenge,
                (self.env.now)(),
                self.env.stale_confirmed,
                None,
            )
            .or_else(|(c, e)| fail(14, c, e))?;
            for l in &at.log {
                self.o.line(format!("  agent: {l}"));
            }
            if !at.os_pass() {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!("attestation after the install: {}", at.report.overall_label),
                );
            }
            self.o
                .line(format!("  attestation again: {}", at.report.overall_label));
        }
        // The installed messenger: its pulled base.apk (our reader) and the
        // package manager's own record (signature hash, versionCode).
        let inst =
            crate::installed::read(&self.env.tools, &self.a.serial, &pkg, &self.env.work_dir)
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, format!("installed base.apk: {e}")))?
                .ok_or(())
                .or_else(|_| fail(14, exit::DELIVERY_CHECK, format!("{pkg} is not installed")))?;
        if inst.signer_sha256 != want.signer_sha256 {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "installed base.apk signer {} differs from the APK file's {}",
                    inst.signer_sha256, want.signer_sha256
                ),
            );
        }
        if !inst.package_manager_agrees() {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "installed signer through the package manager (signature hashes {:x?}) differs from the APK file's certificate ({:08x})",
                    inst.pm_hashes, inst.cert_hash
                ),
            );
        }
        if inst.version_code != Some(want.version_code) {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                "installed versionCode differs from the APK file's",
            );
        }
        self.o.line(format!(
            "  installed signer {} (base.apk; the package manager's signature {:08x} and versionCode {})",
            inst.signer_sha256, inst.cert_hash, want.version_code
        ));
        if let Some(orec) = &self.rec.orbot {
            let ob = self.installed_base_apk_signer(&orec.package).or_else(|e| {
                fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!("installed Orbot base.apk: {e}"),
                )
            })?;
            if ob != orec.signer_sha256 {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!("installed Orbot signer {ob} differs from the file's"),
                );
            }
            self.o.line("  installed Orbot signer matches");
        }
        self.final_simplex()?;
        self.final_app_links()?;
        self.o
            .event(json!({"event": "delivered", "summary": self.summary()}));
        self.o.line("");
        self.o.line(format!("DELIVERED: {}", self.summary()));
        Ok(())
    }

    fn summary(&self) -> String {
        let r = &*self.rec;
        format!(
            "device {}, {}{}, attestation {}, messenger versionCode {} {}, Orbot {}, SimpleX app {}, file_id {}, network_mode {}, file transferred {}, code {}, customer {}",
            r.serial_masked,
            r.tier,
            if r.test { " (TEST)" } else { "" },
            r.attestation,
            r.messenger_version_code.map(|v| v.to_string()).unwrap_or_default(),
            if r.messenger_verified { "verified" } else { "UNVERIFIED" },
            r.orbot.as_ref().map(|o| format!("versionCode {} connected", o.version_code)).unwrap_or_else(|| "not installed".into()),
            match (&r.simplex_app, &r.vpn) {
                (Some(a), Some(v)) => format!(
                    "versionCode {} (not started), VPN {} apps, lockdown {}",
                    a.version_code,
                    v.apps.len(),
                    if v.lockdown { "on" } else { "off" }
                ),
                _ => "not installed".into(),
            },
            r.file_id.as_deref().unwrap_or("-"),
            r.network_mode.as_str(),
            r.file_transferred,
            r.code_masked.as_deref().unwrap_or("-"),
            r.customer_ref
        )
    }
}

fn describe_step(st: &orbot::Step) -> String {
    match st {
        orbot::Step::Tap(s) => format!("tap {}", s.name),
        orbot::Step::WaitFor(s) => format!("wait for {}", s.name),
        orbot::Step::Back => "back key (input keyevent KEYCODE_BACK)".into(),
        orbot::Step::Switch { title, want } => {
            format!(
                "{}: switch {}",
                title.name,
                if *want { "on" } else { "off" }
            )
        }
        orbot::Step::Text { title, value, .. } => format!("{}: set to {value}", title.name),
        orbot::Step::Check { el, want } => {
            format!(
                "{}: tap unless {}",
                el.name,
                if *want { "on" } else { "off" }
            )
        }
        orbot::Step::TapIfShown(s) => format!("tap {} if shown", s.name),
        orbot::Step::Absent { name, .. } => format!("stop if {name} is shown"),
        orbot::Step::WaitText { name, .. } => format!("wait for {name}"),
        orbot::Step::SwitchConfirm { title, want, .. } => format!(
            "{}: switch {} (confirm if asked)",
            title.name,
            if *want { "on" } else { "off" }
        ),
        orbot::Step::TypeInto { field, value } => format!("{}: type {value}", field.name),
        orbot::Step::TapIn { title, gear } => format!("tap {} of {}", gear.name, title.name),
        orbot::Step::ScrollTo { el, .. } => format!("scroll to {}", el.name),
        orbot::Step::TapSelf(s) => format!("tap {} (the element itself)", s.name),
        orbot::Step::TapButton(s) => format!("tap {} (the clickable one)", s.name),
    }
}
