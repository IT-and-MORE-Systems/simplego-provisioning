// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! CLI glue for `os status`, `os fetch` and `flash`.

use crate::config::Config;
use crate::deliver::{phone::Phone, Secret, Ui};
use crate::deliver_cmd::{self, TerminalUi, WorkDir};
use crate::device;
use crate::grapheneos::channel::Channels;
use crate::grapheneos::image::{self, ImageCache};
use crate::grapheneos::status::{self, Installed, Outcome};
use crate::grapheneos::{valid_channel, valid_codename, valid_version, Http, TorHttp};
use crate::trust::lists::GRAPHENEOS_ALLOWED_SIGNERS;
use crate::util::{mask_serial, now_unix};
use crate::{exit, names};
use serde_json::json;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct OsOpts {
    pub serial: Option<String>,
    pub device: Option<String>,
    pub channel: Option<String>,
    pub version: Option<String>,
    pub offline: bool,
    pub json: bool,
    pub test_device: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub confirm_stale: bool,
    pub resume: bool,
}

fn err(code: i32, msg: impl std::fmt::Display) -> i32 {
    eprintln!("{}: {msg}", names::BINARY);
    code
}

/// The Tor client, or None (offline) with the reason.
fn http(cfg: &Config, offline: bool) -> (Option<TorHttp>, Option<String>) {
    if offline {
        return (None, Some("--offline".into()));
    }
    match TorHttp::new(
        &cfg.tor_socks_proxy,
        Duration::from_secs(60),
        cfg.download_idle(),
    ) {
        Ok(h) => (Some(h), None),
        Err(e) => (None, Some(e)),
    }
}

fn channel(cfg: &Config, o: &OsOpts) -> Result<String, i32> {
    let c = o
        .channel
        .clone()
        .unwrap_or_else(|| cfg.grapheneos_channel.clone());
    if !valid_channel(&c) {
        return Err(err(
            exit::USAGE,
            format!("--channel must be stable, beta or alpha, got {c:?}"),
        ));
    }
    Ok(c)
}

/// The status of one phone, for `os status`, `verify` and `deliver`.
pub fn status_of(cfg: &Config, inst: &Installed, channel: &str, offline: bool) -> status::OsStatus {
    let (h, _) = http(cfg, offline);
    let cache = cfg.grapheneos_cache().unwrap_or_default();
    let codename = inst.codename.clone().unwrap_or_default();
    let now = now_unix();
    let ch = Channels {
        base: &cfg.grapheneos_release_base,
        cache_dir: cache,
        http: h.as_ref().map(|x| x as &dyn Http),
        now,
    };
    let rel = ch.release(&codename, channel);
    status::evaluate(inst, &rel, channel, cfg.release_setting(), now)
}

pub fn cmd_os_status(cfg: &Config, o: &OsOpts) -> i32 {
    let Some(serial) = o.serial.clone() else {
        return err(exit::USAGE, "os status needs --serial SERIAL");
    };
    let ch = match channel(cfg, o) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let tools = deliver_cmd::tools(cfg);
    if let Err(e) = crate::deliver::find_target(&tools, &serial) {
        return err(exit::DEVICE, e);
    }
    let p = Phone {
        tools: &tools,
        serial: &serial,
    };
    let props = match p.getprops() {
        Ok(p) => p,
        Err(e) => return err(exit::DEVICE, e.replace(&serial, &mask_serial(&serial))),
    };
    let inst = Installed::from_props(&props);
    let st = status_of(cfg, &inst, &ch, o.offline);
    // OEM unlocking is read from the Developer options screen (no tap).
    let oem = read_oem(&p);
    let code = match st.outcome {
        Outcome::UpToDate => exit::OK,
        Outcome::UpdateAvailable => exit::OS_OUTDATED,
        _ => exit::OS_UNKNOWN,
    };
    let now = now_unix();
    if o.json {
        let v = json!({"device": mask_serial(&serial), "status": st, "oem_unlocking": oem,
                       "build_type": st.build_type_label, "result": st.result});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return code;
    }
    println!("device {}", mask_serial(&serial));
    for l in status::lines(&st, now) {
        println!("{l}");
    }
    println!(
        "  bootloader locked (reported): {}",
        match inst.bootloader_locked {
            Some(true) => "yes",
            Some(false) => "NO",
            None => "unknown",
        }
    );
    println!("  OEM unlocking allowed: {oem}");
    println!("RESULT: {} (build type {})", st.result, st.build_type_label);
    code
}

#[cfg(unix)]
fn read_oem(p: &Phone) -> String {
    let mut log = Vec::new();
    let sleep = |d: Duration| std::thread::sleep(d);
    let r = crate::flash::devopts::DevOpts {
        phone: p,
        sleep: &sleep,
        retries: 5,
        log: &mut log,
    }
    .read_state();
    match r {
        Ok(Some(crate::flash::devopts::Oem::On)) => "yes".into(),
        Ok(Some(crate::flash::devopts::Oem::Off)) => "no".into(),
        Ok(Some(crate::flash::devopts::Oem::Greyed)) => "no (switch greyed out)".into(),
        Ok(None) => "unknown (the switch is not on the Developer options screen)".into(),
        Err(e) => format!("unknown ({e})"),
    }
}

#[cfg(not(unix))]
fn read_oem(_p: &Phone) -> String {
    "unknown (read only on Linux or WSL)".into()
}

pub fn cmd_os_fetch(cfg: &Config, o: &OsOpts) -> i32 {
    let Some(codename) = o.device.clone() else {
        return err(exit::USAGE, "os fetch needs --device CODENAME");
    };
    if !valid_codename(&codename) {
        return err(exit::USAGE, format!("invalid codename {codename:?}"));
    }
    let ch = match channel(cfg, o) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let (h, why) = http(cfg, o.offline);
    let Some(h) = h else {
        return err(
            exit::OS_IMAGE,
            format!("os fetch needs Tor: {}", why.unwrap_or_default()),
        );
    };
    let cache_dir = match cfg.grapheneos_cache() {
        Ok(c) => c,
        Err(e) => return err(exit::CONFIG, e),
    };
    let now = now_unix();
    let version = match &o.version {
        Some(v) if valid_version(v) => v.clone(),
        Some(v) => {
            return err(
                exit::USAGE,
                format!("--version must be ten digits, got {v:?}"),
            )
        }
        None => {
            let chs = Channels {
                base: &cfg.grapheneos_release_base,
                cache_dir: cache_dir.clone(),
                http: Some(&h),
                now,
            };
            let rel = chs.release(&codename, &ch);
            println!("release file: {}", rel.stable.source(now));
            println!("security preview file: {}", rel.preview.source(now));
            match rel.target(cfg.release_setting()) {
                Some((c, preview)) => {
                    println!(
                        "grapheneos_release = {}: {} {}",
                        cfg.grapheneos_release,
                        if preview {
                            "security preview"
                        } else {
                            "release"
                        },
                        c.version
                    );
                    c.version
                }
                None => {
                    return err(
                        exit::OS_IMAGE,
                        format!("no channel file for {codename} {ch}; give --version"),
                    )
                }
            }
        }
    };
    println!(
        "fetching {codename}-install-{version}.zip into {} (over Tor, {})",
        cache_dir.display(),
        cfg.tor_socks_proxy
    );
    let cache = ImageCache { root: cache_dir };
    let t0 = std::time::Instant::now();
    let r = image::fetch(
        &cache,
        &h,
        &cfg.grapheneos_release_base,
        &codename,
        &version,
        GRAPHENEOS_ALLOWED_SIGNERS,
        &now_unix,
        &mut |l| println!("{l}"),
    );
    match r {
        Ok(v) => {
            let secs = t0.elapsed().as_secs();
            if o.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"verified": v, "seconds": secs}))
                        .unwrap_or_default()
                );
            }
            println!(
                "VERIFIED: {} ({} bytes, SHA-256 {}), {}m{:02}s",
                v.file,
                v.size,
                v.sha256,
                secs / 60,
                secs % 60
            );
            exit::OK
        }
        Err(e) => err(exit::OS_IMAGE, e),
    }
}

/// The flash prompts: typed confirmations only on a terminal (never from
/// `--yes`). The store asks for nothing (store key).
struct FlashUi;

impl Ui for FlashUi {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String> {
        TerminalUi.secret(what)
    }
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String> {
        TerminalUi.confirm(word, question)
    }
    fn show_code(&mut self, _code: &str) {}
}

#[cfg(unix)]
pub fn cmd_flash(cfg: &Config, o: &OsOpts) -> i32 {
    use crate::flash::{self, FlashArgs, FlashEnv, Polls};
    let Some(serial) = o.serial.clone() else {
        return err(exit::USAGE, "flash needs --serial SERIAL");
    };
    if cfg.fastboot_path.is_empty() {
        return err(exit::CONFIG, "flash needs fastboot_path in the config");
    }
    let cache_dir = match cfg.grapheneos_cache() {
        Ok(c) => c,
        Err(e) => return err(exit::CONFIG, e),
    };
    let log_dir = match cfg.flash_logs() {
        Ok(c) => c,
        Err(e) => return err(exit::CONFIG, e),
    };
    let standin =
        device::running_in_wsl() && cfg.fastboot_path.to_ascii_lowercase().ends_with(".exe");
    if standin {
        // fastboot.exe must see the image files under a Windows drive.
        let p = cache_dir.to_string_lossy().to_string();
        let on_drive = p.len() > 7 && p.starts_with("/mnt/") && p.as_bytes()[6] == b'/';
        if !on_drive {
            return err(
                exit::CONFIG,
                format!("with the Windows fastboot.exe, grapheneos_cache_dir must be on a Windows drive (/mnt/c/...), not {p}"),
            );
        }
    }
    let tm = if o.dry_run {
        None
    } else {
        match deliver_cmd::trust_with(cfg, o.confirm_stale, "flash") {
            Ok(t) => Some(t),
            Err(c) => return c,
        }
    };
    let work = match WorkDir::new() {
        Ok(w) => w,
        Err(e) => return err(exit::DEVICE, e),
    };
    let (h, why) = http(cfg, o.offline);
    if let Some(w) = &why {
        println!("network: offline ({w}); only cached channel files and images are used");
    }
    let mut ui = FlashUi;
    let mut ch = deliver_cmd::challenge;
    let mut rng = crate::activation::rng::SystemRand::new();
    let now = now_unix;
    let sleep = deliver_cmd::sleep;
    let mut env = FlashEnv {
        cfg,
        tools: deliver_cmd::tools(cfg),
        ui: &mut ui,
        now: &now,
        challenge: &mut ch,
        rng: &mut rng,
        sleep: &sleep,
        trust: tm.as_ref().map(|(t, _)| t),
        stale_confirmed: tm.as_ref().map(|(_, s)| *s).unwrap_or(false),
        http: h.as_ref().map(|x| x as &dyn Http),
        signers: GRAPHENEOS_ALLOWED_SIGNERS,
        boot_keys: crate::grapheneos::pinned_boot_keys(),
        standin,
        polls: Polls::real(cfg.flash_confirm_timeout_secs),
        ui_retries: 10,
        cache_dir,
        log_dir,
        work_dir: work.0.clone(),
    };
    let a = FlashArgs {
        serial,
        channel: o.channel.clone(),
        version: o.version.clone(),
        test_device: o.test_device,
        yes: o.yes,
        dry_run: o.dry_run,
        json: o.json,
        resume: o.resume,
    };
    let mut out = std::io::stdout();
    flash::flash(&mut env, &mut out, &a)
}

#[cfg(not(unix))]
pub fn cmd_flash(_cfg: &Config, _o: &OsOpts) -> i32 {
    err(exit::USAGE, "flash runs on Linux or WSL only")
}
