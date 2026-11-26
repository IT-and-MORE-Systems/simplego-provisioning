// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! sxprov, SimpleGo Provisioning: verifies, delivers and flashes SimpleGo
//! phones from the admin laptop.

mod activation;
mod activation_cmd;
mod agent;
mod apk;
mod attest;
mod config;
mod config_cmd;
mod deliver;
mod deliver_cmd;
mod device;
mod exit;
mod fdroid;
#[cfg(unix)]
mod flash;
mod grapheneos;
mod installed;
mod names;
mod os_cmd;
mod tor;
mod trust;
mod util;
mod verify;
mod verify_run;
mod warning;

use config::Config;
use device::{parse::Mode, Tools};
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use trust::cache::Cache;
use util::{fmt_unix, mask_serial, now_unix};

#[derive(Default)]
struct Opts {
    json: bool,
    show_serial: bool,
    config: Option<PathBuf>,
    serial: Option<String>,
    /// `--messenger-package`: the messenger the read-only commands look at.
    messenger_package: Option<String>,
    confirm_stale: bool,
    act: activation_cmd::ActOpts,
    del: deliver_cmd::DelOpts,
    os: os_cmd::OsOpts,
}

fn usage() -> String {
    let b = names::BINARY;
    format!(
        "usage:
  {b} --version
  {b} devices [--serial SERIAL] [--messenger-package PKG] [--json] [--show-serial]
  {b} verify [--serial SERIAL] [--messenger-package PKG] [--json] [--show-serial] [--confirm-stale-revocation-list] [--offline]
  {b} trust status [--json]
  {b} trust refresh
  {b} trust import DIR   (lists placed by hand: status.json, attestation.json, attestation.json.sig)
  {b} store init
  {b} store list [--json] [--show-serial]
  {b} activation pubkey --key PUBFILE [--json]
  {b} activation issue --customer-ref REF --device-class phone|desktop --network-mode MODE
        --servers FILE --support FILE --key PRIVFILE [--serial SERIAL] --out FILE
  {b} activation update --customer-ref REF --device-class phone|desktop --network-mode MODE
        --servers FILE --support FILE --key PRIVFILE [--rotate-update-key | --under-key-id ID] --out FILE
  {b} activation inspect FILE [--trusted PUBFILE ...] [--code | --update-key-from-store REF |
        --update-key-file FILE | --update-key-prompt] [--json]
  {b} deliver --serial SERIAL --apk FILE --customer-ref REF --network-mode MODE
        --servers FILE --support FILE --key PRIVFILE [--orbot-apk FILE [--fdroid-apk FILE]]
        [--normal-tier] [--reinstall] [--accept-unverified-messenger] [--confirm-stale-revocation-list]
        [--dry-run] [--allow-outdated-os] [--offline] [--json]
        [--test-delivery --test-store-passphrase-file FILE --test-key-passphrase-file FILE [--yes]]
  {b} undeliver --serial SERIAL --test-device [--discard-test-setup] [--json]
        [--test-delivery --test-store-passphrase-file FILE]   (without a terminal)
  {b} handover --serial SERIAL [--json]
  {b} apk inspect FILE [--json]
  {b} store init --test-delivery --test-store-passphrase-file FILE   (throwaway test store only)
  {b} os status --serial SERIAL [--channel CHANNEL] [--offline] [--json]
  {b} os fetch --device CODENAME [--channel CHANNEL | --version VERSION] [--json]
  {b} flash --serial SERIAL [--channel CHANNEL | --version VERSION] [--dry-run] [--offline] [--json]
        [--test-device [--yes] [--test-store-passphrase-file FILE]] [--confirm-stale-revocation-list]
  {b} flash --resume --serial SERIAL [--version VERSION] [--test-device [--yes]] [--json]
        (continues from a phone already in fastboot mode)
  {b} config show [--json]
  {b} config set KEY VALUE [--json]
  CHANNEL: stable (default), beta or alpha; VERSION: ten digits, for example 2026111801
  MODE: tor_required, tor_optional or direct
common options: --config PATH (default: ${} or {})
exit codes: see docs/USAGE.md",
        config::ENV_CONFIG,
        config::DEFAULT_CONFIG_PATH
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    if matches!(args, [a] if a == "--version" || a == "-V") {
        println!("{}", names::version_line());
        return exit::OK;
    }
    let mut words = Vec::new();
    let mut o = Opts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => o.json = true,
            "--show-serial" => o.show_serial = true,
            "--confirm-stale-revocation-list" => o.confirm_stale = true,
            "--config" => match it.next() {
                Some(p) => o.config = Some(PathBuf::from(p)),
                None => return usage_err("--config needs a path"),
            },
            "--serial" | "-s" => match it.next() {
                Some(s) => o.serial = Some(s.clone()),
                None => return usage_err("--serial needs a value"),
            },
            "--messenger-package" => match it.next() {
                Some(p) if agent::valid_package(p) => o.messenger_package = Some(p.clone()),
                Some(p) => {
                    return usage_err(&format!("--messenger-package: {p:?} is not a package name"))
                }
                None => return usage_err("--messenger-package needs a package name"),
            },
            "--rotate-update-key" => o.act.rotate_update_key = true,
            "--normal-tier" => o.del.d.normal_tier = true,
            "--dry-run" => o.del.d.dry_run = true,
            "--reinstall" => o.del.d.reinstall = true,
            "--accept-unverified-messenger" => o.del.d.accept_unverified_messenger = true,
            "--test-delivery" => o.del.d.test_delivery = true,
            "--test-device" => o.del.test_device = true,
            "--discard-test-setup" => o.del.discard_test_setup = true,
            "--resume" => o.os.resume = true,
            "--offline" => o.os.offline = true,
            "--allow-outdated-os" => o.del.d.allow_outdated_os = true,
            "--channel" | "--version" | "--device" => {
                let Some(v) = it.next() else {
                    return usage_err(&format!("{a} needs a value"));
                };
                match a.as_str() {
                    "--channel" => o.os.channel = Some(v.clone()),
                    "--version" => o.os.version = Some(v.clone()),
                    _ => o.os.device = Some(v.clone()),
                }
            }
            "--yes" => o.del.yes = true,
            "--apk"
            | "--orbot-apk"
            | "--fdroid-apk"
            | "--test-store-passphrase-file"
            | "--test-key-passphrase-file" => {
                let Some(v) = it.next() else {
                    return usage_err(&format!("{a} needs a value"));
                };
                let v = PathBuf::from(v);
                match a.as_str() {
                    "--apk" => o.del.d.apk = v,
                    "--orbot-apk" => o.del.d.orbot_apk = Some(v),
                    "--fdroid-apk" => o.del.d.fdroid_apk = Some(v),
                    "--test-store-passphrase-file" => o.del.store_pass_file = Some(v),
                    _ => o.del.key_pass_file = Some(v),
                }
            }
            "--code" => o.act.code = true,
            "--update-key-prompt" => o.act.update_key_prompt = true,
            "--customer-ref"
            | "--device-class"
            | "--network-mode"
            | "--servers"
            | "--support"
            | "--key"
            | "--out"
            | "--under-key-id"
            | "--trusted"
            | "--update-key-from-store"
            | "--update-key-file" => {
                let Some(v) = it.next() else {
                    return usage_err(&format!("{a} needs a value"));
                };
                let v = v.clone();
                match a.as_str() {
                    "--customer-ref" => o.act.customer_ref = Some(v),
                    "--device-class" => o.act.device_class = Some(v),
                    "--network-mode" => o.act.network_mode = Some(v),
                    "--servers" => o.act.servers = Some(PathBuf::from(v)),
                    "--support" => o.act.support = Some(PathBuf::from(v)),
                    "--key" => o.act.key = Some(PathBuf::from(v)),
                    "--out" => o.act.out = Some(PathBuf::from(v)),
                    "--under-key-id" => o.act.under_key_id = Some(v),
                    "--trusted" => o.act.trusted.push(PathBuf::from(v)),
                    "--update-key-file" => o.act.update_key_file = Some(PathBuf::from(v)),
                    _ => o.act.update_key_from_store = Some(v),
                }
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return exit::OK;
            }
            s if s.starts_with('-') => return usage_err(&format!("unknown option {s}")),
            w => words.push(w),
        }
    }
    o.act.json = o.json;
    o.act.show_serial = o.show_serial;
    o.act.serial = o.serial.clone();
    o.del.json = o.json;
    o.del.d.json = o.json;
    o.del.confirm_stale = o.confirm_stale;
    o.del.d.serial = o.serial.clone().unwrap_or_default();
    o.del.d.customer_ref = o.act.customer_ref.clone().unwrap_or_default();
    o.del.d.network_mode = o.act.network_mode.clone().unwrap_or_default();
    o.del.d.servers = o.act.servers.clone().unwrap_or_default();
    o.del.d.support = o.act.support.clone().unwrap_or_default();
    o.del.d.key = o.act.key.clone().unwrap_or_default();
    o.del.offline = o.os.offline;
    o.os.serial = o.serial.clone();
    o.os.json = o.json;
    o.os.test_device = o.del.test_device;
    o.os.yes = o.del.yes;
    o.os.dry_run = o.del.d.dry_run;
    o.os.confirm_stale = o.confirm_stale;
    o.os.store_pass_file = o.del.store_pass_file.clone();
    match words.as_slice() {
        ["devices"] => cmd_devices(&o),
        ["verify"] => cmd_verify(&o),
        ["trust", "status"] => cmd_trust_status(&o),
        ["trust", "refresh"] => cmd_trust_refresh(&o),
        ["trust", "import", dir] => cmd_trust_import(&o, dir),
        ["store", "init"] if o.del.d.test_delivery => {
            with_config(&o, |c| deliver_cmd::cmd_test_store_init(c, &o.del))
        }
        ["store", "init"] => with_config(&o, activation_cmd::cmd_store_init),
        ["deliver"] => with_config(&o, |c| deliver_cmd::cmd_deliver(c, &o.del)),
        ["undeliver"] => with_config(&o, |c| deliver_cmd::cmd_undeliver(c, &o.del)),
        ["handover"] => with_config(&o, |c| deliver_cmd::cmd_handover(c, &o.del)),
        ["apk", "inspect", file] => deliver_cmd::cmd_apk_inspect(file, o.json),
        ["config", "show"] => config_cmd::cmd_show(o.config.as_deref(), o.json),
        ["config", "set", key, value] => {
            config_cmd::cmd_set(o.config.as_deref(), key, value, o.json)
        }
        ["os", "status"] => with_config(&o, |c| os_cmd::cmd_os_status(c, &o.os)),
        ["os", "fetch"] => with_config(&o, |c| os_cmd::cmd_os_fetch(c, &o.os)),
        ["flash"] => with_config(&o, |c| os_cmd::cmd_flash(c, &o.os)),
        ["store", "list"] => with_config(&o, |c| activation_cmd::cmd_store_list(c, &o.act)),
        ["activation", "pubkey"] => activation_cmd::cmd_pubkey(&o.act),
        ["activation", "issue"] => with_config(&o, |c| activation_cmd::cmd_issue(c, &o.act)),
        ["activation", "update"] => with_config(&o, |c| activation_cmd::cmd_update(c, &o.act)),
        ["activation", "inspect", file] => {
            activation_cmd::cmd_inspect(&|| load_config(&o), &o.act, file)
        }
        _ => usage_err("unknown command"),
    }
}

fn with_config(o: &Opts, f: impl FnOnce(&Config) -> i32) -> i32 {
    match load_config(o) {
        Ok(c) => f(&c),
        Err(code) => code,
    }
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("{}: {msg}\n{}", names::BINARY, usage());
    exit::USAGE
}

fn load_config(o: &Opts) -> Result<Config, i32> {
    Config::load(o.config.as_deref())
        .map(|(c, _)| c)
        .map_err(|e| {
            eprintln!("{}: {e}", names::BINARY);
            exit::CONFIG
        })
}

fn tools(c: &Config) -> Tools {
    Tools {
        adb: c.adb_path.clone(),
        fastboot: c.fastboot_path.clone(),
    }
}

fn show_serial(o: &Opts, s: &str) -> String {
    if o.show_serial {
        s.to_string()
    } else {
        mask_serial(s)
    }
}

// ---- devices ---------------------------------------------------------------

fn cmd_devices(o: &Opts) -> i32 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let t = tools(&cfg);
    let versions = json!({
        "adb": device::tool_version(&t.adb).unwrap_or_else(|e| format!("unavailable: {e}")),
        "fastboot": device::tool_version(&t.fastboot).unwrap_or_else(|e| format!("unavailable: {e}")),
    });
    let listed = match device::list(&t) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{}: {e}", names::BINARY);
            return exit::DEVICE;
        }
    };
    let chosen = match device::select_for_query(&listed, o.serial.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", names::BINARY);
            return exit::DEVICE;
        }
    };
    let mut lookup = None;
    let mut infos: Vec<device::DeviceInfo> = listed
        .iter()
        .map(|d| match chosen {
            Some(c) if std::ptr::eq(c, d) && d.mode == Mode::Adb => {
                let r = installed::resolve(o.messenger_package.as_deref(), &cfg, &t, &d.serial);
                let info = device::describe(&t, d, r.package.as_deref());
                lookup = Some(r.note);
                info
            }
            Some(c) if std::ptr::eq(c, d) => device::describe(&t, d, None),
            _ => device::listed_only(d),
        })
        .collect();
    for i in &mut infos {
        i.serial = show_serial(o, &i.serial);
    }
    if o.json {
        let v = json!({"tools": versions, "devices": infos, "messenger_lookup": lookup, "note": "all values are reported by the device, not verified"});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return exit::OK;
    }
    println!("adb: {}", versions["adb"].as_str().unwrap_or(""));
    println!("fastboot: {}", versions["fastboot"].as_str().unwrap_or(""));
    if infos.is_empty() {
        println!("no devices found");
        return exit::OK;
    }
    println!();
    println!(
        "{:<14} {:<12} {:<18} {:<10} {:<8} {:<20} {:<11} {:<10}",
        "SERIAL", "MODE", "MODEL", "CODENAME", "ANDROID", "BUILD", "PATCH", "GRAPHENEOS"
    );
    for i in &infos {
        println!(
            "{:<14} {:<12} {:<18} {:<10} {:<8} {:<20} {:<11} {:<10}",
            i.serial,
            i.mode,
            i.model.as_deref().unwrap_or("-"),
            i.codename.as_deref().unwrap_or("-"),
            i.android_version.as_deref().unwrap_or("-"),
            i.build_id.as_deref().unwrap_or("-"),
            i.security_patch.as_deref().unwrap_or("-"),
            if i.grapheneos_hint.is_some() {
                "hint"
            } else {
                "-"
            }
        );
    }
    for i in &infos {
        println!("\n{} ({}):", i.serial, i.mode);
        if !i.queried {
            println!(
                "  only listed; no command was sent to this device (choose one with --serial to read details)"
            );
            continue;
        }
        if let Some(h) = &i.grapheneos_hint {
            println!("  GrapheneOS hint: {h} (a hint only; proof is attestation)");
        }
        if !i.bootloader_reported.is_empty() {
            println!("  bootloader, reported by the device (not verified):");
            for (k, v) in &i.bootloader_reported {
                println!("    {k} = {v}");
            }
        }
        if let Some(l) = &lookup {
            println!("  {l}");
        }
        if let Some(m) = &i.messenger {
            if m.installed {
                println!(
                    "  messenger {}: installed, versionName {}, versionCode {}",
                    m.package,
                    m.version_name.as_deref().unwrap_or("?"),
                    m.version_code
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into())
                );
            } else {
                println!("  messenger {}: not installed", m.package);
            }
            println!("  messenger signature: {}", m.signature_note);
        }
        for e in &i.errors {
            println!("  error: {e}");
        }
    }
    exit::OK
}

// ---- trust -----------------------------------------------------------------

fn cmd_trust_status(o: &Opts) -> i32 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let cache = Cache::new(&cfg.trust_cache_dir);
    let now = now_unix();
    let rev = cache.load_revocation();
    let gos = cache.load_grapheneos();
    let roots = trust::google_roots();
    let item = |name: &str,
                threshold: u64,
                meta: Option<&trust::cache::Meta>,
                err: Option<&String>,
                extra: String| {
        match (meta, err) {
            (Some(m), None) => {
                let a = verify::list_age(m, threshold, now);
                json!({"item": name, "present": true, "source": a.source, "fetched_at": a.fetched_at, "age": a.age,
                       "age_seconds": a.age_seconds, "last_modified": a.last_modified,
                       "threshold_days": threshold, "over_threshold": a.over_threshold, "detail": extra})
            }
            (_, Some(e)) => json!({"item": name, "present": false, "error": e}),
            _ => json!({"item": name, "present": false}),
        }
    };
    let rev_v = item(
        "google_revocation_list",
        cfg.revocation_max_age_days,
        rev.as_ref().ok().map(|l| &l.meta),
        rev.as_ref().err(),
        rev.as_ref()
            .map(|l| format!("{} entries", l.value.entries.len()))
            .unwrap_or_default(),
    );
    let gos_v = item(
        "grapheneos_key_list",
        cfg.grapheneos_keys_warn_age_days,
        gos.as_ref().ok().map(|l| &l.meta),
        gos.as_ref().err(),
        gos.as_ref()
            .map(|l| {
                format!(
                    "{} keys, signature valid, signed timestamp {}",
                    l.value.keys.len(),
                    fmt_unix(l.value.timestamp)
                )
            })
            .unwrap_or_default(),
    );
    let roots_v = match &roots {
        Ok(r) => json!(r
            .iter()
            .map(|a| json!({"name": a.name, "not_after": fmt_unix(a.not_after)}))
            .collect::<Vec<_>>()),
        Err(e) => json!({"error": e}),
    };
    let ok = rev.is_ok() && gos.is_ok() && roots.is_ok();
    if o.json {
        let v = json!({"cache_dir": cfg.trust_cache_dir, "items": [rev_v, gos_v], "google_roots": roots_v, "usable": ok});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("trust cache: {}", cfg.trust_cache_dir.display());
        for v in [&rev_v, &gos_v] {
            let name = v["item"].as_str().unwrap_or("");
            if v["present"].as_bool() == Some(true) {
                println!(
                    "  {name}: {}
    fetched {} ({} ago), Last-Modified {}, threshold {} days{}; {}",
                    v["source"].as_str().unwrap_or(""),
                    v["fetched_at"].as_str().unwrap_or(""),
                    v["age"].as_str().unwrap_or(""),
                    v["last_modified"].as_str().unwrap_or("unknown"),
                    v["threshold_days"],
                    if v["over_threshold"].as_bool() == Some(true) {
                        ", OVER THRESHOLD"
                    } else {
                        ""
                    },
                    v["detail"].as_str().unwrap_or("")
                );
            } else {
                println!(
                    "  {name}: MISSING ({}). Verification is refused until `{} trust refresh` succeeds.",
                    v["error"].as_str().unwrap_or("not present"),
                    names::BINARY
                );
            }
        }
        match &roots {
            Ok(r) => {
                println!("  google roots (embedded, trust/google-roots):");
                for a in r {
                    println!("    {} valid until {}", a.name, fmt_unix(a.not_after));
                }
            }
            Err(e) => println!("  google roots: ERROR {e}"),
        }
    }
    if ok {
        exit::OK
    } else {
        exit::TRUST_MISSING
    }
}

fn cmd_trust_refresh(o: &Opts) -> i32 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let cache = Cache::new(&cfg.trust_cache_dir);
    println!(
        "refreshing through Tor ({}), no clearnet fallback",
        cfg.tor_socks_proxy
    );
    let rep = trust::refresh::refresh(
        &cache,
        &cfg.tor_socks_proxy,
        trust::refresh::CONNECT_TIMEOUT,
        cfg.download_idle(),
    );
    print_refresh(&rep)
}

fn cmd_trust_import(o: &Opts, dir: &str) -> i32 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let cache = Cache::new(&cfg.trust_cache_dir);
    println!("importing lists placed by hand from {dir} (not downloaded by this tool)");
    let rep = trust::refresh::import_manual(&cache, std::path::Path::new(dir), now_unix());
    print_refresh(&rep)
}

fn print_refresh(rep: &trust::refresh::RefreshReport) -> i32 {
    for (name, r) in [
        ("google revocation list", &rep.revocation),
        ("grapheneos key list", &rep.grapheneos),
    ] {
        match r {
            Some(Ok(msg)) => println!("  {name}: updated, {msg}"),
            Some(Err(e)) => println!("  {name}: FAILED, previous copy kept: {e}"),
            None => println!("  {name}: not attempted"),
        }
    }
    if rep.ok() {
        exit::OK
    } else {
        exit::REFRESH_FAILED
    }
}

// ---- verify ----------------------------------------------------------------

fn confirm_stale(o: &Opts, age: &str, days: u64) -> bool {
    eprintln!(
        "WARNING: the Google revocation list is {age} old (threshold {days} days). \
         Run `{} trust refresh` if possible.",
        names::BINARY
    );
    if o.confirm_stale {
        eprintln!("operator confirmation given with --confirm-stale-revocation-list");
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "no terminal on standard input to type STALE; give --confirm-stale-revocation-list"
        );
        return false;
    }
    eprint!("Type STALE to verify against the stale list anyway: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && line.trim() == "STALE"
}

fn cmd_verify(o: &Opts) -> i32 {
    let cfg = match load_config(o) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let tm = match verify_run::load_trust(&cfg) {
        Ok(t) => t,
        Err((code, e)) => {
            eprintln!("{}: {e}", names::BINARY);
            return code;
        }
    };
    let now = now_unix();
    let mut stale_confirmed = false;
    if tm.revocation_stale(&cfg, now) {
        let age = util::fmt_age(now.saturating_sub(tm.rev.meta.fetched_at));
        if !confirm_stale(o, &age, cfg.revocation_max_age_days) {
            eprintln!("{}: not confirmed; no verification run", names::BINARY);
            return exit::STALE_NOT_CONFIRMED;
        }
        stale_confirmed = true;
    }
    if cfg.agent_apk.is_empty() || !std::path::Path::new(&cfg.agent_apk).is_file() {
        eprintln!(
            "{}: agent_apk {:?} is not a file",
            names::BINARY,
            cfg.agent_apk
        );
        return exit::CONFIG;
    }

    let t = tools(&cfg);
    let listed = match device::list(&t) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{}: {e}", names::BINARY);
            return exit::DEVICE;
        }
    };
    let candidates: Vec<_> = listed
        .iter()
        .filter(|d| o.serial.as_deref().map(|s| s == d.serial).unwrap_or(true))
        .collect();
    let target = match candidates.as_slice() {
        [d] if d.mode == Mode::Adb => *d,
        [d] => {
            eprintln!(
                "{}: device {} is in mode {}; verify needs adb mode (booted, USB debugging authorized)",
                names::BINARY,
                show_serial(o, &d.serial),
                d.mode.as_str()
            );
            return exit::DEVICE;
        }
        [] => {
            eprintln!("{}: no matching device", names::BINARY);
            return exit::DEVICE;
        }
        _ => {
            eprintln!(
                "{}: several devices connected; choose one with --serial",
                names::BINARY
            );
            return exit::DEVICE;
        }
    };
    let mut challenge = vec![0u8; 32];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut challenge).is_err() {
        eprintln!("{}: no system randomness", names::BINARY);
        return exit::DEVICE;
    }
    let lookup = installed::resolve(o.messenger_package.as_deref(), &cfg, &t, &target.serial);
    let messenger = lookup.package.clone();
    let a = match verify_run::attest(
        &t,
        target,
        &cfg,
        &tm,
        challenge,
        now,
        stale_confirmed,
        messenger.as_deref(),
    ) {
        Ok(a) => a,
        Err((code, e)) => {
            eprintln!("{}: {e}", names::BINARY);
            return code;
        }
    };
    let os = os_cmd::status_of(&cfg, &a.info.os, &cfg.grapheneos_channel, o.os.offline);
    let (report, log) = (a.report, a.log);
    let serial = show_serial(o, &target.serial);
    if o.json {
        let v = json!({"device": {"serial": serial, "reported": report.reported}, "agent_log": log, "messenger_lookup": lookup.note, "report": report,
                       "os_status": os, "build_type": os.build_type_label});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("{}", lookup.note);
        print_report(&serial, &report, &log);
        println!();
        for l in grapheneos::status::lines(&os, now) {
            println!("{l}");
        }
    }
    report.overall.exit_code()
}

fn print_report(serial: &str, r: &verify::Report, log: &[String]) {
    let tier = match r.tier {
        verify::Tier::HardenedPixel => "hardened Pixel",
        verify::Tier::NormalPhone => "normal phone",
    };
    println!(
        "device {serial}: {} ({}), tier: {tier}",
        r.reported.model.as_deref().unwrap_or("?"),
        r.reported.codename.as_deref().unwrap_or("?")
    );
    println!(
        "revocation list: {}
  fetched {} ({} ago), Last-Modified {}{}",
        r.revocation_list.source,
        r.revocation_list.fetched_at,
        r.revocation_list.age,
        r.revocation_list
            .last_modified
            .as_deref()
            .unwrap_or("unknown"),
        if r.stale_revocation_list {
            ", STALE"
        } else {
            ""
        }
    );
    println!(
        "GrapheneOS key list: {}
  fetched {} ({} ago){}",
        r.grapheneos_key_list.source,
        r.grapheneos_key_list.fetched_at,
        r.grapheneos_key_list.age,
        if r.grapheneos_key_list.over_threshold {
            ", OLD"
        } else {
            ""
        }
    );
    for l in log {
        println!("agent: {l}");
    }
    println!();
    for c in &r.checks {
        println!("[{}] {}", c.status.label(), c.title);
        for e in &c.evidence {
            println!("    {e}");
        }
    }
    for w in &r.warnings {
        println!("\n{w}");
    }
    println!("\nRESULT: {}", r.overall_label);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messenger_package_option() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            run(&args(&["verify", "--messenger-package", "bad"])),
            exit::USAGE
        );
        assert_eq!(run(&args(&["devices", "--messenger-package"])), exit::USAGE);
    }

    #[test]
    fn version_option() {
        assert_eq!(run(&["--version".to_string()]), exit::OK);
    }
}
