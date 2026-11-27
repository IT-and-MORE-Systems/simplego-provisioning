// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Fake adb for the delivery tests. Test only: built as an example target
//! (`cargo test` builds it), never part of a release (`cargo build --release
//! --bin sxprov`).
//!
//! The tests link this binary into a scenario directory as `adb`. It reads
//! `state.json` next to the name it was started under (argv[0]), answers
//! like a phone with that state, writes the changed state back, and appends
//! every call to `calls.log`: arguments only, never standard input content,
//! the serial written as `<serial>` (or `<OTHER:...>` for any other device),
//! and the activation code written as `<code>`.
//!
//! The activation provider is simulated as the messenger offers it:
//! `status`, `activate` with the code, and optionally the proposed file
//! import. A file sent with `content write` is decrypted with
//! the code (format section 5) to report its `file_id` and `network_mode`.

#[path = "fake_fastboot.rs"]
mod fake_fastboot;
#[path = "fake_screens.rs"]
mod fake_screens;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Dev {
    serial: String,
    state: String,
    model: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Pkg {
    version_code: u64,
    version_name: String,
    /// Signer digest the package manager reports (hex).
    signer: String,
    system: bool,
    /// Copy of the installed file, for `pull`.
    #[serde(skip_serializing_if = "Option::is_none")]
    apk_copy: Option<String>,
    uid: u32,
    /// The name app lists show (Orbot's "Choose apps").
    label: String,
    /// `adb install -i`.
    installer: Option<String>,
    /// Started at least once (`notLaunched=false`).
    launched: bool,
    /// The signature hash `dumpsys package` prints (hex), if any.
    sig_hash: Option<String>,
    /// The `autoVerify` web hosts of its manifest (app link verification).
    web_hosts: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct ApkMeta {
    package: String,
    version_code: u64,
    version_name: String,
    signer: String,
    label: String,
    sig_hash: Option<String>,
    web_hosts: Vec<String>,
}

/// Android's app link verifier.
pub const VERIFIER: &str = "com.android.statementservice";

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Provider {
    /// The provider of today's messenger has no file import.
    file_import: bool,
    activation: bool,
    setup_done: bool,
    /// `activate` answers `result=error: <this>`.
    activate_error: Option<String>,
    pending_file: Option<Vec<u8>>,
    file_id: Option<String>,
    network_mode: Option<String>,
    /// SHA-256 of the last code, so the test can compare it with the shown code.
    code_sha256: Option<String>,
    /// `features_profile` and `features_fixed` of the imported file, as an
    /// app reports them (format document section 12.1).
    features_profile: Option<String>,
    features_fixed: Option<String>,
    /// A test sets this to make the app report another profile.
    report_wrong_profile: bool,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Orbot {
    screen: String,
    boot: bool,
    open_proxy: bool,
    /// Power User Mode: SOCKS without the VPN.
    power: bool,
    port: String,
    field: String,
    connected: bool,
    /// A resource id or title left out of every dump.
    missing: Option<String>,
    /// So many `uiautomator dump` calls fail (after writing the file).
    dump_failures: u32,
    /// The packages on the "Choose apps" list (Orbot's VPN).
    apps: BTreeSet<String>,
    /// The search text of the app list.
    query: String,
    /// Uids the VPN carries besides the list (a wrong list).
    vpn_extra_uids: Vec<u32>,
    /// The list when "Choose apps" was opened.
    apps_on_enter: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct State {
    target: String,
    devices: Vec<Dev>,
    props: BTreeMap<String, String>,
    packages: BTreeMap<String, Pkg>,
    /// By SHA-256 of the file: what installing it gives.
    apks: BTreeMap<String, ApkMeta>,
    whitelist: BTreeSet<String>,
    /// `package:OP` pairs set to allow with `appops set`.
    appops: BTreeSet<String>,
    disabled: BTreeSet<String>,
    provider: Provider,
    settings: BTreeMap<String, String>,
    /// Base64 certificates the agent returns.
    agent_chain: Vec<String>,
    agent_package: String,
    messenger_package: String,
    orbot_package: String,
    orbot: Orbot,
    files: BTreeMap<String, String>,
    /// "install" -> failure text, "content_write" -> error, ...
    fail: BTreeMap<String, String>,
    /// `dumpsys package` reports this signature hash (hex) for the
    /// messenger instead of its certificate's.
    pm_signer_override: Option<String>,
    /// The bootloader side (fake fastboot).
    fastboot: fake_fastboot::Fb,
    /// What the phone is after the flash and its setup.
    after_boot: Option<fake_fastboot::AfterBoot>,
    /// Settings screen shown instead of Orbot: "devopts", "oem_dialog", "pin".
    ui: String,
    devopts: DevOpts,
    /// The F-Droid client.
    fd: fake_screens::Fd,
    /// Lockdown at run time (set only through the Settings screens).
    lockdown_runtime: bool,
    /// The next uid an install gets.
    next_uid: u32,
    /// App ops set to a mode other than allow (`package:OP` -> mode).
    appop_modes: BTreeMap<String, String>,
    /// `[LockdownAlwaysOn] Mode changed` lines, newest first (`dumpsys
    /// vpn_management`).
    vpn_log: Vec<String>,
    /// Seconds for the log's time stamps.
    clock: u32,
    /// Hosts the verifier marked verified: its fetch went out (package ->
    /// hosts), as a fetch that went out leaves them.
    app_links_verified: BTreeMap<String, Vec<String>>,
    /// Packages whose verification waits for a network (lockdown on).
    verifier_waiting: BTreeSet<String>,
    /// TLS sockets the verifier left open to outside addresses.
    verifier_sockets: u32,
}

/// The verifier is there and not disabled.
fn verifier_on(st: &State) -> bool {
    st.packages.contains_key(VERIFIER) && !st.disabled.contains(VERIFIER)
}

/// A mode change of the always-on VPN, as `dumpsys vpn_management` logs it.
fn log_mode(st: &mut State, lockdown: bool, always_on: bool) {
    st.clock += 7;
    let line = format!(
        "      2026-11-25T10:{:02}:{:02}.{:06} - [LockdownAlwaysOn] Mode changed: lockdown={lockdown} alwaysOn={always_on} calling from 1000",
        (st.clock / 60) % 60,
        st.clock % 60,
        st.clock
    );
    st.vpn_log.insert(0, line);
    if !lockdown {
        release_waiting(st);
    }
}

/// Lockdown off: the waiting verifications run at once, over the clear net.
fn release_waiting(st: &mut State) {
    if !verifier_on(st) {
        st.verifier_waiting.clear();
        return;
    }
    for p in std::mem::take(&mut st.verifier_waiting) {
        if let Some(x) = st.packages.get(&p) {
            st.app_links_verified.insert(p.clone(), x.web_hosts.clone());
            st.verifier_sockets += 1;
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct DevOpts {
    oem: bool,
    /// Tapping the switch asks for the PIN first.
    pin: bool,
    /// The switch is greyed out.
    greyed: bool,
}

pub struct Reply {
    out: String,
    err: String,
    code: i32,
}

fn ok(s: impl Into<String>) -> Reply {
    Reply {
        out: s.into(),
        err: String::new(),
        code: 0,
    }
}
fn bad(s: impl Into<String>) -> Reply {
    Reply {
        out: String::new(),
        err: s.into(),
        code: 1,
    }
}

fn sha256_hex(b: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    d.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn base_path(pkg: &str) -> String {
    format!("/data/app/~~TEST==/{pkg}-TEST==/base.apk")
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // The binary's own path (also when started through a link or by PATH).
    let me = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(&argv[0]));
    let dir = me.parent().unwrap_or(Path::new(".")).to_path_buf();
    let state_path = dir.join("state.json");
    let mut st: State =
        serde_json::from_slice(&std::fs::read(&state_path).expect("state.json")).expect("state");
    let args: Vec<String> = argv[1..].to_vec();
    if me.file_name().and_then(|n| n.to_str()) == Some("fastboot") {
        let (line, serial) = fake_fastboot::log_line(&st, &args);
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("calls.log"))
            .expect("log");
        let _ = writeln!(log, "{line}");
        let r = fake_fastboot::handle(&mut st, &args, serial);
        std::fs::write(&state_path, serde_json::to_vec_pretty(&st).unwrap()).unwrap();
        print!("{}", r.out);
        eprint!("{}", r.err);
        std::process::exit(r.code);
    }
    let mut stdin = Vec::new();
    let reads_stdin = args
        .windows(2)
        .any(|w| w[0] == "content" && w[1] == "write");
    if reads_stdin {
        let _ = std::io::stdin().read_to_end(&mut stdin);
    }
    // The log: arguments only, serial and code masked.
    let mut shown: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "-s" && i + 1 < args.len() {
            shown.push("-s".into());
            shown.push(if args[i + 1] == st.target {
                "<serial>".into()
            } else {
                format!("<OTHER:{}>", args[i + 1].len())
            });
            i += 2;
            continue;
        }
        if a == "--arg" && args.iter().any(|x| x == "activate") && i + 1 < args.len() {
            shown.push("--arg".into());
            shown.push("<code>".into());
            i += 2;
            continue;
        }
        shown.push(a.clone());
        i += 1;
    }
    let mut line = format!("adb {}", shown.join(" "));
    if reads_stdin {
        line.push_str(" < (file on standard input)");
    }
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls.log"))
        .expect("log");
    let _ = writeln!(log, "{line}");

    let r = handle(&mut st, &args, &stdin, &dir);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&st).unwrap()).unwrap();
    print!("{}", r.out);
    eprint!("{}", r.err);
    std::process::exit(r.code);
}

fn handle(st: &mut State, args: &[String], stdin: &[u8], dir: &Path) -> Reply {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    if a == ["devices", "-l"] {
        fake_fastboot::maybe_boot(st);
        let mut s = String::from("List of devices attached\n");
        for d in st.devices.iter().filter(|d| d.state != "fastboot") {
            s.push_str(&format!(
                "{}\t{} usb:1-1 product:x model:{} device:x transport_id:1\n",
                d.serial, d.state, d.model
            ));
        }
        return ok(s);
    }
    if a.len() < 3 || a[0] != "-s" {
        return bad("fake adb: unexpected call\n");
    }
    if a[1] != st.target {
        return bad("fake adb: this device must never be addressed\n");
    }
    if !st
        .devices
        .iter()
        .any(|d| d.serial == st.target && d.state == "device")
    {
        return bad(format!("error: device '{}' not found\n", a[1]));
    }
    let rest = &a[2..];
    match rest {
        ["install", tail @ ..] => install(st, tail, dir),
        ["uninstall", p] => {
            if st.packages.remove(*p).is_some() {
                st.whitelist.remove(*p);
                st.orbot.apps.remove(*p);
                if st
                    .settings
                    .get("secure:always_on_vpn_app")
                    .map(String::as_str)
                    == Some(*p)
                {
                    // As Android does when the always-on VPN app is removed.
                    st.settings.remove("secure:always_on_vpn_app");
                    st.settings.remove("secure:always_on_vpn_lockdown");
                    st.lockdown_runtime = false;
                    log_mode(st, false, false);
                }
                if *p == st.orbot_package {
                    st.orbot = Orbot {
                        port: "9050".into(),
                        ..Default::default()
                    };
                    st.appops.retain(|a| !a.starts_with(&format!("{p}:")));
                    st.appop_modes
                        .retain(|a, _| !a.starts_with(&format!("{p}:")));
                }
                ok("Success\n")
            } else {
                bad("Failure [DELETE_FAILED_INTERNAL_ERROR]\n")
            }
        }
        ["pull", remote, local] => {
            let found = st
                .packages
                .iter()
                .find(|(k, _)| base_path(k) == *remote)
                .and_then(|(_, p)| p.apk_copy.clone());
            match found {
                Some(c) => {
                    std::fs::copy(&c, local).unwrap();
                    ok(format!("{remote}: 1 file pulled.\n"))
                }
                None => bad(format!(
                    "adb: error: remote object '{remote}' does not exist\n"
                )),
            }
        }
        ["shell", cmd @ ..] => shell(st, cmd, stdin),
        ["reboot", "bootloader"] => {
            let t = st.target.clone();
            for d in st.devices.iter_mut().filter(|d| d.serial == t) {
                d.state = "fastboot".into();
            }
            st.ui.clear();
            ok("")
        }
        _ => bad("fake adb: unknown command\n"),
    }
}

fn install(st: &mut State, tail: &[&str], dir: &Path) -> Reply {
    let replace = tail.contains(&"-r");
    let installer = tail
        .windows(2)
        .find(|w| w[0] == "-i")
        .map(|w| w[1].to_string());
    let Some(path) = tail.last() else {
        return bad("adb: need APK file\n");
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return bad(format!("adb: failed to stat {path}\n")),
    };
    let sha = sha256_hex(&data);
    let Some(meta) = st.apks.get(&sha).cloned() else {
        return ok("Performing Streamed Install\nadb: failed to install: Failure [INSTALL_PARSE_FAILED_NOT_APK]\n");
    };
    if let Some(f) = st.fail.get(&format!("install:{}", meta.package)) {
        return Reply {
            out: format!("Performing Streamed Install\nadb: failed to install {path}: {f}\n"),
            err: String::new(),
            code: 1,
        };
    }
    if st.packages.contains_key(&meta.package) && !replace {
        return Reply {
            out: format!("Performing Streamed Install\nadb: failed to install {path}: Failure [INSTALL_FAILED_ALREADY_EXISTS: Attempt to re-install {} without first uninstalling.]\n", meta.package),
            err: String::new(),
            code: 1,
        };
    }
    let copy = dir.join(format!("installed-{}.apk", meta.package));
    std::fs::write(&copy, &data).unwrap();
    let uid = match st.packages.get(&meta.package) {
        Some(p) if p.uid != 0 => p.uid,
        _ => {
            st.next_uid = st.next_uid.max(10200) + 1;
            st.next_uid
        }
    };
    st.packages.insert(
        meta.package.clone(),
        Pkg {
            version_code: meta.version_code,
            version_name: meta.version_name.clone(),
            signer: meta.signer.clone(),
            system: false,
            apk_copy: Some(copy.to_string_lossy().to_string()),
            uid,
            label: meta.label.clone(),
            installer,
            launched: false,
            sig_hash: meta.sig_hash.clone(),
            web_hosts: meta.web_hosts.clone(),
        },
    );
    // App link verification at install: the verifier fetches every host at
    // once over a network the system lets it use; under lockdown it waits.
    if !meta.web_hosts.is_empty() && verifier_on(st) {
        st.app_links_verified.remove(&meta.package);
        if st.lockdown_runtime {
            st.verifier_waiting.insert(meta.package.clone());
        } else {
            st.app_links_verified
                .insert(meta.package.clone(), meta.web_hosts.clone());
            st.verifier_sockets += 1;
        }
    }
    ok("Performing Streamed Install\nSuccess\n")
}

fn bundle(pairs: &[(&str, String)]) -> String {
    let inner: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("Result: Bundle[{{{}}}]\n", inner.join(", "))
}

fn yn(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

fn shell(st: &mut State, cmd: &[&str], stdin: &[u8]) -> Reply {
    let messenger = st.messenger_package.clone();
    match cmd {
        ["getprop"] => ok(st
            .props
            .iter()
            .map(|(k, v)| format!("[{k}]: [{v}]\n"))
            .collect::<String>()),
        ["pm", "list", "packages"] => ok(st
            .packages
            .keys()
            .map(|k| format!("package:{k}\n"))
            .collect::<String>()),
        ["pm", "list", "packages", "-U"] => ok(st
            .packages
            .iter()
            .map(|(k, p)| format!("package:{k} uid:{}\n", p.uid))
            .collect::<String>()),
        ["pm", "list", "packages", "-d"] => ok(st
            .disabled
            .iter()
            .filter(|k| st.packages.contains_key(*k))
            .map(|k| format!("package:{k}\n"))
            .collect::<String>()),
        ["pm", "path", p] => match st.packages.get(*p) {
            Some(_) => ok(format!("package:{}\n", base_path(p))),
            None => Reply {
                out: String::new(),
                err: String::new(),
                code: 1,
            },
        },
        ["dumpsys", "package", "providers"] => {
            // The activation provider of the messenger, when it is installed.
            let mut s = String::from("ContentProvider Authorities:\n");
            if st.packages.contains_key(&messenger) {
                s.push_str(&format!(
                    "  [{messenger}.activation]:\n    Provider{{5d6e7f8 {messenger}/.ActivationProvider}}\n"
                ));
            }
            s.push_str("  [com.android.externalstorage.documents]:\n    Provider{9a8b7c6 com.android.externalstorage/.ExternalStorageProvider}\n");
            ok(s)
        }
        ["dumpsys", "package", p] => match st.packages.get(*p) {
            Some(x) => ok(format!(
                "Packages:\n  Package [{p}] (1a2b3c4):\n    versionCode={} minSdk=29 targetSdk=35\n    versionName={}\n    signatures=PackageSignatures{{5d6e7f8 version:3, signatures:[{}], past signatures:[]}}\n    installerPackageName={}\n    User 0: ceDataInode=1 installed=true hidden=false suspended=false distractionFlags=0 stopped={} notLaunched={} enabled=0 instant=false\n",
                x.version_code,
                x.version_name,
                match (&st.pm_signer_override, *p == messenger) {
                    (Some(o), true) => o.as_str(),
                    _ => x.sig_hash.as_deref().unwrap_or("0"),
                },
                x.installer.as_deref().unwrap_or("null"),
                !x.launched && !x.system,
                !x.launched && !x.system
            )),
            None => ok("Dexopt state:\n"),
        },
        ["appops", "set", p, op, mode] => {
            if !st.packages.contains_key(*p) {
                return bad(format!("Unknown package: {p}\n"));
            }
            if st.fail.contains_key(&format!("appops:{op}")) {
                // The system keeps the old mode (the scenario of a refused op).
                return ok("");
            }
            let k = format!("{p}:{op}");
            if *mode == "allow" {
                st.appop_modes.remove(&k);
                st.appops.insert(k);
            } else {
                st.appops.remove(&k);
                st.appop_modes.insert(k, mode.to_string());
            }
            ok("")
        }
        ["appops", "get", p, op] => {
            let k = format!("{p}:{op}");
            if st.appops.contains(&k) {
                ok(format!("{op}: allow; time=+1s ago\n"))
            } else if let Some(m) = st.appop_modes.get(&k) {
                ok(format!("{op}: {m}; rejectTime=+5h11m ago\n"))
            } else {
                ok("No operations.\nDefault mode: default\n")
            }
        }
        ["dumpsys", "deviceidle", "whitelist"] => {
            let mut s = String::from("system-excidle,com.android.shell,2000\n");
            for p in &st.whitelist {
                s.push_str(&format!("user,{p},10234\n"));
            }
            ok(s)
        }
        ["dumpsys", "deviceidle", "whitelist", add] if add.starts_with('+') => {
            let p = &add[1..];
            if st.packages.contains_key(p) {
                st.whitelist.insert(p.to_string());
                ok(format!("Added: {p}\n"))
            } else {
                ok(format!("Unknown package: {p}\n"))
            }
        }
        ["content", "call", "--uri", uri, "--method", m, rest @ ..] => {
            if *uri != format!("content://{messenger}.activation")
                || !st.packages.contains_key(&messenger)
            {
                return Reply {
                    out: String::new(),
                    err: format!("Error while accessing provider:{}\njava.lang.IllegalArgumentException: Unknown authority\n", &uri[10..]),
                    code: 1,
                };
            }
            provider_call(st, m, rest)
        }
        ["content", "write", "--uri", uri] => {
            if !st.packages.contains_key(&messenger) {
                return bad("Error while accessing provider\n");
            }
            if !st.provider.file_import
                || *uri != format!("content://{messenger}.activation/file")
            {
                return bad("java.lang.UnsupportedOperationException: No files supported by provider\n");
            }
            if let Some(e) = st.fail.get("content_write") {
                return bad(format!("{e}\n"));
            }
            st.provider.pending_file = Some(stdin.to_vec());
            ok("")
        }
        ["pm", "disable-user", "--user", "0", p] => {
            if let Some(e) = st.fail.get(&format!("disable:{p}")) {
                return bad(format!("{e}\n"));
            }
            if st.packages.contains_key(*p) {
                if *p == VERIFIER {
                    // Disabling stops its process and cancels its jobs.
                    st.verifier_sockets = 0;
                    st.verifier_waiting.clear();
                }
                st.disabled.insert(p.to_string());
                ok(format!("Package {p} new state: disabled-user\n"))
            } else {
                bad(format!("Error: Unknown package: {p}\n"))
            }
        }
        ["pm", "enable", "--user", "0", p] => {
            if st.packages.contains_key(*p) {
                st.disabled.remove(*p);
                ok(format!("Package {p} new state: enabled\n"))
            } else {
                bad(format!("Error: Unknown package: {p}\n"))
            }
        }
        ["pm", "grant", p, perm] => {
            if st.packages.contains_key(*p) {
                if *p == fake_screens::FD_PKG && *perm == "android.permission.POST_NOTIFICATIONS" {
                    st.fd.notifications = true;
                }
                ok("")
            } else {
                bad("Unknown package\n")
            }
        }
        ["cmd", "package", "resolve-activity", "--brief", "-c", "android.intent.category.LAUNCHER", p] => {
            if st.packages.contains_key(*p) {
                let act = if *p == fake_screens::FD_PKG { "org.fdroid.IconActivity" } else { ".OrbotActivity" };
                ok(format!("priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n{p}/{act}\n"))
            } else {
                ok("No activity found\n")
            }
        }
        ["am", "start", "-n", comp] | ["am", "start", "-S", "-n", comp] => {
            let pkg = comp.split('/').next().unwrap_or_default().to_string();
            if let Some(x) = st.packages.get_mut(&pkg) {
                x.launched = true;
            }
            if pkg == st.orbot_package {
                st.ui.clear();
                st.orbot.screen = "main".into();
            } else if pkg == fake_screens::FD_PKG {
                st.ui = "fdroid_main".into();
            }
            ok(format!("Starting: Intent {{ cmp={comp} }}\n"))
        }
        ["am", "start", "-a", "android.intent.action.VIEW", "-d", uri, "-n", comp] => {
            let pkg = comp.split('/').next().unwrap_or_default().to_string();
            let Some(x) = st.packages.get_mut(&pkg) else {
                return bad("Error: Activity not started, unable to resolve Intent\n");
            };
            x.launched = true;
            st.fd.intent_uri = uri.trim_matches('\'').to_string();
            st.fd.fetch_left = if st.fd.hang_intents > 0 {
                st.fd.hang_intents -= 1;
                u32::MAX
            } else {
                2
            };
            st.ui = "fdroid_add".into();
            ok(format!("Starting: Intent {{ act=android.intent.action.VIEW cmp={comp} }}\n"))
        }
        ["am", "start", "-a", "android.settings.VPN_SETTINGS", "--activity-clear-task"] => {
            st.ui = "vpn_list".into();
            ok("Starting: Intent { act=android.settings.VPN_SETTINGS }\n")
        }
        ["dumpsys", "connectivity"] => ok(fake_screens::connectivity(st)),
        ["dumpsys", "vpn_management"] => {
            let mut s = String::from("VPNs:\n  Lockdown/AlwaysOn logs:\n");
            for l in &st.vpn_log {
                s.push_str(l);
                s.push('\n');
            }
            ok(s)
        }
        ["pm", "get-app-links", "--user", "0", p] => match st.packages.get(*p) {
            Some(x) if !x.web_hosts.is_empty() => {
                let verified = st.app_links_verified.get(*p).cloned().unwrap_or_default();
                let mut s = format!("  {p}:\n    ID: 00000000-0000-0000-0000-000000000000\n    Signatures: [AB:CD]\n    Domain verification state:\n");
                for h in &x.web_hosts {
                    let state = if verified.contains(h) { "verified" } else { "none" };
                    s.push_str(&format!("      {h}: {state}\n"));
                }
                s.push_str("    User 0:\n      Verification link handling allowed: true\n      Selection state:\n        Disabled:\n");
                for h in &x.web_hosts {
                    s.push_str(&format!("          {h}\n"));
                }
                ok(s)
            }
            Some(_) => ok(""),
            None => bad(format!("Error: Unable to find package: {p}\n")),
        },
        ["dumpsys", "jobscheduler", p] if *p == VERIFIER => {
            let uid = st.packages.get(VERIFIER).map(|x| x.uid).unwrap_or(0);
            let mut s = String::from("Settings:\n  conn_update_all_jobs_min_interval_ms=60000\nRegistered jobs:\n");
            if verifier_on(st) {
                for (k, p) in st.verifier_waiting.iter().enumerate() {
                    s.push_str(&format!("  JOB #u0a122/{k}: 1a2b {VERIFIER}/androidx.work.impl.background.systemjob.SystemJobService\n    (work for {p})\n    Required constraints: CONNECTIVITY [0x10000000]\n    Unsatisfied constraints: CONNECTIVITY [0x10000000]\n"));
                }
            }
            s.push_str("Connectivity:\n");
            if st.lockdown_runtime {
                s.push_str(&format!("    UID: {uid}; Network: 100 (blocked=REASON_LOCKDOWN_VPN)\n"));
            } else {
                s.push_str(&format!("    UID: {uid}; Network: 100 (blocked=REASON_NONE)\n"));
            }
            ok(s)
        }
        ["input", "swipe", ..] => {
            if st.ui == "fdroid_settings" {
                st.fd.scrolled += 1;
            }
            ok("")
        }
        ["am", "instrument", rest @ ..] => instrument(st, rest),
        ["am", "start", "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"] => {
            st.ui = "devopts".into();
            ok("Starting: Intent { act=android.settings.APPLICATION_DEVELOPMENT_SETTINGS }\n")
        }
        ["uiautomator", "dump", path] => {
            let xml = if st.ui.starts_with("fdroid") {
                fake_screens::fdroid_dump(st)
            } else if st.ui.starts_with("vpn_") || st.ui == "lock_dialog" {
                fake_screens::vpn_settings_dump(st)
            } else if !st.ui.is_empty() {
                devopts_dump(st)
            } else if st.orbot.screen == "apps" {
                fake_screens::apps_dump(st)
            } else {
                dump(st)
            };
            st.files.insert(path.to_string(), xml);
            if st.orbot.dump_failures > 0 {
                // As on the phone while a screen changes: the file may be
                // written, the command still fails.
                st.orbot.dump_failures -= 1;
                return Reply {
                    out: String::new(),
                    err: "ERROR: could not get idle state.\n".into(),
                    code: 1,
                };
            }
            ok(format!("UI hierchary dumped to: {path}\n"))
        }
        ["cat", "/proc/net/tcp"] => {
            let mut s = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
            let closed = !st.orbot.power && st.fail.contains_key("socks_closed_in_vpn");
            if st.orbot.connected && !closed {
                let port: u16 = st.orbot.port.parse().unwrap_or(0);
                s.push_str(&format!("   0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10240        0 1 1 0000000000000000 100 0 0 10 0\n"));
            }
            ok(s)
        }
        ["cat", "/proc/net/tcp6"] => {
            let mut s = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
            let n = st.verifier_sockets + u32::from(st.fail.contains_key("verifier_socket"));
            if let Some(v) = st.packages.get(VERIFIER) {
                for k in 0..n {
                    // CLOSE_WAIT from 192.0.2.10 to 198.51.100.20:443 (documentation
                    // addresses, RFC 5737), in the format of a phone.
                    s.push_str(&format!("   {k}: 0000000000000000FFFF00000A0200C0:{:04X} 0000000000000000FFFF0000146433C6:01BB 08 00000000:00000000 00:00000000 00000000 {} 0 1 1 0000000000000000\n", 40000 + k, v.uid));
                }
            }
            ok(s)
        }
        ["cat", path] => match st.files.get(*path) {
            Some(x) => ok(x.clone()),
            None => bad(format!("cat: {path}: No such file or directory\n")),
        },
        ["rm", "-f", path] => {
            st.files.remove(*path);
            ok("")
        }
        ["input", "tap", x, y] => {
            let (x, y) = (x.parse().unwrap_or(-1), y.parse().unwrap_or(-1));
            if st.ui.starts_with("fdroid") {
                fake_screens::fdroid_tap(st, x, y);
            } else if st.ui.starts_with("vpn_") || st.ui == "lock_dialog" {
                fake_screens::vpn_settings_tap(st, x, y);
            } else if !st.ui.is_empty() {
                devopts_tap(st, x, y);
            } else if st.orbot.screen == "apps" {
                fake_screens::apps_tap(st, x, y);
            } else {
                tap(st, x, y);
            }
            ok("")
        }
        ["input", "keyevent", keys @ ..] => {
            for k in keys {
                match *k {
                    "KEYCODE_BACK" if st.ui == "pin" || st.ui == "oem_dialog" => {
                        st.ui = "devopts".into()
                    }
                    "KEYCODE_BACK" if st.ui.starts_with("fdroid") => fake_screens::fdroid_back(st),
                    "KEYCODE_BACK" if st.ui == "vpn_orbot" => st.ui = "vpn_list".into(),
                    "KEYCODE_DEL" if st.ui == "fdroid_proxy" => {
                        st.fd.field.pop();
                    }
                    "KEYCODE_DEL" if st.ui.is_empty() && st.orbot.screen == "apps" => {
                        st.orbot.query.pop();
                    }
                    "KEYCODE_BACK" if !st.ui.is_empty() => st.ui.clear(),
                    "KEYCODE_BACK" => back(&mut st.orbot),
                    "KEYCODE_HOME" => {
                        st.ui.clear();
                        st.orbot.screen.clear();
                    }
                    "KEYCODE_DEL" if st.orbot.screen == "dialog" => {
                        st.orbot.field.pop();
                    }
                    _ => {}
                }
            }
            ok("")
        }
        ["input", "text", t] => {
            if st.ui.starts_with("fdroid") {
                fake_screens::fdroid_text(st, t);
            } else if st.ui.is_empty() && st.orbot.screen == "apps" {
                st.orbot.query.push_str(&t.replace("%s", " "));
            } else if st.orbot.screen == "dialog" {
                st.orbot.field.push_str(t);
            }
            ok("")
        }
        ["settings", "put", "global", k, v] => {
            st.settings.insert(k.to_string(), v.to_string());
            if *k == "adb_enabled" && *v == "0" {
                let t = st.target.clone();
                st.devices.retain(|d| d.serial != t);
            }
            ok("")
        }
        ["settings", "get", "global", k] => {
            ok(format!("{}\n", st.settings.get(*k).cloned().unwrap_or("null".into())))
        }
        ["settings", "get", "secure", k] => ok(format!(
            "{}\n",
            st.settings
                .get(&format!("secure:{k}"))
                .cloned()
                .unwrap_or("null".into())
        )),
        ["settings", "put", "secure", k, v] => {
            // Stored, but (as on the phone) no runtime effect is modelled.
            st.settings.insert(format!("secure:{k}"), v.to_string());
            ok("")
        }
        _ => bad(format!("/system/bin/sh: {}: inaccessible or not found\n", cmd.join(" "))),
    }
}

fn provider_call(st: &mut State, m: &str, rest: &[&str]) -> Reply {
    let p = &mut st.provider;
    match (m, rest) {
        ("status", []) => {
            let mut v = vec![
                ("activation", yn(p.activation)),
                (
                    "setup",
                    if p.setup_done { "done" } else { "open" }.to_string(),
                ),
            ];
            if p.file_import {
                v.push(("file_import", "yes".into()));
                if let Some(f) = &p.file_id {
                    v.push(("file_id", f.clone()));
                }
                if let Some(n) = &p.network_mode {
                    v.push(("network_mode", n.clone()));
                }
                if let (Some(fp), Some(ff)) = (&p.features_profile, &p.features_fixed) {
                    let fp = if p.report_wrong_profile {
                        "0000000000000000".to_string()
                    } else {
                        fp.clone()
                    };
                    v.push(("features_profile", fp));
                    v.push(("features_fixed", ff.clone()));
                }
            }
            ok(bundle(&v))
        }
        ("activate", ["--arg", code]) => {
            if let Some(e) = &p.activate_error {
                return ok(bundle(&[("result", format!("error: {e}"))]));
            }
            if p.setup_done {
                return ok(bundle(&[("result", "error: setup already done".into())]));
            }
            if code.len() != 13 {
                return ok(bundle(&[("result", "error: invalid code".into())]));
            }
            if let Some(file) = p.pending_file.take() {
                match decrypt(&file, code.as_bytes()) {
                    Ok((fid, mode, features)) => {
                        p.file_id = Some(fid);
                        p.network_mode = Some(mode);
                        if let Some((fp, ff)) = features {
                            p.features_profile = Some(fp);
                            p.features_fixed = Some(ff);
                        }
                    }
                    Err(e) => return ok(bundle(&[("result", format!("error: {e}"))])),
                }
            }
            p.activation = true;
            p.code_sha256 = Some(sha256_hex(code.as_bytes()));
            ok(bundle(&[("result", "ok".into())]))
        }
        _ => ok(bundle(&[("result", "error: unknown method".into())])),
    }
}

/// The status values of section 12.1, computed as an app does: SHA-256 over
/// the canonical JSON of the object (a `serde_json::Value` map is sorted),
/// first 16 hex characters; the `on` and `off` switches sorted by name.
fn features_status(f: &serde_json::Value) -> Option<(String, String)> {
    let m = f.as_object()?;
    let canon = serde_json::to_vec(f).ok()?;
    let d = ring::digest::digest(&ring::digest::SHA256, &canon);
    let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let fixed: Vec<String> = m
        .iter()
        .filter(|(k, v)| *k != "profile_version" && (*v == "on" || *v == "off"))
        .map(|(k, v)| format!("{k}:{}", v.as_str().unwrap_or("")))
        .collect();
    Some((hex[..16].to_string(), fixed.join(",")))
}

type Imported = (String, String, Option<(String, String)>);

/// Format section 4 and 5: Argon2id from the code, AES-256-GCM, header as AAD.
fn decrypt(file: &[u8], code: &[u8]) -> Result<Imported, String> {
    if file.len() < 66 + 16 + 64 || &file[0..5] != b"SXACT" {
        return Err("bad_format".into());
    }
    let be32 = |i: usize| u32::from_be_bytes([file[i], file[i + 1], file[i + 2], file[i + 3]]);
    let (m, t, lanes) = (be32(7), be32(11), file[15] as u32);
    let ct_len = be32(62) as usize;
    if file.len() != 66 + ct_len + 64 {
        return Err("bad_format".into());
    }
    let params = argon2::Params::new(m, t, lanes, Some(32)).map_err(|e| e.to_string())?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    a2.hash_password_into(code, &file[16..32], &mut key)
        .map_err(|e| e.to_string())?;
    let k = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key).unwrap(),
    );
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&file[33..45]).unwrap();
    let mut ct = file[66..66 + ct_len].to_vec();
    let plain = k
        .open_in_place(nonce, ring::aead::Aad::from(&file[..66]), &mut ct)
        .map_err(|_| "wrong_code".to_string())?;
    let v: serde_json::Value = serde_json::from_slice(plain).map_err(|_| "bad_payload")?;
    Ok((
        v["file_id"].as_str().unwrap_or("").to_string(),
        v["network_mode"].as_str().unwrap_or("").to_string(),
        v.get("features").and_then(features_status),
    ))
}

fn instrument(st: &State, rest: &[&str]) -> Reply {
    if !st.packages.contains_key(&st.agent_package) {
        return ok("INSTRUMENTATION_STATUS: Error=Unable to find instrumentation info\nINSTRUMENTATION_CODE: 0\n");
    }
    // The agent attests only; it takes the challenge and nothing else.
    if rest.contains(&"messenger") {
        return ok("INSTRUMENTATION_STATUS: Error=unexpected argument\nINSTRUMENTATION_CODE: 0\n");
    }
    let mut s =
        String::from("INSTRUMENTATION_RESULT: status=ok\nINSTRUMENTATION_RESULT: keystore=tee\n");
    s.push_str(&format!(
        "INSTRUMENTATION_RESULT: chain_count={}\n",
        st.agent_chain.len()
    ));
    for (i, c) in st.agent_chain.iter().enumerate() {
        s.push_str(&format!("INSTRUMENTATION_RESULT: chain_{i}={c}\n"));
    }
    s.push_str("INSTRUMENTATION_CODE: -1\n");
    ok(s)
}

// ---- Orbot screens (modelled on the real Orbot 17.9.8-RC-1 dumps) ---------
//
// Ids, texts and rough bounds as `uiautomator dump` showed them on a Pixel 6a
// on 2026-11-23. Screens: main, more, settings, general, debug, dialog (SOCKS
// port), alarm (exact-alarm permission dialog), battery (battery dialog),
// vpn (the system VPN consent dialog). Without Power User Mode a connect
// would start the VPN and its consent dialog.

const ORBOT_ID: &str = "org.torproject.android:id/";
const ORBOT_PKG: &str = "org.torproject.android";

#[allow(clippy::too_many_arguments)]
fn node_in(
    pkg: &str,
    text: &str,
    id: &str,
    clickable: bool,
    checkable: bool,
    checked: bool,
    b: (i32, i32, i32, i32),
    kids: &str,
) -> String {
    let attrs = format!(
        "text=\"{}\" resource-id=\"{id}\" class=\"android.view.View\" package=\"{pkg}\" content-desc=\"\" checkable=\"{checkable}\" checked=\"{checked}\" clickable=\"{clickable}\" bounds=\"[{},{}][{},{}]\"",
        text.replace('&', "&amp;").replace('"', "&quot;"),
        b.0,
        b.1,
        b.2,
        b.3
    );
    if kids.is_empty() {
        format!("<node index=\"0\" {attrs} />")
    } else {
        format!("<node index=\"0\" {attrs}>{kids}</node>")
    }
}

fn node(
    text: &str,
    id: &str,
    clickable: bool,
    checkable: bool,
    checked: bool,
    b: (i32, i32, i32, i32),
    kids: &str,
) -> String {
    node_in(ORBOT_PKG, text, id, clickable, checkable, checked, b, kids)
}

type B = (i32, i32, i32, i32);
const SWITCH_CONNECT: B = (327, 1477, 753, 1635);
const STATUS_TITLE: B = (252, 624, 828, 724);
const TAB_CONNECT: B = (160, 2125, 413, 2255);
const TAB_MORE: B = (666, 2125, 919, 2255);
const CARD_SETTINGS: B = (63, 585, 519, 828);
const ROW_GENERAL: B = (0, 279, 1080, 420);
const ROW_DEBUG: B = (0, 1317, 1080, 1458);
const ROW_BOOT: B = (0, 420, 1080, 655);
const ROW_OPEN_PROXY: B = (0, 655, 1080, 890);
const ROW_POWER: B = (0, 890, 1080, 1168);
const ROW_SOCKS: B = (0, 279, 1080, 514);
const EDIT: B = (81, 782, 999, 908);
const DLG_CANCEL: B = (650, 919, 852, 1061);
const DLG_OK: B = (852, 919, 1020, 1061);
const BATTERY_ANYWAY: B = (60, 1408, 452, 1550);
const ALARM_OK: B = (852, 1407, 1020, 1549);

fn dump(st: &State) -> String {
    let o = &st.orbot;
    let skip = |name: &str| o.missing.as_deref() == Some(name);
    let mut kids = String::new();
    let add = |kids: &mut String, name: &str, n: String| {
        if !skip(name) {
            kids.push_str(&n);
        }
    };
    let row = |title: &str, b: B, summary: &str, check: Option<bool>| {
        let mut inner = node(
            title,
            "android:id/title",
            false,
            false,
            false,
            (42, b.1 + 42, 800, b.1 + 99),
            "",
        );
        if !summary.is_empty() {
            inner.push_str(&node(
                summary,
                "android:id/summary",
                false,
                false,
                false,
                (42, b.1 + 99, 912, b.1 + 150),
                "",
            ));
        }
        if let Some(c) = check {
            inner.push_str(&node(
                "",
                "android:id/widget_frame",
                false,
                false,
                false,
                (912, b.1, 1038, b.3),
                &node(
                    "",
                    "android:id/checkbox",
                    false,
                    true,
                    c,
                    (954, b.1 + 75, 1038, b.1 + 159),
                    "",
                ),
            ));
        }
        node("", "", true, false, false, b, &inner)
    };
    let tabs = |kids: &mut String| {
        kids.push_str(&node(
            "",
            &format!("{ORBOT_ID}connectFragment"),
            true,
            false,
            false,
            TAB_CONNECT,
            "",
        ));
        kids.push_str(&node(
            "",
            &format!("{ORBOT_ID}moreFragment"),
            true,
            false,
            false,
            TAB_MORE,
            "",
        ));
    };
    match o.screen.as_str() {
        "main" | "alarm" | "battery" => {
            add(
                &mut kids,
                "Orbot status",
                node(
                    if o.connected {
                        "Connected"
                    } else {
                        "Ready to connect"
                    },
                    &format!("{ORBOT_ID}tvTitle"),
                    false,
                    false,
                    false,
                    STATUS_TITLE,
                    "",
                ),
            );
            if !o.power {
                add(
                    &mut kids,
                    "Full Device VPN",
                    node(
                        "Full Device VPN",
                        &format!("{ORBOT_ID}llBoxShortcutsText"),
                        false,
                        false,
                        false,
                        (451, 904, 693, 947),
                        "",
                    ),
                );
            }
            if !o.power {
                add(
                    &mut kids,
                    "Choose apps",
                    node(
                        "",
                        "",
                        true,
                        false,
                        false,
                        fake_screens::CHOOSE_APPS_ROW,
                        &node(
                            "Choose apps",
                            &format!("{ORBOT_ID}tvLabel"),
                            false,
                            false,
                            false,
                            fake_screens::CHOOSE_APPS,
                            "",
                        ),
                    ),
                );
            }
            add(
                &mut kids,
                &format!("{ORBOT_ID}switchConnect"),
                node(
                    "Connect",
                    &format!("{ORBOT_ID}switchConnect"),
                    true,
                    true,
                    o.connected,
                    SWITCH_CONNECT,
                    "",
                ),
            );
            tabs(&mut kids);
            if o.screen == "alarm" {
                kids.push_str(&node(
                    "Alarms & Reminders Permission Needed for Power User Mode",
                    &format!("{ORBOT_ID}alertTitle"),
                    false,
                    false,
                    false,
                    (91, 955, 989, 1073),
                    "",
                ));
                kids.push_str(&node(
                    "OK",
                    "android:id/button1",
                    true,
                    false,
                    false,
                    ALARM_OK,
                    "",
                ));
            }
            if o.screen == "battery" {
                kids.push_str(&node(
                    "Disable Battery Optimizations",
                    &format!("{ORBOT_ID}alertTitle"),
                    false,
                    false,
                    false,
                    (91, 812, 989, 883),
                    "",
                ));
                kids.push_str(&node(
                    "CONNECT ANYWAY",
                    "android:id/button2",
                    true,
                    false,
                    false,
                    BATTERY_ANYWAY,
                    "",
                ));
            }
        }
        "more" => {
            add(
                &mut kids,
                "Orbot Settings",
                node(
                    "",
                    &format!("{ORBOT_ID}moreActionCard"),
                    true,
                    false,
                    false,
                    CARD_SETTINGS,
                    &node(
                        "Orbot Settings",
                        &format!("{ORBOT_ID}tvLabel"),
                        false,
                        false,
                        false,
                        (187, 743, 395, 786),
                        "",
                    ),
                ),
            );
            tabs(&mut kids);
        }
        "settings" => {
            add(&mut kids, "General", row("General", ROW_GENERAL, "", None));
            add(&mut kids, "Debug", row("Debug", ROW_DEBUG, "", None));
        }
        "general" => {
            add(
                &mut kids,
                "Start Orbot on Boot",
                row(
                    "Start Orbot on Boot",
                    ROW_BOOT,
                    "Automatically start Orbot and connect Tor when your Android device boots",
                    Some(o.boot),
                ),
            );
            add(
                &mut kids,
                "Open Proxy on All Interfaces",
                row(
                    "Open Proxy on All Interfaces",
                    ROW_OPEN_PROXY,
                    "Allow Wi-Fi peers, tethered devices and anyone else who can connect to your IP, to access Tor",
                    Some(o.open_proxy),
                ),
            );
            add(
                &mut kids,
                "Power User Mode",
                row(
                    "Power User Mode",
                    ROW_POWER,
                    "For users familiar with Tor. Allows you to start Orbot without the VPN setting and shows open SOCKS and HTTP ports",
                    Some(o.power),
                ),
            );
        }
        "debug" | "dialog" => {
            add(
                &mut kids,
                "Tor SOCKS",
                row(
                    "Tor SOCKS",
                    ROW_SOCKS,
                    "Port that Tor offers its SOCKS proxy on (default: 9050 or 0 to disable)",
                    None,
                ),
            );
            if o.screen == "dialog" {
                add(
                    &mut kids,
                    "android:id/edit",
                    node(&o.field, "android:id/edit", true, false, false, EDIT, ""),
                );
                kids.push_str(&node(
                    "CANCEL",
                    "android:id/button2",
                    true,
                    false,
                    false,
                    DLG_CANCEL,
                    "",
                ));
                add(
                    &mut kids,
                    "android:id/button1",
                    node("OK", "android:id/button1", true, false, false, DLG_OK, ""),
                );
            }
        }
        "vpn" => {
            kids.push_str(&node_in(
                "com.android.vpndialogs",
                "Connection request",
                "com.android.vpndialogs:id/warning",
                false,
                false,
                false,
                (100, 900, 980, 1200),
                "",
            ));
        }
        _ => {
            kids.push_str(&node_in(
                "com.android.launcher3",
                "Launcher",
                "",
                false,
                false,
                false,
                (0, 0, 1080, 2400),
                "",
            ));
        }
    }
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">{}</hierarchy>",
        node("", "", false, false, false, (0, 0, 1080, 2400), &kids)
    )
}

fn inside(b: B, x: i32, y: i32) -> bool {
    x >= b.0 && x < b.2 && y >= b.1 && y < b.3
}

fn back(o: &mut Orbot) {
    o.screen = match o.screen.as_str() {
        "dialog" => "debug",
        "debug" | "general" => "settings",
        "settings" => "more",
        "alarm" | "battery" | "apps" => "main",
        _ => "",
    }
    .into();
}

fn tap(st: &mut State, x: i32, y: i32) {
    let alarm = st
        .appops
        .contains(&format!("{}:SCHEDULE_EXACT_ALARM", st.orbot_package));
    let consent = st
        .appops
        .contains(&format!("{}:ACTIVATE_VPN", st.orbot_package));
    let excepted = st.whitelist.contains(&st.orbot_package);
    let o = &mut st.orbot;
    let tabs = |o: &mut Orbot| {
        if inside(TAB_CONNECT, x, y) {
            o.screen = "main".into();
        } else if inside(TAB_MORE, x, y) {
            o.screen = "more".into();
        }
    };
    match o.screen.as_str() {
        "main" => {
            if !o.power && inside(fake_screens::CHOOSE_APPS, x, y) {
                o.screen = "apps".into();
                o.query.clear();
                o.apps_on_enter = o.apps.clone();
            } else if inside(SWITCH_CONNECT, x, y) {
                if o.connected {
                    o.connected = false;
                } else if !o.power && consent {
                    o.connected = true;
                } else if !o.power {
                    o.screen = "vpn".into();
                } else if !alarm {
                    o.screen = "alarm".into();
                } else if !excepted {
                    o.screen = "battery".into();
                } else {
                    o.connected = true;
                }
            } else {
                tabs(o);
            }
        }
        "battery" if inside(BATTERY_ANYWAY, x, y) => {
            o.connected = true;
            o.screen = "main".into();
        }
        "alarm" if inside(ALARM_OK, x, y) => {
            // The real app opens the system settings page here.
            o.screen = "".into();
        }
        "more" => {
            if inside(CARD_SETTINGS, x, y) {
                o.screen = "settings".into();
            } else {
                tabs(o);
            }
        }
        "settings" => {
            if inside(ROW_GENERAL, x, y) {
                o.screen = "general".into();
            } else if inside(ROW_DEBUG, x, y) {
                o.screen = "debug".into();
            }
        }
        "general" => {
            if inside(ROW_BOOT, x, y) {
                o.boot = !o.boot;
            } else if inside(ROW_OPEN_PROXY, x, y) {
                o.open_proxy = !o.open_proxy;
            } else if inside(ROW_POWER, x, y) {
                o.power = !o.power;
                // As on the 6a: Orbot asks for the VPN at once; without the
                // app op the system's consent dialog shows.
                if !o.power && !consent {
                    o.screen = "vpn".into();
                }
            }
        }
        "debug" if inside(ROW_SOCKS, x, y) => {
            o.field = o.port.clone();
            o.screen = "dialog".into();
        }
        "dialog" => {
            if inside(DLG_OK, x, y) {
                o.port = o.field.clone();
                o.screen = "debug".into();
            } else if inside(DLG_CANCEL, x, y) {
                o.screen = "debug".into();
            }
        }
        _ => {}
    }
}

// ---- Developer options (Settings), as dumped on a Pixel 6a -------------

const ROW_OEM: B = (0, 1405, 1080, 1597);
const DLG_ENABLE: B = (700, 1500, 1000, 1640);

fn devopts_dump(st: &State) -> String {
    let p = "com.android.settings";
    let mut kids = String::new();
    match st.ui.as_str() {
        "pin" => kids.push_str(&node_in(
            p,
            "Enter your PIN",
            "",
            false,
            false,
            false,
            (100, 600, 980, 700),
            "",
        )),
        "oem_dialog" => {
            kids.push_str(&node_in(
                p,
                "Allow OEM unlocking?",
                "android:id/alertTitle",
                false,
                false,
                false,
                (100, 1100, 980, 1200),
                "",
            ));
            kids.push_str(&node_in(
                p,
                "Enable",
                "android:id/button1",
                true,
                false,
                false,
                DLG_ENABLE,
                "",
            ));
        }
        _ => {
            let en = if st.devopts.greyed { "false" } else { "true" };
            let inner = format!(
                "{}<node index=\"1\" text=\"\" resource-id=\"com.android.settings:id/switchWidget\" class=\"android.widget.Switch\" package=\"{p}\" content-desc=\"\" checkable=\"true\" checked=\"{}\" clickable=\"false\" enabled=\"{en}\" bounds=\"[900,1450][1040,1550]\" />",
                node_in(p, "OEM unlocking", "android:id/title", false, false, false, (42, 1447, 700, 1500), ""),
                st.devopts.oem
            );
            kids.push_str(&format!(
                "<node index=\"0\" text=\"\" resource-id=\"\" class=\"android.widget.LinearLayout\" package=\"{p}\" content-desc=\"\" checkable=\"false\" checked=\"false\" clickable=\"true\" enabled=\"{en}\" bounds=\"[0,1405][1080,1597]\">{inner}</node>"
            ));
        }
    }
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">{}</hierarchy>",
        node_in(p, "", "", false, false, false, (0, 0, 1080, 2400), &kids)
    )
}

fn devopts_tap(st: &mut State, x: i32, y: i32) {
    match st.ui.as_str() {
        "devopts" if inside(ROW_OEM, x, y) && !st.devopts.greyed => {
            if st.devopts.oem {
                st.devopts.oem = false;
            } else if st.devopts.pin {
                st.ui = "pin".into();
            } else {
                st.ui = "oem_dialog".into();
            }
        }
        "oem_dialog" if inside(DLG_ENABLE, x, y) => {
            st.devopts.oem = true;
            st.ui = "devopts".into();
        }
        _ => {}
    }
}
