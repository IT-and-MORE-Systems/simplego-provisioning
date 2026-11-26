// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Device detection over adb and fastboot. Everything here is "reported by the
//! device": it is shown, never treated as proof. Proof comes from attestation.

pub mod parse;

use parse::{Listed, Mode, PackageInfo};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Tools {
    pub adb: String,
    pub fastboot: String,
}

/// Runs a local tool with standard input closed. Only for `--version`,
/// fastboot and the adb functions below; never with a shell string.
pub fn run(program: &str, args: &[&str]) -> Result<Output, String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))
}

fn run_ok(program: &str, args: &[&str]) -> Result<String, String> {
    let out = run(program, args)?;
    if !out.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Like `run`, but the tool is killed after `timeout` (a fastboot call to a
/// device that is not there waits forever).
pub fn run_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    let read = |p: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut p) = p {
                let _ = p.read_to_end(&mut v);
            }
            v
        })
    };
    let out_t = read(child.stdout.take().map(|p| Box::new(p) as _));
    let err_t = read(child.stderr.take().map(|p| Box::new(p) as _));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{program} {} did not finish within {} s and was stopped",
                    args.join(" "),
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("{program}: {e}")),
        }
    };
    Ok(Output {
        status,
        stdout: out_t.join().unwrap_or_default(),
        stderr: err_t.join().unwrap_or_default(),
    })
}

/// Time limit of one fastboot call.
pub const FASTBOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// The one way this tool sends a fastboot command: `fastboot -s <serial>
/// <args...>`, arguments as a list, standard input closed, with a time
/// limit. (The official flash script is the only other fastboot user; it
/// runs with `ANDROID_SERIAL` set to the same serial.)
pub fn fastboot(
    tools: &Tools,
    serial: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Output, String> {
    if tools.fastboot.is_empty() {
        return Err("fastboot is disabled in the config (fastboot_path is empty)".into());
    }
    if serial.is_empty() || !shell_safe(serial) {
        return Err("refusing a fastboot call without a valid serial".into());
    }
    let mut all = vec!["-s", serial];
    all.extend_from_slice(args);
    run_timeout(&tools.fastboot, &all, timeout)
}

/// The one fastboot call without a serial: the device listing.
pub fn fastboot_devices(tools: &Tools) -> Result<String, String> {
    if tools.fastboot.is_empty() {
        return Err("fastboot is disabled in the config (fastboot_path is empty)".into());
    }
    let o = run_timeout(&tools.fastboot, &["devices"], FASTBOOT_TIMEOUT)?;
    if !o.status.success() {
        return Err(format!(
            "fastboot devices failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// `fastboot -s <serial> getvar <var>`; fastboot prints it on stderr.
pub fn fastboot_getvar(tools: &Tools, serial: &str, var: &str) -> Result<Option<String>, String> {
    let o = fastboot(tools, serial, &["getvar", var], FASTBOOT_TIMEOUT)?;
    let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&o.stdout));
    if !o.status.success() {
        return Err(format!("fastboot getvar {var} failed: {}", text.trim()));
    }
    Ok(parse::parse_getvar(&text).get(var).cloned())
}

/// First line of `<tool> --version`, or the error. An empty program name means
/// the tool is disabled in the config.
pub fn tool_version(program: &str) -> Result<String, String> {
    if program.is_empty() {
        return Err("disabled in the config".into());
    }
    let out = run(program, &["--version"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").trim().to_string();
    // adb prints its release version on the second line ("Version 37.0.1-...").
    match lines.next() {
        Some(second) if second.starts_with("Version") => Ok(format!("{first}, {}", second.trim())),
        _ => Ok(first),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MessengerInfo {
    pub package: String,
    pub installed: bool,
    pub version_name: Option<String>,
    pub version_code: Option<u64>,
    /// Signing certificate digest. Not read by `devices`; `verify` reads it
    /// from the pulled `base.apk` and checks it against the package manager's
    /// record (`crate::installed`).
    pub signing_cert_sha256: Option<String>,
    pub signature_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub serial: String,
    pub mode: String,
    pub model: Option<String>,
    pub codename: Option<String>,
    pub manufacturer: Option<String>,
    pub android_version: Option<String>,
    pub build_id: Option<String>,
    pub security_patch: Option<String>,
    pub grapheneos_hint: Option<String>,
    /// Bootloader state as reported by the device. Not verified.
    pub bootloader_reported: BTreeMap<String, String>,
    pub messenger: Option<MessengerInfo>,
    /// The OS as the phone reports it (for the GrapheneOS status lines).
    pub os: crate::grapheneos::status::Installed,
    /// False when the device is only listed: no command was sent to it.
    pub queried: bool,
    pub errors: Vec<String>,
}

pub fn list(tools: &Tools) -> Result<Vec<Listed>, String> {
    let mut all = Vec::new();
    let mut errors = Vec::new();
    match adb_devices(tools) {
        Ok(out) => all.extend(parse::parse_adb_devices(&out)),
        Err(e) => errors.push(e),
    }
    // An empty fastboot path disables fastboot completely.
    if !tools.fastboot.is_empty() {
        match run_ok(&tools.fastboot, &["devices"]) {
            Ok(out) => all.extend(parse::parse_fastboot_devices(&out)),
            Err(e) => errors.push(e),
        }
    }
    let attempted = if tools.fastboot.is_empty() { 1 } else { 2 };
    if errors.len() == attempted {
        return Err(errors.join("; "));
    }
    Ok(all)
}

/// Path of a local file as the adb binary must see it. When this tool runs in
/// WSL and adb is the Windows `adb.exe`, a Linux path is converted with
/// `wslpath -w`; otherwise the path is used as it is.
pub fn path_for_adb(adb: &str, path: &str) -> Result<String, String> {
    if !needs_windows_path(adb, running_in_wsl()) {
        return Ok(path.to_string());
    }
    let out = run("wslpath", &["-w", path])?;
    if !out.status.success() {
        return Err(format!(
            "wslpath -w {path} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() {
        return Err(format!("wslpath -w {path} returned nothing"));
    }
    Ok(p)
}

fn needs_windows_path(adb: &str, in_wsl: bool) -> bool {
    in_wsl && adb.to_ascii_lowercase().ends_with(".exe")
}

pub fn running_in_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// True if `a` may be passed to the phone's shell as one word. `adb shell`
/// joins its arguments with spaces and the phone's shell parses the result,
/// so only characters without a meaning to that shell are allowed.
pub fn shell_safe(a: &str) -> bool {
    !a.is_empty()
        && a.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b':' | b'/' | b'=' | b'+' | b',' | b'@' | b'%' | b'-'
                )
        })
}

/// A word for the phone's shell that holds `?`, `&` or `#` (a URI with a
/// query): single-quoted, so the shell takes it as it is. Only the
/// characters of `shell_safe` and those three are allowed, never a quote.
pub fn quoted(v: &str) -> Result<String, String> {
    let ok = !v.is_empty()
        && v.bytes()
            .all(|b| shell_safe(&(b as char).to_string()) || matches!(b, b'?' | b'&' | b'#'));
    if ok {
        Ok(format!("'{v}'"))
    } else {
        Err(format!("refusing to quote {v:?} for the phone's shell"))
    }
}

/// `shell_safe`, or one word made by `quoted`.
fn shell_word_ok(a: &str) -> bool {
    shell_safe(a)
        || a.len() > 2
            && a.starts_with('\'')
            && a.ends_with('\'')
            && quoted(&a[1..a.len() - 1]).is_ok()
}

fn check_device_args(serial: &str, args: &[&str]) -> Result<(), String> {
    if serial.is_empty() || !shell_safe(serial) {
        return Err("refusing an adb call without a valid serial".into());
    }
    if args.first() == Some(&"shell") || args.first() == Some(&"exec-out") {
        if args.len() < 2 {
            return Err("refusing an empty adb shell command".into());
        }
        if let Some(bad) = args[1..].iter().find(|a| !shell_word_ok(a)) {
            return Err(format!(
                "refusing an adb shell argument with characters the phone's shell would interpret: {bad:?}"
            ));
        }
    }
    Ok(())
}

/// The one way this tool sends a command to a device: `adb -s <serial>
/// <args...>`, arguments as a list, standard input closed (`</dev/null`).
pub fn adb(tools: &Tools, serial: &str, args: &[&str]) -> Result<Output, String> {
    check_device_args(serial, args)?;
    let mut all = vec!["-s", serial];
    all.extend_from_slice(args);
    run(&tools.adb, &all)
}

/// Like `adb`, but `stdin` is the only content of standard input (for
/// `content write`). Nothing else ever gets an open standard input.
pub fn adb_with_stdin(
    tools: &Tools,
    serial: &str,
    args: &[&str],
    stdin: &[u8],
) -> Result<Output, String> {
    check_device_args(serial, args)?;
    let mut all = vec!["-s", serial];
    all.extend_from_slice(args);
    let mut child = Command::new(&tools.adb)
        .args(&all)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", tools.adb))?;
    let mut pipe = child.stdin.take().ok_or("no standard input pipe")?;
    let data = stdin.to_vec();
    // Written from a thread so a full output pipe cannot block the writer.
    let writer = std::thread::spawn(move || {
        let r = pipe.write_all(&data);
        drop(pipe);
        r
    });
    let out = child
        .wait_with_output()
        .map_err(|e| format!("adb failed: {e}"))?;
    writer
        .join()
        .map_err(|_| "writer thread failed".to_string())?
        .map_err(|e| format!("cannot write to adb: {e}"))?;
    Ok(out)
}

/// `adb` that requires exit status 0 and returns standard output.
pub fn adb_ok(tools: &Tools, serial: &str, args: &[&str]) -> Result<String, String> {
    let out = adb(tools, serial, args)?;
    if !out.status.success() {
        return Err(format!(
            "adb {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn adb_shell(tools: &Tools, serial: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["shell"];
    args.extend_from_slice(cmd);
    adb_ok(tools, serial, &args)
}

/// The one adb call without a serial: the device listing.
pub fn adb_devices(tools: &Tools) -> Result<String, String> {
    run_ok(&tools.adb, &["devices", "-l"])
}

pub fn getprops(tools: &Tools, serial: &str) -> Result<BTreeMap<String, String>, String> {
    adb_shell(tools, serial, &["getprop"]).map(|o| parse::parse_getprop(&o))
}

pub fn package_info(
    tools: &Tools,
    serial: &str,
    package: &str,
) -> Result<Option<PackageInfo>, String> {
    let path = adb_shell(tools, serial, &["pm", "path", package]).unwrap_or_default();
    if !path.lines().any(|l| l.starts_with("package:")) {
        return Ok(None);
    }
    let dump = adb_shell(tools, serial, &["dumpsys", "package", package])?;
    Ok(Some(
        parse::parse_dumpsys_package(&dump, package).unwrap_or_default(),
    ))
}

/// What the device listing alone says. Sends no command to the device.
pub fn listed_only(d: &Listed) -> DeviceInfo {
    DeviceInfo {
        serial: d.serial.clone(),
        mode: d.mode.as_str().to_string(),
        model: d.attrs.get("model").map(|m| m.replace('_', " ")),
        codename: d.attrs.get("device").cloned(),
        manufacturer: None,
        android_version: None,
        build_id: None,
        security_patch: None,
        grapheneos_hint: None,
        bootloader_reported: BTreeMap::new(),
        messenger: None,
        os: Default::default(),
        queried: false,
        errors: Vec::new(),
    }
}

/// Which listed devices may be queried. Other devices may belong to someone
/// else on a shared machine, so the tool sends commands to one device only:
/// the one chosen with `--serial`, or the only device if exactly one is listed.
pub fn select_for_query<'a>(
    listed: &'a [Listed],
    serial: Option<&str>,
) -> Result<Option<&'a Listed>, String> {
    match serial {
        Some(s) => {
            let m: Vec<&Listed> = listed.iter().filter(|d| d.serial == s).collect();
            match m.as_slice() {
                [d] => Ok(Some(*d)),
                [] => Err("no listed device has the given serial".into()),
                _ => Err("the given serial is listed more than once".into()),
            }
        }
        None if listed.len() == 1 => Ok(listed.first()),
        None => Ok(None),
    }
}

/// Describes the device; `messenger_package`: the messenger to look up, if
/// one is known.
pub fn describe(tools: &Tools, d: &Listed, messenger_package: Option<&str>) -> DeviceInfo {
    let mut info = listed_only(d);
    info.queried = true;
    match d.mode {
        Mode::Adb => describe_adb(tools, d, messenger_package, &mut info),
        Mode::Fastboot => describe_fastboot(tools, d, &mut info),
        _ => {}
    }
    info
}

fn describe_adb(tools: &Tools, d: &Listed, messenger_package: Option<&str>, info: &mut DeviceInfo) {
    match getprops(tools, &d.serial) {
        Ok(p) => {
            let g = |k: &str| p.get(k).filter(|v| !v.is_empty()).cloned();
            info.model = g("ro.product.model").or(info.model.take());
            info.codename = g("ro.product.device").or(info.codename.take());
            info.manufacturer = g("ro.product.manufacturer");
            info.android_version = g("ro.build.version.release");
            info.build_id = g("ro.build.id");
            info.security_patch = g("ro.build.version.security_patch");
            info.grapheneos_hint = parse::grapheneos_hint(&p);
            info.os = crate::grapheneos::status::Installed::from_props(&p);
            for k in [
                "ro.boot.flash.locked",
                "ro.boot.verifiedbootstate",
                "ro.boot.vbmeta.device_state",
            ] {
                if let Some(v) = g(k) {
                    info.bootloader_reported.insert(k.to_string(), v);
                }
            }
        }
        Err(e) => info.errors.push(e),
    }
    let Some(messenger_package) = messenger_package else {
        return;
    };
    match package_info(tools, &d.serial, messenger_package) {
        Ok(p) => {
            info.messenger = Some(MessengerInfo {
                package: messenger_package.to_string(),
                installed: p.is_some(),
                version_name: p.as_ref().and_then(|x| x.version_name.clone()),
                version_code: p.as_ref().and_then(|x| x.version_code),
                signing_cert_sha256: None,
                signature_note: if p.is_some() {
                    "not read here; `verify` reads it from the installed base.apk".into()
                } else {
                    "not installed".into()
                },
            })
        }
        Err(e) => info.errors.push(e),
    }
}

fn describe_fastboot(tools: &Tools, d: &Listed, info: &mut DeviceInfo) {
    // getvar writes to stderr.
    match fastboot(tools, &d.serial, &["getvar", "all"], FASTBOOT_TIMEOUT) {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stdout));
            let v = parse::parse_getvar(&text);
            info.codename = v.get("product").cloned();
            for k in ["unlocked", "secure", "version-bootloader", "current-slot"] {
                if let Some(val) = v.get(k) {
                    info.bootloader_reported
                        .insert(format!("fastboot {k}"), val.clone());
                }
            }
            if !v.contains_key("unlocked") {
                info.errors
                    .push("fastboot getvar all did not report `unlocked`".into());
            }
        }
        Err(e) => info.errors.push(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_path_only_for_windows_adb_in_wsl() {
        let win = "/mnt/c/Users/u/AppData/Local/Android/Sdk/platform-tools/adb.exe";
        assert!(needs_windows_path(win, true));
        assert!(!needs_windows_path(win, false));
        assert!(!needs_windows_path("adb", true));
        assert!(!needs_windows_path("/usr/bin/adb", true));
    }

    #[test]
    fn only_the_chosen_device_is_queried() {
        let l = parse::parse_adb_devices(include_str!(
            "../../tests/fixtures/device/adb-devices-l.txt"
        ));
        assert_eq!(l.len(), 4);
        // Several devices and no serial: none is queried.
        assert!(select_for_query(&l, None).unwrap().is_none());
        // A serial picks exactly that device.
        let d = select_for_query(&l, Some("XXXXXXXXXXB2")).unwrap().unwrap();
        assert_eq!(d.serial, "XXXXXXXXXXB2");
        assert!(select_for_query(&l, Some("nope")).is_err());
        // A single device is queried without a serial.
        assert_eq!(
            select_for_query(&l[..1], None).unwrap().unwrap().serial,
            "XXXXXXXXXXA1"
        );
        assert!(!listed_only(&l[0]).queried);
    }

    #[test]
    fn device_calls_need_a_serial_and_shell_safe_words() {
        let t = Tools {
            adb: "/nonexistent/adb".into(),
            fastboot: String::new(),
        };
        for bad in [
            "a;b", "$(id)", "x y", "a'b", "*", "a|b", "a>b", "`x`", "a&b", "",
        ] {
            assert!(!shell_safe(bad), "{bad:?}");
            let e = adb(&t, "SERIAL1", &["shell", "echo", bad]).unwrap_err();
            assert!(e.contains("refusing"), "{e}");
        }
        for good in [
            "482917x305186",
            "482917:305186",
            "+org.example.messenger",
            "content://org.example.messenger.activation",
            "KEYCODE_DEL",
            "--user",
        ] {
            assert!(shell_safe(good), "{good}");
        }
        // A URI with a query goes only single-quoted, never with a quote in it.
        let q = quoted("fdroidrepos://a.b/repo?fingerprint=AB12&x=1#y").unwrap();
        assert_eq!(q, "'fdroidrepos://a.b/repo?fingerprint=AB12&x=1#y'");
        assert!(shell_word_ok(&q));
        for bad in ["a'b", "a b", "$(id)", "a;b", "", "`x`", r"a\b"] {
            assert!(quoted(bad).is_err(), "{bad:?}");
        }
        for bad in ["'a b'", "'a'b'", "'$(id)'", "''", "'a?b", "a?b"] {
            assert!(!shell_word_ok(bad), "{bad:?}");
        }
        assert!(adb(&t, "", &["shell", "getprop"])
            .unwrap_err()
            .contains("serial"));
        assert!(adb(&t, "A B", &["shell", "getprop"])
            .unwrap_err()
            .contains("serial"));
        assert!(adb(&t, "SERIAL1", &["shell"])
            .unwrap_err()
            .contains("empty"));
        // Not a shell command: a local path may hold any character.
        assert!(adb(&t, "SERIAL1", &["install", "/tmp/a b.apk"])
            .unwrap_err()
            .contains("cannot run"));
    }

    #[test]
    fn fastboot_calls_need_a_serial_and_time_out() {
        let t = Tools {
            adb: "/nonexistent/adb".into(),
            fastboot: "/nonexistent/fastboot".into(),
        };
        assert!(fastboot(&t, "", &["getvar", "unlocked"], FASTBOOT_TIMEOUT)
            .unwrap_err()
            .contains("serial"));
        assert!(fastboot(&t, "A B", &["reboot"], FASTBOOT_TIMEOUT)
            .unwrap_err()
            .contains("serial"));
        let off = Tools {
            adb: "adb".into(),
            fastboot: String::new(),
        };
        assert!(fastboot_devices(&off).unwrap_err().contains("disabled"));
        #[cfg(unix)]
        {
            let e = run_timeout("sleep", &["5"], Duration::from_millis(300)).unwrap_err();
            assert!(e.contains("did not finish"), "{e}");
            let o = run_timeout(
                "sh",
                &["-c", "echo out; echo err >&2; exit 3"],
                FASTBOOT_TIMEOUT,
            )
            .unwrap();
            assert_eq!(o.status.code(), Some(3));
            assert_eq!(
                o.stdout,
                b"out
"
            );
            assert_eq!(
                o.stderr,
                b"err
"
            );
        }
    }

    #[test]
    fn disabled_fastboot_is_not_run() {
        let t = Tools {
            adb: "/nonexistent/adb".into(),
            fastboot: String::new(),
        };
        assert!(tool_version(&t.fastboot).is_err());
        // adb cannot run and fastboot is disabled: listing fails, nothing else runs.
        assert!(list(&t).is_err());
    }
}
