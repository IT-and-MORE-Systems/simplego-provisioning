// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Parsers for adb and fastboot output. Pure functions, tested against
//! recorded sample output in `tests/fixtures/device/` (serials masked).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Adb,
    Fastboot,
    Unauthorized,
    Offline,
    /// Another state reported by adb (for example "no permissions").
    Other(String),
}

impl Mode {
    pub fn as_str(&self) -> &str {
        match self {
            Mode::Adb => "adb",
            Mode::Fastboot => "fastboot",
            Mode::Unauthorized => "unauthorized",
            Mode::Offline => "offline",
            Mode::Other(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub serial: String,
    pub mode: Mode,
    /// `key:value` attributes from `adb devices -l` (product, model, device, ...).
    pub attrs: BTreeMap<String, String>,
}

/// Parses `adb devices -l`.
pub fn parse_adb_devices(out: &str) -> Vec<Listed> {
    let mut v = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty()
            || line.starts_with("List of devices")
            || line.starts_with("* ")
            || line.starts_with("adb ")
        {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(serial) = it.next() else { continue };
        let rest: Vec<&str> = it.collect();
        // The state may be several words ("no permissions (...)"); attributes are key:value.
        let state_words: Vec<&str> = rest.iter().take_while(|w| !is_attr(w)).copied().collect();
        let state = state_words.join(" ");
        let mode = match state.as_str() {
            "device" => Mode::Adb,
            "unauthorized" => Mode::Unauthorized,
            "offline" => Mode::Offline,
            "" => continue,
            s => Mode::Other(s.to_string()),
        };
        let attrs = rest
            .iter()
            .skip(state_words.len())
            .filter_map(|w| w.split_once(':'))
            .map(|(k, val)| (k.to_string(), val.to_string()))
            .collect();
        v.push(Listed {
            serial: serial.to_string(),
            mode,
            attrs,
        });
    }
    v
}

fn is_attr(w: &str) -> bool {
    matches!(
        w.split_once(':'),
        Some((k, _)) if ["usb", "product", "model", "device", "transport_id"].contains(&k)
    )
}

/// Parses `fastboot devices` (also `-l`).
pub fn parse_fastboot_devices(out: &str) -> Vec<Listed> {
    out.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let serial = it.next()?;
            let state = it.next()?;
            if state != "fastboot" && state != "fastbootd" {
                return None;
            }
            Some(Listed {
                serial: serial.to_string(),
                mode: Mode::Fastboot,
                attrs: BTreeMap::new(),
            })
        })
        .collect()
}

/// Parses `adb shell getprop` (`[key]: [value]` per line).
pub fn parse_getprop(out: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in out.lines() {
        let line = line.trim_end_matches('\r');
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some((key, rest)) = rest.split_once("]: [") else {
            continue;
        };
        let Some(val) = rest.strip_suffix(']') else {
            continue;
        };
        m.insert(key.to_string(), val.to_string());
    }
    m
}

/// Parses `fastboot getvar all` (written to stderr as `(bootloader) key:value`).
/// Also accepts the single-variable form `key: value`.
pub fn parse_getvar(out: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in out.lines() {
        let line = line.trim_end_matches('\r').trim();
        let body = line
            .strip_prefix("(bootloader)")
            .map(str::trim)
            .unwrap_or(line);
        if body.starts_with("Finished.") || body.starts_with("all:") || body.starts_with("getvar:")
        {
            continue;
        }
        if let Some((k, v)) = body.split_once(':') {
            let k = k.trim();
            if k.is_empty() || k.contains(' ') {
                continue;
            }
            m.entry(k.to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    m
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageInfo {
    pub version_name: Option<String>,
    pub version_code: Option<u64>,
}

/// Parses `adb shell dumpsys package <pkg>`. Returns None if the package is
/// not listed in the output.
pub fn parse_dumpsys_package(out: &str, package: &str) -> Option<PackageInfo> {
    let header = format!("Package [{package}]");
    let start = out.find(&header)?;
    let block = &out[start + header.len()..];
    // The block ends at the next package header.
    let block = match block.find("Package [") {
        Some(end) => &block[..end],
        None => block,
    };
    let mut info = PackageInfo::default();
    for tok in block.split_whitespace() {
        if let Some(v) = tok.strip_prefix("versionCode=") {
            if info.version_code.is_none() {
                info.version_code = v.parse().ok();
            }
        } else if let Some(v) = tok.strip_prefix("versionName=") {
            if info.version_name.is_none() {
                info.version_name = Some(v.to_string());
            }
        }
    }
    Some(info)
}

/// GrapheneOS hint from build properties. Only a hint: proof is attestation.
/// GrapheneOS keeps the stock build properties (user, host, fingerprint), so
/// the hint rests on its release number format (YYYYMMDDNN in
/// ro.build.display.id) together with a locked bootloader on a custom
/// verified boot key (state yellow).
pub fn grapheneos_hint(props: &BTreeMap<String, String>) -> Option<String> {
    let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
    let display = get("ro.build.display.id");
    let release_number = display.len() == 10 && display.bytes().all(|b| b.is_ascii_digit());
    let custom_key_locked =
        get("ro.boot.verifiedbootstate") == "yellow" && get("ro.boot.flash.locked") == "1";
    match (release_number, custom_key_locked) {
        (true, true) => Some(format!(
            "build number {display} has the GrapheneOS release format; locked bootloader with a custom verified boot key (yellow)"
        )),
        (true, false) => Some(format!("build number {display} has the GrapheneOS release format")),
        (false, true) => Some("locked bootloader with a custom verified boot key (yellow)".into()),
        (false, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADB: &str = include_str!("../../tests/fixtures/device/adb-devices-l.txt");
    const FB: &str = include_str!("../../tests/fixtures/device/fastboot-devices.txt");
    const PROPS: &str = include_str!("../../tests/fixtures/device/getprop-pixel.txt");
    const GETVAR: &str = include_str!("../../tests/fixtures/device/fastboot-getvar-all.txt");
    const DUMPSYS: &str = include_str!("../../tests/fixtures/device/dumpsys-package.txt");

    #[test]
    fn adb_devices() {
        let d = parse_adb_devices(ADB);
        assert_eq!(d.len(), 4);
        assert_eq!(d[0].mode, Mode::Adb);
        assert_eq!(d[0].attrs["model"], "Pixel_8");
        assert_eq!(d[0].attrs["device"], "shiba");
        assert_eq!(d[1].mode, Mode::Unauthorized);
        assert_eq!(d[2].mode, Mode::Offline);
        assert!(matches!(&d[3].mode, Mode::Other(s) if s.starts_with("no permissions")));
        assert_eq!(d[3].attrs["usb"], "1-4");
    }

    #[test]
    fn adb_devices_empty() {
        assert!(parse_adb_devices("List of devices attached\n\n").is_empty());
    }

    #[test]
    fn fastboot_devices() {
        let d = parse_fastboot_devices(FB);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|x| x.mode == Mode::Fastboot));
    }

    #[test]
    fn getprop() {
        let p = parse_getprop(PROPS);
        assert_eq!(p["ro.product.model"], "Pixel 8");
        assert_eq!(p["ro.product.device"], "shiba");
        assert_eq!(p["ro.boot.flash.locked"], "1");
        assert_eq!(p["ro.boot.verifiedbootstate"], "yellow");
        assert!(grapheneos_hint(&p).unwrap().contains("2026010100"));
        let mut stock = p.clone();
        stock.insert("ro.build.display.id".into(), "CP3A.261005.002.A1".into());
        stock.insert("ro.boot.verifiedbootstate".into(), "green".into());
        assert!(grapheneos_hint(&stock).is_none());
    }

    #[test]
    fn getvar() {
        let v = parse_getvar(GETVAR);
        assert_eq!(v["unlocked"], "no");
        assert_eq!(v["product"], "shiba");
        assert_eq!(v["secure"], "yes");
        assert!(!v.contains_key("Finished. Total time"));
        assert_eq!(
            parse_getvar("unlocked: yes\nFinished. Total time: 0.001s\n")["unlocked"],
            "yes"
        );
    }

    #[test]
    fn dumpsys() {
        let i = parse_dumpsys_package(DUMPSYS, "org.example.messenger").unwrap();
        assert_eq!(i.version_code, Some(7014));
        assert_eq!(i.version_name.as_deref(), Some("7.1.4"));
        assert!(parse_dumpsys_package(DUMPSYS, "com.example.absent").is_none());
        assert!(parse_dumpsys_package("Unable to find package: x\n", "x").is_none());
    }
}
