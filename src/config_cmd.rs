// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `config show` and `config set KEY VALUE`: the settings the assistant
//! shows on its settings page, read and written through `sxprov` with
//! `--json`. Only the keys in `SETTINGS`; none of them holds a secret (the
//! config file holds no passphrase or key at all). A new value is checked
//! alone, then the whole file with it is parsed and validated as `sxprov`
//! would load it; only then is it written (temporary file, rename, same
//! mode). Other lines and comments stay as they are.

use crate::config::Config;
use crate::{exit, names};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
enum Kind {
    Text,
    /// May be empty (empty disables the tool).
    TextOrEmpty,
    Path,
    Choice(&'static [&'static str]),
    Days,
    /// Seconds within the config limits of the confirmation wait.
    Seconds,
    Sha256OrEmpty,
    Package,
    Socks,
    /// `https://...` without a trailing slash.
    Https,
}

struct Setting {
    key: &'static str,
    kind: Kind,
    about: &'static str,
}

const SETTINGS: &[Setting] = &[
    Setting {
        key: "grapheneos_release",
        kind: Kind::Choice(&["newest", "stable"]),
        about: "which GrapheneOS build counts as current and is flashed by default: newest (the security preview build when there is one) or stable",
    },
    Setting {
        key: "grapheneos_channel",
        kind: Kind::Choice(&["stable", "beta", "alpha"]),
        about: "GrapheneOS release channel",
    },
    Setting {
        key: "tor_socks_proxy",
        kind: Kind::Socks,
        about: "Tor SOCKS proxy for every download (socks5h://HOST:PORT, no clearnet fallback)",
    },
    Setting {
        key: "adb_path",
        kind: Kind::Text,
        about: "adb binary",
    },
    Setting {
        key: "fastboot_path",
        kind: Kind::TextOrEmpty,
        about: "fastboot binary (35.0.1 or newer); empty disables fastboot",
    },
    Setting {
        key: "grapheneos_cache_dir",
        kind: Kind::Path,
        about: "folder for channel files and verified factory images (on WSL with fastboot.exe: on a Windows drive)",
    },
    Setting {
        key: "max_os_age_days",
        kind: Kind::Days,
        about: "deliver refuses a phone more than this many days behind the stable channel",
    },
    Setting {
        key: "flash_confirm_timeout_secs",
        kind: Kind::Seconds,
        about: "how long flash waits for the bootloader unlock and lock to be confirmed on the phone, in seconds",
    },
    Setting {
        key: "orbot_package",
        kind: Kind::Package,
        about: "Orbot package name",
    },
    Setting {
        key: "orbot_signing_cert_sha256",
        kind: Kind::Sha256OrEmpty,
        about: "pinned Orbot signing certificate SHA-256 (64 hex digits; empty refuses --orbot-apk)",
    },
    Setting {
        key: "fdroid_package",
        kind: Kind::Package,
        about: "F-Droid client package name",
    },
    Setting {
        key: "fdroid_signing_cert_sha256",
        kind: Kind::Sha256OrEmpty,
        about: "pinned F-Droid client signing certificate SHA-256 (64 hex digits; empty refuses --fdroid-apk)",
    },
    Setting {
        key: "simplex_repo_url",
        kind: Kind::Https,
        about: "SimpleX's own F-Droid repository (https://, no trailing slash)",
    },
    Setting {
        key: "simplex_repo_fingerprint",
        kind: Kind::Sha256OrEmpty,
        about: "pinned fingerprint of SimpleX's repository (SHA-256 of its index signing certificate; empty refuses the SimpleX app step)",
    },
    Setting {
        key: "simplex_app_package",
        kind: Kind::Package,
        about: "package name of the normal SimpleX app",
    },
    Setting {
        key: "simplex_app_signing_cert_sha256",
        kind: Kind::Sha256OrEmpty,
        about: "pinned signing certificate SHA-256 of the normal SimpleX app (empty refuses the SimpleX app step)",
    },
    Setting {
        key: "system_calculator_package",
        kind: Kind::Package,
        about: "system calculator hidden at delivery",
    },
];

fn setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|s| s.key == key)
}

fn current(cfg: &Config, key: &str) -> Value {
    match key {
        "grapheneos_release" => json!(cfg.grapheneos_release),
        "grapheneos_channel" => json!(cfg.grapheneos_channel),
        "tor_socks_proxy" => json!(cfg.tor_socks_proxy),
        "adb_path" => json!(cfg.adb_path),
        "fastboot_path" => json!(cfg.fastboot_path),
        "grapheneos_cache_dir" => json!(cfg.grapheneos_cache().ok()),
        "max_os_age_days" => json!(cfg.max_os_age_days),
        "flash_confirm_timeout_secs" => json!(cfg.flash_confirm_timeout_secs),
        "orbot_package" => json!(cfg.orbot_package),
        "orbot_signing_cert_sha256" => json!(cfg.orbot_signing_cert_sha256),
        "system_calculator_package" => json!(cfg.system_calculator_package),
        "fdroid_package" => json!(cfg.fdroid_package),
        "fdroid_signing_cert_sha256" => json!(cfg.fdroid_signing_cert_sha256),
        "simplex_repo_url" => json!(cfg.simplex_repo_url),
        "simplex_repo_fingerprint" => json!(cfg.simplex_repo_fingerprint),
        "simplex_app_package" => json!(cfg.simplex_app_package),
        "simplex_app_signing_cert_sha256" => json!(cfg.simplex_app_signing_cert_sha256),
        _ => Value::Null,
    }
}

fn kind_str(k: Kind) -> Value {
    match k {
        Kind::Text => json!({"type": "string"}),
        Kind::TextOrEmpty => json!({"type": "string", "empty_allowed": true}),
        Kind::Path => json!({"type": "path"}),
        Kind::Choice(c) => json!({"type": "choice", "values": c}),
        Kind::Days => json!({"type": "integer", "min": 1, "max": 3650}),
        Kind::Seconds => json!({"type": "integer", "min": crate::config::CONFIRM_TIMEOUT_MIN,
                                "max": crate::config::CONFIRM_TIMEOUT_MAX, "unit": "seconds"}),
        Kind::Sha256OrEmpty => json!({"type": "sha256", "empty_allowed": true}),
        Kind::Package => json!({"type": "package"}),
        Kind::Socks => json!({"type": "socks5h"}),
        Kind::Https => json!({"type": "https_url"}),
    }
}

/// The line of `key` (not a comment), if the file sets it.
fn find_line(text: &str, key: &str) -> Option<usize> {
    text.lines().position(|l| {
        let t = l.trim_start();
        t.strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    })
}

fn toml_string(v: &str) -> String {
    let mut s = String::from("\"");
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// Checks the value alone and returns its TOML form.
fn literal(k: Kind, v: &str) -> Result<String, String> {
    if v.chars().any(|c| c.is_control()) {
        return Err("control characters are not allowed".into());
    }
    match k {
        Kind::Text | Kind::Path if v.is_empty() => Err("must not be empty".into()),
        Kind::Text | Kind::TextOrEmpty | Kind::Path => Ok(toml_string(v)),
        Kind::Choice(c) if c.contains(&v) => Ok(toml_string(v)),
        Kind::Choice(c) => Err(format!("must be one of {}", c.join(", "))),
        Kind::Days => match v.parse::<u64>() {
            Ok(n) if (1..=3650).contains(&n) => Ok(n.to_string()),
            _ => Err("must be a whole number of days from 1 to 3650".into()),
        },
        Kind::Seconds => {
            use crate::config::{CONFIRM_TIMEOUT_MAX as MAX, CONFIRM_TIMEOUT_MIN as MIN};
            match v.parse::<u64>() {
                Ok(n) if (MIN..=MAX).contains(&n) => Ok(n.to_string()),
                _ => Err(format!(
                    "must be a whole number of seconds from {MIN} to {MAX}"
                )),
            }
        }
        Kind::Sha256OrEmpty if v.is_empty() || (crate::util::is_sha256_hex(v) && v.len() == 64) => {
            Ok(toml_string(&v.to_ascii_lowercase()))
        }
        Kind::Sha256OrEmpty => Err("must be 64 hex digits or empty".into()),
        Kind::Package if crate::agent::valid_package(v) => Ok(toml_string(v)),
        Kind::Package => Err("must be a package name".into()),
        Kind::Https => {
            if !v.starts_with("https://")
                || v.len() <= "https://".len()
                || v.ends_with('/')
                || v.contains(char::is_whitespace)
            {
                return Err("must be an https:// URL without a trailing slash".into());
            }
            Ok(toml_string(v))
        }
        Kind::Socks => {
            let rest = v
                .strip_prefix("socks5h://")
                .ok_or("must be socks5h://HOST:PORT (DNS through Tor)")?;
            let (host, port) = rest.rsplit_once(':').ok_or("needs :PORT")?;
            if host.is_empty() || port.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
                return Err("must be socks5h://HOST:PORT with a port from 1 to 65535".into());
            }
            Ok(toml_string(v))
        }
    }
}

/// The file text with `key = literal` set (replacing the line, or added).
pub fn with_value(text: &str, key: &str, lit: &str) -> String {
    let line = format!("{key} = {lit}");
    let mut lines: Vec<&str> = text.lines().collect();
    match find_line(text, key) {
        Some(i) => {
            lines[i] = &line;
            let mut s = lines.join("\n");
            s.push('\n');
            s
        }
        None => {
            let mut s = text.to_string();
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&line);
            s.push('\n');
            s
        }
    }
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let perms = std::fs::metadata(path).map(|m| m.permissions()).ok();
    std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    if let Some(p) = perms {
        let _ = std::fs::set_permissions(&tmp, p);
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

fn err(code: i32, json: bool, msg: &str) -> i32 {
    if json {
        println!("{}", json!({"ok": false, "error": msg}));
    } else {
        eprintln!("{}: {msg}", names::BINARY);
    }
    code
}

pub fn cmd_show(explicit: Option<&Path>, json: bool) -> i32 {
    let (cfg, path) = match Config::load(explicit) {
        Ok(x) => x,
        Err(e) => return err(exit::CONFIG, json, &e),
    };
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let items: Vec<Value> = SETTINGS
        .iter()
        .map(|s| {
            json!({"key": s.key, "value": current(&cfg, s.key), "set_in_file": find_line(&text, s.key).is_some(),
                   "kind": kind_str(s.kind), "about": s.about})
        })
        .collect();
    if json {
        let v = json!({"ok": true, "file": path.display().to_string(), "settings": items});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("config {}", path.display());
        for (s, i) in SETTINGS.iter().zip(&items) {
            println!(
                "  {} = {}{}",
                s.key,
                i["value"],
                if i["set_in_file"] == json!(true) {
                    ""
                } else {
                    "   (default)"
                }
            );
        }
    }
    exit::OK
}

pub fn cmd_set(explicit: Option<&Path>, key: &str, value: &str, json: bool) -> i32 {
    let Some(s) = setting(key) else {
        let keys: Vec<&str> = SETTINGS.iter().map(|s| s.key).collect();
        return err(
            exit::USAGE,
            json,
            &format!(
                "{key:?} is not a setting this command changes; settings: {}",
                keys.join(", ")
            ),
        );
    };
    let (cfg, path) = match Config::load(explicit) {
        Ok(x) => x,
        Err(e) => return err(exit::CONFIG, json, &e),
    };
    let lit = match literal(s.kind, value) {
        Ok(l) => l,
        Err(e) => {
            return err(
                exit::USAGE,
                json,
                &format!("{key}: {e}; nothing was changed"),
            )
        }
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            return err(
                exit::CONFIG,
                json,
                &format!("cannot read {}: {e}", path.display()),
            )
        }
    };
    let new = with_value(&text, key, &lit);
    let checked = match Config::parse(&new) {
        Ok(c) => c,
        Err(e) => {
            return err(
                exit::USAGE,
                json,
                &format!("{key}: the config would not be valid ({e}); nothing was changed"),
            )
        }
    };
    let before = current(&cfg, key);
    // The next backup carries the changed config (end of the command).
    crate::activation::store::note_written();
    if let Err(e) = write_atomic(&path, &new) {
        return err(exit::CONFIG, json, &e);
    }
    let after = current(&checked, key);
    if json {
        println!(
            "{}",
            json!({"ok": true, "file": path.display().to_string(), "key": key, "previous": before, "value": after})
        );
    } else {
        println!("{key} = {after} (was {before}) in {}", path.display());
    }
    exit::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "# a comment\ntrust_cache_dir = \"/x\"\n# tor_socks_proxy = \"old\"\ntor_socks_proxy = \"socks5h://127.0.0.1:9050\"\n";

    #[test]
    fn values_are_checked_and_lines_replaced() {
        assert!(literal(Kind::Socks, "socks5h://127.0.0.1:9150").is_ok());
        for bad in [
            "socks5://127.0.0.1:9150",
            "socks5h://127.0.0.1",
            "socks5h://:9150",
            "socks5h://h:0",
        ] {
            assert!(literal(Kind::Socks, bad).is_err(), "{bad}");
        }
        assert_eq!(literal(Kind::Days, "30").unwrap(), "30");
        assert!(literal(Kind::Days, "0").is_err() && literal(Kind::Days, "x").is_err());
        assert_eq!(literal(Kind::Seconds, "1800").unwrap(), "1800");
        assert!(literal(Kind::Seconds, "59").is_err() && literal(Kind::Seconds, "86401").is_err());
        assert!(literal(Kind::Choice(&["newest", "stable"]), "preview").is_err());
        assert!(literal(Kind::Sha256OrEmpty, "abc").is_err());
        assert_eq!(literal(Kind::Sha256OrEmpty, "").unwrap(), "\"\"");
        assert!(literal(Kind::Package, "a b").is_err());
        assert!(literal(Kind::Https, "https://app.simplex.chat/fdroid/repo").is_ok());
        for bad in ["http://x/y", "https://x/", "https://", "https://a b"] {
            assert!(literal(Kind::Https, bad).is_err(), "{bad}");
        }
        assert_eq!(
            literal(Kind::Sha256OrEmpty, &"AB".repeat(32)).unwrap(),
            format!("\"{}\"", "ab".repeat(32))
        );
        assert!(literal(Kind::Text, "").is_err());
        assert!(literal(Kind::Text, "a\nb").is_err());
        assert_eq!(
            literal(Kind::Path, "C:\\x \"y\"").unwrap(),
            "\"C:\\\\x \\\"y\\\"\""
        );
        let t = with_value(BASE, "tor_socks_proxy", "\"socks5h://127.0.0.1:9150\"");
        assert!(
            t.contains("# tor_socks_proxy = \"old\"\n"),
            "comment kept: {t}"
        );
        assert!(t.contains("\ntor_socks_proxy = \"socks5h://127.0.0.1:9150\"\n"));
        assert_eq!(
            Config::parse(&t).unwrap().tor_socks_proxy,
            "socks5h://127.0.0.1:9150"
        );
        let t = with_value(BASE, "max_os_age_days", "45");
        assert!(t.ends_with("max_os_age_days = 45\n"));
        assert_eq!(Config::parse(&t).unwrap().max_os_age_days, 45);
        // A key that is a prefix of another is not confused with it.
        assert_eq!(
            find_line(
                "orbot_package_x = 1\norbot_package = \"a.b\"\n",
                "orbot_package"
            ),
            Some(1)
        );
    }

    #[test]
    fn set_and_show_on_a_file() {
        let d = crate::activation::store::tests::temp_dir("config-cmd");
        let p = d.join("provisioning.toml");
        std::fs::write(&p, BASE).unwrap();
        assert_eq!(
            cmd_set(Some(&p), "grapheneos_release", "stable", true),
            exit::OK
        );
        assert_eq!(
            Config::load(Some(&p)).unwrap().0.grapheneos_release,
            "stable"
        );
        // Refused values and keys change nothing.
        let before = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            cmd_set(Some(&p), "grapheneos_release", "preview", true),
            exit::USAGE
        );
        assert_eq!(
            cmd_set(Some(&p), "trust_cache_dir", "/y", true),
            exit::USAGE
        );
        assert_eq!(
            cmd_set(Some(&p), "allow_test_key_for_test_deliveries", "true", true),
            exit::USAGE
        );
        assert_eq!(
            cmd_set(Some(&p), "grapheneos_cache_dir", "", true),
            exit::USAGE
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);
        assert_eq!(cmd_set(Some(&p), "fastboot_path", "", true), exit::OK);
        assert_eq!(cmd_show(Some(&p), true), exit::OK);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
