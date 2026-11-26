// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! What is installed on a phone, read over adb without the agent: an app's
//! signer from its pulled `base.apk` (our APK reader), cross-checked with
//! the package manager's own record (`dumpsys package`: the signature hash
//! and the versionCode), and the installed messengers, found by their
//! activation provider.

use crate::config::Config;
use crate::device::{self, parse, Tools};
use crate::{agent, apk};
use std::path::Path;

/// One installed app as the phone and its `base.apk` show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApk {
    pub package: String,
    /// SHA-256 (hex) of the signer certificate of the pulled `base.apk`.
    pub signer_sha256: String,
    /// Java's `Arrays.hashCode` of that certificate, as the package manager
    /// prints signatures.
    pub cert_hash: u32,
    /// The signature hashes `dumpsys package` records for the package.
    pub pm_hashes: Vec<u32>,
    pub version_code: Option<u64>,
    pub version_name: Option<String>,
}

impl InstalledApk {
    /// The package manager records exactly the certificate of the pulled
    /// `base.apk`.
    pub fn package_manager_agrees(&self) -> bool {
        self.pm_hashes == [self.cert_hash]
    }
}

/// Reads `package` on the phone: `pm path`, `adb pull` of `base.apk` into
/// `work_dir` (deleted again at once), our APK reader, `dumpsys package`.
/// None: not installed.
pub fn read(
    tools: &Tools,
    serial: &str,
    package: &str,
    work_dir: &Path,
) -> Result<Option<InstalledApk>, String> {
    if !agent::valid_package(package) {
        return Err(format!("{package:?} is not a valid package name"));
    }
    let paths = device::adb_shell(tools, serial, &["pm", "path", package]).unwrap_or_default();
    let Some(base) = paths
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .find(|p| p.ends_with("/base.apk"))
        .map(str::to_string)
    else {
        if paths.lines().any(|l| l.trim().starts_with("package:")) {
            return Err(format!("pm path {package} names no base.apk"));
        }
        return Ok(None);
    };
    let local = work_dir.join(format!("{package}-base.apk"));
    let _ = std::fs::remove_file(&local);
    let pulled = (|| {
        let dest = device::path_for_adb(&tools.adb, &local.to_string_lossy())?;
        let o = device::adb(tools, serial, &["pull", &base, &dest])?;
        if !o.status.success() {
            return Err(format!(
                "adb pull failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        let digest = apk::signer_digest(&local)?;
        let cert = apk::signer_cert(&local)?;
        Ok((digest, cert))
    })();
    let _ = std::fs::remove_file(&local);
    let (signer_sha256, cert) = pulled?;
    let dump = device::adb_shell(tools, serial, &["dumpsys", "package", package])?;
    let info = parse::parse_dumpsys_package(&dump, package).unwrap_or_default();
    Ok(Some(InstalledApk {
        package: package.to_string(),
        signer_sha256,
        cert_hash: apk::java_hash(&cert),
        pm_hashes: pm_signature_hashes(&dump),
        version_code: info.version_code,
        version_name: info.version_name,
    }))
}

/// The signatures the package manager records for a package, as
/// `dumpsys package` prints them (`signatures:[2136bace]`: Java hash codes).
pub fn pm_signature_hashes(dump: &str) -> Vec<u32> {
    dump.lines()
        .filter_map(|l| l.trim().strip_prefix("signatures=PackageSignatures{"))
        .filter_map(|r| r.split_once("signatures:[").map(|(_, x)| x))
        .filter_map(|r| r.split_once(']').map(|(x, _)| x))
        .flat_map(|x| x.split(',').map(str::trim).collect::<Vec<_>>())
        .filter_map(|h| u32::from_str_radix(h, 16).ok())
        .collect()
}

/// The authorities of `dumpsys package providers` (the `[a;b]:` lines of
/// "ContentProvider Authorities").
pub fn provider_authorities(dump: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in dump.lines() {
        let t = line.trim();
        if t.starts_with("ContentProvider Authorities") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.starts_with(' ') && !t.is_empty() {
            inside = false;
            continue;
        }
        if let Some(a) = t.strip_prefix('[').and_then(|r| r.strip_suffix("]:")) {
            out.extend(a.split(';').map(|x| x.trim().to_string()));
        }
    }
    out
}

/// Every installed package that offers the activation provider of the
/// config's authority template: our messenger, whatever its package name.
/// `known` packages are always included when installed.
pub fn messengers(
    tools: &Tools,
    serial: &str,
    cfg: &Config,
    known: &[&str],
) -> Result<Vec<String>, String> {
    let installed: Vec<String> = device::adb_shell(tools, serial, &["pm", "list", "packages"])?
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(str::to_string)
        .collect();
    let authorities = provider_authorities(&device::adb_shell(
        tools,
        serial,
        &["dumpsys", "package", "providers"],
    )?);
    let mut out: Vec<String> = installed
        .iter()
        .filter(|p| known.contains(&p.as_str()) || authorities.contains(&cfg.provider_authority(p)))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// The messenger a read-only command looks at, and how it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub package: Option<String>,
    /// One line for the output: how the package was found, or why none.
    pub note: String,
}

/// The messenger for `devices` and `verify`: `explicit`
/// (`--messenger-package`), else a fixed `messenger_package`, else the one
/// installed app that offers the activation provider of the config's
/// authority template. Several such apps, or none: no package, and the note
/// says why.
pub fn resolve(explicit: Option<&str>, cfg: &Config, tools: &Tools, serial: &str) -> Resolved {
    if let Some(p) = explicit {
        return Resolved {
            package: Some(p.to_string()),
            note: format!("messenger {p} (--messenger-package)"),
        };
    }
    if let Some(p) = cfg.fixed_messenger() {
        return Resolved {
            package: Some(p.to_string()),
            note: format!("messenger {p} (messenger_package in the config)"),
        };
    }
    match messengers(tools, serial, cfg, &[]) {
        Ok(found) => match found.as_slice() {
            [one] => Resolved {
                package: Some(one.clone()),
                note: format!(
                    "messenger {one}, found by its activation provider ({})",
                    cfg.provider_authority(one)
                ),
            },
            [] => Resolved {
                package: None,
                note: "no messenger installed (no app offers the activation provider)".into(),
            },
            many => Resolved {
                package: None,
                note: format!(
                    "several messengers installed ({}); choose one with --messenger-package",
                    many.join(", ")
                ),
            },
        },
        Err(e) => Resolved {
            package: None,
            note: format!("messenger lookup failed: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_hashes_and_provider_authorities() {
        let d = "    signatures=PackageSignatures{1a2b3c4 version:3, signatures:[2136bace], past signatures:[]}\n";
        assert_eq!(pm_signature_hashes(d), vec![0x2136bace]);
        assert_eq!(
            pm_signature_hashes("  signatures=PackageSignatures{0 version:3, signatures:[aa, bb], past signatures:[]}"),
            vec![0xaa, 0xbb]
        );
        assert!(pm_signature_hashes("signatures:[]").is_empty());
        let p = "ContentProvider Authorities:\n  [org.example.messenger.activation]:\n    Provider{1a2b3c4 org.example.messenger/.ActivationProvider}\n      applicationInfo=ApplicationInfo{5d6e7f8 org.example.messenger}\n  [a.b;c.d]:\n    Provider{0 a/.P}\n\nDexopt state:\n  [x.y]:\n";
        assert_eq!(
            provider_authorities(p),
            ["org.example.messenger.activation", "a.b", "c.d"]
        );
        assert!(provider_authorities("Dexopt state:\n  [x.y]:\n").is_empty());
    }

    #[test]
    fn package_manager_agreement() {
        let mut i = InstalledApk {
            package: "org.example.messenger".into(),
            signer_sha256: "ab".repeat(32),
            cert_hash: 7,
            pm_hashes: vec![7],
            version_code: Some(1),
            version_name: None,
        };
        assert!(i.package_manager_agrees());
        i.pm_hashes = vec![7, 8];
        assert!(!i.package_manager_agrees());
        i.pm_hashes = vec![8];
        assert!(!i.package_manager_agrees());
    }
}
