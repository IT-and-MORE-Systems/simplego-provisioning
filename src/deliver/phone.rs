// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The phone commands of a delivery. Every call goes through
//! `device::adb` (always `-s <serial>`, standard input closed), except the
//! activation file, which `content write` reads from standard input.

use crate::device::{self, parse, Tools};
use std::collections::BTreeMap;

/// `content://AUTHORITY`, the messenger's activation provider.
pub fn activation_uri(authority: &str) -> String {
    format!("content://{authority}")
}

/// `content://AUTHORITY/file`, where the activation file is written.
pub fn activation_file_uri(authority: &str) -> String {
    format!("content://{authority}/file")
}
/// Capability the provider's `status` would name for file import. Not
/// confirmed by the messenger yet; a provider without it gets the code
/// only.
pub const FILE_IMPORT_CAPABILITY: &str = "file_import";

pub struct Phone<'a> {
    pub tools: &'a Tools,
    pub serial: &'a str,
}

fn text(o: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let e = String::from_utf8_lossy(&o.stderr);
    if !e.trim().is_empty() {
        if !s.is_empty() {
            s.push_str("; ");
        }
        s.push_str(e.trim());
    }
    s
}

impl Phone<'_> {
    pub fn shell(&self, cmd: &[&str]) -> Result<String, String> {
        device::adb_shell(self.tools, self.serial, cmd)
    }

    pub fn getprops(&self) -> Result<BTreeMap<String, String>, String> {
        device::getprops(self.tools, self.serial)
    }

    /// `pm list packages [flag]` as a set of package names.
    pub fn packages(&self, flag: Option<&str>) -> Result<Vec<String>, String> {
        let mut cmd = vec!["pm", "list", "packages"];
        if let Some(f) = flag {
            cmd.push(f);
        }
        let out = self.shell(&cmd)?;
        let list: Vec<String> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(str::to_string)
            .collect();
        Ok(list)
    }

    pub fn installed(&self, package: &str) -> Result<bool, String> {
        Ok(self.packages(None)?.iter().any(|p| p == package))
    }

    /// Paths of the installed APK files (`pm path`).
    pub fn apk_paths(&self, package: &str) -> Result<Vec<String>, String> {
        let out = self.shell(&["pm", "path", package])?;
        Ok(out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(str::to_string)
            .collect())
    }

    pub fn package_info(&self, package: &str) -> Result<Option<parse::PackageInfo>, String> {
        device::package_info(self.tools, self.serial, package)
    }

    /// `adb install [-r] FILE`; success only with `Success` in the output.
    pub fn install(&self, apk: &str, replace: bool) -> Result<(), String> {
        self.install_as(apk, replace, None)
    }

    /// `adb install [-r] [-i INSTALLER] FILE`: with `-i` the given package
    /// is the installer of record (it may update the app later).
    pub fn install_as(
        &self,
        apk: &str,
        replace: bool,
        installer: Option<&str>,
    ) -> Result<(), String> {
        let path = device::path_for_adb(&self.tools.adb, apk)?;
        let mut args = vec!["install"];
        if replace {
            args.push("-r");
        }
        if let Some(i) = installer {
            if !crate::agent::valid_package(i) {
                return Err(format!("invalid installer package {i:?}"));
            }
            args.push("-i");
            args.push(i);
        }
        args.push(&path);
        let o = device::adb(self.tools, self.serial, &args)?;
        let t = text(&o);
        if o.status.success() && t.lines().any(|l| l.trim() == "Success") {
            Ok(())
        } else {
            Err(format!("install failed: {t}"))
        }
    }

    pub fn uninstall(&self, package: &str) -> Result<(), String> {
        let o = device::adb(self.tools, self.serial, &["uninstall", package])?;
        let t = text(&o);
        if o.status.success() && t.lines().any(|l| l.trim() == "Success") {
            Ok(())
        } else {
            Err(format!("uninstall {package} failed: {t}"))
        }
    }

    pub fn whitelist_add(&self, package: &str) -> Result<(), String> {
        let arg = format!("+{package}");
        self.shell(&["dumpsys", "deviceidle", "whitelist", &arg])
            .map(|_| ())
    }

    /// `appops set <package> <op> allow`, then `appops get` must say allow.
    pub fn appops_allow(&self, package: &str, op: &str) -> Result<(), String> {
        self.shell(&["appops", "set", package, op, "allow"])?;
        let out = self.shell(&["appops", "get", package, op])?;
        let want = format!("{op}: allow");
        if out.lines().any(|l| l.trim().starts_with(&want)) {
            Ok(())
        } else {
            Err(format!(
                "app op {op} of {package} is not allowed after setting it: {}",
                out.trim()
            ))
        }
    }

    /// True if `dumpsys deviceidle whitelist` lists `user,<package>,<uid>`.
    pub fn whitelisted(&self, package: &str) -> Result<bool, String> {
        let out = self.shell(&["dumpsys", "deviceidle", "whitelist"])?;
        Ok(out.lines().any(|l| {
            let f: Vec<&str> = l.trim().split(',').collect();
            f.len() == 3 && f[0] == "user" && f[1] == package
        }))
    }

    /// `content call --uri content://AUTHORITY --method <m> [--arg <a>]`,
    /// parsed.
    pub fn provider_call(
        &self,
        authority: &str,
        method: &str,
        arg: Option<&str>,
    ) -> Result<BTreeMap<String, String>, String> {
        let uri = activation_uri(authority);
        let mut cmd = vec!["content", "call", "--uri", &uri, "--method", method];
        if let Some(a) = arg {
            cmd.push("--arg");
            cmd.push(a);
        }
        let o = device::adb(self.tools, self.serial, &{
            let mut v = vec!["shell"];
            v.extend_from_slice(&cmd);
            v
        })?;
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        match super::provider::parse_bundle(&out) {
            Some(m) => Ok(m),
            None => Err(format!(
                "the activation provider gave no answer to `{method}`: {}",
                super::provider::first_line(&text(&o))
            )),
        }
    }

    /// The file over standard input into the provider (a proposal, not yet
    /// confirmed by the messenger).
    pub fn provider_write_file(&self, authority: &str, file: &[u8]) -> Result<(), String> {
        let uri = activation_file_uri(authority);
        let o = device::adb_with_stdin(
            self.tools,
            self.serial,
            &["shell", "content", "write", "--uri", &uri],
            file,
        )?;
        if o.status.success() && o.stderr.is_empty() {
            Ok(())
        } else {
            Err(format!("content write failed: {}", text(&o)))
        }
    }

    pub fn disable_user(&self, package: &str) -> Result<(), String> {
        let out = self.shell(&["pm", "disable-user", "--user", "0", package])?;
        if out.contains("new state: disabled-user") {
            Ok(())
        } else {
            Err(format!("pm disable-user {package}: {}", out.trim()))
        }
    }

    pub fn enable(&self, package: &str) -> Result<(), String> {
        let out = self.shell(&["pm", "enable", "--user", "0", package])?;
        if out.contains("new state: enabled") {
            Ok(())
        } else {
            Err(format!("pm enable {package}: {}", out.trim()))
        }
    }

    /// Copies a file from the phone to a local path.
    pub fn pull(&self, remote: &str, local: &str) -> Result<(), String> {
        let path = device::path_for_adb(&self.tools.adb, local)?;
        let o = device::adb(self.tools, self.serial, &["pull", remote, &path])?;
        if o.status.success() {
            Ok(())
        } else {
            Err(format!("adb pull failed: {}", text(&o)))
        }
    }
}
