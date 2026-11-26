// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Attestation agent transport over adb only.
//!
//! The agent is an instrumentation (`am instrument -w -r`). The challenge goes
//! in as an instrumentation argument (`-e`); the result comes back as the
//! instrumentation result bundle on adb's stdout. Nothing is written to
//! storage on the phone, and the agent is uninstalled in every outcome. The
//! agent attests only; installed apps are read with `crate::installed`.

use crate::device::{self, Tools};
use crate::names;
use base64ct::{Base64, Encoding};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct AgentResult {
    pub chain: Vec<Vec<u8>>,
    pub keystore: Option<String>,
    pub error: Option<String>,
}

/// Package names go into an adb shell command line: allow only the Java
/// package name alphabet.
pub fn valid_package(p: &str) -> bool {
    !p.is_empty()
        && p.split('.').count() >= 2
        && p.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic())
                    .unwrap_or(false)
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Parses `am instrument -r` output: `INSTRUMENTATION_RESULT: key=value` lines.
pub fn parse_instrument_output(out: &str) -> Result<AgentResult, String> {
    let mut kv = BTreeMap::new();
    let mut code = None;
    for line in out.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("INSTRUMENTATION_RESULT: ") {
            if let Some((k, v)) = rest.split_once('=') {
                kv.insert(k.to_string(), v.to_string());
            }
        } else if let Some(c) = line.strip_prefix("INSTRUMENTATION_CODE: ") {
            code = c.trim().parse::<i64>().ok();
        } else if line.starts_with("INSTRUMENTATION_FAILED")
            || line.starts_with("INSTRUMENTATION_ABORTED")
        {
            return Err(format!("instrumentation did not run: {line}"));
        }
    }
    if code.is_none() {
        return Err("no INSTRUMENTATION_CODE in agent output".into());
    }
    let mut r = AgentResult {
        keystore: kv.get("keystore").cloned(),
        error: kv.get("error").cloned(),
        ..Default::default()
    };
    if kv.get("status").map(String::as_str) == Some("ok") {
        let n: usize = kv
            .get("chain_count")
            .and_then(|v| v.parse().ok())
            .ok_or("agent output without chain_count")?;
        if n == 0 || n > 10 {
            return Err(format!("agent reported {n} certificates"));
        }
        for i in 0..n {
            let b64 = kv
                .get(&format!("chain_{i}"))
                .ok_or(format!("chain_{i} missing"))?;
            r.chain
                .push(Base64::decode_vec(b64).map_err(|_| format!("chain_{i}: bad base64"))?);
        }
    } else if r.error.is_none() {
        r.error = Some("agent reported no status".into());
    }
    Ok(r)
}

pub struct Session<'a> {
    pub tools: &'a Tools,
    pub serial: &'a str,
    pub agent_package: &'a str,
}

/// Uninstalls the agent when dropped, so it is removed on every return path,
/// on error and on panic.
struct Uninstall<'a> {
    tools: &'a Tools,
    serial: &'a str,
    package: &'a str,
    log: &'a mut Vec<String>,
}

impl Drop for Uninstall<'_> {
    fn drop(&mut self) {
        match device::adb(self.tools, self.serial, &["uninstall", self.package]) {
            Ok(o) if o.status.success() => self.log.push("agent uninstalled".into()),
            Ok(o) => self.log.push(format!(
                "WARNING: agent uninstall failed: {} {}",
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => self
                .log
                .push(format!("WARNING: agent uninstall failed: {e}")),
        }
    }
}

impl Session<'_> {
    fn installed(&self) -> bool {
        device::adb_shell(self.tools, self.serial, &["pm", "path", self.agent_package])
            .map(|o| o.lines().any(|l| l.starts_with("package:")))
            .unwrap_or(false)
    }

    /// Installs the agent, runs one attestation with `challenge`, uninstalls.
    pub fn run(
        &self,
        apk: &str,
        challenge: &[u8],
        log: &mut Vec<String>,
    ) -> Result<AgentResult, String> {
        if !valid_package(self.agent_package) {
            return Err("invalid package name in config".into());
        }
        if self.installed() {
            log.push("agent from an earlier interrupted run found; removing it first".into());
            let _ = device::adb(self.tools, self.serial, &["uninstall", self.agent_package]);
        }
        let apk = device::path_for_adb(&self.tools.adb, apk)?;
        let out = device::adb(self.tools, self.serial, &["install", "-r", &apk])?;
        let guard = Uninstall {
            tools: self.tools,
            serial: self.serial,
            package: self.agent_package,
            log,
        };
        if !out.status.success() {
            return Err(format!(
                "agent install failed: {} {}",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        guard.log.push("agent installed".into());
        let component = format!("{}/{}", self.agent_package, names::AGENT_INSTRUMENTATION);
        let hex_challenge = crate::util::hex(challenge);
        let out = device::adb_shell(
            self.tools,
            self.serial,
            &[
                "am",
                "instrument",
                "-w",
                "-r",
                "-e",
                "challenge",
                &hex_challenge,
                &component,
            ],
        )?;
        let result = parse_instrument_output(&out);
        drop(guard);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_names() {
        assert!(valid_package("org.example.messenger"));
        assert!(valid_package("dev.simplego.provisioning.agent"));
        assert!(!valid_package("app"));
        assert!(!valid_package("app.x;rm -rf /"));
        assert!(!valid_package("app..x"));
        assert!(!valid_package("1app.x"));
    }

    #[test]
    fn instrument_output() {
        let out = include_str!("../tests/fixtures/agent/instrument-ok.txt");
        let r = parse_instrument_output(out).unwrap();
        assert_eq!(r.chain.len(), 2);
        assert_eq!(r.chain[0], b"leaf");
        assert_eq!(r.keystore.as_deref(), Some("strongbox"));
    }

    #[test]
    fn instrument_errors() {
        let out = include_str!("../tests/fixtures/agent/instrument-error.txt");
        let r = parse_instrument_output(out).unwrap();
        assert!(r.chain.is_empty());
        assert!(r.error.unwrap().contains("KeyStoreException"));
        assert!(parse_instrument_output("INSTRUMENTATION_FAILED: x/y\n").is_err());
        assert!(parse_instrument_output("nothing\n").is_err());
    }
}
