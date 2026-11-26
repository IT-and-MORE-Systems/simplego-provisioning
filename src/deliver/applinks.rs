// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! App link verification at delivery.
//!
//! When an app with `android:autoVerify` web intent filters is installed,
//! Android's verifier `com.android.statementservice` fetches
//! `https://HOST/.well-known/assetlinks.json` for every host. In the request
//! 63 delivery (2026-11-25) these fetches went out over Wi-Fi without Tor:
//! the SimpleX app's 22 hosts and the F-Droid client's 4 hosts showed as
//! `verified` afterwards. Under lockdown the verification does not fail, it
//! waits (JobScheduler never bypasses `BLOCKED_REASON_LOCKDOWN_VPN`) and
//! runs as soon as lockdown goes off.
//!
//! So, decided on 2026-11-25:
//! - step 5: the verifier is disabled for user 0 before the first install
//!   (before Orbot), checked with `pm list packages -d`; `undeliver`
//!   enables it again as its last step;
//! - every installed APK's `autoVerify` hosts are read on the laptop
//!   (`apk::axml`) and recorded;
//! - the final check: no host of any installed app is `verified` or
//!   `approved` (a verified host means the fetch went out: exit 18), the
//!   verifier is still disabled, it has no socket outside loopback, and its
//!   jobs and network state are recorded as read.

use super::*;

/// Android's app link verifier.
pub const VERIFIER: &str = "com.android.statementservice";

/// `pm get-app-links --user 0 PKG`: `(host, state)` of the domain
/// verification state, in the order shown.
pub fn parse_app_links(out: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    let mut inside = false;
    for l in out.lines() {
        let t = l.trim();
        if t == "Domain verification state:" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if t.starts_with("User ") || t.is_empty() {
            inside = false;
            continue;
        }
        if let Some((h, s)) = t.split_once(": ") {
            v.push((h.trim().to_string(), s.trim().to_string()));
        }
    }
    v
}

/// A state that means Android takes the host as the app's own: the
/// verifier's fetch succeeded (`verified`) or it was granted (`approved`).
pub fn state_is_verified(state: &str) -> bool {
    matches!(state, "verified" | "approved")
}

/// The lines of `dumpsys jobscheduler PKG` that describe the verifier's
/// jobs and the network state of its uid (read only, for the record).
pub fn job_lines(out: &str, uid: Option<u32>) -> (Vec<String>, Option<String>) {
    let uid_tag = uid.map(|u| format!("UID: {u};"));
    let mut jobs = Vec::new();
    let mut net = None;
    for l in out.lines().map(str::trim) {
        if l.starts_with("JOB #")
            || l.starts_with("Required constraints:")
            || l.starts_with("Unsatisfied constraints:")
        {
            if jobs.len() < 40 {
                jobs.push(l.to_string());
            }
        } else if uid_tag.as_deref().is_some_and(|t| l.starts_with(t)) {
            net = Some(l.to_string());
        }
    }
    (jobs, net)
}

impl Delivery_<'_, '_, '_, '_> {
    /// Step 5: app link verification off, before anything is installed.
    pub(super) fn step5_app_links(&mut self) -> Result<(), Failure> {
        self.o
            .step(5, "app link verification off (before any install)");
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let mut r = self.rec.app_links.take().unwrap_or_default();
        let all = p
            .packages(None)
            .or_else(|e| fail(5, exit::DELIVERY_FAILED, e))?;
        if !all.iter().any(|x| x == VERIFIER) {
            self.o.line(format!(
                "  {VERIFIER} is not on this phone: no app link verification to turn off"
            ));
            r.verifier = None;
            self.rec.app_links = Some(r);
            return Ok(());
        }
        r.verifier = Some(VERIFIER.to_string());
        let disabled = p
            .packages(Some("-d"))
            .or_else(|e| fail(5, exit::DELIVERY_FAILED, e))?;
        if disabled.iter().any(|x| x == VERIFIER) {
            r.found_disabled = true;
            self.rec.app_links = Some(r);
            self.o
                .line(format!("  {VERIFIER} already disabled before the delivery"));
            return Ok(());
        }
        self.rec.app_links = Some(r.clone());
        p.disable_user(VERIFIER).or_else(|e| {
            fail(
                5,
                exit::DELIVERY_FAILED,
                format!("the phone refused to disable the app link verifier {VERIFIER} ({e}); nothing was installed"),
            )
        })?;
        let disabled = p
            .packages(Some("-d"))
            .or_else(|e| fail(5, exit::DELIVERY_FAILED, e))?;
        if !disabled.iter().any(|x| x == VERIFIER) {
            return fail(
                5,
                exit::DELIVERY_FAILED,
                format!("{VERIFIER} is not listed as disabled after pm disable-user; nothing was installed"),
            );
        }
        r.disabled_by_delivery = true;
        self.rec.app_links = Some(r);
        self.o.line(format!(
            "  {VERIFIER} disabled for user 0: no app link verification (no /.well-known/assetlinks.json fetch at install)"
        ));
        self.o
            .event(json!({"event": "app_links", "verifier": VERIFIER, "disabled": true}));
        Ok(())
    }

    /// Notes the `autoVerify` hosts of an APK the delivery installs.
    pub(super) fn note_link_hosts(&mut self, info: &ApkInfo) {
        let hosts = info.auto_verify_hosts();
        if hosts.is_empty() {
            return;
        }
        let r = self.rec.app_links.get_or_insert_with(Default::default);
        r.hosts.retain(|(p, _)| *p != info.package);
        r.hosts.push((info.package.clone(), hosts));
    }

    /// Step 4: the app link hosts of every APK. Without a network lock
    /// (no `--fdroid-apk`) an APK with `autoVerify` hosts is refused: it
    /// would be installed with the network open.
    pub(super) fn step4_link_hosts(&mut self, info: &ApkInfo, what: &str) -> Result<(), Failure> {
        let hosts = info.auto_verify_hosts();
        let unresolved = info.unresolved_links();
        if hosts.is_empty() && unresolved.is_empty() {
            self.o.line(format!(
                "  {what}: no autoVerify web hosts (no app link verification at install)"
            ));
            return Ok(());
        }
        if !self.vpn_mode() {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "{what} declares app link hosts ({}{}) and this delivery has no network lock (--fdroid-apk): it would be installed with the network open",
                    hosts.join(", "),
                    if unresolved.is_empty() {
                        String::new()
                    } else {
                        format!("; not resolved: {}", unresolved.join(", "))
                    }
                ),
            );
        }
        self.o.line(format!(
            "  {what}: {} autoVerify web host(s) ({}); installed only after the network lock, with the verifier off",
            hosts.len(),
            hosts.join(", ")
        ));
        if !unresolved.is_empty() {
            self.o.line(format!(
                "  {what}: references not resolved here: {}",
                unresolved.join(", ")
            ));
        }
        Ok(())
    }

    /// The final check's part for app link verification (in step 14).
    pub(super) fn final_app_links(&mut self) -> Result<(), Failure> {
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let mut r = self.rec.app_links.clone().unwrap_or_default();
        r.checked = true;
        r.states.clear();
        let mut verified = Vec::new();
        for (pkg, hosts) in r.hosts.clone() {
            if !p
                .installed(&pkg)
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?
            {
                continue;
            }
            let out = p
                .shell(&["pm", "get-app-links", "--user", "0", &pkg])
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
            let states = parse_app_links(&out);
            for h in &hosts {
                let st = states
                    .iter()
                    .find(|(x, _)| x.eq_ignore_ascii_case(h))
                    .map(|(_, s)| s.clone())
                    .unwrap_or_else(|| "not listed".into());
                if state_is_verified(&st) {
                    verified.push(format!("{pkg} {h} {st}"));
                }
                r.states.push((pkg.clone(), h.clone(), st));
            }
            self.o.line(format!(
                "  {pkg}: {} app link host(s), none verified: {}",
                hosts.len(),
                if verified.iter().any(|v| v.starts_with(&format!("{pkg} "))) {
                    "NO"
                } else {
                    "yes"
                }
            ));
        }
        let uids = p
            .shell(&["pm", "list", "packages", "-U"])
            .map(|o| simplex::parse_uids(&o))
            .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
        let vuid = uids.get(VERIFIER).copied();
        let mut outside = 0u32;
        if let Some(u) = vuid {
            for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
                let t = p
                    .shell(&["cat", f])
                    .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
                outside += simplex::parse_sockets(&t)
                    .iter()
                    .filter(|s| s.uid == u && s.state != "0A" && !s.remote_is_loopback())
                    .count() as u32;
            }
            let jobs = p
                .shell(&["dumpsys", "jobscheduler", VERIFIER])
                .unwrap_or_default();
            let (lines, net) = job_lines(&jobs, Some(u));
            r.verifier_jobs = lines;
            r.verifier_network = net;
        }
        r.verifier_sockets_outside = outside;
        let still_disabled = match &r.verifier {
            Some(v) if r.disabled_by_delivery || r.found_disabled => p
                .packages(Some("-d"))
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?
                .iter()
                .any(|x| x == v),
            _ => true,
        };
        self.rec.app_links = Some(r.clone());
        self.o.event(
            json!({"event": "app_links", "verifier": r.verifier, "disabled": still_disabled,
                            "states": r.states, "verifier_sockets_outside": outside,
                            "verifier_jobs": r.verifier_jobs.len()}),
        );
        if !verified.is_empty() {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "APP LINK VERIFIED: {}; the verifier's fetch went out",
                    verified.join(", ")
                ),
            );
        }
        if !still_disabled {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!("{VERIFIER} is no longer disabled"),
            );
        }
        if outside > 0 {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!("{VERIFIER} has {outside} TCP socket(s) outside loopback"),
            );
        }
        self.o.line(format!(
            "  app link verifier {}: {}; no socket outside loopback; {} job line(s){}",
            r.verifier.as_deref().unwrap_or("not on this phone"),
            if r.verifier.is_some() {
                "disabled"
            } else {
                "-"
            },
            r.verifier_jobs.len(),
            r.verifier_network
                .as_deref()
                .map(|n| format!("; {n}"))
                .unwrap_or_default()
        ));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_link_states_and_jobs_in_the_real_format() {
        let out = "  chat.simplex.app:\n    ID: 0a1b2c3d\n    Signatures: [AA:BB]\n    Domain verification state:\n      smp4.simplexonflux.com: verified\n      simplex.chat: none\n      smp5.simplex.im: 1026\n    User 0:\n      Verification link handling allowed: true\n      Selection state:\n        Disabled:\n          smp4.simplexonflux.com\n";
        let s = parse_app_links(out);
        assert_eq!(
            s,
            [
                ("smp4.simplexonflux.com".into(), "verified".into()),
                ("simplex.chat".into(), "none".into()),
                ("smp5.simplex.im".into(), "1026".into())
            ]
        );
        assert!(state_is_verified("verified") && state_is_verified("approved"));
        assert!(!state_is_verified("none") && !state_is_verified("1026"));
        assert!(parse_app_links("").is_empty());
        let j = "    Required constraints: IDLE CONNECTIVITY FLEXIBILITY [0x10200004]\n    Unsatisfied constraints: IDLE CONNECTIVITY [0x10000004]\n    UID: 1000; Network: 100 (blocked=REASON_LOCKDOWN_VPN)\n    UID: 10052; Network: 100 (blocked=REASON_APP_BACKGROUND|REASON_LOCKDOWN_VPN)\n";
        let (lines, net) = job_lines(j, Some(10052));
        assert_eq!(lines.len(), 2);
        assert_eq!(
            net.as_deref(),
            Some("UID: 10052; Network: 100 (blocked=REASON_APP_BACKGROUND|REASON_LOCKDOWN_VPN)")
        );
    }
}
