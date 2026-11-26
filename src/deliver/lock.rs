// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The network lock: **no app is installed
//! before the network lock is active**, except the lock itself.
//!
//! The lock is the system's always-on VPN with "block connections without
//! VPN" (lockdown). Its provider today is Orbot: its VPN routes the apps on
//! its list through Tor, and lockdown blocks every other app uid outside
//! loopback. Our messenger will later carry Tor itself; then Orbot leaves the delivery and the lock may come from another
//! provider. That provider replaces `Provider::Orbot` here; the delivery
//! order does not change:
//!
//! - step 6: the provider installed (its APK must declare no `autoVerify`
//!   web host, checked in step 4);
//! - step 7: the lock engaged for the apps already on the phone (the
//!   GrapheneOS System Updater and App Store) and **proven** before any
//!   other app is installed: settings, the run-time mode line of `dumpsys
//!   vpn_management`, the filtering rules of `dumpsys connectivity` (every
//!   app uid but the provider's blocked), the VPN's exact uid list, port
//!   9050. Not proven: the delivery stops, nothing else is installed;
//! - steps 8 and 9: the messenger, the F-Droid client and the SimpleX app;
//! - step 10: the delivered apps added to the lock's VPN, and the lock
//!   proven again, with no newer mode line than the one of step 7;
//! - step 14: proven once more in the final check.

use super::appsteps::vpn_packages;
use super::simplex::{self, label_of, SYSTEM_VPN_APPS};
use super::*;
use crate::activation::store::{LockRecord, VpnRecord};

/// The operator console's deliver stepper shows steps 6 and 7 as "Orbot".
pub(super) const CONSOLE_STEP: &str = "Orbot";

/// The Orbot switches and the app list the set-up found.
type Found = (Vec<(&'static str, bool)>, Vec<String>);

/// The app that provides the network lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Provider {
    /// Orbot's VPN with the always-on VPN and lockdown of Settings.
    Orbot,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Orbot => "Orbot",
        }
    }
}

/// The newest `[LockdownAlwaysOn] Mode changed` line of `dumpsys
/// vpn_management` (by its time stamp), trimmed.
pub fn newest_mode_line(out: &str) -> Option<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| l.contains("[LockdownAlwaysOn] Mode changed:"))
        .max_by(|a, b| a.split(' ').next().cmp(&b.split(' ').next()))
        .map(str::to_string)
}

pub fn mode_line_on(line: &str) -> bool {
    line.contains("lockdown=true") && line.contains("alwaysOn=true")
}

/// The apps inside the lock's VPN before anything is installed.
pub(super) fn first_apps() -> Vec<String> {
    SYSTEM_VPN_APPS.iter().map(|s| s.to_string()).collect()
}

fn labels(want: &[String], step: u8) -> Result<Vec<&'static str>, Failure> {
    want.iter()
        .map(|p| label_of(p).ok_or(()))
        .collect::<Result<_, _>>()
        .or_else(|_| {
            fail(
                step,
                exit::DELIVERY_FAILED,
                "no app list label known for one of the VPN packages (see deliver::simplex::LABELS)",
            )
        })
}

impl Delivery_<'_, '_, '_, '_> {
    pub(super) fn provider(&self) -> Provider {
        Provider::Orbot
    }

    fn provider_package(&self) -> String {
        match self.provider() {
            Provider::Orbot => self.env.cfg.orbot_package.clone(),
        }
    }

    /// Stops a write step that would install an app while the lock is not
    /// proven (a delivery with a lock only).
    pub(super) fn require_lock(&self, step: u8) -> Result<(), Failure> {
        if self.vpn_mode() && !self.rec.lock.as_ref().is_some_and(|l| l.proven) {
            return fail(
                step,
                exit::DELIVERY_FAILED,
                "NETWORK LOCK NOT PROVEN: no app is installed before the network lock is active",
            );
        }
        Ok(())
    }

    /// Step 7: the network lock engaged for the apps already on the phone,
    /// then proven, before any other app is installed.
    pub(super) fn step7_lock(&mut self) -> Result<(), Failure> {
        let name = self.provider().name();
        self.o.step_in(
            7,
            &format!("network lock ({name}): always-on VPN with lockdown, before any other app is installed"),
            Some(CONSOLE_STEP),
        );
        let want = first_apps();
        match self.provider() {
            Provider::Orbot => self.orbot_engage(&want)?,
        }
        let line = self
            .prove_lock(7, exit::DELIVERY_FAILED, &want, None)
            .map_err(|mut f| {
                f.msg = format!("{}; nothing else was installed", f.msg);
                f
            })?;
        self.rec.lock = Some(LockRecord {
            provider: self.provider_package(),
            apps_at_lock: want.clone(),
            proven: true,
            mode_line: Some(line.clone()),
            proven_after_apps: false,
        });
        self.o.line(format!(
            "  NETWORK LOCK PROVEN ({name}): lockdown in force, the VPN carries exactly {}; only now other apps are installed",
            want.join(", ")
        ));
        self.o.event(
            json!({"event": "network_lock", "provider": name, "apps": want,
                            "lockdown": true, "mode_line": line, "console_step": CONSOLE_STEP}),
        );
        Ok(())
    }

    /// Step 10: the delivered apps added to the lock's VPN; the lock proven
    /// again, with no mode change since step 7.
    pub(super) fn step10_lock_apps(&mut self) -> Result<(), Failure> {
        if !self.vpn_mode() {
            self.o.step(10, "network lock: not part of this delivery");
            return Ok(());
        }
        let name = self.provider().name();
        self.o.step_in(
            10,
            &format!(
                "network lock ({name}): the F-Droid client and the SimpleX app added to the VPN"
            ),
            Some("SimpleX app"),
        );
        self.require_lock(10)?;
        let want = vpn_packages(self.env.cfg);
        match self.provider() {
            Provider::Orbot => self.orbot_extend(&want)?,
        }
        let baseline = self.rec.lock.as_ref().and_then(|l| l.mode_line.clone());
        self.prove_lock(10, exit::DELIVERY_FAILED, &want, baseline.as_deref())?;
        if let Some(l) = self.rec.lock.as_mut() {
            l.proven_after_apps = true;
        }
        if let Some(v) = self.rec.vpn.as_mut() {
            v.apps = want.clone();
        }
        self.o.line(format!(
            "  network lock still in force after the app list change (no new mode change); the VPN carries exactly {}",
            want.join(", ")
        ));
        self.o.event(
            json!({"event": "vpn", "apps": want, "lockdown": true, "consent": true,
                            "console_step": "SimpleX app"}),
        );
        Ok(())
    }

    /// Proves the lock: Settings, the run-time mode line (no newer one than
    /// `baseline`), the filtering rules, the VPN's exact uid list, port
    /// 9050. Returns the newest mode line.
    pub(super) fn prove_lock(
        &mut self,
        step: u8,
        code: i32,
        want: &[String],
        baseline: Option<&str>,
    ) -> Result<String, Failure> {
        let pkg = self.provider_package();
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let (app, lock) = simplex::lockdown_state(&p).or_else(|e| fail(step, code, e))?;
        if app.as_deref() != Some(pkg.as_str()) || !lock {
            return fail(
                step,
                code,
                format!(
                    "LOCKDOWN NOT ACTIVE: Settings name the always-on VPN {app:?} with lockdown {lock}, expected {pkg} with lockdown on"
                ),
            );
        }
        let log = p
            .shell(&["dumpsys", "vpn_management"])
            .or_else(|e| fail(step, code, e))?;
        let line = newest_mode_line(&log).filter(|l| mode_line_on(l)).ok_or(()).or_else(|_| {
            fail(
                step,
                code,
                format!(
                    "LOCKDOWN NOT ACTIVE: dumpsys vpn_management shows {} as the newest mode change",
                    newest_mode_line(&log).unwrap_or_else(|| "no lockdown mode change".into())
                ),
            )
        })?;
        if let Some(b) = baseline {
            if line != b {
                return fail(
                    step,
                    code,
                    format!("LOCKDOWN CHANGED: a mode change since the lock was proven: {line}"),
                );
            }
        }
        self.lockdown_active(step, code)?;
        self.vpn_check(step, want).map_err(|mut f| {
            f.code = code;
            f
        })?;
        self.socks_listening(step, "with the network lock on")
            .map_err(|mut f| {
                f.code = code;
                f
            })?;
        self.o.line(format!(
            "  lock proven: always-on {pkg} with lockdown (settings and run time: {line})"
        ));
        Ok(line)
    }

    /// Orbot as the lock provider: its VPN for `want`, the consent, connect,
    /// then the always-on VPN with lockdown in Settings.
    fn orbot_engage(&mut self, want: &[String]) -> Result<(), Failure> {
        let cfg = self.env.cfg;
        let opkg = cfg.orbot_package.clone();
        let labels = labels(want, 7)?;
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let found_consent =
            simplex::activate_vpn_mode(&p, &opkg).or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        let (found_app, found_lock) =
            simplex::lockdown_state(&p).or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        let mut vrec = VpnRecord {
            found_always_on_app: found_app.clone(),
            found_lockdown: Some(if found_lock { "1" } else { "0" }.to_string()),
            found_activate_vpn: found_consent.clone(),
            ..Default::default()
        };
        self.rec.vpn = Some(vrec.clone());
        // The VPN consent as an app op before Orbot runs at all: Orbot asks
        // for the VPN as soon as Power User Mode is off (seen on the 6a).
        p.appops_allow(&opkg, "ACTIVATE_VPN").or_else(|e| {
            fail(
                7,
                exit::DELIVERY_FAILED,
                format!("VPN CONSENT NOT GRANTED: {e}"),
            )
        })?;
        self.o
            .line("  VPN consent: app op ACTIVATE_VPN allowed before Orbot starts");
        orbot::launch(&p, &opkg).or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        let mut log = Vec::new();
        let sleep = self.env.sleep;
        let retries = self.env.ui_retries;
        let r = (|| -> Result<Found, String> {
            let mut ui = orbot::Ui {
                phone: &p,
                sleep,
                retries,
                log: &mut log,
                what: "Orbot set-up",
                found: Vec::new(),
            };
            ui.run(orbot::FLOW_VPN_SETTINGS)?;
            let apps_before = ui.select_apps(&orbot::PICKER, &labels)?;
            ui.run(orbot::FLOW_VPN_CONNECT)?;
            Ok((ui.found.clone(), apps_before))
        })();
        for l in &log {
            self.o.line(format!("  orbot: {l}"));
        }
        let (found_switches, apps_before) = r.or_else(|e| {
            let e = if e.contains("VPN consent dialog") {
                format!("VPN CONSENT NOT GRANTED: {e}")
            } else {
                e
            };
            fail(7, exit::DELIVERY_FAILED, e)
        })?;
        vrec.consent = true;
        if let Some(o) = self.rec.orbot.as_mut() {
            o.found_switches = found_switches
                .iter()
                .map(|(n, v)| (n.to_string(), *v))
                .collect();
            o.found_vpn_apps = apps_before;
        }
        let carried = self.vpn_check(7, want)?;
        self.o.line(format!(
            "  Orbot's VPN is up and carries exactly: {}",
            carried.join(", ")
        ));
        self.socks_listening(7, "while Orbot's VPN runs")?;
        self.o.line(format!(
            "  SOCKS listener on 127.0.0.1:{} while the VPN runs (our messenger's way to Tor)",
            orbot::SOCKS_PORT
        ));
        if let Some(o) = self.rec.orbot.as_mut() {
            o.socks_listening = true;
        }
        vrec.apps = want.to_vec();
        self.rec.vpn = Some(vrec.clone());
        // The always-on VPN with lockdown, in Settings (`settings put` has no
        // run-time effect, tested on the 6a).
        p.shell(&[
            "am",
            "start",
            "-a",
            "android.settings.VPN_SETTINGS",
            "--activity-clear-task",
        ])
        .or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        let mut log = Vec::new();
        let r = simplex::run_flow(
            &p,
            sleep,
            retries,
            "VPN settings",
            simplex::LOCKDOWN_ON,
            &mut log,
        );
        for l in &log {
            self.o.line(format!("  settings: {l}"));
        }
        let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
        r.or_else(|e| fail(7, exit::DELIVERY_FAILED, e))?;
        vrec.always_on = true;
        vrec.lockdown = true;
        self.rec.vpn = Some(vrec);
        Ok(())
    }

    /// Orbot as the lock provider: the delivered apps added to its VPN
    /// while it runs.
    fn orbot_extend(&mut self, want: &[String]) -> Result<(), Failure> {
        let opkg = self.env.cfg.orbot_package.clone();
        let labels = labels(want, 10)?;
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        orbot::launch(&p, &opkg).or_else(|e| fail(10, exit::DELIVERY_FAILED, e))?;
        let mut log = Vec::new();
        let (sleep, retries) = (self.env.sleep, self.env.ui_retries);
        let r = (|| -> Result<(), String> {
            let mut ui = orbot::Ui {
                phone: &p,
                sleep,
                retries,
                log: &mut log,
                what: "Orbot app list",
                found: Vec::new(),
            };
            ui.run(orbot::FLOW_VPN_APPS_OPEN)?;
            ui.select_apps(&orbot::PICKER, &labels)?;
            ui.run(orbot::FLOW_VPN_APPS_CLOSE)
        })();
        for l in &log {
            self.o.line(format!("  orbot: {l}"));
        }
        let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
        r.or_else(|e| fail(10, exit::DELIVERY_FAILED, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_lines_in_the_real_format() {
        let log = "      2026-01-01T12:00:10.000001 - [LockdownAlwaysOn] Mode changed: lockdown=false alwaysOn=true calling from 1000\n      2026-01-01T12:00:20.000002 - [LockdownAlwaysOn] Mode changed: lockdown=true alwaysOn=true calling from 1000\n      2026-01-01T12:00:00.000003 - [LockdownAlwaysOn] Mode changed: lockdown=false alwaysOn=false calling from 1000\n";
        let l = newest_mode_line(log).unwrap();
        assert!(l.starts_with("2026-01-01T12:00:20.000002"), "{l}");
        assert!(mode_line_on(&l));
        assert!(!mode_line_on(
            "2026-01-01T12:00:10 - [LockdownAlwaysOn] Mode changed: lockdown=false alwaysOn=true"
        ));
        assert_eq!(newest_mode_line("VPNs:\n"), None);
        assert_eq!(Provider::Orbot.name(), "Orbot");
        assert_eq!(
            first_apps(),
            ["app.seamlessupdate.client", "app.grapheneos.apps"]
        );
    }
}
