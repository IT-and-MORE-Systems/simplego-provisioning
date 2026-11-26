// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `sxprov undeliver` (test phones only) and `sxprov handover`.

use super::applinks::VERIFIER;
use super::orbot::{self, Step};
use super::phone::Phone;
use super::simplex;
use super::{find_target, open_store, provider, Env, Out};
use crate::activation::keys::test_key_id;
use crate::activation::store::{Delivery, Store};
use crate::device::{self, parse::Mode};
use crate::exit;
use crate::util::fmt_unix;
use crate::util::hex;
use std::io::Write;
use std::time::Duration;

/// The newest record of this serial that is not undone.
fn latest<'a>(deliveries: &'a mut [Delivery], serial: &str) -> Option<&'a mut Delivery> {
    deliveries
        .iter_mut()
        .rev()
        .find(|d| d.serial == serial && d.result != "undone")
}

fn err(o: &mut Out, code: i32, msg: impl AsRef<str>) -> i32 {
    o.line(msg);
    code
}

/// What `undeliver` was asked for.
#[derive(Debug, Clone, Copy, Default)]
pub struct UndoOpts {
    pub test_device: bool,
    /// Test only: a test phone whose messenger was set up (`setup=done`)
    /// is undone too, its profile deleted with the app. Only with
    /// `--test-device`, only for a test delivery in a throwaway test store.
    pub discard_test_setup: bool,
    pub json: bool,
}

/// Why `--discard-test-setup` is refused for this store and record, if it
/// is: a test config, a test delivery record, and a store that holds only
/// test deliveries and issues signed with the TEST ONLY key.
fn discard_refusal(allow_test_key: bool, st: &Store, rec: &Delivery) -> Option<String> {
    if !allow_test_key {
        return Some("--discard-test-setup needs a throwaway test config (allow_test_key_for_test_deliveries = true)".into());
    }
    if !rec.test {
        return Some(format!(
            "--discard-test-setup is refused: delivery {} is not a test delivery",
            rec.delivery_id
        ));
    }
    let test_key = hex(&test_key_id());
    let real_records = st.data.deliveries.iter().filter(|d| !d.test).count();
    let real_issues = st
        .data
        .issues
        .iter()
        .filter(|i| i.key_id != test_key)
        .count();
    if real_records > 0 || real_issues > 0 {
        return Some(format!(
            "--discard-test-setup is refused: this admin store holds {real_records} record(s) of real deliveries and {real_issues} issue(s) signed with a real key; it is only for a throwaway test store"
        ));
    }
    if let Some(f) = &rec.file_id {
        if !st
            .data
            .issues
            .iter()
            .any(|i| i.file_id == *f && i.key_id == test_key)
        {
            return Some(format!(
                "--discard-test-setup is refused: the activation {f} of this delivery is not in the store as signed with the TEST ONLY key"
            ));
        }
    }
    None
}

/// Removes a delivery from a test phone: only with `--test-device` and only
/// while the messenger reports `setup=open` (never a customer's phone);
/// with `--discard-test-setup` also a set-up test phone of a test delivery.
///
/// Order: the messenger's state is read before
/// anything changes; every app with `autoVerify` web hosts that this
/// delivery installed (the SimpleX app, the F-Droid client) is removed
/// while lockdown still blocks the app link verifier, and only then the
/// always-on VPN and lockdown go off; the verifier is enabled again last.
pub fn undeliver(env: &mut Env, out: &mut dyn Write, serial: &str, opts: UndoOpts) -> i32 {
    let mut o = Out::new(out, serial);
    o.json = opts.json;
    if opts.discard_test_setup && !opts.test_device {
        return err(
            &mut o,
            exit::UNDELIVER,
            "undeliver: --discard-test-setup is refused without --test-device",
        );
    }
    if !opts.test_device {
        return err(
            &mut o,
            exit::UNDELIVER,
            "undeliver: refused without --test-device (it is for the operator's own test phones only)",
        );
    }
    let mut st = match open_store(env.cfg, env.ui) {
        Ok(s) => s,
        Err((c, e)) => return err(&mut o, c, format!("undeliver: {e}")),
    };
    let Some(rec) = latest(&mut st.data.deliveries, serial).cloned() else {
        return err(
            &mut o,
            exit::UNDELIVER,
            "undeliver: no delivery record for this serial in the admin store",
        );
    };
    if opts.discard_test_setup {
        if let Some(why) = discard_refusal(env.cfg.allow_test_key_for_test_deliveries, &st, &rec) {
            return err(&mut o, exit::UNDELIVER, format!("undeliver: {why}"));
        }
    }
    if let Err(e) = find_target(&env.tools, serial) {
        return err(&mut o, exit::UNDELIVER, format!("undeliver: {e}"));
    }
    let p = Phone {
        tools: &env.tools,
        serial,
    };
    // The messenger of this delivery, as its record names it.
    let pkg = rec.messenger_package.clone();
    let auth = env.cfg.provider_authority(&pkg);
    // The messenger's state first: a customer's installation is never
    // touched, and nothing is changed before that is known.
    let state = (|| -> Result<Option<bool>, String> {
        if !p.installed(&pkg)? {
            return Ok(None);
        }
        let s = p
            .provider_call(&auth, "status", None)
            .and_then(|m| provider::status(&m))
            .map_err(|e| format!("the messenger's state cannot be read ({e}); refusing"))?;
        Ok(Some(s.setup_done))
    })();
    let messenger_there = match state {
        Err(e) => return err(&mut o, exit::UNDELIVER, format!("undeliver: {e}")),
        Ok(Some(true)) if !opts.discard_test_setup => {
            return err(
                &mut o,
                exit::UNDELIVER,
                format!(
                "undeliver: {pkg} reports setup=done: a customer's installation is never removed"
            ),
            )
        }
        Ok(Some(true)) => {
            o.line(format!(
                "--discard-test-setup: {pkg} reports setup=done on this test phone (test delivery {}). Deleted with the app: its app data, that is the messenger's profile on the phone (identity, contacts, messages, settings). No other app's data is touched except what this delivery installed.",
                rec.delivery_id
            ));
            true
        }
        Ok(Some(false)) => true,
        Ok(None) => false,
    };
    let r = (|| -> Result<Vec<String>, String> {
        let mut done = Vec::new();
        // The apps with app link hosts this delivery installed, while
        // lockdown still blocks the verifier: a verification waiting since
        // their install would otherwise go out when lockdown goes off.
        let with_hosts: Vec<String> = rec
            .app_links
            .as_ref()
            .map(|a| {
                a.hosts
                    .iter()
                    .filter(|(_, h)| !h.is_empty())
                    .map(|(p, _)| p.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut first: Vec<String> = [rec.simplex_app.as_ref(), rec.fdroid.as_ref()]
            .into_iter()
            .flatten()
            .filter(|a| a.installed_by_delivery)
            .map(|a| a.package.clone())
            .collect();
        for h in &with_hosts {
            // The messenger and Orbot are installed by every delivery that
            // names them; an app with hosts goes first in any case.
            let ours = *h == pkg
                || rec
                    .orbot
                    .as_ref()
                    .is_some_and(|o| o.installed_by_delivery && o.package == *h);
            if ours && !first.contains(h) {
                first.push(h.clone());
            }
        }
        for a in &first {
            if p.installed(a)? {
                p.uninstall(a)?;
                if p.installed(a)? {
                    return Err(format!("{a} is still listed after the uninstall"));
                }
                done.push(format!(
                    "{a} uninstalled (installed by this delivery; before lockdown goes off)"
                ));
            }
        }
        // The always-on VPN and its lockdown off while Orbot is still there,
        // back to what the delivery found.
        let orbot_pkg = rec
            .orbot
            .as_ref()
            .map(|o| o.package.clone())
            .unwrap_or_else(|| env.cfg.orbot_package.clone());
        if let Some(v) = rec.vpn.as_ref() {
            let (app, lock) = simplex::lockdown_state(&p)?;
            if (app.is_some() || lock) && p.installed(&orbot_pkg)? {
                p.shell(&[
                    "am",
                    "start",
                    "-a",
                    "android.settings.VPN_SETTINGS",
                    "--activity-clear-task",
                ])?;
                let mut log = Vec::new();
                let r = simplex::run_flow(
                    &p,
                    env.sleep,
                    env.ui_retries,
                    "VPN settings",
                    simplex::LOCKDOWN_OFF,
                    &mut log,
                );
                let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
                done.extend(log.into_iter().map(|l| format!("settings: {l}")));
                r?;
            }
            let (app, lock) = simplex::lockdown_state(&p)?;
            let want_lock = v.found_lockdown.as_deref() == Some("1");
            if app != v.found_always_on_app || lock != want_lock {
                return Err(format!(
                    "the always-on VPN is {app:?} with lockdown {lock}; found before the delivery: {:?} with lockdown {want_lock}",
                    v.found_always_on_app
                ));
            }
            done.push(format!(
                "always-on VPN and lockdown as found before the delivery ({}, lockdown {})",
                app.as_deref().unwrap_or("none"),
                if lock { "on" } else { "off" }
            ));
        }
        if p.installed(&pkg)? {
            p.uninstall(&pkg)?;
            if p.installed(&pkg)? {
                return Err(format!("{pkg} is still listed after the uninstall"));
            }
            if p.whitelisted(&pkg)? {
                return Err("the battery exception is still listed".into());
            }
            done.push(format!(
                "{pkg} uninstalled (battery exception removed with it)"
            ));
        } else if !messenger_there {
            done.push(format!("{pkg} was not installed"));
        }
        if let Some(orb) = rec.orbot.as_ref().filter(|o| o.installed_by_delivery) {
            if p.installed(&orb.package)? {
                p.uninstall(&orb.package)?;
                if p.installed(&orb.package)? {
                    return Err(format!(
                        "{} is still listed after the uninstall",
                        orb.package
                    ));
                }
                done.push(format!(
                    "{} uninstalled (installed by this delivery)",
                    orb.package
                ));
            }
        }
        // Orbot kept (it was on the phone before the delivery): its VPN
        // consent, its switches and its app list as found.
        if let (Some(v), Some(orb)) = (rec.vpn.as_ref(), rec.orbot.as_ref()) {
            if !orb.installed_by_delivery && p.installed(&orb.package)? {
                match v.found_activate_vpn.as_deref() {
                    Some(m @ ("allow" | "ignore" | "deny" | "default" | "foreground")) => {
                        p.shell(&["appops", "set", &orb.package, "ACTIVATE_VPN", m])?;
                        done.push(format!("Orbot's VPN consent app op back to {m}"));
                    }
                    _ => {
                        p.shell(&["appops", "set", &orb.package, "ACTIVATE_VPN", "default"])?;
                        done.push("Orbot's VPN consent app op back to default".into());
                    }
                }
                // The app list first (Orbot shows it only without Power User
                // Mode), then the switches; the last step of the set-up flow
                // (opening the app list) is left out.
                let n = orbot::FLOW_VPN_SETTINGS.len() - 1;
                let flow: Vec<Step> = orbot::FLOW_VPN_SETTINGS[..n]
                    .iter()
                    .map(|st| match st {
                        Step::Switch { title, want } => Step::Switch {
                            title: *title,
                            want: orb
                                .found_switches
                                .iter()
                                .find(|(n, _)| n == title.name)
                                .map(|(_, v)| *v)
                                .unwrap_or(*want),
                        },
                        other => *other,
                    })
                    .collect();
                let labels: Vec<&str> = orb.found_vpn_apps.iter().map(String::as_str).collect();
                orbot::launch(&p, &orb.package)?;
                let mut log = Vec::new();
                let r = (|| {
                    let mut ui = orbot::Ui {
                        phone: &p,
                        sleep: env.sleep,
                        retries: env.ui_retries,
                        log: &mut log,
                        what: "Orbot restore",
                        found: Vec::new(),
                    };
                    ui.run(&orbot::FLOW_VPN_SETTINGS[..1])?;
                    ui.run(&orbot::FLOW_VPN_SETTINGS[n..])?;
                    ui.select_apps(&orbot::PICKER, &labels)?;
                    ui.run(&[Step::Tap(orbot::NAVIGATE_UP)])?;
                    ui.run(&flow)
                })();
                let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
                done.extend(log.into_iter().map(|l| format!("orbot: {l}")));
                r?;
                done.push("Orbot's switches and app list as found before the delivery".into());
            }
        }
        // Orbot removed: Android dropped it as the always-on VPN with it.
        if rec.vpn.is_some() && !p.installed(&orbot_pkg)? {
            let (app, lock) = simplex::lockdown_state(&p)?;
            if app.as_deref() == Some(orbot_pkg.as_str()) || lock {
                return Err(format!(
                    "Orbot is removed but Settings still names {app:?} as the always-on VPN with lockdown {lock}"
                ));
            }
        }
        let calc = env.cfg.system_calculator_package.clone();
        if p.packages(Some("-d"))?.contains(&calc) {
            p.enable(&calc)?;
            if p.packages(Some("-d"))?.contains(&calc) {
                return Err(format!("{calc} is still disabled"));
            }
            done.push(format!("{calc} enabled again"));
        }
        // App link verification on again, last (only if this delivery
        // turned it off).
        if rec
            .app_links
            .as_ref()
            .is_some_and(|a| a.disabled_by_delivery)
            && p.packages(Some("-d"))?.iter().any(|x| x == VERIFIER)
        {
            p.enable(VERIFIER)?;
            if p.packages(Some("-d"))?.iter().any(|x| x == VERIFIER) {
                return Err(format!("{VERIFIER} is still disabled"));
            }
            // The system looks the verifier up once, at boot
            // (PackageManagerService): until the next reboot it has none.
            done.push(format!(
                "{VERIFIER} enabled again; app link verification works again only after the next reboot of the phone (Android looks the verifier up once, at boot)"
            ));
        }
        Ok(done)
    })();
    match r {
        Ok(done) => {
            for d in &done {
                o.line(format!("  {d}"));
            }
            if let Some(m) = latest(&mut st.data.deliveries, serial) {
                m.result = "undone".into();
                m.undone_at = Some(fmt_unix((env.now)()));
            }
            if let Err(e) = st.save(env.rng) {
                return err(
                    &mut o,
                    exit::STORE,
                    format!("undeliver: the record could not be saved: {e}"),
                );
            }
            o.event(serde_json::json!({"event": "undone", "delivery_id": rec.delivery_id}));
            o.line(format!(
                "UNDONE: delivery {} marked undone",
                rec.delivery_id
            ));
            exit::OK
        }
        Err(e) => err(&mut o, exit::UNDELIVER, format!("undeliver: {e}")),
    }
}

/// Ends the delivery: turns USB debugging off, so adb access ends. Shows
/// the record, asks for `HANDOVER` typed in full, then checks that the
/// device drops out of the list or goes offline.
pub fn handover(env: &mut Env, out: &mut dyn Write, serial: &str, json: bool) -> i32 {
    let mut o = Out::new(out, serial);
    o.json = json;
    let mut st = match open_store(env.cfg, env.ui) {
        Ok(s) => s,
        Err((c, e)) => return err(&mut o, c, format!("handover: {e}")),
    };
    let Some(rec) = latest(&mut st.data.deliveries, serial).cloned() else {
        return err(
            &mut o,
            exit::HANDOVER,
            "handover: no delivery record for this serial",
        );
    };
    if rec.result != "delivered" || rec.handover_at.is_some() {
        return err(
            &mut o,
            exit::HANDOVER,
            format!(
                "handover: the newest record is {}{}; only a delivered phone is handed over",
                rec.result,
                if rec.handover_at.is_some() {
                    ", already handed over"
                } else {
                    ""
                }
            ),
        );
    }
    if let Err(e) = find_target(&env.tools, serial) {
        return err(&mut o, exit::HANDOVER, format!("handover: {e}"));
    }
    let p = Phone {
        tools: &env.tools,
        serial,
    };
    match p
        .provider_call(
            &env.cfg.provider_authority(&rec.messenger_package),
            "status",
            None,
        )
        .and_then(|m| provider::status(&m))
    {
        Ok(s) if s.activation && !s.setup_done => {}
        Ok(s) => {
            return err(
                &mut o,
                exit::HANDOVER,
                format!(
                "handover: status is activation={} setup={}, expected activation=yes setup=open",
                if s.activation { "yes" } else { "no" },
                if s.setup_done { "done" } else { "open" }
            ),
            )
        }
        Err(e) => return err(&mut o, exit::HANDOVER, format!("handover: {e}")),
    }
    o.line(format!(
        "delivery {}: device {}, {}{}, customer {}, messenger versionCode {} {}, Orbot {}, file_id {}, file transferred {}, code {}, delivered {}",
        rec.delivery_id,
        rec.serial_masked,
        rec.tier,
        if rec.test { " (TEST)" } else { "" },
        rec.customer_ref,
        rec.messenger_version_code.map(|v| v.to_string()).unwrap_or_default(),
        if rec.messenger_verified { "verified" } else { "UNVERIFIED" },
        rec.orbot.as_ref().map(|x| x.version_code.to_string()).unwrap_or_else(|| "none".into()),
        rec.file_id.as_deref().unwrap_or("-"),
        rec.file_transferred,
        rec.code_masked.as_deref().unwrap_or("-"),
        rec.ended_at.as_deref().unwrap_or("?")
    ));
    o.line("Handover turns USB debugging off. adb access to this phone ends here.");
    match env
        .ui
        .confirm("HANDOVER", "Type HANDOVER to turn USB debugging off: ")
    {
        Ok(true) => {}
        Ok(false) => {
            return err(
                &mut o,
                exit::HANDOVER,
                "handover: not confirmed; nothing changed",
            )
        }
        Err(e) => {
            return err(
                &mut o,
                exit::HANDOVER,
                format!("handover: needs a typed confirmation: {e}"),
            )
        }
    }
    // The connection may drop while the command runs; the check below decides.
    let _ = p.shell(&["settings", "put", "global", "adb_enabled", "0"]);
    let mut gone = false;
    for i in 0..=env.ui_retries {
        let listed = device::adb_devices(&env.tools)
            .map(|t| device::parse::parse_adb_devices(&t))
            .unwrap_or_default();
        let still = listed
            .iter()
            .any(|d| d.serial == serial && d.mode == Mode::Adb);
        if !still {
            gone = true;
            break;
        }
        if i < env.ui_retries {
            (env.sleep)(Duration::from_secs(1));
        }
    }
    if !gone {
        return err(
            &mut o,
            exit::HANDOVER,
            "handover: the device still answers over adb; USB debugging is not off",
        );
    }
    if let Some(m) = latest(&mut st.data.deliveries, serial) {
        m.handover_at = Some(fmt_unix((env.now)()));
    }
    if let Err(e) = st.save(env.rng) {
        return err(
            &mut o,
            exit::STORE,
            format!("handover: the record could not be saved: {e}"),
        );
    }
    o.line("HANDED OVER: USB debugging is off, the device left the adb list; time recorded");
    exit::OK
}
