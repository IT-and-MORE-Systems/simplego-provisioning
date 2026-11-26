// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Fake fastboot, the second personality of the fake adb binary: started
//! under the name `fastboot` (a hard link next to `adb` in the scenario
//! directory), it shares `state.json` with the fake adb, so the simulated
//! phone moves between adb and the bootloader.
//!
//! Every call goes to `calls.log`: `fastboot -s <serial> ...` or, for the
//! official script (no `-s`), `fastboot [ANDROID_SERIAL=<serial>] ...`. A
//! call without a serial is logged as `<NO SERIAL>` and fails; another
//! device as `<OTHER:n>`.
//!
//! States: the phone in adb (`device`), in the bootloader (`fastboot`)
//! locked or unlocked, flashing (the script's writes are recorded), and
//! booted after the flash (`after_boot`: new props and attestation chain,
//! user data wiped). `crlf` answers with Windows line ends like
//! `fastboot.exe`.

use super::{bad, ok, Reply, State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Fb {
    pub product: String,
    pub unlocked: bool,
    pub current_slot: String,
    /// What the operator does on the phone: "yes" confirms, anything else
    /// never confirms.
    pub unlock_confirm: String,
    pub lock_confirm: String,
    /// `getvar unlocked` polls until a confirmed unlock or lock shows.
    pub confirm_after: u32,
    pub pending_unlock: Option<u32>,
    pub pending_lock: Option<u32>,
    /// A script command (joined arguments) that fails.
    pub fail_at: Option<String>,
    /// Write commands the script ran, in order.
    pub flashed: Vec<String>,
    pub crlf: bool,
    /// Set when a lock completes after a flash: the next `adb devices -l`
    /// boots the phone into `after_boot`.
    pub locked_after_flash: bool,
    /// Wipes seen (unlock and lock).
    pub wipes: u32,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct AfterBoot {
    pub props: BTreeMap<String, String>,
    pub agent_chain: Vec<String>,
}

fn wipe(st: &mut State) {
    st.packages.retain(|_, p| p.system);
    st.whitelist.clear();
    st.disabled.clear();
    st.appops.clear();
    st.provider = Default::default();
    st.fastboot.wipes += 1;
}

/// The phone boots after the flash (called from `adb devices -l`).
pub fn maybe_boot(st: &mut State) {
    if !st.fastboot.locked_after_flash {
        return;
    }
    let Some(ab) = st.after_boot.clone() else {
        return;
    };
    st.fastboot.locked_after_flash = false;
    st.props = ab.props;
    st.agent_chain = ab.agent_chain;
    let t = st.target.clone();
    for d in st.devices.iter_mut().filter(|d| d.serial == t) {
        d.state = "device".into();
    }
}

fn reply(r: Reply, crlf: bool) -> Reply {
    if !crlf {
        return r;
    }
    Reply {
        out: r.out.replace('\n', "\r\n"),
        err: r.err.replace('\n', "\r\n"),
        code: r.code,
    }
}

/// The log line and the serial this call addresses.
pub fn log_line(st: &State, args: &[String]) -> (String, Option<String>) {
    let env = std::env::var("ANDROID_SERIAL").ok();
    let mask = |s: &str| {
        if s == st.target {
            "<serial>".to_string()
        } else {
            format!("<OTHER:{}>", s.len())
        }
    };
    if args.first().map(String::as_str) == Some("-s") && args.len() > 1 {
        let rest = args[2..].join(" ");
        return (
            format!("fastboot -s {} {rest}", mask(&args[1])),
            Some(args[1].clone()),
        );
    }
    let rest = args.join(" ");
    let no_device = matches!(
        args.first().map(String::as_str),
        Some("devices") | Some("--version")
    );
    match env {
        Some(s) if !no_device => (
            format!("fastboot [ANDROID_SERIAL={}] {rest}", mask(&s)),
            Some(s),
        ),
        _ if no_device => (format!("fastboot {rest}"), None),
        _ => (format!("fastboot <NO SERIAL> {rest}"), None),
    }
}

fn done(text: &str) -> Reply {
    Reply {
        out: String::new(),
        err: format!("{text}\nFinished. Total time: 0.010s\n"),
        code: 0,
    }
}

pub fn handle(st: &mut State, args: &[String], serial: Option<String>) -> Reply {
    let crlf = st.fastboot.crlf;
    reply(handle_inner(st, args, serial), crlf)
}

fn handle_inner(st: &mut State, args: &[String], serial: Option<String>) -> Reply {
    let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
    if a.first() == Some(&"-s") {
        a.drain(..2.min(a.len()));
    }
    match a.as_slice() {
        ["--version"] => {
            return ok("fastboot version 37.0.0-14910828\nInstalled as /fake/fastboot\n")
        }
        ["devices"] | ["devices", "-l"] => {
            let l = a.len() == 2;
            return ok(st
                .devices
                .iter()
                .filter(|d| d.state == "fastboot")
                .map(|d| {
                    if l {
                        format!("{}\t fastboot usb:1-1\n", d.serial)
                    } else {
                        format!("{}\tfastboot\n", d.serial)
                    }
                })
                .collect::<String>());
        }
        _ => {}
    }
    let Some(serial) = serial else {
        return bad("fake fastboot: a call without a serial\n");
    };
    if serial != st.target {
        return bad("fake fastboot: this device must never be addressed\n");
    }
    if !st
        .devices
        .iter()
        .any(|d| d.serial == serial && d.state == "fastboot")
    {
        // The real fastboot waits forever here.
        return bad(format!("< waiting for {serial} >\n"));
    }
    let joined = a.join(" ");
    if st.fastboot.fail_at.as_deref() == Some(joined.as_str()) {
        return bad(format!(
            "FAILED (remote: 'test failure of {joined}')\nfastboot: error: Command failed\n"
        ));
    }
    let fb = &mut st.fastboot;
    match a.as_slice() {
        ["getvar", "unlocked"] => {
            if let Some(n) = fb.pending_unlock {
                if n == 0 {
                    fb.pending_unlock = None;
                    fb.unlocked = true;
                    wipe(st);
                } else {
                    fb.pending_unlock = Some(n - 1);
                }
            } else if let Some(n) = fb.pending_lock {
                if n == 0 {
                    fb.pending_lock = None;
                    fb.unlocked = false;
                    fb.locked_after_flash = !fb.flashed.is_empty();
                    wipe(st);
                } else {
                    fb.pending_lock = Some(n - 1);
                }
            }
            let v = if st.fastboot.unlocked { "yes" } else { "no" };
            done(&format!("unlocked: {v}"))
        }
        ["getvar", "product"] => done(&format!("product: {}", fb.product)),
        ["getvar", "slot-count"] => done("slot-count: 2"),
        ["getvar", "max-download-size"] => done("max-download-size: 0xf900000"),
        ["getvar", "current-slot"] => done(&format!("current-slot: {}", fb.current_slot)),
        ["flashing", "unlock"] => {
            if fb.unlocked {
                return done("OKAY");
            }
            fb.pending_unlock = if fb.unlock_confirm == "yes" {
                Some(fb.confirm_after)
            } else {
                None
            };
            done("OKAY")
        }
        ["flashing", "lock"] => {
            if !fb.unlocked {
                return done("OKAY");
            }
            if fb.lock_confirm == "yes" {
                fb.pending_lock = Some(fb.confirm_after);
            }
            done("OKAY")
        }
        ["reboot-bootloader"] => done("Rebooting into bootloader\nOKAY"),
        [s] if s.starts_with("--set-active=") => {
            let v = &s["--set-active=".len()..];
            fb.current_slot = match v {
                "other" => if fb.current_slot == "a" { "b" } else { "a" }.into(),
                x => x.into(),
            };
            done(&format!(
                "Setting current slot to '{}'\nOKAY",
                fb.current_slot
            ))
        }
        [cmd, ..]
            if ["flash", "erase", "oem", "update", "snapshot-update"].contains(cmd)
                || cmd.starts_with("--") =>
        {
            if !fb.unlocked {
                return bad("FAILED (remote: 'Flashing is not allowed in Lock State')\nfastboot: error: Command failed\n");
            }
            fb.flashed.push(joined.clone());
            done(&format!("{joined}\nOKAY"))
        }
        _ => bad(format!("fastboot: unknown command {joined}\n")),
    }
}
