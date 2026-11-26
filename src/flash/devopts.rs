// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! OEM unlocking, read and turned on over adb UI automation in Developer
//! options (same rules as the Orbot flow: elements by resource id or text,
//! taps at the centre of the bounds the dump reports, every dump file
//! deleted on the phone after each read).
//!
//! `getprop sys.oem_unlock_allowed` is not readable by the shell user on
//! GrapheneOS 2026111801, so the switch on the screen is the
//! source. If the phone asks for its PIN, or the switch is greyed out or not
//! shown, nothing is tapped further: the operator is told which switch to
//! turn on.

use crate::deliver::orbot::{self, find, row_of, switch_in, Node, Sel};
use crate::deliver::phone::Phone;
use std::time::Duration;

pub const ACTION: &str = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS";
pub const TITLE: Sel = Sel {
    id: Some("android:id/title"),
    text: Some("OEM unlocking"),
    name: "OEM unlocking",
};
/// The confirmation dialog's positive button ("Enable").
pub const ENABLE: Sel = Sel {
    id: Some("android:id/button1"),
    text: None,
    name: "Enable button of the OEM unlocking dialog",
};

/// What the operator must do by hand.
pub const MANUAL: &str = "On the phone: open Settings > System > Developer options and turn on \
     \"OEM unlocking\" (enter the phone's PIN if it asks, then tap Enable).";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Oem {
    On,
    Off,
    /// The switch is off and cannot be changed here (greyed out).
    Greyed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    AlreadyOn,
    TurnedOn,
    /// Not done; the reason, for the operator.
    Manual(String),
}

fn credential_screen(nodes: &[Node]) -> bool {
    nodes.iter().any(|n| {
        let t = n.text.to_ascii_lowercase();
        n.resource_id.ends_with(":id/password_entry")
            || n.resource_id.ends_with(":id/pinEntry")
            || n.resource_id.ends_with(":id/lockPattern")
            || t.contains("enter your pin")
            || t.contains("enter your password")
            || t.contains("draw your pattern")
            || t == "confirm your pin"
    })
}

fn state(nodes: &[Node]) -> Option<(Oem, Node)> {
    let (i, _) = find(nodes, &TITLE)?;
    let row = row_of(nodes, i);
    let sw = switch_in(nodes, row)?;
    let st = if nodes[sw].checked {
        Oem::On
    } else if !nodes[sw].enabled || !nodes[row].enabled {
        Oem::Greyed
    } else {
        Oem::Off
    };
    Some((st, nodes[row].clone()))
}

pub struct DevOpts<'a> {
    pub phone: &'a Phone<'a>,
    pub sleep: &'a dyn Fn(Duration),
    pub retries: u32,
    pub log: &'a mut Vec<String>,
}

impl DevOpts<'_> {
    fn ui(&mut self) -> orbot::Ui<'_> {
        orbot::Ui {
            phone: self.phone,
            sleep: self.sleep,
            retries: self.retries,
            log: self.log,
            what: "OEM unlocking",
            found: Vec::new(),
        }
    }

    /// A screen read, retried while `uiautomator dump` fails.
    fn read(&mut self) -> Result<Vec<Node>, String> {
        let mut last = String::new();
        for i in 0..=self.retries {
            match self.ui().dump() {
                Ok(n) => return Ok(n),
                Err(e) if e.starts_with("could not delete") => return Err(e),
                Err(e) => last = e,
            }
            if i < self.retries {
                (self.sleep)(Duration::from_secs(1));
            }
        }
        Err(format!("Developer options: {last}"))
    }

    fn open(&mut self) -> Result<Vec<Node>, String> {
        self.phone.shell(&["am", "start", "-a", ACTION])?;
        for i in 0..=self.retries {
            (self.sleep)(Duration::from_millis(800));
            let n = self.read()?;
            if find(&n, &TITLE).is_some() || i == self.retries {
                return Ok(n);
            }
        }
        unreachable!()
    }

    fn home(&mut self) {
        let _ = self.phone.shell(&["input", "keyevent", "KEYCODE_HOME"]);
    }

    /// Reads the switch. None: the row is not on the screen (Developer
    /// options off, screen locked, or another layout).
    pub fn read_state(&mut self) -> Result<Option<Oem>, String> {
        let n = self.open();
        self.home();
        Ok(state(&n?).map(|(s, _)| s))
    }

    /// Turns OEM unlocking on if it is off. Never types a PIN.
    pub fn ensure_on(&mut self) -> Result<Outcome, String> {
        let r = self.ensure_inner();
        self.home();
        r
    }

    fn ensure_inner(&mut self) -> Result<Outcome, String> {
        let nodes = self.open()?;
        let Some((st, row)) = state(&nodes) else {
            return Ok(Outcome::Manual(
                "the OEM unlocking switch is not on the Developer options screen (are Developer options on and the screen unlocked?)".into(),
            ));
        };
        match st {
            Oem::On => {
                self.log.push("OEM unlocking: already on".into());
                return Ok(Outcome::AlreadyOn);
            }
            Oem::Greyed => {
                return Ok(Outcome::Manual(
                    "the OEM unlocking switch is greyed out (the phone may need an internet connection once, or the bootloader is already unlocked)".into(),
                ))
            }
            Oem::Off => {}
        }
        let (x, y) = row.centre();
        self.log.push(format!("tap OEM unlocking at {x},{y}"));
        self.phone
            .shell(&["input", "tap", &x.to_string(), &y.to_string()])?;
        (self.sleep)(Duration::from_millis(800));
        let d = self.read()?;
        if credential_screen(&d) {
            // Leave the PIN screen; nothing is typed.
            let _ = self.phone.shell(&["input", "keyevent", "KEYCODE_BACK"]);
            return Ok(Outcome::Manual("the phone asks for its PIN".into()));
        }
        let Some((_, ok)) = find(&d, &ENABLE) else {
            return Ok(Outcome::Manual(
                "the OEM unlocking confirmation dialog did not show".into(),
            ));
        };
        let (x, y) = ok.centre();
        self.log.push(format!("tap {} at {x},{y}", ENABLE.name));
        self.phone
            .shell(&["input", "tap", &x.to_string(), &y.to_string()])?;
        (self.sleep)(Duration::from_millis(800));
        let after = self.read()?;
        match state(&after) {
            Some((Oem::On, _)) => {
                self.log.push("OEM unlocking: turned on".into());
                Ok(Outcome::TurnedOn)
            }
            _ => Ok(Outcome::Manual(
                "OEM unlocking did not show as on after the dialog".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_state_and_pin_screen() {
        // As on a Pixel 6a: title, summary, switch in one row.
        let row = |checked: bool, enabled: bool| {
            format!(
                r#"<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation="0"><node index="0" text="" resource-id="" class="android.widget.LinearLayout" package="com.android.settings" content-desc="" checkable="false" checked="false" clickable="true" enabled="{enabled}" bounds="[0,1405][1080,1597]"><node index="0" text="OEM unlocking" resource-id="android:id/title" class="android.widget.TextView" package="com.android.settings" content-desc="" checkable="false" checked="false" clickable="false" enabled="{enabled}" bounds="[42,1447][700,1500]" /><node index="1" text="" resource-id="com.android.settings:id/switchWidget" class="android.widget.Switch" package="com.android.settings" content-desc="" checkable="true" checked="{checked}" clickable="false" enabled="{enabled}" bounds="[900,1450][1040,1550]" /></node></hierarchy>"#
            )
        };
        let n = orbot::parse_dump(&row(true, true)).unwrap();
        assert_eq!(state(&n).unwrap().0, Oem::On);
        let n = orbot::parse_dump(&row(false, true)).unwrap();
        let (s, r) = state(&n).unwrap();
        assert_eq!(s, Oem::Off);
        assert_eq!(r.centre(), (540, 1501));
        let n = orbot::parse_dump(&row(false, false)).unwrap();
        assert_eq!(state(&n).unwrap().0, Oem::Greyed);
        let pin = r#"<hierarchy><node text="Enter your PIN" resource-id="" class="x" package="com.android.settings" content-desc="" checkable="false" checked="false" clickable="false" bounds="[0,0][10,10]" /></hierarchy>"#;
        assert!(credential_screen(&orbot::parse_dump(pin).unwrap()));
        assert!(!credential_screen(
            &orbot::parse_dump(&row(false, true)).unwrap()
        ));
    }
}
