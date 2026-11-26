// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Orbot set up over adb, without a manual step: SOCKS only (never VPN
//! mode, so no system consent dialog), start on boot, SOCKS port 9050,
//! connect, then a listener on 127.0.0.1:9050 on the phone.
//!
//! The screen is read with `uiautomator dump` into a file in
//! `/data/local/tmp` that is deleted after every read. Elements are found by
//! resource id or text, never by fixed coordinates; a tap goes to the centre
//! of the bounds the dump reports for the element found (or of its nearest
//! clickable ancestor).
//!
//! `FLOW` follows the real screens of Orbot 17.9.8-RC-1 (versionCode
//! 1798300102), read with `uiautomator dump` on a Pixel 6a with GrapheneOS
//! on 2026-11-23. In this version SOCKS without VPN is "Power User Mode"
//! (General settings); the SOCKS port is "Tor SOCKS" under Debug. Power User
//! Mode needs the exact-alarm app op and asks to leave battery optimisation;
//! both are set over adb before the flow (`deliver` step 6), so no dialog is
//! expected. Another Orbot version may change these screens: the flow then
//! stops with the name of the element it did not find.

use crate::deliver::phone::Phone;
use std::time::Duration;

pub const PACKAGE_DEFAULT: &str = "org.torproject.android";
pub const DUMP_PATH: &str = "/data/local/tmp/sxprov-ui.xml";
pub const SOCKS_PORT: u16 = 9050;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    pub text: String,
    pub resource_id: String,
    pub content_desc: String,
    pub class: String,
    pub package: String,
    pub checkable: bool,
    pub checked: bool,
    pub clickable: bool,
    /// `enabled` in the dump (true when the attribute is missing).
    pub enabled: bool,
    pub bounds: (i32, i32, i32, i32),
    pub parent: Option<usize>,
}

impl Node {
    pub fn centre(&self) -> (i32, i32) {
        let (l, t, r, b) = self.bounds;
        ((l + r) / 2, (t + b) / 2)
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(j) = rest.find(';') else { break };
        let ent = &rest[1..j];
        let c = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[j + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_bounds(s: &str) -> Option<(i32, i32, i32, i32)> {
    // "[l,t][r,b]"
    let v: Vec<i32> = s
        .split(['[', ']', ','])
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<i32>>>()?;
    match v.as_slice() {
        [l, t, r, b] => Some((*l, *t, *r, *b)),
        _ => None,
    }
}

/// Parses a `uiautomator dump` file into a flat list with parent links.
pub fn parse_dump(xml: &str) -> Result<Vec<Node>, String> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i..];
        let end = rest.find('>').ok_or("damaged UI dump")?;
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            if name.trim() == "node" {
                stack.pop().ok_or("damaged UI dump: unbalanced node")?;
            }
            continue;
        }
        let self_closing = tag.ends_with('/');
        let body = tag.trim_end_matches('/');
        let (name, attrs) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
        if name != "node" {
            continue;
        }
        let mut n = Node {
            parent: stack.last().copied(),
            enabled: true,
            ..Default::default()
        };
        let mut a = attrs;
        while let Some(eq) = a.find("=\"") {
            let key = a[..eq].trim();
            let after = &a[eq + 2..];
            let close = after.find('"').ok_or("damaged UI dump: attribute")?;
            let val = unescape(&after[..close]);
            match key {
                "text" => n.text = val,
                "resource-id" => n.resource_id = val,
                "content-desc" => n.content_desc = val,
                "class" => n.class = val,
                "package" => n.package = val,
                "checkable" => n.checkable = val == "true",
                "checked" => n.checked = val == "true",
                "clickable" => n.clickable = val == "true",
                "enabled" => n.enabled = val == "true",
                "bounds" => n.bounds = parse_bounds(&val).ok_or("damaged UI dump: bounds")?,
                _ => {}
            }
            a = &after[close + 1..];
        }
        nodes.push(n);
        if !self_closing {
            stack.push(nodes.len() - 1);
        }
    }
    if nodes.is_empty() {
        return Err("the UI dump holds no elements".into());
    }
    Ok(nodes)
}

/// An element by resource id, by text (exact, ignoring case) or both.
#[derive(Debug, Clone, Copy)]
pub struct Sel {
    pub id: Option<&'static str>,
    pub text: Option<&'static str>,
    /// How the element is named in an error message.
    pub name: &'static str,
}

impl Sel {
    /// `id` may be `class:NAME` for an element without a resource id (a
    /// Compose text field).
    pub fn matches(&self, n: &Node) -> bool {
        self.id.is_none_or(|i| match i.strip_prefix("class:") {
            Some(c) => n.class == c,
            None => n.resource_id == i,
        }) && self.text.is_none_or(|t| {
            n.text.eq_ignore_ascii_case(t) || n.content_desc.eq_ignore_ascii_case(t)
        })
    }
}

pub fn find<'a>(nodes: &'a [Node], s: &Sel) -> Option<(usize, &'a Node)> {
    nodes.iter().enumerate().find(|(_, n)| s.matches(n))
}

pub fn ancestors(nodes: &[Node], i: usize) -> impl Iterator<Item = usize> + '_ {
    std::iter::successors(Some(i), move |&k| nodes[k].parent)
}

/// The row of a settings entry: the nearest clickable ancestor of `i`.
pub fn row_of(nodes: &[Node], i: usize) -> usize {
    ancestors(nodes, i)
        .find(|&k| nodes[k].clickable)
        .unwrap_or(i)
}

/// The checkable element (switch) inside a row.
pub fn switch_in(nodes: &[Node], row: usize) -> Option<usize> {
    (0..nodes.len()).find(|&k| nodes[k].checkable && ancestors(nodes, k).any(|a| a == row))
}

#[derive(Debug, Clone, Copy)]
pub enum Step {
    /// Taps an element (its nearest clickable ancestor).
    Tap(Sel),
    /// Taps a checkable element itself unless it is already `checked == want`.
    Check { el: Sel, want: bool },
    /// Taps an element if it is shown in the next screen read, else nothing.
    TapIfShown(Sel),
    /// Fails if any element of `package` is shown (a system dialog).
    Absent {
        package: &'static str,
        name: &'static str,
    },
    /// Makes the switch in the row of the element `checked == want`.
    Switch { title: Sel, want: bool },
    /// Opens the row of `title`, sets the text field `field` to `value` and
    /// confirms with `ok`, unless the row's summary already shows `value`.
    Text {
        title: Sel,
        field: Sel,
        value: &'static str,
        ok: Sel,
    },
    /// The back key.
    Back,
    /// Waits until an element is shown (up to the retry limit).
    WaitFor(Sel),
    /// Waits up to `retries` screen reads (one second apart) for an element
    /// whose text or description contains `contains` (a network fetch).
    WaitText {
        contains: &'static str,
        name: &'static str,
        retries: u32,
    },
    /// Like `Switch`, but a confirmation dialog may show after the tap; its
    /// `confirm` button is tapped if shown.
    SwitchConfirm {
        title: Sel,
        want: bool,
        confirm: Sel,
    },
    /// Taps the text field and replaces its text with `value`.
    TypeInto { field: Sel, value: &'static str },
    /// Taps the element `gear` inside the row of `title` (a settings gear).
    TapIn { title: Sel, gear: Sel },
    /// Scrolls down (a swipe) until the element is shown, at most `swipes`
    /// times.
    ScrollTo { el: Sel, swipes: u32 },
    /// Taps the centre of the element itself, not of its clickable row
    /// (Orbot's "Choose apps": the row's centre lies under another box).
    TapSelf(Sel),
    /// Taps the first element that matches and has a clickable ancestor (a
    /// button whose text a title repeats: F-Droid's "Add repository").
    TapButton(Sel),
}

const fn id(id: &'static str, name: &'static str) -> Sel {
    Sel {
        id: Some(id),
        text: None,
        name,
    }
}
const fn title(text: &'static str) -> Sel {
    Sel {
        id: Some("android:id/title"),
        text: Some(text),
        name: text,
    }
}
const fn label(text: &'static str, name: &'static str) -> Sel {
    Sel {
        id: Some("org.torproject.android:id/tvLabel"),
        text: Some(text),
        name,
    }
}
const fn id_text(id: &'static str, text: &'static str, name: &'static str) -> Sel {
    Sel {
        id: Some(id),
        text: Some(text),
        name,
    }
}

const CONNECT: Sel = id(
    "org.torproject.android:id/switchConnect",
    "Orbot connect switch",
);

/// Orbot 17.9.8-RC-1, device-tested (see the module comment).
pub const FLOW: &[Step] = &[
    Step::WaitFor(CONNECT),
    Step::Tap(id(
        "org.torproject.android:id/moreFragment",
        "Orbot More tab",
    )),
    Step::Tap(label("Orbot Settings", "Orbot Settings entry")),
    Step::Tap(title("General")),
    Step::Switch {
        title: title("Start Orbot on Boot"),
        want: true,
    },
    Step::Switch {
        title: title("Open Proxy on All Interfaces"),
        want: false,
    },
    // SOCKS and HTTP proxy without the VPN.
    Step::Switch {
        title: title("Power User Mode"),
        want: true,
    },
    Step::Back,
    Step::Tap(title("Debug")),
    Step::Text {
        title: title("Tor SOCKS"),
        field: id("android:id/edit", "SOCKS port text field"),
        value: "9050",
        ok: id("android:id/button1", "OK button of the SOCKS port dialog"),
    },
    Step::Back,
    Step::Back,
    Step::Tap(id(
        "org.torproject.android:id/connectFragment",
        "Orbot Connect tab",
    )),
    Step::WaitFor(CONNECT),
    Step::Check {
        el: CONNECT,
        want: true,
    },
    // Only if the battery exception did not take (it is set before).
    Step::TapIfShown(id_text(
        "android:id/button2",
        "Connect anyway",
        "Connect anyway button of the battery dialog",
    )),
    Step::Absent {
        package: "com.android.vpndialogs",
        name: "the system VPN consent dialog",
    },
    Step::WaitFor(id_text(
        "org.torproject.android:id/tvTitle",
        "Connected",
        "Orbot status Connected",
    )),
];

/// Orbot's own VPN, for the apps on its "Choose apps" list only
/// The settings part of `FLOW` with Power User
/// Mode turned off (it means "without the VPN"); the SOCKS port stays 9050,
/// which the VPN's tun2socks uses itself, so our messenger keeps it.
pub const FLOW_VPN_SETTINGS: &[Step] = &[
    Step::WaitFor(CONNECT),
    Step::Tap(id(
        "org.torproject.android:id/moreFragment",
        "Orbot More tab",
    )),
    Step::Tap(label("Orbot Settings", "Orbot Settings entry")),
    Step::Tap(title("General")),
    Step::Switch {
        title: title("Start Orbot on Boot"),
        want: true,
    },
    Step::Switch {
        title: title("Open Proxy on All Interfaces"),
        want: false,
    },
    // Off: Orbot starts its VPN.
    Step::Switch {
        title: title("Power User Mode"),
        want: false,
    },
    Step::Back,
    Step::Tap(title("Debug")),
    Step::Text {
        title: title("Tor SOCKS"),
        field: id("android:id/edit", "SOCKS port text field"),
        value: "9050",
        ok: id("android:id/button1", "OK button of the SOCKS port dialog"),
    },
    Step::Back,
    Step::Back,
    Step::Tap(id(
        "org.torproject.android:id/connectFragment",
        "Orbot Connect tab",
    )),
    Step::WaitFor(CONNECT),
    Step::TapSelf(label("Choose apps", "Orbot Choose apps")),
];

/// Orbot's app list opened again while its VPN runs (the delivered apps are
/// added after the lock is on).
pub const FLOW_VPN_APPS_OPEN: &[Step] = &[
    Step::WaitFor(CONNECT),
    Step::TapSelf(label("Choose apps", "Orbot Choose apps")),
];

/// Back from the app list while the VPN runs: Orbot saves the list and
/// restarts its VPN with it (`RESTART_VPN`: the tun is closed and set up
/// again); the always-on VPN and lockdown are the system's and stay.
pub const FLOW_VPN_APPS_CLOSE: &[Step] = &[
    Step::Tap(NAVIGATE_UP),
    Step::WaitFor(CONNECT),
    Step::Absent {
        package: "com.android.vpndialogs",
        name: "the system VPN consent dialog",
    },
    Step::WaitFor(id_text(
        "org.torproject.android:id/tvTitle",
        "Connected",
        "Orbot status Connected",
    )),
];

/// The toolbar's up button ("Navigate up").
pub const NAVIGATE_UP: Sel = Sel {
    id: None,
    text: Some("Navigate up"),
    name: "Navigate up button",
};

/// Orbot's app list ("Choose apps").
pub const PICKER: Picker = Picker {
    search: Sel {
        id: Some("org.torproject.android:id/searchBar"),
        text: None,
        name: "search field of Orbot's app list",
    },
    item_text: "org.torproject.android:id/itemtext",
    item_check: "org.torproject.android:id/itemcheck",
};

/// Back from the app list (Orbot saves it), then connect: with the
/// `ACTIVATE_VPN` app op allowed, no consent dialog may show.
pub const FLOW_VPN_CONNECT: &[Step] = &[
    // Not the back key: with the keyboard of the search field open it only
    // closes the keyboard (Pixel 6a, 2026-11-24).
    Step::Tap(NAVIGATE_UP),
    Step::WaitFor(CONNECT),
    Step::Check {
        el: CONNECT,
        want: true,
    },
    Step::TapIfShown(id_text(
        "android:id/button2",
        "Connect anyway",
        "Connect anyway button of the battery dialog",
    )),
    Step::Absent {
        package: "com.android.vpndialogs",
        name: "the system VPN consent dialog",
    },
    Step::WaitFor(id_text(
        "org.torproject.android:id/tvTitle",
        "Connected",
        "Orbot status Connected",
    )),
];

pub struct Ui<'a> {
    pub phone: &'a Phone<'a>,
    pub sleep: &'a dyn Fn(Duration),
    pub retries: u32,
    pub log: &'a mut Vec<String>,
    /// Names the flow in error messages ("Orbot set-up", ...).
    pub what: &'a str,
    /// The state each `Switch` found before it changed anything.
    pub found: Vec<(&'static str, bool)>,
}

/// `input text` takes no spaces; `%s` stands for one.
pub fn input_text(v: &str) -> String {
    v.replace(' ', "%s")
}

impl Ui<'_> {
    /// One screen read. The dump file is removed on the phone whatever
    /// happened before (a failed `uiautomator dump` may still leave it).
    pub fn dump(&mut self) -> Result<Vec<Node>, String> {
        let made = self.phone.shell(&["uiautomator", "dump", DUMP_PATH]);
        let xml = match made {
            Ok(_) => self.phone.shell(&["cat", DUMP_PATH]),
            Err(e) => Err(e),
        };
        self.phone
            .shell(&["rm", "-f", DUMP_PATH])
            .map_err(|e| format!("could not delete the UI dump on the phone: {e}"))?;
        parse_dump(&xml.map_err(|e| format!("screen read failed: {e}"))?)
    }

    /// A screen read that is retried while it fails (`uiautomator dump`
    /// fails while a screen is still changing). Only a failed `rm` of the
    /// dump file stops at once.
    fn dump_retrying(&mut self) -> Result<Vec<Node>, String> {
        let w = self.what;
        let mut last = String::new();
        for i in 0..=self.retries {
            match self.dump() {
                Ok(n) => return Ok(n),
                Err(e) if e.starts_with("could not delete") => return Err(e),
                Err(e) => last = e,
            }
            self.log
                .push(format!("screen read failed, retrying: {last}"));
            if i < self.retries {
                (self.sleep)(Duration::from_secs(1));
            }
        }
        Err(format!("{w}: {last}"))
    }

    /// Short pause after an input, so the next read sees the new screen.
    fn settle(&self) {
        (self.sleep)(Duration::from_millis(800));
    }

    fn tap(&mut self, n: &Node, what: &str) -> Result<(), String> {
        let (x, y) = n.centre();
        self.log.push(format!("tap {what} at {x},{y}"));
        self.phone
            .shell(&["input", "tap", &x.to_string(), &y.to_string()])?;
        self.settle();
        Ok(())
    }

    fn wait_for(&mut self, s: &Sel) -> Result<Vec<Node>, String> {
        let w = self.what;
        for i in 0..=self.retries {
            let nodes = self.dump_retrying()?;
            if find(&nodes, s).is_some() {
                return Ok(nodes);
            }
            if i < self.retries {
                (self.sleep)(Duration::from_secs(1));
            }
        }
        Err(format!("{w}: element not found: {}", s.name))
    }

    /// Replaces the text of the field `n` with `value` (it is tapped first).
    fn replace_text(&mut self, n: &Node, name: &str, value: &str) -> Result<(), String> {
        self.tap(n, name)?;
        let mut keys = vec!["input", "keyevent", "KEYCODE_MOVE_END"];
        let dels = n.text.chars().count();
        keys.extend(std::iter::repeat_n("KEYCODE_DEL", dels));
        self.phone.shell(&keys)?;
        if !value.is_empty() {
            self.phone.shell(&["input", "text", &input_text(value)])?;
        }
        self.settle();
        Ok(())
    }

    fn step(&mut self, st: &Step) -> Result<(), String> {
        let w = self.what;
        match st {
            Step::WaitFor(s) => self.wait_for(s).map(|_| ()),
            Step::Tap(s) => {
                let nodes = self.wait_for(s)?;
                let (i, _) = find(&nodes, s).ok_or(format!("element not found: {}", s.name))?;
                self.tap(&nodes[row_of(&nodes, i)].clone(), s.name)
            }
            Step::Check { el, want } => {
                let nodes = self.wait_for(el)?;
                let (_, n) = find(&nodes, el).ok_or(format!("element not found: {}", el.name))?;
                if !n.checkable {
                    return Err(format!("{w}: {} is not a switch", el.name));
                }
                if n.checked != *want {
                    self.tap(&n.clone(), el.name)?;
                } else {
                    self.log.push(format!(
                        "{}: already {}",
                        el.name,
                        if *want { "on" } else { "off" }
                    ));
                }
                Ok(())
            }
            Step::TapIfShown(s) => {
                (self.sleep)(Duration::from_secs(2));
                let nodes = self.dump_retrying()?;
                if let Some((i, _)) = find(&nodes, s) {
                    self.tap(&nodes[row_of(&nodes, i)].clone(), s.name)?;
                }
                Ok(())
            }
            Step::Absent { package, name } => {
                let nodes = self.dump_retrying()?;
                if nodes.iter().any(|n| n.package == *package) {
                    return Err(format!("{w}: {name} is shown; stopped"));
                }
                Ok(())
            }
            Step::Back => {
                self.phone.shell(&["input", "keyevent", "KEYCODE_BACK"])?;
                self.settle();
                Ok(())
            }
            Step::Switch { title, want } => {
                let nodes = self.wait_for(title)?;
                let (i, _) = find(&nodes, title).ok_or("unreachable")?;
                let row = row_of(&nodes, i);
                let sw = switch_in(&nodes, row).ok_or(format!(
                    "Orbot set-up: element not found: the switch of {}",
                    title.name
                ))?;
                self.found.push((title.name, nodes[sw].checked));
                if nodes[sw].checked != *want {
                    self.tap(&nodes[row].clone(), title.name)?;
                    let after = self.wait_for(title)?;
                    let (i, _) = find(&after, title).ok_or("unreachable")?;
                    let sw = switch_in(&after, row_of(&after, i)).ok_or("switch vanished")?;
                    if after[sw].checked != *want {
                        return Err(format!(
                            "Orbot set-up: {} did not change to {}",
                            title.name,
                            if *want { "on" } else { "off" }
                        ));
                    }
                }
                self.log.push(format!(
                    "{}: {}",
                    title.name,
                    if *want { "on" } else { "off" }
                ));
                Ok(())
            }
            Step::Text {
                title,
                field,
                value,
                ok,
            } => {
                let nodes = self.wait_for(title)?;
                let (i, _) = find(&nodes, title).ok_or("unreachable")?;
                let row = row_of(&nodes, i);
                let shown = (0..nodes.len()).find(|&k| {
                    nodes[k].resource_id == "android:id/summary"
                        && ancestors(&nodes, k).any(|a| a == row)
                });
                if shown.is_some_and(|k| nodes[k].text == *value) {
                    self.log.push(format!("{}: already {value}", title.name));
                    return Ok(());
                }
                self.tap(&nodes[row].clone(), title.name)?;
                let d = self.wait_for(field)?;
                let (_, f) = find(&d, field).ok_or("unreachable")?;
                let f = f.clone();
                if f.text == *value {
                    let (_, okn) =
                        find(&d, ok).ok_or(format!("{w}: element not found: {}", ok.name))?;
                    self.tap(&okn.clone(), ok.name)?;
                    self.log.push(format!("{}: already {value}", title.name));
                    return Ok(());
                }
                self.tap(&f, field.name)?;
                let mut keys = vec!["input", "keyevent", "KEYCODE_MOVE_END"];
                let dels = f.text.chars().count();
                keys.extend(std::iter::repeat_n("KEYCODE_DEL", dels));
                self.phone.shell(&keys)?;
                self.phone.shell(&["input", "text", value])?;
                let d = self.dump_retrying()?;
                let typed = find(&d, field).map(|(_, n)| n.text.clone());
                if typed.as_deref() != Some(value) {
                    return Err(format!(
                        "Orbot set-up: {} shows {:?} instead of {value}",
                        field.name,
                        typed.unwrap_or_default()
                    ));
                }
                let (_, okn) =
                    find(&d, ok).ok_or(format!("{w}: element not found: {}", ok.name))?;
                self.tap(&okn.clone(), ok.name)?;
                self.log.push(format!("{}: set to {value}", title.name));
                Ok(())
            }
            other => Err(format!("{w}: step {other:?} is not handled here")),
        }
    }

    /// Steps that need more than `step`: see `Step`.
    fn step_more(&mut self, st: &Step) -> Result<(), String> {
        let w = self.what;
        match st {
            Step::WaitText {
                contains,
                name,
                retries,
            } => {
                for i in 0..=*retries {
                    let nodes = self.dump_retrying()?;
                    if nodes
                        .iter()
                        .any(|n| n.text.contains(contains) || n.content_desc.contains(contains))
                    {
                        return Ok(());
                    }
                    if i < *retries {
                        (self.sleep)(Duration::from_secs(1));
                    }
                }
                Err(format!("{w}: not shown in time: {name}"))
            }
            Step::SwitchConfirm {
                title,
                want,
                confirm,
            } => {
                let state = |nodes: &[Node]| -> Result<(usize, bool), String> {
                    let (i, _) = find(nodes, title)
                        .ok_or(format!("{w}: element not found: {}", title.name))?;
                    let row = row_of(nodes, i);
                    let sw = switch_in(nodes, row).ok_or(format!(
                        "{w}: element not found: the switch of {}",
                        title.name
                    ))?;
                    Ok((row, nodes[sw].checked))
                };
                let nodes = self.wait_for(title)?;
                let (row, on) = state(&nodes)?;
                self.found.push((title.name, on));
                if on != *want {
                    self.tap(&nodes[row].clone(), title.name)?;
                    let d = self.dump_retrying()?;
                    if let Some((_, b)) = find(&d, confirm) {
                        self.tap(&b.clone(), confirm.name)?;
                    }
                    let after = self.wait_for(title)?;
                    if state(&after)?.1 != *want {
                        return Err(format!(
                            "{w}: {} did not change to {}",
                            title.name,
                            if *want { "on" } else { "off" }
                        ));
                    }
                }
                self.log.push(format!(
                    "{}: {}",
                    title.name,
                    if *want { "on" } else { "off" }
                ));
                Ok(())
            }
            Step::TypeInto { field, value } => {
                let nodes = self.wait_for(field)?;
                let (_, f) = find(&nodes, field).ok_or("unreachable")?;
                let f = f.clone();
                self.replace_text(&f, field.name, value)?;
                let d = self.dump_retrying()?;
                let typed = find(&d, field).map(|(_, n)| n.text.clone());
                if typed.as_deref() != Some(value) {
                    return Err(format!(
                        "{w}: {} shows {:?} instead of {value}",
                        field.name,
                        typed.unwrap_or_default()
                    ));
                }
                self.log.push(format!("{}: {value}", field.name));
                Ok(())
            }
            Step::TapIn { title, gear } => {
                let nodes = self.wait_for(title)?;
                let (i, _) = find(&nodes, title).ok_or("unreachable")?;
                let row = row_of(&nodes, i);
                let row = nodes[row]
                    .parent
                    .filter(|_| !nodes[row].clickable)
                    .unwrap_or(row);
                let g = (0..nodes.len())
                    .find(|&k| {
                        gear.matches(&nodes[k])
                            && ancestors(&nodes, k)
                                .any(|a| a == row || Some(a) == nodes[row].parent)
                    })
                    .ok_or(format!(
                        "{w}: element not found: {} of {}",
                        gear.name, title.name
                    ))?;
                self.tap(&nodes[g].clone(), gear.name)
            }
            Step::TapButton(s) => {
                let nodes = self.wait_for(s)?;
                let row = (0..nodes.len())
                    .filter(|&i| s.matches(&nodes[i]))
                    .map(|i| row_of(&nodes, i))
                    .find(|&r| nodes[r].clickable)
                    .ok_or(format!("{w}: no clickable element: {}", s.name))?;
                self.tap(&nodes[row].clone(), s.name)
            }
            Step::TapSelf(s) => {
                let nodes = self.wait_for(s)?;
                let (_, n) =
                    find(&nodes, s).ok_or(format!("{w}: element not found: {}", s.name))?;
                self.tap(&n.clone(), s.name)
            }
            Step::ScrollTo { el, swipes } => {
                for i in 0..=*swipes {
                    let nodes = self.dump_retrying()?;
                    if find(&nodes, el).is_some() {
                        return Ok(());
                    }
                    if i < *swipes {
                        self.phone
                            .shell(&["input", "swipe", "540", "1700", "540", "700", "300"])?;
                        self.settle();
                    }
                }
                Err(format!(
                    "{w}: element not found after scrolling: {}",
                    el.name
                ))
            }
            other => self.step(other),
        }
    }

    pub fn run(&mut self, flow: &[Step]) -> Result<(), String> {
        for st in flow {
            self.step_more(st)?;
        }
        Ok(())
    }

    /// Orbot's "Choose apps" list: exactly the apps named `wanted` (labels
    /// as the list shows them) are checked afterwards. Returns the labels
    /// that were checked before. The list is filtered with its search field
    /// (by label); Orbot saves the choice when the screen is left.
    pub fn select_apps(&mut self, p: &Picker, wanted: &[&str]) -> Result<Vec<String>, String> {
        let w = self.what;
        let rows = |nodes: &[Node]| -> Vec<(String, usize, bool)> {
            nodes
                .iter()
                .enumerate()
                .filter(|(_, n)| n.resource_id == p.item_text)
                .filter_map(|(i, n)| {
                    // Label and check box are siblings in one row container.
                    let row = nodes[i].parent?;
                    let cb = (0..nodes.len()).find(|&k| {
                        nodes[k].resource_id == p.item_check
                            && ancestors(nodes, k).any(|a| a == row)
                    })?;
                    Some((n.text.clone(), cb, nodes[cb].checked))
                })
                .collect()
        };
        let nodes = self.wait_for(&p.search)?;
        let before: Vec<String> = rows(&nodes)
            .into_iter()
            .filter(|r| r.2)
            .map(|r| r.0)
            .collect();
        // Every app checked now that is not wanted: unchecked, one at a
        // time (the list moves the checked apps to the top).
        let mut nodes = nodes;
        for _ in 0..=64 {
            let Some((label, cb, _)) = rows(&nodes)
                .into_iter()
                .find(|(l, _, on)| *on && !wanted.contains(&l.as_str()))
            else {
                break;
            };
            self.tap(&nodes[cb].clone(), &format!("check box of {label} (off)"))?;
            nodes = self.dump_retrying()?;
        }
        for label in wanted {
            let nodes = self.wait_for(&p.search)?;
            let (_, f) = find(&nodes, &p.search).ok_or("unreachable")?;
            let f = f.clone();
            self.replace_text(&f, p.search.name, label)?;
            let d = self.dump_retrying()?;
            let hits: Vec<(String, usize, bool)> =
                rows(&d).into_iter().filter(|r| r.0 == *label).collect();
            let (_, cb, on) = match hits.as_slice() {
                [one] => one.clone(),
                [] => return Err(format!("{w}: the app list shows no app named {label:?}")),
                _ => {
                    return Err(format!(
                        "{w}: the app list shows more than one app named {label:?}"
                    ))
                }
            };
            if !on {
                self.tap(&d[cb].clone(), &format!("check box of {label}"))?;
                let d2 = self.dump_retrying()?;
                if !rows(&d2).iter().any(|r| r.0 == *label && r.2) {
                    return Err(format!("{w}: {label} is not checked after the tap"));
                }
            }
            self.log.push(format!("app list: {label} checked"));
        }
        // The search cleared: the list shows the checked apps first.
        let nodes = self.wait_for(&p.search)?;
        let (_, f) = find(&nodes, &p.search).ok_or("unreachable")?;
        let f = f.clone();
        self.replace_text(&f, p.search.name, "")?;
        let d = self.dump_retrying()?;
        let checked: Vec<String> = rows(&d).into_iter().filter(|r| r.2).map(|r| r.0).collect();
        for c in &checked {
            if !wanted.contains(&c.as_str()) {
                return Err(format!("{w}: {c} is still checked in the app list"));
            }
        }
        Ok(before)
    }
}

/// Where the app list keeps its parts.
#[derive(Debug, Clone, Copy)]
pub struct Picker {
    pub search: Sel,
    /// Resource ids of the label and the check box of one list row.
    pub item_text: &'static str,
    pub item_check: &'static str,
}

/// True if `/proc/net/tcp` (or `tcp6`) shows a listener on 127.0.0.1:port.
pub fn listening(proc_net_tcp: &str, port: u16) -> bool {
    let want_v4 = format!("0100007F:{port:04X}");
    let want_v6 = format!("0000000000000000FFFF00000100007F:{port:04X}");
    proc_net_tcp.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 3 && (f[1] == want_v4 || f[1] == want_v6) && f[3] == "0A"
    })
}

/// Starts Orbot's launcher activity.
pub fn launch(phone: &Phone, package: &str) -> Result<(), String> {
    let out = phone.shell(&[
        "cmd",
        "package",
        "resolve-activity",
        "--brief",
        "-c",
        "android.intent.category.LAUNCHER",
        package,
    ])?;
    let comp = out
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with(&format!("{package}/")))
        .ok_or(format!("no launcher activity for {package}"))?
        .to_string();
    phone.shell(&["am", "start", "-n", &comp]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = r#"<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation="0"><node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="org.torproject.android" content-desc="" checkable="false" checked="false" clickable="false" bounds="[0,0][1080,2400]"><node index="0" text="" resource-id="" class="android.widget.LinearLayout" package="org.torproject.android" content-desc="" checkable="false" checked="false" clickable="true" bounds="[0,300][1080,500]"><node index="0" text="Start Orbot on Boot" resource-id="android:id/title" class="android.widget.TextView" package="org.torproject.android" content-desc="" checkable="false" checked="false" clickable="false" bounds="[40,320][800,380]" /><node index="1" text="" resource-id="android:id/switch_widget" class="android.widget.Switch" package="org.torproject.android" content-desc="" checkable="true" checked="false" clickable="false" bounds="[900,340][1040,460]" /></node><node index="1" text="Tor &amp; &quot;SOCKS&quot;" resource-id="x:id/y" class="android.widget.TextView" package="p" content-desc="" checkable="false" checked="false" clickable="true" bounds="[0,600][100,700]" /></node></hierarchy>"#;

    #[test]
    fn dump_rows_and_switches() {
        let n = parse_dump(DUMP).unwrap();
        assert_eq!(n.len(), 5);
        let (i, t) = find(&n, &title("start orbot on boot")).unwrap();
        assert_eq!(t.bounds, (40, 320, 800, 380));
        let row = row_of(&n, i);
        assert_eq!(n[row].centre(), (540, 400));
        let sw = switch_in(&n, row).unwrap();
        assert!(!n[sw].checked);
        assert_eq!(n[4].text, "Tor & \"SOCKS\"");
        assert!(find(&n, &title("VPN Mode")).is_none());
        assert!(parse_dump("<hierarchy></hierarchy>").is_err());
    }

    #[test]
    fn socks_listener() {
        let tcp = "  sl  local_address rem_address   st\n   0: 0100007F:235A 00000000:0000 0A 00000000:00000000\n";
        assert!(listening(tcp, 9050));
        assert!(!listening(tcp, 9150));
        let established = "   0: 0100007F:235A 0100007F:9C40 01 0:0\n";
        assert!(!listening(established, 9050));
    }
}
