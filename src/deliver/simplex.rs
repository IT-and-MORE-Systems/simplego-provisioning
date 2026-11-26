// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The normal SimpleX app on every delivered phone: the official, unchanged
//! `chat.simplex.app`
//! from SimpleX's own F-Droid repository, installed with the F-Droid client,
//! both reaching the network only through Orbot's VPN (Tor) from the first
//! second. Our messenger stays outside the VPN on Orbot's SOCKS port 9050
//! over loopback. We create nothing and start nothing inside the SimpleX
//! app. Customer-facing wording: "the normal SimpleX app for all your
//! SimpleX contacts".
//!
//! Order (decided 2026-11-24):
//!
//! - step 4: the F-Droid client APK (pinned signer); SimpleX's index checked
//!   (`crate::fdroid`) and the SimpleX APK downloaded over Tor and checked
//!   against the index and the pinned app signer;
//! - step 7: both installed (the SimpleX app with the F-Droid client as its
//!   installer of record), battery exceptions; neither is started;
//! - step 8: Orbot with its VPN for exactly four apps (the SimpleX app, the
//!   F-Droid client, the GrapheneOS System Updater and App Store), SOCKS
//!   9050, start on boot, the VPN consent as an app op (no dialog), then the
//!   always-on VPN with "block connections without VPN" (lockdown) in
//!   Settings. Every other app has no network, by design;
//! - step 9: only now the F-Droid client's first start: its own SOCKS proxy
//!   set to Orbot (a second layer), then SimpleX's repository added with the
//!   `fdroidrepos://` intent and one tap on "Add".
//!
//! The packages are found by name on the phone (`pm list packages -U`),
//! never by a fixed uid.

use super::orbot::{self, Sel, Step};
use super::phone::Phone;
use std::collections::{BTreeMap, BTreeSet};

/// The apps inside Orbot's VPN besides the SimpleX app and the F-Droid
/// client: GrapheneOS updates go over Tor too.
pub const SYSTEM_VPN_APPS: [&str; 2] = ["app.seamlessupdate.client", "app.grapheneos.apps"];

/// The label Orbot's app list shows for each app of the VPN.
pub const LABELS: &[(&str, &str)] = &[
    ("chat.simplex.app", "SimpleX"),
    ("org.fdroid.fdroid", "F-Droid"),
    ("app.seamlessupdate.client", "System Updater"),
    ("app.grapheneos.apps", "App Store"),
];

pub fn label_of(package: &str) -> Option<&'static str> {
    LABELS.iter().find(|(p, _)| *p == package).map(|(_, l)| *l)
}

/// `pm list packages -U`: package name to uid.
pub fn parse_uids(out: &str) -> BTreeMap<String, u32> {
    out.lines()
        .filter_map(|l| {
            let l = l.trim().strip_prefix("package:")?;
            let (name, rest) = l.split_once(' ')?;
            let uid = rest.trim().strip_prefix("uid:")?;
            let uid = uid.split(',').next()?.trim().parse().ok()?;
            Some((name.to_string(), uid))
        })
        .collect()
}

/// A VPN network as `dumpsys connectivity` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnNet {
    pub uids: BTreeSet<u32>,
    pub owner: Option<u32>,
}

fn uid_ranges(s: &str) -> Option<BTreeSet<u32>> {
    // "{10050-10050}, {10051-10051}"
    let mut out = BTreeSet::new();
    for part in s.split(',') {
        let p = part.trim().trim_start_matches('{').trim_end_matches('}');
        if p.is_empty() {
            continue;
        }
        let (a, b) = p.split_once('-').unwrap_or((p, p));
        let (a, b): (u32, u32) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
        if b < a || b - a > 100_000 {
            return None;
        }
        out.extend(a..=b);
    }
    Some(out)
}

/// The connected VPN networks (`NetworkAgentInfo` lines with the VPN
/// transport): the uids they carry and their owner.
pub fn parse_vpn(dumpsys: &str) -> Vec<VpnNet> {
    let mut v: Vec<VpnNet> = dumpsys
        .lines()
        // With an underlying network the transports read "WIFI|VPN"; the
        // network info "ni{VPN CONNECTED" names the VPN either way.
        .filter(|l| l.contains("NetworkAgentInfo") && l.contains("ni{VPN CONNECTED"))
        .filter_map(|l| {
            let uids = l
                .split_once("Uids: <")
                .and_then(|(_, r)| r.split_once('>'))
                .and_then(|(u, _)| uid_ranges(u))?;
            let owner = l
                .split_once("OwnerUid: ")
                .and_then(|(_, r)| r.split_whitespace().next())
                .and_then(|x| x.parse().ok());
            Some(VpnNet { uids, owner })
        })
        .collect();
    v.dedup();
    v
}

/// What `dumpsys package` says about user 0 and the installer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgState {
    pub stopped: Option<bool>,
    pub not_launched: Option<bool>,
    pub installer: Option<String>,
}

pub fn parse_pkg_state(dump: &str) -> PkgState {
    let mut s = PkgState::default();
    for l in dump.lines().map(str::trim) {
        if let Some(r) = l.strip_prefix("installerPackageName=") {
            let v = r.split_whitespace().next().unwrap_or_default();
            s.installer = (v != "null" && !v.is_empty()).then(|| v.to_string());
        }
        if l.starts_with("User 0:") {
            for w in l.split_whitespace() {
                match w.split_once('=') {
                    Some(("stopped", v)) => s.stopped = Some(v == "true"),
                    Some(("notLaunched", v)) => s.not_launched = Some(v == "true"),
                    _ => {}
                }
            }
        }
    }
    s
}

pub use crate::installed::pm_signature_hashes;

/// One TCP socket from `/proc/net/tcp` or `tcp6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub local: String,
    pub remote: String,
    /// `0A` listen, `01` established, ...
    pub state: String,
    pub uid: u32,
}

impl Sock {
    pub fn remote_is_loopback(&self) -> bool {
        self.remote.starts_with("127.") || self.remote.starts_with("[::1]")
    }
}

fn addr(hexaddr: &str) -> Option<String> {
    let (ip, port) = hexaddr.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let b: Vec<u8> = (0..ip.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(ip.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    match b.len() {
        4 => Some(format!("{}.{}.{}.{}:{port}", b[3], b[2], b[1], b[0])),
        16 => {
            // Four 32-bit words, each little endian. A mapped IPv4 address
            // is shown as IPv4.
            let w: Vec<[u8; 4]> = b.chunks(4).map(|c| [c[3], c[2], c[1], c[0]]).collect();
            if w[0] == [0; 4] && w[1] == [0; 4] && w[2] == [0, 0, 0xff, 0xff] {
                let v = w[3];
                return Some(format!("{}.{}.{}.{}:{port}", v[0], v[1], v[2], v[3]));
            }
            let parts: Vec<String> = w
                .iter()
                .flat_map(|x| {
                    [
                        u16::from_be_bytes([x[0], x[1]]),
                        u16::from_be_bytes([x[2], x[3]]),
                    ]
                })
                .map(|x| format!("{x:x}"))
                .collect();
            Some(format!("[{}]:{port}", parts.join(":")))
        }
        _ => None,
    }
}

pub fn parse_sockets(proc_net_tcp: &str) -> Vec<Sock> {
    proc_net_tcp
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            Some(Sock {
                local: addr(f[1])?,
                remote: addr(f[2])?,
                state: f[3].to_string(),
                uid: f[7].parse().ok()?,
            })
        })
        .collect()
}

// ---- the screens ----------------------------------------------------------
//
// Built from the strings and resource ids of the apps (Orbot 17.9.8-RC-1,
// F-Droid 2.0.3, AOSP Settings) and the GrapheneOS Settings app; checked
// against the real screens on a Pixel 6a.

const fn text(t: &'static str, name: &'static str) -> Sel {
    Sel {
        id: None,
        text: Some(t),
        name,
    }
}
const fn settings_title(t: &'static str) -> Sel {
    Sel {
        id: Some("android:id/title"),
        text: Some(t),
        name: t,
    }
}
const BUTTON1: Sel = Sel {
    id: Some("android:id/button1"),
    text: None,
    name: "OK button of the dialog",
};

/// Settings > Network & internet > VPN, opened with
/// `am start -a android.settings.VPN_SETTINGS`: Orbot's gear, then the two
/// switches. Turning lockdown on asks for a confirmation.
pub const LOCKDOWN_ON: &[Step] = &[
    Step::TapIn {
        title: settings_title("Orbot"),
        gear: Sel {
            id: Some("com.android.settings:id/settings_button"),
            text: None,
            name: "settings gear",
        },
    },
    Step::SwitchConfirm {
        title: settings_title("Always-on VPN"),
        want: true,
        confirm: BUTTON1,
    },
    Step::SwitchConfirm {
        title: settings_title("Block connections without VPN"),
        want: true,
        confirm: BUTTON1,
    },
];

/// The same screen, both switches off (undeliver).
pub const LOCKDOWN_OFF: &[Step] = &[
    Step::TapIn {
        title: settings_title("Orbot"),
        gear: Sel {
            id: Some("com.android.settings:id/settings_button"),
            text: None,
            name: "settings gear",
        },
    },
    Step::SwitchConfirm {
        title: settings_title("Block connections without VPN"),
        want: false,
        confirm: BUTTON1,
    },
    Step::SwitchConfirm {
        title: settings_title("Always-on VPN"),
        want: false,
        confirm: BUTTON1,
    },
];

/// The F-Droid client's first start, after the VPN is up: its own SOCKS
/// proxy set to Orbot ("Connect via SOCKS proxy", `host:port`).
pub const FDROID_PROXY: &[Step] = &[
    Step::WaitText {
        contains: "F-Droid",
        name: "the F-Droid client",
        retries: 30,
    },
    Step::Tap(text("Settings", "F-Droid Settings")),
    Step::ScrollTo {
        el: text("Connect via SOCKS proxy", "Connect via SOCKS proxy"),
        swipes: 8,
    },
    Step::Tap(text("Connect via SOCKS proxy", "Connect via SOCKS proxy")),
    Step::TypeInto {
        field: Sel {
            id: Some("class:android.widget.EditText"),
            text: None,
            name: "SOCKS proxy text field",
        },
        value: "127.0.0.1:9050",
    },
    Step::Tap(text("OK", "OK button of the proxy dialog")),
    // The summary then reads "Uses 127.0.0.1:9050 to connect".
    Step::WaitText {
        contains: "Uses 127.0.0.1:9050",
        name: "the proxy setting 127.0.0.1:9050",
        retries: 5,
    },
    Step::Back,
];

/// The client's hints, shown once per screen ("Got it").
const GOT_IT: Sel = Sel {
    id: None,
    text: Some("Got it"),
    name: "Got it of the client's hint",
};

/// After the `fdroidrepos://` intent: the client fetches the repository
/// over Tor (slow), shows it, and adds it with one tap.
///
/// As read on the Pixel 6a (F-Droid 2.0.3, 2026-11-24): the screen shows the
/// repository ("SimpleX Chat F-Droid", `app.simplex.chat/fdroid/repo`) and a
/// button "Add repository" (the title has the same text; the button is the
/// one in a clickable row); then the repository's app list with a hint.
/// The caller first waits for the repository on the screen (see
/// `wait_for_repo`).
pub const FDROID_TAP_ADD: &[Step] = &[
    Step::TapButton(text("Add repository", "Add repository button")),
    Step::TapIfShown(GOT_IT),
];

/// The repository intent is sent once more when the repository is not shown
/// this long after the last intent.
pub const REPO_RESEND_AFTER_SECS: u64 = 240;

/// The "Add repository" button (a clickable row), not the screen's title of
/// the same text.
pub fn add_button_shown(nodes: &[orbot::Node]) -> bool {
    nodes.iter().enumerate().any(|(i, n)| {
        n.text.eq_ignore_ascii_case("Add repository")
            && orbot::ancestors(nodes, i).any(|k| nodes[k].clickable)
    })
}

/// SimpleX's repository shown in the client after it was added (its name;
/// the caller checks that the "Add repository" button is gone).
pub fn repo_added(nodes: &[orbot::Node]) -> bool {
    nodes
        .iter()
        .any(|n| n.text.contains("SimpleX Chat F-Droid"))
}

/// The final check, from a fresh start of the client: its repository list
/// (the "Repositories" button of the main screen) names SimpleX's, and its
/// details show the signing key fingerprint (checked by the caller against
/// the pin on the screen read after this flow).
pub const FDROID_REPO_LISTED: &[Step] = &[
    Step::WaitText {
        contains: "F-Droid",
        name: "the F-Droid client",
        retries: 30,
    },
    Step::Tap(text("Repositories", "Repositories button")),
    Step::TapIfShown(GOT_IT),
    Step::Tap(text(
        "SimpleX Chat F-Droid",
        "SimpleX's repository in the list",
    )),
    Step::TapIfShown(GOT_IT),
    Step::Tap(text(
        "Signing key fingerprint (SHA-256)",
        "Signing key fingerprint",
    )),
];

/// Starts an app's launcher activity afresh (`am start -S`: the app is
/// stopped first, so it opens on its main screen, not where it was left).
pub fn launch_fresh(phone: &Phone, package: &str) -> Result<String, String> {
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
    phone.shell(&["am", "start", "-S", "-n", &comp])?;
    Ok(comp)
}

/// The uid ranges of "Lockdown filtering rules" in `dumpsys connectivity`:
/// the uids that are blocked outside the VPN. Empty: no lockdown at run
/// time (`settings put` alone does not set any).
pub fn lockdown_rules(dumpsys: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut inside = false;
    for l in dumpsys.lines() {
        let t = l.trim();
        if t.starts_with("Lockdown filtering rules:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        match t.strip_prefix("UIDs: ") {
            Some(r) => {
                let (a, b) = r.split_once('-').unwrap_or((r, r));
                if let (Ok(a), Ok(b)) = (a.trim().parse(), b.trim().parse()) {
                    out.push((a, b));
                }
            }
            None => break,
        }
    }
    out
}

/// An app uid for a uid the VPN lists: the SDK sandbox uid of an app
/// (app id 20000 to 29999, Android 13 and later) counts as the app.
pub fn app_uid(uid: u32) -> u32 {
    let app = uid % 100_000;
    if (20_000..30_000).contains(&app) {
        uid - 10_000
    } else {
        uid
    }
}

/// What the "Add repository" screen shows after the client's fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoScreen {
    Shown,
    /// "Error connecting to the repository." (seen once on the 6a right
    /// after the proxy was set; the next try worked).
    Error,
    Waiting,
}

pub fn repo_screen(nodes: &[orbot::Node], host_path: &str) -> RepoScreen {
    if nodes.iter().any(|n| n.text.contains(host_path)) {
        RepoScreen::Shown
    } else if nodes
        .iter()
        .any(|n| n.text.contains("Error connecting to the repository"))
    {
        RepoScreen::Error
    } else {
        RepoScreen::Waiting
    }
}

/// `fdroidrepos://HOST/PATH?fingerprint=FP` for the configured repository.
pub fn repo_intent_uri(repo_url: &str, fingerprint: &str) -> Option<String> {
    let rest = repo_url.strip_prefix("https://")?;
    Some(format!(
        "fdroidrepos://{rest}?fingerprint={}",
        fingerprint.to_ascii_uppercase()
    ))
}

/// Starts the client's "Add repository" screen for SimpleX's repository.
pub fn open_add_repo(phone: &Phone, fdroid: &str, uri: &str) -> Result<(), String> {
    let q = crate::device::quoted(uri)?;
    let comp = format!("{fdroid}/org.fdroid.MainActivity");
    phone
        .shell(&[
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            &q,
            "-n",
            &comp,
        ])
        .map(|_| ())
}

/// `settings get secure KEY` (None for `null`).
pub fn secure_get(phone: &Phone, key: &str) -> Result<Option<String>, String> {
    let v = phone.shell(&["settings", "get", "secure", key])?;
    let v = v.trim();
    Ok((v != "null" && !v.is_empty()).then(|| v.to_string()))
}

/// The always-on VPN package and the lockdown flag as Settings stored them.
pub fn lockdown_state(phone: &Phone) -> Result<(Option<String>, bool), String> {
    let app = secure_get(phone, "always_on_vpn_app")?;
    let lock = secure_get(phone, "always_on_vpn_lockdown")?;
    Ok((app, lock.as_deref() == Some("1")))
}

/// The mode of Orbot's `ACTIVATE_VPN` app op as `appops get` shows it.
pub fn activate_vpn_mode(phone: &Phone, orbot: &str) -> Result<Option<String>, String> {
    let out = phone.shell(&["appops", "get", orbot, "ACTIVATE_VPN"])?;
    Ok(out
        .lines()
        .find_map(|l| l.trim().strip_prefix("ACTIVATE_VPN: "))
        .and_then(|r| r.split(';').next())
        .map(|m| m.trim().to_string()))
}

/// Runs a screen flow with the usual retries.
pub fn run_flow(
    phone: &Phone,
    sleep: &dyn Fn(std::time::Duration),
    retries: u32,
    what: &str,
    flow: &[Step],
    log: &mut Vec<String>,
) -> Result<Vec<(&'static str, bool)>, String> {
    let mut ui = orbot::Ui {
        phone,
        sleep,
        retries,
        log,
        what,
        found: Vec::new(),
    };
    ui.run(flow)?;
    Ok(ui.found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uids_vpn_and_package_state() {
        let u = parse_uids("package:chat.simplex.app uid:10201\npackage:org.fdroid.fdroid uid:10200\npackage:android uid:1000\n");
        assert_eq!(u["chat.simplex.app"], 10201);
        assert_eq!(u["android"], 1000);
        let d = "NetworkAgents:\n  NetworkAgentInfo{network{120}  handle{516}  ni{VPN CONNECTED extra: } created=2026-11-24T10:00:00Z lp{{InterfaceName: tun0}} nc{[ Transports: VPN Capabilities: NOT_METERED&INTERNET&NOT_RESTRICTED&TRUSTED Uids: <{10050-10050}, {10051-10051}, {10200-10201}> OwnerUid: 10173 AdminUids: [10173] TransportInfo: <VpnTransportInfo{type=1}>]} factorySerialNumber=-1}\n  NetworkAgentInfo{network{100}  handle{430}  ni{WIFI CONNECTED extra: } nc{[ Transports: WIFI ]}}\n";
        let v = parse_vpn(d);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].owner, Some(10173));
        assert_eq!(
            v[0].uids.iter().copied().collect::<Vec<_>>(),
            vec![10050, 10051, 10200, 10201]
        );
        assert!(
            parse_vpn("NetworkAgentInfo{ ni{WIFI CONNECTED} nc{[ Transports: WIFI ]}}").is_empty()
        );
        // One brace pair, the SDK sandbox uids included (Android 16 format).
        let real = "  NetworkAgentInfo{network{101}  handle{900}  ni{VPN CONNECTED extra: VPN:org.torproject.android} nc{[ Transports: VPN Capabilities: NOT_METERED&INTERNET Uids: <{10050-10050, 10051-10051, 10060-10061, 20050-20050, 20051-20051, 20060-20061}> OwnerUid: 10059 AdminUids: [10059] UnderlyingNetworks: Null]}}";
        let v = parse_vpn(real);
        let real2 = real.replace("Transports: VPN", "Transports: WIFI|VPN");
        assert_eq!(parse_vpn(&real2), v);
        assert_eq!(v[0].owner, Some(10059));
        let apps: BTreeSet<u32> = v[0].uids.iter().map(|u| app_uid(*u)).collect();
        assert_eq!(
            apps.into_iter().collect::<Vec<_>>(),
            vec![10050, 10051, 10060, 10061]
        );
        let d = "  Lockdown filtering rules:\n    UIDs: 1-10058\n    UIDs: 10060-20058\n    UIDs: 20060-99999\n  \n  Update logs:\n";
        assert_eq!(
            lockdown_rules(d),
            vec![(1, 10058), (10060, 20058), (20060, 99999)]
        );
        assert!(lockdown_rules("  Lockdown filtering rules:\n  \n  Update logs:\n").is_empty());
        let s = parse_pkg_state("Packages:\n  Package [chat.simplex.app] (1):\n    installerPackageName=org.fdroid.fdroid\n    User 0: ceDataInode=1 installed=true hidden=false suspended=false distractionFlags=0 stopped=true notLaunched=true enabled=0 instant=false\n");
        assert_eq!(s.installer.as_deref(), Some("org.fdroid.fdroid"));
        assert_eq!((s.stopped, s.not_launched), (Some(true), Some(true)));
        assert_eq!(
            parse_pkg_state("    installerPackageName=null\n").installer,
            None
        );
    }

    #[test]
    fn package_manager_signature_hashes() {
        // In the format of `dumpsys package`, for chat.simplex.app.
        let d = "    signatures=PackageSignatures{1a2b3c4 version:3, signatures:[2136bace], past signatures:[]}\n";
        assert_eq!(pm_signature_hashes(d), vec![0x2136bace]);
        assert!(pm_signature_hashes("signatures:[]").is_empty());
        // Java's Arrays.hashCode over signed bytes.
        assert_eq!(crate::apk::java_hash(&[]), 1);
        assert_eq!(crate::apk::java_hash(&[0xff, 0x01]), 31 * (31 - 1) + 1);
    }

    #[test]
    fn sockets_and_the_repository_intent() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n   0: 0100007F:235A 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10173 0 1\n   1: 0100007F:9C40 0100007F:235A 01 00000000:00000000 00:00000000 00000000 10197 0 2\n";
        let s = parse_sockets(t);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].local, "127.0.0.1:9050");
        assert_eq!((s[1].remote.as_str(), s[1].uid), ("127.0.0.1:9050", 10197));
        assert!(s[1].remote_is_loopback());
        let t6 = "  sl\n   0: 0000000000000000FFFF00000100007F:9C41 0000000000000000FFFF00000100007F:235A 01 0:0 0:0 0 10200 0 3\n";
        assert_eq!(parse_sockets(t6)[0].remote, "127.0.0.1:9050");
        let uri = repo_intent_uri("https://app.simplex.chat/fdroid/repo", "9f35ab").unwrap();
        assert_eq!(
            uri,
            "fdroidrepos://app.simplex.chat/fdroid/repo?fingerprint=9F35AB"
        );
        assert!(crate::device::quoted(&uri).is_ok());
        assert_eq!(label_of("org.fdroid.fdroid"), Some("F-Droid"));
        assert_eq!(label_of("x.y"), None);
    }
}
