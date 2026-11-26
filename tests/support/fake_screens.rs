// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Screens of the fake adb for the normal SimpleX app: Orbot's app list ("Choose apps") and its VPN, Android's
//! VPN settings (always-on VPN and lockdown), and the F-Droid client (its
//! SOCKS proxy setting, "Add repository", the repository list). Built from
//! the apps' strings and resource ids, checked against the real screens on
//! a Pixel 6a.

use super::*;

pub const SET_PKG: &str = "com.android.settings";
pub const FD_PKG: &str = "org.fdroid.fdroid";

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Fd {
    /// The proxy (`host:port`), empty for none.
    pub proxy: String,
    pub field: String,
    /// Swipes done on the settings screen (the proxy row needs one).
    pub scrolled: u32,
    /// Screen reads until the "Add repository" screen has fetched the repo.
    pub fetch_left: u32,
    pub fetch_polls: u32,
    pub intent_uri: String,
    /// The fingerprint the client accepts (the repository's real one).
    pub repo_fingerprint: String,
    pub repos: Vec<String>,
    /// `pm grant ... POST_NOTIFICATIONS` (else the system's dialog shows).
    pub notifications: bool,
    /// Screens whose hint ("Got it") was dismissed.
    pub hints_seen: Vec<String>,
    /// So many repository fetches fail before one works.
    pub fetch_errors: u32,
    /// So many repository intents start a fetch that never ends (Tor stalled).
    pub hang_intents: u32,
    /// Screen reads after "Add repository" before the repository shows in the
    /// client (the index is fetched over Tor).
    pub add_left: u32,
}

const fn b(l: i32, t: i32, r: i32, bt: i32) -> B {
    (l, t, r, bt)
}

// As dumped on the Pixel 6a (Orbot 17.9.8-RC-1, 2026-11-24): the search
// field `searchBar` shows its hint "Search for apps" as text; each row is an
// `appContainer` with the check box `itemcheck` and the label `itemtext` as
// siblings. On the main screen "Choose apps" is a `tvLabel` in a full-width
// clickable row whose centre lies under the "Full Device VPN" box.
const SEARCH: B = b(47, 304, 1033, 430);
const NAV_UP: B = b(0, 132, 147, 279);
const APPS_TOP: i32 = 632;
const ROW_H: i32 = 197;
pub const CHOOSE_APPS_ROW: B = b(63, 873, 1017, 978);
pub const CHOOSE_APPS: B = b(183, 900, 398, 951);

fn hierarchy(pkg: &str, kids: &str) -> String {
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation=\"0\">{}</hierarchy>",
        node_in(pkg, "", "", false, false, false, (0, 0, 1080, 2400), kids)
    )
}

fn class_node(pkg: &str, class: &str, text: &str, clickable: bool, bb: B) -> String {
    format!(
        "<node index=\"0\" text=\"{}\" resource-id=\"\" class=\"{class}\" package=\"{pkg}\" content-desc=\"\" checkable=\"false\" checked=\"false\" clickable=\"{clickable}\" bounds=\"[{},{}][{},{}]\" />",
        text.replace('&', "&amp;").replace('"', "&quot;"),
        bb.0,
        bb.1,
        bb.2,
        bb.3
    )
}

// ---- Orbot's app list -------------------------------------------------------

/// The rows the list shows now: apps with a label, filtered by the search,
/// the chosen ones first, then by label.
fn app_rows(st: &State) -> Vec<(String, String, bool)> {
    let q = st.orbot.query.to_lowercase();
    let mut v: Vec<(String, String, bool)> = st
        .packages
        .iter()
        .filter(|(k, p)| !p.label.is_empty() && **k != st.orbot_package)
        .filter(|(_, p)| q.is_empty() || p.label.to_lowercase().contains(&q))
        .map(|(k, p)| (p.label.clone(), k.clone(), st.orbot.apps.contains(k)))
        .collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    v
}

pub fn apps_dump(st: &State) -> String {
    let q = if st.orbot.query.is_empty() {
        "Search for apps".to_string()
    } else {
        st.orbot.query.clone()
    };
    let mut kids = node(
        &q,
        &format!("{ORBOT_ID}searchBar"),
        true,
        false,
        false,
        SEARCH,
        "",
    );
    kids.push_str(&format!(
        "<node index=\"0\" text=\"\" resource-id=\"\" class=\"android.widget.ImageButton\" package=\"{ORBOT_PKG}\" content-desc=\"Navigate up\" checkable=\"false\" checked=\"false\" clickable=\"true\" bounds=\"[0,132][147,279]\" />"
    ));
    for (i, (label, _, on)) in app_rows(st).iter().enumerate() {
        let y = APPS_TOP + i as i32 * ROW_H;
        let inner = format!(
            "{}{}",
            node(
                "",
                &format!("{ORBOT_ID}itemcheck"),
                true,
                true,
                *on,
                b(42, y, 126, y + 158),
                ""
            ),
            node(
                label,
                &format!("{ORBOT_ID}itemtext"),
                true,
                false,
                false,
                b(310, y, 1033, y + 158),
                ""
            )
        );
        let container = node(
            "",
            &format!("{ORBOT_ID}appContainer"),
            false,
            false,
            false,
            b(42, y, 1038, y + 158),
            &inner,
        );
        kids.push_str(&node(
            "",
            &format!("{ORBOT_ID}itemRow"),
            false,
            false,
            false,
            b(42, y, 1038, y + 158),
            &container,
        ));
    }
    hierarchy(ORBOT_PKG, &kids)
}

pub fn apps_tap(st: &mut State, x: i32, y: i32) {
    if inside(NAV_UP, x, y) {
        st.orbot.screen = "main".into();
        // A changed list restarts Orbot's VPN (RESTART_VPN): the tun is
        // closed and set up again with the new list; lockdown holds.
        let changed = st.orbot.apps != st.orbot.apps_on_enter;
        if changed && st.orbot.connected && st.fail.contains_key("lockdown_drop_on_app_change") {
            st.lockdown_runtime = false;
            log_mode(st, false, true);
        }
        return;
    }
    if inside(SEARCH, x, y) {
        return;
    }
    let rows = app_rows(st);
    for (i, (_, pkg, on)) in rows.iter().enumerate() {
        let yy = APPS_TOP + i as i32 * ROW_H;
        if inside(b(42, yy, 1038, yy + 158), x, y) {
            if st.fail.contains_key(&format!("orbot_app_stuck:{pkg}")) {
                return;
            }
            if *on {
                st.orbot.apps.remove(pkg);
            } else {
                st.orbot.apps.insert(pkg.clone());
            }
            return;
        }
    }
}

/// `dumpsys connectivity`: Wi-Fi, and Orbot's VPN while it is connected
/// in VPN mode, with the uids of its app list.
pub fn connectivity(st: &State) -> String {
    let mut s = String::from("NetworkAgents:\n  NetworkAgentInfo{network{100}  handle{430}  ni{WIFI CONNECTED extra: } nc{[ Transports: WIFI Capabilities: INTERNET ]}}\n");
    if st.orbot.connected && !st.orbot.power {
        let mut uids: Vec<u32> = st
            .orbot
            .apps
            .iter()
            .filter_map(|p| st.packages.get(p).map(|x| x.uid))
            .collect();
        uids.extend(st.orbot.vpn_extra_uids.iter().copied());
        uids.sort();
        let r: Vec<String> = uids.iter().map(|u| format!("{{{u}-{u}}}")).collect();
        let owner = st
            .packages
            .get(&st.orbot_package)
            .map(|p| p.uid)
            .unwrap_or(0);
        s.push_str(&format!(
            "  NetworkAgentInfo{{network{{120}}  handle{{516}}  ni{{VPN CONNECTED extra: }} lp{{{{InterfaceName: tun0}}}} nc{{[ Transports: WIFI|VPN Capabilities: NOT_METERED&INTERNET Uids: <{}> OwnerUid: {owner} AdminUids: [{owner}] ]}} factorySerialNumber=-1}}\n",
            r.join(", ")
        ));
    }
    // Lockdown at run time only when Settings turned it on (as on the
    // phone, `settings put` alone sets no rules).
    if st.lockdown_runtime && st.packages.contains_key(&st.orbot_package) {
        let o = st
            .packages
            .get(&st.orbot_package)
            .map(|p| p.uid)
            .unwrap_or(0);
        s.push_str(&format!(
            "  Lockdown filtering rules:
    UIDs: 1-{}
    UIDs: {}-{}
    UIDs: {}-99999
  
",
            o - 1,
            o + 1,
            o + 9999,
            o + 10001
        ));
    } else {
        s.push_str(
            "  Lockdown filtering rules:
  
",
        );
    }
    s.push_str(
        "  Update logs:
",
    );
    s
}

// ---- Android's VPN settings ---------------------------------------------------

const VPN_ROW: B = b(0, 300, 1080, 450);
const VPN_GEAR: B = b(950, 330, 1040, 420);
const ROW_ALWAYS: B = b(0, 300, 1080, 470);
const ROW_LOCK: B = b(0, 470, 1080, 640);
const LOCK_OK: B = b(700, 1500, 1000, 1640);

fn secure(st: &State, k: &str) -> Option<String> {
    st.settings.get(&format!("secure:{k}")).cloned()
}

pub fn settings_row(title: &str, bb: B, on: bool) -> String {
    let inner = format!(
        "{}{}",
        node_in(
            SET_PKG,
            title,
            "android:id/title",
            false,
            false,
            false,
            b(42, bb.1 + 40, 700, bb.1 + 100),
            ""
        ),
        node_in(
            SET_PKG,
            "",
            "android:id/switch_widget",
            false,
            true,
            on,
            b(900, bb.1 + 40, 1040, bb.1 + 130),
            ""
        )
    );
    node_in(SET_PKG, "", "", true, false, false, bb, &inner)
}

pub fn vpn_settings_dump(st: &State) -> String {
    let orbot_there = st.packages.contains_key(&st.orbot_package);
    let always = secure(st, "always_on_vpn_app").as_deref() == Some(st.orbot_package.as_str());
    let lock = secure(st, "always_on_vpn_lockdown").as_deref() == Some("1");
    let mut kids = String::new();
    match st.ui.as_str() {
        "vpn_list" if orbot_there => {
            let inner = format!(
                "{}{}",
                node_in(
                    SET_PKG,
                    "Orbot",
                    "android:id/title",
                    false,
                    false,
                    false,
                    b(42, 340, 700, 400),
                    ""
                ),
                node_in(
                    SET_PKG,
                    "",
                    "com.android.settings:id/settings_button",
                    true,
                    false,
                    false,
                    VPN_GEAR,
                    ""
                )
            );
            kids.push_str(&node_in(
                SET_PKG, "", "", true, false, false, VPN_ROW, &inner,
            ));
        }
        "vpn_orbot" | "lock_dialog" => {
            kids.push_str(&settings_row("Always-on VPN", ROW_ALWAYS, always));
            kids.push_str(&settings_row(
                "Block connections without VPN",
                ROW_LOCK,
                lock,
            ));
            if st.ui == "lock_dialog" {
                kids.push_str(&node_in(
                    SET_PKG,
                    "Block connections without VPN?",
                    "android:id/alertTitle",
                    false,
                    false,
                    false,
                    b(100, 1100, 980, 1200),
                    "",
                ));
                kids.push_str(&node_in(
                    SET_PKG,
                    "Turn on",
                    "android:id/button1",
                    true,
                    false,
                    false,
                    LOCK_OK,
                    "",
                ));
            }
        }
        _ => {}
    }
    hierarchy(SET_PKG, &kids)
}

pub fn vpn_settings_tap(st: &mut State, x: i32, y: i32) {
    let orbot = st.orbot_package.clone();
    let lock = secure(st, "always_on_vpn_lockdown").as_deref() == Some("1");
    match st.ui.as_str() {
        "vpn_list" if inside(VPN_GEAR, x, y) => st.ui = "vpn_orbot".into(),
        "vpn_orbot" if inside(ROW_ALWAYS, x, y) => {
            if secure(st, "always_on_vpn_app").is_some() {
                st.lockdown_runtime = false;
                st.settings.remove("secure:always_on_vpn_app");
                st.settings.remove("secure:always_on_vpn_lockdown");
                log_mode(st, false, false);
            } else {
                st.settings.insert("secure:always_on_vpn_app".into(), orbot);
                log_mode(st, false, true);
            }
        }
        "vpn_orbot" if inside(ROW_LOCK, x, y) => {
            if lock {
                st.lockdown_runtime = false;
                st.settings
                    .insert("secure:always_on_vpn_lockdown".into(), "0".into());
                log_mode(st, false, true);
            } else if secure(st, "always_on_vpn_app").is_some() {
                st.ui = "lock_dialog".into();
            }
        }
        "lock_dialog" if inside(LOCK_OK, x, y) => {
            st.settings
                .insert("secure:always_on_vpn_lockdown".into(), "1".into());
            // The scenario of a lockdown that is stored but not in force.
            if !st.fail.contains_key("lockdown_no_runtime") {
                st.lockdown_runtime = true;
                log_mode(st, true, true);
            }
            st.ui = "vpn_orbot".into();
        }
        _ => {}
    }
}

// ---- the F-Droid client ---------------------------------------------------------
//
// As dumped on the Pixel 6a (F-Droid 2.0.3, Compose, 2026-11-24): no
// resource ids; the main screen's top bar has the buttons "Repositories",
// "Settings" and "More options" as descriptions; the proxy dialog has an
// `android.widget.EditText`; "Add repository" is both the screen's title
// and its button (the button's text sits in a clickable view); a hint with
// "Got it" covers a screen the first time it is shown. Without the
// notification permission the first start shows the system's dialog.

const FD_REPOS_BTN: B = b(723, 185, 786, 248);
const FD_SETTINGS_BTN: B = b(849, 185, 912, 248);
const FD_ROW_PROXY: B = b(147, 880, 650, 943);
const FD_EDIT: B = b(183, 705, 897, 905);
const FD_OK_ROW: B = b(745, 937, 897, 1063);
const FD_OK: B = b(796, 973, 846, 1026);
const FD_ADD_ROW: B = b(672, 554, 1038, 680);
const FD_ADD: B = b(735, 590, 975, 643);
const FD_GOT_IT_ROW: B = b(800, 597, 954, 723);
const FD_GOT_IT: B = b(832, 633, 922, 686);
const FD_REPO_SX: B = b(210, 568, 632, 631);
const FD_FP_ROW: B = b(126, 974, 891, 1037);

fn fd_t(s: &str, bb: B) -> String {
    node_in(FD_PKG, s, "", false, false, false, bb, "")
}

fn fd_desc(desc: &str, bb: B) -> String {
    format!(
        "<node index=\"0\" text=\"\" resource-id=\"\" class=\"android.view.View\" package=\"{FD_PKG}\" content-desc=\"{desc}\" checkable=\"false\" checked=\"false\" clickable=\"false\" bounds=\"[{},{}][{},{}]\" />",
        bb.0, bb.1, bb.2, bb.3
    )
}

/// A text inside a clickable view (a Compose button).
fn fd_button(s: &str, row: B, bb: B) -> String {
    node_in(FD_PKG, "", "", true, false, false, row, &fd_t(s, bb))
}

/// The hint of a screen not seen before, or None.
fn fd_hint(st: &State) -> Option<&'static str> {
    let screen = st.ui.as_str();
    let text = match screen {
        "fdroid_repo" => "Use filters to only show apps from specific categories or repositories.",
        "fdroid_repos" => {
            "A repository is a source of apps. This list shows all currently added repositories."
        }
        "fdroid_details" => "A repository is a source of apps.",
        _ => return None,
    };
    (!st.fd.hints_seen.iter().any(|h| h == screen)).then_some(text)
}

pub fn fdroid_dump(st: &mut State) -> String {
    let mut kids = String::new();
    if st.ui == "fdroid_main" && !st.fd.notifications {
        let p = "com.android.permissioncontroller";
        kids.push_str(&node_in(
            p,
            "Allow F-Droid to send you notifications?",
            "com.android.permissioncontroller:id/permission_message",
            false,
            false,
            false,
            b(133, 1045, 947, 1214),
            "",
        ));
        kids.push_str(&node_in(
            p,
            "Allow",
            "com.android.permissioncontroller:id/permission_allow_button",
            true,
            false,
            false,
            b(133, 1277, 947, 1403),
            "",
        ));
        return hierarchy(p, &kids);
    }
    if let Some(h) = fd_hint(st) {
        kids.push_str(&fd_t(h, b(198, 416, 954, 575)));
        kids.push_str(&fd_button("Got it", FD_GOT_IT_ROW, FD_GOT_IT));
        return hierarchy(FD_PKG, &kids);
    }
    let added = !st.fd.repos.is_empty();
    match st.ui.as_str() {
        "fdroid_main" => {
            kids.push_str(&fd_t("F-Droid", b(43, 179, 226, 253)));
            kids.push_str(&fd_desc("Repositories", FD_REPOS_BTN));
            kids.push_str(&fd_desc("Settings", FD_SETTINGS_BTN));
            kids.push_str(&fd_desc("More options", b(975, 185, 1038, 248)));
            kids.push_str(&fd_t("Discover", b(107, 2253, 238, 2295)));
        }
        "fdroid_settings" | "fdroid_proxy" => {
            kids.push_str(&fd_t("Settings", b(148, 179, 356, 253)));
            if st.fd.scrolled == 0 {
                kids.push_str(&fd_t("Display", b(42, 363, 163, 416)));
            } else {
                let summary = if st.fd.proxy.is_empty() {
                    "Connect to the Internet without proxy".to_string()
                } else {
                    format!("Uses {} to connect", st.fd.proxy)
                };
                kids.push_str(&fd_t("Network", b(42, 564, 181, 617)));
                kids.push_str(&fd_t("Connect via SOCKS proxy", FD_ROW_PROXY));
                kids.push_str(&fd_t(&summary, b(147, 943, 762, 996)));
            }
            if st.ui == "fdroid_proxy" {
                kids.push_str(&fd_t("Connect via SOCKS proxy", b(183, 579, 895, 663)));
                kids.push_str(&class_node(
                    FD_PKG,
                    "android.widget.EditText",
                    &st.fd.field,
                    true,
                    FD_EDIT,
                ));
                kids.push_str(&fd_t(
                    "Proxy is expected in host:port format",
                    b(225, 863, 774, 905),
                ));
                kids.push_str(&fd_button("OK", FD_OK_ROW, FD_OK));
            }
        }
        "fdroid_add" => {
            let f = &mut st.fd;
            f.fetch_polls += 1;
            if f.fetch_left > 0 {
                f.fetch_left -= 1;
                kids.push_str(&fd_t("Fetching repository...", b(40, 300, 900, 360)));
            } else if f.fetch_errors > 0 {
                kids.push_str(&fd_t(
                    "Error connecting to the repository.",
                    b(66, 1308, 1015, 1392),
                ));
                kids.push_str(&fd_t(
                    "java.util.zip.ZipException: zip file is empty",
                    b(124, 1434, 957, 1497),
                ));
            } else {
                let fp = f
                    .intent_uri
                    .split_once("fingerprint=")
                    .map(|(_, x)| x.to_string())
                    .unwrap_or_default();
                if !fp.eq_ignore_ascii_case(&f.repo_fingerprint) {
                    kids.push_str(&fd_t(
                        "The fingerprint does not match",
                        b(40, 300, 900, 360),
                    ));
                } else {
                    kids.push_str(&fd_t("SimpleX Chat F-Droid", b(210, 342, 642, 405)));
                    kids.push_str(&fd_t("app.simplex.chat/fdroid/repo", b(210, 405, 698, 458)));
                    kids.push_str(&fd_button("Add repository", FD_ADD_ROW, FD_ADD));
                }
            }
            kids.push_str(&fd_t("Add repository", b(148, 179, 518, 253)));
        }
        "fdroid_adding" => {
            if st.fd.add_left > 0 {
                st.fd.add_left -= 1;
                kids.push_str(&fd_t("Adding repository...", b(40, 300, 900, 360)));
            } else {
                st.ui = "fdroid_repo".into();
                kids.push_str(&fd_t("SimpleX Chat", b(231, 353, 498, 416)));
                kids.push_str(&fd_t("SimpleX Chat F-Droid", b(148, 179, 687, 253)));
            }
        }
        "fdroid_repo" => {
            kids.push_str(&fd_t("SimpleX Chat", b(231, 353, 498, 416)));
            kids.push_str(&fd_t("SimpleX Chat F-Droid", b(148, 179, 687, 253)));
        }
        "fdroid_repos" => {
            kids.push_str(&fd_t("F-Droid", b(210, 358, 354, 421)));
            if added {
                kids.push_str(&fd_t("SimpleX Chat F-Droid", FD_REPO_SX));
            }
            kids.push_str(&fd_t("Repositories", b(148, 158, 465, 232)));
        }
        "fdroid_details" | "fdroid_details_fp" => {
            kids.push_str(&fd_t("SimpleX Chat F-Droid", b(231, 342, 935, 437)));
            kids.push_str(&fd_t("app.simplex.chat/fdroid", b(231, 437, 630, 490)));
            kids.push_str(&fd_t("Signing key fingerprint (SHA-256)", FD_FP_ROW));
            if st.ui == "fdroid_details_fp" {
                kids.push_str(&fd_t(
                    &st.fd.repo_fingerprint.to_lowercase(),
                    b(63, 1089, 1017, 1195),
                ));
            }
        }
        _ => {}
    }
    hierarchy(FD_PKG, &kids)
}

pub fn fdroid_tap(st: &mut State, x: i32, y: i32) {
    if st.ui == "fdroid_main" && !st.fd.notifications {
        return;
    }
    if fd_hint(st).is_some() {
        if inside(FD_GOT_IT_ROW, x, y) {
            let s = st.ui.clone();
            st.fd.hints_seen.push(s);
        }
        return;
    }
    let f = &mut st.fd;
    match st.ui.as_str() {
        "fdroid_main" if inside(FD_SETTINGS_BTN, x, y) => st.ui = "fdroid_settings".into(),
        "fdroid_main" if inside(FD_REPOS_BTN, x, y) => st.ui = "fdroid_repos".into(),
        "fdroid_settings" if f.scrolled > 0 && inside(FD_ROW_PROXY, x, y) => {
            f.field = f.proxy.clone();
            st.ui = "fdroid_proxy".into();
        }
        "fdroid_proxy" if inside(FD_OK_ROW, x, y) => {
            f.proxy = f.field.clone();
            st.ui = "fdroid_settings".into();
        }
        "fdroid_add" if inside(FD_ADD_ROW, x, y) && f.fetch_left == 0 => {
            f.repos.push("https://app.simplex.chat/fdroid/repo".into());
            st.ui = if f.add_left > 0 {
                "fdroid_adding"
            } else {
                "fdroid_repo"
            }
            .into();
        }
        "fdroid_repos" if !f.repos.is_empty() && inside(FD_REPO_SX, x, y) => {
            st.ui = "fdroid_details".into();
        }
        "fdroid_details" if inside(FD_FP_ROW, x, y) => st.ui = "fdroid_details_fp".into(),
        _ => {}
    }
}

pub fn fdroid_text(st: &mut State, t: &str) {
    if st.ui == "fdroid_proxy" {
        st.fd.field.push_str(&t.replace("%s", " "));
    }
}

pub fn fdroid_back(st: &mut State) {
    st.ui = match st.ui.as_str() {
        "fdroid_proxy" => "fdroid_settings",
        "fdroid_add" => {
            st.fd.fetch_errors = st.fd.fetch_errors.saturating_sub(1);
            "fdroid_main"
        }
        "fdroid_adding" => "fdroid_main",
        "fdroid_settings" | "fdroid_repos" => "fdroid_main",
        "fdroid_repo" | "fdroid_details" | "fdroid_details_fp" => "fdroid_repos",
        _ => "",
    }
    .into();
}
