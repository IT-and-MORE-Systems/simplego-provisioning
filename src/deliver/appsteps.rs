// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The delivery steps of the normal SimpleX app (see `simplex`): parts of
//! step 4, steps 9 (the two apps installed after the network lock) and 11
//! (the F-Droid client), and the part of the final check for them. The
//! network lock itself (steps 7 and 10) is in `lock`.

use super::simplex::{self, SYSTEM_VPN_APPS};
use super::*;
use crate::activation::store::{AppRecord, RepoRecord};
use crate::fdroid;

/// The SimpleX app as step 4 found it in the repository.
pub(super) struct SxPlan {
    #[allow(dead_code)]
    pub checked: fdroid::Checked,
    /// The downloaded APK (None in a dry run).
    pub file: Option<PathBuf>,
    pub apk: Option<ApkInfo>,
}

/// The packages Orbot's VPN must carry, in the order of its app list.
pub(super) fn vpn_packages(cfg: &Config) -> Vec<String> {
    let mut v = vec![cfg.simplex_app_package.clone(), cfg.fdroid_package.clone()];
    v.extend(SYSTEM_VPN_APPS.iter().map(|s| s.to_string()));
    v
}

const CONSOLE_STEP: &str = "SimpleX app";

impl Delivery_<'_, '_, '_, '_> {
    pub(super) fn vpn_mode(&self) -> bool {
        self.a.fdroid_apk.is_some()
    }

    /// A step of the SimpleX app part, shown by the operator console as the
    /// step "SimpleX app".
    fn sx_step(&mut self, n: u8, title: &str) {
        self.o.step_in(n, title, Some(CONSOLE_STEP));
    }

    /// Step 4, after the messenger and Orbot files: the F-Droid client APK
    /// and the SimpleX app from SimpleX's repository.
    pub(super) fn step4_simplex(&mut self) -> Result<(), Failure> {
        let Some(fpath) = self.a.fdroid_apk.clone() else {
            self.o
                .line("  SimpleX app: not part of this delivery (no --fdroid-apk)");
            return Ok(());
        };
        let cfg = self.env.cfg;
        let fi = apk::inspect(&fpath)
            .or_else(|e| fail(4, exit::DELIVERY_APK, format!("F-Droid client: {e}")))?;
        if fi.package != cfg.fdroid_package {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "F-Droid client APK: package {} is not {}",
                    fi.package, cfg.fdroid_package
                ),
            );
        }
        let want = cfg.fdroid_digest().map(|d| hex(&d)).unwrap_or_default();
        if fi.signer_sha256 != want {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "WRONG SIGNER: the F-Droid client APK is signed by {}, not by the pinned fdroid_signing_cert_sha256 {want}",
                    fi.signer_sha256
                ),
            );
        }
        self.o.line(format!(
            "  F-Droid client {} versionCode {} ({}), SHA-256 {}, signer matches fdroid_signing_cert_sha256",
            fi.package,
            fi.version_code,
            fi.version_name.as_deref().unwrap_or("?"),
            fi.sha256
        ));
        self.step4_link_hosts(&fi, "F-Droid client")?;
        self.note_link_hosts(&fi);
        self.fdroid = Some(fi);

        let (app_pin, repo_fp) = cfg.simplex_pins().ok_or(()).or_else(|_| {
            fail(
                4,
                exit::DELIVERY_APK,
                "simplex_app_signing_cert_sha256 and simplex_repo_fingerprint must both be pinned",
            )
        })?;
        let Some(http) = self.env.http else {
            return fail(
                4,
                exit::DELIVERY_APK,
                "the SimpleX app comes from SimpleX's repository over Tor, and the network is off (--offline or no Tor)",
            );
        };
        // A phone that already has either app is refused before anything is
        // written: a customer's own SimpleX app is never touched.
        for n in [cfg.fdroid_package.clone(), cfg.simplex_app_package.clone()] {
            if self
                .phone()
                .installed(&n)
                .or_else(|e| fail(4, exit::DELIVERY_REFUSED, e))?
            {
                return fail(
                    4,
                    exit::DELIVERY_REFUSED,
                    format!("{n} is already installed on this phone; it is never replaced (on a test phone run undeliver first); nothing was written"),
                );
            }
        }
        let props = self
            .phone()
            .getprops()
            .or_else(|e| fail(4, exit::DELIVERY_REFUSED, e))?;
        let abis: Vec<String> = props
            .get("ro.product.cpu.abilist")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let sdk: u64 = props
            .get("ro.build.version.sdk")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if abis.is_empty() || sdk == 0 {
            return fail(
                4,
                exit::DELIVERY_REFUSED,
                "the phone reports no ABI list or SDK level",
            );
        }
        let last = self.session.as_ref().and_then(|s| {
            s.store
                .data
                .deliveries
                .iter()
                .filter_map(|d| d.simplex_repo.as_ref())
                .filter(|r| r.url == cfg.simplex_repo_url)
                .map(|r| r.index_timestamp_ms)
                .max()
        });
        if self.a.dry_run {
            self.o.line(
                "  dry run: no rollback check against earlier deliveries (the store is not opened)",
            );
        }
        let repo = fdroid::Repo {
            url: &cfg.simplex_repo_url,
            fingerprint: &repo_fp,
        };
        let want = fdroid::Want {
            package: &cfg.simplex_app_package,
            signer: &app_pin,
            abis,
            sdk,
        };
        let mut log = Vec::new();
        let now = (self.env.now)();
        let r = fdroid::check_index(http, &repo, &want, last, now, &mut |l| log.push(l));
        for l in &log {
            self.o.line(format!("  SimpleX repository: {l}"));
        }
        let checked =
            r.or_else(|e| fail(4, exit::DELIVERY_APK, format!("SimpleX repository: {e}")))?;
        let pk = checked.pick.clone();
        self.o.line(format!(
            "  SimpleX app {} (versionCode {}, {}): {}, {} bytes, SHA-256 {} (the newest release in the signed index)",
            pk.version_name, pk.version_code, pk.abi, pk.file, pk.size, pk.sha256
        ));
        for b in &checked.betas_skipped {
            self.o.line(format!("  left out as a beta: {b}"));
        }
        self.o.event(
            json!({"event": "simplex_index", "version_code": pk.version_code,
                            "version_name": pk.version_name, "sha256": pk.sha256,
                            "index_time_ms": checked.timestamp_ms, "console_step": CONSOLE_STEP}),
        );
        self.rec.simplex_repo = Some(RepoRecord {
            url: cfg.simplex_repo_url.clone(),
            fingerprint: repo_fp.clone(),
            index_timestamp_ms: checked.timestamp_ms,
            index_sha256: checked.index_sha256.clone(),
            added_to_client: false,
        });
        if self.a.dry_run {
            self.o.line(
                "  dry run: the SimpleX APK is downloaded and checked (also for app link hosts) in a real delivery only",
            );
            self.sx = Some(SxPlan {
                checked,
                file: None,
                apk: None,
            });
            return Ok(());
        }
        let dest = self
            .env
            .work_dir
            .join(format!("simplex-{}.apk", pk.version_code));
        let _ = std::fs::remove_file(&dest);
        let t0 = (self.env.now)();
        fdroid::download(http, &repo, &pk, &dest)
            .or_else(|e| fail(4, exit::DELIVERY_APK, format!("SimpleX app: {e}")))?;
        let si = apk::inspect(&dest)
            .or_else(|e| fail(4, exit::DELIVERY_APK, format!("SimpleX app: {e}")))?;
        if si.package != cfg.simplex_app_package || si.version_code != pk.version_code {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "SimpleX app: the APK is {} versionCode {}, the index names {} versionCode {}",
                    si.package, si.version_code, cfg.simplex_app_package, pk.version_code
                ),
            );
        }
        if si.signer_sha256 != app_pin {
            return fail(
                4,
                exit::DELIVERY_APK,
                format!(
                    "WRONG SIGNER: the SimpleX APK is signed by {}, not by the pinned simplex_app_signing_cert_sha256 {app_pin}",
                    si.signer_sha256
                ),
            );
        }
        self.o.line(format!(
            "  SimpleX APK downloaded over Tor ({}s), size and SHA-256 as the index names, signer ({}) matches simplex_app_signing_cert_sha256",
            (self.env.now)().saturating_sub(t0),
            si.scheme
        ));
        self.step4_link_hosts(&si, "SimpleX app")?;
        self.note_link_hosts(&si);
        self.sx = Some(SxPlan {
            checked,
            file: Some(dest),
            apk: Some(si),
        });
        Ok(())
    }

    /// Step 9: the F-Droid client and the SimpleX app installed, neither
    /// started, after the network lock (step 7). A phone that already has either is refused: a customer's
    /// own SimpleX app is never touched.
    pub(super) fn step9_apps(&mut self) -> Result<(), Failure> {
        if !self.vpn_mode() {
            self.o.step(
                9,
                "F-Droid client and SimpleX app: not part of this delivery",
            );
            return Ok(());
        }
        self.sx_step(9, "F-Droid client and SimpleX app (installed, not started)");
        self.require_lock(9)?;
        let cfg = self.env.cfg;
        let fi = self.fdroid.clone().expect("step 4 ran");
        let sx = self.sx.as_ref().expect("step 4 ran");
        let si = sx.apk.clone().expect("a real delivery downloaded it");
        let sfile = sx.file.clone().expect("a real delivery downloaded it");
        let fpath = self.a.fdroid_apk.clone().expect("vpn mode");
        let items = [
            (fi, fpath, None),
            (si, sfile, Some(cfg.fdroid_package.clone())),
        ];
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let names = [cfg.fdroid_package.clone(), cfg.simplex_app_package.clone()];
        for n in &names {
            if p.installed(n)
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, e))?
            {
                return fail(
                    9,
                    exit::DELIVERY_FAILED,
                    format!("{n} is already installed on this phone; it is never replaced (on a test phone run undeliver first)"),
                );
            }
        }
        let mut recs = Vec::new();
        for (info, path, installer) in items {
            let pkg = info.package.clone();
            p.install_as(&path.to_string_lossy(), false, installer.as_deref())
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, format!("{pkg}: {e}")))?;
            let rec = AppRecord {
                package: pkg.clone(),
                version_code: info.version_code,
                version_name: info.version_name.clone(),
                apk_sha256: info.sha256.clone(),
                signer_sha256: info.signer_sha256.clone(),
                installed_by_delivery: true,
                installer: installer.clone(),
            };
            recs.push(rec);
            let pi = p
                .package_info(&pkg)
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, e))?
                .unwrap_or_default();
            if pi.version_code != Some(info.version_code) {
                return fail(
                    9,
                    exit::DELIVERY_FAILED,
                    format!("{pkg}: the installed versionCode differs from the APK's"),
                );
            }
            p.whitelist_add(&pkg)
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, e))?;
            if !p
                .whitelisted(&pkg)
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, e))?
            {
                return fail(
                    9,
                    exit::DELIVERY_FAILED,
                    format!("{pkg}: battery exception not listed after setting it"),
                );
            }
            let st = p
                .shell(&["dumpsys", "package", &pkg])
                .map(|d| simplex::parse_pkg_state(&d))
                .or_else(|e| fail(9, exit::DELIVERY_FAILED, e))?;
            if st.not_launched != Some(true) {
                return fail(
                    9,
                    exit::DELIVERY_FAILED,
                    format!("{pkg} was started (notLaunched is not true); nothing may start before the F-Droid client's own step"),
                );
            }
            if st.installer != installer {
                return fail(
                    9,
                    exit::DELIVERY_FAILED,
                    format!(
                        "{pkg}: installer of record is {:?}, expected {:?}",
                        st.installer, installer
                    ),
                );
            }
            self.o.line(format!(
                "  {pkg} installed, versionCode {}, battery exception set, not started{}",
                info.version_code,
                installer
                    .as_deref()
                    .map(|i| format!(", installer of record {i}"))
                    .unwrap_or_default()
            ));
        }
        self.rec.simplex_app = recs.pop();
        self.rec.fdroid = recs.pop();
        Ok(())
    }

    pub(super) fn vpn_check(&mut self, step: u8, want: &[String]) -> Result<Vec<String>, Failure> {
        let cfg = self.env.cfg;
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let uids = p
            .shell(&["pm", "list", "packages", "-U"])
            .map(|o| simplex::parse_uids(&o))
            .or_else(|e| fail(step, exit::DELIVERY_FAILED, e))?;
        let mut want_uids = BTreeSet::new();
        for w in want {
            let u = uids.get(w).ok_or(()).or_else(|_| {
                fail(
                    step,
                    exit::DELIVERY_FAILED,
                    format!("{w} is not installed on this phone; Orbot's VPN cannot carry it"),
                )
            })?;
            want_uids.insert(*u);
        }
        let orbot_uid = uids.get(&cfg.orbot_package).copied();
        let mut seen = None;
        for i in 0..=self.env.ui_retries {
            let d = p
                .shell(&["dumpsys", "connectivity"])
                .or_else(|e| fail(step, exit::DELIVERY_FAILED, e))?;
            let nets = simplex::parse_vpn(&d);
            if let Some(n) = nets.into_iter().find(|n| n.owner == orbot_uid) {
                seen = Some(n);
                break;
            }
            if i < self.env.ui_retries {
                (self.env.sleep)(Duration::from_secs(1));
            }
        }
        let Some(net) = seen else {
            return fail(
                step,
                exit::DELIVERY_FAILED,
                "no connected VPN network owned by Orbot",
            );
        };
        let by_uid: BTreeMap<u32, &String> = uids.iter().map(|(k, v)| (*v, k)).collect();
        // The SDK sandbox uids of the apps (20000 + app id) count as the apps.
        let app_uids: BTreeSet<u32> = net.uids.iter().map(|u| simplex::app_uid(*u)).collect();
        let carried: Vec<String> = app_uids
            .iter()
            .map(|u| {
                by_uid
                    .get(u)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("uid {u}"))
            })
            .collect();
        if app_uids != want_uids {
            return fail(
                step,
                exit::DELIVERY_FAILED,
                format!(
                    "VPN APP LIST WRONG: Orbot's VPN carries {}, expected exactly {}",
                    carried.join(", "),
                    want.join(", ")
                ),
            );
        }
        Ok(carried)
    }

    pub(super) fn socks_listening(&mut self, step: u8, what: &str) -> Result<(), Failure> {
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let mut read_error = None;
        for i in 0..=self.env.ui_retries {
            let (v4, v6) = (
                p.shell(&["cat", "/proc/net/tcp"]),
                p.shell(&["cat", "/proc/net/tcp6"]),
            );
            if let (Err(e), Err(_)) = (&v4, &v6) {
                read_error = Some(e.clone());
            }
            let (v4, v6) = (v4.unwrap_or_default(), v6.unwrap_or_default());
            if orbot::listening(&v4, orbot::SOCKS_PORT) || orbot::listening(&v6, orbot::SOCKS_PORT)
            {
                return Ok(());
            }
            if i < self.env.ui_retries {
                (self.env.sleep)(Duration::from_secs(1));
            }
        }
        fail(
            step,
            exit::DELIVERY_FAILED,
            match read_error {
                Some(e) => format!("/proc/net/tcp cannot be read on the phone: {e}"),
                None => format!(
                    "SOCKS PORT CLOSED: no listener on 127.0.0.1:{} {what}",
                    orbot::SOCKS_PORT
                ),
            },
        )
    }

    /// A wait with the time left: a `waiting` event (`--json`) or a line.
    pub(super) fn waiting(&mut self, step: u8, left: u64, text: &str) {
        if self.o.json {
            self.o
                .event(json!({"event": "waiting", "state": "waiting", "step": step,
                                "remaining_secs": left, "message": text}));
        } else {
            self.o
                .line(format!("  {text}: {}m{:02}s left", left / 60, left % 60));
        }
    }

    /// Step 11: the F-Droid client's first start, inside the VPN with
    /// lockdown on: its own SOCKS proxy, then SimpleX's repository.
    pub(super) fn step11_fdroid(&mut self) -> Result<(), Failure> {
        if !self.vpn_mode() {
            self.o.step(11, "F-Droid client: not part of this delivery");
            return Ok(());
        }
        self.sx_step(11, "F-Droid client: SOCKS proxy and SimpleX's repository");
        let cfg = self.env.cfg;
        let fpkg = cfg.fdroid_package.clone();
        if !self.rec.vpn.as_ref().is_some_and(|v| v.lockdown)
            || !self.rec.lock.as_ref().is_some_and(|l| l.proven_after_apps)
        {
            return fail(
                11,
                exit::DELIVERY_FAILED,
                "the F-Droid client is never started before Orbot's VPN with lockdown is up",
            );
        }
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        // No notification permission dialog at the first start.
        if let Err(e) = p.shell(&[
            "pm",
            "grant",
            &fpkg,
            "android.permission.POST_NOTIFICATIONS",
        ]) {
            self.o
                .line(format!("  note: notification permission not granted: {e}"));
        }
        let st = p
            .shell(&["dumpsys", "package", &fpkg])
            .map(|d| simplex::parse_pkg_state(&d))
            .or_else(|e| fail(11, exit::DELIVERY_FAILED, e))?;
        if st.not_launched != Some(true) {
            return fail(
                11,
                exit::DELIVERY_FAILED,
                format!("{fpkg} was started before its first start here"),
            );
        }
        orbot::launch(&p, &fpkg).or_else(|e| fail(11, exit::DELIVERY_FAILED, e))?;
        let (sleep, retries) = (self.env.sleep, self.env.ui_retries);
        let mut log = Vec::new();
        let r = simplex::run_flow(
            &p,
            sleep,
            retries,
            "F-Droid set-up",
            simplex::FDROID_PROXY,
            &mut log,
        );
        for l in &log {
            self.o.line(format!("  fdroid: {l}"));
        }
        r.or_else(|e| fail(11, exit::DELIVERY_FAILED, e))?;
        if let Some(v) = self.rec.vpn.as_mut() {
            v.fdroid_socks_proxy = true;
        }
        self.o.line(format!(
            "  F-Droid client: SOCKS proxy 127.0.0.1:{} (a second layer under the VPN)",
            orbot::SOCKS_PORT
        ));
        let repo = self.rec.simplex_repo.clone().expect("step 4 ran");
        let uri = simplex::repo_intent_uri(&repo.url, &repo.fingerprint)
            .ok_or(())
            .or_else(|_| {
                fail(
                    11,
                    exit::DELIVERY_FAILED,
                    "simplex_repo_url is not https://",
                )
            })?;
        let host_path = repo.url.trim_start_matches("https://").to_string();
        let wait = cfg.fdroid_repo_wait_secs;
        let now = self.env.now;
        let mut log = Vec::new();
        let mut waits = Vec::new();
        let r = (|| -> Result<(), String> {
            let mut ui = orbot::Ui {
                phone: &p,
                sleep,
                retries,
                log: &mut log,
                what: "F-Droid set-up",
                found: Vec::new(),
            };
            // The client fetches the repository over Tor (it can take
            // minutes): one timed wait for the repository on the "Add
            // repository" screen, the tap, and the repository in the client.
            // The time is the clock or, where it does not move (the tests),
            // this wait's own sleeps.
            let start = now();
            let mut slept: u64 = 0;
            let elapsed = |slept: u64| now().saturating_sub(start).max(slept);
            simplex::open_add_repo(&p, &fpkg, &uri)?;
            let (mut intents, mut last_intent, mut errors) = (1u32, 0u64, 0u32);
            let (mut resent, mut tapped, mut next_report) = (false, false, 30u64);
            loop {
                let e = elapsed(slept);
                if e >= wait {
                    return Err(format!(
                        "F-Droid set-up: SimpleX's repository {host_path} was not shown in the F-Droid client within {wait} s (fdroid_repo_wait_secs; the repository intent was sent {intents} time(s), \"Add repository\" {}): the client's fetch over Tor did not finish",
                        if tapped { "tapped" } else { "never shown" }
                    ));
                }
                let nodes = ui.dump()?;
                let button = simplex::add_button_shown(&nodes);
                if tapped && !button && simplex::repo_added(&nodes) {
                    ui.log.push(format!(
                        "SimpleX's repository shown in the client after {e} s"
                    ));
                    break;
                }
                match simplex::repo_screen(&nodes, &host_path) {
                    simplex::RepoScreen::Shown if button => {
                        ui.run(simplex::FDROID_TAP_ADD)?;
                        tapped = true;
                        continue;
                    }
                    simplex::RepoScreen::Error => {
                        errors += 1;
                        ui.log.push(format!(
                            "the client could not fetch the repository (try {errors} of 3)"
                        ));
                        if errors >= 3 {
                            return Err(format!(
                                "F-Droid set-up: the client could not fetch SimpleX's repository {host_path} (\"Error connecting to the repository\" 3 times)"
                            ));
                        }
                        p.shell(&["input", "keyevent", "KEYCODE_BACK"])?;
                        sleep(Duration::from_secs(2));
                        slept += 2;
                        simplex::open_add_repo(&p, &fpkg, &uri)?;
                        (intents, last_intent, tapped) = (intents + 1, elapsed(slept), false);
                        continue;
                    }
                    _ => {}
                }
                if !resent && e.saturating_sub(last_intent) >= simplex::REPO_RESEND_AFTER_SECS {
                    ui.log.push(format!(
                        "SimpleX's repository not shown after {} s: the repository intent is sent again (once)",
                        simplex::REPO_RESEND_AFTER_SECS
                    ));
                    p.shell(&["input", "keyevent", "KEYCODE_BACK"])?;
                    sleep(Duration::from_secs(2));
                    slept += 2;
                    simplex::open_add_repo(&p, &fpkg, &uri)?;
                    (intents, last_intent, tapped, resent) =
                        (intents + 1, elapsed(slept), false, true);
                    continue;
                }
                if e >= next_report {
                    waits.push(wait.saturating_sub(e));
                    next_report = e - e % 30 + 30;
                }
                sleep(Duration::from_secs(1));
                slept += 1;
            }
            Ok(())
        })();
        for left in &waits {
            self.waiting(
                11,
                *left,
                "waiting for SimpleX's repository in the F-Droid client (fetched over Tor)",
            );
        }
        for l in &log {
            self.o.line(format!("  fdroid: {l}"));
        }
        let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
        r.or_else(|e| fail(11, exit::DELIVERY_FAILED, e))?;
        if let Some(r) = self.rec.simplex_repo.as_mut() {
            r.added_to_client = true;
        }
        self.o.line(format!(
            "  SimpleX's repository {} (fingerprint {}) added to the F-Droid client",
            repo.url, repo.fingerprint
        ));
        Ok(())
    }

    /// Lockdown at run time: `dumpsys connectivity` lists filtering rules
    /// that block every uid outside the VPN except Orbot (and its SDK
    /// sandbox uid). Our messenger is among the blocked uids: it reaches
    /// Orbot only over loopback.
    pub(super) fn lockdown_active(&mut self, step: u8, code: i32) -> Result<(), Failure> {
        let cfg = self.env.cfg;
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let uids = p
            .shell(&["pm", "list", "packages", "-U"])
            .map(|o| simplex::parse_uids(&o))
            .or_else(|e| fail(step, code, e))?;
        let d = p
            .shell(&["dumpsys", "connectivity"])
            .or_else(|e| fail(step, code, e))?;
        let rules = simplex::lockdown_rules(&d);
        let blocked = |u: u32| rules.iter().any(|(a, b)| (*a..=*b).contains(&u));
        let orbot = uids.get(&cfg.orbot_package).copied().unwrap_or(0);
        let messenger = uids.get(&self.rec.messenger_package).copied();
        if rules.is_empty() || blocked(orbot) {
            return fail(
                step,
                code,
                format!(
                    "LOCKDOWN NOT ACTIVE: dumpsys connectivity shows the filtering rules {rules:?} (Orbot uid {orbot})"
                ),
            );
        }
        // Every app uid but Orbot's is blocked outside the VPN.
        if let Some((name, u)) = uids
            .iter()
            .find(|(_, u)| **u >= 10_000 && **u != orbot && !blocked(**u))
        {
            return fail(
                step,
                code,
                format!(
                    "LOCKDOWN NOT ACTIVE: {name} (uid {u}) is outside the filtering rules {rules:?}"
                ),
            );
        }
        self.o.line(format!(
            "  lockdown at run time: {} filtering rule(s), every uid blocked outside the VPN except Orbot ({orbot}); our messenger ({}) blocked outside loopback",
            rules.len(),
            messenger
                .map(|m| {
                    if blocked(m) {
                        m.to_string()
                    } else {
                        format!("{m}, NOT in the rules")
                    }
                })
                .unwrap_or_else(|| "not installed".into())
        ));
        Ok(())
    }

    /// The installed `base.apk` of `package`, pulled and read: the signer's
    /// SHA-256 and its certificate.
    fn installed_cert(&self, package: &str) -> Result<(String, Vec<u8>), String> {
        let p = Phone {
            tools: &self.env.tools,
            serial: &self.a.serial,
        };
        let paths = p.apk_paths(package)?;
        let base = paths
            .iter()
            .find(|x| x.ends_with("/base.apk"))
            .ok_or(format!("pm path {package} names no base.apk"))?;
        let local = self.env.work_dir.join(format!("{package}-base.apk"));
        let _ = std::fs::remove_file(&local);
        let r = p.pull(base, &local.to_string_lossy()).and_then(|_| {
            let d = apk::signer_digest(&local)?;
            Ok((d, apk::signer_cert(&local)?))
        });
        let _ = std::fs::remove_file(&local);
        r
    }

    /// The final check of the SimpleX app part (in step 14).
    pub(super) fn final_simplex(&mut self) -> Result<(), Failure> {
        if !self.vpn_mode() {
            return Ok(());
        }
        let cfg = self.env.cfg;
        // The agent sees only the messenger (its <queries>), so the package
        // manager's view of these two apps comes from `dumpsys package`: its
        // signature hash and versionCode, against the certificate of the
        // pulled base.apk, whose SHA-256 must be the pin.
        let apps = [self.rec.fdroid.clone(), self.rec.simplex_app.clone()];
        for a in apps.into_iter().flatten() {
            let (base, der) = self.installed_cert(&a.package).or_else(|e| {
                fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!("{}: installed base.apk: {e}", a.package),
                )
            })?;
            if base != a.signer_sha256 {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!(
                        "WRONG SIGNER: the installed base.apk of {} is signed by {base}",
                        a.package
                    ),
                );
            }
            let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
            let p = Phone {
                tools: &tools,
                serial: &serial,
            };
            let dump = p
                .shell(&["dumpsys", "package", &a.package])
                .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
            let pm = simplex::pm_signature_hashes(&dump);
            let want = apk::java_hash(&der);
            let info =
                crate::device::parse::parse_dumpsys_package(&dump, &a.package).unwrap_or_default();
            if pm != [want] || info.version_code != Some(a.version_code) {
                return fail(
                    14,
                    exit::DELIVERY_CHECK,
                    format!(
                        "WRONG SIGNER: the package manager records {} with signature hashes {pm:x?} versionCode {:?}, expected [{want:x}] versionCode {}",
                        a.package, info.version_code, a.version_code
                    ),
                );
            }
            self.o.line(format!(
                "  {} signer {} (installed base.apk; the package manager's signature {want:08x} and versionCode {})",
                a.package, a.signer_sha256, a.version_code
            ));
        }
        let (tools, serial) = (self.env.tools.clone(), self.a.serial.clone());
        let p = Phone {
            tools: &tools,
            serial: &serial,
        };
        let st = p
            .shell(&["dumpsys", "package", &cfg.simplex_app_package])
            .map(|d| simplex::parse_pkg_state(&d))
            .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
        if st.stopped != Some(true) || st.not_launched != Some(true) {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "{} was started (stopped {:?}, notLaunched {:?}); nothing may be started inside it",
                    cfg.simplex_app_package, st.stopped, st.not_launched
                ),
            );
        }
        if st.installer.as_deref() != Some(cfg.fdroid_package.as_str()) {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!(
                    "{}: installer of record {:?}",
                    cfg.simplex_app_package, st.installer
                ),
            );
        }
        self.o.line(format!(
            "  {}: never started (stopped, notLaunched); installer of record {}",
            cfg.simplex_app_package, cfg.fdroid_package
        ));
        let want = vpn_packages(cfg);
        let baseline = self.rec.lock.as_ref().and_then(|l| l.mode_line.clone());
        let line = self.prove_lock(14, exit::DELIVERY_CHECK, &want, baseline.as_deref())?;
        self.o.line(format!(
            "  Orbot's VPN carries exactly: {}; always-on VPN Orbot, lockdown on, no mode change since the lock ({line}); listener on 127.0.0.1:9050 for our messenger",
            want.join(", ")
        ));
        let comp = simplex::launch_fresh(&p, &cfg.fdroid_package)
            .or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
        // The client's disguised launcher aliases ("Calculator") stay off.
        if comp.contains("Calculator") {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!("the F-Droid client launches as {comp}, a disguised Calculator alias"),
            );
        }
        let mut log = Vec::new();
        let fp = self
            .rec
            .simplex_repo
            .as_ref()
            .map(|r| r.fingerprint.clone())
            .unwrap_or_default();
        let r = (|| -> Result<bool, String> {
            let mut ui = orbot::Ui {
                phone: &p,
                sleep: self.env.sleep,
                retries: self.env.ui_retries,
                log: &mut log,
                what: "F-Droid check",
                found: Vec::new(),
            };
            ui.run(simplex::FDROID_REPO_LISTED)?;
            let nodes = ui.dump()?;
            Ok(nodes
                .iter()
                .any(|n| n.text.trim().eq_ignore_ascii_case(&fp)))
        })();
        let _ = p.shell(&["input", "keyevent", "KEYCODE_HOME"]);
        let shown = r.or_else(|e| fail(14, exit::DELIVERY_CHECK, e))?;
        if !shown {
            return fail(
                14,
                exit::DELIVERY_CHECK,
                format!("the F-Droid client does not show the pinned fingerprint {fp} for SimpleX's repository"),
            );
        }
        self.o.line(format!(
            "  the F-Droid client lists SimpleX's repository with the signing key fingerprint {fp} (launcher {comp})"
        ));
        // For the delivery report: who talks to whom, from the phone.
        let uids = p
            .shell(&["pm", "list", "packages", "-U"])
            .map(|o| simplex::parse_uids(&o))
            .unwrap_or_default();
        let mut socks = Vec::new();
        for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
            socks.extend(simplex::parse_sockets(
                &p.shell(&["cat", f]).unwrap_or_default(),
            ));
        }
        for pkg in [
            &self.rec.messenger_package,
            &cfg.simplex_app_package,
            &cfg.fdroid_package,
        ] {
            let Some(u) = uids.get(pkg) else { continue };
            let mine: Vec<&simplex::Sock> = socks
                .iter()
                .filter(|s| s.uid == *u && s.state == "01")
                .collect();
            let outside = mine.iter().filter(|s| !s.remote_is_loopback()).count();
            self.o.line(format!(
                "  {pkg}: {} established TCP connection(s), {} to 127.0.0.1:9050, {outside} to other addresses (inside the VPN for the SimpleX app and the F-Droid client)",
                mine.len(),
                mine.iter().filter(|s| s.remote == "127.0.0.1:9050").count()
            ));
        }
        Ok(())
    }
}
