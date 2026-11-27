// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Delivery tests against the fake adb (`tests/support/fake_adb.rs`). No
//! real phone, no real adb: `adb_path` points to the fake, which keeps a
//! simulated phone in `state.json` and logs every call.

use super::*;
use crate::activation::payload::tests::sample;
use crate::activation::payload::Kind;
use crate::activation::rng::SeededRand;
use crate::activation::store::tests::one_at_a_time;
use crate::activation::store::tests::{init_test_store, open_test_store};
use crate::apk::testapk::{self, Spec, TestKey};
use crate::attest::tests as at;
use crate::fdroid::testrepo;
use crate::grapheneos::status as os_status;
use crate::grapheneos::testhttp::FakeHttp;
use crate::trust::cache::Loaded;
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use std::sync::OnceLock;

const SERIAL: &str = "TESTSERIAL6A01";
const OTHER: &str = "OTHERPHONE9P99";
const KEY_PASS: &str = "TEST-ONLY-PASSPHRASE";
const MESSENGER: &str = "org.example.messenger";
const ORBOT: &str = "org.torproject.android";
const CALC: &str = "com.android.calculator2";
const FDROID: &str = "org.fdroid.fdroid";
const SIMPLEX: &str = "chat.simplex.app";
const UPDATER: &str = "app.seamlessupdate.client";
const APPSTORE: &str = "app.grapheneos.apps";
const REPO: &str = "https://app.simplex.chat/fdroid/repo";
const VERIFIER: &str = "com.android.statementservice";
/// The autoVerify web hosts of the test APKs (a part of the real ones).
const SIMPLEX_HOSTS: [&str; 2] = ["simplex.chat", "smp4.simplex.im"];
const FDROID_HOSTS: [&str; 2] = ["f-droid.org", "fdroid.link"];

fn fake_adb_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    let p = dir
        .join("examples")
        .join(format!("fake-adb{}", std::env::consts::EXE_SUFFIX));
    assert!(
        p.is_file(),
        "fake adb not built at {}: run `cargo test` (it builds the example targets)",
        p.display()
    );
    p
}

struct Keys {
    messenger: TestKey,
    other: TestKey,
    orbot: TestKey,
    fdroid: TestKey,
    simplex: TestKey,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| Keys {
        messenger: TestKey::new("messenger"),
        other: TestKey::new("someone else"),
        orbot: TestKey::new("orbot"),
        fdroid: TestKey::new("fdroid client"),
        simplex: TestKey::new("simplex app"),
    })
}

type OsStatusFn = Box<dyn Fn(&Installed) -> OsStatus>;

struct Fx {
    dir: PathBuf,
    cfg_text: String,
    args: DeliverArgs,
    trust: TrustMaterial,
    apk: ApkMeta,
    /// The GrapheneOS status the delivery sees (None: not looked up).
    os_status: Option<OsStatusFn>,
    /// SimpleX's repository over "Tor".
    http: FakeHttp,
    /// The F-Droid client APK (for `--fdroid-apk`).
    fdroid_apk: PathBuf,
    simplex_apk: Vec<u8>,
}

struct ApkMeta {
    sha: String,
}

struct TestUi {
    confirm: Result<bool, String>,
    shown: Vec<String>,
}

impl Ui for TestUi {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(
            match what {
                Secret::SigningKeyPassphrase => KEY_PASS,
            }
            .to_string(),
        ))
    }
    fn confirm(&mut self, _word: &str, _q: &str) -> Result<bool, String> {
        self.confirm.clone()
    }
    fn show_code(&mut self, code: &str) {
        self.shown.push(code.to_string());
    }
}

struct Run {
    code: i32,
    out: String,
    shown: Vec<String>,
}

/// SimpleX's repository with one release (397) of the given APK, signed
/// with the TEST ONLY repository key; the index names `signer`.
fn put_repo(http: &FakeHttp, apk: &[u8], signer: &str, ts: u64) {
    let file = "chat.simplex.app_aarch64_397.apk";
    let vs = [testrepo::V {
        code: 397,
        name: "7.1.4",
        file,
        apk,
        abi: "arm64-v8a",
        signer,
    }];
    let idx = testrepo::index(REPO, SIMPLEX, &vs);
    http.put(&format!("{REPO}/index-v2.json"), &idx);
    http.put(
        &format!("{REPO}/entry.jar"),
        &testrepo::entry_jar(&testrepo::entry_json(&idx, ts)),
    );
    http.put(&format!("{REPO}/{file}"), apk);
}

fn write_apk(dir: &Path, name: &str, spec: &Spec, key: &TestKey) -> (PathBuf, String) {
    let bytes = testapk::build(spec, key);
    let p = dir.join(name);
    std::fs::write(&p, &bytes).unwrap();
    (p, hex(&crate::util::sha256(&bytes)))
}

impl Fx {
    fn new(tag: &str) -> Fx {
        let dir = crate::activation::store::tests::temp_dir(&format!("deliver-{tag}"));
        let adb = dir.join("adb");
        if std::fs::hard_link(fake_adb_binary(), &adb).is_err() {
            std::fs::copy(fake_adb_binary(), &adb).unwrap();
        }
        std::fs::create_dir_all(dir.join("work")).unwrap();
        let k = keys();
        let (apk, apk_sha) = write_apk(
            &dir,
            "messenger.apk",
            &Spec::new(MESSENGER, 2157),
            &k.messenger,
        );
        let mut os = Spec::new(ORBOT, 1_700_200);
        os.filler = b"orbot".to_vec();
        let (orbot, orbot_sha) = write_apk(&dir, "orbot.apk", &os, &k.orbot);
        let mut fs = Spec::new(FDROID, 2_000_053);
        fs.filler = b"fdroid client".to_vec();
        fs.link_hosts = FDROID_HOSTS.to_vec();
        let (fdroid_apk, fdroid_sha) = write_apk(&dir, "F-Droid.apk", &fs, &k.fdroid);
        let mut ss = Spec::new(SIMPLEX, 397);
        ss.filler = b"simplex app".to_vec();
        ss.link_hosts = SIMPLEX_HOSTS.to_vec();
        let simplex_apk = testapk::build(&ss, &k.simplex);
        let simplex_sha = hex(&crate::util::sha256(&simplex_apk));
        let http = FakeHttp::default();
        put_repo(
            &http,
            &simplex_apk,
            &k.simplex.digest_hex(),
            1_794_696_615_000,
        );
        // A test APK as the agent: step 4 reads its web link filters.
        let (agent, agent_sha) = write_apk(
            &dir,
            "agent.apk",
            &Spec::new(crate::names::DEFAULT_AGENT_PACKAGE, 1),
            &k.other,
        );
        // Synthetic attestation chain for the fixed challenge.
        let syn = at::synthetic(&at::grapheneos_kd(at::CHALLENGE), false);
        let chain: Vec<String> = syn.ders.iter().map(|d| Base64::encode_string(d)).collect();
        let p = sample(Kind::Activation, NetworkMode::TorRequired);
        std::fs::write(
            dir.join("servers.txt"),
            format!("{}\n{}\n", p.servers.smp[0], p.servers.xftp[0]),
        )
        .unwrap();
        std::fs::write(dir.join("support.txt"), format!("{}\n", p.support_address)).unwrap();
        let store = dir.join("store/admin.sxdb");
        drop(init_test_store(&store, tag.as_bytes()));
        let cfg_text = format!(
            "trust_cache_dir = \"{d}/trust\"\nadb_path = \"{d}/adb\"\nfastboot_path = \"\"\nagent_apk = \"{agent}\"\n\
             agent_signing_cert_sha256 = \"{a5}\"\nadmin_store_path = \"{store}\"\n\
             orbot_signing_cert_sha256 = \"{orbot_digest}\"\nallow_test_key_for_test_deliveries = true\n\
             fdroid_signing_cert_sha256 = \"{fd}\"\nsimplex_app_signing_cert_sha256 = \"{sx}\"\n\
             simplex_repo_fingerprint = \"{fp}\"\n",
            d = dir.display(),
            agent = agent.display(),
            a5 = "a5".repeat(32),
            store = store.display(),
            orbot_digest = k.orbot.digest_hex(),
            fd = k.fdroid.digest_hex(),
            sx = k.simplex.digest_hex(),
            fp = testrepo::fingerprint(),
        );
        let state = json!({
            "target": SERIAL,
            "devices": [{"serial": SERIAL, "state": "device", "model": "Pixel_6a"}],
            "props": {
                "ro.product.manufacturer": "Google", "ro.product.model": "Pixel 6a",
                "ro.product.device": "bluejay", "ro.build.version.release": "16",
                "ro.build.id": "BP2A.TEST", "ro.build.version.security_patch": "2026-11-05",
                "ro.boot.flash.locked": "1", "ro.boot.verifiedbootstate": "yellow",
                "ro.product.cpu.abilist": "arm64-v8a", "ro.build.version.sdk": "37"
            },
            "packages": {
                CALC: {"version_code": 1, "version_name": "AOSP", "signer": "00", "system": true, "uid": 10050, "label": "Calculator"},
                "com.android.settings": {"version_code": 1, "version_name": "16", "signer": "00", "system": true, "uid": 1000},
                UPDATER: {"version_code": 1, "version_name": "1", "signer": "00", "system": true, "uid": 10054, "label": "System Updater"},
                APPSTORE: {"version_code": 1, "version_name": "1", "signer": "00", "system": true, "uid": 10051, "label": "App Store"},
                "app.vanadium.browser": {"version_code": 1, "version_name": "1", "signer": "00", "system": true, "uid": 10053, "label": "Vanadium"},
                VERIFIER: {"version_code": 1, "version_name": "1", "signer": "00", "system": true, "uid": 10052}
            },
            "apks": {
                apk_sha.clone(): {"package": MESSENGER, "version_code": 2157, "version_name": "1.0-test", "signer": k.messenger.digest_hex(),
                                  "sig_hash": format!("{:x}", crate::apk::java_hash(&k.messenger.cert_der))},
                orbot_sha: {"package": ORBOT, "version_code": 1_700_200, "version_name": "1.0-test", "signer": k.orbot.digest_hex(), "label": "Orbot"},
                fdroid_sha: {"package": FDROID, "version_code": 2_000_053, "version_name": "2.0.3", "signer": k.fdroid.digest_hex(), "label": "F-Droid",
                             "sig_hash": format!("{:x}", crate::apk::java_hash(&k.fdroid.cert_der)), "web_hosts": FDROID_HOSTS},
                simplex_sha: {"package": SIMPLEX, "version_code": 397, "version_name": "7.1.4", "signer": k.simplex.digest_hex(), "label": "SimpleX",
                              "sig_hash": format!("{:x}", crate::apk::java_hash(&k.simplex.cert_der)), "web_hosts": SIMPLEX_HOSTS},
                agent_sha: {"package": crate::names::DEFAULT_AGENT_PACKAGE, "version_code": 1, "version_name": "0.1.0", "signer": "a5".repeat(32)}
            },
            "agent_chain": chain,
            "agent_package": crate::names::DEFAULT_AGENT_PACKAGE,
            "messenger_package": MESSENGER,
            "orbot_package": ORBOT,
            "orbot": {"screen": "", "boot": false, "open_proxy": true, "power": false, "port": "9150", "field": "", "connected": false},
            "provider": {},
            "fd": {"repo_fingerprint": testrepo::fingerprint()}
        });
        std::fs::write(
            dir.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        // One call lets the fake write its normalised state; then a clean log.
        std::process::Command::new(&adb)
            .args(["devices", "-l"])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(dir.join("calls.log"));
        let trust = TrustMaterial {
            anchors: vec![syn.root.clone()],
            rev: Loaded {
                value: at::revocation(r#"{"entries":{"ffff":{"status":"REVOKED"}}}"#),
                meta: at::meta(at::T_SYN - at::DAY),
            },
            gos: Loaded {
                value: at::gos_keys(),
                meta: at::meta(at::T_SYN - at::DAY),
            },
        };
        let args = DeliverArgs {
            serial: SERIAL.into(),
            apk,
            customer_ref: "TEST-6A-0001".into(),
            network_mode: "tor_required".into(),
            servers: dir.join("servers.txt"),
            support: dir.join("support.txt"),
            key: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key-encrypted"),
            orbot_apk: Some(orbot),
            normal_tier: false,
            dry_run: false,
            reinstall: false,
            accept_unverified_messenger: true,
            test_delivery: true,
            allow_outdated_os: false,
            fdroid_apk: None,
            json: false,
            features: None,
            directory: None,
        };
        Fx {
            dir,
            cfg_text,
            args,
            trust,
            apk: ApkMeta { sha: apk_sha },
            os_status: None,
            http,
            fdroid_apk,
            simplex_apk,
        }
    }

    fn cfg(&self) -> Config {
        Config::parse(&self.cfg_text).unwrap()
    }

    fn state(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("state.json")).unwrap()).unwrap()
    }

    fn edit(&self, f: impl FnOnce(&mut Value)) {
        let mut s = self.state();
        f(&mut s);
        std::fs::write(
            self.dir.join("state.json"),
            serde_json::to_vec_pretty(&s).unwrap(),
        )
        .unwrap();
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn clear_calls(&self) {
        let _ = std::fs::remove_file(self.dir.join("calls.log"));
    }

    fn with_env<R>(
        &self,
        confirm: Result<bool, String>,
        f: impl FnOnce(&mut Env) -> R,
    ) -> (R, Vec<String>) {
        let cfg = self.cfg();
        let mut ui = TestUi {
            confirm,
            shown: Vec::new(),
        };
        let mut ch = || Ok(at::CHALLENGE.to_vec());
        let mut rng = SeededRand::new(b"deliver-test");
        let now = || at::T_SYN;
        let sleep = |_d: Duration| {};
        let mut env = Env {
            cfg: &cfg,
            tools: Tools {
                adb: cfg.adb_path.clone(),
                fastboot: String::new(),
            },
            ui: &mut ui,
            now: &now,
            challenge: &mut ch,
            rng: &mut rng,
            sleep: &sleep,
            trust: Some(&self.trust),
            stale_confirmed: false,
            work_dir: self.dir.join("work"),
            ui_retries: 2,
            os_status: self.os_status.as_deref(),
            http: Some(&self.http),
        };
        let r = f(&mut env);
        drop(env);
        (r, ui.shown)
    }

    fn deliver_with(&self, a: &DeliverArgs, confirm: Result<bool, String>) -> Run {
        let mut out = Vec::new();
        let (code, shown) = self.with_env(confirm, |env| deliver(env, &mut out, a));
        Run {
            code,
            out: String::from_utf8(out).unwrap(),
            shown,
        }
    }

    fn deliver(&self) -> Run {
        self.deliver_with(&self.args, Ok(true))
    }

    fn records(&self) -> Vec<Delivery> {
        let s = open_test_store(&self.dir.join("store/admin.sxdb"));
        s.data.deliveries.clone()
    }

    fn undeliver(&self, test_device: bool) -> (i32, String) {
        self.undeliver_with(undo::UndoOpts {
            test_device,
            ..Default::default()
        })
    }

    fn undeliver_with(&self, opts: undo::UndoOpts) -> (i32, String) {
        let mut out = Vec::new();
        let (code, _) = self.with_env(Ok(true), |env| undo::undeliver(env, &mut out, SERIAL, opts));
        (code, String::from_utf8(out).unwrap())
    }

    fn handover(&self, confirm: Result<bool, String>) -> (i32, String) {
        let mut out = Vec::new();
        let (code, _) = self.with_env(confirm, |env| undo::handover(env, &mut out, SERIAL, false));
        (code, String::from_utf8(out).unwrap())
    }

    fn write_report_log(&self, name: &str) {
        // The commands each scenario sends, for the report (no serial, no code).
        if let Some(d) = std::env::var_os("SXPROV_FAKE_ADB_LOG_DIR") {
            let p = PathBuf::from(d).join(format!("{name}.log"));
            let _ = std::fs::write(p, self.calls().join("\n") + "\n");
        }
    }
}

/// Every device call names the target with `-s`, and no call reached
/// another device; no full serial and no code in the log.
fn assert_clean_log(fx: &Fx, run: &Run) {
    for c in fx.calls() {
        assert!(!c.contains("<OTHER"), "another device was addressed: {c}");
        assert!(
            c == "adb devices -l" || c.starts_with("adb -s <serial> "),
            "{c}"
        );
        assert!(!c.contains(SERIAL), "{c}");
    }
    assert!(!run.out.contains(SERIAL), "full serial in the output");
    assert!(!run.out.contains(OTHER), "other serial in the output");
    for code in &run.shown {
        let canon = Code::parse_input(code).unwrap();
        let canon = String::from_utf8_lossy(canon.canonical()).to_string();
        assert!(!run.out.contains(code.as_str()), "code in the output");
        assert!(!run.out.contains(&canon), "canonical code in the output");
        for c in fx.calls() {
            assert!(!c.contains(&canon), "code in the adb log: {c}");
        }
    }
}

#[test]
fn fresh_grapheneos_phone_code_only_with_orbot() {
    let _g = one_at_a_time();
    let fx = Fx::new("fresh");
    let r = fx.deliver();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("DELIVERED"), "{}", r.out);
    assert!(r.out.contains("messenger UNVERIFIED"));
    assert!(r.out.contains("code only"));
    assert_eq!(r.shown.len(), 1, "the code is shown exactly once");
    assert_clean_log(&fx, &r);
    let s = fx.state();
    assert!(s["packages"][MESSENGER].is_object());
    assert!(s["whitelist"]
        .as_array()
        .unwrap()
        .contains(&json!(MESSENGER)));
    assert!(s["disabled"].as_array().unwrap().contains(&json!(CALC)));
    assert_eq!(s["provider"]["activation"], json!(true));
    // The code on the phone is the one shown.
    let shown = Code::parse_input(&r.shown[0]).unwrap();
    assert_eq!(
        s["provider"]["code_sha256"],
        json!(hex(&crate::util::sha256(shown.canonical())))
    );
    // Orbot: SOCKS only (Power User Mode, no VPN), not open on other
    // interfaces, start on boot, port 9050, connected; no dump left.
    assert_eq!(s["orbot"]["power"], json!(true));
    assert_eq!(s["orbot"]["open_proxy"], json!(false));
    assert!(s["appops"]
        .as_array()
        .unwrap()
        .contains(&json!(format!("{ORBOT}:SCHEDULE_EXACT_ALARM"))));
    assert!(s["whitelist"].as_array().unwrap().contains(&json!(ORBOT)));
    assert_eq!(s["orbot"]["boot"], json!(true));
    assert_eq!(s["orbot"]["port"], json!("9050"));
    assert_eq!(s["orbot"]["connected"], json!(true));
    assert!(s["files"].as_object().is_none_or(|f| f.is_empty()));
    // The agent was removed again.
    assert!(s["packages"][crate::names::DEFAULT_AGENT_PACKAGE].is_null());
    let recs = fx.records();
    let d = &recs[0];
    assert_eq!(d.result, "delivered");
    assert!(d.test);
    assert_eq!(d.serial, SERIAL);
    assert_eq!(d.serial_masked, mask_serial(SERIAL));
    assert!(!d.file_transferred);
    assert!(!d.messenger_verified);
    assert_eq!(d.messenger_apk_sha256.as_deref(), Some(fx.apk.sha.as_str()));
    assert_eq!(
        d.messenger_signer_sha256.as_deref(),
        Some(keys().messenger.digest_hex().as_str())
    );
    assert_eq!(d.code_masked.as_deref(), Some(shown.masked().as_str()));
    let o = d.orbot.as_ref().unwrap();
    assert!(o.installed_by_delivery && o.socks_listening);
    assert_eq!(d.calculator_disabled.as_deref(), Some(CALC));
    assert_eq!(d.attestation, "OS PASS, messenger UNVERIFIED");
    // The issue is in the fleet log with the serial.
    let st = open_test_store(&fx.dir.join("store/admin.sxdb"));
    assert_eq!(st.data.issues.len(), 1);
    assert_eq!(st.data.issues[0].file_id, d.file_id.clone().unwrap());
    fx.write_report_log("fresh-grapheneos-phone");
}

#[test]
fn provider_with_file_import() {
    let _g = one_at_a_time();
    let fx = Fx::new("fileimport");
    fx.edit(|s| s["provider"]["file_import"] = json!(true));
    let r = fx.deliver();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("file imported"), "{}", r.out);
    let d = &fx.records()[0];
    assert!(d.file_transferred);
    let s = fx.state();
    assert_eq!(s["provider"]["file_id"], json!(d.file_id.clone().unwrap()));
    assert_eq!(s["provider"]["network_mode"], json!("tor_required"));
    assert!(fx.calls().iter().any(|c| c.ends_with("content write --uri content://org.example.messenger.activation/file < (file on standard input)")));
    assert_clean_log(&fx, &r);
    fx.write_report_log("provider-with-file-import");
}

/// `--features` with the example of section 12.1 (it fixes switches).
fn with_features(fx: &Fx) -> DeliverArgs {
    let p = fx.dir.join("features.json");
    std::fs::write(
        &p,
        r#"{"profile_version":1,"groups":"off","channels":"off","preset_servers":"off","calls":"on","files":"on","voice_messages":"on","calculator_disguise":"on"}"#,
    )
    .unwrap();
    let mut a = fx.args.clone();
    a.features = Some(p);
    a
}

/// `--directory` with one group on the delivery's SMP server.
fn with_directory(fx: &Fx, a: &mut DeliverArgs) {
    let s = sample(Kind::Activation, NetworkMode::TorRequired);
    let server = crate::activation::hosts::parse_server(&s.servers.smp[0], "smp").unwrap();
    let link =
        crate::activation::hosts::tests::group_link_on(&server, "TEST-ONLY-GROUP-LINK-KEY-1");
    let p = fx.dir.join("directory.json");
    std::fs::write(
        &p,
        json!({"display_name": "TEST Anna", "role": "owner",
               "groups": [{"name": "TEST Kanzlei", "link": link, "direct_contacts": true}]})
        .to_string(),
    )
    .unwrap();
    a.directory = Some(p);
}

/// Section 12.4: a fixed profile or a directory entry needs the file
/// import; without it the delivery stops after step 8, nothing issued.
#[test]
fn fixed_features_without_file_import_stop_after_step_8() {
    let _g = one_at_a_time();
    for (tag, dir) in [("featnoimport", false), ("dirnoimport", true)] {
        let fx = Fx::new(tag);
        let mut a = if dir {
            fx.args.clone()
        } else {
            with_features(&fx)
        };
        if dir {
            with_directory(&fx, &mut a);
        }
        let r = fx.deliver_with(&a, Ok(true));
        assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
        assert!(r.out.contains("DELIVERY FAILED at step 8"), "{}", r.out);
        let why = if dir {
            "this phone has a directory entry (role owner, 1 group(s))"
        } else {
            "feature profile fixes calculator_disguise:on,calls:on,channels:off"
        };
        assert!(r.out.contains(why), "{}", r.out);
        assert!(r.out.contains("Nothing was issued"), "{}", r.out);
        assert!(
            r.out.contains("network lock and the apps installed"),
            "{}",
            r.out
        );
        assert!(r.out.contains("undeliver"), "{}", r.out);
        assert!(r.shown.is_empty(), "no code shown");
        let d = &fx.records()[0];
        assert_eq!(d.result, "failed at step 8");
        assert!(d.file_id.is_none() && d.code_masked.is_none());
        let st = open_test_store(&fx.dir.join("store/admin.sxdb"));
        assert!(st.data.issues.is_empty(), "something was issued");
        assert!(st.data.customers.is_empty());
        // The messenger is installed, nothing after it ran.
        assert!(!fx.calls().iter().any(|c| c.contains("--method activate")));
        assert_clean_log(&fx, &r);
    }
    // A profile that fixes nothing needs no file import.
    let fx = Fx::new("featnothingfixed");
    let p = fx.dir.join("features.json");
    std::fs::write(&p, r#"{"profile_version":1,"groups":"ask"}"#).unwrap();
    let mut a = fx.args.clone();
    a.features = Some(p);
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(!fx.records()[0].file_transferred);
}

/// With the file import the profile is applied, recorded and checked in
/// step 14 against what the app reports.
#[test]
fn fixed_features_with_file_import_are_checked_in_step_14() {
    let _g = one_at_a_time();
    let fx = Fx::new("featimport");
    fx.edit(|s| s["provider"]["file_import"] = json!(true));
    let mut a = with_features(&fx);
    with_directory(&fx, &mut a);
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(
        r.out
            .contains("feature profile applied: features_profile 82c3232f78958958"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("file import: customer TEST-6A-0001's feature profile fixes"),
        "{}",
        r.out
    );
    let d = &fx.records()[0];
    assert!(d.file_transferred);
    assert_eq!(d.features_profile.as_deref(), Some("82c3232f78958958"));
    assert_eq!(
        d.directory_role,
        Some(crate::activation::directory::Role::Owner)
    );
    let st = open_test_store(&fx.dir.join("store/admin.sxdb"));
    let c = &st.data.customers["TEST-6A-0001"];
    assert!(c.features.phone.is_some());
    let set = c.directory_set.as_ref().unwrap();
    assert_eq!(set.devices.len(), 1);
    assert_eq!(set.devices[0].serial, SERIAL);
    let all = serde_json::to_string(&st.data).unwrap();
    assert!(
        !all.contains("TEST Anna") && !all.contains("/g#"),
        "names or links stored"
    );
    assert_clean_log(&fx, &r);
    fx.write_report_log("features-with-file-import");

    // The app reports another profile: the final check fails.
    let fx = Fx::new("featwrong");
    fx.edit(|s| {
        s["provider"]["file_import"] = json!(true);
        s["provider"]["report_wrong_profile"] = json!(true);
    });
    let r = fx.deliver_with(&with_features(&fx), Ok(true));
    assert_eq!(r.code, exit::DELIVERY_CHECK, "{}", r.out);
    assert!(
        r.out
            .contains("reports features_profile Some(\"0000000000000000\")"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 14");
}

#[test]
fn dry_run_names_the_file_import_need() {
    let _g = one_at_a_time();
    let fx = Fx::new("featdry");
    let mut a = with_features(&fx);
    a.dry_run = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(
        r.out
            .contains("file import: customer TEST-6A-0001's feature profile fixes"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("unknown until the messenger is installed"),
        "{}",
        r.out
    );
    // Refused before anything: a desktop-only switch on, a bad directory.
    fx.clear_calls();
    let p = fx.dir.join("bad.json");
    std::fs::write(&p, r#"{"profile_version":1,"vault":"on"}"#).unwrap();
    let mut b = fx.args.clone();
    b.features = Some(p.clone());
    let r = fx.deliver_with(&b, Ok(true));
    assert_eq!(r.code, exit::ACTIVATION_INPUT, "{}", r.out);
    assert!(
        r.out.contains("vault exists only on the desktop"),
        "{}",
        r.out
    );
    std::fs::write(
        &p,
        r#"{"display_name":"TEST. Anna","role":"member","groups":[]}"#,
    )
    .unwrap();
    let mut b = fx.args.clone();
    b.directory = Some(p);
    let r = fx.deliver_with(&b, Ok(true));
    assert_eq!(r.code, exit::ACTIVATION_INPUT, "{}", r.out);
    assert!(r.out.contains("U+002E"), "{}", r.out);
    // Neither run reached the phone.
    assert!(fx.calls().is_empty(), "{:?}", fx.calls());
}

#[test]
fn customer_phone_is_never_touched() {
    let _g = one_at_a_time();
    let fx = Fx::new("customer");
    fx.edit(|s| {
        s["packages"][MESSENGER] =
            json!({"version_code": 2157, "version_name": "x", "signer": "ab"});
        s["provider"]["setup_done"] = json!(true);
    });
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_REFUSED, "{}", r.out);
    assert!(r.out.contains("set up by a customer"));
    for c in fx.calls() {
        let writes = [
            "install",
            "uninstall",
            "disable-user",
            "whitelist +",
            "activate",
            "settings put",
        ];
        let agent = c.contains(crate::names::DEFAULT_AGENT_PACKAGE) || c.contains("agent.apk");
        assert!(
            agent || !writes.iter().any(|w| c.contains(w)),
            "write on a customer phone: {c}"
        );
    }
    assert_eq!(fx.records()[0].result, "failed at step 3");
    assert!(r.shown.is_empty());
    // With --reinstall too.
    let mut a = fx.args.clone();
    a.reinstall = true;
    assert_eq!(fx.deliver_with(&a, Ok(true)).code, exit::DELIVERY_REFUSED);
    fx.write_report_log("customer-phone-setup-done");
}

#[test]
fn messenger_package_comes_from_the_apk() {
    let _g = one_at_a_time();
    // Any allowed package name: the record keeps it, and the provider
    // authority follows it ("{package}.activation").
    let fx = Fx::new("package-from-apk");
    let other = "org.example.other";
    let (apk, sha) = write_apk(
        &fx.dir,
        "other.apk",
        &Spec::new(other, 2157),
        &keys().messenger,
    );
    fx.edit(|s| {
        s["apks"][&sha] = json!({"package": other, "version_code": 2157, "version_name": "1.0-test",
            "signer": keys().messenger.digest_hex(),
            "sig_hash": format!("{:x}", crate::apk::java_hash(&keys().messenger.cert_der))});
        s["messenger_package"] = json!(other);
    });
    let mut a = fx.args.clone();
    a.apk = apk.clone();
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    let rec = &fx.records()[0];
    assert_eq!(rec.messenger_package, other);
    assert_eq!(
        rec.sxprov_version.as_deref(),
        Some(crate::names::version_tag().as_str())
    );
    let calls = fx.calls();
    assert!(calls.iter().any(|c| c
        .contains("content call --uri content://org.example.other.activation --method activate")));
    assert!(calls
        .iter()
        .all(|c| !c.contains(&format!("content://{MESSENGER}"))));
    assert!(
        calls.iter().all(|c| !c.contains("-e messenger")),
        "the agent gets no messenger"
    );

    // Another messenger on the phone (found by its activation provider):
    // refused in step 3, set up or not, before anything is written.
    for (setup_done, why) in [
        (false, "another messenger, org.example.messenger"),
        (true, "set up by a customer"),
    ] {
        let fx = Fx::new(&format!("package-other-installed-{setup_done}"));
        let (apk, sha) = write_apk(
            &fx.dir,
            "other.apk",
            &Spec::new(other, 2157),
            &keys().messenger,
        );
        fx.edit(|s| {
            s["apks"][&sha] = json!({"package": other, "version_code": 2157, "version_name": "1.0-test",
                "signer": keys().messenger.digest_hex()});
            s["packages"][MESSENGER] = json!({"version_code": 2157, "version_name": "x", "signer": "ab"});
            s["provider"]["setup_done"] = json!(setup_done);
        });
        let mut a = fx.args.clone();
        a.apk = apk;
        a.reinstall = true;
        let r = fx.deliver_with(&a, Ok(true));
        assert_eq!(r.code, exit::DELIVERY_REFUSED, "{}", r.out);
        assert!(r.out.contains(why), "{}", r.out);
        assert_eq!(fx.records()[0].result, "failed at step 3");
        assert!(fx
            .calls()
            .iter()
            .any(|c| c.ends_with("shell dumpsys package providers")));
        assert!(
            fx.calls().iter().all(|c| !c.contains("other.apk")),
            "the messenger was not installed"
        );
    }
}

#[test]
fn read_only_commands_find_the_messenger_by_its_provider() {
    let _g = one_at_a_time();
    let fx = Fx::new("resolve-messenger");
    let cfg = fx.cfg();
    let tools = Tools {
        adb: cfg.adb_path.clone(),
        fastboot: String::new(),
    };
    let r = crate::installed::resolve(None, &cfg, &tools, SERIAL);
    assert_eq!(r.package, None);
    assert!(r.note.contains("no messenger installed"), "{}", r.note);
    fx.edit(|s| {
        s["packages"][MESSENGER] =
            json!({"version_code": 2157, "version_name": "x", "signer": "ab"});
    });
    let r = crate::installed::resolve(None, &cfg, &tools, SERIAL);
    assert_eq!(r.package.as_deref(), Some(MESSENGER));
    assert!(
        r.note
            .contains("found by its activation provider (org.example.messenger.activation)"),
        "{}",
        r.note
    );
    let r = crate::installed::resolve(Some("org.example.given"), &cfg, &tools, SERIAL);
    assert_eq!(r.package.as_deref(), Some("org.example.given"));
    let fixed = Config::parse(&format!(
        "{}messenger_package = \"org.example.fixed\"
",
        fx.cfg_text
    ))
    .unwrap();
    let r = crate::installed::resolve(None, &fixed, &tools, SERIAL);
    assert_eq!(r.package.as_deref(), Some("org.example.fixed"));
    // Every call named the one device.
    assert!(
        fx.calls().iter().all(|c| c.starts_with("adb -s <serial> ")),
        "{:?}",
        fx.calls()
    );
}

#[test]
fn open_setup_needs_reinstall() {
    let _g = one_at_a_time();
    let fx = Fx::new("reinstall");
    let first = fx.deliver();
    assert_eq!(first.code, exit::UNVERIFIED, "{}", first.out);
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_REFUSED);
    assert!(r.out.contains("give --reinstall"));
    fx.clear_calls();
    let mut a = fx.args.clone();
    a.reinstall = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(fx
        .calls()
        .iter()
        .any(|c| c.contains(" install -r ") && c.contains("messenger.apk")));
    let recs = fx.records();
    assert_eq!(recs.len(), 3);
    assert!(recs[2].reinstall);
    assert!(!recs[2].orbot.as_ref().unwrap().installed_by_delivery);
}

#[test]
fn install_failure_stops_at_step_8() {
    let _g = one_at_a_time();
    let fx = Fx::new("installfail");
    fx.edit(|s| {
        s["fail"]["install:org.example.messenger"] =
            json!("Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]")
    });
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_FAILED);
    assert!(r.out.contains("DELIVERY FAILED at step 8"), "{}", r.out);
    assert!(r.out.contains("INSTALL_FAILED_INSUFFICIENT_STORAGE"));
    assert!(r.out.contains("undeliver"));
    let d = &fx.records()[0];
    assert_eq!(d.result, "failed at step 8");
    assert!(d
        .failure
        .as_deref()
        .unwrap()
        .contains("INSUFFICIENT_STORAGE"));
    // Orbot (step 6) has its battery exception, the messenger none.
    assert!(!fx.state()["whitelist"]
        .as_array()
        .unwrap()
        .contains(&json!(MESSENGER)));
    assert_clean_log(&fx, &r);
    fx.write_report_log("install-fails");
}

#[test]
fn provider_error_stops_at_the_activation() {
    let _g = one_at_a_time();
    let fx = Fx::new("providererr");
    fx.edit(|s| s["provider"]["activate_error"] = json!("code rejected, record not stored"));
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(
        r.out
            .contains("result=error: code rejected, record not stored"),
        "{}",
        r.out
    );
    assert!(
        r.shown.is_empty(),
        "no code shown when the phone refused it"
    );
    let d = &fx.records()[0];
    assert_eq!(d.result, "failed at step 12");
    assert!(d.code_masked.is_some());
    assert_clean_log(&fx, &r);
    fx.write_report_log("provider-error");
}

#[test]
fn second_device_is_never_addressed() {
    let _g = one_at_a_time();
    let fx = Fx::new("twodevices");
    fx.edit(|s| {
        s["devices"]
            .as_array_mut()
            .unwrap()
            .push(json!({"serial": OTHER, "state": "device", "model": "Pixel_6"}));
    });
    let r = fx.deliver();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert_clean_log(&fx, &r);
    // A serial that is not connected, or not in state device, is refused.
    let mut a = fx.args.clone();
    a.serial = "NOTCONNECTED1".into();
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_REFUSED);
    assert!(r.out.contains("no connected device"));
    assert!(!r.out.contains("NOTCONNECTED1"));
    fx.edit(|s| s["devices"][0]["state"] = json!("unauthorized"));
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_REFUSED);
    assert!(r.out.contains("state unauthorized"));
    fx.write_report_log("second-device");
}

#[test]
fn missing_calculator_hardened_stops_normal_warns() {
    let _g = one_at_a_time();
    let fx = Fx::new("nocalc");
    fx.edit(|s| {
        s["packages"].as_object_mut().unwrap().remove(CALC);
    });
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 13");
    // The normal tier warns and continues.
    let fx = Fx::new("nocalc-normal");
    fx.edit(|s| {
        s["packages"].as_object_mut().unwrap().remove(CALC);
    });
    let mut a = fx.args.clone();
    a.normal_tier = true;
    a.orbot_apk = None;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r
        .out
        .contains("WARNING: com.android.calculator2 is not installed"));
    fx.write_report_log("calculator-missing");
}

#[test]
fn normal_android_phone() {
    let _g = one_at_a_time();
    let fx = Fx::new("normalphone");
    fx.edit(|s| {
        s["props"]["ro.product.manufacturer"] = json!("Samsung");
        s["props"]["ro.product.model"] = json!("Galaxy TEST");
    });
    // Stock Android: verified boot state Verified with a key that is not GrapheneOS's.
    let mut kd = at::grapheneos_kd(at::CHALLENGE);
    kd.state = 0;
    kd.boot_key = vec![0x99; 32];
    let chain: Vec<String> = at::synthetic(&kd, false)
        .ders
        .iter()
        .map(|d| Base64::encode_string(d))
        .collect();
    fx.edit(|s| s["agent_chain"] = json!(chain));
    // Hardened tier refuses it.
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_REFUSED, "{}", r.out);
    assert!(r.out.contains("--normal-tier"), "{}", r.out);
    // Normal tier without a terminal is refused before anything is written.
    let mut a = fx.args.clone();
    a.normal_tier = true;
    a.orbot_apk = None;
    fx.clear_calls();
    let r = fx.deliver_with(&a, Err("no terminal on standard input".into()));
    assert_eq!(r.code, exit::DELIVERY_REFUSED);
    assert!(r.out.contains("typed confirmation"));
    assert!(!fx.calls().iter().any(|c| c.contains("install")));
    // Not confirmed: refused too.
    let r = fx.deliver_with(&a, Ok(false));
    assert_eq!(r.code, exit::DELIVERY_REFUSED);
    // Confirmed: delivered as normal-phone tier.
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r
        .out
        .contains("no hardened OS, no bootloader lock, no attestation, Google services present"));
    let recs = fx.records();
    let d = recs.last().unwrap();
    assert_eq!(d.tier, "normal-phone tier");
    assert_eq!(d.attestation, "not run (normal-phone tier)");
    fx.write_report_log("normal-android-phone");
}

#[test]
fn wrong_signer_and_unverified_without_flag() {
    let _g = one_at_a_time();
    let fx = Fx::new("signer");
    // A pinned messenger signer that the APK does not have.
    let mut fx2 = Fx::new("signer-pinned");
    fx2.cfg_text += &format!(
        "messenger_signing_cert_sha256 = \"{}\"\n",
        keys().other.digest_hex()
    );
    let r = fx2.deliver();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("not by the configured messenger signer"));
    // Not pinned and no --accept-unverified-messenger.
    let mut a = fx.args.clone();
    a.accept_unverified_messenger = false;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK);
    assert!(r.out.contains("--accept-unverified-messenger"));
    // Pinned and matching: verified, exit 0.
    let mut fx3 = Fx::new("signer-ok");
    fx3.cfg_text += &format!(
        "messenger_signing_cert_sha256 = \"{}\"\n",
        keys().messenger.digest_hex()
    );
    let mut a = fx3.args.clone();
    a.accept_unverified_messenger = false;
    let r = fx3.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(fx3.records()[0].messenger_verified);
    // The package manager records another certificate than the installed
    // base.apk: failure, never UNVERIFIED.
    let fx4 = Fx::new("signer-pm");
    fx4.edit(|s| {
        s["pm_signer_override"] = json!(format!(
            "{:x}",
            crate::apk::java_hash(&keys().other.cert_der)
        ))
    });
    let r = fx4.deliver();
    assert_eq!(r.code, exit::DELIVERY_CHECK, "{}", r.out);
    assert!(r.out.contains("differs from the APK file's"));
    assert_eq!(fx4.records()[0].result, "failed at step 14");
    // An Orbot APK signed by someone else.
    let fx5 = Fx::new("signer-orbot");
    let (bad_orbot, _) = write_apk(
        &fx5.dir,
        "orbot-other.apk",
        &Spec::new(ORBOT, 1),
        &keys().other,
    );
    let mut a = fx5.args.clone();
    a.orbot_apk = Some(bad_orbot);
    let r = fx5.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK);
    assert!(r.out.contains("not by the configured Orbot signer"));
    // A package name the config does not allow: a fixed messenger_package,
    // or a messenger_package_pattern. Refused before the phone is touched.
    let (wrong, _) = write_apk(
        &fx5.dir,
        "wrong.apk",
        &Spec::new("com.example.wrong", 1),
        &keys().messenger,
    );
    let mut a = fx5.args.clone();
    a.apk = wrong;
    for (extra, why) in [
        (
            format!(
                "messenger_package = \"{MESSENGER}\"
"
            ),
            "is not the configured messenger_package",
        ),
        (
            "messenger_package_pattern = \"org.example.*\"
"
            .to_string(),
            "does not match messenger_package_pattern",
        ),
    ] {
        let mut fx6 = Fx::new("signer-package");
        fx6.cfg_text += &extra;
        let before = fx6.calls().len();
        let r = fx6.deliver_with(&a, Ok(true));
        assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
        assert!(r.out.contains(why), "{}", r.out);
        assert_eq!(fx6.calls().len(), before, "nothing reached the phone");
    }
}

/// `uiautomator dump` fails while a screen changes (seen on the Pixel 6a):
/// the read is retried, and the dump file is removed every time.
#[test]
fn failed_screen_reads_are_retried_and_cleaned_up() {
    let _g = one_at_a_time();
    let fx = Fx::new("dumpfail");
    fx.edit(|s| s["orbot"]["dump_failures"] = json!(2));
    let r = fx.deliver();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("screen read failed, retrying"), "{}", r.out);
    let s = fx.state();
    assert_eq!(s["orbot"]["dump_failures"], json!(0));
    assert_eq!(s["orbot"]["connected"], json!(true));
    assert!(
        s["files"].as_object().is_none_or(|f| f.is_empty()),
        "UI dump left on the phone"
    );
    fx.write_report_log("screen-read-retry");
}

#[test]
fn orbot_element_missing_is_named() {
    let _g = one_at_a_time();
    let fx = Fx::new("orbotmissing");
    fx.edit(|s| s["orbot"]["missing"] = json!("Power User Mode"));
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(
        r.out.contains("element not found: Power User Mode"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 7");
    let s = fx.state();
    assert!(
        s["files"].as_object().is_none_or(|f| f.is_empty()),
        "UI dump left on the phone"
    );
    fx.write_report_log("orbot-element-missing");
}

#[test]
fn dry_run_writes_nothing_and_lists_the_commands() {
    let _g = one_at_a_time();
    let fx = Fx::new("dryrun");
    let before = fx.state();
    let mut a = fx.args.clone();
    a.dry_run = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(r.out.contains("DRY RUN"));
    let after = fx.state();
    assert_eq!(before["packages"], after["packages"]);
    assert_eq!(before["disabled"], after["disabled"]);
    assert_eq!(before["provider"], after["provider"]);
    assert!(fx.records().is_empty(), "the dry run stored something");
    assert!(r.shown.is_empty());
    // Only reads and the agent's own install and removal.
    for c in fx.calls() {
        let agent = c.contains("agent.apk") || c.contains(crate::names::DEFAULT_AGENT_PACKAGE);
        assert!(
            agent
                || !c.contains(" install ")
                    && !c.contains("disable-user")
                    && !c.contains("activate"),
            "{c}"
        );
    }
    // Every shell command of a real delivery appears in the plan.
    let fx2 = Fx::new("dryrun-real");
    assert_eq!(fx2.deliver().code, exit::UNVERIFIED);
    let plan: String = r.out.clone();
    for c in fx2.calls() {
        let Some(cmd) = c.strip_prefix("adb -s <serial> shell ") else {
            continue;
        };
        let first3: Vec<&str> = cmd.split(' ').take(3).collect();
        let key = first3.join(" ");
        let ui = [
            "uiautomator",
            "cat /data",
            "rm -f",
            "input ",
            "am instrument",
            "pm path dev.simplego",
            // Step 3 reads it, also in the dry run (read only).
            "dumpsys package providers",
        ];
        if ui.iter().any(|u| cmd.starts_with(u)) || cmd.starts_with("am start") {
            continue;
        }
        assert!(plan.contains(&key), "planned commands miss `{key}`\n{plan}");
    }
    fx.write_report_log("dry-run");
}

#[test]
fn undeliver_restores_a_test_phone() {
    let _g = one_at_a_time();
    let fx = Fx::new("undeliver");
    let initial = fx.state()["packages"].clone();
    assert_eq!(fx.deliver().code, exit::UNVERIFIED);
    let (c, out) = fx.undeliver(false);
    assert_eq!(c, exit::UNDELIVER);
    assert!(out.contains("--test-device"));
    fx.clear_calls();
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::OK, "{out}");
    let s = fx.state();
    assert_eq!(
        s["packages"], initial,
        "package list differs from before the delivery"
    );
    assert!(s["disabled"].as_array().is_none_or(|d| d.is_empty()));
    assert!(s["whitelist"].as_array().is_none_or(|w| w.is_empty()));
    assert_eq!(fx.records()[0].result, "undone");
    assert!(!out.contains(SERIAL));
    fx.write_report_log("undeliver");
    // Nothing left to undo.
    let (c, _) = fx.undeliver(true);
    assert_eq!(c, exit::UNDELIVER);
    // A customer's phone is refused.
    let fx = Fx::new("undeliver-customer");
    assert_eq!(fx.deliver().code, exit::UNVERIFIED);
    fx.edit(|s| s["provider"]["setup_done"] = json!(true));
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::UNDELIVER);
    assert!(out.contains("setup=done"));
    assert!(fx.state()["packages"][MESSENGER].is_object());
}

#[test]
fn handover_turns_usb_debugging_off() {
    let _g = one_at_a_time();
    let fx = Fx::new("handover");
    assert_eq!(fx.deliver().code, exit::UNVERIFIED);
    let (c, out) = fx.handover(Ok(false));
    assert_eq!(c, exit::HANDOVER);
    assert!(out.contains("not confirmed"));
    let (c, out) = fx.handover(Err("no terminal on standard input".into()));
    assert_eq!(c, exit::HANDOVER, "{out}");
    assert!(fx.state()["settings"]
        .as_object()
        .is_none_or(|s| s.is_empty()));
    fx.clear_calls();
    let (c, out) = fx.handover(Ok(true));
    assert_eq!(c, exit::OK, "{out}");
    assert!(out.contains("HANDED OVER"));
    assert_eq!(fx.state()["settings"]["adb_enabled"], json!("0"));
    assert!(fx.records()[0].handover_at.is_some());
    assert!(!out.contains(SERIAL));
    fx.write_report_log("handover");
    // Once handed over, the device is gone and a second handover is refused.
    let (c, _) = fx.handover(Ok(true));
    assert_eq!(c, exit::HANDOVER);
}

#[test]
fn key_rules_for_test_and_real_deliveries() {
    let _g = one_at_a_time();
    let fx = Fx::new("keys");
    // A real delivery refuses the TEST ONLY key.
    let mut a = fx.args.clone();
    a.test_delivery = false;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::SIGNING_KEY);
    assert!(r.out.contains("refusing the TEST ONLY signing key"));
    // A test delivery without the config switch is refused.
    let mut fx2 = Fx::new("keys-off");
    fx2.cfg_text = fx2
        .cfg_text
        .replace("allow_test_key_for_test_deliveries = true", "");
    let r = fx2.deliver();
    assert_eq!(r.code, exit::SIGNING_KEY);
    assert!(r.out.contains("allow_test_key_for_test_deliveries"));
    // A test delivery with a key that is not the TEST ONLY key is refused.
    let mut a = fx.args.clone();
    a.key = other_encrypted_key(&fx.dir);
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::SIGNING_KEY);
    assert!(
        r.out.contains("refused with a real signing key"),
        "{}",
        r.out
    );
    // Nothing reached the phone in any of these.
    assert!(fx.calls().is_empty() && fx2.calls().is_empty());
}

/// A passphrase-protected Ed25519 key that is not the TEST ONLY key, made in
/// memory for this test only (a throwaway, never a real signing key).
fn other_encrypted_key(dir: &Path) -> PathBuf {
    use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
    use ssh_key::public::Ed25519PublicKey;
    struct R(u8);
    impl ssh_key::rand_core::RngCore for R {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for b in d {
                self.0 = self.0.wrapping_mul(31).wrapping_add(7);
                *b = self.0;
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), ssh_key::rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl ssh_key::rand_core::CryptoRng for R {}
    let seed = [3u8; 32];
    let public = crate::activation::keys::Signer::from_seed(&seed)
        .unwrap()
        .public();
    let kp = Ed25519Keypair {
        public: Ed25519PublicKey(public),
        private: Ed25519PrivateKey::from_bytes(&seed),
    };
    let enc = ssh_key::PrivateKey::from(kp)
        .encrypt(&mut R(1), KEY_PASS)
        .unwrap();
    let p = dir.join("throwaway-not-test-key");
    std::fs::write(
        &p,
        enc.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    p
}

/// The GrapheneOS status lines (dry run included) and the age rule.
#[test]
fn os_status_lines_and_the_age_rule() {
    use crate::grapheneos::channel::{ChannelInfo, Lookup, Release};
    use crate::grapheneos::ReleaseSetting;
    let _g = one_at_a_time();
    let mk = |v: &str, t: u64, ch: &str| Lookup {
        name: "x".into(),
        url: "https://releases.grapheneos.org/x".into(),
        info: Some(ChannelInfo {
            version: v.into(),
            build_time: t,
            codename: "bluejay".into(),
            channel: ch.into(),
        }),
        absent: false,
        offline: false,
        fetched_at: Some(at::T_SYN),
        last_modified: None,
        error: None,
    };
    let rel = Release {
        stable: mk("2026111800", 1_794_968_526, "stable"),
        preview: mk("2026111801", 1_794_968_527, "stable-security-preview"),
    };
    let phone = |fx: &Fx, v: &str, t: u64| {
        fx.edit(|s| {
            s["props"]["ro.build.version.incremental"] = json!(v);
            s["props"]["ro.build.display.id"] = json!(v);
            s["props"]["ro.build.date.utc"] = json!(t.to_string());
        })
    };
    // A security preview phone: up to date, the build type named.
    let mut fx = Fx::new("os-preview");
    let r2 = rel.clone();
    fx.os_status = Some(Box::new(move |i| {
        os_status::evaluate(i, &r2, "stable", ReleaseSetting::Stable, at::T_SYN)
    }));
    phone(&fx, "2026111801", 1_794_968_527);
    let mut a = fx.args.clone();
    a.dry_run = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(
        r.out
            .contains("up to date (security preview, newer than stable)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("build type security preview"), "{}", r.out);
    // 40 days behind the stable channel: refused before any write ...
    let mut fx = Fx::new("os-old");
    let r2 = rel.clone();
    fx.os_status = Some(Box::new(move |i| {
        os_status::evaluate(i, &r2, "stable", ReleaseSetting::Newest, at::T_SYN)
    }));
    phone(&fx, "2026100900", 1_794_968_526 - 40 * 86_400);
    let r = fx.deliver();
    assert_eq!(r.code, exit::DELIVERY_REFUSED, "{}", r.out);
    assert!(
        r.out
            .contains("40 days behind the stable channel (max_os_age_days 30)"),
        "{}",
        r.out
    );
    assert!(fx.calls().iter().all(|c| !c.contains("messenger.apk")));
    assert_eq!(fx.records()[0].result, "failed at step 2");
    // ... unless --allow-outdated-os.
    let mut a = fx.args.clone();
    a.allow_outdated_os = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(
        r.out.contains("delivered anyway (--allow-outdated-os)"),
        "{}",
        r.out
    );
    let rec = fx.records().pop().unwrap();
    assert!(
        rec.os_status.as_deref().unwrap().starts_with(
            "2026100900 not in the current channel files: update available (40 days behind)"
        ),
        "{:?}",
        rec.os_status
    );
}

// ---- the normal SimpleX app ----------------------------------------------

impl Fx {
    fn simplex_args(&self) -> DeliverArgs {
        let mut a = self.args.clone();
        a.fdroid_apk = Some(self.fdroid_apk.clone());
        a
    }

    fn deliver_simplex(&self) -> Run {
        self.deliver_with(&self.simplex_args(), Ok(true))
    }
}

fn pos(calls: &[String], needle: &str) -> usize {
    calls
        .iter()
        .position(|c| c.contains(needle))
        .unwrap_or_else(|| panic!("no call {needle:?} in {calls:#?}"))
}

#[test]
fn slow_repository_fetch_succeeds_after_the_intent_is_sent_again() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-slow-fetch");
    // The first intent's fetch never ends (Tor stalled); after the re-send
    // the repository shows, and adding it takes another 100 screen reads.
    fx.edit(|s| {
        s["fd"]["hang_intents"] = json!(1);
        s["fd"]["add_left"] = json!(100);
    });
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("DELIVERED"), "{}", r.out);
    assert!(
        r.out
            .contains("not shown after 240 s: the repository intent is sent again (once)"),
        "{}",
        r.out
    );
    let intents = fx
        .calls()
        .iter()
        .filter(|c| c.contains("android.intent.action.VIEW -d"))
        .count();
    assert_eq!(intents, 2, "{:?}", fx.calls());
    // A line every 30 s with the time left (600 s by default).
    let waits: Vec<&str> = r
        .out
        .lines()
        .filter(|l| l.contains("waiting for SimpleX's repository in the F-Droid client"))
        .collect();
    assert!(waits.len() >= 10, "{}", r.out);
    assert!(waits[0].ends_with("9m30s left"), "{}", waits[0]);
    assert!(
        fx.records()[0]
            .simplex_repo
            .as_ref()
            .unwrap()
            .added_to_client
    );
}

#[test]
fn no_repository_fails_at_the_limit_with_a_clear_message() {
    let _g = one_at_a_time();
    let mut fx = Fx::new("simplex-no-repo");
    fx.cfg_text += "fdroid_repo_wait_secs = 300\n";
    fx.edit(|s| s["fd"]["hang_intents"] = json!(99));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(
        r.out.contains("was not shown in the F-Droid client within 300 s (fdroid_repo_wait_secs; the repository intent was sent 2 time(s)"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 11");
    // Nothing of the activation happened.
    assert!(fx.calls().iter().all(|c| !c.contains("--method activate")));
    assert!(r.shown.is_empty());
}

#[test]
fn simplex_app_delivery_in_the_decided_order() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex");
    // The first fetch of the repository fails, as once on the 6a.
    fx.edit(|s| s["fd"]["fetch_errors"] = json!(1));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("DELIVERED"), "{}", r.out);
    assert_clean_log(&fx, &r);
    let s = fx.state();
    // Both apps installed, the SimpleX app with the F-Droid client as its
    // installer of record, never started; battery exceptions.
    assert_eq!(s["packages"][SIMPLEX]["installer"], json!(FDROID));
    assert_eq!(s["packages"][SIMPLEX]["launched"], json!(false));
    assert_eq!(s["packages"][FDROID]["launched"], json!(true));
    let wl = s["whitelist"].as_array().unwrap();
    assert!(wl.contains(&json!(SIMPLEX)) && wl.contains(&json!(FDROID)));
    // Orbot: VPN mode (Power User Mode off), exactly the four apps, the
    // consent as an app op, connected, SOCKS 9050, lockdown on.
    assert_eq!(s["orbot"]["power"], json!(false));
    let mut apps: Vec<String> = serde_json::from_value(s["orbot"]["apps"].clone()).unwrap();
    apps.sort();
    let mut want = vec![SIMPLEX, FDROID, UPDATER, APPSTORE];
    want.sort();
    assert_eq!(apps, want);
    assert_eq!(s["orbot"]["port"], json!("9050"));
    assert_eq!(s["orbot"]["connected"], json!(true));
    assert!(s["appops"]
        .as_array()
        .unwrap()
        .contains(&json!(format!("{ORBOT}:ACTIVATE_VPN"))));
    assert_eq!(s["settings"]["secure:always_on_vpn_app"], json!(ORBOT));
    assert_eq!(s["settings"]["secure:always_on_vpn_lockdown"], json!("1"));
    // The F-Droid client: proxy to Orbot, SimpleX's repository added with
    // the pinned fingerprint.
    assert_eq!(s["fd"]["proxy"], json!("127.0.0.1:9050"));
    assert_eq!(s["fd"]["repos"], json!([REPO]));
    assert!(s["fd"]["intent_uri"].as_str().unwrap().ends_with(&format!(
        "?fingerprint={}",
        testrepo::fingerprint().to_uppercase()
    )));
    assert!(s["files"].as_object().is_none_or(|f| f.is_empty()));
    // The order: the verifier off, Orbot, the network lock
    // (consent before Orbot starts, lockdown proven), only then the
    // messenger, the F-Droid client and the SimpleX app, then the two apps
    // added to Orbot's VPN, then the F-Droid client's first start; the
    // SimpleX app never started.
    let c = fx.calls();
    let verifier_off = pos(&c, "pm disable-user --user 0 com.android.statementservice");
    let orbot_install = pos(&c, "orbot.apk");
    let consent = pos(&c, "appops set org.torproject.android ACTIVATE_VPN allow");
    let orbot_launch = pos(&c, "am start -n org.torproject.android/");
    let lockdown = pos(&c, "android.settings.VPN_SETTINGS");
    let proof = pos(&c, "dumpsys vpn_management");
    let messenger = pos(&c, "messenger.apk");
    let fd_install = pos(&c, "F-Droid.apk");
    let sx_install = pos(&c, &format!("install -i {FDROID}"));
    let orbot_again = c
        .iter()
        .rposition(|x| x.contains("am start -n org.torproject.android/"))
        .unwrap();
    let fd_first = pos(&c, "am start -n org.fdroid.fdroid/");
    let repo = pos(&c, "android.intent.action.VIEW");
    let order = [
        verifier_off,
        orbot_install,
        consent,
        orbot_launch,
        lockdown,
        proof,
        messenger,
        fd_install,
        sx_install,
        orbot_again,
        fd_first,
        repo,
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}\n{c:#?}");
    // No install of any app but Orbot before the lock was proven.
    assert!(c[..proof]
        .iter()
        .filter(|x| x.contains(" install "))
        .all(|x| x.contains("orbot.apk") || x.contains("agent.apk")));
    // App link verification: the verifier disabled, no host verified, no
    // socket, the record names the hosts and their states.
    assert!(s["disabled"].as_array().unwrap().contains(&json!(VERIFIER)));
    assert!(
        s["app_links_verified"]
            .as_object()
            .is_none_or(|m| m.is_empty()),
        "{}",
        s["app_links_verified"]
    );
    let al = fx.records()[0].app_links.clone().unwrap();
    assert!(al.disabled_by_delivery && !al.found_disabled && al.checked);
    assert_eq!(al.verifier.as_deref(), Some(VERIFIER));
    assert_eq!(al.hosts.len(), 2, "{:?}", al.hosts);
    assert_eq!(al.states.len(), 4);
    assert!(
        al.states.iter().all(|(_, _, st)| st == "none"),
        "{:?}",
        al.states
    );
    assert_eq!(al.verifier_sockets_outside, 0);
    assert!(al
        .verifier_network
        .as_deref()
        .unwrap()
        .contains("REASON_LOCKDOWN_VPN"));
    let lk = fx.records()[0].lock.clone().unwrap();
    assert!(lk.proven && lk.proven_after_apps);
    assert_eq!(lk.provider, ORBOT);
    assert_eq!(lk.apps_at_lock, [UPDATER, APPSTORE]);
    assert!(lk
        .mode_line
        .unwrap()
        .contains("lockdown=true alwaysOn=true"));
    assert!(r.out.contains("NETWORK LOCK PROVEN"), "{}", r.out);
    assert!(!c
        .iter()
        .any(|x| x.contains(&format!("am start -n {SIMPLEX}"))));
    // Only the repository host was asked over "Tor".
    assert!(fx
        .http
        .urls()
        .iter()
        .all(|u| u.starts_with(&format!("GET {REPO}/"))));
    // The fleet record.
    let d = &fx.records()[0];
    let fr = d.fdroid.as_ref().unwrap();
    assert_eq!(
        (fr.version_code, fr.installer.as_deref()),
        (2_000_053, None)
    );
    assert_eq!(fr.signer_sha256, keys().fdroid.digest_hex());
    let sr = d.simplex_app.as_ref().unwrap();
    assert_eq!(sr.version_code, 397);
    assert_eq!(sr.signer_sha256, keys().simplex.digest_hex());
    assert_eq!(sr.installer.as_deref(), Some(FDROID));
    assert!(sr.installed_by_delivery);
    let rp = d.simplex_repo.as_ref().unwrap();
    assert!(rp.added_to_client);
    assert_eq!(rp.index_timestamp_ms, 1_794_696_615_000);
    let v = d.vpn.as_ref().unwrap();
    assert!(v.consent && v.always_on && v.lockdown && v.fdroid_socks_proxy);
    assert_eq!(v.apps.len(), 4);
    assert_eq!(v.found_always_on_app, None);
    assert!(r.out.contains("Orbot's VPN carries exactly"), "{}", r.out);
    assert!(r.out.contains("never started"), "{}", r.out);
    assert!(
        r.out
            .contains("could not fetch the repository (try 1 of 3)"),
        "{}",
        r.out
    );
    assert_eq!(
        c.iter()
            .filter(|x| x.contains("android.intent.action.VIEW"))
            .count(),
        2
    );
    fx.write_report_log("simplex-delivery");
}

#[test]
fn simplex_delivery_json_events() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-json");
    let mut a = fx.simplex_args();
    a.json = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    let ev: Vec<Value> = r
        .out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect();
    let steps: Vec<u64> = ev
        .iter()
        .filter(|e| e["event"] == "step")
        .map(|e| e["step"].as_u64().unwrap())
        .collect();
    assert_eq!(steps, (1..=14).collect::<Vec<u64>>());
    // The network lock first in the console's stepper ("Orbot"), then the
    // SimpleX app.
    for (n, c) in [
        (6u64, "Orbot"),
        (7, "Orbot"),
        (9, "SimpleX app"),
        (10, "SimpleX app"),
        (11, "SimpleX app"),
    ] {
        assert!(
            ev.iter()
                .any(|e| e["event"] == "step" && e["step"] == n && e["console_step"] == c),
            "step {n} {c}"
        );
    }
    let first_console = ev
        .iter()
        .find(|e| e["event"] == "step" && e["console_step"].is_string())
        .unwrap();
    assert_eq!(first_console["console_step"], "Orbot");
    let lock = ev.iter().find(|e| e["event"] == "network_lock").unwrap();
    assert_eq!(lock["provider"], "Orbot");
    assert_eq!(lock["apps"], json!([UPDATER, APPSTORE]));
    assert!(lock["mode_line"]
        .as_str()
        .unwrap()
        .contains("lockdown=true alwaysOn=true"));
    assert!(ev
        .iter()
        .any(|e| e["event"] == "app_links" && e["disabled"] == true && e["states"].is_array()));
    assert!(ev
        .iter()
        .any(|e| e["event"] == "simplex_index" && e["version_code"] == 397));
    assert!(ev
        .iter()
        .any(|e| e["event"] == "vpn" && e["lockdown"] == true));
    assert!(ev.iter().any(|e| e["event"] == "delivered"));
    assert!(ev
        .iter()
        .any(|e| e["event"] == "record" && e["result"] == "delivered"));
    assert!(!r.out.contains(SERIAL));
}

#[test]
fn simplex_wrong_signers_are_refused() {
    let _g = one_at_a_time();
    // The F-Droid client APK signed by someone else.
    let fx = Fx::new("simplex-fdroid-signer");
    let mut fs = Spec::new(FDROID, 2_000_053);
    fs.filler = b"fdroid client".to_vec();
    let (bad, _) = write_apk(&fx.dir, "F-Droid-other.apk", &fs, &keys().other);
    let mut a = fx.simplex_args();
    a.fdroid_apk = Some(bad);
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(
        r.out.contains("WRONG SIGNER: the F-Droid client APK"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 4");
    assert!(
        fx.state()["packages"][MESSENGER].is_null(),
        "nothing installed"
    );
    // The SimpleX APK in the repository signed by someone else, while the
    // index claims the pinned signer: our APK reader refuses it.
    let fx = Fx::new("simplex-app-signer");
    let mut ss = Spec::new(SIMPLEX, 397);
    ss.filler = b"simplex app".to_vec();
    let other = testapk::build(&ss, &keys().other);
    put_repo(
        &fx.http,
        &other,
        &keys().simplex.digest_hex(),
        1_794_696_615_000,
    );
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("WRONG SIGNER: the SimpleX APK"), "{}", r.out);
    assert!(fx.state()["packages"][MESSENGER].is_null());
    // The index names another signer only: no release to install.
    let fx = Fx::new("simplex-index-signer");
    put_repo(
        &fx.http,
        &fx.simplex_apk,
        &keys().other.digest_hex(),
        1_794_696_615_000,
    );
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("signed by the pinned signer"), "{}", r.out);
}

#[test]
fn simplex_repository_fingerprint_and_index_signature() {
    let _g = one_at_a_time();
    // Pinned to SimpleX's real fingerprint: the test repository is refused.
    let mut fx = Fx::new("simplex-fingerprint");
    fx.cfg_text = fx
        .cfg_text
        .replace(&testrepo::fingerprint(), testrepo::REAL_FINGERPRINT);
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(
        r.out.contains("REPOSITORY FINGERPRINT MISMATCH"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 4");
    // The index changed after it was signed.
    let fx = Fx::new("simplex-index-broken");
    let url = format!("{REPO}/index-v2.json");
    let mut idx = fx.http.files.borrow()[&url].clone();
    let n = idx.len();
    idx[n - 2] = b' ';
    fx.http.put(&url, &idx);
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("INDEX SIGNATURE BROKEN"), "{}", r.out);
    // An older index than the last delivery saw.
    let fx = Fx::new("simplex-rollback");
    assert_eq!(fx.deliver_simplex().code, exit::UNVERIFIED);
    assert_eq!(fx.undeliver(true).0, exit::OK);
    put_repo(
        &fx.http,
        &fx.simplex_apk,
        &keys().simplex.digest_hex(),
        1_794_000_000_000,
    );
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("INDEX ROLLBACK"), "{}", r.out);
    // Offline: refused before anything is written.
    let fx = Fx::new("simplex-offline");
    *fx.http.down.borrow_mut() = true;
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(fx.state()["packages"][MESSENGER].is_null());
}

#[test]
fn simplex_vpn_app_list_wrong() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-vpn-list");
    // The VPN carries Vanadium too (a list Orbot saved wrongly).
    fx.edit(|s| s["orbot"]["vpn_extra_uids"] = json!([10053]));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(r.out.contains("VPN APP LIST WRONG"), "{}", r.out);
    assert!(r.out.contains("app.vanadium.browser"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 7");
    // Lockdown is not switched on with a wrong list, and nothing but Orbot
    // was installed.
    let s = fx.state();
    assert!(s["settings"]["secure:always_on_vpn_lockdown"].is_null());
    assert!(s["packages"][MESSENGER].is_null() && s["packages"][SIMPLEX].is_null());
    // A check box that does not take.
    let fx = Fx::new("simplex-vpn-stuck");
    fx.edit(|s| s["fail"]["orbot_app_stuck:app.grapheneos.apps"] = json!("x"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(r.out.contains("App Store is not checked"), "{}", r.out);
    // An app already on the list that must not be: unchecked.
    let fx = Fx::new("simplex-vpn-extra");
    fx.edit(|s| s["orbot"]["apps"] = json!(["app.vanadium.browser"]));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    let apps = fx.state()["orbot"]["apps"].clone();
    assert!(!apps
        .as_array()
        .unwrap()
        .contains(&json!("app.vanadium.browser")));
}

#[test]
fn simplex_vpn_consent_not_granted() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-consent");
    fx.edit(|s| s["fail"]["appops:ACTIVATE_VPN"] = json!("refused"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(r.out.contains("VPN CONSENT NOT GRANTED"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 7");
    let s = fx.state();
    assert_eq!(s["orbot"]["connected"], json!(false));
    // Nothing but Orbot was installed.
    assert!(s["packages"][FDROID].is_null() && s["packages"][MESSENGER].is_null());
    assert!(s["files"].as_object().is_none_or(|f| f.is_empty()));
}

#[test]
fn simplex_socks_port_closed_in_vpn_mode() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-socks");
    fx.edit(|s| s["fail"]["socks_closed_in_vpn"] = json!("x"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(r.out.contains("SOCKS PORT CLOSED"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 7");
    assert!(fx.state()["settings"]["secure:always_on_vpn_app"].is_null());
}

#[test]
fn simplex_refusals_before_anything_is_written() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-refuse");
    // Without Orbot.
    let mut a = fx.simplex_args();
    a.orbot_apk = None;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("needs --orbot-apk"), "{}", r.out);
    // The normal tier.
    let mut a = fx.simplex_args();
    a.normal_tier = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    // No pin for the F-Droid client.
    let mut fx2 = Fx::new("simplex-nopin");
    fx2.cfg_text = fx2.cfg_text.replace(
        &format!(
            "fdroid_signing_cert_sha256 = \"{}\"",
            keys().fdroid.digest_hex()
        ),
        "fdroid_signing_cert_sha256 = \"\"",
    );
    let r = fx2.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(
        r.out.contains("fdroid_signing_cert_sha256 is not set"),
        "{}",
        r.out
    );
    // A SimpleX app already on the phone (a customer's own) is never touched.
    let fx3 = Fx::new("simplex-present");
    fx3.edit(|s| {
        s["packages"][SIMPLEX] = json!({"version_code": 390, "version_name": "7.1-beta.10", "signer": "aa", "uid": 10199, "label": "SimpleX", "launched": true})
    });
    let r = fx3.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_REFUSED, "{}", r.out);
    assert!(r.out.contains("it is never replaced"), "{}", r.out);
    assert_eq!(fx3.state()["packages"][SIMPLEX]["version_code"], json!(390));
    assert_eq!(fx3.records()[0].result, "failed at step 4");
    // Refused before anything was written: not even the verifier changed.
    assert!(fx3.state()["disabled"]
        .as_array()
        .is_none_or(|d| d.is_empty()));
}

#[test]
fn simplex_dry_run_reads_the_index_only() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-dry");
    let before = fx.state();
    let mut a = fx.simplex_args();
    a.dry_run = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(
        r.out.contains("SimpleX app 7.1.4 (versionCode 397"),
        "{}",
        r.out
    );
    assert!(r.out.contains("step 11 (F-Droid client"), "{}", r.out);
    assert!(r.out.contains("step 7 (the network lock"), "{}", r.out);
    let after = fx.state();
    assert_eq!(before["packages"], after["packages"]);
    assert_eq!(before["settings"], after["settings"]);
    assert!(fx.records().is_empty());
    // The index, not the APK.
    assert!(!fx.http.urls().iter().any(|u| u.contains(".apk")));
    // Every shell command of a real SimpleX delivery appears in the plan.
    let fx2 = Fx::new("simplex-dry-real");
    assert_eq!(fx2.deliver_simplex().code, exit::UNVERIFIED);
    for c in fx2.calls() {
        let Some(cmd) = c.strip_prefix("adb -s <serial> shell ") else {
            continue;
        };
        let key: String = cmd.split(' ').take(3).collect::<Vec<_>>().join(" ");
        let ui = [
            "uiautomator",
            "cat /data",
            "rm -f",
            "input ",
            "am instrument",
            "pm path dev.simplego",
            // Step 3 reads it, also in the dry run (read only).
            "dumpsys package providers",
            "am start",
        ];
        if ui.iter().any(|u| cmd.starts_with(u)) {
            continue;
        }
        assert!(
            r.out.contains(&key),
            "planned commands miss `{key}`\n{}",
            r.out
        );
    }
}

#[test]
fn simplex_undeliver_restores_the_phone() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-undeliver");
    let initial = fx.state();
    assert_eq!(fx.deliver_simplex().code, exit::UNVERIFIED);
    fx.clear_calls();
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::OK, "{out}");
    let s = fx.state();
    assert_eq!(s["packages"], initial["packages"], "{out}");
    assert!(s["settings"]["secure:always_on_vpn_app"].is_null(), "{out}");
    assert!(
        s["settings"]["secure:always_on_vpn_lockdown"].is_null()
            || s["settings"]["secure:always_on_vpn_lockdown"] == json!("0")
    );
    assert!(s["whitelist"].as_array().is_none_or(|w| w.is_empty()));
    assert!(out.contains("chat.simplex.app uninstalled"), "{out}");
    assert!(out.contains("always-on VPN and lockdown as found"), "{out}");
    // The apps with app link hosts go while lockdown is still on, then
    // lockdown off, then Orbot; the verifier is enabled again last.
    let c = fx.calls();
    let order = [
        pos(&c, "content call"),
        pos(&c, "uninstall chat.simplex.app"),
        pos(&c, "uninstall org.fdroid.fdroid"),
        pos(&c, "android.settings.VPN_SETTINGS"),
        pos(&c, "uninstall org.example.messenger"),
        pos(&c, "uninstall org.torproject.android"),
        pos(&c, "pm enable --user 0 com.android.calculator2"),
        pos(&c, "pm enable --user 0 com.android.statementservice"),
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}\n{c:#?}");
    assert!(
        out.contains("com.android.statementservice enabled again"),
        "{out}"
    );
    assert!(
        out.contains("only after the next reboot of the phone"),
        "{out}"
    );
    assert!(s["disabled"].as_array().is_none_or(|d| d.is_empty()));
    assert!(s["app_links_verified"]
        .as_object()
        .is_none_or(|m| m.is_empty()));
    assert_eq!(fx.records()[0].result, "undone");
    fx.write_report_log("simplex-undeliver");
}

#[test]
fn simplex_undeliver_keeps_an_orbot_that_was_there() {
    let _g = one_at_a_time();
    let fx = Fx::new("simplex-orbot-kept");
    // Orbot on the phone before, set up for SOCKS only, with
    // its consent once refused.
    fx.edit(|s| {
        s["packages"][ORBOT] = json!({"version_code": 1_700_200, "version_name": "1.0-test", "signer": keys().orbot.digest_hex(), "uid": 10173, "label": "Orbot"});
        s["orbot"] = json!({"screen": "", "boot": true, "open_proxy": false, "power": true, "port": "9050", "field": "", "connected": true, "apps": []});
        s["appop_modes"] = json!({"org.torproject.android:ACTIVATE_VPN": "ignore"});
    });
    let mut a = fx.simplex_args();
    a.reinstall = true;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    let o = fx.records()[0].orbot.clone().unwrap();
    assert!(!o.installed_by_delivery);
    assert!(
        o.found_switches
            .contains(&("Power User Mode".to_string(), true)),
        "{:?}",
        o.found_switches
    );
    assert_eq!(
        fx.records()[0]
            .vpn
            .as_ref()
            .unwrap()
            .found_activate_vpn
            .as_deref(),
        Some("ignore")
    );
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::OK, "{out}");
    let s = fx.state();
    assert!(s["packages"][ORBOT].is_object(), "Orbot kept");
    assert_eq!(s["orbot"]["power"], json!(true), "{out}");
    assert_eq!(s["orbot"]["apps"], json!([]), "{out}");
    assert_eq!(
        s["appop_modes"]["org.torproject.android:ACTIVATE_VPN"],
        json!("ignore")
    );
    assert!(s["settings"]["secure:always_on_vpn_app"].is_null());
    assert!(s["packages"][SIMPLEX].is_null() && s["packages"][FDROID].is_null());
}

// ---- the network lock before any install ---------------------------------

#[test]
fn lock_not_active_stops_before_any_other_install() {
    let _g = one_at_a_time();
    let fx = Fx::new("lock-not-active");
    // Settings store "block connections without VPN", the run time does not.
    fx.edit(|s| s["fail"]["lockdown_no_runtime"] = json!("x"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(r.out.contains("LOCKDOWN NOT ACTIVE"), "{}", r.out);
    assert!(r.out.contains("nothing else was installed"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 7");
    let s = fx.state();
    for p in [MESSENGER, FDROID, SIMPLEX] {
        assert!(s["packages"][p].is_null(), "{p} installed without the lock");
    }
    assert!(s["packages"][ORBOT].is_object());
    assert!(!fx.calls().iter().any(|c| c.contains("messenger.apk")
        || c.contains("F-Droid.apk")
        || c.contains(&format!("install -i {FDROID}"))));
    fx.write_report_log("lock-not-active");
}

#[test]
fn app_list_change_that_drops_lockdown_is_caught() {
    let _g = one_at_a_time();
    let fx = Fx::new("lock-dropped");
    fx.edit(|s| s["fail"]["lockdown_drop_on_app_change"] = json!("x"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(
        r.out.contains("LOCKDOWN NOT ACTIVE") || r.out.contains("LOCKDOWN CHANGED"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 10");
    // The F-Droid client was never started.
    assert_eq!(fx.state()["packages"][FDROID]["launched"], json!(false));
    let d = &fx.records()[0];
    assert!(d
        .lock
        .as_ref()
        .is_some_and(|l| l.proven && !l.proven_after_apps));
    fx.write_report_log("lock-dropped-on-app-change");
}

#[test]
fn simplex_app_with_a_verified_host_fails_the_final_check() {
    let _g = one_at_a_time();
    let fx = Fx::new("applink-verified");
    // The phone shows a host as verified (a fetch went out).
    fx.edit(|s| s["app_links_verified"] = json!({SIMPLEX: ["smp4.simplex.im"]}));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_CHECK, "{}", r.out);
    assert!(
        r.out
            .contains("APP LINK VERIFIED: chat.simplex.app smp4.simplex.im verified"),
        "{}",
        r.out
    );
    let d = &fx.records()[0];
    assert_eq!(d.result, "failed at step 14");
    let al = d.app_links.as_ref().unwrap();
    assert!(
        al.states
            .contains(&(SIMPLEX.into(), "smp4.simplex.im".into(), "verified".into())),
        "{:?}",
        al.states
    );
    fx.write_report_log("applink-verified");
}

#[test]
fn verifier_socket_outside_loopback_fails_the_final_check() {
    let _g = one_at_a_time();
    let fx = Fx::new("applink-socket");
    fx.edit(|s| s["fail"]["verifier_socket"] = json!("x"));
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_CHECK, "{}", r.out);
    assert!(
        r.out
            .contains("com.android.statementservice has 1 TCP socket(s) outside loopback"),
        "{}",
        r.out
    );
    let d = &fx.records()[0];
    assert_eq!(d.result, "failed at step 14");
    assert_eq!(d.app_links.as_ref().unwrap().verifier_sockets_outside, 1);
}

#[test]
fn verifier_disable_refused_stops_before_any_install() {
    let _g = one_at_a_time();
    let fx = Fx::new("applink-refused");
    fx.edit(|s| {
        s["fail"]["disable:com.android.statementservice"] =
            json!("Error: java.lang.IllegalArgumentException: Cannot disable a protected package")
    });
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::DELIVERY_FAILED, "{}", r.out);
    assert!(
        r.out.contains("refused to disable the app link verifier"),
        "{}",
        r.out
    );
    assert_eq!(fx.records()[0].result, "failed at step 5");
    let s = fx.state();
    assert!(s["packages"][ORBOT].is_null() && s["packages"][MESSENGER].is_null());
    // No verifier on the phone: noted, the delivery goes on.
    let fx = Fx::new("applink-none");
    fx.edit(|s| {
        s["packages"].as_object_mut().unwrap().remove(VERIFIER);
    });
    let r = fx.deliver_simplex();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(r.out.contains("is not on this phone"), "{}", r.out);
    assert_eq!(fx.records()[0].app_links.as_ref().unwrap().verifier, None);
    // Already disabled before: left as found by undeliver.
    let fx = Fx::new("applink-found-off");
    fx.edit(|s| s["disabled"] = json!([VERIFIER]));
    assert_eq!(fx.deliver_simplex().code, exit::UNVERIFIED);
    assert!(fx.records()[0].app_links.as_ref().unwrap().found_disabled);
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::OK, "{out}");
    assert!(fx.state()["disabled"]
        .as_array()
        .unwrap()
        .contains(&json!(VERIFIER)));
}

#[test]
fn app_link_hosts_without_a_lock_and_on_the_lock_provider_are_refused() {
    let _g = one_at_a_time();
    // A messenger APK with autoVerify hosts in a delivery without the lock
    // (SOCKS only): refused before anything is written.
    let fx = Fx::new("applink-nolock");
    let mut ms = Spec::new(MESSENGER, 2157);
    ms.link_hosts = vec!["example.org"];
    let (m, _) = write_apk(&fx.dir, "messenger-links.apk", &ms, &keys().messenger);
    let mut a = fx.args.clone();
    a.apk = m;
    let r = fx.deliver_with(&a, Ok(true));
    assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
    assert!(r.out.contains("has no network lock"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 4");
    // The lock provider with an autoVerify host, or a reference host.
    for (tag, hosts, reference) in [
        ("host", vec!["orbot.example"], false),
        ("ref", vec![], true),
    ] {
        let fx = Fx::new(&format!("applink-provider-{tag}"));
        let mut os = Spec::new(ORBOT, 1_700_200);
        os.filler = b"orbot".to_vec();
        os.link_hosts = hosts;
        os.link_host_ref = reference;
        let (o, _) = write_apk(&fx.dir, "orbot-links.apk", &os, &keys().orbot);
        let mut a = fx.simplex_args();
        a.orbot_apk = Some(o);
        let r = fx.deliver_with(&a, Ok(true));
        assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
        assert!(
            r.out.contains("the network lock provider Orbot declares"),
            "{}",
            r.out
        );
        assert!(fx.state()["packages"][ORBOT].is_null());
    }
}

// ---- undeliver --discard-test-setup --------------------------------------

fn discard() -> undo::UndoOpts {
    undo::UndoOpts {
        test_device: true,
        discard_test_setup: true,
        json: false,
    }
}

#[test]
fn discard_test_setup_undoes_a_set_up_test_phone() {
    let _g = one_at_a_time();
    let fx = Fx::new("discard");
    let initial = fx.state();
    assert_eq!(fx.deliver_simplex().code, exit::UNVERIFIED);
    // The messenger was set up on the phone (a test profile).
    fx.edit(|s| s["provider"]["setup_done"] = json!(true));
    // Without the flag: refused as before, and nothing changed.
    fx.clear_calls();
    let before = fx.state();
    let (c, out) = fx.undeliver(true);
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(out.contains("setup=done"), "{out}");
    assert_eq!(fx.state()["packages"], before["packages"]);
    assert_eq!(fx.state()["settings"], before["settings"]);
    assert!(!fx
        .calls()
        .iter()
        .any(|c| c.contains("uninstall") || c.contains("VPN_SETTINGS") || c.contains("pm enable")));
    // With it: undone, and the output says which app data goes.
    let (c, out) = fx.undeliver_with(discard());
    assert_eq!(c, exit::OK, "{out}");
    assert!(out.contains("--discard-test-setup"), "{out}");
    assert!(
        out.contains("the messenger's profile on the phone"),
        "{out}"
    );
    let s = fx.state();
    assert_eq!(s["packages"], initial["packages"], "{out}");
    assert!(s["settings"]["secure:always_on_vpn_app"].is_null());
    assert!(s["disabled"].as_array().is_none_or(|d| d.is_empty()));
    assert_eq!(fx.records()[0].result, "undone");
    // The note comes before anything is removed.
    let at = out.find("--discard-test-setup").unwrap();
    assert!(at < out.find("uninstalled").unwrap(), "{out}");
    fx.write_report_log("undeliver-discard-test-setup");
}

#[test]
fn discard_test_setup_refusals() {
    let _g = one_at_a_time();
    let fx = Fx::new("discard-refuse");
    assert_eq!(fx.deliver_simplex().code, exit::UNVERIFIED);
    fx.edit(|s| s["provider"]["setup_done"] = json!(true));
    let before = fx.state();
    // Without --test-device.
    let (c, out) = fx.undeliver_with(undo::UndoOpts {
        test_device: false,
        discard_test_setup: true,
        json: false,
    });
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(
        out.contains("--discard-test-setup is refused without --test-device"),
        "{out}"
    );
    // Without a test config.
    let mut fx2 = Fx::new("discard-config");
    assert_eq!(fx2.deliver_simplex().code, exit::UNVERIFIED);
    fx2.edit(|s| s["provider"]["setup_done"] = json!(true));
    fx2.cfg_text = fx2.cfg_text.replace(
        "allow_test_key_for_test_deliveries = true",
        "allow_test_key_for_test_deliveries = false",
    );
    let (c, out) = fx2.undeliver_with(discard());
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(out.contains("throwaway test config"), "{out}");
    // A store that holds a real delivery record: not a test store.
    let path = fx.dir.join("store/admin.sxdb");
    let mut st = open_test_store(&path);
    let mut real = st.data.deliveries[0].clone();
    real.delivery_id = "ff".repeat(16);
    real.serial = "REALPHONE0001".into();
    real.test = false;
    st.data.deliveries.insert(0, real);
    st.save(&mut SeededRand::new(b"discard-real")).unwrap();
    drop(st);
    let (c, out) = fx.undeliver_with(discard());
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(out.contains("only for a throwaway test store"), "{out}");
    // The record itself is not a test delivery.
    let mut st = open_test_store(&path);
    st.data.deliveries.remove(0);
    let last = st.data.deliveries.len() - 1;
    st.data.deliveries[last].test = false;
    st.save(&mut SeededRand::new(b"discard-real2")).unwrap();
    drop(st);
    let (c, out) = fx.undeliver_with(discard());
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(out.contains("is not a test delivery"), "{out}");
    // An issue signed with another key in the store.
    let mut st = open_test_store(&path);
    let last = st.data.deliveries.len() - 1;
    st.data.deliveries[last].test = true;
    st.data.issues[0].key_id = "00".repeat(16);
    st.save(&mut SeededRand::new(b"discard-real3")).unwrap();
    drop(st);
    let (c, out) = fx.undeliver_with(discard());
    assert_eq!(c, exit::UNDELIVER, "{out}");
    assert!(out.contains("signed with a real key"), "{out}");
    // Nothing on the phone changed by any of the refusals.
    let after = fx.state();
    assert_eq!(after["packages"], before["packages"]);
    assert_eq!(after["settings"], before["settings"]);
    assert_eq!(after["disabled"], before["disabled"]);
}

#[test]
fn agent_with_app_link_hosts_is_refused_before_the_phone_is_touched() {
    let _g = one_at_a_time();
    // The agent is installed in step 2, before the network lock.
    for (tag, hosts, reference) in [
        ("host", vec!["agent.example"], false),
        ("ref", vec![], true),
    ] {
        let mut fx = Fx::new(&format!("agent-links-{tag}"));
        let mut s = Spec::new(crate::names::DEFAULT_AGENT_PACKAGE, 1);
        s.link_hosts = hosts;
        s.link_host_ref = reference;
        let (bad, _) = write_apk(&fx.dir, "agent-links.apk", &s, &keys().other);
        let good = fx.dir.join("agent.apk");
        fx.cfg_text = fx
            .cfg_text
            .replace(&good.display().to_string(), &bad.display().to_string());
        let r = fx.deliver_simplex();
        assert_eq!(r.code, exit::DELIVERY_APK, "{}", r.out);
        assert!(r.out.contains("the agent APK"), "{}", r.out);
        assert!(
            r.out.contains("installed before the network lock"),
            "{}",
            r.out
        );
        assert!(
            fx.calls().is_empty(),
            "the phone was addressed: {:?}",
            fx.calls()
        );
        assert!(fx.records().is_empty());
    }
    // The normal agent: its line in step 4.
    let fx = Fx::new("agent-links-none");
    let r = fx.deliver();
    assert_eq!(r.code, exit::UNVERIFIED, "{}", r.out);
    assert!(
        r.out
            .contains("agent dev.simplego.provisioning.agent: no autoVerify web hosts"),
        "{}",
        r.out
    );
}
