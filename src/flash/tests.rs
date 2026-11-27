// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `flash` against the fake adb and fake fastboot (one binary, two names,
//! one simulated phone in `state.json`) and a fake web server. No real
//! phone, no real fastboot, no network.

use super::*;
use crate::activation::rng::SeededRand;
use crate::activation::store::tests::{init_test_store, open_test_store};
use crate::activation::store::tests::{one_at_a_time, temp_dir};
use crate::activation::store::Delivery;
use crate::attest::tests as at;
use crate::grapheneos::testhttp::FakeHttp;
use crate::grapheneos::zipx;
use crate::trust::cache::Loaded;
use base64ct::{Base64, Encoding};
use serde_json::Value;
use std::path::Path;

const SERIAL: &str = "TESTSERIAL6A01";
const OTHER: &str = "OTHERPHONE9P99";
const VERSION: &str = "2026111801";
const BASE: &str = "https://releases.grapheneos.org";
const T_STABLE: u64 = 1_794_968_526;

/// A short flash-all.sh with the official script's checks (version,
/// product, slot count) and the same kind of writes.
const SCRIPT: &str = r#"#!/bin/sh
if ! command -v fastboot > /dev/null; then
  echo "fastboot not found"
  exit 1
fi
set -e
FASTBOOT_VERSION_STR=$(fastboot --version | grep "fastboot version " | cut -c18-23)
FASTBOOT_VERSION_NUM=$(echo $FASTBOOT_VERSION_STR | tr -d .)
if ! [ $FASTBOOT_VERSION_NUM -ge 3501 ]; then
  echo "fastboot version ($FASTBOOT_VERSION_STR) is older than the minimum supported version (35.0.1)."
  exit 1
fi
echo Available devices:
fastboot devices -l
product=$(fastboot getvar product 2>&1 | grep "product:" | cut -d ' ' -f 2)
if ! [ $product = "bluejay" ]; then
  echo Error: this factory image is for bluejay, but the name of connected device is $product
  exit 1
fi
slotcount=$(fastboot getvar slot-count 2>&1 | grep "slot-count:" | cut -d ' ' -f 2)
if ! [ $slotcount = "2" ]; then
  echo Error: unexpected value of slot-count variable: expected 2, got $slotcount
  exit 1
fi
fastboot flash --slot=other bootloader bootloader-bluejay-test.img
fastboot --set-active=other
fastboot reboot-bootloader
fastboot --set-active=a
fastboot erase avb_custom_key
fastboot flash avb_custom_key avb_pkmd.bin
fastboot flash boot boot.img
fastboot erase userdata
echo Flashing super, 1/2
fastboot flash super super_1.img
echo Flashing super, 2/2
fastboot flash super super_2.img
"#;

fn fake_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap();
    let p = dir
        .join("examples")
        .join(format!("fake-adb{}", std::env::consts::EXE_SUFFIX));
    assert!(p.is_file(), "fake adb not built at {}", p.display());
    p
}

fn link(dst: &Path) {
    if std::fs::hard_link(fake_binary(), dst).is_err() {
        std::fs::copy(fake_binary(), dst).unwrap();
    }
}

fn image(version: &str) -> Vec<u8> {
    let top = format!("bluejay-install-{version}");
    let big: Vec<u8> = (0..400_000u32).map(|i| (i % 249) as u8).collect();
    let files: Vec<(String, Vec<u8>, bool)> = vec![
        (
            format!("{top}/flash-all.sh"),
            SCRIPT.as_bytes().to_vec(),
            true,
        ),
        (
            format!("{top}/flash-all.bat"),
            b"@ECHO OFF\r\n".to_vec(),
            true,
        ),
        (
            format!("{top}/bootloader-bluejay-test.img"),
            vec![1; 1000],
            false,
        ),
        (format!("{top}/avb_pkmd.bin"), vec![2; 100], false),
        (format!("{top}/boot.img"), big.clone(), true),
        (format!("{top}/super_1.img"), big.clone(), true),
        (format!("{top}/super_2.img"), big, false),
    ];
    let refs: Vec<(&str, &[u8], bool)> = files
        .iter()
        .map(|(n, d, c)| (n.as_str(), d.as_slice(), *c))
        .collect();
    zipx::build_for_tests(&refs)
}

fn chain(key: u8) -> (Vec<String>, crate::attest::chain::Anchor) {
    let mut kd = at::grapheneos_kd(at::CHALLENGE);
    kd.boot_key = vec![key; 32];
    let syn = at::synthetic(&kd, false);
    (
        syn.ders.iter().map(|d| Base64::encode_string(d)).collect(),
        syn.root.clone(),
    )
}

struct Ui_ {
    confirm: Result<bool, String>,
}

impl Ui for Ui_ {
    fn secret(&mut self, _w: crate::deliver::Secret) -> Result<zeroize::Zeroizing<String>, String> {
        Ok(zeroize::Zeroizing::new("TEST-ONLY-PASSPHRASE".into()))
    }
    fn confirm(&mut self, _w: &str, _q: &str) -> Result<bool, String> {
        self.confirm.clone()
    }
    fn show_code(&mut self, _c: &str) {}
}

struct Fx {
    dir: PathBuf,
    cfg_text: String,
    trust: TrustMaterial,
    http: FakeHttp,
    signers: String,
    standin: bool,
    /// A valid chain with the other GrapheneOS key (0x43), same anchors.
    wrong_chain: Vec<String>,
}

struct Ran {
    code: i32,
    out: String,
}

impl Fx {
    fn new(tag: &str) -> Fx {
        let dir = temp_dir(&format!("flash-{tag}"));
        link(&dir.join("adb"));
        link(&dir.join("fastboot"));
        for d in ["work", "cache", "logs"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let agent = dir.join("agent.apk");
        std::fs::write(&agent, b"TEST agent placeholder").unwrap();
        let agent_sha = hex(&crate::util::sha256(b"TEST agent placeholder"));
        let (good, root_good) = chain(0x42);
        let (wrong_chain, root_wrong) = chain(0x43);
        let store = dir.join("store/admin.sxdb");
        drop(init_test_store(&store, tag.as_bytes()));
        let cfg_text = format!(
            "trust_cache_dir = \"{d}/trust\"\nadb_path = \"{d}/adb\"\nfastboot_path = \"{d}/fastboot\"\n\
             agent_apk = \"{a}\"\nagent_signing_cert_sha256 = \"{a5}\"\nadmin_store_path = \"{s}\"\n\
             grapheneos_cache_dir = \"{d}/cache\"\n",
            d = dir.display(),
            a = agent.display(),
            a5 = "a5".repeat(32),
            s = store.display()
        );
        let before = json!({
            "ro.product.manufacturer": "Google", "ro.product.model": "Pixel 6a",
            "ro.product.device": "bluejay", "ro.build.version.release": "17",
            "ro.build.id": "CP4A.TEST", "ro.build.version.security_patch": "2026-10-05",
            "ro.build.version.incremental": "2026100900", "ro.build.display.id": "2026100900",
            "ro.build.date.utc": (T_STABLE - 40 * 86_400).to_string(),
            "ro.boot.flash.locked": "1", "ro.boot.verifiedbootstate": "yellow"
        });
        let mut after = before.clone();
        after["ro.build.version.incremental"] = json!(VERSION);
        after["ro.build.display.id"] = json!(VERSION);
        after["ro.build.date.utc"] = json!((T_STABLE + 1).to_string());
        after["ro.build.version.security_patch"] = json!("2026-11-05");
        let state = json!({
            "target": SERIAL,
            "devices": [{"serial": SERIAL, "state": "device", "model": "Pixel_6a"}],
            "props": before,
            "packages": {
                "com.android.calculator2": {"version_code": 1, "version_name": "AOSP", "signer": "00", "system": true},
                "com.android.settings": {"version_code": 1, "version_name": "17", "signer": "00", "system": true}
            },
            "apks": {agent_sha: {"package": crate::names::DEFAULT_AGENT_PACKAGE, "version_code": 1, "version_name": "0.1.0", "signer": "a5".repeat(32)}},
            "agent_chain": good.clone(),
            "agent_package": crate::names::DEFAULT_AGENT_PACKAGE,
            "messenger_package": "org.example.messenger",
            "orbot_package": "org.torproject.android",
            "fastboot": {"product": "bluejay", "unlocked": false, "current_slot": "a",
                         "unlock_confirm": "yes", "lock_confirm": "yes", "confirm_after": 1},
            "after_boot": {"props": after, "agent_chain": good},
            "devopts": {"oem": false}
        });
        std::fs::write(
            dir.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let http = FakeHttp::default();
        http.put(
            &format!("{BASE}/bluejay-stable"),
            b"2026111800 1794968526 bluejay stable\n",
        );
        http.put(
            &format!("{BASE}/bluejay-stable-security-preview"),
            b"2026111801 1794968527 bluejay stable-security-preview\n",
        );
        let img = image(VERSION);
        let (signers, sig) = crate::grapheneos::image::tests::signed(&img);
        let url = format!("{BASE}/bluejay-install-{VERSION}.zip");
        http.put(&url, &img);
        http.put(&format!("{url}.sig"), sig.as_bytes());
        let trust = TrustMaterial {
            anchors: vec![root_good, root_wrong],
            rev: Loaded {
                value: at::revocation(r#"{"entries":{"ffff":{"status":"REVOKED"}}}"#),
                meta: at::meta(at::T_SYN - at::DAY),
            },
            gos: Loaded {
                value: at::gos_keys(),
                meta: at::meta(at::T_SYN - at::DAY),
            },
        };
        Fx {
            dir,
            cfg_text,
            trust,
            http,
            signers,
            standin: false,
            wrong_chain,
        }
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

    fn run(&self, a: &FlashArgs, confirm: Result<bool, String>) -> Ran {
        let cfg = Config::parse(&self.cfg_text).unwrap();
        let mut ui = Ui_ { confirm };
        let mut ch = || Ok(at::CHALLENGE.to_vec());
        let mut rng = SeededRand::new(b"flash-test");
        let now = || at::T_SYN;
        let sleep = |_d: Duration| {};
        let mut env = FlashEnv {
            cfg: &cfg,
            tools: Tools {
                adb: cfg.adb_path.clone(),
                fastboot: cfg.fastboot_path.clone(),
            },
            ui: &mut ui,
            now: &now,
            challenge: &mut ch,
            rng: &mut rng,
            sleep: &sleep,
            trust: Some(&self.trust),
            stale_confirmed: false,
            http: Some(&self.http),
            signers: &self.signers,
            boot_keys: vec![("bluejay".into(), "42".repeat(32))],
            standin: self.standin,
            polls: Polls {
                interval: Duration::ZERO,
                fastboot_appear: 3,
                unlock: 4,
                lock: 4,
                setup: 4,
                confirm_secs: 900,
                setup_secs: 3600,
                report_every: 2,
            },
            ui_retries: 2,
            cache_dir: self.dir.join("cache"),
            log_dir: self.dir.join("logs"),
            work_dir: self.dir.join("work"),
        };
        let mut out = Vec::new();
        let code = flash(&mut env, &mut out, a);
        Ran {
            code,
            out: String::from_utf8(out).unwrap(),
        }
    }

    fn records(&self) -> Vec<Flash> {
        open_test_store(&self.dir.join("store/admin.sxdb"))
            .data
            .flashes
    }

    fn report_log(&self, name: &str) {
        if let Some(d) = std::env::var_os("SXPROV_FAKE_ADB_LOG_DIR") {
            let _ = std::fs::write(
                PathBuf::from(d).join(format!("flash-{name}.log")),
                self.calls().join("\n") + "\n",
            );
        }
    }
}

fn args() -> FlashArgs {
    FlashArgs {
        serial: SERIAL.into(),
        ..Default::default()
    }
}

/// Every adb and fastboot call addressed the one phone; no full serial in
/// the output, the calls or the script logs.
fn assert_clean(fx: &Fx, r: &Ran) {
    for c in fx.calls() {
        assert!(!c.contains("<OTHER") && !c.contains("<NO SERIAL>"), "{c}");
        assert!(!c.contains(SERIAL), "{c}");
        assert!(
            c == "adb devices -l"
                || c.starts_with("adb -s <serial> ")
                || c == "fastboot devices"
                || c == "fastboot devices -l"
                || c == "fastboot --version"
                || c.starts_with("fastboot -s <serial> ")
                || c.starts_with("fastboot [ANDROID_SERIAL=<serial>] "),
            "{c}"
        );
    }
    assert!(
        !r.out.contains(SERIAL) && !r.out.contains(OTHER),
        "{}",
        r.out
    );
    for e in std::fs::read_dir(fx.dir.join("logs")).unwrap() {
        let t = std::fs::read_to_string(e.unwrap().path()).unwrap();
        assert!(!t.contains(SERIAL) && !t.contains(OTHER), "{t}");
    }
}

fn idx(calls: &[String], needle: &str) -> usize {
    calls
        .iter()
        .position(|c| c.contains(needle))
        .unwrap_or_else(|| panic!("no call {needle:?} in {calls:#?}"))
}

#[test]
fn full_flash_of_the_security_preview_build() {
    let _g = one_at_a_time();
    let fx = Fx::new("full");
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(
        r.out
            .contains("FLASHED: GrapheneOS 2026111801 (security preview)"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("update available (40 days behind): security preview 2026111801"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(MSG_UNLOCK)
            && r.out.contains(MSG_LOCK)
            && r.out.contains("press power to start")
    );
    assert_clean(&fx, &r);
    let s = fx.state();
    // OEM unlocking was turned on through the screen; no dump file left.
    assert_eq!(s["devopts"]["oem"], json!(true));
    assert!(s["files"].as_object().is_none_or(|f| f.is_empty()));
    // The script's writes, through ANDROID_SERIAL, between unlock and lock.
    let flashed: Vec<String> = serde_json::from_value(s["fastboot"]["flashed"].clone()).unwrap();
    assert_eq!(
        flashed,
        vec![
            "flash --slot=other bootloader bootloader-bluejay-test.img",
            "erase avb_custom_key",
            "flash avb_custom_key avb_pkmd.bin",
            "flash boot boot.img",
            "erase userdata",
            "flash super super_1.img",
            "flash super super_2.img"
        ]
    );
    assert_eq!(s["fastboot"]["wipes"], json!(2));
    assert_eq!(s["fastboot"]["unlocked"], json!(false));
    let c = fx.calls();
    let unlock = idx(&c, "fastboot -s <serial> flashing unlock");
    let first_write = idx(&c, "fastboot [ANDROID_SERIAL=<serial>] flash --slot=other");
    let lock = idx(&c, "fastboot -s <serial> flashing lock");
    assert!(idx(&c, "adb -s <serial> reboot bootloader") < unlock);
    assert!(unlock < first_write && first_write < lock);
    assert!(
        idx(
            &c,
            "am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS"
        ) < unlock
    );
    // The record.
    let rec = &fx.records()[0];
    assert_eq!(rec.result, "flashed");
    assert_eq!(rec.new_version, VERSION);
    assert_eq!(rec.new_build_type, "security preview");
    assert_eq!(rec.old_version.as_deref(), Some("2026100900"));
    assert_eq!(
        rec.verified_boot_key.as_deref(),
        Some("42".repeat(32).as_str())
    );
    assert_eq!(rec.serial, SERIAL);
    assert!(rec.durations.contains_key("flash_script") && rec.durations.contains_key("setup_wait"));
    assert!(!rec.image_sha256.is_empty());
    // The unpacked image is removed after a good flash; the zip stays.
    let vdir = fx.dir.join("cache").join(VERSION);
    assert!(std::fs::read_dir(&vdir).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("unpacked")));
    fx.report_log("full");
}

#[test]
fn windows_fastboot_crlf_needs_the_standin() {
    let _g = one_at_a_time();
    let mut fx = Fx::new("crlf");
    fx.edit(|s| {
        s["fastboot"]["crlf"] = json!(true);
        s["devopts"]["oem"] = json!(true);
    });
    fx.standin = true;
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert_clean(&fx, &r);
    // Without the stand-in the official checks stop the script before any write.
    let mut fx = Fx::new("crlf-raw");
    fx.edit(|s| s["fastboot"]["crlf"] = json!(true));
    fx.standin = false;
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_SCRIPT, "{}", r.out);
    assert!(
        r.out.contains("the name of connected device is bluejay"),
        "{}",
        r.out
    );
    assert!(fx.state()["fastboot"]["flashed"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(r.out.contains("UNLOCKED"), "{}", r.out);
    assert_eq!(fx.records()[0].result, "failed at step 7");
}

#[test]
fn wrong_codename_is_refused() {
    let _g = one_at_a_time();
    // A codename without a pinned GrapheneOS key: refused at step 1.
    let fx = Fx::new("codename");
    fx.edit(|s| s["props"]["ro.product.device"] = json!("oriole"));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(r
        .out
        .contains("no pinned GrapheneOS verified boot key for oriole"));
    assert!(fx
        .calls()
        .iter()
        .all(|c| !c.contains("reboot") && !c.starts_with("fastboot")));
    // The bootloader reports another product than adb: stopped before unlock.
    let fx = Fx::new("product");
    fx.edit(|s| s["fastboot"]["product"] = json!("oriole"));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    assert!(r.out.contains("the image is for bluejay"), "{}", r.out);
    assert!(fx.calls().iter().all(|c| !c.contains("flashing")));
    assert_eq!(fx.state()["fastboot"]["wipes"], json!(0));
}

#[test]
fn two_devices_in_fastboot_mode() {
    let _g = one_at_a_time();
    let fx = Fx::new("two");
    fx.edit(|s| {
        s["devices"]
            .as_array_mut()
            .unwrap()
            .push(json!({"serial": OTHER, "state": "fastboot", "model": "Pixel_6"}))
    });
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    assert!(
        r.out.contains("2 devices are in fastboot mode"),
        "{}",
        r.out
    );
    assert_clean(&fx, &r);
    assert!(fx.calls().iter().all(|c| !c.contains("flashing")));
}

#[test]
fn broken_signature_stops_before_the_phone_is_touched() {
    let _g = one_at_a_time();
    let fx = Fx::new("sig");
    let mut bad = image(VERSION);
    let n = bad.len();
    bad[n / 2] ^= 0x01;
    fx.http
        .put(&format!("{BASE}/bluejay-install-{VERSION}.zip"), &bad);
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::OS_IMAGE, "{}", r.out);
    assert!(r.out.contains("SIGNATURE CHECK FAILED"), "{}", r.out);
    assert!(!fx
        .dir
        .join(format!("cache/{VERSION}/bluejay-install-{VERSION}.zip"))
        .exists());
    assert!(fx
        .calls()
        .iter()
        .all(|c| !c.contains("reboot") && !c.contains("am start")));
    assert_eq!(fx.records()[0].result, "failed at step 3");
}

#[test]
fn unlock_not_confirmed() {
    let _g = one_at_a_time();
    let fx = Fx::new("unlock");
    fx.edit(|s| s["fastboot"]["unlock_confirm"] = json!("no"));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    assert!(
        r.out
            .contains("the unlock was not confirmed on the phone within 900 s"),
        "{}",
        r.out
    );
    assert!(r.out.contains("still LOCKED"), "{}", r.out);
    // A line with the time left every report interval (4 polls, every 2).
    for left in ["15m00s", "7m30s"] {
        let want = format!("waiting for you on the phone (press_volume_down_unlock): {left} left");
        assert!(r.out.contains(&want), "{}", r.out);
    }
    let s = fx.state();
    assert_eq!(s["fastboot"]["unlocked"], json!(false));
    assert!(s["fastboot"]["flashed"].as_array().unwrap().is_empty());
    assert_eq!(fx.records()[0].result, "failed at step 6");
}

#[test]
fn script_fails_in_the_middle() {
    let _g = one_at_a_time();
    let fx = Fx::new("script");
    fx.edit(|s| s["fastboot"]["fail_at"] = json!("flash super super_1.img"));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_SCRIPT, "{}", r.out);
    assert!(
        r.out.contains("flash-all.sh failed (exit Some(1))"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("UNLOCKED and only partly flashed"),
        "{}",
        r.out
    );
    let flashed = fx.state()["fastboot"]["flashed"].as_array().unwrap().len();
    assert_eq!(flashed, 5, "stopped at super_1");
    assert!(fx.calls().iter().all(|c| !c.contains("flashing lock")));
    // The unpacked image is kept for the manual run; the log names the failure.
    let vdir = fx.dir.join("cache").join(VERSION);
    assert!(std::fs::read_dir(&vdir).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("unpacked")));
    let logs: Vec<_> = std::fs::read_dir(fx.dir.join("logs")).unwrap().collect();
    let t = std::fs::read_to_string(logs[0].as_ref().unwrap().path()).unwrap();
    assert!(t.contains("test failure of flash super super_1.img"), "{t}");
    assert!(
        t.contains("\n************01\t fastboot"),
        "masked device list: {t}"
    );
    assert_clean(&fx, &r);
}

#[test]
fn lock_not_confirmed() {
    let _g = one_at_a_time();
    let fx = Fx::new("lock");
    fx.edit(|s| s["fastboot"]["lock_confirm"] = json!("no"));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    assert!(r.out.contains("the lock was not confirmed"), "{}", r.out);
    assert!(r.out.contains("STILL UNLOCKED"), "{}", r.out);
    assert_eq!(fx.state()["fastboot"]["unlocked"], json!(true));
}

#[test]
fn attestation_after_the_flash_shows_another_key() {
    let _g = one_at_a_time();
    let fx = Fx::new("key");
    let wrong = fx.wrong_chain.clone();
    fx.edit(|s| s["after_boot"]["agent_chain"] = json!(wrong));
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_CHECK, "{}", r.out);
    assert!(
        r.out
            .contains(&format!("the verified boot key is {}", "43".repeat(32))),
        "{}",
        r.out
    );
    let rec = &fx.records()[0];
    assert_eq!(rec.result, "failed at step 10");
    assert_eq!(
        rec.verified_boot_key.as_deref(),
        Some("43".repeat(32).as_str())
    );
}

#[test]
fn phone_never_comes_back_after_setup() {
    let _g = one_at_a_time();
    let fx = Fx::new("setup");
    fx.edit(|s| s["after_boot"] = Value::Null);
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    assert!(r.out.contains("did not come back over adb"), "{}", r.out);
    assert!(r.out.contains("run sxprov verify"), "{}", r.out);
}

fn delivered_record() -> Delivery {
    serde_json::from_value(json!({
        "delivery_id": "00", "serial": SERIAL, "serial_masked": mask_serial(SERIAL),
        "device_class": "phone", "tier": "hardened", "test": true, "model": null, "os_build": null,
        "security_patch": null, "attestation": "x", "messenger_package": "org.example.messenger",
        "messenger_version_code": null, "messenger_version_name": null, "messenger_apk_sha256": null,
        "messenger_signer_sha256": null, "messenger_verified": false, "reinstall": false,
        "network_mode": "tor_required", "file_transferred": false, "customer_ref": "TEST-6A-0001",
        "started_at": "2026-11-23T10:00:00Z", "result": "delivered"
    }))
    .unwrap()
}

#[test]
fn delivery_record_needs_test_device_and_setup_done_is_never_wiped() {
    let _g = one_at_a_time();
    let fx = Fx::new("record");
    {
        let mut st = open_test_store(&fx.dir.join("store/admin.sxdb"));
        st.data.deliveries.push(delivered_record());
        st.save(&mut SeededRand::new(b"x")).unwrap();
    }
    let r = fx.run(&args(), Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(r.out.contains("delivery record"), "{}", r.out);
    assert!(fx.calls().iter().all(|c| !c.contains("reboot")));
    // --test-device --yes: allowed (dry run here).
    let a = FlashArgs {
        test_device: true,
        yes: true,
        dry_run: true,
        ..args()
    };
    let r = fx.run(&a, Err("no terminal".into()));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    // A messenger set up by a customer: refused even on a test device.
    fx.edit(|s| {
        s["packages"]["org.example.messenger"] =
            json!({"version_code": 397, "version_name": "7.1.4", "signer": "bc", "system": false});
        s["provider"] = json!({"activation": true, "setup_done": true});
    });
    let a = FlashArgs {
        test_device: true,
        yes: true,
        ..args()
    };
    let r = fx.run(&a, Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(r.out.contains("setup=done"), "{}", r.out);
    assert!(fx.calls().iter().all(|c| !c.contains("reboot")));
    // The same under a package no record and no config names: found by its
    // activation provider, refused.
    fx.edit(|s| {
        s["packages"]
            .as_object_mut()
            .unwrap()
            .remove("org.example.messenger");
        s["packages"]["org.example.unlisted"] =
            json!({"version_code": 397, "version_name": "7.1.4", "signer": "bc", "system": false});
        s["messenger_package"] = json!("org.example.unlisted");
    });
    let r = fx.run(&a, Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(
        r.out.contains("org.example.unlisted reports setup=done"),
        "{}",
        r.out
    );
    assert!(fx.calls().iter().all(|c| !c.contains("reboot")));
    // --yes without --test-device is a usage error.
    let a = FlashArgs {
        yes: true,
        ..args()
    };
    assert_eq!(fx.run(&a, Ok(true)).code, exit::USAGE);
}

#[test]
fn dry_run_and_json_events() {
    let _g = one_at_a_time();
    let fx = Fx::new("dry");
    let a = FlashArgs {
        dry_run: true,
        json: true,
        ..args()
    };
    let r = fx.run(&a, Err("no terminal".into()));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    let events: Vec<Value> = r
        .out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let target = events.iter().find(|e| e["event"] == "target").unwrap();
    assert_eq!(target["build_type"], json!("security preview"));
    assert_eq!(target["version"], json!(VERSION));
    let st = events.iter().find(|e| e["event"] == "os_status").unwrap();
    assert_eq!(st["status"]["build_type"], json!("not_in_channel"));
    assert!(r.out.contains("DRY RUN"));
    // The image was fetched and verified; nothing was sent to the phone
    // but reads; nothing stored.
    assert!(fx
        .dir
        .join(format!(
            "cache/{VERSION}/bluejay-install-{VERSION}.zip.verified.json"
        ))
        .exists());
    assert!(fx
        .calls()
        .iter()
        .all(|c| !c.contains("reboot") && !c.starts_with("fastboot") && !c.contains("am start")));
    assert!(fx.records().is_empty());
    // Only the release host was asked.
    assert!(fx
        .http
        .urls()
        .iter()
        .all(|u| u.starts_with(&format!("GET {BASE}/"))));
    // --version picks an exact build: the release, labelled as such.
    let img = image("2026111800");
    let (_, sig) = crate::trust::sshsig::sign_for_tests(
        &crate::grapheneos::image::tests::SEED,
        crate::trust::lists::GRAPHENEOS_PRINCIPAL,
        crate::grapheneos::FACTORY_NAMESPACE,
        &img,
    );
    let url = format!("{BASE}/bluejay-install-2026111800.zip");
    fx.http.put(&url, &img);
    fx.http.put(&format!("{url}.sig"), sig.as_bytes());
    let a = FlashArgs {
        dry_run: true,
        version: Some("2026111800".into()),
        ..args()
    };
    let r = fx.run(&a, Err("no terminal".into()));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(
        r.out
            .contains("GrapheneOS 2026111800 for bluejay, build type release"),
        "{}",
        r.out
    );
    fx.report_log("dry-run");
}

#[test]
fn oem_unlocking_behind_a_pin_needs_the_operator() {
    let _g = one_at_a_time();
    let fx = Fx::new("pin");
    fx.edit(|s| s["devopts"]["pin"] = json!(true));
    let r = fx.run(&args(), Ok(true));
    // Ok(true) confirms WIPE; the DONE prompt then also says yes, but the
    // switch is still off, so the flash stops.
    assert_eq!(r.code, exit::FLASH_OEM_UNLOCK, "{}", r.out);
    assert!(r.out.contains("the phone asks for its PIN"), "{}", r.out);
    assert!(r.out.contains(devopts::MANUAL), "{}", r.out);
    let s = fx.state();
    assert_eq!(s["devopts"]["oem"], json!(false));
    assert!(s["files"].as_object().is_none_or(|f| f.is_empty()));
    assert!(fx.calls().iter().all(|c| !c.contains("reboot")));
    // Greyed out, no terminal: stopped with the instruction.
    let fx = Fx::new("greyed");
    fx.edit(|s| s["devopts"]["greyed"] = json!(true));
    let a = FlashArgs {
        test_device: true,
        yes: true,
        ..args()
    };
    let r = fx.run(&a, Err("no terminal on standard input".into()));
    assert_eq!(r.code, exit::FLASH_OEM_UNLOCK, "{}", r.out);
    assert!(
        r.out.contains("greyed out") && r.out.contains("no terminal"),
        "{}",
        r.out
    );
}

fn events(out: &str) -> Vec<Value> {
    out.lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect()
}

#[test]
fn waiting_for_user_events_with_the_time_left() {
    let _g = one_at_a_time();
    let fx = Fx::new("waiting");
    fx.edit(|s| s["fastboot"]["lock_confirm"] = json!("no"));
    let a = FlashArgs {
        json: true,
        ..args()
    };
    let r = fx.run(&a, Ok(true));
    assert_eq!(r.code, exit::FLASH_BOOTLOADER, "{}", r.out);
    let ev = events(&r.out);
    let waits: Vec<(String, u64)> = ev
        .iter()
        .filter(|e| e["event"] == "waiting_for_user")
        .map(|e| {
            assert_eq!(e["state"], "waiting_for_user");
            assert!(e["message"].as_str().unwrap().starts_with("On the phone:"));
            (
                e["action"].as_str().unwrap().to_string(),
                e["remaining_secs"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        waits,
        vec![
            ("press_volume_down_unlock".to_string(), 900),
            ("press_volume_down_lock".to_string(), 900),
            ("press_volume_down_lock".to_string(), 450),
        ]
    );
    assert!(ev.iter().any(|e| e["event"] == "failed" && e["step"] == 8));
    assert_clean(&fx, &r);
}

#[test]
fn real_polls_follow_the_config_timeout() {
    let p = Polls::real(900);
    assert_eq!((p.unlock, p.lock, p.report_every), (450, 450, 15));
    assert_eq!(p.interval, Duration::from_secs(2));
    assert_eq!(Polls::real(61).unlock, 31);
    assert_eq!(Polls::left(900, 0, 450), 900);
    assert_eq!(Polls::left(900, 15, 450), 870);
    assert_eq!(Polls::left(900, 450, 450), 0);
    let cfg =
        Config::parse("trust_cache_dir = \"/x\"\nflash_confirm_timeout_secs = 1800\n").unwrap();
    assert_eq!(Polls::real(cfg.flash_confirm_timeout_secs).unlock, 900);
}

#[test]
fn operator_texts_have_no_runs_of_spaces() {
    for m in [MSG_UNLOCK, MSG_LOCK, MSG_SETUP] {
        assert!(!m.contains("  "), "{m}");
    }
}

/// The phone as the operator left it: in the bootloader, the image
/// fetched and verified by an earlier run.
fn in_fastboot(fx: &Fx, unlocked: bool) {
    let r = fx.run(
        &FlashArgs {
            dry_run: true,
            test_device: true,
            yes: true,
            ..args()
        },
        Ok(true),
    );
    assert_eq!(r.code, exit::OK, "{}", r.out);
    fx.edit(|s| {
        s["devices"][0]["state"] = json!("fastboot");
        s["fastboot"]["unlocked"] = json!(unlocked);
    });
    let _ = std::fs::remove_file(fx.dir.join("calls.log"));
}

fn resume() -> FlashArgs {
    FlashArgs {
        resume: true,
        version: Some(VERSION.into()),
        ..args()
    }
}

#[test]
fn resume_after_a_late_unlock_flashes_and_locks() {
    let _g = one_at_a_time();
    let fx = Fx::new("resume-unlocked");
    in_fastboot(&fx, true);
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(r.out.contains("continuing at step 7"), "{}", r.out);
    assert!(
        r.out.contains("FLASHED: GrapheneOS 2026111801"),
        "{}",
        r.out
    );
    let calls = fx.calls();
    // Nothing over adb before the lock; no unlock; the script, then the lock.
    assert!(!calls[..idx(&calls, "flashing lock")]
        .iter()
        .any(|c| c.starts_with("adb ") && c != "adb devices -l"));
    assert!(!calls.iter().any(|c| c.contains("flashing unlock")));
    assert!(idx(&calls, "flash boot boot.img") < idx(&calls, "flashing lock"));
    assert_eq!(fx.state()["fastboot"]["wipes"], json!(1));
    let rec = fx.records();
    let last = rec.last().unwrap();
    assert_eq!(last.result, "flashed");
    assert_eq!(last.resumed_at_step, Some(7));
    assert_eq!(last.new_version, VERSION);
    assert!(!last.image_sha256.is_empty());
    assert_clean(&fx, &r);
}

#[test]
fn resume_when_still_locked_unlocks_first() {
    let _g = one_at_a_time();
    let fx = Fx::new("resume-locked");
    in_fastboot(&fx, false);
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(r.out.contains("continuing at step 6"), "{}", r.out);
    let calls = fx.calls();
    assert!(idx(&calls, "flashing unlock") < idx(&calls, "flash boot boot.img"));
    assert_eq!(fx.state()["fastboot"]["wipes"], json!(2));
    assert_eq!(fx.records().last().unwrap().resumed_at_step, Some(6));
    assert_clean(&fx, &r);
}

#[test]
fn resume_after_a_late_lock_goes_to_the_setup() {
    let _g = one_at_a_time();
    let fx = Fx::new("resume-setup");
    in_fastboot(&fx, false);
    // The earlier run gave up at step 8; the lock was confirmed later and
    // the flash is on the phone.
    let mut st = open_test_store(&fx.dir.join("store/admin.sxdb"));
    st.data.flashes.push(Flash {
        flash_id: "00".repeat(16),
        serial: SERIAL.into(),
        serial_masked: crate::util::mask_serial(SERIAL),
        codename: "bluejay".into(),
        test_device: false,
        old_version: None,
        old_build_type: None,
        new_version: VERSION.into(),
        new_build_type: "security preview".into(),
        channel: "stable".into(),
        image_sha256: "11".repeat(32),
        verified_boot_key: None,
        attestation: None,
        started_at: "2026-11-24T10:00:00Z".into(),
        ended_at: None,
        result: "failed at step 8".into(),
        failure: None,
        durations: BTreeMap::new(),
        resumed_at_step: None,
        sxprov_version: None,
    });
    st.save(&mut SeededRand::new(b"resume-setup")).unwrap();
    drop(st);
    fx.edit(|s| {
        s["fastboot"]["locked_after_flash"] = json!(true);
        s["fastboot"]["flashed"] = json!(["flash boot boot.img"]);
    });
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::OK, "{}", r.out);
    assert!(r.out.contains("continuing at step 9"), "{}", r.out);
    let calls = fx.calls();
    assert!(!calls
        .iter()
        .any(|c| c.contains("flashing") || c.contains("ANDROID_SERIAL")));
    assert_eq!(fx.records().last().unwrap().resumed_at_step, Some(9));
    assert_clean(&fx, &r);
}

#[test]
fn resume_refusals() {
    let _g = one_at_a_time();
    let fx = Fx::new("resume-refused");
    // The phone in adb, not in fastboot mode.
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(
        r.out.contains("exactly one device in fastboot mode"),
        "{}",
        r.out
    );
    // The image is not in the cache: nothing is downloaded.
    fx.edit(|s| s["devices"][0]["state"] = json!("fastboot"));
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::OS_IMAGE, "{}", r.out);
    assert!(r.out.contains("--resume downloads nothing"), "{}", r.out);
    assert!(!fx.http.urls().iter().any(|u| u.contains(".zip")));
    fx.edit(|s| s["devices"][0]["state"] = json!("device"));
    in_fastboot(&fx, true);
    // Another device in fastboot mode too.
    fx.edit(|s| {
        s["devices"]
            .as_array_mut()
            .unwrap()
            .push(json!({"serial": OTHER, "state": "fastboot", "model": "Pixel_6"}))
    });
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(r.out.contains("2 listed"), "{}", r.out);
    fx.edit(|s| {
        s["devices"].as_array_mut().unwrap().pop();
    });
    // No typed WIPE and no terminal: refused, nothing flashed.
    let r = fx.run(
        &resume(),
        Err("no terminal on standard input to type WIPE".into()),
    );
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    // --yes needs --test-device, and --resume never with --dry-run.
    let r = fx.run(
        &FlashArgs {
            yes: true,
            ..resume()
        },
        Ok(true),
    );
    assert_eq!(r.code, exit::USAGE, "{}", r.out);
    let r = fx.run(
        &FlashArgs {
            dry_run: true,
            ..resume()
        },
        Ok(true),
    );
    assert_eq!(r.code, exit::USAGE, "{}", r.out);
    // The product must have a pinned key.
    fx.edit(|s| s["fastboot"]["product"] = json!("oriole"));
    let r = fx.run(&resume(), Ok(true));
    assert_eq!(r.code, exit::FLASH_REFUSED, "{}", r.out);
    assert!(fx.state()["fastboot"]["flashed"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_clean(&fx, &r);
}
