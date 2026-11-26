// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems

use super::testapk::{self, Spec, TestKey};
use super::*;
use std::path::PathBuf;

fn write(tag: &str, data: &[u8]) -> PathBuf {
    let d = crate::activation::store::tests::temp_dir(tag);
    let p = d.join("test.apk");
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn reads_package_version_and_signer_v2_and_v3() {
    let key = TestKey::new("a");
    for v3 in [false, true] {
        for deflate in [false, true] {
            let mut s = Spec::new("org.example.messenger", 2157);
            s.v3 = v3;
            s.deflate_manifest = deflate;
            let bytes = testapk::build(&s, &key);
            let p = write("apk-read", &bytes);
            let i = inspect(&p).unwrap();
            assert_eq!(i.package, "org.example.messenger");
            assert_eq!(i.version_code, 2157);
            assert_eq!(i.version_name.as_deref(), Some("1.0-test"));
            assert_eq!(i.signer_sha256, key.digest_hex());
            assert_eq!(i.scheme, if v3 { "v3" } else { "v2" });
            assert_eq!(i.sha256, hex(&crate::util::sha256(&bytes)));
            assert_eq!(i.size, bytes.len() as u64);
            assert_eq!(signer_digest(&p).unwrap(), key.digest_hex());
            assert_eq!(i.legacy_rsa_bits, None);
            assert_eq!(i.key_warning(), None);
        }
    }
}

#[test]
fn different_keys_give_different_digests() {
    let (a, b) = (TestKey::new("a"), TestKey::new("b"));
    let s = Spec::new("org.torproject.android", 1);
    let ia = inspect(&write("apk-ka", &testapk::build(&s, &a))).unwrap();
    let ib = inspect(&write("apk-kb", &testapk::build(&s, &b))).unwrap();
    assert_ne!(ia.signer_sha256, ib.signer_sha256);
}

#[test]
fn altered_contents_are_refused() {
    let key = TestKey::new("a");
    let mut s = Spec::new("org.example.messenger", 1);
    s.filler = vec![0x11; 3000];
    let good = testapk::build(&s, &key);
    // A byte inside the stored classes.dex entry.
    let pos = good.windows(4).position(|w| w == [0x11; 4]).unwrap() + 100;
    let mut bad = good.clone();
    bad[pos] ^= 1;
    let e = inspect(&write("apk-alt", &bad)).unwrap_err();
    assert!(e.contains("content digest differs"), "{e}");
    // The signature itself altered.
    let mut bad = good.clone();
    let magic = bad.windows(16).position(|w| w == sigblock::MAGIC).unwrap();
    // Before the magic: the size (8), the public key (4 + 91), then the signature.
    let sig_byte = magic - 8 - 95 - 10;
    bad[sig_byte] ^= 1;
    assert!(inspect(&write("apk-alt2", &bad)).is_err());
}

#[test]
fn unsigned_and_non_zip_files_are_refused() {
    let unsigned = testapk::zip(&[(
        "AndroidManifest.xml",
        testapk::manifest("org.example.messenger", 1, "1"),
        false,
    )]);
    let e = inspect(&write("apk-unsigned", &unsigned)).unwrap_err();
    assert!(e.contains("no APK Signing Block"), "{e}");
    let e = inspect(&write("apk-junk", b"not an apk at all, just text")).unwrap_err();
    assert!(e.contains("not a ZIP file"), "{e}");
}

#[test]
fn missing_manifest_is_refused() {
    let key = TestKey::new("a");
    let unsigned = testapk::zip(&[("classes.dex", vec![1, 2, 3], false)]);
    let e = inspect(&write("apk-noman", &testapk::sign(&unsigned, &key, false))).unwrap_err();
    assert!(e.contains("AndroidManifest.xml not found"), "{e}");
}

/// The real agent APK of this repository, when it has been built: RSA v2
/// (and v3) as produced by the Android build tools.
#[test]
fn real_agent_apk_if_built() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("agent/build/outputs/apk/release/sxprov-agent-release.apk");
    if !p.is_file() {
        eprintln!("agent APK not built; skipped");
        return;
    }
    let i = inspect(&p).unwrap();
    assert_eq!(i.package, crate::names::DEFAULT_AGENT_PACKAGE);
    assert!(i.version_code >= 1);
    assert_eq!(i.signer_sha256.len(), 64);
    assert_eq!(i.legacy_rsa_bits, None);
}

/// A downloaded Orbot release APK in `dist/orbot-in/`, when present: its
/// signer is the Tor Project's RSA 1024 key (v2 only), read through the
/// legacy verifier and reported as such.
#[test]
fn real_orbot_apk_if_downloaded() {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("dist/orbot-in");
    let Some(p) = std::fs::read_dir(&d).ok().and_then(|r| {
        r.flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "apk"))
    }) else {
        eprintln!("no Orbot APK in dist/orbot-in; skipped");
        return;
    };
    let i = inspect(&p).unwrap();
    assert_eq!(i.package, "org.torproject.android");
    assert_eq!(
        i.signer_sha256,
        "a454b87a1847a89ed7f5e70fba6bba96f3ef29c26e0981204fe347bf231dfd5b"
    );
    assert_eq!(i.legacy_rsa_bits, Some(1024));
    assert!(i.key_warning().unwrap().contains("RSA 1024 bits"));
}

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/apk")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn web_links_of_the_real_simplex_fdroid_and_orbot_manifests() {
    // The SimpleX app 7.1.4: one autoVerify filter, http and https, 22 hosts
    // (as `aapt2 dump xmltree` shows them).
    let f = axml::link_filters(&fixture("simplex-7.1.4-397-AndroidManifest.xml")).unwrap();
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].component, "chat.simplex.app.MainActivity");
    assert!(f[0].auto_verify && f[0].unresolved.is_empty());
    assert_eq!(f[0].schemes, ["http", "https"]);
    let hosts = axml::auto_verify_hosts(&f);
    assert_eq!(hosts.len(), 22, "{hosts:?}");
    assert!(hosts.contains(&"simplex.chat".to_string()));
    for n in [4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19] {
        assert!(hosts.contains(&format!("smp{n}.simplex.im")), "smp{n}");
    }
    assert!(!hosts.contains(&"smp13.simplex.im".to_string()));
    for n in 1..=6 {
        assert!(hosts.contains(&format!("smp{n}.simplexonflux.com")));
    }
    // The F-Droid client 2.0.3: two autoVerify https filters, 4 hosts.
    let f = axml::link_filters(&fixture("fdroid-2.0.3-2000053-AndroidManifest.xml")).unwrap();
    assert_eq!(f.len(), 2, "{f:#?}");
    assert!(f
        .iter()
        .all(|x| x.component == "org.fdroid.MainActivity" && x.auto_verify));
    assert_eq!(
        axml::auto_verify_hosts(&f),
        [
            "cloudflare.f-droid.org",
            "f-droid.org",
            "fdroid.link",
            "staging.f-droid.org"
        ]
    );
    // Orbot 17.9.8: no web filter at all (the network lock may be installed
    // before the lock is on).
    let f = axml::link_filters(&fixture("orbot-17.9.8-RC-1-AndroidManifest.xml")).unwrap();
    assert!(f.is_empty(), "{f:#?}");
    // The manifest fields still read as before.
    let m = axml::manifest_info(&fixture("simplex-7.1.4-397-AndroidManifest.xml")).unwrap();
    assert_eq!(
        (m.package.as_str(), m.version_code),
        ("chat.simplex.app", 397)
    );
}

#[test]
fn web_links_of_synthetic_manifests() {
    let key = TestKey::new("a");
    // No web filter: the plain test manifest, and one with only a custom
    // scheme and a launcher filter.
    let s = Spec::new("org.example.messenger", 1);
    let i = inspect(&write("apk-nolinks", &testapk::build(&s, &key))).unwrap();
    assert!(i.link_filters.is_empty() && i.auto_verify_hosts().is_empty());
    let m = testapk::manifest_with_links("a.b", 1, "1", &[], false);
    assert!(axml::link_filters(&m).unwrap().is_empty());
    // An autoVerify https filter.
    let mut s = Spec::new("chat.simplex.app", 397);
    s.link_hosts = vec!["simplex.chat", "SMP4.simplex.im", "simplex.chat"];
    let i = inspect(&write("apk-links", &testapk::build(&s, &key))).unwrap();
    assert_eq!(i.auto_verify_hosts(), ["simplex.chat", "smp4.simplex.im"]);
    assert_eq!(i.link_filters[0].component, "x.MainActivity");
    assert!(i.unresolved_links().is_empty());
    assert_eq!(i.version_code, 397);
    // A host given as a resource reference: reported, not guessed.
    let mut s = Spec::new("org.example.lock", 1);
    s.link_host_ref = true;
    let i = inspect(&write("apk-linkref", &testapk::build(&s, &key))).unwrap();
    assert_eq!(i.unresolved_links(), ["x.MainActivity host=@0x7f1300a1"]);
    assert!(i.auto_verify_hosts().is_empty());
    // Damaged nesting is refused.
    let mut m = testapk::manifest_with_links("a.b", 1, "1", &["h.example"], false);
    let n = m.len();
    m.truncate(n - 24 * 2); // drop </application> and </manifest>
    let len = m.len() as u32;
    m[4..8].copy_from_slice(&len.to_le_bytes());
    assert!(
        axml::link_filters(&m).is_ok(),
        "unclosed elements at the end are tolerated"
    );
    let mut m = testapk::manifest_with_links("a.b", 1, "1", &["h.example"], false);
    let n = m.len();
    // </manifest> renamed to </activity>: a nesting error.
    m[n - 4..].copy_from_slice(&9u32.to_le_bytes());
    let e = axml::link_filters(&m).unwrap_err();
    assert!(e.contains("nesting"), "{e}");
}
