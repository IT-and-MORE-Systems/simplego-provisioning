// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The index check against the real files of SimpleX's repository and
//! against synthetic repositories signed with the TEST ONLY key.

use super::testrepo::*;
use super::*;
use crate::grapheneos::testhttp::FakeHttp;

fn real_want() -> Want<'static> {
    Want {
        package: "chat.simplex.app",
        signer: REAL_SIGNER,
        abis: vec!["arm64-v8a".into(), "armeabi-v7a".into(), "armeabi".into()],
        sdk: 37,
    }
}

fn real_repo() -> Repo<'static> {
    Repo {
        url: REAL_URL,
        fingerprint: REAL_FINGERPRINT,
    }
}

#[test]
fn the_real_entry_jar_verifies_against_the_pinned_fingerprint() {
    let entry = jar::verify_entry_jar(REAL_ENTRY_JAR, REAL_FINGERPRINT).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&entry).unwrap();
    assert_eq!(v["timestamp"], 1_794_696_615_000u64);
    assert_eq!(
        v["index"]["sha256"],
        "b3c0246b7d96ebf928757c0d0db02504ad9cdb31bbf3616ba2bd6a5e5a7b7e14"
    );
    // The fingerprint is compared without regard to case.
    assert!(jar::verify_entry_jar(REAL_ENTRY_JAR, &REAL_FINGERPRINT.to_uppercase()).is_ok());
    // Any other fingerprint is a mismatch.
    let e = jar::verify_entry_jar(REAL_ENTRY_JAR, &"00".repeat(32)).unwrap_err();
    assert!(e.contains("REPOSITORY FINGERPRINT MISMATCH"), "{e}");
}

#[test]
fn every_changed_byte_of_the_real_entry_jar_is_refused() {
    // Each entry of the archive changed in one byte: the archive is stored
    // compressed, so change the inflated files and rebuild the JAR.
    let mut f = std::io::Cursor::new(REAL_ENTRY_JAR);
    let layout = crate::apk::zip::Layout::read(&mut f, REAL_ENTRY_JAR.len() as u64).unwrap();
    let names = crate::apk::zip::names(&layout).unwrap();
    let files: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| {
            (
                n.clone(),
                crate::apk::zip::read_entry(&mut f, &layout, n).unwrap(),
            )
        })
        .collect();
    let rebuild = |files: &[(String, Vec<u8>)]| {
        let e: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
        jar(&e)
    };
    // Rebuilt unchanged, it still verifies.
    assert!(jar::verify_entry_jar(&rebuild(&files), REAL_FINGERPRINT).is_ok());
    for i in 0..files.len() {
        let mut t = files.clone();
        let is_sig = t[i].0.ends_with(".RSA");
        let d = &mut t[i].1;
        let at = if is_sig {
            d.len() - 10 // inside the signature value
        } else {
            d.len() / 2
        };
        d[at] ^= 0x01;
        let e = jar::verify_entry_jar(&rebuild(&t), REAL_FINGERPRINT).unwrap_err();
        assert!(
            e.contains("BROKEN") || e.contains("DER") || e.contains("signature"),
            "{}: {e}",
            files[i].0
        );
    }
    // An extra file in the archive.
    let mut t = files.clone();
    t.push(("index-v1.json".into(), b"{}".to_vec()));
    let e = jar::verify_entry_jar(&rebuild(&t), REAL_FINGERPRINT).unwrap_err();
    assert!(e.contains("exactly"), "{e}");
}

#[test]
fn the_real_index_gives_the_newest_release_for_arm64() {
    let index: serde_json::Value = serde_json::from_slice(REAL_INDEX).unwrap();
    let (p, betas) = choose(&index, &real_repo(), &real_want()).unwrap();
    assert_eq!(p.version_code, 397);
    assert_eq!(p.version_name, "7.1.4");
    assert_eq!(p.file, "chat.simplex.app_aarch64_397.apk");
    assert_eq!(
        p.sha256,
        "6339d21c530ebbd6e8bbab34d29a7de874f1c579ee3df7a5d360ff56f7b0df42"
    );
    assert_eq!(p.size, 93_341_184);
    assert_eq!(p.abi, "arm64-v8a");
    assert!(betas.is_empty(), "{betas:?}");
    // A 32-bit phone gets the armv7 build of the same version.
    let mut w = real_want();
    w.abis = vec!["armeabi-v7a".into()];
    let (p, _) = choose(&index, &real_repo(), &w).unwrap();
    assert_eq!(p.file, "chat.simplex.app_armv7_397.apk");
    // Another pinned signer: nothing to install.
    let mut w = real_want();
    w.signer = "ab";
    assert!(choose(&index, &real_repo(), &w).is_err());
    // Another configured repository address.
    let r = Repo {
        url: "https://example.org/fdroid/repo",
        fingerprint: REAL_FINGERPRINT,
    };
    assert!(choose(&index, &r, &real_want())
        .unwrap_err()
        .contains("not the configured"));
}

#[test]
fn betas_are_left_out() {
    for n in [
        "7.1-beta.9",
        "7.1-BETA.10",
        "2.0-alpha1",
        "1.0-rc2",
        "6.4.0.rc1",
    ] {
        assert!(is_prerelease(n), "{n}");
    }
    for n in ["7.1", "7.1.4", "6.5.0"] {
        assert!(!is_prerelease(n), "{n}");
    }
    let (a, b) = (b"release".to_vec(), b"beta".to_vec());
    let s = fingerprint();
    let vs = [
        V {
            code: 391,
            name: "7.1",
            file: "a_391.apk",
            apk: &a,
            abi: "arm64-v8a",
            signer: &s,
        },
        V {
            code: 399,
            name: "7.2-beta.1",
            file: "a_399.apk",
            apk: &b,
            abi: "arm64-v8a",
            signer: &s,
        },
    ];
    let idx: serde_json::Value =
        serde_json::from_slice(&index("https://r.test/repo", "p.q", &vs)).unwrap();
    let want = Want {
        package: "p.q",
        signer: &s,
        abis: vec!["arm64-v8a".into()],
        sdk: 37,
    };
    let repo = Repo {
        url: "https://r.test/repo",
        fingerprint: &s,
    };
    let (p, betas) = choose(&idx, &repo, &want).unwrap();
    assert_eq!(p.version_code, 391);
    assert_eq!(betas, vec!["7.2-beta.1 (399)".to_string()]);
}

#[test]
fn unsafe_file_names_are_refused() {
    for n in [
        "/../x.apk",
        "/a/b.apk",
        "a.apk",
        "/x.apk?y",
        "/.apk",
        "https://evil/x.apk",
    ] {
        assert!(plain_file(n).is_none(), "{n}");
    }
    assert_eq!(
        plain_file("/chat.simplex.app_aarch64_397.apk").unwrap(),
        "chat.simplex.app_aarch64_397.apk"
    );
}

struct Synth {
    http: FakeHttp,
    url: String,
    fp: String,
    apk: Vec<u8>,
}

fn synth(ts: u64) -> Synth {
    let url = "https://repo.test/fdroid/repo".to_string();
    let apk: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let fp = fingerprint();
    let vs = [V {
        code: 7,
        name: "1.0",
        file: "app_7.apk",
        apk: &apk,
        abi: "arm64-v8a",
        signer: &fp,
    }];
    let idx = index(&url, "p.q", &vs);
    let http = FakeHttp::default();
    http.put(&format!("{url}/index-v2.json"), &idx);
    http.put(
        &format!("{url}/entry.jar"),
        &entry_jar(&entry_json(&idx, ts)),
    );
    http.put(&format!("{url}/app_7.apk"), &apk);
    Synth { http, url, fp, apk }
}

fn run(s: &Synth, last: Option<u64>) -> Result<Checked, String> {
    let repo = Repo {
        url: &s.url,
        fingerprint: &s.fp,
    };
    let want = Want {
        package: "p.q",
        signer: &s.fp,
        abis: vec!["arm64-v8a".into()],
        sdk: 37,
    };
    check_index(&s.http, &repo, &want, last, 1_794_700_000, &mut |_| {})
}

#[test]
fn a_synthetic_repository_end_to_end() {
    let s = synth(1_794_696_615_000);
    let c = run(&s, Some(1_794_696_615_000)).unwrap();
    assert_eq!(c.pick.version_code, 7);
    assert_eq!(c.timestamp_ms, 1_794_696_615_000);
    let d = crate::activation::store::tests::temp_dir("fdroid-download");
    let dest = d.join("app.apk");
    let repo = Repo {
        url: &s.url,
        fingerprint: &s.fp,
    };
    download(&s.http, &repo, &c.pick, &dest).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), s.apk);
    // Every request went to the repository, over the one HTTP client.
    assert!(s
        .http
        .urls()
        .iter()
        .all(|u| u.starts_with(&format!("GET {}/", s.url))));
    // A changed APK on the server: refused and deleted.
    let mut bad = s.apk.clone();
    bad[10] ^= 1;
    s.http.put(&format!("{}/app_7.apk", s.url), &bad);
    let dest2 = d.join("bad.apk");
    let e = download(&s.http, &repo, &c.pick, &dest2).unwrap_err();
    assert!(e.contains("is not the one the index names"), "{e}");
    assert!(!dest2.exists());
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn rollback_fingerprint_and_index_tampering_are_refused() {
    // An older index than the one already seen.
    let s = synth(1_794_000_000_000);
    let e = run(&s, Some(1_794_696_615_000)).unwrap_err();
    assert!(e.contains("INDEX ROLLBACK"), "{e}");
    // Pinned to another fingerprint (the real SimpleX one).
    let s = synth(1_794_696_615_000);
    let repo = Repo {
        url: &s.url,
        fingerprint: REAL_FINGERPRINT,
    };
    let want = Want {
        package: "p.q",
        signer: &s.fp,
        abis: vec!["arm64-v8a".into()],
        sdk: 37,
    };
    let e = check_index(&s.http, &repo, &want, None, 0, &mut |_| {}).unwrap_err();
    assert!(e.contains("REPOSITORY FINGERPRINT MISMATCH"), "{e}");
    // The index changed after signing.
    let s = synth(1_794_696_615_000);
    let mut idx = s.http.files.borrow()[&format!("{}/index-v2.json", s.url)].clone();
    let at = idx.len() - 3;
    idx[at] = b' ';
    s.http.put(&format!("{}/index-v2.json", s.url), &idx);
    let e = run(&s, None).unwrap_err();
    assert!(e.contains("INDEX SIGNATURE BROKEN"), "{e}");
    // A SHA-1 signature is refused.
    let s = synth(1_794_696_615_000);
    let idx = s.http.files.borrow()[&format!("{}/index-v2.json", s.url)].clone();
    let ej = entry_json(&idx, 1_794_696_615_000);
    let (mf, sf) = jar_files(&ej);
    let p7 = pkcs7(&sf, CERT_DER, SHA1);
    let j = jar(&[
        ("META-INF/MANIFEST.MF", mf),
        ("META-INF/TEST.SF", sf),
        ("META-INF/TEST.RSA", p7),
        ("entry.json", ej),
    ]);
    s.http.put(&format!("{}/entry.jar", s.url), &j);
    let e = run(&s, None).unwrap_err();
    assert!(e.contains("SHA-1 is refused"), "{e}");
    // The signature made over another file.
    let s = synth(1_794_696_615_000);
    let idx = s.http.files.borrow()[&format!("{}/index-v2.json", s.url)].clone();
    let ej = entry_json(&idx, 1_794_696_615_000);
    let (mf, sf) = jar_files(&ej);
    let p7 = pkcs7(
        b"another file",
        CERT_DER,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
    let j = jar(&[
        ("META-INF/MANIFEST.MF", mf),
        ("META-INF/TEST.SF", sf),
        ("META-INF/TEST.RSA", p7),
        ("entry.json", ej),
    ]);
    s.http.put(&format!("{}/entry.jar", s.url), &j);
    let e = run(&s, None).unwrap_err();
    assert!(e.contains("INDEX SIGNATURE BROKEN"), "{e}");
    // Tor down: a clear error, nothing else tried.
    let s = synth(1_794_696_615_000);
    *s.http.down.borrow_mut() = true;
    assert!(run(&s, None).unwrap_err().contains("connection refused"));
    assert_eq!(s.http.urls().len(), 1);
}
