// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Synthetic F-Droid repositories for the tests: an `entry.jar` signed like
//! the real one (PKCS#7, SHA-256, RSA, no signed attributes) with the TEST
//! ONLY key in `tests/fixtures/fdroid`, and an `index-v2.json`. Never a
//! real key.

use crate::util::{hex, sha256};
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};

pub const KEY_PKCS1: &[u8] =
    include_bytes!("../../tests/fixtures/fdroid/test-only-repo-key-pkcs1.der");
pub const CERT_DER: &[u8] = include_bytes!("../../tests/fixtures/fdroid/test-only-repo-cert.der");
pub const REAL_ENTRY_JAR: &[u8] = include_bytes!("../../tests/fixtures/fdroid/simplex-entry.jar");
pub const REAL_INDEX: &[u8] = include_bytes!("../../tests/fixtures/fdroid/simplex-index-v2.json");
pub const REAL_FINGERPRINT: &str =
    "9f358ff284d1f71656a2bfaf0e005deae6aa14143720e089f11ff2ddcfeb01ba";
pub const REAL_SIGNER: &str = "3c52c4fd3cad1c07c9b00a7080e358fab9fefcb8af5aec147765f16d0f21ad85";
pub const REAL_URL: &str = "https://app.simplex.chat/fdroid/repo";

pub fn fingerprint() -> String {
    hex(&sha256(CERT_DER))
}

fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let b: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&x| x == 0)
            .collect();
        let mut v = vec![0x80 | b.len() as u8];
        v.extend(b);
        v
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(len(content.len()));
    v.extend_from_slice(content);
    v
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

fn alg(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &cat(&[tlv(0x06, oid), vec![0x05, 0x00]]))
}

/// RSA PKCS#1 v1.5 SHA-256 with the TEST ONLY key.
pub fn rsa_sign(msg: &[u8]) -> Vec<u8> {
    let kp = ring::signature::RsaKeyPair::from_der(KEY_PKCS1).unwrap();
    let mut sig = vec![0u8; kp.public().modulus_len()];
    kp.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        msg,
        &mut sig,
    )
    .unwrap();
    sig
}

/// A detached PKCS#7 `SignedData` over `sf`.
pub fn pkcs7(sf: &[u8], cert: &[u8], digest_oid: &[u8]) -> Vec<u8> {
    let sig = rsa_sign(sf);
    let signer = tlv(
        0x30,
        &cat(&[
            tlv(0x02, &[1]),
            tlv(0x30, &cat(&[tlv(0x30, &[]), tlv(0x02, &[1])])),
            alg(digest_oid),
            alg(RSA),
            tlv(0x04, &sig),
        ]),
    );
    let sd = tlv(
        0x30,
        &cat(&[
            tlv(0x02, &[1]),
            tlv(0x31, &alg(digest_oid)),
            tlv(0x30, &tlv(0x06, DATA)),
            tlv(0xa0, cert),
            tlv(0x31, &signer),
        ]),
    );
    tlv(0x30, &cat(&[tlv(0x06, SIGNED_DATA), tlv(0xa0, &sd)]))
}

fn b64(b: &[u8]) -> String {
    Base64::encode_string(&sha256(b))
}

/// The three signed files of `entry.jar` for `entry_json`.
pub fn jar_files(entry_json: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let section = format!(
        "Name: entry.json\r\nSHA-256-Digest: {}\r\n\r\n",
        b64(entry_json)
    );
    let mf = format!("Manifest-Version: 1.0\r\n\r\n{section}");
    let sf = format!(
        "Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\nSHA-256-Digest-Manifest: {}\r\n\r\nName: entry.json\r\nSHA-256-Digest: {}\r\n\r\n",
        b64(mf.as_bytes()),
        b64(section.as_bytes())
    );
    (mf.into_bytes(), sf.into_bytes())
}

pub fn jar(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let e: Vec<(&str, Vec<u8>, bool)> =
        entries.iter().map(|(n, d)| (*n, d.clone(), true)).collect();
    crate::apk::testapk::zip(&e)
}

/// A signed `entry.jar` for this `entry.json`.
pub fn entry_jar(entry_json: &[u8]) -> Vec<u8> {
    let (mf, sf) = jar_files(entry_json);
    let p7 = pkcs7(&sf, CERT_DER, SHA256);
    jar(&[
        ("META-INF/MANIFEST.MF", mf),
        ("META-INF/TEST.SF", sf),
        ("META-INF/TEST.RSA", p7),
        ("entry.json", entry_json.to_vec()),
    ])
}

pub fn entry_json(index: &[u8], timestamp_ms: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "timestamp": timestamp_ms, "version": 20002,
        "index": {"name": "/index-v2.json", "sha256": hex(&sha256(index)), "size": index.len(), "numPackages": 1}
    }))
    .unwrap()
}

/// One version entry of the index.
pub struct V<'a> {
    pub code: u64,
    pub name: &'a str,
    pub file: &'a str,
    pub apk: &'a [u8],
    pub abi: &'a str,
    pub signer: &'a str,
}

pub fn index(url: &str, package: &str, versions: &[V]) -> Vec<u8> {
    let mut vs = serde_json::Map::new();
    for v in versions {
        let sha = hex(&sha256(v.apk));
        vs.insert(
            sha.clone(),
            json!({"added": 1_794_696_613_000u64,
                   "file": {"name": format!("/{}", v.file), "sha256": sha, "size": v.apk.len()},
                   "manifest": {"nativecode": [v.abi], "versionName": v.name, "versionCode": v.code,
                                "usesSdk": {"minSdkVersion": 26, "targetSdkVersion": 36},
                                "signer": {"sha256": [v.signer]}}}),
        );
    }
    serde_json::to_vec(&json!({
        "repo": {"address": url, "timestamp": 1_794_696_615_000u64},
        "packages": {package: {"metadata": {}, "versions": Value::Object(vs)}}
    }))
    .unwrap()
}
