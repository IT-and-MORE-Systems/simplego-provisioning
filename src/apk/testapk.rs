// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Synthetic APKs for the tests: a binary manifest, a ZIP archive and an
//! APK Signing Block (v2 or v3, ECDSA P-256), signed with a key that exists
//! only in the test process. Never a real signing key.

use super::axml::{ATTR_VERSION_CODE, ATTR_VERSION_NAME};
use super::sigblock::{self, ID_V2, ID_V3, MAGIC, SIG_ECDSA_SHA256};
use super::zip::Layout;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use std::io::Cursor;

pub struct TestKey {
    pkcs8: Vec<u8>,
    pub cert_der: Vec<u8>,
}

impl TestKey {
    pub fn new(name: &str) -> TestKey {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let kp = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("TEST ONLY apk signer {name}"),
        );
        let cert = p.self_signed(&kp).unwrap();
        TestKey {
            pkcs8,
            cert_der: cert.der().to_vec(),
        }
    }

    pub fn digest_hex(&self) -> String {
        crate::util::hex(&crate::util::sha256(&self.cert_der))
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8, &rng).unwrap();
        kp.sign(&rng, msg).unwrap().as_ref().to_vec()
    }

    fn spki(&self) -> Vec<u8> {
        use x509_cert::der::{Decode, Encode};
        let c = x509_cert::Certificate::from_der(&self.cert_der).unwrap();
        let s = c
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        // Same key as the pkcs8 (checked once here).
        let rng = SystemRandom::new();
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.pkcs8, &rng).unwrap();
        assert!(s.ends_with(kp.public_key().as_ref()));
        s
    }
}

pub struct Spec<'a> {
    pub package: &'a str,
    pub version_code: u32,
    pub version_name: &'a str,
    pub v3: bool,
    pub deflate_manifest: bool,
    /// Extra bytes in a stored entry, to make files of different hashes.
    pub filler: Vec<u8>,
    /// Hosts of one `autoVerify` https filter on an activity (app links).
    pub link_hosts: Vec<&'a str>,
    /// One more https filter whose host is a resource reference.
    pub link_host_ref: bool,
}

impl Spec<'_> {
    pub fn new(package: &str, version_code: u32) -> Spec<'_> {
        Spec {
            package,
            version_code,
            version_name: "1.0-test",
            v3: false,
            deflate_manifest: true,
            filler: b"classes".to_vec(),
            link_hosts: Vec::new(),
            link_host_ref: false,
        }
    }
}

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Compiled manifest with package, versionCode and versionName.
pub fn manifest(package: &str, version_code: u32, version_name: &str) -> Vec<u8> {
    let strings = [
        "versionCode",
        "versionName",
        "package",
        "manifest",
        package,
        version_name,
    ];
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in &strings {
        offsets.push(data.len() as u32);
        data.push(s.chars().count() as u8);
        data.push(s.len() as u8);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let mut pool = Vec::new();
    let start = 28 + 4 * strings.len() as u32;
    u16le(&mut pool, 0x0001);
    u16le(&mut pool, 28);
    u32le(&mut pool, start + data.len() as u32);
    u32le(&mut pool, strings.len() as u32);
    u32le(&mut pool, 0);
    u32le(&mut pool, 0x100);
    u32le(&mut pool, start);
    u32le(&mut pool, 0);
    for o in offsets {
        u32le(&mut pool, o);
    }
    pool.extend_from_slice(&data);

    let mut resmap = Vec::new();
    u16le(&mut resmap, 0x0180);
    u16le(&mut resmap, 8);
    u32le(&mut resmap, 16);
    u32le(&mut resmap, ATTR_VERSION_CODE);
    u32le(&mut resmap, ATTR_VERSION_NAME);

    let attr = |v: &mut Vec<u8>, name: u32, raw: u32, ty: u8, d: u32| {
        u32le(v, u32::MAX);
        u32le(v, name);
        u32le(v, raw);
        u16le(v, 8);
        v.push(0);
        v.push(ty);
        u32le(v, d);
    };
    let mut el = Vec::new();
    u16le(&mut el, 0x0102);
    u16le(&mut el, 16);
    u32le(&mut el, 16 + 20 + 3 * 20);
    u32le(&mut el, 1);
    u32le(&mut el, u32::MAX);
    u32le(&mut el, u32::MAX);
    u32le(&mut el, 3);
    u16le(&mut el, 20);
    u16le(&mut el, 20);
    u16le(&mut el, 3);
    u16le(&mut el, 0);
    u16le(&mut el, 0);
    u16le(&mut el, 0);
    attr(&mut el, 2, 4, 0x03, 4);
    attr(&mut el, 0, u32::MAX, 0x10, version_code);
    attr(&mut el, 1, 5, 0x03, 5);

    let mut out = Vec::new();
    u16le(&mut out, 0x0003);
    u16le(&mut out, 8);
    u32le(&mut out, (8 + pool.len() + resmap.len() + el.len()) as u32);
    out.extend_from_slice(&pool);
    out.extend_from_slice(&resmap);
    out.extend_from_slice(&el);
    out
}

/// A manifest with an application, one activity and its intent filters:
/// a launcher filter, a custom scheme filter (`simplex:`, never verified),
/// an `autoVerify` https filter with `hosts` (if any), and with `host_ref`
/// an https filter whose host is a resource reference.
pub fn manifest_with_links(
    package: &str,
    version_code: u32,
    version_name: &str,
    hosts: &[&str],
    host_ref: bool,
) -> Vec<u8> {
    use super::axml::{ATTR_AUTO_VERIFY, ATTR_HOST, ATTR_NAME, ATTR_SCHEME};
    // The attribute names with a resource id come first (the resource map
    // is indexed by string pool position).
    let mut strings: Vec<String> = [
        "versionCode",
        "versionName",
        "name",
        "scheme",
        "host",
        "autoVerify",
        "package",
        "manifest",
        "application",
        "activity",
        "intent-filter",
        "action",
        "category",
        "data",
        package,
        version_name,
        "x.MainActivity",
        "android.intent.action.MAIN",
        "android.intent.action.VIEW",
        "android.intent.category.BROWSABLE",
        "simplex",
        "https",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let first_host = strings.len() as u32;
    strings.extend(hosts.iter().map(|h| h.to_string()));
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in &strings {
        offsets.push(data.len() as u32);
        data.push(s.chars().count() as u8);
        data.push(s.len() as u8);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let mut pool = Vec::new();
    let start = 28 + 4 * strings.len() as u32;
    u16le(&mut pool, 0x0001);
    u16le(&mut pool, 28);
    u32le(&mut pool, start + data.len() as u32);
    u32le(&mut pool, strings.len() as u32);
    u32le(&mut pool, 0);
    u32le(&mut pool, 0x100);
    u32le(&mut pool, start);
    u32le(&mut pool, 0);
    for o in offsets {
        u32le(&mut pool, o);
    }
    pool.extend_from_slice(&data);
    let mut resmap = Vec::new();
    let ids = [
        ATTR_VERSION_CODE,
        ATTR_VERSION_NAME,
        ATTR_NAME,
        ATTR_SCHEME,
        ATTR_HOST,
        ATTR_AUTO_VERIFY,
    ];
    u16le(&mut resmap, 0x0180);
    u16le(&mut resmap, 8);
    u32le(&mut resmap, 8 + 4 * ids.len() as u32);
    for i in ids {
        u32le(&mut resmap, i);
    }
    // (name index, raw string index or MAX, type, data)
    type A = (u32, u32, u8, u32);
    let s = |i: u32| -> A { (0, i, 0x03, i) };
    let start_el = |out: &mut Vec<u8>, name: u32, attrs: &[A]| {
        u16le(out, 0x0102);
        u16le(out, 16);
        u32le(out, 16 + 20 + 20 * attrs.len() as u32);
        u32le(out, 1);
        u32le(out, u32::MAX);
        u32le(out, u32::MAX);
        u32le(out, name);
        u16le(out, 20);
        u16le(out, 20);
        u16le(out, attrs.len() as u16);
        u16le(out, 0);
        u16le(out, 0);
        u16le(out, 0);
        for (n, raw, ty, d) in attrs {
            u32le(out, u32::MAX);
            u32le(out, *n);
            u32le(out, *raw);
            u16le(out, 8);
            out.push(0);
            out.push(*ty);
            u32le(out, *d);
        }
    };
    let end_el = |out: &mut Vec<u8>, name: u32| {
        u16le(out, 0x0103);
        u16le(out, 16);
        u32le(out, 24);
        u32le(out, 1);
        u32le(out, u32::MAX);
        u32le(out, u32::MAX);
        u32le(out, name);
    };
    let with = |a: A, n: u32| -> A { (n, a.1, a.2, a.3) };
    let mut el = Vec::new();
    start_el(
        &mut el,
        7,
        &[
            with(s(14), 6),
            (0, u32::MAX, 0x10, version_code),
            with(s(15), 1),
        ],
    );
    start_el(&mut el, 8, &[]);
    start_el(&mut el, 9, &[with(s(16), 2)]);
    // Launcher filter: no data, left out by the reader.
    start_el(&mut el, 10, &[]);
    start_el(&mut el, 11, &[with(s(17), 2)]);
    end_el(&mut el, 11);
    end_el(&mut el, 10);
    // A custom scheme: never verified, left out.
    start_el(&mut el, 10, &[]);
    start_el(&mut el, 11, &[with(s(18), 2)]);
    end_el(&mut el, 11);
    start_el(&mut el, 13, &[with(s(20), 3)]);
    end_el(&mut el, 13);
    end_el(&mut el, 10);
    if !hosts.is_empty() {
        start_el(&mut el, 10, &[(5, u32::MAX, 0x12, u32::MAX)]);
        start_el(&mut el, 11, &[with(s(18), 2)]);
        end_el(&mut el, 11);
        start_el(&mut el, 12, &[with(s(19), 2)]);
        end_el(&mut el, 12);
        start_el(&mut el, 13, &[with(s(21), 3)]);
        end_el(&mut el, 13);
        for k in 0..hosts.len() as u32 {
            start_el(&mut el, 13, &[with(s(first_host + k), 4)]);
            end_el(&mut el, 13);
        }
        end_el(&mut el, 10);
    }
    if host_ref {
        start_el(&mut el, 10, &[]);
        start_el(
            &mut el,
            13,
            &[with(s(21), 3), (4, u32::MAX, 0x01, 0x7f13_00a1)],
        );
        end_el(&mut el, 13);
        end_el(&mut el, 10);
    }
    end_el(&mut el, 9);
    end_el(&mut el, 8);
    end_el(&mut el, 7);
    let mut out = Vec::new();
    u16le(&mut out, 0x0003);
    u16le(&mut out, 8);
    u32le(&mut out, (8 + pool.len() + resmap.len() + el.len()) as u32);
    out.extend_from_slice(&pool);
    out.extend_from_slice(&resmap);
    out.extend_from_slice(&el);
    out
}

/// ZIP archive of `(name, data, deflate)` entries, without a signing block.
pub fn zip(entries: &[(&str, Vec<u8>, bool)]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut cd = Vec::new();
    for (name, data, deflate) in entries {
        let stored = if *deflate {
            miniz_oxide::deflate::compress_to_vec(data, 6)
        } else {
            data.clone()
        };
        let offset = body.len() as u32;
        let method: u16 = if *deflate { 8 } else { 0 };
        u32le(&mut body, 0x0403_4b50);
        u16le(&mut body, 20);
        u16le(&mut body, 0);
        u16le(&mut body, method);
        u32le(&mut body, 0);
        u32le(&mut body, 0);
        u32le(&mut body, stored.len() as u32);
        u32le(&mut body, data.len() as u32);
        u16le(&mut body, name.len() as u16);
        u16le(&mut body, 0);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&stored);

        u32le(&mut cd, 0x0201_4b50);
        u16le(&mut cd, 20);
        u16le(&mut cd, 20);
        u16le(&mut cd, 0);
        u16le(&mut cd, method);
        u32le(&mut cd, 0);
        u32le(&mut cd, 0);
        u32le(&mut cd, stored.len() as u32);
        u32le(&mut cd, data.len() as u32);
        u16le(&mut cd, name.len() as u16);
        u16le(&mut cd, 0);
        u16le(&mut cd, 0);
        u16le(&mut cd, 0);
        u16le(&mut cd, 0);
        u32le(&mut cd, 0);
        u32le(&mut cd, offset);
        cd.extend_from_slice(name.as_bytes());
    }
    let mut out = body.clone();
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&cd);
    u32le(&mut out, 0x0605_4b50);
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, entries.len() as u16);
    u16le(&mut out, entries.len() as u16);
    u32le(&mut out, cd.len() as u32);
    u32le(&mut out, cd_offset);
    u16le(&mut out, 0);
    out
}

fn lp(v: &[u8]) -> Vec<u8> {
    let mut o = (v.len() as u32).to_le_bytes().to_vec();
    o.extend_from_slice(v);
    o
}

/// Inserts an APK Signing Block (v2 or v3) signed with `key`.
pub fn sign(unsigned: &[u8], key: &TestKey, v3: bool) -> Vec<u8> {
    let layout = Layout::read(&mut Cursor::new(unsigned), unsigned.len() as u64).unwrap();
    let entries_len = layout.cd_offset;
    let digest = sigblock::content_digest(
        &mut Cursor::new(unsigned),
        &layout,
        entries_len,
        SIG_ECDSA_SHA256,
    )
    .unwrap();
    let mut digest_item = SIG_ECDSA_SHA256.to_le_bytes().to_vec();
    digest_item.extend(lp(&digest));
    let mut signed = lp(&lp(&digest_item));
    signed.extend(lp(&lp(&key.cert_der)));
    if v3 {
        signed.extend(28u32.to_le_bytes());
        signed.extend(0x7fff_ffffu32.to_le_bytes());
    }
    signed.extend(lp(&[]));
    let mut sig_item = SIG_ECDSA_SHA256.to_le_bytes().to_vec();
    sig_item.extend(lp(&key.sign(&signed)));
    let mut signer = lp(&signed);
    if v3 {
        signer.extend(28u32.to_le_bytes());
        signer.extend(0x7fff_ffffu32.to_le_bytes());
    }
    signer.extend(lp(&lp(&sig_item)));
    signer.extend(lp(&key.spki()));
    let value = lp(&lp(&signer));
    let id = if v3 { ID_V3 } else { ID_V2 };
    let mut pair = ((value.len() + 4) as u64).to_le_bytes().to_vec();
    pair.extend(id.to_le_bytes());
    pair.extend(&value);
    let size = (8 + pair.len() + 8 + 16) as u64 - 8;
    let mut block = size.to_le_bytes().to_vec();
    block.extend(&pair);
    block.extend(size.to_le_bytes());
    block.extend(MAGIC);

    let mut out = unsigned[..entries_len as usize].to_vec();
    out.extend(&block);
    out.extend(&layout.cd);
    let mut eocd = layout.eocd.clone();
    eocd[16..20].copy_from_slice(&((entries_len as usize + block.len()) as u32).to_le_bytes());
    out.extend(eocd);
    out
}

/// A complete signed test APK.
pub fn build(spec: &Spec, key: &TestKey) -> Vec<u8> {
    let unsigned = zip(&[
        (
            "AndroidManifest.xml",
            if spec.link_hosts.is_empty() && !spec.link_host_ref {
                manifest(spec.package, spec.version_code, spec.version_name)
            } else {
                manifest_with_links(
                    spec.package,
                    spec.version_code,
                    spec.version_name,
                    &spec.link_hosts,
                    spec.link_host_ref,
                )
            },
            spec.deflate_manifest,
        ),
        ("classes.dex", spec.filler.clone(), false),
    ]);
    sign(&unsigned, key, spec.v3)
}
