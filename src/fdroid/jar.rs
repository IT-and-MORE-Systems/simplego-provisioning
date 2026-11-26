// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The signed `entry.jar` of an F-Droid repository (index v2), checked in
//! pure Rust:
//!
//! 1. the JAR holds exactly `META-INF/MANIFEST.MF`, one `META-INF/X.SF`, one
//!    `META-INF/X.RSA` and `entry.json`, nothing else;
//! 2. `X.RSA` is a PKCS#7 `SignedData` with exactly one certificate and one
//!    `SignerInfo`, digest SHA-256, signature RSA PKCS#1 v1.5 with SHA-256,
//!    detached over `X.SF`. Signed attributes, if present, must carry the
//!    content type `data` and the SHA-256 of `X.SF`; the signature then
//!    covers their DER SET. SHA-1 is refused everywhere;
//! 3. the SHA-256 of the certificate is the pinned repository fingerprint;
//!    only then is the signature checked with the certificate's RSA key;
//! 4. `X.SF` names the SHA-256 of the whole manifest and of the manifest
//!    section of `entry.json`; the manifest names the SHA-256 of
//!    `entry.json`.
//!
//! The result is the verified `entry.json`.

use crate::apk::zip::{self, Layout};
use crate::attest::der::{Class, Reader, Tag};
use crate::util::{hex, sha256};
use base64ct::{Base64, Encoding};
use ring::signature::{self, UnparsedPublicKey};
use std::io::Cursor;

/// Largest `entry.jar` accepted (the real one is about 3 KiB).
pub const MAX_ENTRY_JAR: usize = 1024 * 1024;

// DER encodings of the object identifiers (tag, length, value).
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

const OID: Tag = Tag::OID;

const fn ctx(n: u32, constructed: bool) -> Tag {
    Tag {
        class: Class::Context,
        constructed,
        number: n,
    }
}

/// The OID of an `AlgorithmIdentifier` (parameters, if any, are NULL).
fn alg_oid(v: &[u8]) -> Result<&[u8], String> {
    let mut r = Reader::new(v);
    let oid = r.expect(OID)?;
    if !r.is_empty() {
        let p = r.read()?;
        if p.tag != Tag::NULL || !p.value.is_empty() {
            return Err("unexpected algorithm parameters".into());
        }
    }
    r.finish()?;
    Ok(oid)
}

/// What the PKCS#7 signature says, before the key is trusted.
struct Signed<'a> {
    cert: &'a [u8],
    signed_attrs: Option<&'a [u8]>,
    signature: &'a [u8],
}

fn parse_pkcs7(der: &[u8]) -> Result<Signed<'_>, String> {
    let mut top = Reader::new(der);
    let ci = top.expect(Tag::SEQUENCE)?;
    top.finish()?;
    let mut ci = Reader::new(ci);
    if ci.expect(OID)? != OID_SIGNED_DATA {
        return Err("not a PKCS#7 SignedData".into());
    }
    let sd = ci.expect(ctx(0, true))?;
    ci.finish()?;
    let mut sd0 = Reader::new(sd);
    let sd = sd0.expect(Tag::SEQUENCE)?;
    sd0.finish()?;
    let mut sd = Reader::new(sd);
    let _version = sd.expect(Tag::INTEGER)?;
    let algs = sd.expect(Tag::SET)?;
    let mut ar = Reader::new(algs);
    let a = ar.expect(Tag::SEQUENCE)?;
    ar.finish()
        .map_err(|_| "more than one digest algorithm".to_string())?;
    if alg_oid(a)? != OID_SHA256 {
        return Err("the digest algorithm is not SHA-256 (SHA-1 is refused)".into());
    }
    let eci = sd.expect(Tag::SEQUENCE)?;
    let mut eci = Reader::new(eci);
    if eci.expect(OID)? != OID_DATA {
        return Err("the signed content type is not data".into());
    }
    if !eci.is_empty() {
        return Err("the signature is not detached".into());
    }
    let certs = sd.expect(ctx(0, true))?;
    let mut cr = Reader::new(certs);
    let (_, cert) = cr.read_raw()?;
    if !cr.is_empty() {
        return Err("more than one certificate in the signature".into());
    }
    let mut next = sd.read()?;
    if next.tag == ctx(1, true) {
        next = sd.read()?;
    }
    if next.tag != Tag::SET {
        return Err("no signer infos".into());
    }
    sd.finish()?;
    let mut sis = Reader::new(next.value);
    let si = sis.expect(Tag::SEQUENCE)?;
    sis.finish()
        .map_err(|_| "more than one signer".to_string())?;
    let mut si = Reader::new(si);
    let _v = si.expect(Tag::INTEGER)?;
    let _sid = si.read()?;
    let dalg = si.expect(Tag::SEQUENCE)?;
    if alg_oid(dalg)? != OID_SHA256 {
        return Err("the signer's digest is not SHA-256 (SHA-1 is refused)".into());
    }
    let (mut t, mut raw) = si.read_raw()?;
    let mut signed_attrs = None;
    if t.tag == ctx(0, true) {
        signed_attrs = Some(raw);
        (t, raw) = si.read_raw()?;
    }
    let _ = raw;
    if t.tag != Tag::SEQUENCE {
        return Err("damaged signer info".into());
    }
    let salg = alg_oid(t.value)?;
    if salg != OID_RSA && salg != OID_SHA256_RSA {
        return Err("the signature is not RSA PKCS#1 v1.5 with SHA-256".into());
    }
    let signature = si.expect(Tag::OCTET_STRING)?;
    if !si.is_empty() {
        let u = si.read()?;
        if u.tag != ctx(1, true) {
            return Err("damaged signer info".into());
        }
        si.finish()?;
    }
    Ok(Signed {
        cert,
        signed_attrs,
        signature,
    })
}

/// The DER SET the signature covers when signed attributes are present,
/// after checking them: content type `data`, message digest SHA-256(sf).
fn signed_attrs_message(raw: &[u8], sf: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(raw);
    let t = r.read()?;
    let mut set = Reader::new(t.value);
    let (mut ct, mut md) = (false, false);
    while !set.is_empty() {
        let a = set.expect(Tag::SEQUENCE)?;
        let mut a = Reader::new(a);
        let oid = a.expect(OID)?;
        let vals = a.expect(Tag::SET)?;
        a.finish()?;
        let mut v = Reader::new(vals);
        if oid == OID_CONTENT_TYPE {
            ct = v.expect(OID)? == OID_DATA;
        } else if oid == OID_MESSAGE_DIGEST {
            md = v.expect(Tag::OCTET_STRING)? == sha256(sf).as_slice();
        }
    }
    if !ct || !md {
        return Err("the signed attributes do not name the signature file".into());
    }
    // The signature is over the attributes with the tag of a SET.
    let mut m = raw.to_vec();
    m[0] = 0x31;
    Ok(m)
}

fn rsa_key(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_cert::der::Decode;
    let c = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| format!("index certificate: {e}"))?;
    let spki = c.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1" {
        return Err("the index certificate does not hold an RSA key".into());
    }
    spki.subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "damaged public key in the index certificate".into())
}

/// A manifest or signature file split into sections; each keeps its bytes
/// as they are in the file (for the section digests of `.SF`).
struct Section<'a> {
    raw: &'a [u8],
    attrs: Vec<(String, String)>,
}

impl Section<'_> {
    fn get(&self, k: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }
}

fn sections(b: &[u8]) -> Result<Vec<Section<'_>>, String> {
    let text = std::str::from_utf8(b).map_err(|_| "a JAR manifest is not UTF-8")?;
    let mut out = Vec::new();
    let mut start = 0;
    let mut lines: Vec<String> = Vec::new();
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        pos += line.len();
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            if !lines.is_empty() {
                out.push((start, pos, std::mem::take(&mut lines)));
            }
            start = pos;
            continue;
        }
        if let Some(cont) = l.strip_prefix(' ') {
            let last = lines
                .last_mut()
                .ok_or("a JAR manifest starts with a continuation")?;
            last.push_str(cont);
        } else {
            lines.push(l.to_string());
        }
    }
    if !lines.is_empty() {
        out.push((start, pos, lines));
    }
    out.into_iter()
        .map(|(s, e, ls)| {
            let attrs = ls
                .iter()
                .map(|l| {
                    l.split_once(": ")
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or_else(|| format!("damaged JAR manifest line {l:?}"))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(Section {
                raw: &b[s..e],
                attrs,
            })
        })
        .collect()
}

fn b64_sha256(b: &[u8]) -> String {
    Base64::encode_string(&sha256(b))
}

/// Checks `entry.jar` against the pinned repository fingerprint (SHA-256 of
/// the signing certificate, hex, any case) and returns `entry.json`.
pub fn verify_entry_jar(jar: &[u8], fingerprint: &str) -> Result<Vec<u8>, String> {
    if jar.len() > MAX_ENTRY_JAR {
        return Err("entry.jar is larger than 1 MiB".into());
    }
    let mut f = Cursor::new(jar);
    let layout = Layout::read(&mut f, jar.len() as u64).map_err(|e| format!("entry.jar: {e}"))?;
    let names = zip::names(&layout).map_err(|e| format!("entry.jar: {e}"))?;
    let sf_names: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("META-INF/") && n.ends_with(".SF"))
        .collect();
    let [sf_name] = sf_names.as_slice() else {
        return Err("entry.jar must hold exactly one signature file".into());
    };
    let base = sf_name.trim_end_matches(".SF");
    let rsa_name = format!("{base}.RSA");
    let mut want = vec![
        "META-INF/MANIFEST.MF".to_string(),
        (*sf_name).clone(),
        rsa_name.clone(),
        "entry.json".to_string(),
    ];
    let mut have = names.clone();
    want.sort();
    have.sort();
    if have != want {
        return Err(format!(
            "entry.jar must hold exactly MANIFEST.MF, one .SF, its .RSA and entry.json; it holds {names:?}"
        ));
    }
    let read = |n: &str, f: &mut Cursor<&[u8]>| {
        zip::read_entry(f, &layout, n).map_err(|e| format!("entry.jar: {e}"))
    };
    let mf = read("META-INF/MANIFEST.MF", &mut f)?;
    let sf = read(sf_name, &mut f)?;
    let p7 = read(&rsa_name, &mut f)?;
    let entry = read("entry.json", &mut f)?;

    let s = parse_pkcs7(&p7).map_err(|e| format!("entry.jar signature: {e}"))?;
    let got = hex(&sha256(s.cert));
    if !got.eq_ignore_ascii_case(fingerprint) {
        return Err(format!(
            "REPOSITORY FINGERPRINT MISMATCH: the index is signed by the certificate {got}, not by the pinned {}",
            fingerprint.to_ascii_lowercase()
        ));
    }
    let key = rsa_key(s.cert)?;
    let msg = match s.signed_attrs {
        Some(raw) => {
            signed_attrs_message(raw, &sf).map_err(|e| format!("entry.jar signature: {e}"))?
        }
        None => sf.clone(),
    };
    UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &key)
        .verify(&msg, s.signature)
        .map_err(|_| {
            "INDEX SIGNATURE BROKEN: the signature of entry.jar does not verify".to_string()
        })?;

    let sfs = sections(&sf)?;
    let main = sfs.first().ok_or("empty signature file")?;
    let whole = main
        .get("SHA-256-Digest-Manifest")
        .ok_or("the signature file has no SHA-256 manifest digest (SHA-1 is refused)")?;
    if whole != b64_sha256(&mf) {
        return Err(
            "INDEX SIGNATURE BROKEN: the manifest does not match the signature file".into(),
        );
    }
    let mfs = sections(&mf)?;
    let entry_sec = mfs
        .iter()
        .find(|s| s.get("Name") == Some("entry.json"))
        .ok_or("the manifest has no section for entry.json")?;
    if let Some(sec) = sfs.iter().find(|s| s.get("Name") == Some("entry.json")) {
        if sec.get("SHA-256-Digest") != Some(b64_sha256(entry_sec.raw).as_str()) {
            return Err(
                "INDEX SIGNATURE BROKEN: the manifest section of entry.json does not match".into(),
            );
        }
    }
    if entry_sec.get("SHA-256-Digest") != Some(b64_sha256(&entry).as_str()) {
        return Err("INDEX SIGNATURE BROKEN: entry.json does not match the manifest".into());
    }
    Ok(entry)
}
