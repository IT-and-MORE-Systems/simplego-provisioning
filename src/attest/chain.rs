// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Certificate chain validation for key attestation chains.
//!
//! The chain is ordered leaf first, root last (as returned by Android
//! Keystore). Every signature is checked with the next certificate's key, and
//! the last certificate must carry the public key of a pinned trust anchor.
//! Anchors are matched by public key, as the Android documentation phrases it
//! ("contains this public key"): Google has issued four RSA root certificates
//! with one key, and current devices chain to different ones.

use crate::util::{fmt_unix, hex};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use serde::Serialize;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use super::keydesc::OID_KEY_DESCRIPTION;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";

/// A pinned trust anchor (a root certificate).
#[derive(Debug, Clone)]
pub struct Anchor {
    pub name: String,
    pub spki_der: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    cert: Certificate,
}

impl Anchor {
    pub fn from_der(name: &str, der: &[u8]) -> Result<Anchor, String> {
        let cert = Certificate::from_der(der).map_err(|e| format!("anchor {name}: {e}"))?;
        let tbs = cert.tbs_certificate();
        Ok(Anchor {
            name: name.to_string(),
            spki_der: tbs
                .subject_public_key_info()
                .to_der()
                .map_err(|e| e.to_string())?,
            not_before: tbs.validity().not_before.to_unix_duration().as_secs(),
            not_after: tbs.validity().not_after.to_unix_duration().as_secs(),
            cert,
        })
    }

    pub fn from_pem(name: &str, pem: &str) -> Result<Anchor, String> {
        let certs = Certificate::load_pem_chain(pem.as_bytes())
            .map_err(|e| format!("anchor {name}: {e}"))?;
        let [cert] = certs.as_slice() else {
            return Err(format!("anchor {name}: expected exactly one certificate"));
        };
        Anchor::from_der(name, &cert.to_der().map_err(|e| e.to_string())?)
    }

    fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub index: usize,
    pub subject: String,
    /// Serial number, lowercase hex without leading zeros.
    pub serial_hex: String,
    /// Serial number in decimal (the revocation list uses both forms).
    pub serial_dec: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainReport {
    pub certs: Vec<CertSummary>,
    /// Name of the pinned anchor the chain ends at.
    pub anchor: Option<String>,
    pub signatures_ok: bool,
    pub validity_ok: bool,
    /// Why the chain is not accepted. Empty means accepted.
    pub errors: Vec<String>,
    pub notes: Vec<String>,
    /// Value of the KeyDescription extension of the leaf, if the chain is
    /// structurally valid.
    #[serde(skip)]
    pub key_description: Option<Vec<u8>>,
}

impl ChainReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty() && self.anchor.is_some() && self.signatures_ok && self.validity_ok
    }
}

pub fn verify(ders: &[Vec<u8>], anchors: &[Anchor], now: u64) -> ChainReport {
    let mut rep = ChainReport {
        certs: Vec::new(),
        anchor: None,
        signatures_ok: false,
        validity_ok: false,
        errors: Vec::new(),
        notes: Vec::new(),
        key_description: None,
    };
    if ders.len() < 2 {
        rep.errors.push(format!(
            "chain has {} certificate(s), at least 2 needed",
            ders.len()
        ));
        return rep;
    }
    let mut certs = Vec::with_capacity(ders.len());
    for (i, d) in ders.iter().enumerate() {
        match Certificate::from_der(d) {
            Ok(c) => certs.push(c),
            Err(e) => {
                rep.errors
                    .push(format!("certificate {i}: cannot parse: {e}"));
                return rep;
            }
        }
    }
    for (i, c) in certs.iter().enumerate() {
        rep.certs.push(summary(i, c));
    }

    // Signatures and name chaining, leaf to root.
    let mut sig_ok = true;
    for i in 0..certs.len() - 1 {
        let (child, parent) = (&certs[i], &certs[i + 1]);
        if enc(child.tbs_certificate().issuer()) != enc(parent.tbs_certificate().subject()) {
            rep.errors.push(format!(
                "certificate {i}: issuer does not match subject of certificate {}",
                i + 1
            ));
            sig_ok = false;
        }
        if let Err(e) = verify_sig(child, parent) {
            rep.errors.push(format!(
                "certificate {i}: signature by certificate {} invalid: {e}",
                i + 1
            ));
            sig_ok = false;
        }
    }

    // Anchor: the last certificate's key must be a pinned anchor key, and the
    // certificate must be self-signed with it.
    let last = certs.last().expect("len >= 2");
    let last_spki = enc(last.tbs_certificate().subject_public_key_info());
    let matching: Vec<&Anchor> = anchors.iter().filter(|a| a.spki_der == last_spki).collect();
    if matching.is_empty() {
        rep.errors
            .push("root key is not one of the pinned Google attestation root keys".into());
        sig_ok = false;
    } else if let Err(e) = verify_sig(last, last) {
        rep.errors
            .push(format!("root certificate self-signature invalid: {e}"));
        sig_ok = false;
    } else {
        let exact = matching
            .iter()
            .find(|a| a.cert.to_der().ok().as_deref() == ders.last().map(|v| v.as_slice()));
        let chosen = exact.copied().unwrap_or(matching[0]);
        rep.anchor = Some(chosen.name.clone());
        if exact.is_none() {
            rep.notes.push(format!(
                "root certificate differs from the pinned file but has the pinned key of {}",
                chosen.name
            ));
        }
    }
    rep.signatures_ok = sig_ok;

    // Validity of every certificate. For the root, the pinned anchor key is
    // what is trusted: an expired copy of a root (Google's 2016 RSA root
    // expired 2026-05-24) is accepted when a pinned root with the same key is
    // valid now. Every other certificate must be valid now.
    let mut validity_ok = true;
    let n = certs.len();
    for (i, c) in certs.iter().enumerate() {
        let v = c.tbs_certificate().validity();
        let (nb, na) = (
            v.not_before.to_unix_duration().as_secs(),
            v.not_after.to_unix_duration().as_secs(),
        );
        if nb <= now && now <= na {
            continue;
        }
        if i == n - 1 {
            if let Some(a) = matching.iter().find(|a| a.valid_at(now)) {
                rep.notes.push(format!(
                    "root certificate in the chain is outside its validity ({} to {}); its key is the \
                     pinned key of {}, valid until {}",
                    fmt_unix(nb),
                    fmt_unix(na),
                    a.name,
                    fmt_unix(a.not_after)
                ));
                continue;
            }
        }
        rep.errors.push(format!(
            "certificate {i}: not valid at {} (valid {} to {})",
            fmt_unix(now),
            fmt_unix(nb),
            fmt_unix(na)
        ));
        validity_ok = false;
    }
    rep.validity_ok = validity_ok;

    // The KeyDescription must be in the leaf and nowhere else. Counting from
    // the root, only the first attestation extension can be trusted; requiring
    // it to be the leaf's rules out a certificate below an attested key.
    let with_ext: Vec<usize> = certs
        .iter()
        .enumerate()
        .filter(|(_, c)| key_description_ext(c).is_some())
        .map(|(i, _)| i)
        .collect();
    match with_ext.as_slice() {
        [0] => rep.key_description = key_description_ext(&certs[0]),
        [] => rep
            .errors
            .push("no key attestation extension in the chain".into()),
        other => rep.errors.push(format!(
            "key attestation extension found in certificates {other:?}; expected in the leaf only"
        )),
    }
    rep
}

fn enc<T: Encode>(v: &T) -> Vec<u8> {
    v.to_der().unwrap_or_default()
}

fn key_description_ext(c: &Certificate) -> Option<Vec<u8>> {
    c.tbs_certificate()
        .extensions()?
        .iter()
        .find(|e| e.extn_id.to_string() == OID_KEY_DESCRIPTION)
        .map(|e| e.extn_value.as_bytes().to_vec())
}

fn summary(i: usize, c: &Certificate) -> CertSummary {
    let tbs = c.tbs_certificate();
    let serial = tbs.serial_number().as_bytes();
    CertSummary {
        index: i,
        subject: tbs.subject().to_string(),
        serial_hex: serial_hex(serial),
        serial_dec: serial_dec(serial),
        not_before: fmt_unix(tbs.validity().not_before.to_unix_duration().as_secs()),
        not_after: fmt_unix(tbs.validity().not_after.to_unix_duration().as_secs()),
    }
}

/// Lowercase hex without leading zeros ("0" for zero).
pub fn serial_hex(bytes: &[u8]) -> String {
    let h = hex(bytes);
    let t = h.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

/// Decimal form of an unsigned big-endian integer.
pub fn serial_dec(bytes: &[u8]) -> String {
    let mut num: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if num.is_empty() {
        return "0".into();
    }
    let mut digits = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(num.len());
        for &b in &num {
            let cur = rem * 256 + b as u32;
            let q = (cur / 10) as u8;
            rem = cur % 10;
            if !(next.is_empty() && q == 0) {
                next.push(q);
            }
        }
        digits.push(b'0' + rem as u8);
        num = next;
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

fn verify_sig(child: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let tbs = child
        .tbs_certificate()
        .to_der()
        .map_err(|e| e.to_string())?;
    let sig = child
        .signature()
        .as_bytes()
        .ok_or("signature bit string has unused bits")?;
    let sig_alg = child.signature_algorithm().oid.to_string();
    if child.tbs_certificate().signature().oid != child.signature_algorithm().oid {
        return Err("signature algorithm differs between TBS and certificate".into());
    }
    let spki = issuer.tbs_certificate().subject_public_key_info();
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or("public key bit string has unused bits")?;
    let key_alg = spki.algorithm.oid.to_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string());
    let alg: &dyn VerificationAlgorithm =
        match (key_alg.as_str(), curve.as_deref(), sig_alg.as_str()) {
            (OID_RSA, _, OID_SHA256_RSA) => &signature::RSA_PKCS1_2048_8192_SHA256,
            (OID_RSA, _, OID_SHA384_RSA) => &signature::RSA_PKCS1_2048_8192_SHA384,
            (OID_RSA, _, OID_SHA512_RSA) => &signature::RSA_PKCS1_2048_8192_SHA512,
            (OID_EC, Some(OID_P256), OID_ECDSA_SHA256) => &signature::ECDSA_P256_SHA256_ASN1,
            (OID_EC, Some(OID_P256), OID_ECDSA_SHA384) => &signature::ECDSA_P256_SHA384_ASN1,
            (OID_EC, Some(OID_P384), OID_ECDSA_SHA256) => &signature::ECDSA_P384_SHA256_ASN1,
            (OID_EC, Some(OID_P384), OID_ECDSA_SHA384) => &signature::ECDSA_P384_SHA384_ASN1,
            _ => {
                return Err(format!(
                    "unsupported key/signature algorithm {key_alg} {curve:?} {sig_alg}"
                ))
            }
        };
    UnparsedPublicKey::new(alg, key)
        .verify(&tbs, sig)
        .map_err(|_| "signature does not verify".to_string())
}

/// SHA-256 of a certificate's SubjectPublicKeyInfo, for SOURCES.md checks.
#[cfg(test)]
pub fn spki_sha256(a: &Anchor) -> String {
    hex(&crate::util::sha256(&a.spki_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_forms() {
        assert_eq!(serial_hex(&[0x00, 0x0a, 0xbc]), "abc");
        assert_eq!(serial_hex(&[0x00]), "0");
        assert_eq!(serial_dec(&[0x01, 0x00]), "256");
        assert_eq!(serial_dec(&[0x00]), "0");
        // 2^64 - 1
        assert_eq!(serial_dec(&[0xff; 8]), "18446744073709551615");
    }
}
