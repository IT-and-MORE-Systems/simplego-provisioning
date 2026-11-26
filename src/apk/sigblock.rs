// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! APK Signing Block, APK Signature Scheme v2 and v3 (v3.1), verified.
//!
//! Layout before the central directory: `u64 size`, pairs of
//! (`u64 len`, `u32 id`, value), `u64 size`, magic `APK Sig Block 42`.
//! Every v2/v3 value is a length-prefixed list of length-prefixed signers.

use super::zip::{le32, Layout};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use std::io::{Read, Seek, SeekFrom};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

pub const MAGIC: &[u8; 16] = b"APK Sig Block 42";
pub const ID_V2: u32 = 0x7109_871a;
pub const ID_V3: u32 = 0xf053_68c0;
pub const ID_V31: u32 = 0x1b93_ad61;
const MAX_BLOCK: u64 = 32 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;

pub const SIG_RSA_PSS_SHA256: u32 = 0x0101;
pub const SIG_RSA_PSS_SHA512: u32 = 0x0102;
pub const SIG_RSA_PKCS1_SHA256: u32 = 0x0103;
pub const SIG_RSA_PKCS1_SHA512: u32 = 0x0104;
pub const SIG_ECDSA_SHA256: u32 = 0x0201;
pub const SIG_ECDSA_SHA512: u32 = 0x0202;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

#[derive(Debug, Clone)]
pub struct Signer {
    pub scheme: &'static str,
    pub cert_sha256: Vec<u8>,
    /// The chosen signer's certificate (DER).
    pub cert_der: Vec<u8>,
    /// Set when the chosen signer is an RSA key under 2048 bits: its size.
    pub legacy_rsa_bits: Option<usize>,
}

fn le64(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

/// A cursor over length-prefixed (u32 little-endian) fields.
struct Lp<'a>(&'a [u8]);

impl<'a> Lp<'a> {
    fn u32(&mut self) -> Result<u32, String> {
        if self.0.len() < 4 {
            return Err("damaged signature block".into());
        }
        let v = le32(self.0, 0);
        self.0 = &self.0[4..];
        Ok(v)
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        if self.0.len() < n {
            return Err("damaged signature block".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The id/value pairs of the APK Signing Block.
pub type Pairs = Vec<(u32, Vec<u8>)>;

/// The pairs of the APK Signing Block, and where the block starts.
pub fn read_block<R: Read + Seek>(f: &mut R, layout: &Layout) -> Result<(u64, Pairs), String> {
    if layout.cd_offset < 32 {
        return Err("no APK Signing Block (v1-only or unsigned APK refused)".into());
    }
    let mut foot = [0u8; 24];
    f.seek(SeekFrom::Start(layout.cd_offset - 24))
        .and_then(|_| f.read_exact(&mut foot))
        .map_err(|e| format!("read error: {e}"))?;
    if &foot[8..24] != MAGIC {
        return Err("no APK Signing Block (v1-only or unsigned APK refused)".into());
    }
    let size = le64(&foot, 0);
    if !(32..=MAX_BLOCK).contains(&size) || size + 8 > layout.cd_offset {
        return Err("damaged APK Signing Block size".into());
    }
    let start = layout.cd_offset - size - 8;
    let mut block = vec![0u8; (size + 8) as usize];
    f.seek(SeekFrom::Start(start))
        .and_then(|_| f.read_exact(&mut block))
        .map_err(|e| format!("read error: {e}"))?;
    if le64(&block, 0) != size {
        return Err("APK Signing Block sizes differ".into());
    }
    let pairs_end = block.len() - 24;
    let mut i = 8;
    let mut pairs = Vec::new();
    while i < pairs_end {
        if i + 12 > pairs_end {
            return Err("damaged APK Signing Block pair".into());
        }
        let len = le64(&block, i) as usize;
        if len < 4 || i + 8 + len > pairs_end {
            return Err("damaged APK Signing Block pair".into());
        }
        let id = le32(&block, i + 8);
        pairs.push((id, block[i + 12..i + 8 + len].to_vec()));
        i += 8 + len;
    }
    Ok((start, pairs))
}

/// Verifies the strongest present scheme and returns its signer.
pub fn verify<R: Read + Seek>(f: &mut R, layout: &Layout) -> Result<Signer, String> {
    let (start, pairs) = read_block(f, layout)?;
    let get = |id: u32| -> Result<Option<&[u8]>, String> {
        let m: Vec<&[u8]> = pairs
            .iter()
            .filter(|(i, _)| *i == id)
            .map(|(_, v)| v.as_slice())
            .collect();
        match m.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(one)),
            _ => Err(format!(
                "signature scheme block {id:#x} present more than once"
            )),
        }
    };
    let (scheme, value, v3) = if let Some(v) = get(ID_V31)? {
        ("v3.1", v, true)
    } else if let Some(v) = get(ID_V3)? {
        ("v3", v, true)
    } else if let Some(v) = get(ID_V2)? {
        ("v2", v, false)
    } else {
        return Err("no v2 or v3 signature in the APK Signing Block".into());
    };
    let mut list = Lp(value);
    let signers = Lp(list.field()?);
    if !list.empty() {
        return Err("damaged signer list".into());
    }
    let mut signers = signers;
    let mut found = Vec::new();
    while !signers.empty() {
        found.push(signers.field()?);
    }
    let [signer] = found.as_slice() else {
        return Err(format!(
            "{scheme}: {} signers; exactly one is supported",
            found.len()
        ));
    };
    let (cert, legacy_rsa_bits) = verify_signer(signer, v3, scheme)?;
    let wanted = content_digest_wanted(signer, v3)?;
    let actual = content_digest(f, layout, start, wanted.0)?;
    if actual != wanted.1 {
        return Err(format!(
            "{scheme}: the file contents do not match the signature (content digest differs)"
        ));
    }
    // The weaker schemes next to the chosen one must verify too.
    let others: &[(u32, bool, &str)] = match scheme {
        "v3.1" => &[(ID_V3, true, "v3"), (ID_V2, false, "v2")],
        "v3" => &[(ID_V2, false, "v2")],
        _ => &[],
    };
    for (id, is_v3, name) in others {
        if let Some(v) = get(*id)? {
            let mut l = Lp(v);
            let mut s = Lp(l.field()?);
            while !s.empty() {
                verify_signer(s.field()?, *is_v3, name)?;
            }
        }
    }
    Ok(Signer {
        scheme,
        cert_sha256: crate::util::sha256(&cert),
        cert_der: cert.to_vec(),
        legacy_rsa_bits,
    })
}

/// The verifier for one signature algorithm and key, and the RSA key size
/// when it is under 2048 bits. Such keys (Orbot's signer is RSA 1024) are
/// checked with ring's legacy PKCS#1 v1.5 verifier, which takes 1024 to
/// 8192 bits; RSA-PSS and keys under 1024 bits stay refused.
fn alg_for(
    sig_alg: u32,
    spki: &[u8],
) -> Result<(&'static dyn VerificationAlgorithm, Option<usize>), String> {
    let s = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|e| format!("signer public key: {e}"))?;
    let key_alg = s.algorithm.oid.to_string();
    let curve = s
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string());
    let legacy = if key_alg == OID_RSA {
        let bits =
            rsa_modulus_bits(&key_bits(spki)?).ok_or("signer public key: damaged RSA key")?;
        (bits < 2048).then_some(bits)
    } else {
        None
    };
    let alg: &'static dyn VerificationAlgorithm =
        match (sig_alg, key_alg.as_str(), curve.as_deref(), legacy) {
            (SIG_RSA_PSS_SHA256, OID_RSA, _, None) => &signature::RSA_PSS_2048_8192_SHA256,
            (SIG_RSA_PSS_SHA512, OID_RSA, _, None) => &signature::RSA_PSS_2048_8192_SHA512,
            (SIG_RSA_PKCS1_SHA256, OID_RSA, _, None) => &signature::RSA_PKCS1_2048_8192_SHA256,
            (SIG_RSA_PKCS1_SHA512, OID_RSA, _, None) => &signature::RSA_PKCS1_2048_8192_SHA512,
            (SIG_RSA_PKCS1_SHA256, OID_RSA, _, Some(1024..)) => {
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
            }
            (SIG_RSA_PKCS1_SHA512, OID_RSA, _, Some(1024..)) => {
                &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
            }
            (SIG_ECDSA_SHA256, OID_EC, Some(OID_P256), _) => &signature::ECDSA_P256_SHA256_ASN1,
            (SIG_ECDSA_SHA256, OID_EC, Some(OID_P384), _) => &signature::ECDSA_P384_SHA256_ASN1,
            _ => return Err(format!("unsupported signature algorithm {sig_alg:#06x}")),
        };
    Ok((alg, legacy))
}

/// Modulus size in bits of a PKCS#1 `RSAPublicKey` (DER).
fn rsa_modulus_bits(key: &[u8]) -> Option<usize> {
    // One DER element with the expected tag: (contents, rest).
    fn element(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (&t, b) = b.split_first()?;
        if t != tag {
            return None;
        }
        let (&l0, mut b) = b.split_first()?;
        let len = if l0 < 0x80 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 || b.len() < n {
                return None;
            }
            let v = b[..n].iter().fold(0usize, |v, &x| (v << 8) | x as usize);
            b = &b[n..];
            v
        };
        (b.len() >= len).then(|| (&b[..len], &b[len..]))
    }
    let (seq, _) = element(key, 0x30)?;
    let (n, _) = element(seq, 0x02)?;
    let n = &n[n.iter().position(|&x| x != 0)?..];
    Some(n.len() * 8 - n[0].leading_zeros() as usize)
}

fn key_bits(spki: &[u8]) -> Result<Vec<u8>, String> {
    let s = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|e| format!("signer public key: {e}"))?;
    s.subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "public key bit string has unused bits".into())
}

/// Order of preference: SHA-512 variants first, then SHA-256.
fn rank(alg: u32) -> u8 {
    match alg {
        SIG_RSA_PSS_SHA512 | SIG_RSA_PKCS1_SHA512 | SIG_ECDSA_SHA512 => 2,
        SIG_RSA_PSS_SHA256 | SIG_RSA_PKCS1_SHA256 | SIG_ECDSA_SHA256 => 1,
        _ => 0,
    }
}

/// Verifies one signer; returns its first certificate (DER) and the RSA key
/// size when it is under 2048 bits.
fn verify_signer(
    signer: &[u8],
    v3: bool,
    scheme: &str,
) -> Result<(Vec<u8>, Option<usize>), String> {
    let mut s = Lp(signer);
    let signed = s.field()?;
    if v3 {
        let _min_sdk = s.u32()?;
        let _max_sdk = s.u32()?;
    }
    let sigs = s.field()?;
    let pubkey = s.field()?;
    // Pick the strongest signature this tool can check.
    let mut l = Lp(sigs);
    let mut best: Option<(u32, &[u8])> = None;
    while !l.empty() {
        let mut one = Lp(l.field()?);
        let alg = one.u32()?;
        let sig = one.field()?;
        if alg_for(alg, pubkey).is_ok() && best.is_none_or(|(b, _)| rank(alg) > rank(b)) {
            best = Some((alg, sig));
        }
    }
    let (alg, sig) = best.ok_or(format!("{scheme}: no supported signature algorithm"))?;
    let (verifier, legacy) = alg_for(alg, pubkey)?;
    UnparsedPublicKey::new(verifier, key_bits(pubkey)?)
        .verify(signed, sig)
        .map_err(|_| format!("{scheme}: signature does not verify"))?;
    // Signed data: digests, certificates, (v3: min/max SDK), attributes.
    let mut d = Lp(signed);
    let digests = d.field()?;
    let certs = d.field()?;
    let mut algs_in_digests = Vec::new();
    let mut dl = Lp(digests);
    while !dl.empty() {
        let mut one = Lp(dl.field()?);
        algs_in_digests.push(one.u32()?);
    }
    if !algs_in_digests.contains(&alg) {
        return Err(format!(
            "{scheme}: signature algorithms and digests do not match"
        ));
    }
    let mut cl = Lp(certs);
    let first = cl.field()?.to_vec();
    let cert = Certificate::from_der(&first).map_err(|e| format!("{scheme}: certificate: {e}"))?;
    let cert_spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| e.to_string())?;
    if cert_spki != pubkey {
        return Err(format!(
            "{scheme}: the public key does not match the certificate"
        ));
    }
    Ok((first, legacy))
}

/// The content digest the chosen signature covers: (sig alg, digest).
fn content_digest_wanted(signer: &[u8], v3: bool) -> Result<(u32, Vec<u8>), String> {
    let mut s = Lp(signer);
    let signed = s.field()?;
    if v3 {
        s.u32()?;
        s.u32()?;
    }
    let sigs = s.field()?;
    let pubkey = s.field()?;
    let mut l = Lp(sigs);
    let mut best: Option<u32> = None;
    while !l.empty() {
        let mut one = Lp(l.field()?);
        let alg = one.u32()?;
        one.field()?;
        if alg_for(alg, pubkey).is_ok() && best.is_none_or(|b| rank(alg) > rank(b)) {
            best = Some(alg);
        }
    }
    let alg = best.ok_or("no supported signature algorithm")?;
    let mut d = Lp(signed);
    let mut dl = Lp(d.field()?);
    while !dl.empty() {
        let mut one = Lp(dl.field()?);
        if one.u32()? == alg {
            return Ok((alg, one.field()?.to_vec()));
        }
    }
    Err("no content digest for the chosen algorithm".into())
}

/// Chunked digest over the three protected sections: the entries, the
/// central directory, and the end record with its directory offset set to
/// the start of the signing block.
pub fn content_digest<R: Read + Seek>(
    f: &mut R,
    layout: &Layout,
    block_start: u64,
    sig_alg: u32,
) -> Result<Vec<u8>, String> {
    let alg = match rank(sig_alg) {
        2 => &ring::digest::SHA512,
        1 => &ring::digest::SHA256,
        _ => return Err("unsupported digest".into()),
    };
    let mut eocd = layout.eocd.clone();
    eocd[16..20].copy_from_slice(&(block_start as u32).to_le_bytes());
    let mut chunk_digests: Vec<u8> = Vec::new();
    let mut count: u32 = 0;
    let mut add = |data: &[u8]| {
        let mut c = ring::digest::Context::new(alg);
        c.update(&[0xa5]);
        c.update(&(data.len() as u32).to_le_bytes());
        c.update(data);
        chunk_digests.extend_from_slice(c.finish().as_ref());
        count += 1;
    };
    // Section 1: the entries, read in 1 MiB chunks.
    f.seek(SeekFrom::Start(0))
        .map_err(|e| format!("read error: {e}"))?;
    let mut left = block_start;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        f.read_exact(&mut buf[..n])
            .map_err(|e| format!("read error: {e}"))?;
        add(&buf[..n]);
        left -= n as u64;
    }
    for section in [&layout.cd[..], &eocd[..]] {
        for c in section.chunks(CHUNK) {
            add(c);
        }
    }
    let mut top = ring::digest::Context::new(alg);
    top.update(&[0x5a]);
    top.update(&count.to_le_bytes());
    top.update(&chunk_digests);
    Ok(top.finish().as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::rsa_modulus_bits;

    /// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
    fn rsa_key(modulus_bytes: usize, top: u8) -> Vec<u8> {
        let mut n = vec![0u8]; // sign byte, as DER writes for a set top bit
        n.push(top);
        n.extend(std::iter::repeat_n(0x55, modulus_bytes - 1));
        let mut int = vec![0x02];
        der_len(&mut int, n.len());
        int.extend(&n);
        int.extend([0x02, 0x03, 0x01, 0x00, 0x01]);
        let mut seq = vec![0x30];
        der_len(&mut seq, int.len());
        seq.extend(&int);
        seq
    }

    fn der_len(out: &mut Vec<u8>, n: usize) {
        if n < 0x80 {
            out.push(n as u8);
        } else {
            out.extend([0x82, (n >> 8) as u8, n as u8]);
        }
    }

    #[test]
    fn rsa_modulus_sizes() {
        assert_eq!(rsa_modulus_bits(&rsa_key(128, 0xc1)), Some(1024));
        assert_eq!(rsa_modulus_bits(&rsa_key(256, 0x80)), Some(2048));
        assert_eq!(rsa_modulus_bits(&rsa_key(256, 0x01)), Some(2041));
        assert_eq!(rsa_modulus_bits(&rsa_key(64, 0xff)), Some(512));
        assert_eq!(rsa_modulus_bits(&[0x30, 0x05, 0x02, 0x09, 0x00]), None);
        assert_eq!(rsa_modulus_bits(&[0x02, 0x01, 0x01]), None);
        assert_eq!(rsa_modulus_bits(&[]), None);
    }
}
