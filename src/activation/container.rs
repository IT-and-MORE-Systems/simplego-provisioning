// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `.sxact` container (format document sections 4 and 5).
//!
//! Header (66 bytes, big-endian), ciphertext with the GCM tag, Ed25519
//! signature over `SXACT-v1-SIG\0 || header || ciphertext`.
//!
//! Type states enforce the order of checks: `Parsed` (size, magic, version,
//! algorithms, bounds, exact length) -> `Verified` (trusted key, signature)
//! -> decryption. Nothing is decrypted before the signature is checked.

use super::code::Code;
use super::keys::{key_id, Signer, TrustedKey};
use super::Refusal;
use ring::aead;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 5] = b"SXACT";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 66;
pub const TAG_LEN: usize = 16;
pub const SIG_LEN: usize = 64;
pub const MAX_FILE_LEN: usize = 64 * 1024;
pub const SIG_DOMAIN: &[u8; 13] = b"SXACT-v1-SIG\0";

pub const KDF_ARGON2ID: u8 = 1;
pub const KDF_UPDATE_KEY: u8 = 2;
pub const AEAD_AES_256_GCM: u8 = 1;
pub const SIG_ED25519: u8 = 1;

/// Parameters the generator writes for activation files.
pub const ARGON2_M_KIB: u32 = 65_536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u8 = 1;
/// Bounds the reader accepts (section 5).
pub const ARGON2_M_MIN: u32 = 65_536;
pub const ARGON2_M_MAX: u32 = 262_144;
pub const ARGON2_T_MIN: u32 = 3;
pub const ARGON2_T_MAX: u32 = 10;
pub const ARGON2_P_MIN: u8 = 1;
pub const ARGON2_P_MAX: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kdf_alg: u8,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u8,
    pub salt: [u8; 16],
    pub aead_alg: u8,
    pub nonce: [u8; 12],
    pub sig_alg: u8,
    pub key_id: [u8; 16],
    pub ct_len: u32,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..5].copy_from_slice(MAGIC);
        h[5] = self.version;
        h[6] = self.kdf_alg;
        h[7..11].copy_from_slice(&self.kdf_m_kib.to_be_bytes());
        h[11..15].copy_from_slice(&self.kdf_t.to_be_bytes());
        h[15] = self.kdf_p;
        h[16..32].copy_from_slice(&self.salt);
        h[32] = self.aead_alg;
        h[33..45].copy_from_slice(&self.nonce);
        h[45] = self.sig_alg;
        h[46..62].copy_from_slice(&self.key_id);
        h[62..66].copy_from_slice(&self.ct_len.to_be_bytes());
        h
    }

    /// Reads the fields without any check (the magic is not part of the struct).
    pub fn from_bytes(h: &[u8; HEADER_LEN]) -> Header {
        let u32_at = |i: usize| u32::from_be_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&h[16..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&h[33..45]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&h[46..62]);
        Header {
            version: h[5],
            kdf_alg: h[6],
            kdf_m_kib: u32_at(7),
            kdf_t: u32_at(11),
            kdf_p: h[15],
            salt,
            aead_alg: h[32],
            nonce,
            sig_alg: h[45],
            key_id,
            ct_len: u32_at(62),
        }
    }

    pub fn activation(salt: [u8; 16], nonce: [u8; 12], key_id: [u8; 16], pt_len: usize) -> Header {
        Header {
            version: VERSION,
            kdf_alg: KDF_ARGON2ID,
            kdf_m_kib: ARGON2_M_KIB,
            kdf_t: ARGON2_T,
            kdf_p: ARGON2_P,
            salt,
            aead_alg: AEAD_AES_256_GCM,
            nonce,
            sig_alg: SIG_ED25519,
            key_id,
            ct_len: (pt_len + TAG_LEN) as u32,
        }
    }

    pub fn update(
        update_key_id: [u8; 16],
        nonce: [u8; 12],
        key_id: [u8; 16],
        pt_len: usize,
    ) -> Header {
        Header {
            version: VERSION,
            kdf_alg: KDF_UPDATE_KEY,
            kdf_m_kib: 0,
            kdf_t: 0,
            kdf_p: 0,
            salt: update_key_id,
            aead_alg: AEAD_AES_256_GCM,
            nonce,
            sig_alg: SIG_ED25519,
            key_id,
            ct_len: (pt_len + TAG_LEN) as u32,
        }
    }
}

/// A file that passed step 1 of section 6 (structure and bounds).
#[derive(Debug)]
pub struct Parsed<'a> {
    pub header: Header,
    header_bytes: &'a [u8],
    ciphertext: &'a [u8],
    signature: &'a [u8],
}

/// A file whose signature was checked against a trusted key.
#[derive(Debug)]
pub struct Verified<'a> {
    pub parsed: Parsed<'a>,
    pub signer_name: String,
}

pub fn parse(file: &[u8]) -> Result<Parsed<'_>, Refusal> {
    if file.len() > MAX_FILE_LEN {
        return Err(Refusal::TooLarge);
    }
    if file.len() < HEADER_LEN {
        return Err(Refusal::LengthMismatch);
    }
    if &file[0..5] != MAGIC {
        return Err(Refusal::BadMagic);
    }
    let mut hb = [0u8; HEADER_LEN];
    hb.copy_from_slice(&file[..HEADER_LEN]);
    let h = Header::from_bytes(&hb);
    if h.version != VERSION {
        return Err(Refusal::UnsupportedVersion);
    }
    match h.kdf_alg {
        KDF_ARGON2ID => {
            if !(ARGON2_M_MIN..=ARGON2_M_MAX).contains(&h.kdf_m_kib)
                || !(ARGON2_T_MIN..=ARGON2_T_MAX).contains(&h.kdf_t)
                || !(ARGON2_P_MIN..=ARGON2_P_MAX).contains(&h.kdf_p)
            {
                return Err(Refusal::KdfParamsOutOfBounds);
            }
        }
        KDF_UPDATE_KEY => {
            if h.kdf_m_kib != 0 || h.kdf_t != 0 || h.kdf_p != 0 {
                return Err(Refusal::KdfParamsOutOfBounds);
            }
        }
        _ => return Err(Refusal::UnknownKdfAlg),
    }
    if h.aead_alg != AEAD_AES_256_GCM {
        return Err(Refusal::UnknownAeadAlg);
    }
    if h.sig_alg != SIG_ED25519 {
        return Err(Refusal::UnknownSigAlg);
    }
    let ct_len = h.ct_len as usize;
    if ct_len < TAG_LEN
        || HEADER_LEN
            .checked_add(ct_len)
            .and_then(|n| n.checked_add(SIG_LEN))
            != Some(file.len())
    {
        return Err(Refusal::LengthMismatch);
    }
    Ok(Parsed {
        header: h,
        header_bytes: &file[..HEADER_LEN],
        ciphertext: &file[HEADER_LEN..HEADER_LEN + ct_len],
        signature: &file[HEADER_LEN + ct_len..],
    })
}

fn signed_message(header: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + header.len() + ciphertext.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(header);
    m.extend_from_slice(ciphertext);
    m
}

impl<'a> Parsed<'a> {
    /// Steps 2 and 3 of section 6: the key must be in the trusted list, then
    /// the signature must verify.
    pub fn verify(self, trusted: &[TrustedKey]) -> Result<Verified<'a>, Refusal> {
        let key = trusted
            .iter()
            .find(|k| k.key_id == self.header.key_id)
            .ok_or(Refusal::UnknownKey)?;
        let msg = signed_message(self.header_bytes, self.ciphertext);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key.public)
            .verify(&msg, self.signature)
            .map_err(|_| Refusal::BadSignature)?;
        let signer_name = key.name.clone();
        Ok(Verified {
            parsed: self,
            signer_name,
        })
    }
}

impl Verified<'_> {
    pub fn header(&self) -> &Header {
        &self.parsed.header
    }

    /// Activation file: derive the key from the code and decrypt.
    pub fn decrypt_with_code(&self, code: &Code) -> Result<Zeroizing<Vec<u8>>, Refusal> {
        let h = &self.parsed.header;
        if h.kdf_alg != KDF_ARGON2ID {
            return Err(Refusal::NotAnActivationFile);
        }
        let key = derive_key(code, &h.salt, h.kdf_m_kib, h.kdf_t, h.kdf_p)
            .map_err(|_| Refusal::WrongCode)?;
        open(
            &key,
            &h.nonce,
            self.parsed.header_bytes,
            self.parsed.ciphertext,
        )
        .ok_or(Refusal::WrongCode)
    }

    /// Update file: the salt must be the id of the given update key.
    pub fn decrypt_with_update_key(
        &self,
        update_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, Refusal> {
        let h = &self.parsed.header;
        if h.kdf_alg != KDF_UPDATE_KEY {
            return Err(Refusal::NotAnUpdateFile);
        }
        if h.salt != update_key_id(update_key) {
            return Err(Refusal::WrongUpdateKey);
        }
        open(
            update_key,
            &h.nonce,
            self.parsed.header_bytes,
            self.parsed.ciphertext,
        )
        .ok_or(Refusal::DecryptFailed)
    }
}

/// First 16 bytes of SHA-256 over the 32-byte update key (section 5).
pub fn update_key_id(update_key: &[u8; 32]) -> [u8; 16] {
    key_id(update_key)
}

/// Argon2id v0x13, 32-byte output.
pub fn derive_key(
    code: &Code,
    salt: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u8,
) -> Result<Zeroizing<[u8; 32]>, String> {
    argon2id(code.canonical(), salt, m_kib, t, p)
}

pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u8,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params =
        argon2::Params::new(m_kib, t, u32::from(p), Some(32)).map_err(|e| e.to_string())?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// AES-256-GCM seal, the tag appended.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let k = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "bad key")?,
    );
    let mut buf = plaintext.to_vec();
    k.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(*nonce),
        aead::Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| "encryption failed".to_string())?;
    Ok(buf)
}

/// AES-256-GCM open. None on a tag failure.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let k = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key).ok()?);
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let n = match k.open_in_place(
        aead::Nonce::assume_unique_for_key(*nonce),
        aead::Aad::from(aad),
        &mut buf,
    ) {
        Ok(pt) => pt.len(),
        Err(_) => {
            buf.zeroize();
            return None;
        }
    };
    buf.truncate(n);
    Some(buf)
}

/// Header, ciphertext and signature for an arbitrary header (the test
/// vectors use this for out-of-bounds headers). `ct_len` must already be set.
pub fn assemble(header: &Header, ciphertext: &[u8], signer: &Signer) -> Vec<u8> {
    let hb = header.to_bytes();
    let sig = signer.sign(&signed_message(&hb, ciphertext));
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len() + SIG_LEN);
    out.extend_from_slice(&hb);
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(&sig);
    out
}

/// Encrypts under `key` with `header` as AAD, then signs.
pub fn encrypt_and_sign(
    header: &Header,
    key: &[u8; 32],
    plaintext: &[u8],
    signer: &Signer,
) -> Result<Vec<u8>, String> {
    let ct = seal(key, &header.nonce, &header.to_bytes(), plaintext)?;
    if ct.len() != header.ct_len as usize {
        return Err("internal error: ct_len does not match".into());
    }
    let file = assemble(header, &ct, signer);
    if file.len() > MAX_FILE_LEN {
        return Err(format!(
            "the file would be {} bytes, more than the 64 KiB limit",
            file.len()
        ));
    }
    Ok(file)
}

/// Builds an activation file: Argon2id from the code, then encrypt and sign.
pub fn build_activation(
    plaintext: &[u8],
    code: &Code,
    salt: [u8; 16],
    nonce: [u8; 12],
    signer: &Signer,
) -> Result<Vec<u8>, String> {
    let h = Header::activation(salt, nonce, signer.key_id(), plaintext.len());
    let key = derive_key(code, &h.salt, h.kdf_m_kib, h.kdf_t, h.kdf_p)?;
    encrypt_and_sign(&h, &key, plaintext, signer)
}

/// Builds an update file under the given update key.
pub fn build_update(
    plaintext: &[u8],
    update_key: &[u8; 32],
    nonce: [u8; 12],
    signer: &Signer,
) -> Result<Vec<u8>, String> {
    let h = Header::update(
        update_key_id(update_key),
        nonce,
        signer.key_id(),
        plaintext.len(),
    );
    encrypt_and_sign(&h, update_key, plaintext, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(n: u8) -> Signer {
        Signer::from_seed(&[n; 32]).unwrap()
    }

    #[test]
    fn header_round_trip_and_layout() {
        let h = Header::update([7; 16], [9; 12], [3; 16], 100);
        let b = h.to_bytes();
        assert_eq!(&b[0..5], b"SXACT");
        assert_eq!(b[5], 1);
        assert_eq!(b[6], 2);
        assert_eq!(&b[62..66], &116u32.to_be_bytes());
        assert_eq!(Header::from_bytes(&b), h);
        let a = Header::activation([1; 16], [2; 12], [3; 16], 0);
        let b = a.to_bytes();
        assert_eq!(&b[7..11], &65536u32.to_be_bytes());
        assert_eq!(&b[11..15], &3u32.to_be_bytes());
        assert_eq!(b[15], 1);
    }

    #[test]
    fn update_round_trip_and_refusals() {
        let s = signer(1);
        let trusted = [s.trusted("t")];
        let key = [5u8; 32];
        let f = build_update(b"{\"x\":1}", &key, [4; 12], &s).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 7 + TAG_LEN + SIG_LEN);
        let v = parse(&f).unwrap().verify(&trusted).unwrap();
        assert_eq!(
            v.decrypt_with_update_key(&key).unwrap().as_slice(),
            b"{\"x\":1}"
        );
        assert_eq!(
            v.decrypt_with_update_key(&[6; 32]).unwrap_err(),
            Refusal::WrongUpdateKey
        );
        // Another signer is unknown; a list with several keys works.
        let other = signer(2);
        assert_eq!(
            parse(&f)
                .unwrap()
                .verify(&[other.trusted("o")])
                .unwrap_err(),
            Refusal::UnknownKey
        );
        assert!(parse(&f)
            .unwrap()
            .verify(&[other.trusted("o"), s.trusted("t")])
            .is_ok());
        // Every single-byte change after the magic is refused before decryption.
        for i in 5..f.len() {
            let mut g = f.clone();
            g[i] ^= 0x01;
            let r = parse(&g).and_then(|p| p.verify(&trusted));
            assert!(r.is_err(), "byte {i}");
        }
        let mut long = f.clone();
        long.push(0);
        assert_eq!(parse(&long).unwrap_err(), Refusal::LengthMismatch);
        assert_eq!(
            parse(&f[..f.len() - 1]).unwrap_err(),
            Refusal::LengthMismatch
        );
        assert_eq!(parse(&f[..10]).unwrap_err(), Refusal::LengthMismatch);
        assert_eq!(
            parse(&vec![0u8; MAX_FILE_LEN + 1]).unwrap_err(),
            Refusal::TooLarge
        );
    }

    #[test]
    fn bounds() {
        let s = signer(1);
        let base = Header::activation([1; 16], [2; 12], s.key_id(), 0);
        let file = |h: &Header| assemble(h, &[0u8; TAG_LEN], &s);
        assert!(parse(&file(&base)).is_ok());
        type Case = (Box<dyn Fn(&mut Header)>, Refusal);
        let cases: Vec<Case> = vec![
            (Box::new(|h| h.version = 2), Refusal::UnsupportedVersion),
            (Box::new(|h| h.kdf_alg = 3), Refusal::UnknownKdfAlg),
            (
                Box::new(|h| h.kdf_m_kib = 65_535),
                Refusal::KdfParamsOutOfBounds,
            ),
            (
                Box::new(|h| h.kdf_m_kib = 262_145),
                Refusal::KdfParamsOutOfBounds,
            ),
            (Box::new(|h| h.kdf_t = 2), Refusal::KdfParamsOutOfBounds),
            (Box::new(|h| h.kdf_t = 11), Refusal::KdfParamsOutOfBounds),
            (Box::new(|h| h.kdf_p = 0), Refusal::KdfParamsOutOfBounds),
            (Box::new(|h| h.kdf_p = 5), Refusal::KdfParamsOutOfBounds),
            (Box::new(|h| h.aead_alg = 2), Refusal::UnknownAeadAlg),
            (Box::new(|h| h.sig_alg = 2), Refusal::UnknownSigAlg),
            (
                Box::new(|h| {
                    h.kdf_alg = 2;
                }),
                Refusal::KdfParamsOutOfBounds,
            ),
        ];
        for (i, (f, want)) in cases.iter().enumerate() {
            let mut h = base.clone();
            f(&mut h);
            assert_eq!(parse(&file(&h)).unwrap_err(), *want, "case {i}");
        }
        for (m, t, p) in [(262_144, 10, 4), (65_536, 3, 1)] {
            let mut h = base.clone();
            (h.kdf_m_kib, h.kdf_t, h.kdf_p) = (m, t, p);
            assert!(parse(&file(&h)).is_ok());
        }
        let mut u = Header::update([1; 16], [2; 12], s.key_id(), 0);
        assert!(parse(&file(&u)).is_ok());
        u.kdf_t = 3;
        assert_eq!(parse(&file(&u)).unwrap_err(), Refusal::KdfParamsOutOfBounds);
        let mut bad = file(&base);
        bad[0] = b'X';
        assert_eq!(parse(&bad).unwrap_err(), Refusal::BadMagic);
    }
}
