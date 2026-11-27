// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The age layer (age-encryption.org/v1, binary, through the `age` crate).
//!
//! - The backup payload is encrypted to exactly one X25519 recipient.
//! - The wrapped seed is the seed encrypted with age's scrypt recipient
//!   under the backup password (work factor 20 for the admin store).
//! - The check after every backup needs no secret: while the file is
//!   written, a thin wrapper around our X25519 recipient sees the file key
//!   that age hands to `Recipient::wrap_file_key` and keeps a copy in
//!   memory only. The file read back from the destination is then decrypted
//!   with an `Identity` that returns this file key: age checks the header
//!   MAC over the stanza and every payload chunk as in any decryption. The
//!   copy is wiped afterwards. What this does not check is that the X25519
//!   stanza unwraps with the seed's identity; the monthly drill does.

use super::code::{Seed, SEED_LEN};
use age::secrecy::{ExposeSecret, SecretString};
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// The scrypt work factor of the wrapped seed (format: at least 18).
pub const WRAP_LOG_N: u8 = 20;
/// The highest work factor accepted when unwrapping (Go age's default).
pub const MAX_LOG_N: u8 = 22;
pub const MIN_LOG_N: u8 = 18;
pub const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";
/// Largest plaintext a reader accepts (the admin store is far below).
pub const MAX_PLAIN: usize = 256 * 1024 * 1024;

/// A copy of a file key, in memory only.
pub struct FileKeyCopy(Zeroizing<[u8; FILE_KEY_BYTES]>);

struct Capture<'a> {
    inner: &'a age::x25519::Recipient,
    seen: RefCell<Option<FileKeyCopy>>,
}

impl age::Recipient for Capture<'_> {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        *self.seen.borrow_mut() = Some(FileKeyCopy(Zeroizing::new(*file_key.expose_secret())));
        self.inner.wrap_file_key(file_key)
    }
}

/// Opens only a file with exactly one X25519 stanza, with the given key.
struct KnownFileKey<'a>(&'a FileKeyCopy);

impl age::Identity for KnownFileKey<'_> {
    fn unwrap_stanza(&self, _s: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        None
    }
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let x: Vec<_> = stanzas.iter().filter(|s| s.tag == "X25519").collect();
        let others = stanzas.len() - x.len();
        let grease = stanzas.iter().filter(|s| is_grease(&s.tag)).count();
        match x.as_slice() {
            [_] if others == grease && grease <= 1 => Some(Ok(FileKey::new(Box::new(*self.0 .0)))),
            _ => None,
        }
    }
}

/// Encrypts `plain` to `recipient` (binary age v1) and returns the file
/// with a copy of its file key.
pub fn encrypt_to(
    recipient: &age::x25519::Recipient,
    plain: &[u8],
) -> Result<(Vec<u8>, FileKeyCopy), String> {
    let cap = Capture {
        inner: recipient,
        seen: RefCell::new(None),
    };
    let enc = age::Encryptor::with_recipients(std::iter::once(&cap as &dyn age::Recipient))
        .map_err(|e| format!("age: {e}"))?;
    let mut out = Vec::with_capacity(plain.len() + 256);
    let mut w = enc.wrap_output(&mut out).map_err(|e| format!("age: {e}"))?;
    w.write_all(plain).map_err(|e| format!("age: {e}"))?;
    w.finish().map_err(|e| format!("age: {e}"))?;
    let fk = cap
        .seen
        .into_inner()
        .ok_or("age did not hand out a file key")?;
    Ok((out, fk))
}

fn read_all(r: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    r.take(MAX_PLAIN as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("age: {e}"))?;
    if out.len() > MAX_PLAIN {
        return Err("age: the content is too large".into());
    }
    Ok(out)
}

/// Decrypts with a file key copy (the check after every backup).
pub fn decrypt_with_file_key(file: &[u8], fk: &FileKeyCopy) -> Result<Zeroizing<Vec<u8>>, String> {
    let d = age::Decryptor::new_buffered(file).map_err(|e| format!("age: {e}"))?;
    if d.is_scrypt() {
        return Err("age: a passphrase file, not a backup".into());
    }
    let id = KnownFileKey(fk);
    let r = d
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| format!("age: {e}"))?;
    read_all(r)
}

/// Decrypts with the identity of the seed (restore, drill).
pub fn decrypt_with_identity(
    file: &[u8],
    id: &age::x25519::Identity,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let d = age::Decryptor::new_buffered(file).map_err(|e| format!("age: {e}"))?;
    if d.is_scrypt() {
        return Err("age: a passphrase file, not a backup".into());
    }
    let r = d
        .decrypt(std::iter::once(id as &dyn age::Identity))
        .map_err(|e| format!("age: {e}"))?;
    read_all(r)
}

/// The wrapped seed: the seed as an age scrypt file under the password.
pub fn wrap_seed(seed: &[u8; SEED_LEN], password: &str, log_n: u8) -> Result<Vec<u8>, String> {
    let mut r = age::scrypt::Recipient::new(SecretString::from(password.to_string()));
    r.set_work_factor(log_n);
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
        .map_err(|e| format!("age: {e}"))?;
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).map_err(|e| format!("age: {e}"))?;
    w.write_all(seed).map_err(|e| format!("age: {e}"))?;
    w.finish().map_err(|e| format!("age: {e}"))?;
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnwrapError {
    /// The password does not open the wrapped seed.
    WrongPassword,
    Invalid(String),
}

impl std::fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnwrapError::WrongPassword => f.write_str("wrong backup password"),
            UnwrapError::Invalid(e) => write!(f, "the wrapped seed is refused: {e}"),
        }
    }
}

/// Unwraps the seed with the backup password; refuses anything but a
/// scrypt file with a work factor from 18 to 22 holding 18 bytes.
pub fn unwrap_seed(blob: &[u8], password: &str) -> Result<Seed, UnwrapError> {
    let log_n = scrypt_work_factor(blob).map_err(UnwrapError::Invalid)?;
    if !(MIN_LOG_N..=MAX_LOG_N).contains(&log_n) {
        return Err(UnwrapError::Invalid(format!(
            "scrypt work factor {log_n} outside {MIN_LOG_N} to {MAX_LOG_N}"
        )));
    }
    let d = age::Decryptor::new_buffered(blob).map_err(|e| UnwrapError::Invalid(e.to_string()))?;
    if !d.is_scrypt() {
        return Err(UnwrapError::Invalid("not a passphrase file".into()));
    }
    let mut id = age::scrypt::Identity::new(SecretString::from(password.to_string()));
    id.set_max_work_factor(MAX_LOG_N);
    let r = d
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                UnwrapError::WrongPassword
            }
            e => UnwrapError::Invalid(e.to_string()),
        })?;
    let plain = read_all(r).map_err(UnwrapError::Invalid)?;
    if plain.len() != SEED_LEN {
        return Err(UnwrapError::Invalid(format!(
            "it holds {} bytes, not an 18-byte seed",
            plain.len()
        )));
    }
    let mut s = Zeroizing::new([0u8; SEED_LEN]);
    s.copy_from_slice(&plain);
    Ok(s)
}

/// The age header of a file, read without any secret: the stanza lines
/// (`-> TAG ARGS`) and where the binary payload starts.
pub struct HeaderView {
    pub stanzas: Vec<Vec<String>>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub payload_at: usize,
}

pub fn header_view(file: &[u8]) -> Result<HeaderView, String> {
    if !file.starts_with(AGE_MAGIC) {
        return Err("not an age v1 file".into());
    }
    let mut at = AGE_MAGIC.len();
    let mut stanzas = Vec::new();
    loop {
        let end = file[at..]
            .iter()
            .position(|b| *b == b'\n')
            .ok_or("the age header does not end")?;
        let line =
            std::str::from_utf8(&file[at..at + end]).map_err(|_| "the age header is not text")?;
        at += end + 1;
        if let Some(rest) = line.strip_prefix("-> ") {
            stanzas.push(rest.split(' ').map(String::from).collect());
        } else if line.starts_with("--- ") {
            return Ok(HeaderView {
                stanzas,
                payload_at: at,
            });
        } else if stanzas.is_empty() {
            return Err("a line before the first stanza".into());
        }
        if at > 64 * 1024 {
            return Err("the age header is too long".into());
        }
    }
}

/// The scrypt work factor of a wrapped seed (the second argument of its
/// only stanza).
pub fn scrypt_work_factor(blob: &[u8]) -> Result<u8, String> {
    let h = header_view(blob)?;
    match h.stanzas.as_slice() {
        [s] if s.len() == 3 && s[0] == "scrypt" => s[2]
            .parse::<u8>()
            .map_err(|_| "the scrypt work factor is not a number".to_string()),
        _ => Err("not exactly one scrypt stanza".into()),
    }
}

/// A grease stanza (`<random>-grease`): the Rust `age` crate adds one to
/// every file that has no scrypt stanza, to keep readers honest about
/// unknown stanzas. It is not a recipient; every age reader ignores it.
pub fn is_grease(tag: &str) -> bool {
    tag.len() > "-grease".len() && tag.ends_with("-grease")
}

/// Exactly one stanza of type X25519 (with one argument), and besides it
/// at most one grease stanza; nothing else.
pub fn check_backup_header(file: &[u8]) -> Result<(), String> {
    let h = header_view(file)?;
    let x = h.stanzas.iter().filter(|s| s[0] == "X25519").count();
    let grease = h.stanzas.iter().filter(|s| is_grease(&s[0])).count();
    if x != 1 {
        return Err(format!("{x} X25519 stanzas, not exactly one"));
    }
    if let Some(s) = h
        .stanzas
        .iter()
        .find(|s| s[0] != "X25519" && !is_grease(&s[0]))
    {
        return Err(format!("a {:?} stanza besides the X25519 recipient", s[0]));
    }
    if grease > 1 {
        return Err("more than one grease stanza".into());
    }
    match h.stanzas.iter().find(|s| s[0] == "X25519") {
        Some(s) if s.len() == 2 => Ok(()),
        _ => Err("the X25519 stanza does not have exactly one argument".into()),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::backup::code::tests::V1_SEED;
    use crate::backup::keys;

    /// The file-key path through the public API of the age crate: the copy
    /// taken during encryption opens the file read back, and age still
    /// checks the header MAC and every payload chunk.
    #[test]
    fn file_key_check_through_the_public_api() {
        let r = keys::parse_recipient(&keys::recipient(&V1_SEED)).unwrap();
        let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (file, fk) = encrypt_to(&r, &plain).unwrap();
        check_backup_header(&file).unwrap();
        assert_eq!(*decrypt_with_file_key(&file, &fk).unwrap(), plain);
        // The seed's identity opens the same file.
        assert_eq!(
            *decrypt_with_identity(&file, &keys::identity(&V1_SEED)).unwrap(),
            plain
        );
        // A changed stanza byte: the header MAC fails.
        let h = header_view(&file).unwrap();
        let mut bad = file.clone();
        let i = AGE_MAGIC.len() + 12;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_with_file_key(&bad, &fk).is_err());
        // A changed payload byte (first chunk, last chunk): refused.
        for i in [h.payload_at + 20, file.len() - 3] {
            let mut bad = file.clone();
            bad[i] ^= 1;
            assert!(decrypt_with_file_key(&bad, &fk).is_err(), "{i}");
        }
        // Truncated: refused.
        assert!(decrypt_with_file_key(&file[..file.len() - 100], &fk).is_err());
        // Another file's key does not open it.
        let (_, other) = encrypt_to(&r, b"x").unwrap();
        assert!(decrypt_with_file_key(&file, &other).is_err());
        // Another seed's identity does not open it.
        let mut s2 = V1_SEED;
        s2[0] = 1;
        assert!(decrypt_with_identity(&file, &keys::identity(&s2)).is_err());
    }

    #[test]
    fn wrapped_seed_round_trip_and_refusals() {
        // A low work factor keeps the test fast; the reader refuses it.
        let blob = wrap_seed(&V1_SEED, "TEST-ONLY backup password", 10).unwrap();
        assert_eq!(scrypt_work_factor(&blob).unwrap(), 10);
        assert!(matches!(
            unwrap_seed(&blob, "TEST-ONLY backup password"),
            Err(UnwrapError::Invalid(e)) if e.contains("outside 18 to 22")
        ));
        let blob = wrap_seed(&V1_SEED, "TEST-ONLY backup password", MIN_LOG_N).unwrap();
        assert_eq!(
            *unwrap_seed(&blob, "TEST-ONLY backup password").unwrap(),
            V1_SEED
        );
        assert_eq!(
            unwrap_seed(&blob, "TEST-ONLY other password").err(),
            Some(UnwrapError::WrongPassword)
        );
        // A backup file is not a wrapped seed, and the other way round.
        let r = keys::parse_recipient(&keys::recipient(&V1_SEED)).unwrap();
        let (file, _) = encrypt_to(&r, &V1_SEED).unwrap();
        assert!(matches!(
            unwrap_seed(&file, "x"),
            Err(UnwrapError::Invalid(_))
        ));
        assert!(check_backup_header(&blob).is_err());
    }

    /// The admin store's work factor 20, once (about 1 GiB, some seconds).
    #[test]
    fn wrapped_seed_with_work_factor_20() {
        let blob = wrap_seed(&V1_SEED, "TEST-ONLY backup password", WRAP_LOG_N).unwrap();
        assert_eq!(scrypt_work_factor(&blob).unwrap(), 20);
        assert_eq!(
            *unwrap_seed(&blob, "TEST-ONLY backup password").unwrap(),
            V1_SEED
        );
    }
}
