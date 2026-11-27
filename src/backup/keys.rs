// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The backup key pair (backup format section 3.2): an age X25519 identity
//! derived from the seed with HKDF-SHA256 (salt `SimpleGo backup v1`, info
//! `age x25519 identity`, 32 bytes). Only the recipient (`age1...`) is kept
//! on the device.

use super::code::SEED_LEN;
use age::secrecy::ExposeSecret;
use bech32::{ToBase32, Variant};
use std::str::FromStr;
use zeroize::Zeroizing;

const HKDF_SALT: &[u8] = b"SimpleGo backup v1";
const HKDF_INFO: &[u8] = b"age x25519 identity";

struct Len32;
impl ring::hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// The 32 identity bytes.
pub fn identity_bytes(seed: &[u8; SEED_LEN]) -> Zeroizing<[u8; 32]> {
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, HKDF_SALT).extract(seed);
    let mut out = Zeroizing::new([0u8; 32]);
    prk.expand(&[HKDF_INFO], Len32)
        .and_then(|okm| okm.fill(out.as_mut()))
        .expect("HKDF output of 32 bytes is always valid");
    out
}

/// `AGE-SECRET-KEY-1...`, as the official tool writes it.
pub fn identity_string(seed: &[u8; SEED_LEN]) -> Zeroizing<String> {
    let b = identity_bytes(seed);
    let s = bech32::encode("age-secret-key-", b.to_base32(), Variant::Bech32)
        .expect("the HRP is valid");
    Zeroizing::new(s.to_uppercase())
}

pub fn identity(seed: &[u8; SEED_LEN]) -> age::x25519::Identity {
    age::x25519::Identity::from_str(&identity_string(seed)).expect("a valid identity string")
}

/// `age1...`
pub fn recipient(seed: &[u8; SEED_LEN]) -> String {
    identity(seed).to_public().to_string()
}

/// Parses a recipient as stored in the backup state.
pub fn parse_recipient(s: &str) -> Result<age::x25519::Recipient, String> {
    age::x25519::Recipient::from_str(s).map_err(|e| format!("not an age X25519 recipient: {e}"))
}

/// The identity string of an `age::x25519::Identity` (for the cross-check
/// with the official tool).
#[cfg_attr(not(test), allow(dead_code))]
pub fn identity_text(id: &age::x25519::Identity) -> Zeroizing<String> {
    Zeroizing::new(id.to_string().expose_secret().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::code::tests::V1_SEED;

    /// Vector V1, the key half.
    #[test]
    fn vector_v1_keys() {
        assert_eq!(
            identity_string(&V1_SEED).as_str(),
            "AGE-SECRET-KEY-1PKTXMYS98WVKRDZJA67HD0RV3AS4T049EVNXR3SRNTFX97DX0VPSAKTH4Y"
        );
        assert_eq!(
            identity_text(&identity(&V1_SEED)).as_str(),
            identity_string(&V1_SEED).as_str()
        );
        assert_eq!(
            recipient(&V1_SEED),
            "age19y5jv697frrqjkrxgywrt7aquxsxhtxa9zmjlqtnjqx4h5f2lyyq8pzu0c"
        );
        assert!(parse_recipient(&recipient(&V1_SEED)).is_ok());
        assert!(parse_recipient("age1nope").is_err());
    }
}
