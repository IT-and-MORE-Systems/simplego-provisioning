// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! SimpleGo activation and update files (`.sxact`), format version 1.
//! Source of truth: the activation file format document
//! (`activation-file-format.md`); section numbers below refer to it.

pub mod code;
pub mod container;
pub mod directory;
pub mod features;
pub mod hosts;
pub mod import;
pub mod issue;
pub mod keys;
pub mod payload;
pub mod rng;
pub mod store;
pub mod storekey;
pub mod strict;
#[cfg(test)]
mod vectors;

/// Why a file is refused. `code()` is the stable name used in the test
/// vectors (`tests/fixtures/sxact/vectors.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    LengthMismatch,
    BadMagic,
    UnsupportedVersion,
    UnknownKdfAlg,
    KdfParamsOutOfBounds,
    UnknownAeadAlg,
    UnknownSigAlg,
    UnknownKey,
    BadSignature,
    BadCode(String),
    WrongCode,
    NotAnActivationFile,
    NotAnUpdateFile,
    WrongUpdateKey,
    DecryptFailed,
    BadPayload(String),
    KindMismatch,
    NetworkModeRule(String),
    DeviceClassMismatch,
    CustomerMismatch,
    ReplayedSequence,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::TooLarge => "too_large",
            Refusal::LengthMismatch => "length_mismatch",
            Refusal::BadMagic => "bad_magic",
            Refusal::UnsupportedVersion => "unsupported_version",
            Refusal::UnknownKdfAlg => "unknown_kdf_alg",
            Refusal::KdfParamsOutOfBounds => "kdf_params_out_of_bounds",
            Refusal::UnknownAeadAlg => "unknown_aead_alg",
            Refusal::UnknownSigAlg => "unknown_sig_alg",
            Refusal::UnknownKey => "unknown_key",
            Refusal::BadSignature => "bad_signature",
            Refusal::BadCode(_) => "bad_code",
            Refusal::WrongCode => "wrong_code",
            Refusal::NotAnActivationFile => "not_an_activation_file",
            Refusal::NotAnUpdateFile => "not_an_update_file",
            Refusal::WrongUpdateKey => "wrong_update_key",
            Refusal::DecryptFailed => "decrypt_failed",
            Refusal::BadPayload(_) => "bad_payload",
            Refusal::KindMismatch => "kind_mismatch",
            Refusal::NetworkModeRule(_) => "network_mode_rule",
            Refusal::DeviceClassMismatch => "device_class_mismatch",
            Refusal::CustomerMismatch => "customer_mismatch",
            Refusal::ReplayedSequence => "replayed_sequence",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Refusal::TooLarge => "the file is larger than 64 KiB".to_string(),
            Refusal::LengthMismatch => {
                "the file length does not match its header (truncated or trailing bytes)".into()
            }
            Refusal::BadMagic => "not an SXACT file".into(),
            Refusal::UnsupportedVersion => "unsupported SXACT version".into(),
            Refusal::UnknownKdfAlg => "unknown key derivation algorithm".into(),
            Refusal::KdfParamsOutOfBounds => "key derivation parameters out of bounds".into(),
            Refusal::UnknownAeadAlg => "unknown encryption algorithm".into(),
            Refusal::UnknownSigAlg => "unknown signature algorithm".into(),
            Refusal::UnknownKey => {
                "the file is signed with a key that is not in the trusted list".into()
            }
            Refusal::BadSignature => {
                "this file was not issued by IT & MORE Systems (signature invalid)".into()
            }
            Refusal::BadCode(e) => format!("invalid activation code: {e}"),
            Refusal::WrongCode => "the code does not match this file".into(),
            Refusal::NotAnActivationFile => "this is an update file, not an activation file".into(),
            Refusal::NotAnUpdateFile => "this is an activation file, not an update file".into(),
            Refusal::WrongUpdateKey => "this update is not for this installation".into(),
            Refusal::DecryptFailed => {
                "the update file does not decrypt with the stored update key".into()
            }
            Refusal::BadPayload(e) => format!("invalid payload: {e}"),
            Refusal::KindMismatch => "the payload kind does not match the container".into(),
            Refusal::NetworkModeRule(e) => format!("network mode rule broken: {e}"),
            Refusal::DeviceClassMismatch => "the file is for another device class".into(),
            Refusal::CustomerMismatch => "the update is for another customer".into(),
            Refusal::ReplayedSequence => "the update is not newer than the last applied one".into(),
        };
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::code::Code;
    use super::container::*;
    use super::keys::Signer;
    use super::Refusal;

    /// One real-parameter Argon2id round trip (64 MiB, 3 passes).
    #[test]
    fn activation_round_trip_real_parameters() {
        let s = Signer::from_seed(&[3; 32]).unwrap();
        let code = Code::parse_input("482913x105377").unwrap();
        let f = build_activation(b"{\"a\":true}", &code, [1; 16], [2; 12], &s).unwrap();
        let v = parse(&f).unwrap().verify(&[s.trusted("t")]).unwrap();
        assert_eq!(
            v.decrypt_with_code(&code).unwrap().as_slice(),
            b"{\"a\":true}"
        );
        let wrong = Code::parse_input("482913x105378").unwrap();
        assert_eq!(v.decrypt_with_code(&wrong).unwrap_err(), Refusal::WrongCode);
        assert_eq!(
            v.decrypt_with_update_key(&[0; 32]).unwrap_err(),
            Refusal::NotAnUpdateFile
        );
    }
}
