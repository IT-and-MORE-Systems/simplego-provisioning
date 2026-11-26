// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Signing and trusted keys.
//!
//! The real activation signing key is a passphrase-protected OpenSSH Ed25519
//! private key file that the operator creates with `ssh-keygen`. It is read only
//! from the path given with `--key`, after a passphrase prompt, and wiped
//! from memory after signing (`Signer` drop).
//!
//! The test key (`tests/fixtures/sxact/keys/`) is refused for issuing.

use ssh_key::{PrivateKey, PublicKey};
use std::mem::ManuallyDrop;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// The committed test public key. Used only to refuse it in `issue` and
/// `update`; it is never in a trusted list of the tool.
const TEST_PUBLIC_KEY: &str =
    include_str!("../../tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key.pub");

/// First 16 bytes of SHA-256 over the raw 32-byte key.
pub fn key_id(raw: &[u8; 32]) -> [u8; 16] {
    let d = crate::util::sha256(raw);
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub name: String,
    pub public: [u8; 32],
    pub key_id: [u8; 16],
}

impl TrustedKey {
    pub fn new(name: &str, public: [u8; 32]) -> TrustedKey {
        TrustedKey {
            name: name.to_string(),
            public,
            key_id: key_id(&public),
        }
    }
}

/// The test key's key_id.
pub fn test_key_id() -> [u8; 16] {
    // The file is committed and parsed in the tests; a broken file would make
    // every issue refuse, which is the safe side.
    parse_public(TEST_PUBLIC_KEY)
        .map(|k| key_id(&k))
        .unwrap_or([0xff; 16])
}

pub fn is_test_key(public: &[u8; 32]) -> bool {
    key_id(public) == test_key_id()
}

/// Raw Ed25519 public key from an OpenSSH public key line.
pub fn parse_public(text: &str) -> Result<[u8; 32], String> {
    let k = PublicKey::from_openssh(text.trim())
        .map_err(|e| format!("not an OpenSSH public key: {e}"))?;
    let ed = k
        .key_data()
        .ed25519()
        .ok_or("the key is not an Ed25519 key")?;
    Ok(ed.0)
}

pub fn read_public(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_public(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A private key file, read but not yet decrypted. The public part of an
/// OpenSSH key file is stored in the clear, so the test key can be refused
/// before any passphrase is asked.
pub struct KeyFile {
    key: PrivateKey,
    pub public: [u8; 32],
}

impl KeyFile {
    pub fn read(path: &Path) -> Result<KeyFile, String> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?,
        );
        let key = PrivateKey::from_openssh(text.as_bytes())
            .map_err(|e| format!("{}: not an OpenSSH private key: {e}", path.display()))?;
        let public = key
            .public_key()
            .key_data()
            .ed25519()
            .ok_or_else(|| format!("{}: the key is not an Ed25519 key", path.display()))?
            .0;
        Ok(KeyFile { key, public })
    }

    pub fn is_encrypted(&self) -> bool {
        self.key.is_encrypted()
    }

    /// Decrypts with the passphrase (if encrypted) and returns the signer.
    pub fn unlock(self, passphrase: Option<&str>) -> Result<Signer, String> {
        let key = if self.key.is_encrypted() {
            let p = passphrase.ok_or("the key is passphrase protected")?;
            self.key
                .decrypt(p.as_bytes())
                .map_err(|_| "wrong passphrase for the signing key".to_string())?
        } else {
            self.key
        };
        let pair = key
            .key_data()
            .ed25519()
            .ok_or("the key is not an Ed25519 key")?;
        let seed = Zeroizing::new(pair.private.to_bytes());
        let signer = Signer::from_seed(&seed)?;
        if signer.public() != pair.public.0 {
            return Err("the private and public parts of the key file do not match".into());
        }
        Ok(signer)
    }
}

/// Ed25519 signer. The key material is overwritten when it is dropped.
pub struct Signer {
    pair: ManuallyDrop<ring::signature::Ed25519KeyPair>,
    public: [u8; 32],
}

impl Signer {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Signer, String> {
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| "invalid Ed25519 seed".to_string())?;
        let mut public = [0u8; 32];
        public.copy_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
        Ok(Signer {
            pair: ManuallyDrop::new(pair),
            public,
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    pub fn key_id(&self) -> [u8; 16] {
        key_id(&self.public)
    }

    pub fn trusted(&self, name: &str) -> TrustedKey {
        TrustedKey::new(name, self.public)
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.pair.sign(msg).as_ref());
        out
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        // SAFETY: ring 0.17's Ed25519KeyPair consists only of byte arrays
        // (private scalar, prefix and public key, no pointers and no Drop
        // impl), so overwriting it with zero bytes leaves a valid value. It
        // is wrapped in ManuallyDrop and never used after this point.
        let p = &mut *self.pair as *mut ring::signature::Ed25519KeyPair as *mut u8;
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                p,
                std::mem::size_of::<ring::signature::Ed25519KeyPair>(),
            )
        };
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE: &str =
        include_str!("../../tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key");

    #[test]
    fn test_key_parses_and_is_recognised() {
        let pubkey = parse_public(TEST_PUBLIC_KEY).unwrap();
        assert!(is_test_key(&pubkey));
        assert!(TEST_PUBLIC_KEY.contains("TEST ONLY, never trusted in release builds"));
        let dir = std::env::temp_dir().join(format!("sxprov-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k");
        std::fs::write(&p, TEST_PRIVATE).unwrap();
        let kf = KeyFile::read(&p).unwrap();
        assert_eq!(kf.public, pubkey);
        assert!(!kf.is_encrypted());
        let s = kf.unlock(None).unwrap();
        assert_eq!(s.public(), pubkey);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!is_test_key(&Signer::from_seed(&[1; 32]).unwrap().public()));
    }

    #[test]
    fn passphrase_protected_key_unlocks_only_with_its_passphrase() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key-encrypted");
        let kf = KeyFile::read(&p).unwrap();
        assert!(kf.is_encrypted());
        assert!(is_test_key(&kf.public));
        assert!(KeyFile::read(&p).unwrap().unlock(None).is_err());
        assert!(KeyFile::read(&p).unwrap().unlock(Some("wrong")).is_err());
        let s = kf.unlock(Some("TEST-ONLY-PASSPHRASE")).unwrap();
        assert!(is_test_key(&s.public()));
    }

    #[test]
    fn signer_matches_ring_verification() {
        let s = Signer::from_seed(&[9; 32]).unwrap();
        let sig = s.sign(b"msg");
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, s.public())
            .verify(b"msg", &sig)
            .unwrap();
    }

    #[test]
    fn non_ed25519_public_key_refused() {
        assert!(parse_public("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 x").is_err());
        assert!(parse_public("not a key").is_err());
    }
}
