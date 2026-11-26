// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! OpenSSH signature (SSHSIG) verification, `ssh-keygen -Y verify` semantics,
//! for Ed25519 keys. Format: PROTOCOL.sshsig in the OpenSSH sources.

use base64ct::{Base64, Encoding};

const MAGIC: &[u8] = b"SSHSIG";
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

/// One `allowed_signers` entry.
#[derive(Debug, Clone)]
pub struct AllowedSigner {
    pub principal: String,
    pub namespaces: Option<Vec<String>>,
    /// SSH wire encoding of the public key.
    pub key_blob: Vec<u8>,
}

pub fn parse_allowed_signers(text: &str) -> Result<Vec<AllowedSigner>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let principal = fields.next().ok_or("empty line")?.to_string();
        let mut namespaces = None;
        let mut next = fields
            .next()
            .ok_or(format!("allowed_signers line {}: no key", n + 1))?;
        // Options come before the key type.
        if !next.starts_with("ssh-") && !next.starts_with("ecdsa-") && !next.starts_with("sk-") {
            for opt in next.split(',') {
                if let Some(v) = opt.strip_prefix("namespaces=") {
                    namespaces = Some(v.trim_matches('"').split(',').map(String::from).collect());
                } else if opt.starts_with("valid-after=") || opt.starts_with("valid-before=") {
                    return Err(format!(
                        "allowed_signers line {}: validity options are not supported",
                        n + 1
                    ));
                }
            }
            next = fields
                .next()
                .ok_or(format!("allowed_signers line {}: no key type", n + 1))?;
        }
        let key_type = next;
        let b64 = fields
            .next()
            .ok_or(format!("allowed_signers line {}: no key", n + 1))?;
        let key_blob = Base64::decode_vec(b64)
            .map_err(|_| format!("allowed_signers line {}: bad base64", n + 1))?;
        let mut r = Wire::new(&key_blob);
        if r.string()? != key_type.as_bytes() {
            return Err(format!("allowed_signers line {}: key type mismatch", n + 1));
        }
        out.push(AllowedSigner {
            principal,
            namespaces,
            key_blob,
        });
    }
    Ok(out)
}

/// Verifies `message` against an armored SSHSIG made by `principal` in
/// `namespace`. Only Ed25519 signatures with SHA-512 or SHA-256 are accepted.
pub fn verify(
    signers: &[AllowedSigner],
    principal: &str,
    namespace: &str,
    message: &[u8],
    armored_sig: &str,
) -> Result<(), String> {
    let mut r = message;
    verify_reader(
        signers,
        principal,
        namespace,
        &mut r,
        armored_sig,
        &mut |_| {},
    )
}

/// Like `verify`, but the message is read from `message` in chunks, so a
/// file of any size is checked without being held in memory. Every chunk
/// is also passed to `on_chunk` (for example to compute a SHA-256 in the
/// same pass).
pub fn verify_reader(
    signers: &[AllowedSigner],
    principal: &str,
    namespace: &str,
    message: &mut dyn std::io::Read,
    armored_sig: &str,
    on_chunk: &mut dyn FnMut(&[u8]),
) -> Result<(), String> {
    let sig = Parsed::parse(signers, principal, namespace, armored_sig)?;
    let alg = match sig.hash_alg {
        b"sha512" => &ring::digest::SHA512,
        b"sha256" => &ring::digest::SHA256,
        other => {
            return Err(format!(
                "unsupported hash {:?}",
                String::from_utf8_lossy(other)
            ))
        }
    };
    let mut ctx = ring::digest::Context::new(alg);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match message.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("cannot read the signed file: {e}")),
        };
        ctx.update(&buf[..n]);
        on_chunk(&buf[..n]);
    }
    sig.check(namespace, ctx.finish().as_ref())
}

/// Verifies a signature against the digest of the message (the hash the
/// signature names, SHA-512 or SHA-256), for a message that is not at hand.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify_prehashed(
    signers: &[AllowedSigner],
    principal: &str,
    namespace: &str,
    digest: &[u8],
    armored_sig: &str,
) -> Result<(), String> {
    let sig = Parsed::parse(signers, principal, namespace, armored_sig)?;
    let want = match sig.hash_alg {
        b"sha512" => 64,
        b"sha256" => 32,
        other => {
            return Err(format!(
                "unsupported hash {:?}",
                String::from_utf8_lossy(other)
            ))
        }
    };
    if digest.len() != want {
        return Err("the digest does not fit the signature's hash".into());
    }
    sig.check(namespace, digest)
}

/// An SSHSIG blob whose namespace and signer are already checked.
struct Parsed {
    reserved: Vec<u8>,
    hash_alg: &'static [u8],
    raw_key: Vec<u8>,
    raw_sig: Vec<u8>,
}

impl Parsed {
    fn parse(
        signers: &[AllowedSigner],
        principal: &str,
        namespace: &str,
        armored_sig: &str,
    ) -> Result<Parsed, String> {
        let blob = dearmor(armored_sig)?;
        let mut r = Wire::new(&blob);
        if r.take(MAGIC.len())? != MAGIC {
            return Err("not an SSHSIG blob".into());
        }
        if r.u32()? != 1 {
            return Err("unsupported SSHSIG version".into());
        }
        let pubkey = r.string()?;
        let sig_namespace = r.string()?;
        let reserved = r.string()?;
        let hash_alg = r.string()?;
        let signature = r.string()?;
        r.finish()?;

        if sig_namespace != namespace.as_bytes() {
            return Err(format!(
                "signature namespace is {:?}, expected {namespace:?}",
                String::from_utf8_lossy(sig_namespace)
            ));
        }
        let signer = signers
            .iter()
            .find(|s| s.principal == principal && s.key_blob == pubkey)
            .ok_or("signing key is not an allowed signer for this principal")?;
        if let Some(ns) = &signer.namespaces {
            if !ns.iter().any(|n| n == namespace) {
                return Err("namespace not allowed for this signer".into());
            }
        }

        let mut k = Wire::new(pubkey);
        if k.string()? != b"ssh-ed25519" {
            return Err("only ssh-ed25519 keys are supported".into());
        }
        let raw_key = k.string()?.to_vec();
        k.finish()?;

        let mut s = Wire::new(signature);
        if s.string()? != b"ssh-ed25519" {
            return Err("signature type is not ssh-ed25519".into());
        }
        let raw_sig = s.string()?.to_vec();
        s.finish()?;
        let hash_alg: &'static [u8] = match hash_alg {
            b"sha512" => b"sha512",
            b"sha256" => b"sha256",
            other => {
                return Err(format!(
                    "unsupported hash {:?}",
                    String::from_utf8_lossy(other)
                ))
            }
        };
        Ok(Parsed {
            reserved: reserved.to_vec(),
            hash_alg,
            raw_key,
            raw_sig,
        })
    }

    fn check(&self, namespace: &str, digest: &[u8]) -> Result<(), String> {
        let mut signed = Vec::new();
        signed.extend_from_slice(MAGIC);
        put_string(&mut signed, namespace.as_bytes());
        put_string(&mut signed, &self.reserved);
        put_string(&mut signed, self.hash_alg);
        put_string(&mut signed, digest);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.raw_key)
            .verify(&signed, &self.raw_sig)
            .map_err(|_| "signature does not verify".to_string())
    }
}

fn dearmor(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let body = text
        .strip_prefix(ARMOR_BEGIN)
        .and_then(|t| t.strip_suffix(ARMOR_END))
        .ok_or("not an armored SSH signature")?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    Base64::decode_vec(&b64).map_err(|_| "bad base64 in signature".into())
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

struct Wire<'a> {
    data: &'a [u8],
}

impl<'a> Wire<'a> {
    fn new(data: &'a [u8]) -> Self {
        Wire { data }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.data.len() {
            return Err("truncated SSH data".into());
        }
        let (a, b) = self.data.split_at(n);
        self.data = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn finish(&self) -> Result<(), String> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err("trailing SSH data".into())
        }
    }
}

/// Test only: an Ed25519 SSHSIG over `message`, made with a key from `seed`,
/// and the `allowed_signers` line for that key. For synthetic factory images.
#[cfg(test)]
pub fn sign_for_tests(
    seed: &[u8; 32],
    principal: &str,
    namespace: &str,
    message: &[u8],
) -> (String, String) {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let mut key_blob = Vec::new();
    put_string(&mut key_blob, b"ssh-ed25519");
    put_string(&mut key_blob, kp.public_key().as_ref());
    let digest = ring::digest::digest(&ring::digest::SHA512, message);
    let mut signed = Vec::new();
    signed.extend_from_slice(MAGIC);
    put_string(&mut signed, namespace.as_bytes());
    put_string(&mut signed, b"");
    put_string(&mut signed, b"sha512");
    put_string(&mut signed, digest.as_ref());
    let sig = kp.sign(&signed);
    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, b"ssh-ed25519");
    put_string(&mut sig_blob, sig.as_ref());
    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &key_blob);
    put_string(&mut blob, namespace.as_bytes());
    put_string(&mut blob, b"");
    put_string(&mut blob, b"sha512");
    put_string(&mut blob, &sig_blob);
    let b64 = Base64::encode_string(&blob);
    let mut armored = format!("{ARMOR_BEGIN}\n");
    for chunk in b64.as_bytes().chunks(70) {
        armored.push_str(std::str::from_utf8(chunk).unwrap());
        armored.push('\n');
    }
    armored.push_str(ARMOR_END);
    armored.push('\n');
    let signer = format!(
        "{principal} ssh-ed25519 {}\n",
        Base64::encode_string(&key_blob)
    );
    (signer, armored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::lists::{GRAPHENEOS_ALLOWED_SIGNERS, GRAPHENEOS_PRINCIPAL};
    use crate::util::unhex;

    const FACTORY: &str = "factory images";
    /// The real signature of `bluejay-install-2026111800.zip` (public, from
    /// releases.grapheneos.org, 2026-11-23) and the SHA-512 of that zip.
    const REAL_SIG: &str =
        include_str!("../../tests/fixtures/grapheneos/bluejay-install-2026111800.zip.sig");
    const REAL_SHA512: &str =
        include_str!("../../tests/fixtures/grapheneos/bluejay-install-2026111800.zip.sha512");

    fn pinned() -> Vec<AllowedSigner> {
        parse_allowed_signers(GRAPHENEOS_ALLOWED_SIGNERS).unwrap()
    }

    #[test]
    fn real_factory_image_signature_with_the_pinned_key() {
        let digest = unhex(REAL_SHA512.trim()).unwrap();
        verify_prehashed(&pinned(), GRAPHENEOS_PRINCIPAL, FACTORY, &digest, REAL_SIG).unwrap();
        // One bit of the file's digest changed: refused.
        let mut bad = digest.clone();
        bad[17] ^= 0x01;
        let e =
            verify_prehashed(&pinned(), GRAPHENEOS_PRINCIPAL, FACTORY, &bad, REAL_SIG).unwrap_err();
        assert!(e.contains("does not verify"), "{e}");
        // Other namespace or principal: refused.
        assert!(verify_prehashed(
            &pinned(),
            GRAPHENEOS_PRINCIPAL,
            "attestation keys",
            &digest,
            REAL_SIG
        )
        .unwrap_err()
        .contains("namespace"));
        assert!(verify_prehashed(
            &pinned(),
            "other@grapheneos.org",
            FACTORY,
            &digest,
            REAL_SIG
        )
        .is_err());
        // A changed byte in the signature itself: refused.
        let blob = dearmor(REAL_SIG).unwrap();
        let mut t = blob.clone();
        let n = t.len();
        t[n - 5] ^= 0x40;
        let armored = format!(
            "{ARMOR_BEGIN}\n{}\n{ARMOR_END}\n",
            Base64::encode_string(&t)
        );
        assert!(
            verify_prehashed(&pinned(), GRAPHENEOS_PRINCIPAL, FACTORY, &digest, &armored).is_err()
        );
    }

    /// The whole real image through the streaming check. Runs only when the
    /// image is in the local cache (`dist/grapheneos-cache/`, git-ignored).
    #[test]
    fn real_factory_image_streamed_when_cached() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("dist/grapheneos-cache/2026111800/bluejay-install-2026111800.zip");
        let Ok(f) = std::fs::File::open(&p) else {
            eprintln!("skipped: {} not present", p.display());
            return;
        };
        let mut r = std::io::BufReader::new(f);
        let mut n = 0u64;
        verify_reader(
            &pinned(),
            GRAPHENEOS_PRINCIPAL,
            FACTORY,
            &mut r,
            REAL_SIG,
            &mut |c| n += c.len() as u64,
        )
        .unwrap();
        assert_eq!(n, 2_085_371_338);
    }

    #[test]
    fn streaming_equals_whole_and_tampering_is_refused() {
        let msg: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7) as u8).collect();
        let (signer, sig) = sign_for_tests(&[7; 32], "test@example.invalid", FACTORY, &msg);
        let s = parse_allowed_signers(&signer).unwrap();
        verify(&s, "test@example.invalid", FACTORY, &msg, &sig).unwrap();
        let mut r = &msg[..];
        let mut seen = Vec::new();
        verify_reader(
            &s,
            "test@example.invalid",
            FACTORY,
            &mut r,
            &sig,
            &mut |c| seen.extend_from_slice(c),
        )
        .unwrap();
        assert_eq!(seen, msg);
        let mut bad = msg.clone();
        bad[2_999_999] ^= 1;
        assert!(verify(&s, "test@example.invalid", FACTORY, &bad, &sig).is_err());
        // The test key is not the pinned GrapheneOS key.
        assert!(verify(&pinned(), GRAPHENEOS_PRINCIPAL, FACTORY, &msg, &sig).is_err());
    }
}
