// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Reads an APK file on the admin machine before it is installed: package
//! name, version code and name and the web link intent filters from the
//! binary manifest, the SHA-256 of the file, and the signing certificate
//! from the APK Signature Scheme v2/v3 block. Pure Rust, no `apksigner`.
//!
//! The signature block is verified, not only read: the signer's signature
//! over its signed data, the public key against the certificate, and the
//! chunked content digest over the whole file (APK Signature Scheme v2,
//! section "Integrity-protected contents"). A file whose contents do not
//! match the signature is refused, so the certificate digest really belongs
//! to the bytes that will be installed.
//!
//! Scheme choice, as Android 13 and later do: v3.1 if present, else v3, else
//! v2. A v1-only (JAR signed) APK is refused. Proof-of-rotation lineages are
//! not evaluated; the digest reported is the certificate of the chosen
//! signer, which is what the package manager reports as the current signer.
//!
//! RSA signer keys under 2048 bits (Orbot is signed with the Tor Project's
//! RSA 1024 key) are verified with ring's legacy PKCS#1 v1.5 verifier and
//! reported as legacy; RSA-PSS and keys under 1024 bits are refused.

pub mod axml;
pub mod sigblock;
pub mod zip;

#[cfg(test)]
pub mod testapk;
#[cfg(test)]
mod tests;

use crate::util::hex;
use serde::Serialize;
use std::io::Read;
use std::path::Path;

/// Largest APK accepted (the debug messenger build is about 280 MB).
pub const MAX_APK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApkInfo {
    pub package: String,
    pub version_code: u64,
    pub version_name: Option<String>,
    /// SHA-256 of the whole file, lowercase hex.
    pub sha256: String,
    pub size: u64,
    /// SHA-256 of the chosen signer's certificate (DER), lowercase hex.
    pub signer_sha256: String,
    /// "v2", "v3" or "v3.1".
    pub scheme: String,
    /// The signer's RSA key size when it is under 2048 bits (a legacy key,
    /// such as Orbot's RSA 1024). Absent for stronger keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_rsa_bits: Option<usize>,
    /// The intent filters that take web links (see `axml::link_filters`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub link_filters: Vec<axml::LinkFilter>,
}

impl ApkInfo {
    /// A warning line about a weak signer key, if any.
    pub fn key_warning(&self) -> Option<String> {
        self.legacy_rsa_bits.map(|b| {
            format!("the signer key is RSA {b} bits (legacy, below 2048); the pinned signer digest is what is trusted")
        })
    }

    /// The hosts Android verifies when this APK is installed (app link
    /// verification: one `https://HOST/.well-known/assetlinks.json` fetch
    /// each).
    pub fn auto_verify_hosts(&self) -> Vec<String> {
        axml::auto_verify_hosts(&self.link_filters)
    }

    /// Scheme, host or `autoVerify` values given as resource references,
    /// which this reader does not resolve.
    pub fn unresolved_links(&self) -> Vec<String> {
        self.link_filters
            .iter()
            .flat_map(|f| {
                f.unresolved
                    .iter()
                    .map(move |u| format!("{} {u}", f.component))
            })
            .collect()
    }
}

/// Reads and checks the APK at `path`.
pub fn inspect(path: &Path) -> Result<ApkInfo, String> {
    let shown = path.display();
    let mut f = std::fs::File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.len() > MAX_APK_BYTES {
        return Err(format!("{shown} is larger than {MAX_APK_BYTES} bytes"));
    }
    let size = meta.len();
    let layout = zip::Layout::read(&mut f, size).map_err(|e| format!("{shown}: {e}"))?;
    let manifest = zip::read_entry(&mut f, &layout, "AndroidManifest.xml")
        .map_err(|e| format!("{shown}: {e}"))?;
    let m = axml::manifest_info(&manifest).map_err(|e| format!("{shown}: manifest: {e}"))?;
    let link_filters =
        axml::link_filters(&manifest).map_err(|e| format!("{shown}: manifest: {e}"))?;
    let signer = sigblock::verify(&mut f, &layout).map_err(|e| format!("{shown}: {e}"))?;
    let sha256 = file_sha256(&mut f).map_err(|e| format!("cannot read {shown}: {e}"))?;
    Ok(ApkInfo {
        package: m.package,
        version_code: m.version_code,
        version_name: m.version_name,
        sha256,
        size,
        signer_sha256: hex(&signer.cert_sha256),
        scheme: signer.scheme.to_string(),
        legacy_rsa_bits: signer.legacy_rsa_bits,
        link_filters,
    })
}

/// The verified signer's certificate (DER) of an APK file.
pub fn signer_cert(path: &Path) -> Result<Vec<u8>, String> {
    let shown = path.display();
    let mut f = std::fs::File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let size = f
        .metadata()
        .map_err(|e| format!("cannot read {shown}: {e}"))?
        .len();
    let layout = zip::Layout::read(&mut f, size).map_err(|e| format!("{shown}: {e}"))?;
    let signer = sigblock::verify(&mut f, &layout).map_err(|e| format!("{shown}: {e}"))?;
    Ok(signer.cert_der)
}

/// Java's `Arrays.hashCode` of a certificate, as Android's package manager
/// prints a signature in `dumpsys package` (`signatures:[1a2b3c4d]`).
pub fn java_hash(der: &[u8]) -> u32 {
    der.iter().fold(1i32, |h, &b| {
        h.wrapping_mul(31).wrapping_add(b as i8 as i32)
    }) as u32
}

/// Only the signer digest (for the installed `base.apk` cross-check).
pub fn signer_digest(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let mut f = std::fs::File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let size = f
        .metadata()
        .map_err(|e| format!("cannot read {shown}: {e}"))?
        .len();
    let layout = zip::Layout::read(&mut f, size).map_err(|e| format!("{shown}: {e}"))?;
    let signer = sigblock::verify(&mut f, &layout).map_err(|e| format!("{shown}: {e}"))?;
    Ok(hex(&signer.cert_sha256))
}

fn file_sha256(f: &mut std::fs::File) -> std::io::Result<String> {
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(0))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex(ctx.finish().as_ref()))
}
