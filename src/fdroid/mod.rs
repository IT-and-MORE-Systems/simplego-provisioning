// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! SimpleX's own F-Droid repository at delivery: the signed index is checked in pure Rust before an APK is taken
//! from it, then the APK is downloaded over Tor and checked against the
//! index and, independently, against the pinned app signer.
//!
//! Order:
//!
//! 1. `entry.jar` over Tor, verified against the pinned repository
//!    fingerprint (`jar`), which gives `entry.json`;
//! 2. its `timestamp` is not older than the last one recorded in the admin
//!    store for this repository (no rollback); an old index gives a warning;
//! 3. `index-v2.json` over Tor, its size and SHA-256 as `entry.json` names;
//! 4. `repo.address` is the configured repository; the newest version of
//!    the app that is not a beta, fits the phone's ABI and SDK, and is
//!    signed by exactly the pinned signer; its file name is a plain name at
//!    the repository root;
//! 5. the APK over Tor, its size and SHA-256 as the index names (the caller
//!    then reads it with the APK reader: package, version code, signer).

pub mod jar;

#[cfg(test)]
pub mod testrepo;
#[cfg(test)]
mod tests;

use crate::grapheneos::{read_small, Http};
use crate::util::hex;
use serde::Deserialize;
use serde_json::Value;
use std::io::{Read, Write};
use std::path::Path;

/// Largest `index-v2.json` accepted (the real one is about 110 KB).
pub const MAX_INDEX: u64 = 32 * 1024 * 1024;
/// Largest APK downloaded from the repository.
pub const MAX_APK: u64 = 1024 * 1024 * 1024;
/// An index older than this gives a warning (it is not refused).
pub const INDEX_WARN_AGE_DAYS: u64 = 180;

#[derive(Debug, Deserialize)]
struct Entry {
    timestamp: u64,
    version: u64,
    index: FileRef,
}

#[derive(Debug, Clone, Deserialize)]
struct FileRef {
    name: String,
    sha256: String,
    size: u64,
}

/// The repository as configured.
#[derive(Debug, Clone)]
pub struct Repo<'a> {
    /// `https://...`, no trailing slash.
    pub url: &'a str,
    /// SHA-256 of the index signing certificate, hex.
    pub fingerprint: &'a str,
}

/// What the app must be, and the phone it is for.
#[derive(Debug, Clone)]
pub struct Want<'a> {
    pub package: &'a str,
    /// The pinned signer, hex.
    pub signer: &'a str,
    /// `ro.product.cpu.abilist`, in the phone's order of preference.
    pub abis: Vec<String>,
    pub sdk: u64,
}

/// The version chosen from the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    pub version_code: u64,
    pub version_name: String,
    /// The file name at the repository root, without the leading slash.
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub abi: String,
}

/// A checked index.
#[derive(Debug, Clone)]
pub struct Checked {
    /// `entry.json` `timestamp` (milliseconds).
    pub timestamp_ms: u64,
    pub index_sha256: String,
    pub pick: Pick,
    /// Versions left out as betas (newer than the pick), for the output.
    pub betas_skipped: Vec<String>,
}

fn get_small(http: &dyn Http, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut r = http.get(url, 0)?;
    if r.status != 200 {
        return Err(format!("{url}: HTTP {}", r.status));
    }
    read_small(&mut r, limit, url)
}

/// A pre-release version name (`7.1-beta.9`, `2.0-alpha1`, `1.0-rc2`).
pub fn is_prerelease(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["beta", "alpha", "-rc", ".rc", "-dev", "snapshot"]
        .iter()
        .any(|w| n.contains(w))
}

fn plain_file(name: &str) -> Option<String> {
    let f = name.strip_prefix('/')?;
    let ok = !f.is_empty()
        && f.len() <= 200
        && f.ends_with(".apk")
        && !f.starts_with('.')
        && f.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    ok.then(|| f.to_string())
}

/// Chooses the version from `index-v2.json` (step 4 of the module comment).
pub fn choose(index: &Value, repo: &Repo, want: &Want) -> Result<(Pick, Vec<String>), String> {
    let addr = index["repo"]["address"].as_str().unwrap_or_default();
    if addr.trim_end_matches('/') != repo.url {
        return Err(format!(
            "the index names the repository {addr:?}, not the configured {}",
            repo.url
        ));
    }
    let versions = index["packages"][want.package]["versions"]
        .as_object()
        .ok_or_else(|| format!("the index has no package {}", want.package))?;
    let mut cands: Vec<(u64, usize, Pick)> = Vec::new();
    let mut betas = Vec::new();
    for v in versions.values() {
        let m = &v["manifest"];
        let Some(code) = m["versionCode"].as_u64() else {
            continue;
        };
        let name = m["versionName"].as_str().unwrap_or_default().to_string();
        let channels = v["releaseChannels"]
            .as_array()
            .is_some_and(|a| !a.is_empty());
        if channels || is_prerelease(&name) {
            betas.push((code, name));
            continue;
        }
        let signers: Vec<&str> = m["signer"]["sha256"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if signers.len() != 1 || !signers[0].eq_ignore_ascii_case(want.signer) {
            continue;
        }
        let min_sdk = m["usesSdk"]["minSdkVersion"].as_u64().unwrap_or(1);
        if min_sdk > want.sdk {
            continue;
        }
        let native: Vec<&str> = m["nativecode"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        // The phone's most preferred ABI the APK has (none listed: any).
        let abi_rank = if native.is_empty() {
            Some((0, String::new()))
        } else {
            want.abis
                .iter()
                .enumerate()
                .find(|(_, a)| native.contains(&a.as_str()))
                .map(|(i, a)| (i, a.clone()))
        };
        let Some((rank, abi)) = abi_rank else {
            continue;
        };
        let f = &v["file"];
        let Some(file) = f["name"].as_str().and_then(plain_file) else {
            return Err(format!(
                "the index names an unsafe file for version {code}: {:?}",
                f["name"]
            ));
        };
        let sha256 = f["sha256"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let size = f["size"].as_u64().unwrap_or(0);
        if !crate::util::is_sha256_hex(&sha256) || size == 0 {
            return Err(format!(
                "the index entry of version {code} has no file digest or size"
            ));
        }
        cands.push((
            code,
            rank,
            Pick {
                version_code: code,
                version_name: name,
                file,
                sha256,
                size,
                abi,
            },
        ));
    }
    // Highest version code; for equal codes the phone's preferred ABI.
    cands.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let pick = cands.into_iter().next().map(|c| c.2).ok_or_else(|| {
        format!(
            "the index has no release of {} for this phone (ABI {}, SDK {}) signed by the pinned signer {}",
            want.package,
            want.abis.join(","),
            want.sdk,
            want.signer
        )
    })?;
    let mut newer: Vec<(u64, String)> = betas
        .into_iter()
        .filter(|(c, _)| *c > pick.version_code)
        .collect();
    newer.sort();
    newer.dedup();
    Ok((
        pick,
        newer
            .into_iter()
            .map(|(c, n)| format!("{n} ({c})"))
            .collect(),
    ))
}

/// Steps 1 to 4: the verified index and the chosen version. `last_ms` is
/// the newest index timestamp recorded for this repository (None: none).
pub fn check_index(
    http: &dyn Http,
    repo: &Repo,
    want: &Want,
    last_ms: Option<u64>,
    now: u64,
    log: &mut dyn FnMut(String),
) -> Result<Checked, String> {
    let entry_url = format!("{}/entry.jar", repo.url);
    let jar_bytes = get_small(http, &entry_url, jar::MAX_ENTRY_JAR as u64)?;
    let entry_json = jar::verify_entry_jar(&jar_bytes, repo.fingerprint)?;
    let entry: Entry =
        serde_json::from_slice(&entry_json).map_err(|e| format!("entry.json: {e}"))?;
    if entry.version < 20000 {
        return Err(format!(
            "entry.json: index version {} is not v2",
            entry.version
        ));
    }
    log(format!(
        "index signed by the pinned repository key {}; index time {}",
        repo.fingerprint.to_ascii_lowercase(),
        crate::util::fmt_unix(entry.timestamp / 1000)
    ));
    if let Some(last) = last_ms {
        if entry.timestamp < last {
            return Err(format!(
                "INDEX ROLLBACK: the index is from {}, older than the one already seen ({}); refused",
                crate::util::fmt_unix(entry.timestamp / 1000),
                crate::util::fmt_unix(last / 1000)
            ));
        }
    }
    let age_days = now.saturating_sub(entry.timestamp / 1000) / 86_400;
    if age_days > INDEX_WARN_AGE_DAYS {
        log(format!(
            "WARNING: the repository index is {age_days} days old"
        ));
    }
    let name = entry
        .index
        .name
        .strip_prefix('/')
        .filter(|n| *n == "index-v2.json")
        .ok_or_else(|| format!("entry.json names the index {:?}", entry.index.name))?;
    if entry.index.size > MAX_INDEX {
        return Err("the index is larger than 32 MiB".into());
    }
    let index_url = format!("{}/{name}", repo.url);
    let body = get_small(http, &index_url, MAX_INDEX)?;
    let sha = hex(&crate::util::sha256(&body));
    if body.len() as u64 != entry.index.size || !sha.eq_ignore_ascii_case(&entry.index.sha256) {
        return Err(format!(
            "INDEX SIGNATURE BROKEN: index-v2.json ({} bytes, SHA-256 {sha}) is not the one entry.json names ({} bytes, {})",
            body.len(),
            entry.index.size,
            entry.index.sha256
        ));
    }
    let index: Value = serde_json::from_slice(&body).map_err(|e| format!("index-v2.json: {e}"))?;
    let (pick, betas) = choose(&index, repo, want)?;
    Ok(Checked {
        timestamp_ms: entry.timestamp,
        index_sha256: sha,
        pick,
        betas_skipped: betas,
    })
}

/// Step 5: the APK into `dest` (a new file), size and SHA-256 as the index
/// names. A wrong file is deleted.
pub fn download(http: &dyn Http, repo: &Repo, pick: &Pick, dest: &Path) -> Result<(), String> {
    if pick.size > MAX_APK {
        return Err("the APK is larger than 1 GiB".into());
    }
    let url = format!("{}/{}", repo.url, pick.file);
    let r = (|| {
        let mut resp = http.get(&url, 0)?;
        if resp.status != 200 {
            return Err(format!("{url}: HTTP {}", resp.status));
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buf = vec![0u8; 1 << 20];
        let mut n: u64 = 0;
        let mut body = (&mut resp.body).take(pick.size + 1);
        loop {
            let k = body.read(&mut buf).map_err(|e| format!("{url}: {e}"))?;
            if k == 0 {
                break;
            }
            n += k as u64;
            if n > pick.size {
                return Err(format!("{url}: larger than the index says"));
            }
            ctx.update(&buf[..k]);
            f.write_all(&buf[..k])
                .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
        }
        let sha = hex(ctx.finish().as_ref());
        if n != pick.size || sha != pick.sha256 {
            return Err(format!(
                "the downloaded APK ({n} bytes, SHA-256 {sha}) is not the one the index names ({} bytes, {})",
                pick.size, pick.sha256
            ));
        }
        Ok(())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    r
}
