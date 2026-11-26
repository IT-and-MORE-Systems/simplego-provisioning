// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Local trust cache (configured directory, outside the repository). Each
//! downloaded file has a `.meta.json` with fetch time and HTTP Last-Modified.

use super::lists::{GrapheneOsKeys, RevocationList};
use crate::util::{hex, sha256};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const REVOCATION_FILE: &str = "revocation-status.json";
pub const GOS_FILE: &str = "grapheneos-attestation.json";
pub const GOS_SIG_FILE: &str = "grapheneos-attestation.json.sig";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Meta {
    pub url: String,
    /// Unix seconds when the file was fetched.
    pub fetched_at: u64,
    pub last_modified: Option<String>,
    pub sha256: String,
    /// None: downloaded by `trust refresh` through Tor. Some: where the file
    /// came from otherwise (`trust import` writes "manually placed ...").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Meta {
    /// Human readable origin of the cached file.
    pub fn source_label(&self) -> String {
        match &self.source {
            Some(s) => s.clone(),
            None => format!("downloaded through Tor from {}", self.url),
        }
    }
}

pub struct Cache {
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Loaded<T> {
    pub value: T,
    pub meta: Meta,
}

impl Cache {
    pub fn new(dir: &Path) -> Cache {
        Cache {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.meta.json"))
    }

    pub fn read_meta(&self, name: &str) -> Result<Meta, String> {
        let p = self.meta_path(name);
        let b = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", p.display()))
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let p = self.path(name);
        std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))
    }

    /// Loads the revocation list. Missing or damaged means the tool refuses
    /// to verify.
    pub fn load_revocation(&self) -> Result<Loaded<RevocationList>, String> {
        let data = self.read(REVOCATION_FILE)?;
        let meta = self.read_meta(REVOCATION_FILE)?;
        check_hash(&data, &meta)?;
        Ok(Loaded {
            value: RevocationList::parse(&data)?,
            meta,
        })
    }

    /// Loads the GrapheneOS key list and checks its signature again.
    pub fn load_grapheneos(&self) -> Result<Loaded<GrapheneOsKeys>, String> {
        let data = self.read(GOS_FILE)?;
        let sig = self.read(GOS_SIG_FILE)?;
        let meta = self.read_meta(GOS_FILE)?;
        check_hash(&data, &meta)?;
        let sig = String::from_utf8(sig).map_err(|_| "signature file is not text")?;
        Ok(Loaded {
            value: GrapheneOsKeys::verify_and_parse(&data, &sig)?,
            meta,
        })
    }

    pub fn ensure_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Writes files atomically (temp file, then rename), data before meta.
    pub fn store(
        &self,
        files: &[(&str, &[u8])],
        meta_for: &str,
        meta: &Meta,
    ) -> Result<(), String> {
        self.ensure_dir()?;
        for (name, data) in files {
            write_atomic(&self.path(name), data)?;
        }
        let m = serde_json::to_vec_pretty(meta).map_err(|e| e.to_string())?;
        write_atomic(&self.meta_path(meta_for), &m)
    }
}

pub fn meta_for(url: &str, fetched_at: u64, last_modified: Option<String>, data: &[u8]) -> Meta {
    Meta {
        url: url.to_string(),
        fetched_at,
        last_modified,
        sha256: hex(&sha256(data)),
        source: None,
    }
}

fn check_hash(data: &[u8], meta: &Meta) -> Result<(), String> {
    if hex(&sha256(data)) != meta.sha256 {
        return Err("cached file does not match its recorded SHA-256".into());
    }
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sxprov-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn missing_lists_are_errors() {
        let c = Cache::new(&tmpdir("missing"));
        assert!(c.load_revocation().is_err());
        assert!(c.load_grapheneos().is_err());
    }

    #[test]
    fn store_and_load_roundtrip_and_tamper() {
        let dir = tmpdir("roundtrip");
        let c = Cache::new(&dir);
        let status = include_bytes!("../../tests/fixtures/trust/status-sample.json");
        let m = meta_for(
            "u",
            100,
            Some("Mon, 16 Nov 2026 20:48:00 GMT".into()),
            status,
        );
        c.store(&[(REVOCATION_FILE, status)], REVOCATION_FILE, &m)
            .unwrap();
        let l = c.load_revocation().unwrap();
        assert_eq!(l.meta, m);
        assert_eq!(l.value.entries.len(), 4);

        let json = include_bytes!("../../tests/fixtures/trust/attestation.json");
        let sig = include_bytes!("../../tests/fixtures/trust/attestation.json.sig");
        let gm = meta_for("u", 100, None, json);
        c.store(&[(GOS_FILE, json), (GOS_SIG_FILE, sig)], GOS_FILE, &gm)
            .unwrap();
        assert_eq!(c.load_grapheneos().unwrap().value.keys.len(), 21);

        // A changed file no longer matches its meta and is refused.
        std::fs::write(dir.join(REVOCATION_FILE), b"{\"entries\":{}}").unwrap();
        assert!(c.load_revocation().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
