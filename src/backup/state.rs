// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The backup state next to the store: `<store>.backup.json`, mode 0600.
//! No secret: the recipient, the wrapped seed, the destinations, our own
//! list of written files (name, size, SHA-256 of the whole file, SHA-256 of
//! the store file inside), the last drill. Kept outside the store, because
//! the list changes after every backup and a store write starts a backup.

use crate::activation::store::{write_atomic_plain, write_new_private};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FORMAT: u32 = 1;
/// The always-on destination on the laptop's own disk.
pub const LOCAL: &str = "local";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    /// A folder (USB stick, PC share mounted here, the laptop's own disk).
    Folder { path: PathBuf },
    /// WebDAV or Nextcloud, over Tor; the credentials in a file of their own.
    Webdav { url: String, credentials: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub name: String,
    /// 16 random bytes, hex; the folder marker holds it.
    pub id: String,
    #[serde(flatten)]
    pub target: Target,
    /// On the laptop itself (does not count as off the laptop).
    pub on_laptop: bool,
    pub added_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Written {
    pub destination: String,
    pub file: String,
    pub size: u64,
    pub sha256: String,
    /// SHA-256 of `admin/store.sxdb` inside: what the drill compares.
    pub store_sha256: String,
    pub created_unix: u64,
    /// Read back and checked with the file key (section "after every
    /// backup").
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub format: u32,
    pub recipient: String,
    /// base64 of the age scrypt file, as in every backup header.
    pub wrapped_seed: String,
    pub created_unix: u64,
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub written: Vec<Written>,
    #[serde(default)]
    pub last_drill_unix: Option<u64>,
    /// The last failed backup attempt per destination (name, time, reason).
    #[serde(default)]
    pub last_failure: Vec<(String, u64, String)>,
}

pub fn path(store: &Path) -> PathBuf {
    let mut n = store.file_name().unwrap_or_default().to_os_string();
    n.push(".backup.json");
    store.with_file_name(n)
}

/// The default local destination: `backups/` next to the store.
pub fn local_folder(store: &Path) -> PathBuf {
    store.with_file_name("backups")
}

impl State {
    pub fn load(store: &Path) -> Result<Option<State>, String> {
        let p = path(store);
        let raw = match std::fs::read(&p) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", p.display())),
        };
        let s: State =
            serde_json::from_slice(&raw).map_err(|e| format!("{} is damaged: {e}", p.display()))?;
        if s.format != FORMAT {
            return Err(format!(
                "{}: backup state format {} (this sxprov reads {FORMAT})",
                p.display(),
                s.format
            ));
        }
        Ok(Some(s))
    }

    pub fn save(&self, store: &Path) -> Result<(), String> {
        let p = path(store);
        let data = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let r = if p.exists() {
            write_atomic_plain(&p, &data)
        } else {
            write_new_private(&p, &data)
        };
        r.map_err(|e| format!("cannot write {}: {e}", p.display()))
    }

    pub fn destination(&self, name: &str) -> Option<&Destination> {
        self.destinations.iter().find(|d| d.name == name)
    }

    pub fn written_at(&self, dest: &str) -> Vec<&Written> {
        let mut v: Vec<&Written> = self
            .written
            .iter()
            .filter(|w| w.destination == dest)
            .collect();
        v.sort_by_key(|w| (w.created_unix, w.file.clone()));
        v
    }

    /// The newest verified backup at any destination.
    pub fn last_good(&self) -> Option<u64> {
        self.written
            .iter()
            .filter(|w| w.verified)
            .map(|w| w.created_unix)
            .max()
    }

    /// The newest verified backup off the laptop.
    pub fn last_good_off_laptop(&self) -> Option<u64> {
        self.written
            .iter()
            .filter(|w| {
                w.verified
                    && self
                        .destination(&w.destination)
                        .is_some_and(|d| !d.on_laptop)
            })
            .map(|w| w.created_unix)
            .max()
    }

    pub fn note_failure(&mut self, dest: &str, now: u64, reason: &str) {
        self.last_failure.retain(|(d, _, _)| d != dest);
        self.last_failure
            .push((dest.to_string(), now, reason.to_string()));
    }

    pub fn clear_failure(&mut self, dest: &str) {
        self.last_failure.retain(|(d, _, _)| d != dest);
    }
}

/// Rotation (section 6, 5.3, decision of 2026-11-27): per destination the
/// newest 30 files, and besides them the newest file of each of the last
/// 30 days. Returns the files to delete, oldest first.
pub fn to_delete<'a>(written: &[&'a Written], now: u64) -> Vec<&'a Written> {
    const KEEP_LAST: usize = 30;
    const DAYS: u64 = 30;
    let mut keep: std::collections::BTreeSet<(u64, String)> = std::collections::BTreeSet::new();
    let mut newest_first: Vec<&&Written> = written.iter().collect();
    newest_first.sort_by_key(|w| std::cmp::Reverse((w.created_unix, w.file.clone())));
    for w in newest_first.iter().take(KEEP_LAST) {
        keep.insert((w.created_unix, w.file.clone()));
    }
    let today = now / 86_400;
    let mut days_seen = std::collections::BTreeSet::new();
    for w in &newest_first {
        let day = w.created_unix / 86_400;
        if today.saturating_sub(day) < DAYS && days_seen.insert(day) {
            keep.insert((w.created_unix, w.file.clone()));
        }
    }
    let mut del: Vec<&Written> = written
        .iter()
        .filter(|w| !keep.contains(&(w.created_unix, w.file.clone())))
        .copied()
        .collect();
    del.sort_by_key(|w| w.created_unix);
    del
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(t: u64) -> Written {
        Written {
            destination: "d".into(),
            file: crate::backup::container::file_name(t),
            size: 1,
            sha256: String::new(),
            store_sha256: String::new(),
            created_unix: t,
            verified: true,
        }
    }

    #[test]
    fn rotation_keeps_30_and_one_per_day() {
        let day = 86_400;
        let now = 100 * day + day / 2;
        // 40 backups today, one per day for the 40 days before.
        let mut all: Vec<Written> = (0..40).map(|i| w(now - i * 60)).collect();
        all.extend((1..=40).map(|d| w(now - d * day)));
        let refs: Vec<&Written> = all.iter().collect();
        let del = to_delete(&refs, now);
        let kept: Vec<u64> = all
            .iter()
            .filter(|x| !del.iter().any(|d| d.created_unix == x.created_unix))
            .map(|x| x.created_unix)
            .collect();
        // The 30 newest (all from today) plus one for each of the 29 days
        // before today that are inside the 30 days.
        assert_eq!(kept.len(), 30 + 29);
        assert!(kept.contains(&(now - 29 * day)));
        assert!(!kept.contains(&(now - 30 * day)));
        assert!(del
            .windows(2)
            .all(|p| p[0].created_unix <= p[1].created_unix));
        // Fewer than 30: nothing deleted.
        let few: Vec<&Written> = all[..10].iter().collect();
        assert!(to_delete(&few, now).is_empty());
    }
}
