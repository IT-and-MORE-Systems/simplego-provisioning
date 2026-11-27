// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Product `admin-store` (section 5.3): `admin/store.sxdb` (the encrypted
//! store as it is on disk), `admin/store-key` (its key text, so a restore
//! works without the old laptop's TPM), `admin/config.toml` (the config
//! without paths of this machine). `admin/organizer/<set_id>/` is reserved
//! for the organizer databases of a later version; none exist yet, and a backup that carries one is
//! refused until that is built. Not in a backup: the activation signing
//! key, trust lists, APKs, factory images.

use super::tar::Member;
use crate::activation::store::{self, StoreData};
use crate::activation::storekey;

pub const PRODUCT: &str = "admin-store";
pub const STORE: &str = "admin/store.sxdb";
pub const KEY: &str = "admin/store-key";
pub const CONFIG: &str = "admin/config.toml";
pub const ORGANIZER_PREFIX: &str = "admin/organizer/";

/// Config keys that name paths of this machine; left out of the backup.
pub const PATH_KEYS: [&str; 7] = [
    "admin_store_path",
    "adb_path",
    "fastboot_path",
    "agent_apk",
    "trust_cache_dir",
    "grapheneos_cache_dir",
    "flash_log_dir",
];

/// The config text without the lines of `PATH_KEYS` (the config is flat
/// `key = value` TOML; comments and every other line stay).
pub fn strip_paths(config: &str) -> String {
    let mut out = String::with_capacity(config.len());
    for line in config.split_inclusive('\n') {
        let key = line
            .trim_start()
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .unwrap_or("");
        if !PATH_KEYS.contains(&key) || line.trim_start().starts_with('#') {
            out.push_str(line);
        }
    }
    out
}

/// The members of one backup.
pub fn members(store_file: &[u8], key: &[u8; 32], config: Option<&str>) -> Vec<Member> {
    let mut m = vec![
        Member {
            path: STORE.into(),
            data: store_file.to_vec(),
        },
        Member {
            path: KEY.into(),
            data: storekey::to_text(key).as_bytes().to_vec(),
        },
    ];
    if let Some(c) = config {
        m.push(Member {
            path: CONFIG.into(),
            data: strip_paths(c).into_bytes(),
        });
    }
    m
}

/// What an admin-store backup holds, checked: the store opens with the key
/// it carries.
pub struct Restored {
    pub store_file: Vec<u8>,
    pub key: storekey::StoreKey,
    pub config: Option<String>,
    pub data: StoreData,
}

pub fn read(members: Vec<Member>) -> Result<Restored, String> {
    let mut store_file = None;
    let mut key = None;
    let mut config = None;
    for m in &members {
        match m.path.as_str() {
            STORE => store_file = Some(m.data.clone()),
            KEY => key = Some(storekey::from_text(&m.data).map_err(|e| format!("{KEY}: {e}"))?),
            CONFIG => {
                config = Some(
                    String::from_utf8(m.data.clone())
                        .map_err(|_| format!("{CONFIG} is not UTF-8"))?,
                )
            }
            p if p.starts_with(ORGANIZER_PREFIX) => {
                return Err(format!(
                    "{p}: organizer databases are not restored by this sxprov yet"
                ))
            }
            p => return Err(format!("{p}: not a member of an admin-store backup")),
        }
    }
    let store_file = store_file.ok_or(format!("{STORE} is missing"))?;
    let key = key.ok_or(format!("{KEY} is missing"))?;
    let data = store::decrypt(&store_file, &key, STORE)
        .map_err(|e| format!("{STORE} does not open with {KEY}: {e}"))?;
    Ok(Restored {
        store_file,
        key,
        config,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_without_machine_paths() {
        let c = "# sxprov\nadb_path = \"/usr/bin/adb\"\n  trust_cache_dir=\"/x\"\ntor_socks_proxy = \"socks5h://127.0.0.1:9050\"\n# adb_path = \"kept comment\"\nadmin_store_path = \"/home/op/s.sxdb\"\nmax_os_age_days = 30\n";
        assert_eq!(
            strip_paths(c),
            "# sxprov\ntor_socks_proxy = \"socks5h://127.0.0.1:9050\"\n# adb_path = \"kept comment\"\nmax_os_age_days = 30\n"
        );
    }
}
