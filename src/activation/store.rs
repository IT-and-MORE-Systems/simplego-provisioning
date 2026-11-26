// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Encrypted local admin store (format document section 8).
//!
//! One file, JSON inside, encrypted at rest:
//! `SXDB` | version 1 | m_kib u32 | t u32 | p u8 | salt 16 | nonce 12 |
//! ct_len u32 | AES-256-GCM ciphertext (the 46-byte header is the AAD).
//! The key is Argon2id from the store passphrase. Holds per customer the
//! update key (and the earlier ones after a rotation), the last sequence,
//! and the fleet log. Never a copy of an issued file, never a full code,
//! never a server password. Written atomically, previous version as `.bak`,
//! mode 0600. Refuses any path inside a git repository.
//!
//! Lock: every command that uses the store holds an exclusive advisory
//! `flock` on `<store>.lock` (for example `admin-store.sxdb.lock`, mode
//! 0600) from before it reads the store until after its last write. A
//! second `sxprov` process gets `StoreError::Locked` at once; it never
//! waits and never writes. The lock file holds no data. The kernel drops
//! the lock when the holder exits, so a lock file left behind is harmless
//! and is reused. Never delete the lock file while a command runs: a
//! second process would lock a new file and both could write.

use super::container::{argon2id, open, seal};
use super::payload::{DeviceClass, Kind, NetworkMode};
use super::rng::{bytes, Rand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 4] = b"SXDB";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 46;
pub const DEFAULT_RELATIVE_PATH: &str = ".local/share/sxprov/admin-store.sxdb";
pub const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreKdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

/// Argon2id 64 MiB, 3 passes, 1 lane.
pub const STORE_KDF: StoreKdf = StoreKdf {
    m_kib: 65_536,
    t: 3,
    p: 1,
};
/// Small parameters, for the tests only.
#[cfg(test)]
pub const TEST_KDF: StoreKdf = StoreKdf {
    m_kib: 1024,
    t: 1,
    p: 1,
};

fn kdf_acceptable(k: &StoreKdf) -> bool {
    let (m_min, t_min) = if cfg!(test) { (1024, 1) } else { (65_536, 3) };
    (m_min..=1_048_576).contains(&k.m_kib) && (t_min..=10).contains(&k.t) && (1..=4).contains(&k.p)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreData {
    pub store_version: u32,
    pub customers: BTreeMap<String, Customer>,
    pub issues: Vec<Issue>,
    #[serde(default)]
    pub deliveries: Vec<Delivery>,
    #[serde(default)]
    pub flashes: Vec<Flash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Customer {
    /// Current update key, 64 lowercase hex characters.
    pub update_key: String,
    /// Earlier update keys after a rotation, oldest first (section 8).
    #[serde(default)]
    pub previous_update_keys: Vec<PreviousKey>,
    pub last_sequence: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousKey {
    pub update_key: String,
    pub retired_at: String,
}

impl Drop for Customer {
    fn drop(&mut self) {
        self.update_key.zeroize();
        for k in &mut self.previous_update_keys {
            k.update_key.zeroize();
        }
    }
}

/// One fleet log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub file_id: String,
    pub kind: Kind,
    pub customer_ref: String,
    pub device_class: DeviceClass,
    pub network_mode: NetworkMode,
    pub issued_at: String,
    /// key_id of the signing key (hex).
    pub key_id: String,
    /// `sequence` in the payload (activation: the customer's state at issue).
    pub sequence: u64,
    /// Update key id: of the key the activation carries, or of the key the
    /// update is encrypted under.
    pub update_key_id: String,
    /// The update carries a new update key.
    #[serde(default)]
    pub rotated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Activation code masked as `4*****x*****7`; never the full code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_masked: Option<String>,
}

/// Content version of the store. 1: customers and issues. 2: also the
/// `deliveries` fleet records. 3: also the
/// `flashes` records. An older store is migrated
/// when it is opened and written as version 3 on the next save; an older
/// `sxprov` refuses a newer store instead of dropping records.
pub const CONTENT_VERSION: u32 = 3;

/// One GrapheneOS installation (`sxprov flash`). The full serial lives only
/// here, inside the encrypted store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flash {
    /// 16 random bytes, hex.
    pub flash_id: String,
    pub serial: String,
    pub serial_masked: String,
    pub codename: String,
    /// `--test-device` was given.
    pub test_device: bool,
    /// The version the phone reported before (None: not GrapheneOS).
    pub old_version: Option<String>,
    pub old_build_type: Option<String>,
    pub new_version: String,
    /// `release` or `security preview` (or why neither).
    pub new_build_type: String,
    pub channel: String,
    pub image_sha256: String,
    /// Verified boot key the attestation showed after the flash (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_boot_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// `flashed`, or `failed at step N`.
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    /// Seconds per part (download, unpack, unlock, flash script, lock,
    /// setup, attestation).
    #[serde(default)]
    pub durations: BTreeMap<String, u64>,
    /// `flash --resume`: the step the run continued at (6 to 9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at_step: Option<u8>,
    /// The sxprov version that ran it (`0.1.0-alpha+N`). None in records
    /// written before 0.1.0-alpha.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sxprov_version: Option<String>,
}

/// One delivery of a phone (`sxprov deliver`), its undo and its handover.
/// The full serial lives only here, inside the encrypted store. Never a
/// full code, a name, a server password or a copy of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// 16 random bytes, hex.
    pub delivery_id: String,
    pub serial: String,
    pub serial_masked: String,
    pub device_class: DeviceClass,
    /// `hardened` or `normal-phone tier`.
    pub tier: String,
    /// A test delivery (TEST ONLY key, `--test-delivery`).
    pub test: bool,
    pub model: Option<String>,
    pub os_build: Option<String>,
    pub security_patch: Option<String>,
    /// The overall label of the attestation, or why none ran.
    pub attestation: String,
    /// The messenger package of this delivery, from its APK.
    pub messenger_package: String,
    /// The sxprov version that ran it (`0.1.0-alpha+N`). None in records
    /// written before 0.1.0-alpha.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sxprov_version: Option<String>,
    pub messenger_version_code: Option<u64>,
    pub messenger_version_name: Option<String>,
    pub messenger_apk_sha256: Option<String>,
    /// The signer digest of the APK file, or None before step 4.
    pub messenger_signer_sha256: Option<String>,
    /// False: the digest is not pinned in the config (`messenger UNVERIFIED`).
    pub messenger_verified: bool,
    pub reinstall: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orbot: Option<OrbotRecord>,
    /// The F-Droid client and the normal SimpleX app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fdroid: Option<AppRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simplex_app: Option<AppRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simplex_repo: Option<RepoRecord>,
    /// Orbot's VPN, the always-on VPN with lockdown, and what was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<VpnRecord>,
    /// The network lock: the always-on VPN with
    /// lockdown, on before any app but the lock itself is installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<LockRecord>,
    /// App link verification at delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_links: Option<AppLinksRecord>,
    /// GrapheneOS version, build type and status at delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    pub network_mode: NetworkMode,
    pub file_transferred: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_masked: Option<String>,
    /// The system calculator package this delivery disabled, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calculator_disabled: Option<String>,
    pub customer_ref: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// `delivered`, `failed at step N`, `undone`, or `in progress` while
    /// the command runs (never saved in that state by a finished command).
    pub result: String,
    /// Why a step failed (no code, no full serial).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handover_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrbotRecord {
    pub package: String,
    pub version_code: u64,
    pub version_name: Option<String>,
    pub apk_sha256: String,
    pub signer_sha256: String,
    /// This delivery installed it (so `undeliver` removes it).
    pub installed_by_delivery: bool,
    /// SOCKS listener on 127.0.0.1:9050 seen on the phone.
    pub socks_listening: bool,
    /// The Orbot switches the set-up found (title, on), and the apps on
    /// Orbot's VPN list before it, for `undeliver` on a phone whose Orbot
    /// was there before the delivery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub found_switches: Vec<(String, bool)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub found_vpn_apps: Vec<String>,
}

/// An app a delivery installs besides the messenger and Orbot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecord {
    pub package: String,
    pub version_code: u64,
    pub version_name: Option<String>,
    pub apk_sha256: String,
    pub signer_sha256: String,
    /// This delivery installed it (so `undeliver` removes it).
    pub installed_by_delivery: bool,
    /// The installer of record given at install (`adb install -i`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer: Option<String>,
}

/// SimpleX's repository as the delivery checked it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRecord {
    pub url: String,
    pub fingerprint: String,
    /// `entry.json` timestamp (milliseconds): later deliveries refuse an
    /// older index (no rollback).
    pub index_timestamp_ms: u64,
    pub index_sha256: String,
    /// The F-Droid client lists the repository.
    pub added_to_client: bool,
}

/// Orbot's VPN at delivery and the system settings found before it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnRecord {
    /// The packages the VPN network carries, as the system reports them.
    pub apps: Vec<String>,
    /// `ACTIVATE_VPN` allowed for Orbot (no consent dialog).
    pub consent: bool,
    pub always_on: bool,
    pub lockdown: bool,
    /// The F-Droid client's own SOCKS proxy set to Orbot.
    pub fdroid_socks_proxy: bool,
    /// What the delivery found, restored by `undeliver` (None: not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found_always_on_app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found_lockdown: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found_activate_vpn: Option<String>,
}

/// The network lock of a delivery: which app provides it (Orbot today),
/// what it carried when it was proven, and the run-time proof.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    /// The package of the lock provider (`org.torproject.android`).
    pub provider: String,
    /// The packages its VPN carried when the lock was proven, before any
    /// other app was installed.
    pub apps_at_lock: Vec<String>,
    /// Proven before the first other install: settings, the run-time mode,
    /// the filtering rules, the VPN's uid list.
    pub proven: bool,
    /// The newest `[LockdownAlwaysOn] Mode changed` line of `dumpsys
    /// vpn_management` at the proof; no newer line may follow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_line: Option<String>,
    /// Proven again after the delivered apps were added to the VPN.
    #[serde(default)]
    pub proven_after_apps: bool,
}

/// App link verification: the verifier (`com.android.statementservice`)
/// is disabled before the first install; the final check proves that no
/// host was verified (no fetch went out).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppLinksRecord {
    /// The verifier package; None when the phone has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// Already disabled before the delivery (then `undeliver` leaves it).
    pub found_disabled: bool,
    /// Disabled by this delivery (`undeliver` enables it again, last).
    pub disabled_by_delivery: bool,
    /// The `autoVerify` web hosts each installed APK declares.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<(String, Vec<String>)>,
    /// Final check: `(package, host, state)` as `pm get-app-links` shows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<(String, String, String)>,
    /// Final check, read only: the verifier's jobs and its network state
    /// as `dumpsys jobscheduler` shows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_jobs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_network: Option<String>,
    /// Final check: the verifier's TCP sockets outside loopback (must be 0).
    #[serde(default)]
    pub verifier_sockets_outside: u32,
    /// The final check ran.
    #[serde(default)]
    pub checked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Missing(String),
    Exists(String),
    InRepository(String),
    WrongPassphrase,
    Damaged(String),
    Io(String),
    /// Another process holds the store lock.
    Locked,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Missing(p) => {
                write!(f, "no admin store at {p}; create it with `store init`")
            }
            StoreError::Exists(p) => write!(f, "an admin store already exists at {p}"),
            StoreError::InRepository(p) => {
                write!(f, "refusing store path {p}: it is inside a git repository")
            }
            StoreError::WrongPassphrase => {
                f.write_str("wrong store passphrase, or the store is damaged; nothing was changed")
            }
            StoreError::Damaged(e) => write!(f, "the admin store is damaged: {e}"),
            StoreError::Io(e) => f.write_str(e),
            StoreError::Locked => f.write_str(
                "the admin store is in use by another sxprov process; nothing was read or changed",
            ),
        }
    }
}

/// `$HOME/.local/share/sxprov/admin-store.sxdb`.
pub fn default_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(DEFAULT_RELATIVE_PATH))
}

/// Refuses a path inside a git repository (any ancestor holding `.git`).
pub fn check_path(path: &Path) -> Result<PathBuf, StoreError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| StoreError::Io(e.to_string()))?
            .join(path)
    };
    let mut existing = abs.parent().map(Path::to_path_buf).unwrap_or_default();
    while !existing.as_os_str().is_empty() && !existing.exists() {
        existing = existing.parent().map(Path::to_path_buf).unwrap_or_default();
    }
    let canon = std::fs::canonicalize(&existing).unwrap_or(existing);
    for a in canon.ancestors() {
        if a.join(".git").exists() {
            return Err(StoreError::InRepository(abs.display().to_string()));
        }
    }
    if abs.is_dir() {
        return Err(StoreError::Io(format!("{} is a directory", abs.display())));
    }
    Ok(abs)
}

/// `<store>.lock`, next to the store.
pub fn lock_path(store: &Path) -> PathBuf {
    sibling(store, ".lock")
}

/// An exclusive `flock` on the store's lock file, held until dropped.
#[derive(Debug)]
pub struct StoreLock {
    store: PathBuf,
    _file: std::fs::File,
}

impl StoreLock {
    /// Takes the lock without waiting. The store's directory must exist.
    /// `store` must already have passed `check_path`.
    pub fn acquire(store: &Path) -> Result<StoreLock, StoreError> {
        let lp = lock_path(store);
        if std::fs::symlink_metadata(&lp).is_ok_and(|m| !m.file_type().is_file()) {
            return Err(StoreError::Io(format!(
                "{} is not a regular file",
                lp.display()
            )));
        }
        let mut o = std::fs::OpenOptions::new();
        o.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let file = o
            .open(&lp)
            .map_err(|e| StoreError::Io(format!("cannot open {}: {e}", lp.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata().map(|m| m.permissions().mode() & 0o777);
            if mode.is_ok_and(|m| m != 0o600) {
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
        }
        match file.try_lock() {
            Ok(()) => Ok(StoreLock {
                store: store.to_path_buf(),
                _file: file,
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(StoreError::Locked),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(StoreError::Io(format!("cannot lock {}: {e}", lp.display())))
            }
        }
    }

    pub fn store_path(&self) -> &Path {
        &self.store
    }
}

pub struct Store {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    kdf: StoreKdf,
    pub data: StoreData,
    /// Held for the life of the store value (see the module comment).
    _lock: StoreLock,
}

fn header(kdf: &StoreKdf, salt: &[u8; 16], nonce: &[u8; 12], ct_len: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5..9].copy_from_slice(&kdf.m_kib.to_be_bytes());
    h[9..13].copy_from_slice(&kdf.t.to_be_bytes());
    h[13] = kdf.p;
    h[14..30].copy_from_slice(salt);
    h[30..42].copy_from_slice(nonce);
    h[42..46].copy_from_slice(&ct_len.to_be_bytes());
    h
}

impl Store {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Checks the path, creates the store's directory (mode 0700) and takes
    /// the lock, before anything is asked or read.
    pub fn lock_for_init(path: &Path) -> Result<StoreLock, StoreError> {
        let path = check_path(path)?;
        if let Some(dir) = path.parent() {
            create_private_dir(dir)
                .map_err(|e| StoreError::Io(format!("cannot create {}: {e}", dir.display())))?;
        }
        let lock = StoreLock::acquire(&path)?;
        if path.exists() {
            return Err(StoreError::Exists(path.display().to_string()));
        }
        Ok(lock)
    }

    /// Checks the path, refuses a missing store and takes the lock.
    pub fn lock_for_open(path: &Path) -> Result<StoreLock, StoreError> {
        let path = check_path(path)?;
        if !path.exists() {
            return Err(StoreError::Missing(path.display().to_string()));
        }
        StoreLock::acquire(&path)
    }

    /// Creates a new, empty store. Refuses an existing file.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn init(
        path: &Path,
        passphrase: &str,
        kdf: StoreKdf,
        rng: &mut dyn Rand,
    ) -> Result<Store, StoreError> {
        let lock = Store::lock_for_init(path)?;
        Store::init_locked(lock, passphrase, kdf, rng)
    }

    /// `init` under a lock from `lock_for_init`.
    pub fn init_locked(
        lock: StoreLock,
        passphrase: &str,
        kdf: StoreKdf,
        rng: &mut dyn Rand,
    ) -> Result<Store, StoreError> {
        let path = lock.store_path().to_path_buf();
        if path.exists() {
            return Err(StoreError::Exists(path.display().to_string()));
        }
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(StoreError::Io(format!(
                "the store passphrase needs at least {MIN_PASSPHRASE_CHARS} characters"
            )));
        }
        let salt: [u8; 16] = bytes(rng).map_err(StoreError::Io)?;
        let key = argon2id(passphrase.as_bytes(), &salt, kdf.m_kib, kdf.t, kdf.p)
            .map_err(StoreError::Io)?;
        let s = Store {
            path,
            key,
            salt,
            kdf,
            data: StoreData {
                store_version: CONTENT_VERSION,
                ..Default::default()
            },
            _lock: lock,
        };
        s.save(rng)?;
        Ok(s)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open(path: &Path, passphrase: &str) -> Result<Store, StoreError> {
        let lock = Store::lock_for_open(path)?;
        Store::open_locked(lock, passphrase)
    }

    /// `open` under a lock from `lock_for_open`.
    pub fn open_locked(lock: StoreLock, passphrase: &str) -> Result<Store, StoreError> {
        let path = lock.store_path().to_path_buf();
        let raw = match std::fs::read(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::Missing(path.display().to_string()))
            }
            Err(e) => {
                return Err(StoreError::Io(format!(
                    "cannot read {}: {e}",
                    path.display()
                )))
            }
        };
        if raw.len() < HEADER_LEN + 16 || &raw[0..4] != MAGIC {
            return Err(StoreError::Damaged("not an SXDB file".into()));
        }
        if raw[4] != VERSION {
            return Err(StoreError::Damaged(format!(
                "unsupported store version {}",
                raw[4]
            )));
        }
        let u32_at = |i: usize| u32::from_be_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        let kdf = StoreKdf {
            m_kib: u32_at(5),
            t: u32_at(9),
            p: raw[13],
        };
        if !kdf_acceptable(&kdf) {
            return Err(StoreError::Damaged(
                "key derivation parameters out of bounds".into(),
            ));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&raw[14..30]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&raw[30..42]);
        if u32_at(42) as usize != raw.len() - HEADER_LEN {
            return Err(StoreError::Damaged(
                "length does not match the header".into(),
            ));
        }
        let key = argon2id(passphrase.as_bytes(), &salt, kdf.m_kib, kdf.t, kdf.p)
            .map_err(StoreError::Io)?;
        let plain = open(&key, &nonce, &raw[..HEADER_LEN], &raw[HEADER_LEN..])
            .ok_or(StoreError::WrongPassphrase)?;
        let data: StoreData = serde_json::from_slice(&plain)
            .map_err(|e| StoreError::Damaged(format!("content: {e}")))?;
        let mut data = data;
        match data.store_version {
            CONTENT_VERSION => {}
            // Versions 1 and 2 have no deliveries or flashes; serde filled in
            // the empty lists.
            1 | 2 => data.store_version = CONTENT_VERSION,
            v => {
                return Err(StoreError::Damaged(format!(
                    "unsupported content version {v} (this sxprov reads 1 to {CONTENT_VERSION})"
                )))
            }
        }
        Ok(Store {
            path,
            key,
            salt,
            kdf,
            data,
            _lock: lock,
        })
    }

    /// Encrypts with a fresh nonce and writes atomically: temporary file,
    /// fsync, previous version copied to `.bak`, rename, directory fsync.
    pub fn save(&self, rng: &mut dyn Rand) -> Result<(), StoreError> {
        let plain = Zeroizing::new(
            serde_json::to_vec(&self.data).map_err(|e| StoreError::Io(e.to_string()))?,
        );
        let nonce: [u8; 12] = bytes(rng).map_err(StoreError::Io)?;
        let h = header(&self.kdf, &self.salt, &nonce, (plain.len() + 16) as u32);
        let ct = seal(&self.key, &nonce, &h, &plain).map_err(StoreError::Io)?;
        let mut out = h.to_vec();
        out.extend_from_slice(&ct);
        write_atomic(&self.path, &out)
            .map_err(|e| StoreError::Io(format!("cannot write {}: {e}", self.path.display())))
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

pub fn backup_path(path: &Path) -> PathBuf {
    sibling(path, ".bak")
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Writes a new file with mode 0600, refusing to follow an existing one.
pub fn write_new_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = sibling(path, ".tmp");
    let _ = std::fs::remove_file(&tmp);
    write_new_private(&tmp, data)?;
    if path.exists() {
        let bak_tmp = sibling(path, ".bak.tmp");
        let _ = std::fs::remove_file(&bak_tmp);
        write_new_private(&bak_tmp, &std::fs::read(path)?)?;
        std::fs::rename(&bak_tmp, backup_path(path))?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activation::rng::SeededRand;

    /// Tests that drop a store and open it again, and tests that start many
    /// processes (the delivery tests), run one at a time: a fork in a
    /// parallel test briefly shares every open file description, the lock
    /// file's included, until its exec closes it, so a store just dropped
    /// could still look locked. `sxprov` itself runs one command at a time.
    pub fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        M.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sxprov-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const PASS: &str = "TEST-ONLY store passphrase";

    fn customer(key: &str) -> Customer {
        Customer {
            update_key: key.into(),
            previous_update_keys: Vec::new(),
            last_sequence: 0,
            created_at: "2026-11-19T18:00:00Z".into(),
        }
    }

    #[test]
    fn init_open_save_backup_and_wrong_passphrase() {
        let _g = one_at_a_time();
        let d = temp_dir("store");
        let p = d.join("sub/admin-store.sxdb");
        let mut r = SeededRand::new(b"store");
        let mut s = Store::init(&p, PASS, TEST_KDF, &mut r).unwrap();
        assert!(!backup_path(&p).exists());
        s.data
            .customers
            .insert("TEST-1".into(), customer(&"ab".repeat(32)));
        s.save(&mut r).unwrap();
        let saved = s.data.clone();
        drop(s);
        assert!(matches!(
            Store::init(&p, PASS, TEST_KDF, &mut r),
            Err(StoreError::Exists(_))
        ));
        let first = std::fs::read(&p).unwrap();
        // The update key is not readable in the file.
        assert!(!first.windows(64).any(|w| w == "ab".repeat(32).as_bytes()));
        // A wrong passphrase is refused and changes nothing.
        assert_eq!(
            Store::open(&p, "TEST-ONLY wrong passphrase").err(),
            Some(StoreError::WrongPassphrase)
        );
        assert_eq!(std::fs::read(&p).unwrap(), first);
        let mut s = Store::open(&p, PASS).unwrap();
        assert_eq!(s.data, saved);
        // The previous version is kept as .bak and still opens.
        s.data.customers.get_mut("TEST-1").unwrap().last_sequence = 4;
        s.save(&mut r).unwrap();
        assert_eq!(std::fs::read(backup_path(&p)).unwrap(), first);
        assert_eq!(
            Store::open(&backup_path(&p), PASS).unwrap().data.customers["TEST-1"].last_sequence,
            0
        );
        // A stale temporary file from an interrupted write does not matter.
        std::fs::write(sibling(&p, ".tmp"), b"partial").unwrap();
        s.save(&mut r).unwrap();
        assert!(!sibling(&p, ".tmp").exists());
        drop(s);
        assert_eq!(
            Store::open(&p, PASS).unwrap().data.customers["TEST-1"].last_sequence,
            4
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [p.clone(), backup_path(&p)] {
                assert_eq!(
                    std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        // A changed byte is refused.
        let mut bad = std::fs::read(&p).unwrap();
        let n = bad.len();
        bad[n - 1] ^= 1;
        let q = d.join("bad.sxdb");
        std::fs::write(&q, &bad).unwrap();
        assert_eq!(
            Store::open(&q, PASS).err(),
            Some(StoreError::WrongPassphrase)
        );
        assert!(matches!(
            Store::open(&d.join("none.sxdb"), PASS),
            Err(StoreError::Missing(_))
        ));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn lock_two_file_descriptors() {
        let _g = one_at_a_time();
        let d = temp_dir("store-lock");
        let p = d.join("admin-store.sxdb");
        let mut r = SeededRand::new(b"lock");
        let mut s = Store::init(&p, PASS, TEST_KDF, &mut r).unwrap();
        let lp = lock_path(&p);
        assert_eq!(lp, d.join("admin-store.sxdb.lock"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&lp).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let before = std::fs::read(&p).unwrap();
        // While the store is held, a second descriptor fails at once, for
        // open, init and a bare lock, and the store is not touched.
        assert_eq!(Store::open(&p, PASS).err(), Some(StoreError::Locked));
        assert_eq!(Store::lock_for_init(&p).err(), Some(StoreError::Locked));
        assert_eq!(StoreLock::acquire(&p).err(), Some(StoreError::Locked));
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert!(StoreError::Locked
            .to_string()
            .contains("the admin store is in use by another sxprov process"));
        // The holder still writes; the lock file never holds data.
        s.data
            .customers
            .insert("TEST-1".into(), customer(&"cd".repeat(32)));
        s.save(&mut r).unwrap();
        assert_eq!(std::fs::read(&lp).unwrap(), b"");
        drop(s);
        // A lock file left behind without a holder is reused.
        assert!(lp.exists());
        let o = Store::open(&p, PASS).unwrap();
        assert!(o.data.customers.contains_key("TEST-1"));
        drop(o);
        // A lock file that is not a regular file is refused.
        std::fs::remove_file(&lp).unwrap();
        std::fs::create_dir(&lp).unwrap();
        assert!(matches!(Store::open(&p, PASS), Err(StoreError::Io(_))));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Helper process for `lock_second_process`: holds the lock named in
    /// SXPROV_TEST_LOCK_HOLD until its standard input closes.
    #[test]
    #[ignore = "helper, started by lock_second_process"]
    fn lock_holder_helper() {
        let Some(p) = std::env::var_os("SXPROV_TEST_LOCK_HOLD") else {
            return;
        };
        let _lock = StoreLock::acquire(Path::new(&p)).unwrap();
        println!("SXPROV-LOCKED");
        let mut sink = String::new();
        let _ = std::io::stdin().read_line(&mut sink);
    }

    #[test]
    fn lock_second_process() {
        let _g = one_at_a_time();
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let d = temp_dir("store-lock-proc");
        let p = d.join("admin-store.sxdb");
        let mut r = SeededRand::new(b"lock-proc");
        drop(Store::init(&p, PASS, TEST_KDF, &mut r).unwrap());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "activation::store::tests::lock_holder_helper",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SXPROV_TEST_LOCK_HOLD", &p)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("SXPROV-LOCKED") {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "helper ended early");
        }
        let before = std::fs::read(&p).unwrap();
        assert_eq!(Store::open(&p, PASS).err(), Some(StoreError::Locked));
        assert_eq!(std::fs::read(&p).unwrap(), before);
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(Store::open(&p, PASS).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn short_passphrase_and_weak_parameters_refused() {
        let _g = one_at_a_time();
        let d = temp_dir("store-weak");
        let mut r = SeededRand::new(b"weak");
        assert!(Store::init(&d.join("a.sxdb"), "short", TEST_KDF, &mut r).is_err());
        assert!(!kdf_acceptable(&StoreKdf {
            m_kib: 512,
            t: 1,
            p: 1
        }));
        assert!(kdf_acceptable(&STORE_KDF));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn path_inside_a_repository_refused() {
        let _g = one_at_a_time();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        for p in [
            repo.join("admin-store.sxdb"),
            repo.join("tests/fixtures/x/admin.sxdb"),
        ] {
            assert!(
                matches!(check_path(&p), Err(StoreError::InRepository(_))),
                "{}",
                p.display()
            );
        }
        let d = temp_dir("store-repo");
        std::fs::create_dir_all(d.join("other/.git")).unwrap();
        assert!(matches!(
            check_path(&d.join("other/deep/s.sxdb")),
            Err(StoreError::InRepository(_))
        ));
        assert!(check_path(&d.join("plain/s.sxdb")).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// One run with the real parameters (64 MiB, 3 passes).
    #[test]
    fn real_parameters_round_trip() {
        let _g = one_at_a_time();
        let d = temp_dir("store-real");
        let p = d.join("s.sxdb");
        let mut r = SeededRand::new(b"real");
        Store::init(&p, PASS, STORE_KDF, &mut r).unwrap();
        assert!(Store::open(&p, PASS).unwrap().data.customers.is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Writes `plain` as the store content, encrypted like `save` does.
    fn write_content(s: &Store, plain: &[u8], r: &mut dyn Rand) {
        let nonce: [u8; 12] = bytes(r).unwrap();
        let h = header(&s.kdf, &s.salt, &nonce, (plain.len() + 16) as u32);
        let mut out = h.to_vec();
        out.extend(seal(&s.key, &nonce, &h, plain).unwrap());
        std::fs::write(&s.path, out).unwrap();
    }

    #[test]
    fn old_stores_are_migrated_and_unknown_versions_refused() {
        let _g = one_at_a_time();
        let d = temp_dir("migrate");
        let p = d.join("admin-store.sxdb");
        let mut r = SeededRand::new(b"migrate");
        let s = Store::init(&p, PASS, TEST_KDF, &mut r).unwrap();
        // A content version 1 store: no deliveries.
        let v1 = format!(
            r#"{{"store_version":1,"customers":{{"TEST-1":{{"update_key":"{}","previous_update_keys":[],"last_sequence":3,"created_at":"2026-11-19T18:00:00Z"}}}},"issues":[]}}"#,
            "ab".repeat(32)
        );
        write_content(&s, v1.as_bytes(), &mut r);
        drop(s);
        let o = Store::open(&p, PASS).unwrap();
        assert_eq!(o.data.store_version, CONTENT_VERSION);
        assert!(o.data.deliveries.is_empty());
        assert_eq!(o.data.customers["TEST-1"].last_sequence, 3);
        o.save(&mut r).unwrap();
        drop(o);
        let o = Store::open(&p, PASS).unwrap();
        assert_eq!(o.data.store_version, 3);
        assert_eq!(o.data.customers["TEST-1"].last_sequence, 3);
        // A version 2 store keeps its deliveries, gains flashes.
        let v2 = r#"{"store_version":2,"customers":{},"issues":[],"deliveries":[]}"#;
        write_content(&o, v2.as_bytes(), &mut r);
        drop(o);
        let o = Store::open(&p, PASS).unwrap();
        assert_eq!(o.data.store_version, 3);
        assert!(o.data.flashes.is_empty());
        // A newer content version is refused, never rewritten.
        let v4 = r#"{"store_version":4,"customers":{},"issues":[],"deliveries":[],"flashes":[]}"#;
        write_content(&o, v4.as_bytes(), &mut r);
        drop(o);
        assert!(
            matches!(Store::open(&p, PASS), Err(StoreError::Damaged(e)) if e.contains("unsupported content version 4"))
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn lock_and_app_link_records_are_optional_and_round_trip() {
        let old = serde_json::json!({
            "delivery_id": "00", "serial": "S", "serial_masked": "*S",
            "device_class": "phone", "tier": "hardened", "test": true, "model": null, "os_build": null,
            "security_patch": null, "attestation": "x", "messenger_package": "org.example.messenger",
            "messenger_version_code": null, "messenger_version_name": null, "messenger_apk_sha256": null,
            "messenger_signer_sha256": null, "messenger_verified": false, "reinstall": false,
            "network_mode": "tor_required", "file_transferred": false, "customer_ref": "TEST-6A-0001",
            "started_at": "2026-11-23T10:00:00Z", "result": "delivered"
        });
        let mut d: Delivery = serde_json::from_value(old).unwrap();
        assert!(d.lock.is_none() && d.app_links.is_none());
        d.lock = Some(LockRecord {
            provider: "org.torproject.android".into(),
            apps_at_lock: vec!["app.seamlessupdate.client".into()],
            proven: true,
            mode_line: Some("lockdown=true alwaysOn=true".into()),
            proven_after_apps: true,
        });
        d.app_links = Some(AppLinksRecord {
            verifier: Some("com.android.statementservice".into()),
            disabled_by_delivery: true,
            hosts: vec![("chat.simplex.app".into(), vec!["simplex.chat".into()])],
            states: vec![(
                "chat.simplex.app".into(),
                "simplex.chat".into(),
                "none".into(),
            )],
            checked: true,
            ..Default::default()
        });
        let back: Delivery = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back, d);
    }
}
