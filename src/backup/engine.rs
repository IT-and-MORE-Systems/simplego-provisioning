// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Running backups: write to every destination, read back, check, rotate;
//! verify; restore; the monthly drill; the warnings.
//!
//! After every write, the file is read back from the destination and
//! checked without any secret: the bytes equal what was written, magic line
//! and header, one X25519 stanza, and then the full content through the
//! file key kept in memory during encryption (age header MAC, every
//! payload chunk, the tar rules, every manifest SHA-256, the store opening
//! with the key it carries and equal to the live store). Only then the
//! file counts as verified and the rotation may delete older files of our
//! own list. A failed check never deletes anything.

use super::admin;
use super::agefile::{self, FileKeyCopy};
use super::code::{self, Seed};
use super::container;
use super::dest::{self, Reach};
use super::keys;
use super::state::{self, Destination, State, Target, Written};
use crate::activation::rng::Rand;
use crate::activation::store::{self, Store, StoreData};
use crate::activation::storekey::{self, Backend, Creds};
use crate::util::{fmt_unix, hex, sha256};
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The warnings' limits.
pub const STALE_BACKUP_SECS: u64 = 48 * 3600;
pub const STALE_DRILL_SECS: u64 = 35 * 86_400;
/// The automatic run's limit (hourly timer, end of any command).
pub const DAILY_SECS: u64 = 24 * 3600;

/// Where the engine reports: text lines and `--json` events.
pub trait Events {
    fn event(&mut self, v: Value);
    fn line(&mut self, s: &str);
}

/// Collects events (tests).
#[cfg(test)]
#[derive(Default)]
pub struct Collect {
    pub events: Vec<Value>,
    pub lines: Vec<String>,
}

#[cfg(test)]
impl Events for Collect {
    fn event(&mut self, v: Value) {
        self.events.push(v);
    }
    fn line(&mut self, s: &str) {
        self.lines.push(s.to_string());
    }
}

/// What one destination did in a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Written { file: String, deleted: Vec<String> },
    NotConnected(String),
    Failed(String),
}

pub struct RunReport {
    pub file: String,
    pub results: Vec<(String, Outcome)>,
}

impl RunReport {
    #[cfg(test)]
    pub fn all_ok(&self) -> bool {
        self.results
            .iter()
            .all(|(_, o)| !matches!(o, Outcome::Failed(_)))
    }
    pub fn written(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Written { .. }))
            .count()
    }
}

/// The backup file for the live store, and the file key copy for the check.
pub struct Built {
    pub file: Vec<u8>,
    pub fk: FileKeyCopy,
    pub store_sha256: String,
}

pub fn build(
    st: &Store,
    state: &State,
    config_text: Option<&str>,
    now: u64,
) -> Result<Built, String> {
    let store_file = std::fs::read(st.path())
        .map_err(|e| format!("cannot read {}: {e}", st.path().display()))?;
    // The file on disk must be what the store holds (written by `save`).
    let on_disk = store::decrypt(&store_file, st.key(), "store")
        .map_err(|e| format!("the store file does not open: {e}"))?;
    if on_disk != st.data {
        return Err("the store file differs from the open store; save first".into());
    }
    let members = admin::members(&store_file, st.key(), config_text);
    let archive = container::archive(
        admin::PRODUCT,
        &crate::names::version_tag(),
        &fmt_unix(now),
        members,
    )?;
    let r = keys::parse_recipient(&state.recipient)?;
    let (age, fk) = agefile::encrypt_to(&r, &archive)?;
    let wrapped = Base64::decode_vec(&state.wrapped_seed)
        .map_err(|_| "the wrapped seed in the backup state is not base64")?;
    Ok(Built {
        file: container::assemble(&wrapped, &age),
        fk,
        store_sha256: hex(&sha256(&store_file)),
    })
}

/// The check of a file read back, with the file key, against the live data.
pub fn check_with_file_key(
    file: &[u8],
    fk: &FileKeyCopy,
    state: &State,
    live: &StoreData,
    live_key: &[u8; 32],
) -> Result<(), String> {
    let p = container::parse(file)?;
    if Base64::encode_string(&p.wrapped_seed) != state.wrapped_seed {
        return Err("the wrapped seed differs from the backup state".into());
    }
    let plain = agefile::decrypt_with_file_key(p.age, fk)?;
    let (man, members) = container::unpack(&plain)?;
    if man.product != admin::PRODUCT {
        return Err(format!(
            "product {} instead of {}",
            man.product,
            admin::PRODUCT
        ));
    }
    let r = admin::read(members)?;
    if *r.key != *live_key {
        return Err("the store key inside differs from the live key".into());
    }
    if r.data != *live {
        return Err("the store inside differs from the live store".into());
    }
    Ok(())
}

/// Checks without any secret what `verify` can: the bytes match our list,
/// magic line, header, the age stanzas.
pub fn check_structure(file: &[u8], w: &Written) -> Result<(), String> {
    if file.len() as u64 != w.size {
        return Err(format!("{} bytes, our list says {}", file.len(), w.size));
    }
    if hex(&sha256(file)) != w.sha256 {
        return Err("the SHA-256 differs from our list".into());
    }
    container::parse(file).map(|_| ())
}

/// The run's file name: the time, one second later while any destination
/// already lists that name (two runs in one second).
fn unique_name(state: &State, mut t: u64) -> (String, u64) {
    loop {
        let n = container::file_name(t);
        if !state.written.iter().any(|w| w.file == n) {
            return (n, t);
        }
        t += 1;
    }
}

/// One run to every destination.
#[allow(clippy::too_many_arguments)]
pub fn run(
    st: &Store,
    state: &mut State,
    config_text: Option<&str>,
    tor_proxy: &str,
    now: u64,
    why: &str,
    ev: &mut dyn Events,
) -> Result<RunReport, String> {
    let (name, t) = unique_name(state, now);
    let built = build(st, state, config_text, t)?;
    ev.event(json!({"event": "backup_started", "why": why, "file": name,
                    "size": built.file.len(), "destinations": state.destinations.len()}));
    let mut results = Vec::new();
    for d in state.destinations.clone() {
        let outcome = run_one(&d, &built, &name, t, st, state, tor_proxy, now);
        match &outcome {
            Outcome::Written { file, deleted } => {
                state.clear_failure(&d.name);
                ev.event(
                    json!({"event": "backup_written", "destination": d.name, "file": file,
                                "size": built.file.len(), "sha256": hex(&sha256(&built.file)),
                                "verified": true}),
                );
                ev.line(&format!("backup {file} written to {} and checked", d.name));
                for f in deleted {
                    ev.event(
                        json!({"event": "backup_rotated", "destination": d.name, "deleted": f}),
                    );
                }
                if !deleted.is_empty() {
                    ev.line(&format!(
                        "  {}: {} older backup(s) deleted (rotation)",
                        d.name,
                        deleted.len()
                    ));
                }
            }
            Outcome::NotConnected(why) => {
                ev.event(json!({"event": "backup_skipped", "destination": d.name, "reason": why}));
                ev.line(&format!(
                    "backup to {} skipped: not connected ({why})",
                    d.name
                ));
            }
            Outcome::Failed(why) => {
                state.note_failure(&d.name, now, why);
                ev.event(json!({"event": "backup_failed", "destination": d.name, "reason": why}));
                ev.line(&format!("BACKUP FAILED at {}: {why}", d.name));
            }
        }
        state.save(st.path())?;
        results.push((d.name.clone(), outcome));
    }
    Ok(RunReport {
        file: name,
        results,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    d: &Destination,
    built: &Built,
    name: &str,
    t: u64,
    st: &Store,
    state: &mut State,
    tor_proxy: &str,
    now: u64,
) -> Outcome {
    let remote = match dest::open(d, tor_proxy) {
        Ok(Reach::Ready(r)) => r,
        Ok(Reach::NotConnected(why)) => return Outcome::NotConnected(why),
        Err(e) => return Outcome::Failed(e),
    };
    if let Err(e) = remote.put(name, &built.file) {
        return Outcome::Failed(e);
    }
    let w = Written {
        destination: d.name.clone(),
        file: name.to_string(),
        size: built.file.len() as u64,
        sha256: hex(&sha256(&built.file)),
        store_sha256: built.store_sha256.clone(),
        created_unix: t,
        verified: false,
    };
    // In our list from the moment it exists there, verified or not.
    state.written.push(w.clone());
    let back = match remote.get(name) {
        Ok(b) => b,
        Err(e) => return Outcome::Failed(format!("read back: {e}")),
    };
    if let Err(e) = check_structure(&back, &w)
        .and_then(|_| check_with_file_key(&back, &built.fk, state, &st.data, st.key()))
    {
        return Outcome::Failed(format!("the file read back is refused: {e}"));
    }
    if let Some(x) = state
        .written
        .iter_mut()
        .find(|x| x.destination == d.name && x.file == name)
    {
        x.verified = true;
    }
    // Rotation: only files of our own list, only after this check.
    let list: Vec<Written> = state.written_at(&d.name).into_iter().cloned().collect();
    let refs: Vec<&Written> = list.iter().collect();
    let mut deleted = Vec::new();
    for old in state::to_delete(&refs, now) {
        if old.file == name {
            continue;
        }
        match remote.delete(&old.file) {
            Ok(_) => {
                state
                    .written
                    .retain(|x| !(x.destination == d.name && x.file == old.file));
                deleted.push(old.file.clone());
            }
            Err(e) => {
                return Outcome::Failed(format!("written and checked, but rotation stopped: {e}"))
            }
        }
    }
    Outcome::Written {
        file: name.to_string(),
        deleted,
    }
}

/// `backup verify`: every file of our list, read back and checked without
/// a secret (size, SHA-256, magic line, header, stanzas).
pub fn verify_all(
    state: &State,
    tor_proxy: &str,
    ev: &mut dyn Events,
) -> Result<(usize, usize), String> {
    let (mut ok, mut bad) = (0, 0);
    for d in &state.destinations {
        let remote = match dest::open(d, tor_proxy) {
            Ok(Reach::Ready(r)) => r,
            Ok(Reach::NotConnected(why)) => {
                ev.event(json!({"event": "verify_skipped", "destination": d.name, "reason": why}));
                ev.line(&format!("{}: not connected ({why})", d.name));
                continue;
            }
            Err(e) => {
                bad += 1;
                ev.event(json!({"event": "verify_failed", "destination": d.name, "reason": e}));
                ev.line(&format!("{}: FAILED: {e}", d.name));
                continue;
            }
        };
        for w in state.written_at(&d.name) {
            let r = remote.get(&w.file).and_then(|b| check_structure(&b, w));
            match r {
                Ok(()) => {
                    ok += 1;
                    ev.event(json!({"event": "verify_ok", "destination": d.name, "file": w.file}));
                    ev.line(&format!("{}: {} ok", d.name, w.file));
                }
                Err(e) => {
                    bad += 1;
                    ev.event(json!({"event": "verify_failed", "destination": d.name,
                                    "file": w.file, "reason": e}));
                    ev.line(&format!("{}: {} FAILED: {e}", d.name, w.file));
                }
            }
        }
    }
    Ok((ok, bad))
}

/// A seed from what the operator typed: the recovery code if the text is
/// one (32 characters of the alphabet with a valid checksum), else the
/// backup password against `wrapped_seed`.
pub fn seed_from_secret(typed: &str, wrapped_seed: &[u8]) -> Result<(Seed, &'static str), String> {
    if let Ok(s) = code::parse(typed) {
        return Ok((s, "recovery code"));
    }
    let n = code::normalise(typed);
    if n.len() == 32 && n.bytes().all(|b| code::ALPHABET.contains(&b)) {
        // Looks like a code with a typo; it may still be a password.
        if let Ok(s) = agefile::unwrap_seed(wrapped_seed, typed) {
            return Ok((s, "backup password"));
        }
        return Err(code::CodeError::Checksum.to_string());
    }
    agefile::unwrap_seed(wrapped_seed, typed)
        .map(|s| (s, "backup password"))
        .map_err(|e| e.to_string())
}

/// Everything a backup file holds, opened with the seed.
pub struct Opened {
    pub restored: admin::Restored,
    pub manifest: container::Manifest,
    pub wrapped_seed: Vec<u8>,
    pub recipient: String,
}

pub fn open_with_seed(file: &[u8], seed: &[u8; code::SEED_LEN]) -> Result<Opened, String> {
    let p = container::parse(file)?;
    let id = keys::identity(seed);
    let plain = agefile::decrypt_with_identity(p.age, &id)
        .map_err(|e| format!("{e} (this backup was made with another recovery code?)"))?;
    let (manifest, members) = container::unpack(&plain)?;
    if manifest.product != admin::PRODUCT {
        return Err(format!(
            "this is a backup of {}, not of the admin store",
            manifest.product
        ));
    }
    Ok(Opened {
        restored: admin::read(members)?,
        manifest,
        wrapped_seed: p.wrapped_seed,
        recipient: keys::recipient(seed),
    })
}

/// A private temporary folder (mode 0700), removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(near: &Path, tag: &str, rng: &mut dyn Rand) -> Result<TempDir, String> {
        let b: [u8; 8] = crate::activation::rng::bytes(rng)?;
        let p = near.with_file_name(format!(".sxprov-{tag}-{}", hex(&b)));
        let mut d = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            d.mode(0o700);
        }
        d.create(&p)
            .map_err(|e| format!("cannot create {}: {e}", p.display()))?;
        Ok(TempDir(p))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The monthly drill on one file: the seed opens it, every manifest hash
/// matches (checked by `unpack`), the members are written to a private
/// temporary folder, the store there opens with the restored key, and it
/// is compared with what our list recorded and with the live key.
pub fn drill_file(
    file: &[u8],
    seed: &[u8; code::SEED_LEN],
    w: Option<&Written>,
    state: &State,
    live_key: &[u8; 32],
    near: &Path,
    rng: &mut dyn Rand,
) -> Result<String, String> {
    let o = open_with_seed(file, seed)?;
    if o.recipient != state.recipient {
        return Err("the seed's recipient is not the one in the backup state".into());
    }
    let tmp = TempDir::new(near, "drill", rng)?;
    let sp = tmp.0.join("admin-store.sxdb");
    store::write_new_private(&sp, &o.restored.store_file).map_err(|e| e.to_string())?;
    storekey::write(&sp, Backend::File, &o.restored.key, &Creds::system())?;
    let (k2, _) = storekey::load(&sp, &Creds::system())?;
    let data = store::decrypt(
        &std::fs::read(&sp).map_err(|e| e.to_string())?,
        &k2,
        "drill",
    )
    .map_err(|e| e.to_string())?;
    if data != o.restored.data {
        return Err("the store restored to the temporary folder differs".into());
    }
    if let Some(w) = w {
        if hex(&sha256(&o.restored.store_file)) != w.store_sha256 {
            return Err("the restored store differs from what our list recorded".into());
        }
    }
    if *o.restored.key != *live_key {
        return Err("the restored store key differs from the live key".into());
    }
    drop(tmp);
    Ok(format!(
        "{} customers, {} issues, {} deliveries",
        data.customers.len(),
        data.issues.len(),
        data.deliveries.len()
    ))
}

/// The newest verified file per destination.
pub fn newest_per_destination(state: &State) -> Vec<(Destination, Written)> {
    state
        .destinations
        .iter()
        .filter_map(|d| {
            state
                .written_at(&d.name)
                .into_iter()
                .rev()
                .find(|w| w.verified)
                .map(|w| (d.clone(), w.clone()))
        })
        .collect()
}

/// The warnings every command prints.
pub fn warnings(state: Option<&State>, now: u64) -> Vec<(&'static str, String)> {
    let Some(s) = state else {
        return vec![(
            "no_backup",
            "backups are not set up: run `sxprov backup init`; losing the store means no update file for any customer".into(),
        )];
    };
    let mut w = Vec::new();
    match s.last_good() {
        None => w.push((
            "no_backup",
            "no good backup yet: run `sxprov backup now`".into(),
        )),
        Some(t) if now.saturating_sub(t) > STALE_BACKUP_SECS => w.push((
            "stale_backup",
            format!(
                "the last good backup is {} old (more than 48 hours): run `sxprov backup now`",
                crate::util::fmt_age(now - t)
            ),
        )),
        _ => {}
    }
    match s.last_drill_unix {
        None => w.push((
            "no_drill",
            "no restore drill yet: run `sxprov backup drill` (the backup password is typed once)"
                .into(),
        )),
        Some(t) if now.saturating_sub(t) > STALE_DRILL_SECS => w.push((
            "stale_drill",
            format!(
                "the last restore drill is {} old (more than 35 days): run `sxprov backup drill`",
                crate::util::fmt_age(now - t)
            ),
        )),
        _ => {}
    }
    if !s.destinations.iter().any(|d| !d.on_laptop) {
        w.push((
            "no_offsite",
            "every backup is on this laptop only: add a destination off the laptop (`sxprov backup destination add`)".into(),
        ));
    }
    w
}

/// A new backup state for a seed (init, new code, restore on a new laptop).
pub fn new_state(
    store: &Path,
    seed: &[u8; code::SEED_LEN],
    wrapped: &[u8],
    now: u64,
    rng: &mut dyn Rand,
) -> Result<State, String> {
    let id: [u8; 16] = crate::activation::rng::bytes(rng)?;
    let local = state::local_folder(store);
    dest::add_folder(&local, &hex(&id), true)?;
    Ok(State {
        format: state::FORMAT,
        recipient: keys::recipient(seed),
        wrapped_seed: Base64::encode_string(wrapped),
        created_unix: now,
        destinations: vec![Destination {
            name: state::LOCAL.into(),
            id: hex(&id),
            target: Target::Folder { path: local },
            on_laptop: true,
            added_unix: now,
        }],
        written: Vec::new(),
        last_drill_unix: None,
        last_failure: Vec::new(),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activation::rng::SeededRand;
    use crate::activation::store::tests::{init_test_store, one_at_a_time, temp_dir};
    use crate::backup::code::tests::V1_SEED;
    use crate::backup::dest::tests::serve;

    pub const PASS: &str = "TEST-ONLY backup password";

    /// A store with a customer and a backup state (work factor 18 for
    /// speed; the reader accepts 18 to 22).
    pub fn setup(tag: &str) -> (PathBuf, Store, State) {
        let d = temp_dir(tag);
        let p = d.join("admin.sxdb");
        let mut s = init_test_store(&p, tag.as_bytes());
        s.data.customers.insert(
            "TEST-1".into(),
            crate::activation::store::Customer {
                update_key: "ab".repeat(32),
                previous_update_keys: vec![],
                last_sequence: 1,
                created_at: "2026-11-27T12:00:00Z".into(),
                features: Default::default(),
                directory_set: None,
            },
        );
        s.save(&mut SeededRand::new(b"s")).unwrap();
        let wrapped = agefile::wrap_seed(&V1_SEED, PASS, 18).unwrap();
        let st = new_state(
            &p,
            &V1_SEED,
            &wrapped,
            1_800_000_000,
            &mut SeededRand::new(b"id"),
        )
        .unwrap();
        st.save(&p).unwrap();
        (d, s, st)
    }

    #[test]
    fn run_writes_checks_and_drills() {
        let _g = one_at_a_time();
        let (d, s, mut st) = setup("engine-run");
        let mut ev = Collect::default();
        let rep = run(
            &s,
            &mut st,
            Some("adb_path = \"/x\"\nmax_os_age_days = 30\n"),
            "x",
            1_800_000_000,
            "test",
            &mut ev,
        )
        .unwrap();
        assert!(rep.all_ok() && rep.written() == 1, "{:?}", rep.results);
        assert_eq!(st.written.len(), 1);
        assert!(st.written[0].verified);
        let f = std::fs::read(state::local_folder(s.path()).join(&rep.file)).unwrap();
        // The config inside has no machine paths.
        let o = open_with_seed(&f, &V1_SEED).unwrap();
        assert_eq!(o.restored.config.as_deref(), Some("max_os_age_days = 30\n"));
        assert_eq!(o.restored.data, s.data);
        // The drill with the password and with the recovery code.
        let (seed, how) = seed_from_secret(PASS, &o.wrapped_seed).unwrap();
        assert_eq!(how, "backup password");
        drill_file(
            &f,
            &seed,
            Some(&st.written[0]),
            &st,
            s.key(),
            s.path(),
            &mut SeededRand::new(b"t"),
        )
        .unwrap();
        let (seed, how) =
            seed_from_secret(crate::backup::code::tests::V1_CODE, &o.wrapped_seed).unwrap();
        assert_eq!(how, "recovery code");
        drill_file(
            &f,
            &seed,
            None,
            &st,
            s.key(),
            s.path(),
            &mut SeededRand::new(b"t"),
        )
        .unwrap();
        assert!(
            seed_from_secret("TEST-ONLY wrong password", &o.wrapped_seed)
                .unwrap_err()
                .contains("wrong backup password")
        );
        assert!(
            seed_from_secret("000G 40R4 0M30 E209 185G R38E 1W81 3K80", &o.wrapped_seed)
                .unwrap_err()
                .contains("typo")
        );
        // No temporary folder stays.
        assert!(!std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".sxprov-drill")));
        // verify reads every listed file.
        let mut ev = Collect::default();
        assert_eq!(verify_all(&st, "x", &mut ev).unwrap(), (1, 0));
        // A changed file at the destination: verify fails, nothing deleted.
        let fp = state::local_folder(s.path()).join(&rep.file);
        let mut b = std::fs::read(&fp).unwrap();
        let n = b.len() - 1;
        b[n] ^= 1;
        std::fs::write(&fp, b).unwrap();
        assert_eq!(verify_all(&st, "x", &mut ev).unwrap(), (0, 1));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A WebDAV destination (the loopback test server, reached directly
    /// in test builds only): written, read back, checked; a server that
    /// hands back changed bytes makes the run fail and nothing is verified
    /// or deleted.
    #[test]
    fn webdav_destination_through_the_engine() {
        let _g = one_at_a_time();
        let (d, s, mut st) = setup("engine-webdav");
        let srv = serve("op", "TEST-ONLY app password");
        let cred = d.join("webdav.cred");
        crate::activation::store::write_new_private(&cred, b"op\nTEST-ONLY app password\n")
            .unwrap();
        st.destinations.push(Destination {
            name: "cloud".into(),
            id: "c1".into(),
            target: Target::Webdav {
                url: srv.url.clone(),
                credentials: cred.clone(),
            },
            on_laptop: false,
            added_unix: 0,
        });
        let t0 = 1_800_000_000u64;
        let rep = run(
            &s,
            &mut st,
            None,
            "socks5h://127.0.0.1:1",
            t0,
            "test",
            &mut Collect::default(),
        )
        .unwrap();
        assert!(rep.all_ok() && rep.written() == 2, "{:?}", rep.results);
        assert_eq!(srv.files.lock().unwrap().len(), 1);
        assert!(st.last_good_off_laptop().is_some());
        // The server now changes bytes on the way back.
        *srv.corrupt_get.lock().unwrap() = true;
        let rep = run(
            &s,
            &mut st,
            None,
            "socks5h://127.0.0.1:1",
            t0 + 60,
            "test",
            &mut Collect::default(),
        )
        .unwrap();
        assert!(
            matches!(&rep.results[1].1, Outcome::Failed(e) if e.contains("refused")),
            "{:?}",
            rep.results
        );
        let cloud: Vec<_> = st.written_at("cloud");
        assert_eq!(cloud.len(), 2);
        assert!(cloud[0].verified && !cloud[1].verified);
        assert!(st.last_failure.iter().any(|(n, _, _)| n == "cloud"));
        // verify sees the changed bytes too.
        assert_eq!(
            verify_all(&st, "socks5h://127.0.0.1:1", &mut Collect::default())
                .unwrap()
                .1,
            2
        );
        *srv.corrupt_get.lock().unwrap() = false;
        // A folder with another destination's marker: a failure, never written.
        let usb = d.join("usb");
        std::fs::create_dir(&usb).unwrap();
        std::fs::write(
            usb.join(dest::MARKER),
            "simplego-backup-destination v1 other\n",
        )
        .unwrap();
        st.destinations.push(Destination {
            name: "usb".into(),
            id: "u1".into(),
            target: Target::Folder { path: usb.clone() },
            on_laptop: false,
            added_unix: 0,
        });
        let rep = run(
            &s,
            &mut st,
            None,
            "socks5h://127.0.0.1:1",
            t0 + 120,
            "test",
            &mut Collect::default(),
        )
        .unwrap();
        assert!(matches!(&rep.results[2].1, Outcome::Failed(_)));
        assert!(st.written.iter().all(|w| w.destination != "usb"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rotation_through_runs() {
        let _g = one_at_a_time();
        let (d, s, mut st) = setup("engine-rot");
        let t0 = 1_800_000_000u64;
        for i in 0..33 {
            run(
                &s,
                &mut st,
                None,
                "x",
                t0 + i * 60,
                "test",
                &mut Collect::default(),
            )
            .unwrap();
        }
        // 33 the same day: 30 kept, the 3 oldest deleted.
        let local = state::local_folder(s.path());
        let files: Vec<_> = std::fs::read_dir(&local)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| container::is_backup_name(n))
            .collect();
        assert_eq!(files.len(), 30);
        assert_eq!(st.written.len(), 30);
        // A file not in our list is never deleted.
        std::fs::write(local.join("bk-20000101T000000Z.bin"), b"not ours").unwrap();
        run(
            &s,
            &mut st,
            None,
            "x",
            t0 + 40 * 60,
            "test",
            &mut Collect::default(),
        )
        .unwrap();
        assert!(local.join("bk-20000101T000000Z.bin").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn warnings_name_every_gap() {
        let now = 1_800_000_000;
        assert_eq!(warnings(None, now)[0].0, "no_backup");
        let _g = one_at_a_time();
        let (d, _s, mut st) = setup("engine-warn");
        let kinds = |st: &State, now| {
            warnings(Some(st), now)
                .iter()
                .map(|w| w.0)
                .collect::<Vec<_>>()
        };
        assert_eq!(kinds(&st, now), ["no_backup", "no_drill", "no_offsite"]);
        st.written.push(Written {
            destination: "local".into(),
            file: container::file_name(now),
            size: 1,
            sha256: String::new(),
            store_sha256: String::new(),
            created_unix: now,
            verified: true,
        });
        st.last_drill_unix = Some(now);
        assert_eq!(kinds(&st, now + 3600), ["no_offsite"]);
        assert_eq!(kinds(&st, now + 49 * 3600), ["stale_backup", "no_offsite"]);
        assert_eq!(
            kinds(&st, now + 36 * 86_400),
            ["stale_backup", "stale_drill", "no_offsite"]
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}
