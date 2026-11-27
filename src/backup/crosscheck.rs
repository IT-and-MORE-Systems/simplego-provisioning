// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Cross-check with the official `age` tool (`tools/age_crosscheck.py`):
//! `cross_export` writes our files into `SXPROV_CROSS_DIR`, the script has
//! the tool open them and write its own, `cross_import` opens the tool's
//! files with our reader. Both are ignored in a normal test run.

use super::code::tests::V1_SEED;
use super::{agefile, container, engine, keys};
use crate::activation::store::tests::init_test_store;
use std::path::PathBuf;

pub const PASS: &str = "TEST-ONLY crosscheck password";

fn dir() -> Option<PathBuf> {
    std::env::var_os("SXPROV_CROSS_DIR").map(PathBuf::from)
}

/// Our side: a full admin-store backup for the V1 seed (work factor 20),
/// its age part, its plaintext tar, its wrapped seed, the V1 identity and
/// recipient.
#[test]
#[ignore = "cross-check with the official age tool, run by tools/age_crosscheck.py"]
fn cross_export() {
    let Some(d) = dir() else { return };
    let sp = d.join("store/admin.sxdb");
    let st = init_test_store(&sp, b"crosscheck");
    let wrapped = agefile::wrap_seed(&V1_SEED, PASS, agefile::WRAP_LOG_N).unwrap();
    let state = engine::new_state(
        &sp,
        &V1_SEED,
        &wrapped,
        1_800_000_000,
        &mut crate::activation::rng::SeededRand::new(b"x"),
    )
    .unwrap();
    let built = engine::build(&st, &state, Some("max_os_age_days = 30\n"), 1_800_000_000).unwrap();
    let p = container::parse(&built.file).unwrap();
    let plain = agefile::decrypt_with_identity(p.age, &keys::identity(&V1_SEED)).unwrap();
    std::fs::write(d.join("ours.bin"), &built.file).unwrap();
    std::fs::write(d.join("ours.age"), p.age).unwrap();
    std::fs::write(d.join("ours.tar"), &*plain).unwrap();
    std::fs::write(d.join("ours-wrapped.age"), &wrapped).unwrap();
    std::fs::write(d.join("seed.bin"), V1_SEED).unwrap();
    std::fs::write(
        d.join("id.txt"),
        format!("{}\n", keys::identity_string(&V1_SEED).as_str()),
    )
    .unwrap();
    std::fs::write(
        d.join("recipient.txt"),
        format!("{}\n", keys::recipient(&V1_SEED)),
    )
    .unwrap();
}

/// The tool's side, opened by us: `tool.age` (the tar encrypted by the
/// tool to the V1 recipient) and `tool-wrapped.age` (the seed encrypted by
/// the tool with a passphrase), also assembled into a container.
#[test]
#[ignore = "cross-check with the official age tool, run by tools/age_crosscheck.py"]
fn cross_import() {
    let Some(d) = dir() else { return };
    let tool_age = std::fs::read(d.join("tool.age")).unwrap();
    let tool_wrapped = std::fs::read(d.join("tool-wrapped.age")).unwrap();
    let ours_tar = std::fs::read(d.join("ours.tar")).unwrap();
    agefile::check_backup_header(&tool_age).unwrap();
    let plain = agefile::decrypt_with_identity(&tool_age, &keys::identity(&V1_SEED)).unwrap();
    assert_eq!(*plain, ours_tar);
    let log_n = agefile::scrypt_work_factor(&tool_wrapped).unwrap();
    assert_eq!(*agefile::unwrap_seed(&tool_wrapped, PASS).unwrap(), V1_SEED);
    let file = container::assemble(&tool_wrapped, &tool_age);
    let o = engine::open_with_seed(&file, &V1_SEED).unwrap();
    let (seed, how) = engine::seed_from_secret(PASS, &o.wrapped_seed).unwrap();
    assert_eq!((*seed, how), (V1_SEED, "backup password"));
    assert_eq!(o.recipient, keys::recipient(&V1_SEED));
    println!(
        "SXPROV-CROSS-IMPORT-OK tool.age {} bytes, tool-wrapped.age work factor {log_n}, {} customers",
        tool_age.len(),
        o.restored.data.customers.len()
    );
}
