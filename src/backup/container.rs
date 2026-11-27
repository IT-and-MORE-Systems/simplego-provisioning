// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The backup file (section 4): `SIMPLEGO-BACKUP/1` and a line feed; one
//! header line, compact JSON `{"format":1,"wrapped_seed":"<base64>"}` and a
//! line feed; the binary age file. Inside the age file a ustar archive whose
//! first member is `manifest.json` (compact JSON, sorted keys: `format`,
//! `product`, `app_version`, `created_utc`, `entries`), then the members.
//! Readers refuse a missing or different magic line, any other header, a
//! `format` other than 1, anything age refuses, and check every SHA-256 of
//! the manifest before a single file is restored.

use super::agefile;
use super::tar::{self, Member};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const MAGIC_LINE: &[u8] = b"SIMPLEGO-BACKUP/1\n";
pub const PRODUCTS: [&str; 4] = [
    "messenger-android",
    "messenger-desktop",
    "os-laptop",
    "admin-store",
];
/// The file name at a destination: `bk-<yyyymmdd>T<hhmmss>Z.bin` (UTC).
pub fn file_name(unix: u64) -> String {
    let t = crate::util::fmt_unix(unix); // YYYY-MM-DDTHH:MM:SSZ
    let d: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    format!("bk-{}T{}Z.bin", &d[..8], &d[8..14])
}

pub fn is_backup_name(n: &str) -> bool {
    let b = n.as_bytes();
    n.len() == 23
        && n.starts_with("bk-")
        && n.ends_with("Z.bin")
        && b[11] == b'T'
        && b[3..11].iter().chain(&b[12..18]).all(u8::is_ascii_digit)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderJson {
    format: serde_json::Value,
    wrapped_seed: String,
}

/// The parts of a backup file, checked without any secret.
pub struct Parsed<'a> {
    pub wrapped_seed: Vec<u8>,
    pub age: &'a [u8],
}

/// Magic line, header line, the age header (exactly one X25519 stanza
/// besides at most one grease stanza).
impl std::fmt::Debug for Parsed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Parsed(wrapped seed {} bytes, age {} bytes)",
            self.wrapped_seed.len(),
            self.age.len()
        )
    }
}

pub fn parse(file: &[u8]) -> Result<Parsed<'_>, String> {
    let rest = file
        .strip_prefix(MAGIC_LINE)
        .ok_or("not a SimpleGo backup (the magic line SIMPLEGO-BACKUP/1 is missing)")?;
    let nl = rest
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("the header line does not end")?;
    if nl > 64 * 1024 {
        return Err("the header line is too long".into());
    }
    let line = &rest[..nl];
    let h: HeaderJson = serde_json::from_slice(line)
        .map_err(|e| format!("the header is not the format's JSON: {e}"))?;
    match h.format.as_u64() {
        Some(1) if h.format.is_u64() => {}
        _ => return Err(format!("header format {} is not 1", h.format)),
    }
    // Compact JSON, nothing else: the line must be exactly this.
    let canonical = format!(r#"{{"format":1,"wrapped_seed":"{}"}}"#, h.wrapped_seed);
    if line != canonical.as_bytes() {
        return Err("the header line is not compact JSON in the format's form".into());
    }
    let wrapped_seed =
        Base64::decode_vec(&h.wrapped_seed).map_err(|_| "wrapped_seed is not base64")?;
    agefile::scrypt_work_factor(&wrapped_seed)
        .map_err(|e| format!("wrapped_seed is not an age scrypt file: {e}"))?;
    let age = &rest[nl + 1..];
    agefile::check_backup_header(age).map_err(|e| format!("the age file is refused: {e}"))?;
    Ok(Parsed { wrapped_seed, age })
}

pub fn assemble(wrapped_seed: &[u8], age: &[u8]) -> Vec<u8> {
    let mut out = MAGIC_LINE.to_vec();
    out.extend_from_slice(
        format!(
            r#"{{"format":1,"wrapped_seed":"{}"}}"#,
            Base64::encode_string(wrapped_seed)
        )
        .as_bytes(),
    );
    out.push(b'\n');
    out.extend_from_slice(age);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub product: String,
    pub app_version: String,
    pub created_utc: String,
    pub entries: BTreeMap<String, String>,
}

impl Manifest {
    /// Compact JSON with sorted keys (serde_json sorts object keys).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "format": 1,
            "product": self.product,
            "app_version": self.app_version,
            "created_utc": self.created_utc,
            "entries": self.entries,
        }))
        .expect("serialisable")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestJson {
    format: serde_json::Value,
    product: String,
    app_version: String,
    created_utc: String,
    entries: BTreeMap<String, String>,
}

fn valid_utc(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|i| b[*i].is_ascii_digit())
}

/// Builds the archive: `manifest.json` first, then the members.
pub fn archive(
    product: &str,
    app_version: &str,
    created_utc: &str,
    members: Vec<Member>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let entries = members
        .iter()
        .map(|m| {
            (
                m.path.clone(),
                crate::util::hex(&crate::util::sha256(&m.data)),
            )
        })
        .collect();
    let man = Manifest {
        product: product.into(),
        app_version: app_version.into(),
        created_utc: created_utc.into(),
        entries,
    };
    let mut all = vec![Member {
        path: "manifest.json".into(),
        data: man.to_json(),
    }];
    all.extend(members);
    tar::write(&all)
}

/// Reads the archive and checks the manifest and every SHA-256 before
/// anything is returned: first member `manifest.json`, format 1, a known
/// product, a UTC time, entries naming exactly the other members.
pub fn unpack(plain: &[u8]) -> Result<(Manifest, Vec<Member>), String> {
    let mut members = tar::read(plain)?;
    if members.first().map(|m| m.path.as_str()) != Some("manifest.json") {
        return Err("the first member is not manifest.json".into());
    }
    let man_m = members.remove(0);
    let mj: ManifestJson = serde_json::from_slice(&man_m.data)
        .map_err(|e| format!("manifest.json is refused: {e}"))?;
    if mj.format.as_u64() != Some(1) || !mj.format.is_u64() {
        return Err(format!("manifest format {} is not 1", mj.format));
    }
    if !PRODUCTS.contains(&mj.product.as_str()) {
        return Err(format!("unknown product {:?}", mj.product));
    }
    if !valid_utc(&mj.created_utc) {
        return Err(format!(
            "created_utc {:?} is not UTC with seconds",
            mj.created_utc
        ));
    }
    let names: Vec<&str> = members.iter().map(|m| m.path.as_str()).collect();
    if mj.entries.keys().map(String::as_str).ne(names
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>())
    {
        return Err("the manifest entries do not name exactly the members".into());
    }
    for m in &members {
        let want = &mj.entries[&m.path];
        if !crate::util::is_sha256_hex(want) || want.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "{}: the manifest SHA-256 is not lower-case hex",
                m.path
            ));
        }
        if *want != crate::util::hex(&crate::util::sha256(&m.data)) {
            return Err(format!("{}: SHA-256 differs from the manifest", m.path));
        }
    }
    Ok((
        Manifest {
            product: mj.product,
            app_version: mj.app_version,
            created_utc: mj.created_utc,
            entries: mj.entries,
        },
        members,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::code::tests::V1_SEED;
    use crate::backup::keys;

    fn m(p: &str, d: &[u8]) -> Member {
        Member {
            path: p.into(),
            data: d.to_vec(),
        }
    }

    #[test]
    fn names() {
        assert_eq!(file_name(0), "bk-19700101T000000Z.bin");
        assert_eq!(file_name(1_700_000_000), "bk-20231114T221320Z.bin");
        assert!(is_backup_name("bk-20261117T080640Z.bin"));
        for bad in [
            "bk-20261117T080640Z.bin.tmp",
            "x-20261117T080640Z.bin",
            "bk-2026111xT080640Z.bin",
        ] {
            assert!(!is_backup_name(bad), "{bad}");
        }
    }

    fn sample() -> (Vec<u8>, Vec<u8>) {
        let r = keys::parse_recipient(&keys::recipient(&V1_SEED)).unwrap();
        let wrapped = agefile::wrap_seed(&V1_SEED, "TEST-ONLY backup password", 18).unwrap();
        let a = archive(
            "admin-store",
            "0.1.0-alpha",
            "2026-11-27T12:00:00Z",
            vec![
                m("admin/store.sxdb", b"store"),
                m("admin/store-key", b"key\n"),
            ],
        )
        .unwrap();
        let (age, _) = agefile::encrypt_to(&r, &a).unwrap();
        (assemble(&wrapped, &age), a.to_vec())
    }

    #[test]
    fn container_round_trip_and_header_refusals() {
        let (file, plain) = sample();
        let p = parse(&file).unwrap();
        let back = agefile::decrypt_with_identity(p.age, &keys::identity(&V1_SEED)).unwrap();
        assert_eq!(*back, plain);
        let (man, members) = unpack(&back).unwrap();
        assert_eq!(man.product, "admin-store");
        assert_eq!(members.len(), 2);
        // The manifest is compact with sorted keys.
        let first = tar::read(&back).unwrap().remove(0);
        let t = String::from_utf8(first.data.clone()).unwrap();
        assert!(t.starts_with(r#"{"app_version":"0.1.0-alpha","created_utc":"2026-11-27T12:00:00Z","entries":{"admin/store-key":"#), "{t}");
        assert!(
            t.ends_with(r#","format":1,"product":"admin-store"}"#),
            "{t}"
        );
        let header_end = MAGIC_LINE.len()
            + file[MAGIC_LINE.len()..]
                .iter()
                .position(|b| *b == b'\n')
                .unwrap();
        let header = std::str::from_utf8(&file[MAGIC_LINE.len()..header_end])
            .unwrap()
            .to_string();
        let with = |h: &str| {
            let mut f = MAGIC_LINE.to_vec();
            f.extend_from_slice(h.as_bytes());
            f.extend_from_slice(&file[header_end..]);
            f
        };
        let ws = header
            .trim_start_matches(r#"{"format":1,"wrapped_seed":""#)
            .trim_end_matches(r#""}"#)
            .to_string();
        for (bad, want) in [
            (format!(r#"{{"format":2,"wrapped_seed":"{ws}"}}"#), "not 1"),
            (
                format!(r#"{{"format":"1","wrapped_seed":"{ws}"}}"#),
                "not 1",
            ),
            (
                format!(r#"{{"format":1.0,"wrapped_seed":"{ws}"}}"#),
                "not 1",
            ),
            (
                format!(r#"{{"format":1,"wrapped_seed":"{ws}","x":1}}"#),
                "format's JSON",
            ),
            (r#"{"format":1}"#.to_string(), "format's JSON"),
            (
                format!(r#"{{ "format":1,"wrapped_seed":"{ws}"}}"#),
                "compact",
            ),
            (
                format!(r#"{{"wrapped_seed":"{ws}","format":1}}"#),
                "compact",
            ),
            (r#"{"format":1,"wrapped_seed":"!!"}"#.to_string(), "base64"),
        ] {
            let e = parse(&with(&bad)).err().unwrap_or_default();
            assert!(e.contains(want), "{bad}: {e}");
        }
        assert!(parse(&with(&header)).is_ok());
        assert!(parse(&file[1..]).unwrap_err().contains("magic"));
        let mut other = file.clone();
        other[16] = b'2';
        assert!(parse(&other).unwrap_err().contains("magic"));
        // The age part: a passphrase file instead of a backup.
        let wrapped = agefile::wrap_seed(&V1_SEED, "x", 10).unwrap();
        assert!(parse(&assemble(&wrapped, &wrapped))
            .unwrap_err()
            .contains("age file is refused"));
    }

    #[test]
    fn manifest_refusals() {
        let a = |man: &str, members: Vec<Member>| {
            let mut all = vec![m("manifest.json", man.as_bytes())];
            all.extend(members);
            tar::write(&all).unwrap()
        };
        let sha = crate::util::hex(&crate::util::sha256(b"store"));
        let good = format!(
            r#"{{"app_version":"1","created_utc":"2026-11-27T12:00:00Z","entries":{{"admin/store.sxdb":"{sha}"}},"format":1,"product":"admin-store"}}"#
        );
        assert!(unpack(&a(&good, vec![m("admin/store.sxdb", b"store")])).is_ok());
        for (man, members, want) in [
            (
                good.clone(),
                vec![m("admin/store.sxdb", b"other")],
                "differs",
            ),
            (good.clone(), vec![], "exactly the members"),
            (
                good.clone(),
                vec![m("admin/store.sxdb", b"store"), m("admin/x", b"")],
                "exactly the members",
            ),
            (
                good.replace(&sha, &sha.to_uppercase()),
                vec![m("admin/store.sxdb", b"store")],
                "lower-case",
            ),
            (
                good.replace("admin-store\"", "other\""),
                vec![m("admin/store.sxdb", b"store")],
                "unknown product",
            ),
            (
                good.replace("\"format\":1", "\"format\":2"),
                vec![m("admin/store.sxdb", b"store")],
                "not 1",
            ),
            (
                good.replace("12:00:00Z", "12:00Z"),
                vec![m("admin/store.sxdb", b"store")],
                "UTC",
            ),
            (
                good.replace("\"format\":1", "\"format\":1,\"x\":0"),
                vec![m("admin/store.sxdb", b"store")],
                "refused",
            ),
        ] {
            let e = unpack(&a(&man, members)).err().unwrap_or_default();
            assert!(e.contains(want), "{want}: {e}");
        }
        // manifest.json not first.
        let t = tar::write(&[
            m("admin/store.sxdb", b"store"),
            m("manifest.json", good.as_bytes()),
        ])
        .unwrap();
        assert!(unpack(&t).unwrap_err().contains("first member"));
    }
}
