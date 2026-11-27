// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The customer directory, the optional `directory` object of an
//! activation payload (format document section 12.2, amended in 12.4).
//!
//! Fail closed inside: an unknown field, a missing field or a wrong type
//! refuses the whole file while the payload is parsed (section 6 step 5).
//! The field rules (versions, `set_id`, names, the number of groups) are
//! step 5 too; the group links are checked with the other addresses, last
//! (`Payload::check_addresses`).
//!
//! Names (12.4): `display_name` and every group `name` must be valid
//! SimpleX names as the v7.1.4 core accepts them unchanged, otherwise the
//! setup on the device fails after the import. The core's rule is
//! `mkValidName` (simplex-chat `src/Simplex/Chat/Library/Commands.hs`
//! lines 7368 to 7396, `checkValidName` at 4247). The generator accepts a
//! strict subset: Latin letters (also the accented letters and umlauts),
//! digits, space and hyphen; [`mk_valid_name`] ports the core's rule for
//! these characters.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const DIRECTORY_VERSION: u32 = 1;
pub const MAX_NAME_CHARS: usize = 50;
pub const MAX_GROUPS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryGroup {
    pub name: String,
    pub link: String,
    pub direct_contacts: bool,
}

impl Drop for DirectoryGroup {
    fn drop(&mut self) {
        // A group link lets anyone join while the organizer is online.
        self.link.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub directory_version: u32,
    pub set_id: String,
    pub display_name: String,
    pub role: Role,
    /// Each group a JSON object (serde alone would read an array too).
    #[serde(deserialize_with = "super::strict::objects")]
    pub groups: Vec<DirectoryGroup>,
}

impl Drop for Directory {
    fn drop(&mut self) {
        // Personal data (section 12.2).
        self.display_name.zeroize();
    }
}

/// The characters the generator accepts in a name: `A-Z a-z 0-9`, space,
/// hyphen, and the Latin letters of Latin-1 Supplement, Latin Extended-A
/// and -B and Latin Extended Additional (U+00C0 to U+024F without the
/// signs U+00D7 and U+00F7, U+1E00 to U+1EFF; every one of them is a
/// letter in Unicode).
fn is_latin_letter(c: char) -> bool {
    c.is_ascii_alphabetic()
        || (('\u{c0}'..='\u{24f}').contains(&c) && c != '\u{d7}' && c != '\u{f7}')
        || ('\u{1e00}'..='\u{1eff}').contains(&c)
}

fn is_accepted(c: char) -> bool {
    is_latin_letter(c) || c.is_ascii_digit() || c == ' ' || c == '-'
}

/// The core's `mkValidName`, exact for the accepted characters (letters
/// and digits are `validFirstNameChar`, `-` is `DashPunctuation`; the
/// core's other categories do not occur here and count as invalid). The
/// `_<digits>` suffix rule of the core needs `_`, which is not accepted.
pub fn mk_valid_name(s: &str) -> String {
    let mut out: Vec<char> = Vec::new();
    let (mut prev, mut punct) = ('\0', 0u32);
    for c0 in s.chars() {
        let c = if c0.is_whitespace() { ' ' } else { c0 };
        let is_punct = c == '-';
        let first_name = is_latin_letter(c) || c.is_ascii_digit();
        let first = first_name;
        let prohibited = ".,;/\\#@'\"`~".contains(c);
        let valid = if prohibited {
            false
        } else if prev == '\0' {
            c > ' ' && first_name
        } else if prev == ' ' {
            first || (punct == 0 && is_punct)
        } else if punct > 0 {
            first || c == ' '
        } else {
            first || c == ' ' || is_punct
        };
        if valid {
            out.push(c);
            prev = c;
            punct = if is_punct {
                punct + 1
            } else if c == ' ' {
                punct
            } else {
                0
            };
        }
    }
    let mut r: String = out.into_iter().take(MAX_NAME_CHARS).collect();
    while r.ends_with(' ') {
        r.pop();
    }
    r
}

/// A name of 12.4. Errors never repeat the name (it is personal data);
/// a refused character is named by itself and its code point.
pub fn check_name(what: &str, s: &str) -> Result<(), String> {
    let n = s.chars().count();
    if n == 0 || n > MAX_NAME_CHARS {
        return Err(format!(
            "{what} must have 1 to {MAX_NAME_CHARS} characters, it has {n}"
        ));
    }
    if let Some(c) = s.chars().find(|c| !is_accepted(*c)) {
        let shown = if c.is_control() || c.is_whitespace() {
            String::new()
        } else {
            format!("\"{c}\" ")
        };
        return Err(format!(
            "{what}: the character {shown}(U+{:04X}) is not accepted; a name may hold Latin letters (also accented letters and umlauts, each as one character), digits, spaces and hyphens",
            c as u32
        ));
    }
    if mk_valid_name(s) != s {
        return Err(format!(
            "{what} is not a valid SimpleX name: it must start with a letter or digit, must not end with a space, and must not have two spaces or two hyphens in a row (also not with a space between the hyphens)"
        ));
    }
    Ok(())
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Directory {
    /// Section 6 step 5: every field rule except the group links.
    pub fn check_fields(&self) -> Result<(), String> {
        if self.directory_version != DIRECTORY_VERSION {
            return Err("directory: directory_version must be 1".into());
        }
        if !is_lower_hex(&self.set_id, 32) {
            return Err("directory: set_id must be 32 lowercase hex characters".into());
        }
        check_name("directory: display_name", &self.display_name)?;
        if self.groups.is_empty() || self.groups.len() > MAX_GROUPS {
            return Err(format!(
                "directory: groups must have 1 to {MAX_GROUPS} entries, it has {}",
                self.groups.len()
            ));
        }
        for (i, g) in self.groups.iter().enumerate() {
            check_name(&format!("directory.groups[{i}].name"), &g.name)?;
        }
        Ok(())
    }

    /// SHA-256 (hex) over the canonical JSON of the group list (keys
    /// sorted, no spaces): what the admin store keeps instead of the
    /// names and links, so every device of a set gets the same groups.
    pub fn groups_sha256(groups: &[DirectoryGroup]) -> String {
        let v = serde_json::to_value(groups).unwrap_or_default();
        crate::util::hex(&crate::util::sha256(
            &serde_json::to_vec(&v).unwrap_or_default(),
        ))
    }
}

/// A `--directory FILE`: the device's part of the object. `sxprov` adds
/// `directory_version` and `set_id` from the admin store.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryInput {
    pub display_name: String,
    pub role: Role,
    #[serde(deserialize_with = "super::strict::objects")]
    pub groups: Vec<DirectoryGroup>,
    /// Only read to refuse it with a clear message.
    #[serde(default)]
    directory_version: Option<serde_json::Value>,
    #[serde(default)]
    set_id: Option<serde_json::Value>,
}

impl Drop for DirectoryInput {
    fn drop(&mut self) {
        self.display_name.zeroize();
    }
}

impl DirectoryInput {
    pub fn to_directory(&self, set_id: &str) -> Directory {
        Directory {
            directory_version: DIRECTORY_VERSION,
            set_id: set_id.to_string(),
            display_name: self.display_name.clone(),
            role: self.role,
            groups: self.groups.clone(),
        }
    }
}

pub fn parse_directory_file(text: &str) -> Result<DirectoryInput, String> {
    let d: DirectoryInput =
        super::strict::from_slice(text.as_bytes()).map_err(|e| format!("directory file: {e}"))?;
    if d.set_id.is_some() || d.directory_version.is_some() {
        return Err("directory file: set_id and directory_version are set by sxprov from the admin store; remove them".into());
    }
    // Every rule but the links, which need the servers of the request.
    d.to_directory(&"0".repeat(32)).check_fields()?;
    Ok(d)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for ok in [
            "Anna",
            "Dr Weber",
            "Kanzlei Müller-Lüdenscheidt",
            "Jürgen Groß",
            "Łukasz Żółć",
            "Françoise Gonçalves",
            "Peña Ibáñez",
            "Ștefan Țurcanu",
            "Praxis 2",
            "1A",
            "Anna - Büro",
            "Anna-",
            "ẞ Kapital",
            &"a".repeat(50),
        ] {
            assert_eq!(mk_valid_name(ok), ok, "{ok}");
            check_name("name", ok).unwrap();
        }
    }

    #[test]
    fn refused_names() {
        for (bad, want) in [
            ("", "1 to 50 characters"),
            (&"a".repeat(51) as &str, "it has 51"),
            ("Dr. Weber", "\".\" (U+002E)"),
            ("Anna, Ben", "(U+002C)"),
            ("Anna_1", "(U+005F)"),
            ("Anna's", "(U+0027)"),
            ("Anna@Home", "(U+0040)"),
            ("Ann\u{e4}\u{308}", "(U+0308)"),
            ("Anna\tBen", "character (U+0009)"),
            ("Anna\u{a0}Ben", "character (U+00A0)"),
            ("Μαρία", "(U+039C)"),
            ("Иван", "(U+0418)"),
            ("Anna ×2", "(U+00D7)"),
            ("Anna 😀", "(U+1F600)"),
            (" Anna", "not a valid SimpleX name"),
            ("-Anna", "not a valid SimpleX name"),
            ("Anna ", "not a valid SimpleX name"),
            ("Anna  Ben", "not a valid SimpleX name"),
            ("Anna--Ben", "not a valid SimpleX name"),
            ("Anna - -Ben", "not a valid SimpleX name"),
        ] {
            let e = check_name("display_name", bad).unwrap_err();
            assert!(e.contains(want), "{bad:?}: {e}");
            if bad.len() > 3 {
                assert!(!e.contains(bad), "{e}");
            }
        }
        // What the core would make of them (the port's own behaviour).
        assert_eq!(mk_valid_name(" Anna "), "Anna");
        assert_eq!(mk_valid_name("Anna  Ben"), "Anna Ben");
        assert_eq!(mk_valid_name("Dr. Weber"), "Dr Weber");
        assert_eq!(mk_valid_name("a--b"), "a-b");
    }

    fn group(name: &str) -> DirectoryGroup {
        DirectoryGroup {
            name: name.into(),
            link: "https://example.invalid/g#x".into(),
            direct_contacts: true,
        }
    }

    pub fn sample(groups: usize) -> Directory {
        Directory {
            directory_version: 1,
            set_id: "5e".repeat(16),
            display_name: "TEST Anna".into(),
            role: Role::Member,
            groups: (0..groups)
                .map(|i| group(&format!("TEST Gruppe {i}")))
                .collect(),
        }
    }

    #[test]
    fn field_rules() {
        sample(1).check_fields().unwrap();
        sample(20).check_fields().unwrap();
        let with = |f: fn(&mut Directory)| {
            let mut d = sample(1);
            f(&mut d);
            d
        };
        let cases: Vec<(Directory, &str)> = vec![
            (sample(0), "1 to 20 entries"),
            (sample(21), "it has 21"),
            (with(|d| d.directory_version = 2), "directory_version"),
            (with(|d| d.set_id = "5E".repeat(16)), "set_id"),
            (with(|d| d.set_id = "5e".repeat(15)), "set_id"),
            (with(|d| d.display_name = "Dr. Test".into()), "display_name"),
        ];
        for (d, want) in cases {
            let e = d.check_fields().unwrap_err();
            assert!(e.contains(want), "{e}");
        }
        let mut d = sample(2);
        d.groups[1].name = "Team; Alle".into();
        assert!(d.check_fields().unwrap_err().contains("groups[1].name"));
    }

    #[test]
    fn reading() {
        let ok = r#"{"display_name":"TEST Anna","role":"owner","groups":[{"name":"TEST Kanzlei","link":"https://x.example.invalid/g#k","direct_contacts":false}]}"#;
        let d = parse_directory_file(ok).unwrap();
        assert_eq!(d.role, Role::Owner);
        for (bad, want) in [
            (ok.replace("\"owner\"", "\"admin\""), "unknown variant"),
            (ok.replace("\"role\"", "\"rolle\""), "unknown field"),
            (ok.replace("false}", "false,\"x\":1}"), "unknown field"),
            (ok.replace("false", "\"no\""), "invalid type"),
            (ok.replace("{\"display_name\"", "{\"set_id\":\"00\",\"display_name\""), "set by sxprov"),
            (ok.replace("{\"display_name\"", "{\"directory_version\":1,\"display_name\""), "set by sxprov"),
            (ok.replace("\"TEST Anna\"", "\"TEST. Anna\""), "U+002E"),
            (ok.replace(",\"direct_contacts\":false", ""), "missing field"),
            (
                ok.replace(
                    "{\"name\":\"TEST Kanzlei\",\"link\":\"https://x.example.invalid/g#k\",\"direct_contacts\":false}",
                    "[\"TEST Kanzlei\",\"https://x.example.invalid/g#k\",false]",
                ),
                "expected a JSON object",
            ),
            ("[\"TEST Anna\",\"owner\",[]]".to_string(), "expected a JSON object"),
        ] {
            let e = parse_directory_file(&bad).unwrap_err();
            assert!(e.contains(want), "{bad}: {e}");
        }
        // Serialized as the payload object, every field present.
        let v = serde_json::to_value(d.to_directory(&"ab".repeat(16))).unwrap();
        assert_eq!(v["directory_version"], 1);
        assert_eq!(v["groups"][0]["direct_contacts"], false);
    }

    #[test]
    fn groups_hash_is_order_and_value_sensitive() {
        let a = sample(2);
        let mut b = sample(2);
        b.groups.swap(0, 1);
        assert_ne!(
            Directory::groups_sha256(&a.groups),
            Directory::groups_sha256(&b.groups)
        );
        let mut c = sample(2);
        c.groups[0].direct_contacts = false;
        assert_ne!(
            Directory::groups_sha256(&a.groups),
            Directory::groups_sha256(&c.groups)
        );
        assert_eq!(
            Directory::groups_sha256(&a.groups),
            Directory::groups_sha256(&sample(2).groups)
        );
    }
}
