// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Small helpers: hex, hashing, time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parses hex, ignoring case and `:` separators.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|c| *c != b':').collect();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    clean
        .chunks(2)
        .map(|p| Some(val(p[0])? << 4 | val(p[1])?))
        .collect()
}

/// True if `s` is a 64 digit hex SHA-256 value.
pub fn is_sha256_hex(s: &str) -> bool {
    unhex(s).map(|b| b.len() == 32).unwrap_or(false)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UTC timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn fmt_unix(secs: u64) -> String {
    match x509_cert::der::DateTime::from_unix_duration(Duration::from_secs(secs)) {
        Ok(dt) => dt.to_string(),
        Err(_) => format!("unix:{secs}"),
    }
}

/// Human readable age, for example `3d 4h`.
pub fn fmt_age(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

/// Masks a device serial for normal output: only the last two characters stay.
pub fn mask_serial(serial: &str) -> String {
    let n = serial.chars().count();
    if n <= 2 {
        return "*".repeat(n.max(1));
    }
    let tail: String = serial.chars().skip(n - 2).collect();
    format!("{}{}", "*".repeat(n - 2), tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&b), "0001abff");
        assert_eq!(unhex("00:01:AB:ff").unwrap(), b);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn sha256_hex_check() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex("REPLACE_ME"));
    }

    #[test]
    fn masking() {
        assert_eq!(mask_serial("ABCDEF123456"), "**********56");
        assert_eq!(mask_serial("A"), "*");
    }

    #[test]
    fn time_format() {
        assert_eq!(fmt_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_age(3 * 86_400 + 4 * 3_600), "3d 4h");
        assert_eq!(fmt_age(125), "2m");
    }
}
