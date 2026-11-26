// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Answers of the messenger's activation provider:
//! `adb shell content call ...` prints `Result: Bundle[{key=value, ...}]`.
//! The values the provider defines: `result=ok` or `result=error: ...`;
//! `status` gives `activation=yes|no` and `setup=done|open`.

use std::collections::BTreeMap;

/// Key/value pairs of the printed bundle. A value may contain `, ` (an error
/// text); a new pair starts only where `, ` is followed by `key=` with a
/// lower case key. None if there is no bundle in the output.
pub fn parse_bundle(out: &str) -> Option<BTreeMap<String, String>> {
    let start = out.find("Bundle[{")? + "Bundle[{".len();
    let end = out.rfind("}]")?;
    if end < start {
        return None;
    }
    let inner = &out[start..end];
    let mut map = BTreeMap::new();
    if inner.trim().is_empty() {
        return Some(map);
    }
    let mut pairs: Vec<String> = Vec::new();
    for piece in inner.split(", ") {
        let starts_pair = piece
            .split_once('=')
            .map(|(k, _)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .unwrap_or(false);
        match pairs.last_mut() {
            Some(last) if !starts_pair => {
                last.push_str(", ");
                last.push_str(piece);
            }
            _ => pairs.push(piece.to_string()),
        }
    }
    for p in pairs {
        let (k, v) = p.split_once('=')?;
        map.insert(k.to_string(), v.to_string());
    }
    Some(map)
}

pub fn first_line(s: &str) -> String {
    let l = s.lines().next().unwrap_or("").trim();
    if l.is_empty() {
        "no output".into()
    } else {
        l.chars().take(200).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub activation: bool,
    pub setup_done: bool,
    pub file_import: bool,
    pub file_id: Option<String>,
    pub network_mode: Option<String>,
}

pub fn status(m: &BTreeMap<String, String>) -> Result<Status, String> {
    let yes_no = |k: &str| match m.get(k).map(String::as_str) {
        Some("yes") => Ok(true),
        Some("no") => Ok(false),
        other => Err(format!("status: unexpected {k}={other:?}")),
    };
    let setup = match m.get("setup").map(String::as_str) {
        Some("done") => true,
        Some("open") => false,
        other => return Err(format!("status: unexpected setup={other:?}")),
    };
    Ok(Status {
        activation: yes_no("activation")?,
        setup_done: setup,
        file_import: m
            .get(super::phone::FILE_IMPORT_CAPABILITY)
            .map(String::as_str)
            == Some("yes"),
        file_id: m.get("file_id").cloned(),
        network_mode: m.get("network_mode").cloned(),
    })
}

/// `result=ok`, or the error the provider gave.
pub fn result_ok(m: &BTreeMap<String, String>) -> Result<(), String> {
    match m.get("result").map(String::as_str) {
        Some("ok") => Ok(()),
        Some(e) => Err(format!("the activation provider answered result={e}")),
        None => Err("the activation provider gave no result".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles() {
        let m = parse_bundle("Result: Bundle[{result=ok}]\n").unwrap();
        assert_eq!(m.get("result").unwrap(), "ok");
        assert!(result_ok(&m).is_ok());
        let m = parse_bundle("Result: Bundle[{activation=yes, setup=open}]").unwrap();
        let s = status(&m).unwrap();
        assert!(s.activation && !s.setup_done && !s.file_import);
        let m = parse_bundle("Result: Bundle[{result=error: bad code, try again, n=1}]").unwrap();
        assert_eq!(m.get("result").unwrap(), "error: bad code, try again");
        assert_eq!(m.get("n").unwrap(), "1");
        assert!(result_ok(&m).unwrap_err().contains("error: bad code"));
        assert!(parse_bundle("Error while accessing provider:x").is_none());
        let m = parse_bundle(
            "Result: Bundle[{activation=yes, setup=open, file_import=yes, file_id=ab, network_mode=tor_required}]",
        )
        .unwrap();
        let s = status(&m).unwrap();
        assert!(s.file_import);
        assert_eq!(s.file_id.as_deref(), Some("ab"));
        assert!(status(&parse_bundle("Result: Bundle[{setup=maybe}]").unwrap()).is_err());
    }
}
