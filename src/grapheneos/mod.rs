// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! GrapheneOS releases: channel files, the
//! installed version compared with them, and signed factory images.
//!
//! Everything comes from `grapheneos_release_base`
//! (`https://releases.grapheneos.org`) through Tor only. The channel files
//! are not signed (only Tor protects them), so every output names their
//! source and fetch time. Factory images are accepted only with a valid
//! SSHSIG signature (namespace `factory images`, `contact@grapheneos.org`)
//! against the key pinned in `trust/grapheneos/allowed_signers`.

pub mod channel;
pub mod image;
pub mod status;
pub mod zipx;

use std::io::Read;

pub const DEFAULT_RELEASE_BASE: &str = "https://releases.grapheneos.org";
pub const FACTORY_NAMESPACE: &str = "factory images";

/// SHA-256 of the GrapheneOS verified boot key per device codename, from the
/// official CLI install guide (grapheneos.org/install/cli, section "Verified
/// boot key hash", read over Tor on 2026-11-23). `flash` refuses a codename
/// without an entry here.
pub const BOOT_KEYS: &[(&str, &str)] = &[(
    "bluejay",
    "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031",
)];

pub fn boot_key<'a>(keys: &'a [(String, String)], codename: &str) -> Option<&'a str> {
    keys.iter()
        .find(|(c, _)| c == codename)
        .map(|(_, k)| k.as_str())
}

pub fn pinned_boot_keys() -> Vec<(String, String)> {
    BOOT_KEYS
        .iter()
        .map(|(c, k)| (c.to_string(), k.to_string()))
        .collect()
}

/// `newest`: the security preview build when the channel has one, otherwise
/// the release. `stable`: the release only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseSetting {
    Newest,
    Stable,
}

impl ReleaseSetting {
    pub fn parse(s: &str) -> Option<ReleaseSetting> {
        match s {
            "newest" => Some(ReleaseSetting::Newest),
            "stable" => Some(ReleaseSetting::Stable),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseSetting::Newest => "newest",
            ReleaseSetting::Stable => "stable",
        }
    }
}

pub fn valid_channel(s: &str) -> bool {
    matches!(s, "stable" | "beta" | "alpha")
}

pub fn valid_codename(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A GrapheneOS version: ten digits, `YYYYMMDDNN`.
pub fn valid_version(s: &str) -> bool {
    s.len() == 10 && s.bytes().all(|b| b.is_ascii_digit())
}

/// One HTTP answer. `body` streams; nothing is held in memory.
pub struct HttpResp {
    pub status: u16,
    pub content_length: Option<u64>,
    /// The `start` of `Content-Range: bytes start-end/total`, and `total`.
    pub range: Option<(u64, Option<u64>)>,
    pub last_modified: Option<String>,
    pub body: Box<dyn Read>,
}

/// GET with an optional `Range: bytes=FROM-`. The real one goes through Tor;
/// the tests use a fake.
pub trait Http {
    fn get(&self, url: &str, from: u64) -> Result<HttpResp, String>;
}

/// Every download over Tor (`crate::tor`): idle limit and new circuits.
pub use crate::tor::TorHttp;

pub(crate) fn parse_content_range(v: &str) -> Option<(u64, Option<u64>)> {
    // "bytes 100-199/200" or "bytes 100-199/*"
    let rest = v.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, _) = range.split_once('-')?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse().ok()?)
    };
    Some((start.parse().ok()?, total))
}

/// Reads a small body (channel file, signature) with a size limit.
pub fn read_small(r: &mut HttpResp, limit: u64, url: &str) -> Result<Vec<u8>, String> {
    let mut v = Vec::new();
    (&mut r.body)
        .take(limit + 1)
        .read_to_end(&mut v)
        .map_err(|e| format!("{url}: {e}"))?;
    if v.len() as u64 > limit {
        return Err(format!("{url}: answer larger than {limit} bytes"));
    }
    Ok(v)
}

#[cfg(test)]
pub mod testhttp {
    //! A fake web server for the tests: answers from a map, logs every URL,
    //! can break a download after a number of bytes.
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct FakeHttp {
        pub files: RefCell<BTreeMap<String, Vec<u8>>>,
        pub log: RefCell<Vec<String>>,
        /// Break the next answers for this URL after so many bytes.
        pub break_after: RefCell<BTreeMap<String, Vec<usize>>>,
        /// Answer an error (Tor down) for every URL.
        pub down: RefCell<bool>,
        /// Ignore Range headers (answer 200 with the whole file).
        pub no_ranges: RefCell<bool>,
    }

    struct Broken {
        data: std::io::Cursor<Vec<u8>>,
        left: usize,
    }

    impl Read for Broken {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset (test)",
                ));
            }
            let n = buf.len().min(self.left);
            let got = self.data.read(&mut buf[..n])?;
            self.left -= got;
            if got == 0 {
                return Ok(0);
            }
            Ok(got)
        }
    }

    impl FakeHttp {
        pub fn put(&self, url: &str, data: &[u8]) {
            self.files.borrow_mut().insert(url.into(), data.to_vec());
        }
        pub fn urls(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl Http for FakeHttp {
        fn get(&self, url: &str, from: u64) -> Result<HttpResp, String> {
            self.log.borrow_mut().push(format!("GET {url} from {from}"));
            if *self.down.borrow() {
                return Err(format!("{url}: connection refused (test: Tor down)"));
            }
            let Some(data) = self.files.borrow().get(url).cloned() else {
                return Ok(HttpResp {
                    status: 404,
                    content_length: Some(0),
                    range: None,
                    last_modified: None,
                    body: Box::new(std::io::empty()),
                });
            };
            let total = data.len() as u64;
            let ranged = from > 0 && !*self.no_ranges.borrow();
            if ranged && from >= total {
                return Ok(HttpResp {
                    status: 416,
                    content_length: Some(0),
                    range: None,
                    last_modified: None,
                    body: Box::new(std::io::empty()),
                });
            }
            let part = if ranged {
                data[from as usize..].to_vec()
            } else {
                data.clone()
            };
            let len = part.len() as u64;
            let brk = self.break_after.borrow_mut().get_mut(url).and_then(|v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.remove(0))
                }
            });
            let body: Box<dyn Read> = match brk {
                Some(n) => Box::new(Broken {
                    data: std::io::Cursor::new(part),
                    left: n,
                }),
                None => Box::new(std::io::Cursor::new(part)),
            };
            Ok(HttpResp {
                status: if ranged { 206 } else { 200 },
                content_length: Some(len),
                range: if ranged {
                    Some((from, Some(total)))
                } else {
                    None
                },
                last_modified: Some("Wed, 18 Nov 2026 16:54:22 GMT".into()),
                body,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ranges() {
        assert!(valid_version("2026111801"));
        assert!(!valid_version("202611180"));
        assert!(!valid_version("20261118a1"));
        assert!(valid_codename("bluejay"));
        assert!(!valid_codename("Bluejay"));
        assert!(!valid_codename("blue/jay"));
        assert!(!valid_codename(""));
        assert_eq!(
            parse_content_range("bytes 100-199/200"),
            Some((100, Some(200)))
        );
        assert_eq!(parse_content_range("bytes 5-9/*"), Some((5, None)));
        assert_eq!(parse_content_range("items 1-2/3"), None);
        assert_eq!(
            boot_key(&pinned_boot_keys(), "bluejay"),
            Some("08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031")
        );
        assert_eq!(boot_key(&pinned_boot_keys(), "oriole"), None);
    }
}
