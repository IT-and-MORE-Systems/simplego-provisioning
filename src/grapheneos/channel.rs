// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Channel files: `<base>/<codename>-<channel>` (for example `bluejay-stable`)
//! and `<base>/<codename>-<channel>-security-preview`, one line each:
//! `VERSION BUILD_TIME CODENAME CHANNEL`, for example
//! `2026111800 1794968526 bluejay stable`. The second field is the build time
//! in Unix seconds; it equals `ro.build.date.utc` of that build on a phone.
//!
//! The security preview file was found on 2026-11-24 next to the documented
//! channel files (same host, same format, channel field
//! `stable-security-preview`); it names the build the phone actually
//! received (build time equal to its `ro.build.date.utc`). GrapheneOS does
//! not document it on grapheneos.org. A missing
//! file (HTTP 404) means "no security preview build".
//!
//! The files are not signed. They are fetched through Tor only and cached
//! with their fetch time; offline (`--offline` or no Tor) the cached copy is
//! used and its age shown.

use super::{read_small, valid_channel, valid_codename, valid_version, Http};
use crate::util::{fmt_age, fmt_unix};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const PREVIEW_SUFFIX: &str = "-security-preview";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub version: String,
    pub build_time: u64,
    pub codename: String,
    pub channel: String,
}

/// Parses a channel file. The codename and channel must be the expected ones.
pub fn parse(text: &str, codename: &str, channel: &str) -> Result<ChannelInfo, String> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let [line] = lines.as_slice() else {
        return Err("channel file: expected exactly one line".into());
    };
    let f: Vec<&str> = line.split_whitespace().collect();
    let [version, time, c, ch] = f.as_slice() else {
        return Err(format!("channel file: expected 4 fields, got {:?}", line));
    };
    if !valid_version(version) {
        return Err(format!("channel file: bad version {version:?}"));
    }
    let build_time: u64 = time
        .parse()
        .map_err(|_| format!("channel file: bad build time {time:?}"))?;
    if *c != codename || *ch != channel {
        return Err(format!(
            "channel file names {c} {ch}, expected {codename} {channel}"
        ));
    }
    Ok(ChannelInfo {
        version: version.to_string(),
        build_time,
        codename: c.to_string(),
        channel: ch.to_string(),
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Meta {
    url: String,
    fetched_at: u64,
    last_modified: Option<String>,
    /// The server answered 404 (no such channel file).
    absent: bool,
}

/// The outcome of one channel file lookup.
#[derive(Debug, Clone, Serialize)]
pub struct Lookup {
    pub name: String,
    pub url: String,
    pub info: Option<ChannelInfo>,
    /// The file does not exist on the server (404), now or when cached.
    pub absent: bool,
    /// Not fetched now: the cached copy (or nothing) was used.
    pub offline: bool,
    pub fetched_at: Option<u64>,
    pub last_modified: Option<String>,
    pub error: Option<String>,
}

impl Lookup {
    /// "fetched over Tor 2026-11-24T10:00:00Z from URL" or "cached copy ...".
    pub fn source(&self, now: u64) -> String {
        match (self.offline, self.fetched_at) {
            (false, Some(t)) => format!("fetched over Tor {} from {}", fmt_unix(t), self.url),
            (true, Some(t)) => format!(
                "cached copy fetched {} ({} ago) from {} (offline{})",
                fmt_unix(t),
                fmt_age(now.saturating_sub(t)),
                self.url,
                self.error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            ),
            (_, None) => format!(
                "not available (offline, nothing cached{})",
                self.error
                    .as_ref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            ),
        }
    }
}

pub struct Channels<'a> {
    pub base: &'a str,
    pub cache_dir: PathBuf,
    /// None: offline, the cache only.
    pub http: Option<&'a dyn Http>,
    pub now: u64,
}

fn private_dir(d: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(d)
}

impl Channels<'_> {
    fn paths(&self, name: &str) -> (PathBuf, PathBuf) {
        let d = self.cache_dir.join("channels");
        (d.join(name), d.join(format!("{name}.meta.json")))
    }

    fn cached(&self, name: &str, codename: &str, channel: &str, url: &str) -> Lookup {
        let (file, meta) = self.paths(name);
        let m: Option<Meta> = std::fs::read(&meta)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let info = std::fs::read_to_string(&file)
            .ok()
            .and_then(|t| parse(&t, codename, channel).ok());
        Lookup {
            name: name.into(),
            url: url.into(),
            info: if m.as_ref().is_some_and(|m| m.absent) {
                None
            } else {
                info
            },
            absent: m.as_ref().is_some_and(|m| m.absent),
            offline: true,
            fetched_at: m.as_ref().map(|m| m.fetched_at),
            last_modified: m.and_then(|m| m.last_modified),
            error: None,
        }
    }

    fn store(&self, name: &str, body: Option<&[u8]>, meta: &Meta) -> Result<(), String> {
        let (file, mp) = self.paths(name);
        if let Some(d) = file.parent() {
            private_dir(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
        }
        match body {
            Some(b) => std::fs::write(&file, b),
            None => match std::fs::remove_file(&file) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        }
        .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
        std::fs::write(&mp, serde_json::to_vec_pretty(meta).unwrap_or_default())
            .map_err(|e| format!("cannot write {}: {e}", mp.display()))
    }

    /// Looks up `<codename>-<channel>` (or its security preview file).
    pub fn lookup(&self, codename: &str, channel: &str, preview: bool) -> Lookup {
        let ch = if preview {
            format!("{channel}{PREVIEW_SUFFIX}")
        } else {
            channel.to_string()
        };
        let name = format!("{codename}-{ch}");
        let url = format!("{}/{name}", self.base);
        if !valid_codename(codename) || !valid_channel(channel) {
            let mut l = self.cached(&name, codename, &ch, &url);
            l.info = None;
            l.error = Some(format!(
                "invalid codename or channel {codename:?} {channel:?}"
            ));
            return l;
        }
        let Some(http) = self.http else {
            return self.cached(&name, codename, &ch, &url);
        };
        let fetched = http.get(&url, 0).and_then(|mut r| match r.status {
            200 => {
                let body = read_small(&mut r, 4096, &url)?;
                let text =
                    String::from_utf8(body.clone()).map_err(|_| format!("{url}: not text"))?;
                let info = parse(&text, codename, &ch).map_err(|e| format!("{url}: {e}"))?;
                Ok((Some(body), Some(info), r.last_modified.clone()))
            }
            404 => Ok((None, None, None)),
            s => Err(format!("{url}: HTTP {s}")),
        });
        match fetched {
            Ok((body, info, last_modified)) => {
                let meta = Meta {
                    url: url.clone(),
                    fetched_at: self.now,
                    last_modified: last_modified.clone(),
                    absent: body.is_none(),
                };
                let error = self.store(&name, body.as_deref(), &meta).err();
                Lookup {
                    name,
                    url,
                    absent: info.is_none(),
                    info,
                    offline: false,
                    fetched_at: Some(self.now),
                    last_modified,
                    error,
                }
            }
            Err(e) => {
                let mut l = self.cached(&name, codename, &ch, &url);
                l.error = Some(e);
                l
            }
        }
    }

    /// The release and the security preview file of a channel.
    pub fn release(&self, codename: &str, channel: &str) -> Release {
        Release {
            stable: self.lookup(codename, channel, false),
            preview: self.lookup(codename, channel, true),
        }
    }
}

/// What the channel offers for one device.
#[derive(Debug, Clone, Serialize)]
pub struct Release {
    /// The channel's release (`<codename>-<channel>`).
    pub stable: Lookup,
    /// Its security preview (`<codename>-<channel>-security-preview`).
    pub preview: Lookup,
}

impl Release {
    /// The build the setting asks for: `newest` takes the security preview
    /// when there is one not older than the release; `stable` the release.
    pub fn target(&self, setting: super::ReleaseSetting) -> Option<(ChannelInfo, bool)> {
        let s = self.stable.info.clone()?;
        if setting == super::ReleaseSetting::Newest {
            if let Some(p) = &self.preview.info {
                if p.build_time >= s.build_time {
                    return Some((p.clone(), true));
                }
            }
        }
        Some((s, false))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testhttp::FakeHttp;
    use super::super::ReleaseSetting;
    use super::*;

    const STABLE: &str = include_str!("../../tests/fixtures/grapheneos/bluejay-stable");
    const PREVIEW: &str =
        include_str!("../../tests/fixtures/grapheneos/bluejay-stable-security-preview");
    const BASE: &str = "https://releases.grapheneos.org";

    #[test]
    fn real_channel_files_parse() {
        let s = parse(STABLE, "bluejay", "stable").unwrap();
        assert_eq!(s.version, "2026111800");
        assert_eq!(s.build_time, 1_794_968_526);
        let p = parse(PREVIEW, "bluejay", "stable-security-preview").unwrap();
        assert_eq!(p.version, "2026111801");
        assert_eq!(p.build_time, 1_794_968_527);
        assert!(parse(STABLE, "oriole", "stable").is_err());
        assert!(parse(STABLE, "bluejay", "beta").is_err());
        assert!(parse("2026111800 1794968526 bluejay\n", "bluejay", "stable").is_err());
        assert!(parse("x 1 bluejay stable\n", "bluejay", "stable").is_err());
        assert!(parse(&format!("{STABLE}{STABLE}"), "bluejay", "stable").is_err());
    }

    #[test]
    fn fetch_cache_offline_and_preview_absent() {
        let d = crate::activation::store::tests::temp_dir("channels");
        let h = FakeHttp::default();
        h.put(&format!("{BASE}/bluejay-stable"), STABLE.as_bytes());
        h.put(
            &format!("{BASE}/bluejay-stable-security-preview"),
            PREVIEW.as_bytes(),
        );
        let ch = Channels {
            base: BASE,
            cache_dir: d.clone(),
            http: Some(&h),
            now: 1_795_000_000,
        };
        let r = ch.release("bluejay", "stable");
        assert!(!r.stable.offline && r.stable.error.is_none());
        let (t, preview) = r.target(ReleaseSetting::Newest).unwrap();
        assert!(preview);
        assert_eq!(t.version, "2026111801");
        let (t, preview) = r.target(ReleaseSetting::Stable).unwrap();
        assert!(!preview);
        assert_eq!(t.version, "2026111800");
        // Only the allowed host was asked, only for the two files.
        assert_eq!(
            h.urls(),
            vec![
                format!("GET {BASE}/bluejay-stable from 0"),
                format!("GET {BASE}/bluejay-stable-security-preview from 0")
            ]
        );
        // Tor down: the cached copy, marked offline, with its age.
        *h.down.borrow_mut() = true;
        let ch2 = Channels {
            now: 1_795_000_000 + 7200,
            ..ch
        };
        let r = ch2.release("bluejay", "stable");
        assert!(r.stable.offline);
        assert_eq!(r.stable.info.as_ref().unwrap().version, "2026111800");
        assert!(
            r.stable.source(ch2.now).contains("2h"),
            "{}",
            r.stable.source(ch2.now)
        );
        assert!(r.stable.source(ch2.now).contains("Tor down"));
        // No security preview on the server (404): newest falls back to stable.
        *h.down.borrow_mut() = false;
        h.files
            .borrow_mut()
            .remove(&format!("{BASE}/bluejay-stable-security-preview"));
        let r = ch2.release("bluejay", "stable");
        assert!(r.preview.absent && r.preview.info.is_none());
        assert_eq!(
            r.target(ReleaseSetting::Newest).unwrap().0.version,
            "2026111800"
        );
        // ...and offline the absence is remembered, not the old file.
        let off = Channels { http: None, ..ch2 };
        let r = off.release("bluejay", "stable");
        assert!(r.preview.absent && r.preview.info.is_none() && r.preview.offline);
        assert_eq!(r.stable.info.unwrap().version, "2026111800");
        // Nothing cached at all: no info.
        let empty = Channels {
            base: BASE,
            cache_dir: d.join("none"),
            http: None,
            now: 1,
        };
        let r = empty.release("bluejay", "stable");
        assert!(r.stable.info.is_none() && r.target(ReleaseSetting::Newest).is_none());
        assert!(r.stable.source(1).contains("nothing cached"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
