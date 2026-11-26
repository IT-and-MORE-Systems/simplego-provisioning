// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `trust refresh`: download the lists through Tor only. No clearnet fallback.

use super::cache::{self, Cache, GOS_FILE, GOS_SIG_FILE, REVOCATION_FILE};
use super::lists::{GrapheneOsKeys, RevocationList};
use crate::grapheneos::{Http, TorHttp};
use crate::names;
use crate::util::now_unix;
use std::time::Duration;

const MAX_BODY: u64 = 16 * 1024 * 1024;
/// Connect timeout to the SOCKS proxy (Tor circuits can be slow to build).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Fetched {
    pub body: Vec<u8>,
    pub last_modified: Option<String>,
}

/// One list over Tor (`crate::tor`: the idle limit and new circuits), with a
/// size limit.
pub fn fetch(http: &dyn Http, url: &str) -> Result<Fetched, String> {
    let mut r = http.get(url, 0)?;
    if r.status != 200 {
        return Err(format!("{url}: HTTP {}", r.status));
    }
    let body = crate::grapheneos::read_small(&mut r, MAX_BODY, url)?;
    Ok(Fetched {
        body,
        last_modified: r.last_modified.clone(),
    })
}

#[derive(Debug, Default)]
pub struct RefreshReport {
    pub revocation: Option<Result<String, String>>,
    pub grapheneos: Option<Result<String, String>>,
}

impl RefreshReport {
    pub fn ok(&self) -> bool {
        matches!(self.revocation, Some(Ok(_))) && matches!(self.grapheneos, Some(Ok(_)))
    }
}

pub fn refresh(
    cache: &Cache,
    proxy_url: &str,
    connect_timeout: Duration,
    idle: Duration,
) -> RefreshReport {
    let mut rep = RefreshReport::default();
    let agent = match TorHttp::new(proxy_url, connect_timeout, idle) {
        Ok(a) => a,
        Err(e) => {
            rep.revocation = Some(Err(e.clone()));
            rep.grapheneos = Some(Err(e));
            return rep;
        }
    };
    rep.revocation = Some(refresh_revocation(cache, &agent));
    rep.grapheneos = Some(refresh_grapheneos(cache, &agent));
    rep
}

fn refresh_revocation(cache: &Cache, agent: &dyn Http) -> Result<String, String> {
    let f = fetch(agent, names::URL_REVOCATION_STATUS)?;
    let list = RevocationList::parse(&f.body)?;
    let meta = cache::meta_for(
        names::URL_REVOCATION_STATUS,
        now_unix(),
        f.last_modified,
        &f.body,
    );
    cache.store(&[(REVOCATION_FILE, &f.body)], REVOCATION_FILE, &meta)?;
    Ok(format!("{} entries", list.entries.len()))
}

fn refresh_grapheneos(cache: &Cache, agent: &dyn Http) -> Result<String, String> {
    let f = fetch(agent, names::URL_GRAPHENEOS_KEYS)?;
    let s = fetch(agent, names::URL_GRAPHENEOS_KEYS_SIG)?;
    let sig = String::from_utf8(s.body.clone()).map_err(|_| "signature is not text")?;
    let keys = accept_grapheneos(cache, &f.body, &sig)?;
    let meta = cache::meta_for(
        names::URL_GRAPHENEOS_KEYS,
        now_unix(),
        f.last_modified,
        &f.body,
    );
    cache.store(
        &[(GOS_FILE, &f.body), (GOS_SIG_FILE, &s.body)],
        GOS_FILE,
        &meta,
    )?;
    Ok(format!(
        "{} keys, signed list timestamp {}",
        keys.keys.len(),
        crate::util::fmt_unix(keys.timestamp)
    ))
}

/// File names `trust import` expects in its directory.
pub const IMPORT_REVOCATION: &str = "status.json";
pub const IMPORT_GOS: &str = "attestation.json";
pub const IMPORT_GOS_SIG: &str = "attestation.json.sig";
/// Suffix of the optional response header file next to a placed list, as
/// written by `curl -D <file>.headers.txt`.
pub const IMPORT_HEADERS_SUFFIX: &str = ".headers.txt";

/// The `Last-Modified` value from saved HTTP response headers. When the file
/// holds several responses (for example after a redirect), only the last
/// response counts. Header names are matched without regard to case.
pub fn last_modified_from_headers(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .rposition(|l| l.starts_with("HTTP/"))
        .unwrap_or(0);
    lines[start..].iter().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        let v = v.trim();
        (k.trim().eq_ignore_ascii_case("last-modified") && !v.is_empty()).then(|| v.to_string())
    })
}

/// `trust import DIR`: takes lists that an operator placed by hand (for
/// example when no Tor proxy runs). The same checks as for a download apply:
/// the revocation list must parse, the GrapheneOS list must carry a valid
/// signature and must not be older than the cached one. The age counts from
/// the file's modification time, the best available sign of when it was
/// fetched, and the source is recorded as "manually placed". `Last-Modified`
/// is taken from `<file>.headers.txt` next to the file, if present.
pub fn import_manual(cache: &Cache, dir: &std::path::Path, now: u64) -> RefreshReport {
    let read = |name: &str| -> Result<(Vec<u8>, u64, String), String> {
        let p = dir.join(name);
        let data = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let mtime = std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .map_err(|e| format!("{}: {e}", p.display()))?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok((data, mtime.min(now), p.display().to_string()))
    };
    let last_modified = |name: &str| -> Option<String> {
        let p = dir.join(format!("{name}{IMPORT_HEADERS_SUFFIX}"));
        let text = std::fs::read_to_string(p).ok()?;
        last_modified_from_headers(&text)
    };
    let source = |path: &str, mtime: u64| {
        format!(
            "manually placed: {path} (file modified {}, imported {}); not downloaded by {}",
            crate::util::fmt_unix(mtime),
            crate::util::fmt_unix(now),
            names::BINARY
        )
    };
    let revocation = (|| {
        let (data, mtime, path) = read(IMPORT_REVOCATION)?;
        let list = RevocationList::parse(&data)?;
        let mut meta = cache::meta_for(
            names::URL_REVOCATION_STATUS,
            mtime,
            last_modified(IMPORT_REVOCATION),
            &data,
        );
        meta.source = Some(source(&path, mtime));
        cache.store(&[(REVOCATION_FILE, &data)], REVOCATION_FILE, &meta)?;
        Ok(format!("{} entries, manually placed", list.entries.len()))
    })();
    let grapheneos = (|| {
        let (data, mtime, path) = read(IMPORT_GOS)?;
        let (sig, _, _) = read(IMPORT_GOS_SIG)?;
        let sig_text = String::from_utf8(sig.clone()).map_err(|_| "signature is not text")?;
        let keys = accept_grapheneos(cache, &data, &sig_text)?;
        let mut meta = cache::meta_for(
            names::URL_GRAPHENEOS_KEYS,
            mtime,
            last_modified(IMPORT_GOS),
            &data,
        );
        meta.source = Some(source(&path, mtime));
        cache.store(&[(GOS_FILE, &data), (GOS_SIG_FILE, &sig)], GOS_FILE, &meta)?;
        Ok(format!(
            "{} keys, signature valid, signed list timestamp {}, manually placed",
            keys.keys.len(),
            crate::util::fmt_unix(keys.timestamp)
        ))
    })();
    RefreshReport {
        revocation: Some(revocation),
        grapheneos: Some(grapheneos),
    }
}

/// Checks a downloaded GrapheneOS list before it may replace the cached one:
/// valid signature, and not older than the cached list (rollback protection,
/// as the GrapheneOS guide recommends). On error the previous copy stays.
pub fn accept_grapheneos(cache: &Cache, json: &[u8], sig: &str) -> Result<GrapheneOsKeys, String> {
    let keys = GrapheneOsKeys::verify_and_parse(json, sig)?;
    let cached = cache.load_grapheneos().ok().map(|o| o.value.timestamp);
    check_not_older(keys.timestamp, cached)?;
    Ok(keys)
}

fn check_not_older(new_ts: u64, cached_ts: Option<u64>) -> Result<(), String> {
    match cached_ts {
        Some(old) if new_ts < old => Err(format!(
            "downloaded GrapheneOS key list is older than the cached one ({new_ts} < {old}); kept the cached list"
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A placeholder proxy: refresh refuses before any connection.
    #[test]
    fn placeholder_proxy_refuses_refresh() {
        let dir =
            std::env::temp_dir().join(format!("sxprov-test-placeholder-{}", std::process::id()));
        let c = Cache::new(&dir);
        let rep = refresh(
            &c,
            "REPLACE_WITH_GATEWAY_SOCKS",
            CONNECT_TIMEOUT,
            CONNECT_TIMEOUT,
        );
        assert!(!rep.ok());
        match &rep.revocation {
            Some(Err(e)) => assert!(e.contains("placeholder")),
            other => panic!("{other:?}"),
        }
        assert!(c.load_revocation().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing listens on the port: the refresh must fail, never fall back.
    #[test]
    fn unreachable_proxy_fails_without_fallback() {
        let dir = std::env::temp_dir().join(format!("sxprov-test-noproxy-{}", std::process::id()));
        let c = Cache::new(&dir);
        let rep = refresh(
            &c,
            "socks5h://127.0.0.1:9",
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        assert!(!rep.ok());
        assert!(matches!(rep.revocation, Some(Err(_))));
        assert!(matches!(rep.grapheneos, Some(Err(_))));
        assert!(c.load_revocation().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_modified_parsing() {
        let one = "HTTP/1.1 200 OK\r\nlast-modified: Mon, 20 Apr 2026 22:44:15 GMT\r\n\r\n";
        assert_eq!(
            last_modified_from_headers(one).as_deref(),
            Some("Mon, 20 Apr 2026 22:44:15 GMT")
        );
        // After a redirect only the last response counts.
        let two = "HTTP/1.1 301 Moved\nLast-Modified: Thu, 01 Jan 2026 00:00:00 GMT\n\n\
                   HTTP/1.1 200 OK\nLAST-MODIFIED: Fri, 02 Jan 2026 00:00:00 GMT\n";
        assert_eq!(
            last_modified_from_headers(two).as_deref(),
            Some("Fri, 02 Jan 2026 00:00:00 GMT")
        );
        // A value from an earlier response is not carried over.
        let redirect_only = "HTTP/1.1 301 Moved\nLast-Modified: Thu, 01 Jan 2026 00:00:00 GMT\n\n\
                             HTTP/1.1 200 OK\nDate: x\n";
        assert!(last_modified_from_headers(redirect_only).is_none());
        assert!(last_modified_from_headers("HTTP/1.1 200 OK\nDate: x\n").is_none());
        assert!(last_modified_from_headers("HTTP/1.1 200 OK\nLast-Modified: \n").is_none());
    }

    #[test]
    fn manual_import_records_source_and_checks_signature() {
        let base = std::env::temp_dir().join(format!("sxprov-test-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("placed");
        std::fs::create_dir_all(&src).unwrap();
        let json = include_bytes!("../../tests/fixtures/trust/attestation.json");
        let sig = include_bytes!("../../tests/fixtures/trust/attestation.json.sig");
        let status = include_bytes!("../../tests/fixtures/trust/status-sample.json");
        std::fs::write(src.join(IMPORT_GOS), json).unwrap();
        std::fs::write(src.join(IMPORT_GOS_SIG), sig).unwrap();
        std::fs::write(src.join(IMPORT_REVOCATION), status).unwrap();
        // Headers saved by curl -D for the revocation list only.
        std::fs::write(
            src.join(format!("{IMPORT_REVOCATION}{IMPORT_HEADERS_SUFFIX}")),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Last-Modified: Mon, 16 Nov 2026 20:48:00 GMT\r\n\r\n",
        )
        .unwrap();
        let c = Cache::new(&base.join("cache"));
        let now = now_unix() + 3600;
        let rep = import_manual(&c, &src, now);
        assert!(rep.ok(), "{rep:?}");
        let r = c.load_revocation().unwrap();
        assert!(r.meta.source_label().starts_with("manually placed"));
        assert!(r.meta.fetched_at <= now);
        assert_eq!(
            r.meta.last_modified.as_deref(),
            Some("Mon, 16 Nov 2026 20:48:00 GMT")
        );
        // No headers file: Last-Modified stays unknown.
        assert!(c.load_grapheneos().unwrap().meta.last_modified.is_none());
        assert!(c
            .load_grapheneos()
            .unwrap()
            .meta
            .source_label()
            .starts_with("manually placed"));

        // A tampered list is refused and the imported copy stays.
        let mut bad = json.to_vec();
        bad[5] ^= 1;
        std::fs::write(src.join(IMPORT_GOS), &bad).unwrap();
        let rep = import_manual(&c, &src, now);
        assert!(matches!(rep.grapheneos, Some(Err(_))));
        assert!(c.load_grapheneos().is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rollback_rejected_and_bad_signature_keeps_old() {
        let dir = std::env::temp_dir().join(format!("sxprov-test-rollback-{}", std::process::id()));
        let c = Cache::new(&dir);
        let json = include_bytes!("../../tests/fixtures/trust/attestation.json");
        let sig = include_str!("../../tests/fixtures/trust/attestation.json.sig");
        assert!(accept_grapheneos(&c, json, sig).is_ok());
        assert!(check_not_older(99, Some(100)).is_err());
        assert!(check_not_older(100, Some(100)).is_ok());
        assert!(check_not_older(1, None).is_ok());
        let meta = cache::meta_for("u", 1, None, json);
        c.store(
            &[(GOS_FILE, json), (GOS_SIG_FILE, sig.as_bytes())],
            GOS_FILE,
            &meta,
        )
        .unwrap();
        // Same timestamp is accepted (not older).
        assert!(accept_grapheneos(&c, json, sig).is_ok());
        // A tampered download is rejected and the cached copy stays loadable.
        let mut bad = json.to_vec();
        bad[5] ^= 1;
        assert!(accept_grapheneos(&c, &bad, sig).is_err());
        assert!(c.load_grapheneos().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
