// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Factory images in the cache: `<cache>/<VERSION>/<codename>-install-<VERSION>.zip`
//! with its `.sig` and, once the signature is checked, `.verified.json`
//! (SHA-256, size, time, source). A download goes to `.zip.part` first and
//! resumes from there (HTTP Range); a broken transfer is retried and can be
//! resumed by running the command again. Only verified images keep their
//! final name: a failed signature deletes the zip and its signature.

use super::{read_small, valid_codename, valid_version, Http, FACTORY_NAMESPACE};
use crate::trust::lists::GRAPHENEOS_PRINCIPAL;
use crate::trust::sshsig;
use crate::util::{fmt_unix, hex};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    pub codename: String,
    pub version: String,
    pub file: String,
    pub size: u64,
    pub sha256: String,
    pub sig_sha256: String,
    pub verified_at: String,
    pub source: String,
}

pub struct ImageCache {
    pub root: PathBuf,
}

pub fn top_folder(codename: &str, version: &str) -> String {
    format!("{codename}-install-{version}")
}

impl ImageCache {
    pub fn dir(&self, version: &str) -> PathBuf {
        self.root.join(version)
    }
    pub fn zip(&self, codename: &str, version: &str) -> PathBuf {
        self.dir(version)
            .join(format!("{}.zip", top_folder(codename, version)))
    }
    fn with(p: &Path, suffix: &str) -> PathBuf {
        let mut s = p.as_os_str().to_os_string();
        s.push(suffix);
        PathBuf::from(s)
    }
    pub fn sig(&self, codename: &str, version: &str) -> PathBuf {
        Self::with(&self.zip(codename, version), ".sig")
    }
    fn part(&self, codename: &str, version: &str) -> PathBuf {
        Self::with(&self.zip(codename, version), ".part")
    }
    fn record(&self, codename: &str, version: &str) -> PathBuf {
        Self::with(&self.zip(codename, version), ".verified.json")
    }

    /// The record of a verified image whose file is still there with the
    /// recorded size.
    pub fn verified(&self, codename: &str, version: &str) -> Option<Verified> {
        let r: Verified =
            serde_json::from_slice(&std::fs::read(self.record(codename, version)).ok()?).ok()?;
        let len = std::fs::metadata(self.zip(codename, version)).ok()?.len();
        (len == r.size && r.codename == codename && r.version == version).then_some(r)
    }
}

/// Checks `zip` against `sig` with the pinned key; returns (SHA-256, size).
pub fn verify_file(zip: &Path, sig: &Path, signers_text: &str) -> Result<(String, u64), String> {
    let signers = sshsig::parse_allowed_signers(signers_text)?;
    let sig_text =
        std::fs::read_to_string(sig).map_err(|e| format!("cannot read {}: {e}", sig.display()))?;
    let f = std::fs::File::open(zip).map_err(|e| format!("cannot open {}: {e}", zip.display()))?;
    let mut r = std::io::BufReader::with_capacity(1 << 20, f);
    let mut sha = ring::digest::Context::new(&ring::digest::SHA256);
    let mut n = 0u64;
    sshsig::verify_reader(
        &signers,
        GRAPHENEOS_PRINCIPAL,
        FACTORY_NAMESPACE,
        &mut r,
        &sig_text,
        &mut |c| {
            sha.update(c);
            n += c.len() as u64;
        },
    )?;
    Ok((hex(sha.finish().as_ref()), n))
}

fn private_dir(d: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(d)
        .map_err(|e| format!("cannot create {}: {e}", d.display()))
}

/// One download attempt into `part`, resuming at its current length.
fn download_once(
    http: &dyn Http,
    url: &str,
    part: &Path,
    log: &mut dyn FnMut(&str),
) -> Result<u64, String> {
    let have = std::fs::metadata(part).map(|m| m.len()).unwrap_or(0);
    let mut r = http.get(url, have)?;
    let (mut f, start, total) = match r.status {
        206 => {
            let (start, total) = r.range.ok_or(format!("{url}: 206 without Content-Range"))?;
            if start != have {
                return Err(format!(
                    "{url}: the server resumed at {start}, not at {have}"
                ));
            }
            let f = std::fs::OpenOptions::new()
                .append(true)
                .open(part)
                .map_err(|e| format!("cannot open {}: {e}", part.display()))?;
            (f, have, total)
        }
        200 => {
            if have > 0 {
                log(&format!(
                    "  the server sent the whole file; restarting from 0 (had {have} bytes)"
                ));
            }
            let f = std::fs::File::create(part)
                .map_err(|e| format!("cannot create {}: {e}", part.display()))?;
            (f, 0, r.content_length)
        }
        416 if have > 0 => {
            // Range beyond the file: the part is complete or stale; start over.
            let _ = std::fs::remove_file(part);
            return Err(format!(
                "{url}: range not satisfiable; the partial file was removed"
            ));
        }
        404 => {
            return Err(format!(
                "{url}: not found (HTTP 404); is the version right?"
            ))
        }
        s => return Err(format!("{url}: HTTP {s}")),
    };
    let mut buf = vec![0u8; 1 << 20];
    let mut done = start;
    let mut next_note = start + (256 << 20);
    loop {
        let n = match r.body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = f.flush();
                return Err(format!("download broken at {done} bytes: {e}"));
            }
        };
        f.write_all(&buf[..n])
            .map_err(|e| format!("cannot write {}: {e}", part.display()))?;
        done += n as u64;
        if done >= next_note {
            log(&format!(
                "  {} MB{}",
                done >> 20,
                total
                    .map(|t| format!(" of {} MB", t >> 20))
                    .unwrap_or_default()
            ));
            next_note += 256 << 20;
        }
    }
    f.sync_all()
        .map_err(|e| format!("cannot write {}: {e}", part.display()))?;
    if let Some(t) = total {
        if done != t {
            return Err(format!("download broken at {done} of {t} bytes"));
        }
    }
    Ok(done)
}

/// Downloads (if needed) and verifies `<codename>-install-<version>.zip`.
#[allow(clippy::too_many_arguments)]
pub fn fetch(
    cache: &ImageCache,
    http: &dyn Http,
    base: &str,
    codename: &str,
    version: &str,
    signers_text: &str,
    // Read once, right after the signature check: the `verified` time.
    now: &dyn Fn() -> u64,
    log: &mut dyn FnMut(&str),
) -> Result<Verified, String> {
    if !valid_codename(codename) || !valid_version(version) {
        return Err(format!(
            "invalid codename or version {codename:?} {version:?}"
        ));
    }
    if let Some(v) = cache.verified(codename, version) {
        log(&format!(
            "  already verified: {} (SHA-256 {}, verified {})",
            v.file, v.sha256, v.verified_at
        ));
        return Ok(v);
    }
    let zip = cache.zip(codename, version);
    let sig = cache.sig(codename, version);
    let part = cache.part(codename, version);
    private_dir(&cache.dir(version))?;
    let name = format!("{}.zip", top_folder(codename, version));
    let url = format!("{base}/{name}");
    let sig_url = format!("{url}.sig");
    // The signature first: small, and it fails fast for a wrong version.
    let mut r = http.get(&sig_url, 0)?;
    if r.status != 200 {
        return Err(format!("{sig_url}: HTTP {}", r.status));
    }
    let sig_body = read_small(&mut r, 64 * 1024, &sig_url)?;
    std::fs::write(&sig, &sig_body).map_err(|e| format!("cannot write {}: {e}", sig.display()))?;
    log(&format!("  signature {sig_url} ({} bytes)", sig_body.len()));
    if zip.is_file() {
        log(&format!(
            "  {} is present but not verified yet; checking it",
            zip.display()
        ));
    } else {
        log(&format!("  downloading {url} over Tor"));
        let mut last = String::new();
        let mut ok = false;
        for i in 1..=ATTEMPTS {
            match download_once(http, &url, &part, log) {
                Ok(n) => {
                    log(&format!("  downloaded {n} bytes"));
                    ok = true;
                    break;
                }
                Err(e) => {
                    log(&format!("  attempt {i} of {ATTEMPTS}: {e}"));
                    // A stall already had its attempts on new Tor circuits.
                    let stalled = e.contains(crate::tor::STALLED);
                    last = e;
                    if stalled {
                        break;
                    }
                }
            }
        }
        if !ok {
            return Err(format!(
                "{last}. The partial file is kept; run the same command again to resume"
            ));
        }
        std::fs::rename(&part, &zip)
            .map_err(|e| format!("cannot rename {}: {e}", part.display()))?;
    }
    log("  checking the signature (namespace \"factory images\", contact@grapheneos.org, pinned key)");
    let (sha256, size) = match verify_file(&zip, &sig, signers_text) {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(&zip);
            let _ = std::fs::remove_file(&sig);
            return Err(format!(
                "SIGNATURE CHECK FAILED for {name}: {e}. The file and its signature were deleted; nothing is flashed from it"
            ));
        }
    };
    let v = Verified {
        codename: codename.into(),
        version: version.into(),
        file: zip.display().to_string(),
        size,
        sha256,
        sig_sha256: hex(&crate::util::sha256(&sig_body)),
        verified_at: fmt_unix(now()),
        source: url,
    };
    std::fs::write(
        cache.record(codename, version),
        serde_json::to_vec_pretty(&v).unwrap_or_default(),
    )
    .map_err(|e| format!("cannot write the verification record: {e}"))?;
    log(&format!(
        "  Good \"factory images\" signature; SHA-256 {}",
        v.sha256
    ));
    Ok(v)
}

#[cfg(test)]
pub mod tests {
    use super::super::testhttp::FakeHttp;
    use super::*;

    pub const BASE: &str = "https://releases.grapheneos.org";
    pub const SEED: [u8; 32] = [9; 32];

    /// A signed synthetic image and the allowed_signers text that trusts it.
    pub fn signed(data: &[u8]) -> (String, String) {
        crate::trust::sshsig::sign_for_tests(&SEED, GRAPHENEOS_PRINCIPAL, FACTORY_NAMESPACE, data)
    }

    #[test]
    fn download_resume_verify_and_refuse() {
        let d = crate::activation::store::tests::temp_dir("image");
        let cache = ImageCache { root: d.clone() };
        let data: Vec<u8> = (0..5_000_000u32).map(|i| (i % 253) as u8).collect();
        let (signers, sig) = signed(&data);
        let h = FakeHttp::default();
        let url = format!("{BASE}/bluejay-install-2026111801.zip");
        h.put(&url, &data);
        h.put(&format!("{url}.sig"), sig.as_bytes());
        // The first two transfers break; the third resumes and completes.
        h.break_after
            .borrow_mut()
            .insert(url.clone(), vec![1_000_000, 1_500_000]);
        let mut log = Vec::new();
        let v = fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026111801",
            &signers,
            &|| 1,
            &mut |l| log.push(l.to_string()),
        )
        .unwrap();
        assert_eq!(v.size, 5_000_000);
        assert_eq!(v.sha256, hex(&crate::util::sha256(&data)));
        assert_eq!(
            std::fs::read(cache.zip("bluejay", "2026111801")).unwrap(),
            data
        );
        let gets: Vec<String> = h
            .urls()
            .into_iter()
            .filter(|u| u.contains(".zip from"))
            .collect();
        assert_eq!(
            gets,
            vec![
                format!("GET {url} from 0"),
                format!("GET {url} from 1000000"),
                format!("GET {url} from 2500000"),
            ]
        );
        // Every URL is on the release host.
        assert!(h
            .urls()
            .iter()
            .all(|u| u.starts_with(&format!("GET {BASE}/"))));
        // Second run: nothing downloaded again.
        let n = h.urls().len();
        fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026111801",
            &signers,
            &|| 2,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(h.urls().len(), n);
        // A server without ranges: restart from 0 cleanly.
        let url2 = format!("{BASE}/bluejay-install-2026111800.zip");
        h.put(&url2, &data);
        h.put(&format!("{url2}.sig"), sig.as_bytes());
        *h.no_ranges.borrow_mut() = true;
        h.break_after
            .borrow_mut()
            .insert(url2.clone(), vec![2_000_000]);
        fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026111800",
            &signers,
            &|| 3,
            &mut |_| {},
        )
        .unwrap();
        *h.no_ranges.borrow_mut() = false;
        // A tampered image: refused, deleted, no record.
        let mut bad = data.clone();
        bad[4_999_999] ^= 1;
        let url3 = format!("{BASE}/bluejay-install-2026112000.zip");
        h.put(&url3, &bad);
        h.put(&format!("{url3}.sig"), sig.as_bytes());
        let e = fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026112000",
            &signers,
            &|| 4,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.contains("SIGNATURE CHECK FAILED"), "{e}");
        assert!(!cache.zip("bluejay", "2026112000").exists());
        assert!(!cache.sig("bluejay", "2026112000").exists());
        assert!(cache.verified("bluejay", "2026112000").is_none());
        // Signed by another key (the real pinned key does not trust it).
        let url4 = format!("{BASE}/bluejay-install-2026112100.zip");
        h.put(&url4, &data);
        h.put(&format!("{url4}.sig"), sig.as_bytes());
        let pinned = crate::trust::lists::GRAPHENEOS_ALLOWED_SIGNERS;
        assert!(fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026112100",
            pinned,
            &|| 5,
            &mut |_| {}
        )
        .is_err());
        assert!(!cache.zip("bluejay", "2026112100").exists());
        // A missing version: 404 on the signature, nothing written.
        assert!(fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026010100",
            &signers,
            &|| 6,
            &mut |_| {}
        )
        .unwrap_err()
        .contains("404"));
        // Broken every time: the partial file is kept for the next run.
        let url5 = format!("{BASE}/bluejay-install-2026112200.zip");
        h.put(&url5, &data);
        h.put(&format!("{url5}.sig"), sig.as_bytes());
        h.break_after
            .borrow_mut()
            .insert(url5.clone(), vec![100; 5]);
        let e = fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026112200",
            &signers,
            &|| 7,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.contains("run the same command again"), "{e}");
        assert!(cache.part("bluejay", "2026112200").exists());
        let v = fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026112200",
            &signers,
            &|| 8,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(v.size, 5_000_000);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn verified_time_is_the_time_of_the_check() {
        let d = crate::activation::store::tests::temp_dir("image-verified-time");
        let cache = ImageCache { root: d.clone() };
        let data = b"an image checked after its download".to_vec();
        let (signers, sig) = signed(&data);
        let h = FakeHttp::default();
        let url = format!("{BASE}/bluejay-install-2026111801.zip");
        h.put(&url, &data);
        h.put(&format!("{url}.sig"), sig.as_bytes());
        let zip = cache.zip("bluejay", "2026111801");
        let calls = std::cell::Cell::new(0u32);
        // The clock answers 1000 before the image is complete on disk and
        // 2000 after: the record must carry 2000.
        let clock = || {
            calls.set(calls.get() + 1);
            if zip.is_file() {
                2000
            } else {
                1000
            }
        };
        let v = fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026111801",
            &signers,
            &clock,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(v.verified_at, fmt_unix(2000));
        assert_eq!(calls.get(), 1);
        assert_eq!(
            cache.verified("bluejay", "2026111801").unwrap().verified_at,
            fmt_unix(2000)
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn present_but_unverified_image_is_checked_not_downloaded() {
        let d = crate::activation::store::tests::temp_dir("image-present");
        let cache = ImageCache { root: d.clone() };
        let data = b"a small image".to_vec();
        let (signers, sig) = signed(&data);
        std::fs::create_dir_all(cache.dir("2026111800")).unwrap();
        std::fs::write(cache.zip("bluejay", "2026111800"), &data).unwrap();
        let h = FakeHttp::default();
        h.put(
            &format!("{BASE}/bluejay-install-2026111800.zip.sig"),
            sig.as_bytes(),
        );
        fetch(
            &cache,
            &h,
            BASE,
            "bluejay",
            "2026111800",
            &signers,
            &|| 1,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(h.urls().len(), 1, "only the signature was fetched");
        assert!(cache.verified("bluejay", "2026111800").is_some());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
