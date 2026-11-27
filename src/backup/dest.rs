// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Backup destinations: a folder (USB stick, PC share, the laptop's own
//! disk) and WebDAV/Nextcloud over Tor. The SimpleGo server is not a
//! destination until its transport (format 8.1) is decided.
//!
//! - A folder holds a marker `.simplego-backup-destination` with the
//!   destination's random id. Without the marker (an unplugged stick, an
//!   empty mount point) the destination is "not connected" and nothing is
//!   written there; a marker with another id is a failure.
//! - WebDAV: `https://` only (`http://` only for a `.onion` host), always
//!   through `tor_socks_proxy` (`socks5h`, a new circuit per request), the
//!   user and app password from a file of their own (mode 0600, outside any
//!   git repository). Only PUT, GET and DELETE; the folder must exist.

use super::state::{Destination, Target};
use crate::activation::store::write_new_private;
use base64ct::{Base64, Encoding};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub const MARKER: &str = ".simplego-backup-destination";
const MAX_FILE: u64 = 256 * 1024 * 1024;

pub trait Remote {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), String>;
    fn get(&self, name: &str) -> Result<Vec<u8>, String>;
    /// Ok(false): the file was not there any more.
    fn delete(&self, name: &str) -> Result<bool, String>;
}

pub enum Reach {
    Ready(Box<dyn Remote>),
    NotConnected(String),
}

fn marker_text(id: &str) -> String {
    format!("simplego-backup-destination v1 {id}\n")
}

/// True if `p` or an ancestor holds `.git`.
pub fn in_repository(p: &Path) -> bool {
    let mut existing = p.to_path_buf();
    while !existing.exists() {
        match existing.parent() {
            Some(x) => existing = x.to_path_buf(),
            None => return false,
        }
    }
    let canon = std::fs::canonicalize(&existing).unwrap_or(existing);
    canon.ancestors().any(|a| a.join(".git").exists())
}

pub struct Folder {
    dir: PathBuf,
}

impl Folder {
    fn file(&self, name: &str) -> Result<PathBuf, String> {
        if !super::container::is_backup_name(name) && !name.starts_with(".sxprov-probe-") {
            return Err(format!("{name:?} is not a backup file name"));
        }
        Ok(self.dir.join(name))
    }
}

fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

impl Remote for Folder {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
        let f = self.file(name)?;
        if std::fs::symlink_metadata(&f).is_ok() {
            return Err(format!("{} exists already", f.display()));
        }
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        write_new_private(&tmp, data)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &f).map_err(|e| format!("cannot rename to {}: {e}", f.display()))?;
        sync_dir(&self.dir);
        Ok(())
    }
    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        let f = self.file(name)?;
        let meta = std::fs::symlink_metadata(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        if !meta.file_type().is_file() || meta.len() > MAX_FILE {
            return Err(format!("{} is not a backup file", f.display()));
        }
        std::fs::read(&f).map_err(|e| format!("cannot read {}: {e}", f.display()))
    }
    fn delete(&self, name: &str) -> Result<bool, String> {
        let f = self.file(name)?;
        match std::fs::remove_file(&f) {
            Ok(()) => {
                sync_dir(&self.dir);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("cannot delete {}: {e}", f.display())),
        }
    }
}

/// Prepares a folder destination: the folder must exist (it is mounted),
/// must not be inside a git repository, and gets the marker. A marker of
/// another destination is refused.
pub fn add_folder(dir: &Path, id: &str, create: bool) -> Result<PathBuf, String> {
    let dir = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(dir)
    };
    if in_repository(&dir) {
        return Err(format!("{} is inside a git repository", dir.display()));
    }
    if create {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    if !dir.is_dir() {
        return Err(format!(
            "{} is not a folder (mount the stick or share first)",
            dir.display()
        ));
    }
    let m = dir.join(MARKER);
    match std::fs::read_to_string(&m) {
        Ok(t) if t == marker_text(id) => Ok(dir),
        Ok(_) => Err(format!(
            "{} belongs to another backup destination; choose another folder",
            m.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_new_private(&m, marker_text(id).as_bytes())
                .map_err(|e| format!("cannot write {}: {e}", m.display()))?;
            Ok(dir)
        }
        Err(e) => Err(format!("cannot read {}: {e}", m.display())),
    }
}

/// Reads the WebDAV credentials file: two lines, user and password.
pub fn read_credentials(p: &Path) -> Result<(String, Zeroizing<String>), String> {
    if in_repository(p) {
        return Err(format!("{} is inside a git repository", p.display()));
    }
    let t = crate::deliver_cmd::read_lines_private(p, 2)?;
    let user = t[0].to_string();
    if user.is_empty() || user.contains(':') || t[1].is_empty() {
        return Err(format!(
            "{}: the first line is the user (no `:`), the second the password",
            p.display()
        ));
    }
    Ok((user, Zeroizing::new(t[1].to_string())))
}

/// Checks a WebDAV folder URL: `https://HOST[:PORT]/PATH/`, or `http://`
/// with a `.onion` host. Returns the host.
pub fn check_url(url: &str) -> Result<String, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("a WebDAV URL starts with https://")?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .to_ascii_lowercase();
    if host.is_empty() || host_port.contains('@') {
        return Err(
            "the URL has no host, or carries a user (put it in the credentials file)".into(),
        );
    }
    match scheme {
        "https" => {}
        "http" if host.ends_with(".onion") => {}
        _ => return Err("WebDAV only over https:// (http:// only for a .onion host)".into()),
    }
    if !url.ends_with('/') || url.contains('?') || url.contains('#') {
        return Err("the WebDAV URL names a folder and ends with `/`, without ? or #".into());
    }
    Ok(host)
}

pub struct WebDav {
    url: String,
    auth: Zeroizing<String>,
    proxy: Option<String>,
    https_only: bool,
}

impl WebDav {
    pub fn new(url: &str, cred: &Path, tor_proxy: &str) -> Result<WebDav, String> {
        // Test builds only: the loopback test server, reached directly.
        #[cfg(test)]
        if url.starts_with("http://127.0.0.1:") {
            let (u, p) = read_credentials(cred)?;
            return Ok(WebDav::loopback_for_tests(url, &u, &p));
        }
        let host = check_url(url)?;
        if crate::config::is_placeholder(tor_proxy) || !tor_proxy.starts_with("socks5h://") {
            return Err("WebDAV needs tor_socks_proxy (socks5h://HOST:PORT) in the config".into());
        }
        let (user, pass) = read_credentials(cred)?;
        let auth = Zeroizing::new(format!(
            "Basic {}",
            Base64::encode_string(format!("{user}:{}", pass.as_str()).as_bytes())
        ));
        Ok(WebDav {
            url: url.to_string(),
            auth,
            proxy: Some(tor_proxy.to_string()),
            https_only: !host.ends_with(".onion"),
        })
    }

    /// Test only: a WebDAV server on loopback, reached directly.
    #[cfg(test)]
    pub fn loopback_for_tests(url: &str, user: &str, pass: &str) -> WebDav {
        assert!(url.starts_with("http://127.0.0.1:"));
        WebDav {
            url: url.into(),
            auth: Zeroizing::new(format!(
                "Basic {}",
                Base64::encode_string(format!("{user}:{pass}").as_bytes())
            )),
            proxy: None,
            https_only: false,
        }
    }

    fn agent(&self) -> Result<ureq::Agent, String> {
        let proxy = match &self.proxy {
            Some(p) => Some(
                ureq::Proxy::new(&crate::tor::isolated_proxy(p)?)
                    .map_err(|e| format!("Tor proxy: {e}"))?,
            ),
            None => None,
        };
        let config = ureq::Agent::config_builder()
            .proxy(proxy)
            .https_only(self.https_only)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(60)))
            .timeout_global(Some(Duration::from_secs(600)))
            .user_agent("sxprov")
            .build();
        Ok(ureq::Agent::new_with_config(config))
    }

    fn target(&self, name: &str) -> Result<String, String> {
        if !super::container::is_backup_name(name) && !name.starts_with(".sxprov-probe-") {
            return Err(format!("{name:?} is not a backup file name"));
        }
        Ok(format!("{}{name}", self.url))
    }
}

fn http_err(what: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            format!("{what}: {io} (is Tor running and reachable at the configured SOCKS proxy?)")
        }
        e => format!("{what}: {e}"),
    }
}

impl Remote for WebDav {
    fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
        let u = self.target(name)?;
        let r = self
            .agent()?
            .put(&u)
            .header("Authorization", self.auth.as_str())
            .header("Content-Type", "application/octet-stream")
            .send(data)
            .map_err(|e| http_err("WebDAV PUT", e))?;
        match r.status().as_u16() {
            200 | 201 | 204 => Ok(()),
            s => Err(format!("WebDAV PUT {name}: HTTP {s}")),
        }
    }
    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        let u = self.target(name)?;
        let r = self
            .agent()?
            .get(&u)
            .header("Authorization", self.auth.as_str())
            .call()
            .map_err(|e| http_err("WebDAV GET", e))?;
        match r.status().as_u16() {
            200 => {}
            s => return Err(format!("WebDAV GET {name}: HTTP {s}")),
        }
        let mut out = Vec::new();
        r.into_body()
            .into_reader()
            .take(MAX_FILE + 1)
            .read_to_end(&mut out)
            .map_err(|e| format!("WebDAV GET {name}: {e}"))?;
        if out.len() as u64 > MAX_FILE {
            return Err(format!("WebDAV GET {name}: too large"));
        }
        Ok(out)
    }
    fn delete(&self, name: &str) -> Result<bool, String> {
        let u = self.target(name)?;
        let r = self
            .agent()?
            .delete(&u)
            .header("Authorization", self.auth.as_str())
            .call()
            .map_err(|e| http_err("WebDAV DELETE", e))?;
        match r.status().as_u16() {
            200 | 202 | 204 => Ok(true),
            404 => Ok(false),
            s => Err(format!("WebDAV DELETE {name}: HTTP {s}")),
        }
    }
}

/// The destination, ready to use, or why it is not connected now.
pub fn open(d: &Destination, tor_proxy: &str) -> Result<Reach, String> {
    match &d.target {
        Target::Folder { path } => {
            if !path.is_dir() {
                return Ok(Reach::NotConnected(format!(
                    "{} is not there (not mounted?)",
                    path.display()
                )));
            }
            match std::fs::read_to_string(path.join(MARKER)) {
                Ok(t) if t == marker_text(&d.id) => {
                    Ok(Reach::Ready(Box::new(Folder { dir: path.clone() })))
                }
                Ok(_) => Err(format!(
                    "{} holds the marker of another destination",
                    path.display()
                )),
                Err(_) => Ok(Reach::NotConnected(format!(
                    "{} has no destination marker (not mounted?)",
                    path.display()
                ))),
            }
        }
        Target::Webdav { url, credentials } => Ok(Reach::Ready(Box::new(WebDav::new(
            url,
            credentials,
            tor_proxy,
        )?))),
    }
}

/// Writes, reads back and deletes a probe file (`destination add`).
pub fn probe(r: &dyn Remote, rng: &mut dyn crate::activation::rng::Rand) -> Result<(), String> {
    let b: [u8; 8] = crate::activation::rng::bytes(rng)?;
    let name = format!(".sxprov-probe-{}", crate::util::hex(&b));
    let data = format!("sxprov probe {}\n", crate::util::hex(&b)).into_bytes();
    r.put(&name, &data)?;
    let back = r.get(&name);
    let del = r.delete(&name);
    if back? != data {
        return Err("the probe file read back differs".into());
    }
    del?;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn urls() {
        assert!(check_url("https://cloud.example.org/remote.php/dav/files/op/backups/").is_ok());
        assert!(check_url(
            "http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab.onion/dav/"
        )
        .is_ok());
        for bad in [
            "http://cloud.example.org/dav/",
            "https://cloud.example.org/dav",
            "https://user@cloud.example.org/dav/",
            "ftp://cloud.example.org/dav/",
            "https:///dav/",
            "https://cloud.example.org/dav/?x=1",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn folder_marker_and_names() {
        let _g = crate::activation::store::tests::one_at_a_time();
        let d = crate::activation::store::tests::temp_dir("dest-folder");
        let stick = d.join("stick");
        assert!(add_folder(&stick, "aa", false).is_err());
        std::fs::create_dir(&stick).unwrap();
        add_folder(&stick, "aa", false).unwrap();
        add_folder(&stick, "aa", false).unwrap();
        assert!(add_folder(&stick, "bb", false)
            .unwrap_err()
            .contains("another"));
        let dest = |id: &str, p: &Path| Destination {
            name: "usb".into(),
            id: id.into(),
            target: Target::Folder { path: p.into() },
            on_laptop: false,
            added_unix: 0,
        };
        let Reach::Ready(r) = open(&dest("aa", &stick), "x").unwrap() else {
            panic!("not ready")
        };
        let n = "bk-20261127T120000Z.bin";
        r.put(n, b"data").unwrap();
        assert!(r.put(n, b"again").is_err());
        assert_eq!(r.get(n).unwrap(), b"data");
        assert!(r.put("../evil", b"x").is_err());
        assert!(r.get("notes.txt").is_err());
        assert!(r.delete(n).unwrap());
        assert!(!r.delete(n).unwrap());
        // Unplugged: not connected, never written; another id: a failure.
        assert!(matches!(
            open(&dest("aa", &d.join("gone")), "x").unwrap(),
            Reach::NotConnected(_)
        ));
        let empty = d.join("empty-mountpoint");
        std::fs::create_dir(&empty).unwrap();
        assert!(matches!(
            open(&dest("aa", &empty), "x").unwrap(),
            Reach::NotConnected(_)
        ));
        assert!(open(&dest("bb", &stick), "x").is_err());
        assert!(add_folder(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("x").as_path(),
            "aa",
            true
        )
        .unwrap_err()
        .contains("git"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A minimal WebDAV server on loopback for the tests: PUT, GET, DELETE
    /// with basic auth; `fail_put` answers 507 to every PUT.
    pub struct TestServer {
        pub url: String,
        pub files: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
        pub fail_put: Arc<Mutex<bool>>,
        pub corrupt_get: Arc<Mutex<bool>>,
        pub requests: Arc<Mutex<Vec<String>>>,
    }

    pub fn serve(user: &str, pass: &str) -> TestServer {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/dav/", l.local_addr().unwrap().port());
        let files = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let fail_put = Arc::new(Mutex::new(false));
        let corrupt_get = Arc::new(Mutex::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let want = format!(
            "Basic {}",
            Base64::encode_string(format!("{user}:{pass}").as_bytes())
        );
        let (f, fp, cg, rq) = (
            files.clone(),
            fail_put.clone(),
            corrupt_get.clone(),
            requests.clone(),
        );
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut rd = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let parts: Vec<String> = line.split_whitespace().map(String::from).collect();
                let (mut len, mut auth) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap_or(("", ""));
                    match k.to_ascii_lowercase().as_str() {
                        "content-length" => len = v.trim().parse().unwrap_or(0),
                        "authorization" => auth = v.trim().to_string(),
                        _ => {}
                    }
                }
                let mut body = vec![0u8; len];
                let _ = rd.read_exact(&mut body);
                let (m, path) = (parts[0].clone(), parts[1].clone());
                rq.lock().unwrap().push(format!("{m} {path}"));
                let name = path.trim_start_matches("/dav/").to_string();
                let (status, out): (&str, Vec<u8>) = if auth != want {
                    ("401 Unauthorized", vec![])
                } else {
                    match m.as_str() {
                        "PUT" if *fp.lock().unwrap() => ("507 Insufficient Storage", vec![]),
                        "PUT" => {
                            f.lock().unwrap().insert(name, body);
                            ("201 Created", vec![])
                        }
                        "GET" => match f.lock().unwrap().get(&name) {
                            Some(d) => {
                                let mut d = d.clone();
                                if *cg.lock().unwrap() && !d.is_empty() {
                                    let n = d.len() - 1;
                                    d[n] ^= 1;
                                }
                                ("200 OK", d)
                            }
                            None => ("404 Not Found", vec![]),
                        },
                        "DELETE" => match f.lock().unwrap().remove(&name) {
                            Some(_) => ("204 No Content", vec![]),
                            None => ("404 Not Found", vec![]),
                        },
                        _ => ("405 Method Not Allowed", vec![]),
                    }
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    out.len()
                );
                let _ = s.write_all(&out);
            }
        });
        TestServer {
            url,
            files,
            fail_put,
            corrupt_get,
            requests,
        }
    }

    #[test]
    fn webdav_round_trip_on_loopback() {
        let srv = serve("op", "TEST-ONLY app password");
        let w = WebDav::loopback_for_tests(&srv.url, "op", "TEST-ONLY app password");
        let n = "bk-20261127T120000Z.bin";
        w.put(n, b"backup bytes").unwrap();
        assert_eq!(w.get(n).unwrap(), b"backup bytes");
        probe(&w, &mut crate::activation::rng::SeededRand::new(b"p")).unwrap();
        assert!(w.delete(n).unwrap());
        assert!(!w.delete(n).unwrap());
        assert!(w.get(n).unwrap_err().contains("404"));
        let bad = WebDav::loopback_for_tests(&srv.url, "op", "wrong");
        assert!(bad.put(n, b"x").unwrap_err().contains("401"));
        *srv.fail_put.lock().unwrap() = true;
        assert!(w.put(n, b"x").unwrap_err().contains("507"));
        assert!(w.put("../x", b"x").is_err());
        let r = srv.requests.lock().unwrap();
        assert!(
            r.iter()
                .all(|l| ["PUT ", "GET ", "DELETE "].iter().any(|m| l.starts_with(m))),
            "{r:?}"
        );
    }

    #[test]
    fn webdav_credentials_and_proxy() {
        let _g = crate::activation::store::tests::one_at_a_time();
        let d = crate::activation::store::tests::temp_dir("dest-cred");
        let c = d.join("cred");
        crate::activation::store::write_new_private(&c, b"op\nTEST-ONLY app password\n").unwrap();
        let u = "https://cloud.example.org/dav/";
        assert!(WebDav::new(u, &c, "socks5h://127.0.0.1:9050").is_ok());
        assert!(WebDav::new(u, &c, "REPLACE_WITH_PROXY").is_err());
        assert!(WebDav::new(
            "http://cloud.example.org/dav/",
            &c,
            "socks5h://127.0.0.1:9050"
        )
        .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(WebDav::new(u, &c, "socks5h://127.0.0.1:9050").is_err());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
