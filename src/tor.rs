// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Every download over Tor: HTTPS through the configured `socks5h` proxy
//! only, no redirects, no clearnet fallback.
//!
//! No total time limit (a factory image is 2 GB), but an idle limit: when no
//! byte arrives for `download_idle_timeout_secs`, that attempt is given up
//! and the download continues on a new Tor circuit (a new SOCKS username and
//! password: Tor isolates streams by them) with `Range: bytes=OFFSET-`, at
//! most `ATTEMPTS` attempts in all; then it fails with a clear message. A
//! request that gets no answer (connect or response timeout) is tried again
//! the same way.

use crate::grapheneos::{Http, HttpResp};
use std::io::{self, Read};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::time::Duration;

/// Attempts per download (the first and two on new circuits).
pub const ATTEMPTS: u32 = 3;
/// Marks the error of a download given up after `ATTEMPTS` stalls, so a
/// caller with its own retries (the factory image) does not try again.
pub const STALLED: &str = "stalled over Tor";

/// The error a stalled read gives (no byte for the idle limit).
#[derive(Debug)]
struct IdleStall;

impl std::fmt::Display for IdleStall {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "no byte received within the idle limit")
    }
}

impl std::error::Error for IdleStall {}

fn is_stall(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<IdleStall>())
}

/// Reads `inner` on its own thread and gives up when no byte arrives for
/// `idle`. A stalled thread stays blocked on its socket until the process
/// ends or the peer closes it; it holds no data and no lock.
pub struct IdleReader {
    rx: Receiver<io::Result<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
    idle: Duration,
    done: bool,
}

impl IdleReader {
    pub fn new(mut inner: Box<dyn Read + Send>, idle: Duration) -> IdleReader {
        let (tx, rx) = sync_channel::<io::Result<Vec<u8>>>(4);
        std::thread::spawn(move || {
            let mut b = vec![0u8; 64 * 1024];
            loop {
                match inner.read(&mut b) {
                    Ok(0) => {
                        let _ = tx.send(Ok(Vec::new()));
                        break;
                    }
                    Ok(n) => {
                        if tx.send(Ok(b[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });
        IdleReader {
            rx,
            buf: Vec::new(),
            pos: 0,
            idle,
            done: false,
        }
    }
}

impl Read for IdleReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv_timeout(self.idle) {
                Ok(Ok(v)) if v.is_empty() => {
                    self.done = true;
                    return Ok(0);
                }
                Ok(Ok(v)) => {
                    self.buf = v;
                    self.pos = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, IdleStall))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("the download's reader ended"))
                }
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// One answer of a (re)opened download.
pub struct Opened {
    pub status: u16,
    /// The start of `Content-Range`, for a 206.
    pub range_start: Option<u64>,
    pub body: Box<dyn Read + Send>,
}

/// Opens the download again at a byte offset, on a new circuit.
pub type Opener = Box<dyn FnMut(u64) -> Result<Opened, String> + Send>;

/// A body that continues on a new circuit after a stall.
pub struct ResumingBody {
    url: String,
    open: Opener,
    cur: IdleReader,
    offset: u64,
    attempts: u32,
    idle: Duration,
}

impl ResumingBody {
    /// `body` is the first attempt's body, which starts at byte `from`.
    pub fn new(
        url: &str,
        from: u64,
        body: Box<dyn Read + Send>,
        idle: Duration,
        open: Opener,
    ) -> ResumingBody {
        ResumingBody {
            url: url.to_string(),
            open,
            cur: IdleReader::new(body, idle),
            offset: from,
            attempts: 1,
            idle,
        }
    }
}

impl Read for ResumingBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.cur.read(out) {
                Ok(n) => {
                    self.offset += n as u64;
                    return Ok(n);
                }
                Err(e) if is_stall(&e) => {
                    if self.attempts >= ATTEMPTS {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "{}: {STALLED}: no byte received for {} s, {ATTEMPTS} attempts, each on a new Tor circuit; giving up at byte {}",
                                self.url,
                                self.idle.as_secs(),
                                self.offset
                            ),
                        ));
                    }
                    self.attempts += 1;
                    let o = (self.open)(self.offset).map_err(|e| {
                        io::Error::other(format!(
                            "{}: stalled at byte {}; attempt {} on a new Tor circuit failed: {e}",
                            self.url, self.offset, self.attempts
                        ))
                    })?;
                    let resumed = (o.status == 206 && o.range_start == Some(self.offset))
                        || (o.status == 200 && self.offset == 0);
                    if !resumed {
                        return Err(io::Error::other(format!(
                            "{}: stalled at byte {}; the server did not resume there (HTTP {}, range {:?})",
                            self.url, self.offset, o.status, o.range_start
                        )));
                    }
                    self.cur = IdleReader::new(o.body, self.idle);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// A `socks5h` proxy URL with a fresh random username and password, so that
/// Tor puts the connection on a circuit of its own.
pub fn isolated_proxy(base: &str) -> Result<String, String> {
    let rest = base
        .strip_prefix("socks5h://")
        .ok_or("Tor proxy must be socks5h://")?;
    let rest = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
    let mut r = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut r)
        .map_err(|_| "no system randomness")?;
    let h = crate::util::hex(&r);
    Ok(format!("socks5h://sxprov-{}:{}@{rest}", &h[..16], &h[16..]))
}

/// HTTPS through the Tor SOCKS proxy only (`socks5h`, no clearnet, no
/// redirects), with the idle limit and the new-circuit attempts above.
#[derive(Clone)]
pub struct TorHttp {
    proxy: String,
    connect_timeout: Duration,
    idle: Duration,
}

impl TorHttp {
    pub fn new(
        proxy_url: &str,
        connect_timeout: Duration,
        idle: Duration,
    ) -> Result<TorHttp, String> {
        if crate::config::is_placeholder(proxy_url) {
            return Err(format!(
                "tor_socks_proxy is still the placeholder {proxy_url:?}; enter the Tor SOCKS proxy (socks5h://HOST:PORT) in the config first. Nothing was downloaded."
            ));
        }
        if !proxy_url.starts_with("socks5h://") {
            return Err("Tor proxy must be socks5h://".into());
        }
        ureq::Proxy::new(proxy_url).map_err(|e| format!("Tor proxy {proxy_url}: {e}"))?;
        Ok(TorHttp {
            proxy: proxy_url.to_string(),
            connect_timeout,
            idle,
        })
    }

    /// An agent on a new circuit.
    fn agent(&self) -> Result<ureq::Agent, String> {
        let url = isolated_proxy(&self.proxy)?;
        let proxy = ureq::Proxy::new(&url).map_err(|e| format!("Tor proxy: {e}"))?;
        let config = ureq::Agent::config_builder()
            .proxy(Some(proxy))
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(self.connect_timeout))
            .timeout_recv_response(Some(Duration::from_secs(180)))
            .user_agent("sxprov")
            .build();
        Ok(ureq::Agent::new_with_config(config))
    }

    /// One request on a new circuit; requests without an answer are tried
    /// again on new circuits, at most `ATTEMPTS` times.
    fn request(&self, url: &str, from: u64) -> Result<ureq::http::Response<ureq::Body>, String> {
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            let agent = self.agent()?;
            let mut req = agent.get(url);
            if from > 0 {
                req = req.header("Range", &format!("bytes={from}-"));
            }
            match req.call() {
                Ok(r) => return Ok(r),
                Err(ureq::Error::Io(io)) if io.kind() == io::ErrorKind::ConnectionRefused => {
                    return Err(format!(
                        "{url}: {io} (is Tor running and reachable at the configured SOCKS proxy?)"
                    ))
                }
                Err(e @ (ureq::Error::Timeout(_) | ureq::Error::Io(_))) => {
                    last =
                        format!("{e} (attempt {attempt} of {ATTEMPTS}, each on a new Tor circuit)");
                }
                Err(other) => return Err(format!("{url}: {other}")),
            }
        }
        Err(format!("{url}: no answer: {last}"))
    }
}

fn header(resp: &ureq::http::Response<ureq::Body>, k: &str) -> Option<String> {
    resp.headers()
        .get(k)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn into_body(resp: ureq::http::Response<ureq::Body>) -> Box<dyn Read + Send> {
    Box::new(resp.into_body().into_with_config().limit(u64::MAX).reader())
}

impl Http for TorHttp {
    fn get(&self, url: &str, from: u64) -> Result<HttpResp, String> {
        let resp = self.request(url, from)?;
        let status = resp.status().as_u16();
        let content_length = header(&resp, "content-length").and_then(|v| v.trim().parse().ok());
        let range =
            header(&resp, "content-range").and_then(|v| crate::grapheneos::parse_content_range(&v));
        let last_modified = header(&resp, "last-modified");
        let first = into_body(resp);
        let body: Box<dyn Read> = if status == 200 || status == 206 {
            let me = self.clone();
            let u = url.to_string();
            let open: Opener = Box::new(move |offset| {
                let r = me.request(&u, offset)?;
                let status = r.status().as_u16();
                let range_start = header(&r, "content-range")
                    .and_then(|v| crate::grapheneos::parse_content_range(&v))
                    .map(|(s, _)| s);
                Ok(Opened {
                    status,
                    range_start,
                    body: into_body(r),
                })
            });
            Box::new(ResumingBody::new(url, from, first, self.idle, open))
        } else {
            Box::new(IdleReader::new(first, self.idle))
        };
        Ok(HttpResp {
            status,
            content_length,
            range,
            last_modified,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    const IDLE: Duration = Duration::from_millis(300);

    /// A fake server: for each connection, the client writes the offset it
    /// wants as one line; `plan(n, offset)` says what the n-th connection
    /// sends: a number of bytes of `DATA` from the offset, then whether it
    /// stalls (keeps the connection open, silent) or closes.
    const DATA: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    fn server(plan: fn(usize) -> (usize, bool)) -> (u16, Arc<Mutex<Vec<u64>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for (n, c) in l.incoming().enumerate() {
                let mut c = c.unwrap();
                let mut line = Vec::new();
                let mut b = [0u8; 1];
                while c.read(&mut b).unwrap_or(0) == 1 && b[0] != b'\n' {
                    line.push(b[0]);
                }
                let off: usize = String::from_utf8(line).unwrap().parse().unwrap();
                s2.lock().unwrap().push(off as u64);
                let (count, stall) = plan(n);
                let end = (off + count).min(DATA.len());
                c.write_all(&DATA[off..end]).unwrap();
                c.flush().unwrap();
                if stall {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(30));
                        drop(c);
                    });
                }
            }
        });
        (port, seen)
    }

    fn connect(port: u16, offset: u64) -> Box<dyn Read + Send> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        writeln!(s, "{offset}").unwrap();
        Box::new(s)
    }

    fn opener(port: u16, circuits: Arc<Mutex<Vec<String>>>) -> Opener {
        Box::new(move |offset| {
            circuits
                .lock()
                .unwrap()
                .push(isolated_proxy("socks5h://127.0.0.1:9050").unwrap());
            Ok(Opened {
                status: 206,
                range_start: Some(offset),
                body: connect(port, offset),
            })
        })
    }

    #[test]
    fn idle_reader_gives_up_on_a_stalled_body() {
        // 10 bytes, then silence.
        let (port, _) = server(|_| (10, true));
        let mut r = IdleReader::new(connect(port, 0), IDLE);
        let mut got = [0u8; 64];
        let mut n = 0;
        let err = loop {
            match r.read(&mut got[n..]) {
                Ok(k) => n += k,
                Err(e) => break e,
            }
        };
        assert_eq!(&got[..n], &DATA[..10]);
        assert!(is_stall(&err), "{err}");
    }

    #[test]
    fn a_stall_mid_body_continues_on_a_new_circuit() {
        // The first connection stalls after 10 bytes, the second after 20
        // more, the third sends the rest and closes.
        let (port, seen) = server(|n| match n {
            0 => (10, true),
            1 => (20, true),
            _ => (usize::MAX / 2, false),
        });
        let circuits = Arc::new(Mutex::new(Vec::new()));
        let mut b = ResumingBody::new(
            "https://x.example/f",
            0,
            connect(port, 0),
            IDLE,
            opener(port, circuits.clone()),
        );
        let mut v = Vec::new();
        b.read_to_end(&mut v).unwrap();
        assert_eq!(v, DATA);
        assert_eq!(*seen.lock().unwrap(), vec![0, 10, 30]);
        let c = circuits.lock().unwrap();
        assert_eq!(c.len(), 2);
        assert_ne!(c[0], c[1], "each attempt has its own SOCKS credentials");
    }

    #[test]
    fn three_stalls_fail_with_a_clear_message() {
        let (port, seen) = server(|_| (5, true));
        let circuits = Arc::new(Mutex::new(Vec::new()));
        let mut b = ResumingBody::new(
            "https://x.example/f",
            0,
            connect(port, 0),
            IDLE,
            opener(port, circuits.clone()),
        );
        let mut v = Vec::new();
        let e = b.read_to_end(&mut v).unwrap_err();
        let m = e.to_string();
        assert!(m.contains(STALLED), "{m}");
        assert!(m.contains("3 attempts, each on a new Tor circuit"), "{m}");
        assert!(m.contains("giving up at byte 15"), "{m}");
        assert_eq!(*seen.lock().unwrap(), vec![0, 5, 10]);
        assert_eq!(v, &DATA[..15]);
    }

    #[test]
    fn a_server_that_cannot_resume_is_named() {
        let (port, _) = server(|n| if n == 0 { (10, true) } else { (5, false) });
        let open: Opener = Box::new(move |offset| {
            Ok(Opened {
                status: 200,
                range_start: None,
                body: connect(port, offset),
            })
        });
        let mut b = ResumingBody::new("https://x.example/f", 0, connect(port, 0), IDLE, open);
        let e = b.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(
            e.to_string().contains("the server did not resume there"),
            "{e}"
        );
    }

    #[test]
    fn isolated_proxy_urls() {
        let a = isolated_proxy("socks5h://127.0.0.1:9150").unwrap();
        let b = isolated_proxy("socks5h://127.0.0.1:9150").unwrap();
        assert_ne!(a, b);
        assert!(
            a.starts_with("socks5h://sxprov-") && a.ends_with("@127.0.0.1:9150"),
            "{a}"
        );
        let p = ureq::Proxy::new(&a).unwrap();
        assert!(p.username().is_some_and(|u| u.starts_with("sxprov-")));
        assert!(p.password().is_some_and(|x| x.len() == 16));
        // Credentials in the configured URL are replaced, not added.
        let c = isolated_proxy("socks5h://u:p@127.0.0.1:9050").unwrap();
        assert!(c.ends_with("@127.0.0.1:9050") && !c.contains("u:p"), "{c}");
        assert!(isolated_proxy("socks5://127.0.0.1:9050").is_err());
    }

    #[test]
    fn tor_http_takes_only_socks5h() {
        let d = Duration::from_secs(1);
        assert!(TorHttp::new("socks5://127.0.0.1:9050", d, d).is_err());
        assert!(TorHttp::new("http://127.0.0.1:8118", d, d).is_err());
        assert!(TorHttp::new("REPLACE_WITH_GATEWAY_SOCKS", d, d).is_err());
        assert!(TorHttp::new("socks5h://127.0.0.1:9050", d, d).is_ok());
    }
}
