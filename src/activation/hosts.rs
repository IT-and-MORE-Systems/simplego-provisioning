// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Server and support addresses and the network mode host rules
//! (format document section 7, amended 2026-11-19 23:10).

use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Onion,
    Clearnet,
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[cfg(test)]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in data {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B32.iter().position(|x| *x == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Checksum of a v3 onion name: first 2 bytes of
/// SHA3-256(".onion checksum" || public key || version).
pub fn onion_checksum(public: &[u8; 32], version: u8) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(public);
    h.update([version]);
    let d = h.finalize();
    [d[0], d[1]]
}

/// The v3 onion host for a 32-byte public key.
#[cfg(test)]
pub fn onion_from_public(public: &[u8; 32]) -> String {
    let mut raw = public.to_vec();
    raw.extend_from_slice(&onion_checksum(public, 3));
    raw.push(3);
    format!("{}.onion", base32_encode(&raw))
}

/// A v3 onion name: 56 base32 characters plus `.onion`, decoding to a public
/// key, the checksum and the version byte 0x03. Case-insensitive, like DNS.
pub fn is_valid_onion_v3(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let Some(label) = lower.strip_suffix(".onion") else {
        return false;
    };
    if label.len() != 56 {
        return false;
    }
    let Some(raw) = base32_decode(label) else {
        return false;
    };
    if raw.len() != 35 || raw[34] != 3 {
        return false;
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&raw[..32]);
    raw[32..34] == onion_checksum(&public, 3)
}

/// Onion or clearnet. A host ending in `.onion` that is not a valid v3 name
/// is refused; it never counts as a clearnet host. Onion names must be lower
/// case: simplexmq `Transport/Client.hs` `StrEncoding TransportHost` reads
/// an onion host only from `a-z 0-9` and refuses any other `.onion` host.
pub fn classify(host: &str) -> Result<HostKind, String> {
    if host.is_empty() {
        return Err("empty host".into());
    }
    if !host
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        return Err(format!(
            "host {:?} has an invalid character",
            mask_host(host)
        ));
    }
    if host.to_ascii_lowercase().ends_with(".onion") {
        if host.bytes().any(|c| c.is_ascii_uppercase()) {
            Err(format!(
                "{} is not accepted: onion names must be lower case",
                mask_host(&host.to_ascii_lowercase())
            ))
        } else if is_valid_onion_v3(host) {
            Ok(HostKind::Onion)
        } else {
            Err(format!("{} is not a valid v3 onion name", mask_host(host)))
        }
    } else {
        Ok(HostKind::Clearnet)
    }
}

/// A parsed `smp://` or `xftp://` server address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress {
    pub scheme: String,
    pub fingerprint: String,
    pub password: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<u16>,
}

fn b64url_value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    }))
}

/// Canonical base64url (RFC 4648 section 5): `A-Z a-z 0-9 - _`, either
/// without padding or padded with `=` to a multiple of 4 characters, and the
/// unused low bits of the last character zero. Both padding forms parse in
/// simplexmq (`Encoding/String.hs` `base64urlP`: the link key and `c` of a
/// short link are written unpadded, server key hashes padded, and both are
/// read by the same parser).
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let body = s.trim_end_matches('=');
    let pad = s.len() - body.len();
    let rem = body.len() % 4;
    if rem == 1 || (pad > 0 && (!s.len().is_multiple_of(4) || pad != (4 - rem) % 4)) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        acc = (acc << 6) | b64url_value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

/// A server key hash (format document section 7, "Server fingerprint",
/// amended 2026-11-21 11:00): 32 bytes as canonical base64url, 43
/// characters without padding or 44 with one trailing `=`. The client checks
/// it against the SHA-256 fingerprint of the server's identity certificate
/// (simplexmq `Transport/Client.hs` `validateCertificateChain`), so any
/// other length can never connect.
pub fn is_key_hash(s: &str) -> bool {
    (s.len() == 43 || s.len() == 44) && b64url_decode(s).is_some_and(|b| b.len() == 32)
}

/// A server password as simplexmq `Protocol.hs` `basicAuth` accepts it,
/// restricted to ASCII: printable, no space, no `@`, `:` or `/`.
fn is_valid_password(p: &str) -> bool {
    !p.is_empty()
        && p.bytes()
            .all(|c| c.is_ascii_graphic() && !matches!(c, b'@' | b':' | b'/'))
}

/// `scheme://fingerprint[:password]@host[,host...][:port]`, a strict subset
/// of simplexmq `Protocol.hs` `serverStrP`.
pub fn parse_server(addr: &str, scheme: &str) -> Result<ServerAddress, String> {
    let rest = addr
        .strip_prefix(scheme)
        .and_then(|r| r.strip_prefix("://"))
        .ok_or_else(|| format!("a {scheme} server address must start with {scheme}://"))?;
    let (cred, hostpart) = rest
        .rsplit_once('@')
        .ok_or_else(|| format!("{scheme} address without @"))?;
    let (fingerprint, password) = match cred.split_once(':') {
        Some((f, p)) => (f, Some(p)),
        None => (cred, None),
    };
    if !is_key_hash(fingerprint) {
        return Err(format!("{scheme} address: the fingerprint must be the server key hash, 32 bytes as base64url (43 characters, or 44 with one trailing =)"));
    }
    if let Some(p) = password {
        if !is_valid_password(p) {
            return Err(format!(
                "{scheme} address: invalid password (printable ASCII without space, @, : and /)"
            ));
        }
    }
    let (hosts, port) = match hostpart.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .ok()
                .filter(|n| *n > 0 && p.bytes().all(|c| c.is_ascii_digit()))
                .ok_or_else(|| format!("{scheme} address: invalid port"))?;
            (h, Some(port))
        }
        None => (hostpart, None),
    };
    let hosts: Vec<String> = hosts.split(',').map(str::to_string).collect();
    for h in &hosts {
        classify(h).map_err(|e| format!("{scheme} address: {e}"))?;
    }
    Ok(ServerAddress {
        scheme: scheme.into(),
        fingerprint: fingerprint.into(),
        password: password.map(str::to_string),
        hosts,
        port,
    })
}

fn percent_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("invalid percent encoding")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "percent encoding is not UTF-8".into())
}

/// The form of a support contact address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportForm {
    /// `simplex:/contact#/?v=...&smp=...` or `https://<host>/contact#/?...`.
    Long,
    /// `https://<host>/a#<key>?...` (format document section 7, short link
    /// grammar amended 2026-11-21 10:30). `key` is the 43-character link key.
    Short { key: String },
}

/// A support contact address and the SMP servers a client connects to for
/// it. Long form: the queues of the decoded `smp` parameter; the host in
/// front of `/contact` is only link notation. Short link: one server, made
/// of the host in front of `/a` plus the `h` hosts, the `p` port and the
/// `c` key hash (as `fingerprint`); the link data lives in the address's
/// own queue on that server (SimpleX source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportAddress {
    pub link_prefix: String,
    pub form: SupportForm,
    pub queues: Vec<ServerAddress>,
}

/// Unpadded base64url of exactly 32 bytes: 43 characters, canonical (the
/// two unused low bits of the last character are zero).
fn is_b64url_32(s: &str) -> bool {
    s.len() == 43 && is_key_hash(s)
}

/// Strict short link grammar (format document section 7, amended
/// 2026-11-21 10:30), a subset of simplexmq `Agent/Protocol.hs`
/// `StrEncoding AConnShortLink`:
/// `https://<host>/a#<key43>[?<param>(&<param>)*]`, params `h`, `p`, `c`,
/// each at most once, `c` required.
fn parse_short(host: &str, fragment: &str) -> Result<SupportAddress, String> {
    if host.contains(':') {
        return Err("support address: a port in front of /a is not accepted; use ?p=<port>".into());
    }
    classify(host).map_err(|e| format!("support address: short link host: {e}"))?;
    let (key, query) = match fragment.split_once('?') {
        Some((k, q)) => (k, Some(q)),
        None => (fragment, None),
    };
    if key.is_empty() {
        return Err("support address: short link without key".into());
    }
    if !is_b64url_32(key) {
        return Err("support address: the short link key must be 43 characters of unpadded base64url (32 bytes)".into());
    }
    let mut hosts = vec![host.to_string()];
    let (mut h_seen, mut port, mut key_hash) = (false, None, None);
    if let Some(q) = query {
        if q.is_empty() {
            return Err("support address: empty parameter list after ?".into());
        }
        for pair in q.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                return Err(
                    "support address: malformed short link parameter (expected name=value)".into(),
                );
            };
            if name.is_empty() || value.is_empty() {
                return Err(
                    "support address: malformed short link parameter (empty name or value)".into(),
                );
            }
            let twice = || format!("support address: short link parameter {name} appears twice");
            match name {
                "h" => {
                    if h_seen {
                        return Err(twice());
                    }
                    h_seen = true;
                    let v = value.replace("%2C", ",").replace("%2c", ",");
                    if v.contains('%') {
                        return Err(
                            "support address: h parameter: only %2C is allowed as an escape".into(),
                        );
                    }
                    for h in v.split(',') {
                        if h.is_empty() {
                            return Err("support address: h parameter: empty host".into());
                        }
                        classify(h).map_err(|e| format!("support address: h parameter: {e}"))?;
                        hosts.push(h.to_string());
                    }
                }
                "p" => {
                    if port.is_some() {
                        return Err(twice());
                    }
                    let n = value
                        .parse::<u16>()
                        .ok()
                        .filter(|n| {
                            *n > 0
                                && !value.starts_with('0')
                                && value.bytes().all(|c| c.is_ascii_digit())
                        })
                        .ok_or("support address: p parameter: the port must be 1 to 65535, decimal, no leading zero")?;
                    port = Some(n);
                }
                "c" => {
                    if key_hash.is_some() {
                        return Err(twice());
                    }
                    if !is_b64url_32(value) {
                        return Err("support address: c parameter: the server key hash must be 43 characters of unpadded base64url (32 bytes)".into());
                    }
                    key_hash = Some(value.to_string());
                }
                other => {
                    let shown = if other.len() <= 16
                        && other
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    {
                        format!(" {other:?}")
                    } else {
                        String::new()
                    };
                    return Err(format!(
                        "support address: unknown short link parameter{shown}; only h, p and c are accepted"
                    ));
                }
            }
        }
    }
    let fingerprint = key_hash
        .ok_or("support address: short link without c (the server key hash); c is required")?;
    Ok(SupportAddress {
        link_prefix: format!("https://{host}"),
        form: SupportForm::Short {
            key: key.to_string(),
        },
        queues: vec![ServerAddress {
            scheme: "smp".into(),
            fingerprint,
            password: None,
            hosts,
            port,
        }],
    })
}

/// The link type of a short link path `<t>#...` or `<t>/#...`, or `None`
/// if the path is not a short link.
fn short_link_type(path: &str) -> Option<(char, bool, &str)> {
    let mut it = path.char_indices();
    let (_, t) = it.next()?;
    let rest = &path[t.len_utf8()..];
    if let Some(f) = rest.strip_prefix('#') {
        Some((t, false, f))
    } else {
        rest.strip_prefix("/#").map(|f| (t, true, f))
    }
}

fn short_type_error(t: char) -> String {
    match t {
        'i' => "support address: /i# is a one-time invitation link, not a contact address".into(),
        'c' | 'C' => "support address: /c# is a channel link, not a contact address".into(),
        'g' | 'G' => "support address: /g# is a group link, not a contact address".into(),
        'r' | 'R' => "support address: /r# is a chat relay link, not a contact address".into(),
        'A' => "support address: upper case /A# is not accepted; write /a#".into(),
        _ => "support address: unknown short link type".into(),
    }
}

pub fn parse_support(addr: &str) -> Result<SupportAddress, String> {
    let (prefix, query) = if let Some(q) = addr.strip_prefix("simplex:/contact#/?") {
        ("simplex:".to_string(), q)
    } else if let Some(rest) = addr.strip_prefix("https://") {
        let (host, path) = rest.split_once('/').ok_or("support address: no path")?;
        if host.is_empty() {
            return Err("support address: invalid link host".into());
        }
        if let Some(q) = path.strip_prefix("contact#/?") {
            if classify(host).is_err() {
                return Err("support address: invalid link host".into());
            }
            (format!("https://{host}"), q)
        } else if let Some((t, slash, fragment)) = short_link_type(path) {
            return match (t, slash) {
                ('a', false) => parse_short(host, fragment),
                ('a', true) => Err("support address: /a/# is not accepted; write /a#".into()),
                _ => Err(short_type_error(t)),
            };
        } else {
            return Err(
                "support address: expected https://<host>/contact#/?... or https://<host>/a#..."
                    .into(),
            );
        }
    } else if addr.starts_with("simplex:/") && short_link_type(&addr[9..]).is_some() {
        return Err("support address: the simplex:/ short link form is not accepted; use https://<host>/a#...".into());
    } else {
        return Err(
            "support address: expected simplex:/contact#/?..., https://<host>/contact#/?... or https://<host>/a#..."
                .into(),
        );
    };
    let mut v = None;
    let mut smp = None;
    for (name, value) in query_pairs(query).map_err(|e| format!("support address: {e}"))? {
        match name {
            "v" => v = Some(value),
            "smp" => smp = Some(value),
            _ => {
                return Err(
                    "support address: unknown parameter; a contact address carries only v and smp"
                        .into(),
                )
            }
        }
    }
    let v = v.ok_or("support address: no v parameter (the agent version range)")?;
    percent_decode(v)
        .and_then(|v| parse_version_range(&v))
        .map_err(|e| format!("support address: v parameter: {e}"))?;
    let smp = smp.ok_or("support address: no smp parameter")?;
    let decoded = percent_decode(smp).map_err(|e| format!("support address: {e}"))?;
    // Queues are separated by `;` (`%3B` in the address), because the comma
    // separates the hosts of one server (simplexmq `connReqUriP`).
    let mut queues = Vec::new();
    for (i, q) in decoded.split(';').enumerate() {
        queues.push(parse_queue_uri(q).map_err(|e| format!("support address queue {i}: {e}"))?);
    }
    Ok(SupportAddress {
        link_prefix: prefix,
        form: SupportForm::Long,
        queues,
    })
}

/// The `name=value` pairs of a query string, still percent-encoded. Refused:
/// an empty pair, a pair without `=`, an empty name or value, a repeated
/// name, a raw `;` (http-types `parseSimpleQuery` splits on it as on `&`)
/// and a raw `+` (it decodes to a space there).
fn query_pairs(q: &str) -> Result<Vec<(&str, &str)>, String> {
    if q.contains([';', '+']) {
        return Err("a raw ; or + in the parameters; write %3B or %2B".into());
    }
    let mut out: Vec<(&str, &str)> = Vec::new();
    for pair in q.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            return Err("malformed parameter (expected name=value)".into());
        };
        if name.is_empty() || value.is_empty() {
            return Err("malformed parameter (empty name or value)".into());
        }
        if out.iter().any(|(n, _)| *n == name) {
            let shown = if name.len() <= 8 && name.bytes().all(|c| c.is_ascii_alphanumeric()) {
                format!(" {name}")
            } else {
                String::new()
            };
            return Err(format!("parameter{shown} appears twice"));
        }
        out.push((name, value));
    }
    Ok(out)
}

/// A version range `n` or `n-m`, decimal 1 to 65535 without leading zeros,
/// `n <= m` (simplexmq `Version.hs` `StrEncoding (VersionRange v)`).
/// Returns the highest version.
fn parse_version_range(s: &str) -> Result<u16, String> {
    let num = |p: &str| -> Option<u16> {
        (!p.is_empty() && !p.starts_with('0') && p.bytes().all(|c| c.is_ascii_digit()))
            .then(|| p.parse().ok())?
    };
    let bad = || "expected a version range like 2-7".to_string();
    let (lo, hi) = match s.split_once('-') {
        Some((a, b)) => (num(a).ok_or_else(bad)?, num(b).ok_or_else(bad)?),
        None => {
            let n = num(s).ok_or_else(bad)?;
            (n, n)
        }
    };
    if lo > hi {
        return Err("the lower version is above the upper one".into());
    }
    Ok(hi)
}

/// DER prefix of an X25519 SubjectPublicKeyInfo (RFC 8410), the form of the
/// `dh` key (simplexmq `Crypto.hs` `encodePubKey`): 12 bytes, then the 32-byte
/// public key.
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

/// One SMP queue URI of the `smp` parameter, already percent-decoded once:
/// `smp://<key hash>@<host>[,<host>...][:<port>]/<sender id>#/?<params>`,
/// params `v` (SMP client version range, required, highest version at
/// least 2), `dh` (X25519 key, required), `srv` (further hosts), `q` (`m`
/// or `c`) and `k` (`s`). A strict subset of simplexmq `Agent/Protocol.hs`
/// `StrEncoding SMPQueueUri`. The hosts of `srv` are added to the server's
/// hosts, as upstream does, so the mode rules see every host.
fn parse_queue_uri(q: &str) -> Result<ServerAddress, String> {
    let rest = q
        .strip_prefix("smp://")
        .ok_or("not an smp:// queue address")?;
    let (server, rest) = rest
        .split_once('/')
        .ok_or("no sender id after the server")?;
    let mut s = parse_server(&format!("smp://{server}"), "smp")?;
    if s.password.is_some() {
        return Err("the queue server must not carry a password".into());
    }
    let (sender_id, params) = rest
        .split_once("#/?")
        .ok_or("expected <sender id>#/?<parameters> after the server")?;
    if !b64url_decode(sender_id).is_some_and(|b| !b.is_empty()) {
        return Err("the sender id must be canonical base64url".into());
    }
    let (mut version, mut dh) = (None, None);
    for (name, value) in query_pairs(params)? {
        let value = percent_decode(value)?;
        match name {
            "v" => {
                version =
                    Some(parse_version_range(&value).map_err(|e| format!("v parameter: {e}"))?)
            }
            "dh" => dh = Some(value),
            "srv" => {
                for h in value.split(',') {
                    classify(h).map_err(|e| format!("srv parameter: {e}"))?;
                    s.hosts.push(h.to_string());
                }
            }
            "q" if value == "m" || value == "c" => {}
            "k" if value == "s" => {}
            "q" | "k" => return Err(format!("invalid {name} parameter")),
            _ => return Err("unknown parameter; a queue carries only v, dh, srv, q and k".into()),
        }
    }
    let version = version.ok_or("no v parameter (the SMP client version range)")?;
    if version < 2 {
        // Below version 2 the client rewrites the hosts of SimpleX preset
        // servers (`updateSMPServerHosts`), so the hosts would not be the
        // ones checked here.
        return Err("v parameter: the highest version must be at least 2".into());
    }
    let dh = dh.ok_or("no dh parameter (the X25519 key)")?;
    let key = b64url_decode(&dh).unwrap_or_default();
    if key.len() != 44 || key[..12] != X25519_SPKI_PREFIX {
        return Err("dh parameter: expected an X25519 public key (44 bytes DER, base64url)".into());
    }
    Ok(s)
}

/// A support address for messages: hosts masked, the short link key and
/// the key hash shortened to their first and last 4 characters.
pub fn mask_support(s: &SupportAddress) -> serde_json::Value {
    let link_host = mask_host(s.link_prefix.trim_start_matches("https://"));
    match &s.form {
        SupportForm::Long => serde_json::json!({
            "form": if s.link_prefix == "simplex:" { "simplex:/contact".to_string() } else { format!("{link_host}/contact") },
            "queues": s.queues.iter().map(mask_server).collect::<Vec<_>>(),
        }),
        SupportForm::Short { key } => serde_json::json!({
            "form": format!("{link_host}/a"),
            "key": mask_host(key),
            "server": s.queues.iter().map(mask_server).next(),
        }),
    }
}

/// `abcd...wxyz.onion` for onion hosts, `abcd...wxyz` for others.
pub fn mask_host(host: &str) -> String {
    let (label, suffix) = match host.strip_suffix(".onion") {
        Some(l) => (l, ".onion"),
        None => (host, ""),
    };
    let chars: Vec<char> = label.chars().collect();
    if chars.len() <= 8 {
        return format!("{}{suffix}", "*".repeat(chars.len().max(1)));
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail}{suffix}")
}

/// Fingerprint shortened, password hidden, hosts masked.
pub fn mask_server(s: &ServerAddress) -> String {
    let hosts: Vec<String> = s.hosts.iter().map(|h| mask_host(h)).collect();
    format!(
        "{}://{}{}@{}{}",
        s.scheme,
        mask_host(&s.fingerprint),
        if s.password.is_some() {
            ":<hidden>"
        } else {
            ""
        },
        hosts.join(","),
        s.port.map(|p| format!(":{p}")).unwrap_or_default()
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};

    /// A checksum-valid fake v3 onion whose name starts with `pattern`
    /// (base32 letters, at most 51 characters are kept).
    pub fn fake_onion(pattern: &str) -> String {
        let mut p: String = pattern.chars().cycle().take(51).collect();
        p.push('a');
        let raw = base32_decode(&p).unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(&raw[..32]);
        let h = onion_from_public(&public);
        assert!(h.starts_with(&p[..51]));
        h
    }

    #[test]
    fn onion_v3_checks() {
        let fake = fake_onion("testonly");
        // Computed independently from the Tor v3 specification.
        assert_eq!(
            fake,
            "testonlytestonlytestonlytestonlytestonlytestonlytesf6cyd.onion"
        );
        assert!(is_valid_onion_v3(&fake.to_ascii_uppercase()));
        // Upstream reads onion hosts only in lower case.
        assert!(classify(&fake.to_ascii_uppercase()).is_err());
        assert_eq!(classify(&fake).unwrap(), HostKind::Onion);
        assert_eq!(fake.len(), 62);
        assert!(is_valid_onion_v3(&fake));
        // One changed character breaks the checksum.
        let mut bad = fake.clone().into_bytes();
        bad[10] = if bad[10] == b'a' { b'b' } else { b'a' };
        let bad = String::from_utf8(bad).unwrap();
        assert!(!is_valid_onion_v3(&bad));
        assert!(classify(&bad).is_err());
        // v2 names and wrong versions are refused, never clearnet.
        assert!(classify("expyuzz4wqqyqhjn.onion").is_err());
        assert!(classify(&format!("sub.{fake}")).is_err());
        assert_eq!(
            classify("smp-a.example.invalid").unwrap(),
            HostKind::Clearnet
        );
        assert!(classify("bad_host.example.invalid").is_err());
    }

    fn sha256(seed: &str) -> [u8; 32] {
        let d = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    /// A synthetic server key hash: SHA-256 over `seed` (a visibly fake
    /// `TEST-ONLY-...` string), as unpadded base64url (43 characters).
    pub fn key_hash(seed: &str) -> String {
        Base64UrlUnpadded::encode_string(&sha256(seed))
    }

    /// Query string escaping as http-types `renderSimpleQuery` (used by
    /// simplexmq `QSP QEscape`): `A-Z a-z 0-9 - _ . ~` stay, every other
    /// byte becomes `%XX`.
    pub fn qs_escape(s: &str) -> String {
        s.bytes()
            .map(|c| {
                if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) {
                    (c as char).to_string()
                } else {
                    format!("%{c:02X}")
                }
            })
            .collect()
    }

    /// A synthetic long contact address in the form simplexmq writes it
    /// (`Agent/Protocol.hs` `StrEncoding (ConnectionRequestUri m)` and
    /// `StrEncoding SMPQueueUri`): agent versions 2-7, one queue with SMP
    /// client versions 1-4, so the first host is in the server and further
    /// hosts are in `srv`, the `dh` key padded, `q=c` for a contact queue.
    /// `link` is `simplex:` or `https://<host>`. Key hash, sender id (24
    /// bytes) and X25519 key are SHA-256 over `TEST-ONLY-...` seeds; X25519
    /// takes any 32 bytes as a public key.
    pub fn long_support(link: &str, hosts: &[&str]) -> String {
        let kh = key_hash("TEST-ONLY-SUPPORT-SMP-1");
        let sid = Base64Url::encode_string(&sha256("TEST-ONLY-SUPPORT-SENDER-ID-1")[..24]);
        let mut dh = X25519_SPKI_PREFIX.to_vec();
        dh.extend_from_slice(&sha256("TEST-ONLY-SUPPORT-DH-1"));
        let mut params = format!("v=1-4&dh={}&q=c", qs_escape(&Base64Url::encode_string(&dh)));
        if hosts.len() > 1 {
            params.push_str(&format!("&srv={}", qs_escape(&hosts[1..].join(","))));
        }
        let queue = format!("smp://{kh}@{}/{sid}#/?{params}", hosts[0]);
        format!("{link}/contact#/?v=2-7&smp={}", qs_escape(&queue))
    }

    #[test]
    fn base64url_canonical() {
        assert_eq!(b64url_decode("").unwrap(), b"");
        assert_eq!(b64url_decode("AQID").unwrap(), [1, 2, 3]);
        assert_eq!(b64url_decode("AQI").unwrap(), [1, 2]);
        assert_eq!(b64url_decode("AQI=").unwrap(), [1, 2]);
        assert_eq!(b64url_decode("AQ").unwrap(), [1]);
        assert_eq!(b64url_decode("AQ==").unwrap(), [1]);
        assert_eq!(b64url_decode("-_-_").unwrap(), [0xfb, 0xff, 0xbf]);
        for bad in [
            "A", "AQJ", "AR", "AQ=", "AQI==", "AQID=", "AQID====", "A=QI", "AQ+/", "AQ I",
        ] {
            assert!(b64url_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn fingerprints() {
        let o = fake_onion("testonlysmpa");
        let kh = key_hash("TEST-ONLY-SMP-1");
        assert_eq!(kh.len(), 43);
        let padded = Base64Url::encode_string(&sha256("TEST-ONLY-SMP-1"));
        assert_eq!(padded, format!("{kh}="));
        for fp in [kh.clone(), padded.clone(), fake43("A")] {
            assert!(is_key_hash(&fp), "{fp}");
            parse_server(&format!("smp://{fp}:TEST-ONLY-PASSWORD@{o}"), "smp").unwrap();
            parse_server(&format!("xftp://{fp}@{o}:443"), "xftp").unwrap();
        }
        let b31 = Base64UrlUnpadded::encode_string(&sha256("TEST-ONLY-SMP-1")[..31]);
        let b33 = Base64UrlUnpadded::encode_string(&[sha256("x").as_slice(), &[1]].concat());
        for bad in [
            "TEST-ONLY-FINGERPRINT-SMP".to_string(),
            b31.clone(),
            format!("{b31}="),
            b33,
            kh[..42].to_string(),
            format!("{}B", &kh[..42]),
            format!("{kh}=="),
            format!("{padded}="),
            format!("{}+", &kh[..42]),
            format!("{}/", &kh[..42]),
            kh.replace(|c: char| c.is_ascii_alphabetic(), "+"),
            String::new(),
        ] {
            assert!(!is_key_hash(&bad), "{bad}");
            let e = parse_server(&format!("smp://{bad}@{o}"), "smp").unwrap_err();
            assert!(
                e.contains("fingerprint must be the server key hash"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn server_addresses() {
        let o = fake_onion("testonlysmpa");
        let fp = key_hash("TEST-ONLY-SMP-1");
        let s = parse_server(
            &format!("smp://{fp}:TESTPASS@{o},smp-a.example.invalid:5223"),
            "smp",
        )
        .unwrap();
        assert_eq!(s.hosts.len(), 2);
        assert_eq!(s.port, Some(5223));
        assert_eq!(s.password.as_deref(), Some("TESTPASS"));
        let m = mask_server(&s);
        assert!(!m.contains("TESTPASS"));
        assert!(m.contains("@test...") && m.contains(":<hidden>@"));
        assert!(parse_server(&format!("smp://{fp}@{o}"), "smp")
            .unwrap()
            .password
            .is_none());
        parse_server(&format!("smp://{fp}:TEST-ONLY-PASSWORD@{o}"), "smp").unwrap();
        parse_server(&format!("smp://{fp}:a!#$%&*+,;=?[]^`{{|}}~\"'@{o}"), "smp").unwrap();
        for bad in [
            format!("xftp://{fp}@{o}"),
            format!("smp://{fp}@"),
            "smp://@host.example.invalid".to_string(),
            format!("smp://{fp}:@host.example.invalid"),
            format!("smp://{fp}:pass:word@host.example.invalid"),
            format!("smp://{fp}:pass/word@host.example.invalid"),
            format!("smp://{fp}:pass word@host.example.invalid"),
            format!("smp://{fp}:pässword@host.example.invalid"),
            format!("smp://{fp}:pass\tword@host.example.invalid"),
            format!("smp://{fp}@host.example.invalid:0"),
            format!("smp://{fp}@host.example.invalid:x"),
            format!("smp://{fp}@a.example.invalid,,b.example.invalid"),
            format!("smp://{fp}@bad.onion"),
            format!("smp://{fp}@{}", o.to_ascii_uppercase()),
            format!("smp://{fp}@{}", o.replace(".onion", ".ONION")),
            "smp://F/P@host.example.invalid".to_string(),
        ] {
            assert!(parse_server(&bad, "smp").is_err(), "{bad}");
        }
        let e = parse_server(&format!("smp://{fp}@{}", o.to_ascii_uppercase()), "smp").unwrap_err();
        assert!(
            e.contains("lower case") && !e.contains(&o) && !e.contains(&o.to_ascii_uppercase()),
            "{e}"
        );
    }

    #[test]
    fn support_addresses() {
        let o = fake_onion("testonlysupport");
        let clear = "support.example.invalid";
        let a = parse_support(&long_support("simplex:", &[&o, clear])).unwrap();
        assert_eq!(a.link_prefix, "simplex:");
        assert_eq!(a.queues.len(), 1);
        // The srv hosts belong to the server.
        assert_eq!(a.queues[0].hosts, vec![o.clone(), clear.to_string()]);
        assert_eq!(a.queues[0].fingerprint, key_hash("TEST-ONLY-SUPPORT-SMP-1"));
        let b = parse_support(&long_support("https://link.example.invalid", &[&o, clear])).unwrap();
        assert_eq!(b.link_prefix, "https://link.example.invalid");
        // The link host does not count as a connection host.
        assert_eq!(b.queues[0].hosts, a.queues[0].hosts);
        let one = parse_support(&long_support("simplex:", &[&o])).unwrap();
        assert_eq!(one.queues[0].hosts, vec![o.clone()]);

        // The upstream form, spelled out: the X25519 key's padding is
        // escaped twice (%253D), the queue separator ; once (%3B).
        let base = long_support("simplex:", &[&o]);
        assert!(
            base.starts_with("simplex:/contact#/?v=2-7&smp=smp%3A%2F%2F"),
            "{base}"
        );
        assert!(
            base.contains("%26dh%3DMCowBQYDK2VuAyEA") && base.contains("%253D%26q%3Dc"),
            "{base}"
        );
        let queue = base.split_once("&smp=").unwrap().1.to_string();
        let two =
            parse_support(&format!("simplex:/contact#/?v=2-7&smp={queue}%3B{queue}")).unwrap();
        assert_eq!(two.queues.len(), 2);
        // All hosts in the server (versions from 2) parse as well.
        let modern = base.replace(&format!("%40{o}%2F"), &format!("%40{o}%2C{clear}%2F"));
        assert_eq!(parse_support(&modern).unwrap().queues[0].hosts.len(), 2);
        // The key hash in the padded form.
        let kh = key_hash("TEST-ONLY-SUPPORT-SMP-1");
        parse_support(&base.replace(&kh, &format!("{kh}%3D"))).unwrap();

        let swap = |from: &str, to: &str| {
            assert!(base.contains(from), "{from}");
            base.replacen(from, to, 1)
        };
        let cases: Vec<(String, &str)> = vec![
            ("simplex:/a#abcdef".into(), "simplex:/ short link form"),
            (
                "https://link.example.invalid/a#abcdef".into(),
                "short link key",
            ),
            ("simplex:/contact#/?v=2-7".into(), "no smp parameter"),
            (
                base.replace("simplex:/contact", "simplex:/invitation"),
                "expected simplex:/contact",
            ),
            (format!("simplex:/contact#/?smp={queue}"), "no v parameter"),
            (
                format!("simplex:/contact#/?v=7-2&smp={queue}"),
                "v parameter",
            ),
            (format!("simplex:/contact#/?v=x&smp={queue}"), "v parameter"),
            (format!("{base}&data=x"), "unknown parameter"),
            (format!("{base}&v=2-7"), "appears twice"),
            (format!("{base};x=1"), "raw ; or +"),
            (
                format!("simplex:/contact#/?v=2-7&smp={queue},{queue}"),
                "queue 0",
            ),
            (
                swap(&kh, "TEST-ONLY-FINGERPRINT-SUPPORT"),
                "fingerprint must be the server key hash",
            ),
            (
                swap(&kh, &kh[..42]),
                "fingerprint must be the server key hash",
            ),
            (
                swap(
                    &format!("{kh}%40"),
                    &format!("{kh}%3ATEST-ONLY-PASSWORD%40"),
                ),
                "must not carry a password",
            ),
            (
                swap("smp%3A%2F%2F", "xftp%3A%2F%2F"),
                "not an smp:// queue address",
            ),
            (swap("%23%2F%3F", "%2F%3F"), "expected <sender id>#/?"),
            (
                swap("%23%2F%3Fv%3D1-4", "%23%2F%3Fv%3D1"),
                "highest version must be at least 2",
            ),
            (swap("%23%2F%3Fv%3D1-4%26", "%23%2F%3F"), "no v parameter"),
            (swap("%26dh%3DMCow", "%26dh%3DMCoA"), "dh parameter"),
            (swap("%26dh%3D", "%26dx%3D"), "unknown parameter"),
            (swap("%26q%3Dc", "%26q%3Dx"), "invalid q parameter"),
            (swap("%26q%3Dc", "%26srv%3Dbad.onion"), "srv parameter"),
            (swap("%26q%3Dc", "%26srv%3D"), "empty name or value"),
            (swap("%26q%3Dc", "%26q%3Dc%26q%3Dc"), "appears twice"),
            (
                swap(
                    &format!("%40{o}"),
                    &format!("%40{}", o.to_ascii_uppercase()),
                ),
                "lower case",
            ),
            (format!("{base}%ZZ"), "invalid percent encoding"),
        ];
        for (addr, want) in cases {
            let e = parse_support(&addr).unwrap_err();
            assert!(e.contains(want), "{addr}: {e}");
            assert!(!e.contains(&o) && !e.contains(&kh[..20]), "{e}");
        }
    }

    /// A synthetic 43-character value: `prefix` padded with `A` (canonical,
    /// the last character's unused bits are zero).
    pub fn fake43(prefix: &str) -> String {
        format!("{prefix}{}", "A".repeat(43 - prefix.len()))
    }

    pub fn short_link(host: &str, params: &str) -> String {
        let key = fake43("TEST-ONLY-LINK-KEY");
        if params.is_empty() {
            format!("https://{host}/a#{key}")
        } else {
            format!("https://{host}/a#{key}?{params}")
        }
    }

    #[test]
    fn short_links_accepted() {
        let o = fake_onion("testonlysupport");
        let o2 = fake_onion("testonlysupportb");
        let c = format!("c={}", fake43("TEST-ONLY-KEY-HASH"));
        let a = parse_support(&short_link(&o, &c)).unwrap();
        assert_eq!(
            a.form,
            SupportForm::Short {
                key: fake43("TEST-ONLY-LINK-KEY")
            }
        );
        assert_eq!(a.link_prefix, format!("https://{o}"));
        assert_eq!(a.queues.len(), 1);
        assert_eq!(a.queues[0].hosts, vec![o.clone()]);
        assert_eq!(a.queues[0].port, None);
        assert_eq!(a.queues[0].fingerprint, fake43("TEST-ONLY-KEY-HASH"));
        // Further hosts (raw comma and %2C), port, any parameter order.
        for params in [
            format!("h={o2},support.example.invalid&p=5223&{c}"),
            format!("{c}&p=5223&h={o2}%2Csupport.example.invalid"),
            format!("p=5223&h={o2}%2csupport.example.invalid&{c}"),
        ] {
            let b = parse_support(&short_link(&o, &params)).unwrap();
            assert_eq!(
                b.queues[0].hosts,
                vec![o.clone(), o2.clone(), "support.example.invalid".to_string()],
                "{params}"
            );
            assert_eq!(b.queues[0].port, Some(5223));
        }
        // A clearnet link host is parsed; the mode rules decide later.
        let d = parse_support(&short_link("support.example.invalid", &c)).unwrap();
        assert_eq!(
            d.queues[0].hosts,
            vec!["support.example.invalid".to_string()]
        );
        // The long form is still read.
        let l = parse_support(&long_support("simplex:", &[&o])).unwrap();
        assert_eq!(l.form, SupportForm::Long);
    }

    #[test]
    fn short_links_refused() {
        let o = fake_onion("testonlysupport");
        let key = fake43("TEST-ONLY-LINK-KEY");
        let kh = fake43("TEST-ONLY-KEY-HASH");
        let c = format!("c={kh}");
        let cases: Vec<(String, &str)> = vec![
            (
                format!("simplex:/a#{key}?h={o}&{c}"),
                "simplex:/ short link form",
            ),
            (
                format!("simplex:/i#LINKID/{key}?h={o}"),
                "simplex:/ short link form",
            ),
            (
                format!("https://{o}/i#LINKID/{key}?{c}"),
                "one-time invitation",
            ),
            (format!("https://{o}/c#{key}?{c}"), "channel link"),
            (format!("https://{o}/g#{key}?{c}"), "group link"),
            (format!("https://{o}/r#{key}?{c}"), "chat relay link"),
            (format!("https://{o}/A#{key}?{c}"), "upper case /A#"),
            (format!("https://{o}/a/#{key}?{c}"), "/a/# is not accepted"),
            (
                format!("https://{o}/x#{key}?{c}"),
                "unknown short link type",
            ),
            (
                format!("https://{o}:5223/a#{key}?{c}"),
                "port in front of /a",
            ),
            (format!("https://{o}/a#"), "without key"),
            (format!("https://{o}/a#?{c}"), "without key"),
            (
                format!("https://{o}/a#{}?{c}", &key[..42]),
                "short link key must be",
            ),
            (
                format!("https://{o}/a#{key}A?{c}"),
                "short link key must be",
            ),
            (
                format!("https://{o}/a#{}B?{c}", &key[..42]),
                "short link key must be",
            ),
            (
                format!("https://{o}/a#{key}=?{c}"),
                "short link key must be",
            ),
            (
                format!("https://{o}/a#{}+?{c}", &key[..42]),
                "short link key must be",
            ),
            (short_link(&o, ""), "without c"),
            (short_link(&o, "p=5223"), "without c"),
            (format!("https://{o}/a#{key}?"), "empty parameter list"),
            (
                short_link(&o, &format!("{c}&x=1")),
                "unknown short link parameter \"x\"",
            ),
            (
                short_link(&o, &format!("{c}&smp=1")),
                "unknown short link parameter",
            ),
            (
                short_link(&o, &format!("{c}&{c}")),
                "parameter c appears twice",
            ),
            (
                short_link(&o, &format!("{c}&p=1&p=2")),
                "parameter p appears twice",
            ),
            (
                short_link(&o, &format!("{c}&h={o}&h={o}")),
                "parameter h appears twice",
            ),
            (
                short_link(&o, &format!("{c}&h")),
                "malformed short link parameter",
            ),
            (
                short_link(&o, &format!("{c}&h=")),
                "malformed short link parameter",
            ),
            (
                short_link(&o, &format!("{c}&=x")),
                "malformed short link parameter",
            ),
            (
                short_link(&o, &format!("{c}&&p=1")),
                "malformed short link parameter",
            ),
            (
                short_link(&o, &format!("{c}&h={o},")),
                "h parameter: empty host",
            ),
            (short_link(&o, &format!("{c}&h={o}%2F")), "only %2C"),
            (
                short_link(&o, &format!("{c}&h=bad.onion")),
                "not a valid v3 onion",
            ),
            (
                short_link(&o, &format!("{c}&h=bad_host.example.invalid")),
                "invalid character",
            ),
            (short_link(&o, &format!("{c}&p=0")), "p parameter"),
            (short_link(&o, &format!("{c}&p=05223")), "p parameter"),
            (short_link(&o, &format!("{c}&p=65536")), "p parameter"),
            (short_link(&o, &format!("{c}&p=+80")), "p parameter"),
            (short_link(&o, &format!("c={}", &kh[..42])), "c parameter"),
            (short_link(&o, &format!("c={kh}=")), "c parameter"),
            (short_link(&o, &format!("c={}B", &kh[..42])), "c parameter"),
            (short_link("bad.onion", &c), "short link host"),
            (
                short_link("bad_host.example.invalid", &c),
                "short link host",
            ),
            (format!("https:///a#{key}?{c}"), "invalid link host"),
            (format!("https://{o}/a"), "expected https://"),
        ];
        for (addr, want) in cases {
            let e = parse_support(&addr).unwrap_err();
            assert!(e.contains(want), "{addr}: {e}");
            // No message shows the key, the key hash or a full host.
            assert!(!e.contains(&key[..20]) && !e.contains(&kh[..20]), "{e}");
            assert!(!e.contains(&o), "{e}");
        }
    }

    #[test]
    fn short_link_masking() {
        let o = fake_onion("testonlysupport");
        let kh = fake43("TEST-ONLY-KEY-HASH");
        let a = parse_support(&short_link(
            &o,
            &format!("h=support.example.invalid&p=5223&c={kh}"),
        ))
        .unwrap();
        let m = mask_support(&a).to_string();
        assert!(
            m.contains(&format!("\"form\":\"{}/a\"", mask_host(&o))),
            "{m}"
        );
        assert!(m.contains("\"key\":\"TEST...AAAA\""), "{m}");
        assert!(m.contains("smp://TEST...AAAA@test"), "{m}");
        assert!(m.contains("supp...alid:5223"), "{m}");
        assert!(
            !m.contains(&o) && !m.contains(&kh) && !m.contains("TEST-ONLY-LINK-KEY"),
            "{m}"
        );
    }

    #[test]
    fn masking() {
        assert_eq!(
            mask_host("abcdefghijklmnopqrstuvwxyz.onion"),
            "abcd...wxyz.onion"
        );
        assert_eq!(mask_host("smp-a.example.invalid"), "smp-...alid");
        assert_eq!(mask_host("short"), "*****");
    }

    #[test]
    fn base32_round_trip() {
        let d: Vec<u8> = (0u8..35).collect();
        assert_eq!(base32_decode(&base32_encode(&d)).unwrap(), d);
        assert!(base32_decode("ABC").is_none());
        assert!(base32_decode("a1").is_none());
    }
}
