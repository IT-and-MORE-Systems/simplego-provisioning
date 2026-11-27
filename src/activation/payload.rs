// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Payload (format document section 7, amended 2026-11-19 23:10): UTF-8
//! JSON. Unknown fields are ignored when reading; required fields are
//! checked strictly. `sequence` is required in both kinds.
//!
//! Order of checks when reading (section 6, clarified 2026-11-21 11:00):
//! step 5 parses the payload ([`RawPayload::from_json`]) and checks the
//! fields ([`PayloadOf::check_fields`]); step 6 checks the device class (the
//! caller, it knows the app), then the network mode value
//! ([`RawPayload::into_payload`]), then the server and support address rules
//! ([`Payload::check_addresses`]). So a payload that breaks several rules is
//! refused for the first of them in this order.
//!
//! The optional `features` and `directory` objects (section 12) follow the
//! same order: their structure and field rules in step 5 (inside both
//! objects fail closed: an unknown name, value or field refuses the file),
//! the device class rule of the switches right after the device class
//! ([`PayloadOf::check_class_rules`]), the group links with the other
//! addresses: grammar first, then the network mode rules over every
//! address, then the server match of section 12.4.

use super::directory::Directory;
use super::features::Features;
use super::hosts::{
    classify, parse_group_link, parse_server, parse_support, same_server, HostKind, ServerAddress,
    SupportForm,
};
use super::Refusal;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const PAYLOAD_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Activation,
    Update,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Phone,
    Desktop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    TorRequired,
    TorOptional,
    Direct,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Activation => "activation",
            Kind::Update => "update",
        }
    }
}

impl DeviceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceClass::Phone => "phone",
            DeviceClass::Desktop => "desktop",
        }
    }
    pub fn parse(s: &str) -> Result<DeviceClass, String> {
        match s {
            "phone" => Ok(DeviceClass::Phone),
            "desktop" => Ok(DeviceClass::Desktop),
            _ => Err(format!("device class must be phone or desktop, got {s:?}")),
        }
    }
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::TorRequired => "tor_required",
            NetworkMode::TorOptional => "tor_optional",
            NetworkMode::Direct => "direct",
        }
    }
    pub fn parse(s: &str) -> Result<NetworkMode, String> {
        match s {
            "tor_required" => Ok(NetworkMode::TorRequired),
            "tor_optional" => Ok(NetworkMode::TorOptional),
            "direct" => Ok(NetworkMode::Direct),
            _ => Err(format!(
                "network mode must be tor_required, tor_optional or direct, got {s:?}"
            )),
        }
    }
    /// The rule for one address with the given host kinds.
    fn check(self, kinds: &[HostKind]) -> Result<(), &'static str> {
        let onion = kinds.contains(&HostKind::Onion);
        let clear = kinds.contains(&HostKind::Clearnet);
        match self {
            NetworkMode::TorRequired if !onion => {
                Err("tor_required needs an onion host in every address")
            }
            NetworkMode::TorOptional if !(onion && clear) => {
                Err("tor_optional needs an onion host and a clearnet host in every address")
            }
            NetworkMode::Direct if !clear => Err("direct needs a clearnet host in every address"),
            _ => Ok(()),
        }
    }
    /// The rule for one queue of the support address (its hosts: the queue
    /// host, the `srv` hosts; for a short link the link host and the `h`
    /// hosts). As for the servers, except in `tor_optional`: support is
    /// reachable only over Tor, so an onion host and no clearnet host
    /// (section 7, amended 2026-11-23).
    fn check_support(self, kinds: &[HostKind]) -> Result<(), &'static str> {
        let onion = kinds.contains(&HostKind::Onion);
        let clear = kinds.contains(&HostKind::Clearnet);
        match self {
            NetworkMode::TorOptional if !onion => {
                Err("tor_optional needs an onion host in the support address")
            }
            NetworkMode::TorOptional if clear => Err(
                "tor_optional allows no clearnet host in the support address (support is reachable only over Tor)",
            ),
            NetworkMode::TorOptional => Ok(()),
            _ => self.check(kinds),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Servers {
    pub smp: Vec<String>,
    pub xftp: Vec<String>,
}

/// The payload with its network mode as `M`: [`NetworkMode`] once checked
/// ([`Payload`]), the string as read before step 6 ([`RawPayload`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadOf<M> {
    pub payload_version: u32,
    pub kind: Kind,
    pub file_id: String,
    pub issued_at: String,
    pub customer_ref: String,
    pub device_class: DeviceClass,
    pub network_mode: M,
    pub servers: Servers,
    pub support_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_key: Option<String>,
    pub sequence: u64,
    /// Section 12.1: in both kinds. In an update, absent means the
    /// installed profile stays; present replaces it (12.4).
    /// When present, an object: `null` or another type is refused rather
    /// than read as absent (fail closed).
    #[serde(
        default,
        deserialize_with = "super::strict::object",
        skip_serializing_if = "Option::is_none"
    )]
    pub features: Option<Features>,
    /// Section 12.2: only in activation files.
    #[serde(
        default,
        deserialize_with = "super::strict::object",
        skip_serializing_if = "Option::is_none"
    )]
    pub directory: Option<Directory>,
}

pub type Payload = PayloadOf<NetworkMode>;

/// A payload as read from a file, before its network mode value is checked.
pub type RawPayload = PayloadOf<String>;

impl<M> Drop for PayloadOf<M> {
    fn drop(&mut self) {
        if let Some(k) = self.update_key.as_mut() {
            k.zeroize();
        }
        for s in self
            .servers
            .smp
            .iter_mut()
            .chain(self.servers.xftp.iter_mut())
        {
            s.zeroize();
        }
        self.support_address.zeroize();
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, a real calendar date.
pub fn is_rfc3339_utc_seconds(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let p = &s[r];
        p.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| p.parse().ok())?
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d) && h < 24 && mi < 60 && se < 60
}

pub fn is_valid_customer_ref(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

impl<M> PayloadOf<M> {
    /// Section 6 step 5: the fields other than the network mode and the
    /// addresses, for a file whose container kind is `container`.
    pub fn check_fields(&self, container: Kind) -> Result<(), Refusal> {
        let bad = |m: &str| Err(Refusal::BadPayload(m.to_string()));
        if self.payload_version != PAYLOAD_VERSION {
            return bad("payload_version must be 1");
        }
        if self.kind != container {
            return Err(Refusal::KindMismatch);
        }
        if !is_lower_hex(&self.file_id, 32) {
            return bad("file_id must be 32 lowercase hex characters");
        }
        if !is_rfc3339_utc_seconds(&self.issued_at) {
            return bad("issued_at must be UTC, RFC 3339, seconds, Z");
        }
        if !is_valid_customer_ref(&self.customer_ref) {
            return bad("customer_ref: only A-Z a-z 0-9 -, 1 to 32 characters");
        }
        match (&self.update_key, self.kind) {
            (None, Kind::Activation) => return bad("update_key is required in an activation file"),
            (Some(k), _) if !is_lower_hex(k, 64) => {
                return bad("update_key must be 64 lowercase hex characters")
            }
            _ => {}
        }
        if self.kind == Kind::Update && self.sequence < 1 {
            return bad("sequence starts at 1 in an update file");
        }
        if let Some(f) = &self.features {
            f.check().map_err(Refusal::BadPayload)?;
        }
        if let Some(d) = &self.directory {
            if self.kind == Kind::Update {
                return bad("directory is carried only in activation files, never in an update");
            }
            d.check_fields().map_err(Refusal::BadPayload)?;
        }
        Ok(())
    }

    /// Section 6 step 6, right after the device class (section 12.1): a
    /// desktop-only switch may be `off` or `ask` in a phone file, not `on`.
    pub fn check_class_rules(&self) -> Result<(), Refusal> {
        if let Some(f) = &self.features {
            f.check_class(self.device_class)
                .map_err(Refusal::BadPayload)?;
        }
        Ok(())
    }
}

impl RawPayload {
    /// Section 6 step 5: parse. `network_mode` is only required to be a
    /// string here; its value is checked in step 6. The payload must be a
    /// JSON object (serde alone would also read an array of the fields).
    pub fn from_json(bytes: &[u8]) -> Result<RawPayload, Refusal> {
        super::strict::from_slice(bytes).map_err(|e| Refusal::BadPayload(e.to_string()))
    }

    /// Section 6 step 6, after the device class: the network mode value.
    pub fn into_payload(mut self) -> Result<Payload, Refusal> {
        let network_mode = NetworkMode::parse(&self.network_mode).map_err(Refusal::BadPayload)?;
        let take = std::mem::take::<String>;
        Ok(Payload {
            payload_version: self.payload_version,
            kind: self.kind,
            file_id: take(&mut self.file_id),
            issued_at: take(&mut self.issued_at),
            customer_ref: take(&mut self.customer_ref),
            device_class: self.device_class,
            network_mode,
            servers: Servers {
                smp: std::mem::take(&mut self.servers.smp),
                xftp: std::mem::take(&mut self.servers.xftp),
            },
            support_address: take(&mut self.support_address),
            update_key: self.update_key.take(),
            sequence: self.sequence,
            features: self.features.take(),
            directory: self.directory.take(),
        })
    }
}

impl Payload {
    /// Parse and check the network mode value, without the other rules.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn from_json(bytes: &[u8]) -> Result<Payload, Refusal> {
        RawPayload::from_json(bytes)?.into_payload()
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// All rules of section 7 for a file whose container kind is
    /// `container` (used when issuing; the device class is the request's).
    pub fn validate(&self, container: Kind) -> Result<(), Refusal> {
        self.check_fields(container)?;
        self.check_class_rules()?;
        self.check_addresses()
    }

    /// Section 6 step 6, last: the server, support address and group link
    /// rules. Every address is parsed first (fingerprint, password, hosts,
    /// the group link grammar), then the network mode rules are checked
    /// over all of them, then every group link's server must be one of
    /// `servers.smp` (section 12.4).
    pub fn check_addresses(&self) -> Result<(), Refusal> {
        if self.servers.smp.is_empty() || self.servers.xftp.is_empty() {
            return Err(Refusal::BadPayload(
                "servers.smp and servers.xftp need at least one address each".into(),
            ));
        }
        // (name, host kinds, is a support address queue)
        let mut addresses: Vec<(String, Vec<HostKind>, bool)> = Vec::new();
        let mut smp_servers: Vec<ServerAddress> = Vec::new();
        for (scheme, list) in [("smp", &self.servers.smp), ("xftp", &self.servers.xftp)] {
            for (i, a) in list.iter().enumerate() {
                let s = parse_server(a, scheme)
                    .map_err(|e| Refusal::BadPayload(format!("servers.{scheme}[{i}]: {e}")))?;
                let kinds = s
                    .hosts
                    .iter()
                    .map(|h| classify(h))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(Refusal::BadPayload)?;
                addresses.push((format!("servers.{scheme}[{i}]"), kinds, false));
                if scheme == "smp" {
                    smp_servers.push(s);
                }
            }
        }
        let support = parse_support(&self.support_address).map_err(Refusal::BadPayload)?;
        for (i, q) in support.queues.iter().enumerate() {
            let kinds = q
                .hosts
                .iter()
                .map(|h| classify(h))
                .collect::<Result<Vec<_>, _>>()
                .map_err(Refusal::BadPayload)?;
            let name = match support.form {
                SupportForm::Long => format!("support_address queue {i}"),
                // The link host plus the h hosts (section 7, short links).
                SupportForm::Short { .. } => "support_address short link server".to_string(),
            };
            addresses.push((name, kinds, true));
        }
        let mut group_servers = Vec::new();
        for (i, g) in self
            .directory
            .iter()
            .flat_map(|d| d.groups.iter())
            .enumerate()
        {
            let name = format!("directory.groups[{i}].link");
            let l = parse_group_link(&g.link)
                .map_err(|e| Refusal::BadPayload(format!("{name}: {e}")))?;
            let kinds = l
                .server
                .hosts
                .iter()
                .map(|h| classify(h))
                .collect::<Result<Vec<_>, _>>()
                .map_err(Refusal::BadPayload)?;
            // Group links follow the rule of the servers (section 12.2).
            addresses.push((name.clone(), kinds, false));
            group_servers.push((name, l.server));
        }
        for (name, kinds, is_support) in &addresses {
            let rule = if *is_support {
                self.network_mode.check_support(kinds)
            } else {
                self.network_mode.check(kinds)
            };
            rule.map_err(|e| Refusal::NetworkModeRule(format!("{name}: {e}")))?;
        }
        for (name, server) in &group_servers {
            if !smp_servers.iter().any(|s| same_server(server, s)) {
                return Err(Refusal::BadPayload(format!(
                    "{name}: the link's server (hosts, port and key hash c) is not one of servers.smp"
                )));
            }
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update_key_bytes(&self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        let v = crate::util::unhex(self.update_key.as_deref()?)?;
        let mut k = zeroize::Zeroizing::new([0u8; 32]);
        if v.len() != 32 {
            return None;
        }
        k.copy_from_slice(&v);
        let mut v = v;
        v.zeroize();
        Some(k)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activation::hosts::tests::{fake_onion, key_hash, long_support};

    pub fn support(onion: &str, clear: Option<&str>) -> String {
        let hosts: Vec<&str> = std::iter::once(onion).chain(clear).collect();
        long_support("simplex:", &hosts)
    }

    pub fn sample(kind: Kind, mode: NetworkMode) -> Payload {
        let o = fake_onion("testonlysmpa");
        let x = fake_onion("testonlyxftpa");
        let s = fake_onion("testonlysupport");
        let fs = key_hash("TEST-ONLY-SMP-1");
        let fx = key_hash("TEST-ONLY-XFTP-1");
        let (smp, xftp, sup) = match mode {
            NetworkMode::TorRequired => (
                format!("smp://{fs}:TEST-ONLY-PASSWORD@{o}"),
                format!("xftp://{fx}:TEST-ONLY-PASSWORD@{x}"),
                support(&s, None),
            ),
            NetworkMode::TorOptional => (
                format!("smp://{fs}:TEST-ONLY-PASSWORD@{o},smp-a.example.invalid"),
                format!("xftp://{fx}:TEST-ONLY-PASSWORD@{x},xftp-a.example.invalid:443"),
                // Support only over Tor (section 7, amended 2026-11-23).
                support(&s, None),
            ),
            NetworkMode::Direct => (
                format!("smp://{fs}:TEST-ONLY-PASSWORD@smp-a.example.invalid"),
                format!("xftp://{fx}:TEST-ONLY-PASSWORD@xftp-a.example.invalid:443"),
                long_support("https://link.example.invalid", &["support.example.invalid"]),
            ),
        };
        Payload {
            payload_version: 1,
            kind,
            file_id: "0".repeat(32),
            issued_at: "2026-11-19T18:00:00Z".into(),
            customer_ref: "TEST-CUSTOMER-0001".into(),
            device_class: DeviceClass::Phone,
            network_mode: mode,
            servers: Servers {
                smp: vec![smp],
                xftp: vec![xftp],
            },
            support_address: sup,
            update_key: match kind {
                Kind::Activation => Some("ab".repeat(32)),
                Kind::Update => None,
            },
            sequence: match kind {
                Kind::Activation => 0,
                Kind::Update => 1,
            },
            features: None,
            directory: None,
        }
    }

    #[test]
    fn valid_samples_for_every_mode() {
        for mode in [
            NetworkMode::TorRequired,
            NetworkMode::TorOptional,
            NetworkMode::Direct,
        ] {
            for kind in [Kind::Activation, Kind::Update] {
                let p = sample(kind, mode);
                p.validate(kind).unwrap();
                let back = Payload::from_json(&p.to_json()).unwrap();
                assert_eq!(back, p);
                assert_eq!(
                    p.validate(if kind == Kind::Activation {
                        Kind::Update
                    } else {
                        Kind::Activation
                    })
                    .unwrap_err(),
                    Refusal::KindMismatch
                );
            }
        }
    }

    #[test]
    fn host_rules_per_mode() {
        let onion_only = sample(Kind::Update, NetworkMode::TorRequired);
        let both = sample(Kind::Update, NetworkMode::TorOptional);
        let clear_only = sample(Kind::Update, NetworkMode::Direct);
        let with_mode = |p: &Payload, m| {
            let mut q = p.clone();
            q.network_mode = m;
            q.validate(Kind::Update)
        };
        use NetworkMode::*;
        assert!(with_mode(&onion_only, TorRequired).is_ok());
        assert!(matches!(
            with_mode(&onion_only, TorOptional),
            Err(Refusal::NetworkModeRule(_))
        ));
        assert!(matches!(
            with_mode(&onion_only, Direct),
            Err(Refusal::NetworkModeRule(_))
        ));
        assert!(with_mode(&both, TorRequired).is_ok());
        assert!(with_mode(&both, TorOptional).is_ok());
        // Its support address has only an onion host.
        assert!(matches!(
            with_mode(&both, Direct),
            Err(Refusal::NetworkModeRule(e)) if e.contains("support")
        ));
        assert!(matches!(
            with_mode(&clear_only, TorRequired),
            Err(Refusal::NetworkModeRule(_))
        ));
        assert!(matches!(
            with_mode(&clear_only, TorOptional),
            Err(Refusal::NetworkModeRule(_))
        ));
        assert!(with_mode(&clear_only, Direct).is_ok());
        // The support address: as the servers in tor_required and direct; in
        // tor_optional an onion host and no clearnet host (amended
        // 2026-11-23), counted over every queue, its host and its srv hosts.
        let so = fake_onion("testonlysupport");
        let with_support = |p: &Payload, addr: String, m| {
            let mut q = p.clone();
            q.support_address = addr;
            with_mode(&q, m)
        };
        let support_rule = |r: Result<(), Refusal>, what: &str| matches!(r, Err(Refusal::NetworkModeRule(e)) if e.contains("support") && e.contains(what));
        let onion_and_srv_clear = support(&so, Some("support.example.invalid"));
        assert!(support_rule(
            with_support(&both, onion_and_srv_clear.clone(), TorOptional),
            "no clearnet host"
        ));
        assert!(with_support(&both, onion_and_srv_clear.clone(), TorRequired).is_ok());
        assert!(with_support(&both, onion_and_srv_clear, Direct).is_ok());
        let clear_support = clear_only.support_address.clone();
        assert!(support_rule(
            with_support(&both, clear_support.clone(), TorOptional),
            "needs an onion host"
        ));
        assert!(with_support(&both, clear_support, Direct).is_ok());
        assert!(with_support(&both, support(&so, None), TorOptional).is_ok());
        // Two queues (`;`): the second one with a clearnet host in srv.
        let queue = |a: &str| a.split_once("&smp=").unwrap().1.to_string();
        let one = support(&so, None);
        let two = format!(
            "simplex:/contact#/?v=2-7&smp={}%3B{}",
            queue(&one),
            queue(&support(&so, Some("support.example.invalid")))
        );
        assert!(support_rule(
            with_support(&both, two, TorOptional),
            "no clearnet host"
        ));
        let two_onion = format!(
            "simplex:/contact#/?v=2-7&smp={}%3B{}",
            queue(&one),
            queue(&one)
        );
        assert!(with_support(&both, two_onion, TorOptional).is_ok());
        // Short links: the link host plus the h hosts follow the mode rules.
        use crate::activation::hosts::tests::{fake43, short_link};
        let o = fake_onion("testonlysupport");
        let c = format!("c={}", fake43("TEST-ONLY-KEY-HASH"));
        let short = |p: &Payload, addr: String, m| {
            let mut q = p.clone();
            q.support_address = addr;
            with_mode(&q, m)
        };
        assert!(short(&onion_only, short_link(&o, &c), TorRequired).is_ok());
        assert!(matches!(
            short(&onion_only, short_link("support.example.invalid", &c), TorRequired),
            Err(Refusal::NetworkModeRule(e)) if e.contains("support_address short link server")
        ));
        assert!(short(&both, short_link(&o, &c), TorOptional).is_ok());
        let mixed = short_link(&o, &format!("h=support.example.invalid&{c}"));
        assert!(matches!(
            short(&both, mixed.clone(), TorOptional),
            Err(Refusal::NetworkModeRule(e)) if e.contains("no clearnet host")
        ));
        assert!(short(&both, mixed.clone(), TorRequired).is_ok());
        assert!(short(&both, mixed, Direct).is_ok());
        assert!(short(
            &clear_only,
            short_link("support.example.invalid", &c),
            Direct
        )
        .is_ok());
        assert!(matches!(
            short(&clear_only, short_link(&o, &c), Direct),
            Err(Refusal::NetworkModeRule(_))
        ));
        assert!(matches!(
            short(&onion_only, short_link(&o, ""), TorRequired),
            Err(Refusal::BadPayload(e)) if e.contains("without c")
        ));
        // A second address breaking the rule is found too.
        let mut p = onion_only.clone();
        p.servers.smp.push(format!(
            "smp://{}@smp-b.example.invalid",
            key_hash("TEST-ONLY-SMP-2")
        ));
        assert!(
            matches!(p.validate(Kind::Update), Err(Refusal::NetworkModeRule(e)) if e.contains("smp[1]"))
        );
    }

    #[test]
    fn strict_fields() {
        let good = sample(Kind::Activation, NetworkMode::TorRequired);
        let cases: Vec<fn(&mut Payload)> = vec![
            |p| p.payload_version = 2,
            |p| p.file_id = "A".repeat(32),
            |p| p.file_id = "0".repeat(31),
            |p| p.issued_at = "2026-11-19T18:00:00.5Z".into(),
            |p| p.issued_at = "2026-11-19T18:00:00+00:00".into(),
            |p| p.issued_at = "2026-02-30T18:00:00Z".into(),
            |p| p.customer_ref = String::new(),
            |p| p.customer_ref = "a".repeat(33),
            |p| p.customer_ref = "TEST_1".into(),
            |p| p.update_key = None,
            |p| p.update_key = Some("AB".repeat(32)),
            |p| p.servers.smp.clear(),
            |p| p.servers.xftp.clear(),
            |p| p.servers.smp[0] = "xftp://FP@h.example.invalid".into(),
            |p| p.support_address = "simplex:/a#TESTONLYSHORTLINK".into(),
            // Server fingerprints must be 32-byte key hashes (amended
            // 2026-11-21 11:00), also inside the support address.
            |p| {
                p.servers.smp[0] = p.servers.smp[0].replacen(
                    &key_hash("TEST-ONLY-SMP-1"),
                    "TEST-ONLY-FINGERPRINT-SMP",
                    1,
                )
            },
            |p| {
                p.servers.xftp[0] =
                    p.servers.xftp[0].replacen(&key_hash("TEST-ONLY-XFTP-1")[..42], "", 1)
            },
            |p| {
                p.support_address = p.support_address.replacen(
                    &key_hash("TEST-ONLY-SUPPORT-SMP-1"),
                    "TEST-ONLY-FINGERPRINT-SUPPORT",
                    1,
                )
            },
        ];
        for (i, f) in cases.iter().enumerate() {
            let mut p = good.clone();
            f(&mut p);
            assert!(
                matches!(p.validate(Kind::Activation), Err(Refusal::BadPayload(_))),
                "case {i}"
            );
        }
        let mut u = sample(Kind::Update, NetworkMode::TorRequired);
        u.sequence = 0;
        assert!(u.validate(Kind::Update).is_err());
        u.sequence = 1;
        u.update_key = Some("cd".repeat(32));
        assert!(u.validate(Kind::Update).is_ok());
    }

    /// A directory whose group links are on the payload's first SMP server.
    pub fn with_directory(mut p: Payload, groups: usize) -> Payload {
        use crate::activation::directory::{Directory, DirectoryGroup, Role};
        use crate::activation::hosts::tests::group_link_on;
        let s = parse_server(&p.servers.smp[0], "smp").unwrap();
        p.directory = Some(Directory {
            directory_version: 1,
            set_id: "5e".repeat(16),
            display_name: "TEST Anna".into(),
            role: Role::Member,
            groups: (0..groups)
                .map(|i| DirectoryGroup {
                    name: format!("TEST Gruppe {i}"),
                    link: group_link_on(&s, &format!("TEST-ONLY-GROUP-LINK-KEY-{i}")),
                    direct_contacts: i == 0,
                })
                .collect(),
        });
        p
    }

    #[test]
    fn section_12_features() {
        use crate::activation::features::tests::example;
        use crate::activation::features::FeatureValue;
        for kind in [Kind::Activation, Kind::Update] {
            let mut p = sample(kind, NetworkMode::TorRequired);
            p.features = Some(example());
            p.validate(kind).unwrap();
            let back = Payload::from_json(&p.to_json()).unwrap();
            assert_eq!(back, p);
            let mut v = p.features.clone().unwrap();
            v.profile_version = 2;
            p.features = Some(v);
            assert!(
                matches!(p.validate(kind), Err(Refusal::BadPayload(e)) if e.contains("profile_version"))
            );
        }
        // A desktop-only switch in a phone file: on refused, off and ask accepted.
        let mut p = sample(Kind::Activation, NetworkMode::TorRequired);
        for (v, ok) in [
            (FeatureValue::On, false),
            (FeatureValue::Off, true),
            (FeatureValue::Ask, true),
        ] {
            let mut f = example();
            f.vault = Some(v);
            p.features = Some(f);
            assert_eq!(p.validate(Kind::Activation).is_ok(), ok, "{v:?}");
            p.device_class = DeviceClass::Desktop;
            p.validate(Kind::Activation).unwrap();
            p.device_class = DeviceClass::Phone;
        }
        // Inside the object fail closed, outside unknown fields ignored.
        let p = sample(Kind::Activation, NetworkMode::TorRequired);
        let mut v: serde_json::Value = serde_json::from_slice(&p.to_json()).unwrap();
        v["features"] = serde_json::json!({"profile_version": 1, "groups": "off"});
        assert!(Payload::from_json(v.to_string().as_bytes()).is_ok());
        for bad in [
            serde_json::json!({"profile_version": 1, "stories": "off"}),
            serde_json::json!({"profile_version": 1, "groups": "disabled"}),
            serde_json::json!({"groups": "off"}),
            serde_json::json!({"profile_version": 1.0}),
            serde_json::json!(null),
            serde_json::json!("off"),
        ] {
            let mut w = v.clone();
            w["features"] = bad.clone();
            assert!(
                matches!(
                    RawPayload::from_json(w.to_string().as_bytes()),
                    Err(Refusal::BadPayload(_))
                ),
                "{bad}"
            );
        }
        let dup = v.to_string().replacen(
            "\"groups\":\"off\"",
            "\"groups\":\"off\",\"groups\":\"on\"",
            1,
        );
        assert!(RawPayload::from_json(dup.as_bytes()).is_err());
        // The features object, and the payload itself, as an array of the
        // fields in order: serde alone reads them, the strict reader not.
        let mut w = v.clone();
        w["features"] = serde_json::json!([1, "off"]);
        assert!(RawPayload::from_json(w.to_string().as_bytes()).is_err());
        let fields: Vec<serde_json::Value> = [
            "payload_version",
            "kind",
            "file_id",
            "issued_at",
            "customer_ref",
            "device_class",
            "network_mode",
            "servers",
            "support_address",
            "update_key",
            "sequence",
        ]
        .iter()
        .map(|k| v[*k].clone())
        .collect();
        let arr = serde_json::to_vec(&fields).unwrap();
        assert!(serde_json::from_slice::<RawPayload>(&arr).is_ok());
        assert!(
            matches!(RawPayload::from_json(&arr), Err(Refusal::BadPayload(e)) if e.contains("JSON object"))
        );
    }

    #[test]
    fn section_12_directory() {
        let p = with_directory(sample(Kind::Activation, NetworkMode::TorRequired), 2);
        p.validate(Kind::Activation).unwrap();
        assert_eq!(Payload::from_json(&p.to_json()).unwrap(), p);
        // tor_optional: the server has an onion and a clearnet host, the
        // link carries both.
        let q = with_directory(sample(Kind::Activation, NetworkMode::TorOptional), 1);
        q.validate(Kind::Activation).unwrap();
        assert!(q.directory.as_ref().unwrap().groups[0]
            .link
            .contains("?h=smp-a.example.invalid&c="));
        // Never in an update.
        let mut u = with_directory(sample(Kind::Update, NetworkMode::TorRequired), 1);
        assert!(
            matches!(u.validate(Kind::Update), Err(Refusal::BadPayload(e)) if e.contains("only in activation files"))
        );
        u.directory = None;
        u.validate(Kind::Update).unwrap();
        let change = |f: &dyn Fn(&mut Payload)| {
            let mut p = with_directory(sample(Kind::Activation, NetworkMode::TorRequired), 2);
            f(&mut p);
            p.validate(Kind::Activation)
        };
        let link = |p: &mut Payload, l: String| p.directory.as_mut().unwrap().groups[1].link = l;
        use crate::activation::hosts::tests::{fake43, key_hash};
        let kh = key_hash("TEST-ONLY-SMP-1");
        // A clearnet link host in tor_required: the mode rule.
        assert!(matches!(
            change(&|p| link(p, format!("https://smp-a.example.invalid/g#{}?c={kh}", fake43("K")))),
            Err(Refusal::NetworkModeRule(e)) if e.contains("directory.groups[1].link")
        ));
        // An onion link host on another server: the server match (12.4).
        let other = crate::activation::hosts::tests::fake_onion("testonlyother");
        assert!(matches!(
            change(&|p| link(p, format!("https://{other}/g#{}?c={kh}", fake43("K")))),
            Err(Refusal::BadPayload(e)) if e.contains("not one of servers.smp")
        ));
        let o = crate::activation::hosts::tests::fake_onion("testonlysmpa");
        assert!(matches!(
            change(&|p| link(p, format!("https://{o}/g#{}?c={}", fake43("K"), key_hash("TEST-ONLY-SMP-2")))),
            Err(Refusal::BadPayload(e)) if e.contains("not one of servers.smp")
        ));
        // Grammar: before any mode rule.
        assert!(matches!(
            change(&|p| link(p, format!("https://{o}/c#{}?c={kh}", fake43("K")))),
            Err(Refusal::BadPayload(e)) if e.contains("groups[1].link: group link: /c# is a channel link")
        ));
        // Field rules: names, counts, version, set_id.
        assert!(matches!(
            change(&|p| p.directory.as_mut().unwrap().display_name = "Dr. Weber".into()),
            Err(Refusal::BadPayload(e)) if e.contains("display_name") && !e.contains("Weber")
        ));
        assert!(matches!(
            change(&|p| p.directory.as_mut().unwrap().groups.clear()),
            Err(Refusal::BadPayload(e)) if e.contains("1 to 20")
        ));
        // Unknown field inside directory, inside a group, null: refused.
        let mut v: serde_json::Value = serde_json::from_slice(&p.to_json()).unwrap();
        for f in [
            |v: &mut serde_json::Value| v["directory"]["nickname"] = "x".into(),
            |v: &mut serde_json::Value| v["directory"]["groups"][0]["admin"] = true.into(),
            |v: &mut serde_json::Value| v["directory"]["role"] = "admin".into(),
            |v: &mut serde_json::Value| v["directory"] = serde_json::Value::Null,
            |v: &mut serde_json::Value| {
                v["directory"].as_object_mut().unwrap().remove("set_id");
            },
        ] {
            let mut w = v.clone();
            f(&mut w);
            assert!(matches!(
                RawPayload::from_json(w.to_string().as_bytes()),
                Err(Refusal::BadPayload(_))
            ));
        }
        v.as_object_mut().unwrap().remove("directory");
        assert!(Payload::from_json(v.to_string().as_bytes())
            .unwrap()
            .directory
            .is_none());
    }

    #[test]
    fn json_reading() {
        let p = sample(Kind::Activation, NetworkMode::TorRequired);
        let mut v: serde_json::Value = serde_json::from_slice(&p.to_json()).unwrap();
        v["later_optional_field"] = serde_json::json!({"x": 1});
        assert_eq!(Payload::from_json(v.to_string().as_bytes()).unwrap(), p);
        let mut missing = v.clone();
        missing.as_object_mut().unwrap().remove("sequence");
        assert!(Payload::from_json(missing.to_string().as_bytes()).is_err());
        let mut wrong = v.clone();
        wrong["network_mode"] = "tor".into();
        assert!(Payload::from_json(wrong.to_string().as_bytes()).is_err());
        // The raw form reads any string; its value is checked in step 6.
        let raw = RawPayload::from_json(wrong.to_string().as_bytes()).unwrap();
        assert_eq!(raw.network_mode, "tor");
        raw.check_fields(Kind::Activation).unwrap();
        assert!(
            matches!(raw.into_payload(), Err(Refusal::BadPayload(e)) if e.contains("network mode must be"))
        );
        let mut not_string = v.clone();
        not_string["network_mode"] = serde_json::json!(1);
        assert!(RawPayload::from_json(not_string.to_string().as_bytes()).is_err());
        let mut float = v.clone();
        float["payload_version"] = serde_json::json!(1.0);
        assert!(Payload::from_json(float.to_string().as_bytes()).is_err());
        assert!(Payload::from_json(b"\xff\xfe").is_err());
        let dup = String::from_utf8(p.to_json())
            .unwrap()
            .replacen('{', "{\"kind\":\"update\",", 1);
        assert!(Payload::from_json(dup.as_bytes()).is_err());
    }
}
