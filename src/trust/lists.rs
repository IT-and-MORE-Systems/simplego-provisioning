// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The two downloaded lists: Google's attestation revocation list and the
//! signed GrapheneOS verified boot key list.

use super::sshsig;
use crate::util::unhex;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Committed public signing key of GrapheneOS (trust/grapheneos/allowed_signers).
pub const GRAPHENEOS_ALLOWED_SIGNERS: &str = include_str!("../../trust/grapheneos/allowed_signers");
pub const GRAPHENEOS_PRINCIPAL: &str = "contact@grapheneos.org";
pub const GRAPHENEOS_NAMESPACE: &str = "attestation keys";

#[derive(Debug, Clone, Deserialize)]
pub struct RevocationEntry {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevocationList {
    /// Keys lowercased, leading zeros removed.
    pub entries: BTreeMap<String, RevocationEntry>,
}

#[derive(Deserialize)]
struct RevocationJson {
    entries: BTreeMap<String, RevocationEntry>,
}

impl RevocationList {
    pub fn parse(json: &[u8]) -> Result<RevocationList, String> {
        let raw: RevocationJson =
            serde_json::from_slice(json).map_err(|e| format!("revocation list: {e}"))?;
        let entries = raw
            .entries
            .into_iter()
            .map(|(k, v)| (normalize(&k), v))
            .collect();
        Ok(RevocationList { entries })
    }

    /// Looks a certificate serial up. The documented key form is lowercase
    /// hex without leading zeros; the live list also holds keys that are
    /// decimal serial numbers, so both forms are matched. Any listed status
    /// blocks (REVOKED, SUSPENDED, and unknown values, fail-safe).
    pub fn lookup(&self, serial_hex: &str, serial_dec: &str) -> Option<(&str, &RevocationEntry)> {
        for key in [normalize(serial_hex), normalize(serial_dec)] {
            if let Some((k, v)) = self.entries.get_key_value(&key) {
                return Some((k.as_str(), v));
            }
        }
        None
    }
}

fn normalize(k: &str) -> String {
    let l = k.trim().to_ascii_lowercase();
    let t = l.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

#[derive(Debug, Clone)]
pub struct GrapheneOsKeys {
    pub keys: BTreeSet<Vec<u8>>,
    /// `timestamp` field of the signed file (unix seconds).
    pub timestamp: u64,
}

#[derive(Deserialize)]
struct GosJson {
    #[serde(rename = "verifiedBootKeys")]
    verified_boot_keys: Vec<String>,
    timestamp: u64,
}

impl GrapheneOsKeys {
    /// Verifies the signature with the committed allowed_signers, then parses.
    pub fn verify_and_parse(json: &[u8], sig: &str) -> Result<GrapheneOsKeys, String> {
        Self::verify_and_parse_with(GRAPHENEOS_ALLOWED_SIGNERS, json, sig)
    }

    pub fn verify_and_parse_with(
        allowed: &str,
        json: &[u8],
        sig: &str,
    ) -> Result<GrapheneOsKeys, String> {
        let signers = sshsig::parse_allowed_signers(allowed)?;
        sshsig::verify(
            &signers,
            GRAPHENEOS_PRINCIPAL,
            GRAPHENEOS_NAMESPACE,
            json,
            sig,
        )
        .map_err(|e| format!("GrapheneOS key list signature: {e}"))?;
        let raw: GosJson =
            serde_json::from_slice(json).map_err(|e| format!("GrapheneOS key list: {e}"))?;
        let mut keys = BTreeSet::new();
        for k in raw.verified_boot_keys {
            let b = unhex(&k).ok_or_else(|| format!("GrapheneOS key list: bad hex {k:?}"))?;
            if b.len() != 32 {
                return Err(format!("GrapheneOS key list: key {k} is not 32 bytes"));
            }
            keys.insert(b);
        }
        if keys.is_empty() {
            return Err("GrapheneOS key list is empty".into());
        }
        Ok(GrapheneOsKeys {
            keys,
            timestamp: raw.timestamp,
        })
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        self.keys.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATT_JSON: &[u8] = include_bytes!("../../tests/fixtures/trust/attestation.json");
    const ATT_SIG: &str = include_str!("../../tests/fixtures/trust/attestation.json.sig");
    const STATUS: &[u8] = include_bytes!("../../tests/fixtures/trust/status-sample.json");

    #[test]
    fn real_grapheneos_list_verifies() {
        let k = GrapheneOsKeys::verify_and_parse(ATT_JSON, ATT_SIG).unwrap();
        assert_eq!(k.timestamp, 1776709772);
        assert_eq!(k.keys.len(), 21);
        let pixel_10a =
            unhex("d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80").unwrap();
        assert!(k.contains(&pixel_10a));
    }

    #[test]
    fn tampered_grapheneos_list_rejected() {
        let mut j = ATT_JSON.to_vec();
        let pos = j.iter().position(|b| *b == b'd').unwrap();
        j[pos] = b'e';
        assert!(GrapheneOsKeys::verify_and_parse(&j, ATT_SIG).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let other = "contact@grapheneos.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuX/XO3nzRXF3kF4ODJ8TxMV8GVVODLz8Oy8KjLzrbW\n";
        assert!(GrapheneOsKeys::verify_and_parse_with(other, ATT_JSON, ATT_SIG).is_err());
        let wrong_principal = GRAPHENEOS_ALLOWED_SIGNERS.replace("contact@", "other@");
        assert!(
            GrapheneOsKeys::verify_and_parse_with(&wrong_principal, ATT_JSON, ATT_SIG).is_err()
        );
    }

    #[test]
    fn revocation_hex_and_decimal() {
        let l = RevocationList::parse(STATUS).unwrap();
        // Hex key from the sample.
        assert!(l.lookup("c35747a084470c3135aeefe2b8d40cd6", "0").is_some());
        // Leading zeros and case do not matter.
        assert!(l
            .lookup("00C35747A084470C3135AEEFE2B8D40CD6", "0")
            .is_some());
        // Decimal key from the sample.
        assert!(l.lookup("ffff", "6681152659205225093").is_some());
        assert!(l.lookup("abc", "2748").is_none());
    }
}
