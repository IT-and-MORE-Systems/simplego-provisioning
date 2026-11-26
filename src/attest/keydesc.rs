// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! KeyDescription (Android key attestation extension, OID
//! 1.3.6.1.4.1.11129.2.1.17). Schema: source.android.com, "Key and ID
//! attestation". Only the fields the checks need are kept; every field is
//! still parsed strictly.

use super::der::{self, Class, Reader, Tag};
use serde::Serialize;

pub const OID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl SecurityLevel {
    fn from(v: i64) -> der::Result<Self> {
        match v {
            0 => Ok(SecurityLevel::Software),
            1 => Ok(SecurityLevel::TrustedEnvironment),
            2 => Ok(SecurityLevel::StrongBox),
            _ => Err(format!("unknown SecurityLevel {v}")),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SecurityLevel::Software => "Software",
            SecurityLevel::TrustedEnvironment => "TEE",
            SecurityLevel::StrongBox => "StrongBox",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
}

impl VerifiedBootState {
    fn from(v: i64) -> der::Result<Self> {
        match v {
            0 => Ok(VerifiedBootState::Verified),
            1 => Ok(VerifiedBootState::SelfSigned),
            2 => Ok(VerifiedBootState::Unverified),
            3 => Ok(VerifiedBootState::Failed),
            _ => Err(format!("unknown VerifiedBootState {v}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RootOfTrust {
    #[serde(serialize_with = "ser_hex")]
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    /// Absent before attestation version 3.
    #[serde(serialize_with = "ser_opt_hex")]
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppId {
    pub packages: Vec<PackageInfo>,
    #[serde(serialize_with = "ser_hex_list")]
    pub signature_digests: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuthList {
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<i64>,
    pub os_patch_level: Option<i64>,
    pub vendor_patch_level: Option<i64>,
    pub boot_patch_level: Option<i64>,
    pub attestation_application_id: Option<AppId>,
    /// Tags 710 to 717 and 723 (device ID attestation). Recorded so that test
    /// fixtures can be checked for device identifiers.
    pub device_id_tags: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyDescription {
    pub attestation_version: i64,
    pub attestation_security_level: SecurityLevel,
    pub keymint_version: i64,
    pub keymint_security_level: SecurityLevel,
    #[serde(skip)]
    pub challenge: Vec<u8>,
    /// Kept so that test fixtures can be checked for device identifiers;
    /// not used by any check.
    #[serde(skip)]
    pub unique_id: Vec<u8>,
    pub software_enforced: AuthList,
    pub hardware_enforced: AuthList,
}

const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_VERSION: u32 = 705;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;
const TAG_VENDOR_PATCH_LEVEL: u32 = 718;
const TAG_BOOT_PATCH_LEVEL: u32 = 719;
const DEVICE_ID_TAGS: [u32; 9] = [710, 711, 712, 713, 714, 715, 716, 717, 723];

pub fn parse(ext_value: &[u8]) -> der::Result<KeyDescription> {
    let mut outer = Reader::new(ext_value);
    let seq = outer.expect(Tag::SEQUENCE)?;
    outer.finish()?;
    let mut r = Reader::new(seq);
    let attestation_version = der::int(r.expect(Tag::INTEGER)?)?;
    let attestation_security_level = SecurityLevel::from(der::int(r.expect(Tag::ENUMERATED)?)?)?;
    let keymint_version = der::int(r.expect(Tag::INTEGER)?)?;
    let keymint_security_level = SecurityLevel::from(der::int(r.expect(Tag::ENUMERATED)?)?)?;
    let challenge = r.expect(Tag::OCTET_STRING)?.to_vec();
    let unique_id = r.expect(Tag::OCTET_STRING)?.to_vec();
    let software_enforced = auth_list(r.expect(Tag::SEQUENCE)?)?;
    let hardware_enforced = auth_list(r.expect(Tag::SEQUENCE)?)?;
    // Later schema versions may append fields; they are not used here.
    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        keymint_version,
        keymint_security_level,
        challenge,
        unique_id,
        software_enforced,
        hardware_enforced,
    })
}

fn auth_list(data: &[u8]) -> der::Result<AuthList> {
    let mut list = AuthList::default();
    let mut r = Reader::new(data);
    let mut seen = std::collections::BTreeSet::new();
    while !r.is_empty() {
        let field = r.read()?;
        if field.tag.class != Class::Context || !field.tag.constructed {
            return Err(format!("AuthorizationList: unexpected {:?}", field.tag));
        }
        let n = field.tag.number;
        if !seen.insert(n) {
            return Err(format!("AuthorizationList: tag [{n}] repeated"));
        }
        let mut inner = Reader::new(field.value);
        match n {
            TAG_ROOT_OF_TRUST => {
                list.root_of_trust = Some(root_of_trust(inner.expect(Tag::SEQUENCE)?)?)
            }
            TAG_OS_VERSION => list.os_version = Some(der::int(inner.expect(Tag::INTEGER)?)?),
            TAG_OS_PATCH_LEVEL => {
                list.os_patch_level = Some(der::int(inner.expect(Tag::INTEGER)?)?)
            }
            TAG_VENDOR_PATCH_LEVEL => {
                list.vendor_patch_level = Some(der::int(inner.expect(Tag::INTEGER)?)?)
            }
            TAG_BOOT_PATCH_LEVEL => {
                list.boot_patch_level = Some(der::int(inner.expect(Tag::INTEGER)?)?)
            }
            TAG_ATTESTATION_APPLICATION_ID => {
                list.attestation_application_id = Some(app_id(inner.expect(Tag::OCTET_STRING)?)?)
            }
            _ => {
                if DEVICE_ID_TAGS.contains(&n) {
                    list.device_id_tags.push(n);
                }
                // Other fields are read as one TLV and not interpreted.
                inner.read()?;
            }
        }
        inner.finish()?;
    }
    Ok(list)
}

fn root_of_trust(data: &[u8]) -> der::Result<RootOfTrust> {
    let mut r = Reader::new(data);
    let verified_boot_key = r.expect(Tag::OCTET_STRING)?.to_vec();
    let device_locked = der::boolean(r.expect(Tag::BOOLEAN)?)?;
    let verified_boot_state = VerifiedBootState::from(der::int(r.expect(Tag::ENUMERATED)?)?)?;
    let verified_boot_hash = if r.is_empty() {
        None
    } else {
        Some(r.expect(Tag::OCTET_STRING)?.to_vec())
    };
    r.finish()?;
    Ok(RootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot_state,
        verified_boot_hash,
    })
}

fn app_id(data: &[u8]) -> der::Result<AppId> {
    let mut outer = Reader::new(data);
    let seq = outer.expect(Tag::SEQUENCE)?;
    outer.finish()?;
    let mut r = Reader::new(seq);
    let mut packages = Vec::new();
    let mut infos = Reader::new(r.expect(Tag::SET)?);
    while !infos.is_empty() {
        let mut p = Reader::new(infos.expect(Tag::SEQUENCE)?);
        let name = String::from_utf8(p.expect(Tag::OCTET_STRING)?.to_vec())
            .map_err(|_| "package name is not UTF-8")?;
        let version = der::int(p.expect(Tag::INTEGER)?)?;
        p.finish()?;
        packages.push(PackageInfo { name, version });
    }
    let mut signature_digests = Vec::new();
    let mut digests = Reader::new(r.expect(Tag::SET)?);
    while !digests.is_empty() {
        signature_digests.push(digests.expect(Tag::OCTET_STRING)?.to_vec());
    }
    r.finish()?;
    Ok(AppId {
        packages,
        signature_digests,
    })
}

fn ser_hex<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::util::hex(v))
}

fn ser_opt_hex<S: serde::Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(b) => s.serialize_str(&crate::util::hex(b)),
        None => s.serialize_none(),
    }
}

fn ser_hex_list<S: serde::Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for b in v {
        seq.serialize_element(&crate::util::hex(b))?;
    }
    seq.end()
}
