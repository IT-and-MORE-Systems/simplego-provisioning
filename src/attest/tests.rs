// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Tests without a phone: real public sample chains (Google, Apache-2.0) and
//! synthetic chains from a test root that exists only in this module.

use super::chain::{self, Anchor};
use super::keydesc::{self, SecurityLevel, VerifiedBootState};
use crate::trust::cache::Meta;
use crate::trust::google_roots;
use crate::trust::lists::{GrapheneOsKeys, RevocationList};
use crate::verify::{
    self, Evidence, ListState, MessengerEvidence, Overall, Policy, Reported, Status, Tier, Trust,
};
use crate::warning;
use base64ct::{Base64, Encoding};
use std::collections::BTreeSet;
use x509_cert::der::Encode;
use x509_cert::Certificate;

// ---- fixed times (no system clock in tests) --------------------------------

pub const DAY: u64 = 86_400;
/// 2025-10-01T00:00:00Z, inside the caiman sample validity.
const T_CAIMAN: u64 = 1_759_276_800;
/// 2026-03-01T00:00:00Z, inside the tegu sample validity.
const T_TEGU: u64 = 1_772_323_200;
/// 2026-11-15T00:00:00Z, inside the frankel sample validity.
const T_FRANKEL: u64 = 1_794_700_800;
/// 2026-06-01T00:00:00Z, inside the synthetic chain validity.
pub const T_SYN: u64 = 1_780_272_000;

fn pem_chain(pem: &str) -> Vec<Vec<u8>> {
    Certificate::load_pem_chain(pem.as_bytes())
        .unwrap()
        .iter()
        .map(|c| c.to_der().unwrap())
        .collect()
}

const FRANKEL: &str = include_str!("../../tests/fixtures/chains/frankel_sdk37_TEE_EC_2026.pem");
const TEGU: &str = include_str!("../../tests/fixtures/chains/tegu_sdk36_TEE_EC_2026_ROOT.pem");
const CAIMAN_TEE: &str = include_str!("../../tests/fixtures/chains/caiman_sdk36_TEE_EC_RKP.pem");
const CAIMAN_SB: &str = include_str!("../../tests/fixtures/chains/caiman_sdk36_SB_EC_RKP.pem");

// ---- real sample chains ----------------------------------------------------

#[test]
fn real_frankel_chain_to_new_ecdsa_root() {
    let roots = google_roots().unwrap();
    let rep = chain::verify(&pem_chain(FRANKEL), &roots, T_FRANKEL);
    assert!(rep.ok(), "{:?}", rep.errors);
    assert_eq!(rep.anchor.as_deref(), Some("google-root-ecdsa-p384-2025"));
    let kd = keydesc::parse(rep.key_description.as_ref().unwrap()).unwrap();
    assert_eq!(kd.attestation_version, 500);
    assert_eq!(
        kd.attestation_security_level,
        SecurityLevel::TrustedEnvironment
    );
    assert_eq!(kd.challenge, b"146aaf16-7814-4e44-acdb-e5d652a7b602");
    let rot = kd.hardware_enforced.root_of_trust.as_ref().unwrap();
    assert!(rot.device_locked);
    assert_eq!(rot.verified_boot_state, VerifiedBootState::Verified);
    assert_eq!(
        rot.verified_boot_key,
        Base64::decode_vec("dXxiaiqR/oUlNlRgSNfKP1DfbHRcAm25/4nMRwPFlIE=").unwrap()
    );
    assert_eq!(kd.hardware_enforced.os_version, Some(170000));
    assert_eq!(kd.hardware_enforced.os_patch_level, Some(202611));
    assert_eq!(kd.hardware_enforced.vendor_patch_level, Some(20261105));
    assert_eq!(kd.hardware_enforced.boot_patch_level, Some(20261105));
    let app = kd
        .software_enforced
        .attestation_application_id
        .as_ref()
        .unwrap();
    assert_eq!(app.packages[0].name, "com.google.android.attestation");
    assert_eq!(
        app.signature_digests,
        vec![Base64::decode_vec("EDk47kU35Z6O55L2VFBPuDRvxrNG0LvEQV/DOfz8jsE=").unwrap()]
    );
}

#[test]
fn real_tegu_chain_to_new_ecdsa_root() {
    let rep = chain::verify(&pem_chain(TEGU), &google_roots().unwrap(), T_TEGU);
    assert!(rep.ok(), "{:?}", rep.errors);
    assert_eq!(rep.anchor.as_deref(), Some("google-root-ecdsa-p384-2025"));
    let kd = keydesc::parse(rep.key_description.as_ref().unwrap()).unwrap();
    assert_eq!(kd.attestation_version, 400);
}

#[test]
fn real_caiman_chains_to_rsa_2019_root() {
    for (pem, level, version) in [
        (CAIMAN_TEE, SecurityLevel::TrustedEnvironment, 400),
        (CAIMAN_SB, SecurityLevel::StrongBox, 300),
    ] {
        let rep = chain::verify(&pem_chain(pem), &google_roots().unwrap(), T_CAIMAN);
        assert!(rep.ok(), "{:?}", rep.errors);
        assert_eq!(rep.anchor.as_deref(), Some("google-root-rsa-2019"));
        let kd = keydesc::parse(rep.key_description.as_ref().unwrap()).unwrap();
        assert_eq!(kd.attestation_security_level, level);
        assert_eq!(kd.attestation_version, version);
    }
}

/// Committed fixtures must carry no device identifiers: no attested serial,
/// IMEI, MEID or second IMEI (tags 713, 714, 715, 723) and an empty uniqueId.
#[test]
fn real_chains_carry_no_device_identifiers() {
    for (name, pem) in [
        ("frankel", FRANKEL),
        ("tegu", TEGU),
        ("caiman TEE", CAIMAN_TEE),
        ("caiman StrongBox", CAIMAN_SB),
    ] {
        let chain = pem_chain(pem);
        let ext = chain
            .iter()
            .filter_map(|d| {
                let c = <Certificate as x509_cert::der::Decode>::from_der(d).ok()?;
                c.tbs_certificate()
                    .extensions()?
                    .iter()
                    .find(|e| e.extn_id.to_string() == keydesc::OID_KEY_DESCRIPTION)
                    .map(|e| e.extn_value.as_bytes().to_vec())
            })
            .next()
            .unwrap_or_else(|| panic!("{name}: no key description"));
        let kd = keydesc::parse(&ext).unwrap();
        assert!(kd.unique_id.is_empty(), "{name}: uniqueId present");
        for t in [713, 714, 715, 723] {
            assert!(
                !kd.hardware_enforced.device_id_tags.contains(&t),
                "{name}: hardware-enforced tag {t}"
            );
            assert!(
                !kd.software_enforced.device_id_tags.contains(&t),
                "{name}: software-enforced tag {t}"
            );
        }
    }
}

#[test]
fn real_chain_wrong_root_rejected() {
    let only_rsa: Vec<Anchor> = google_roots()
        .unwrap()
        .into_iter()
        .filter(|a| a.name.contains("rsa"))
        .collect();
    let rep = chain::verify(&pem_chain(FRANKEL), &only_rsa, T_FRANKEL);
    assert!(!rep.ok());
    assert!(rep
        .errors
        .iter()
        .any(|e| e.contains("not one of the pinned")));
}

#[test]
fn real_chain_expired_intermediate_rejected() {
    // 2026-11-30: the frankel intermediate expired on 2026-11-21.
    let rep = chain::verify(
        &pem_chain(FRANKEL),
        &google_roots().unwrap(),
        T_FRANKEL + 15 * DAY,
    );
    assert!(!rep.ok());
    assert!(!rep.validity_ok);
}

#[test]
fn real_chain_tampered_signature_rejected() {
    let mut c = pem_chain(FRANKEL);
    let n = c[0].len();
    c[0][n - 5] ^= 0x01;
    let rep = chain::verify(&c, &google_roots().unwrap(), T_FRANKEL);
    assert!(!rep.ok());
    assert!(!rep.signatures_ok);
}

#[test]
fn real_chain_truncated_rejected() {
    let c = pem_chain(FRANKEL);
    let rep = chain::verify(&c[..c.len() - 1], &google_roots().unwrap(), T_FRANKEL);
    assert!(!rep.ok());
}

// ---- DER builder for synthetic KeyDescriptions -----------------------------

fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let b = (n as u32).to_be_bytes();
        let s: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
        let mut v = vec![0x80 | s.len() as u8];
        v.extend(s);
        v
    }
}

fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut v = tag.to_vec();
    v.extend(len(content.len()));
    v.extend_from_slice(content);
    v
}

fn int_bytes(x: i64) -> Vec<u8> {
    let b = x.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    b[i..].to_vec()
}

fn int(x: i64) -> Vec<u8> {
    tlv(&[0x02], &int_bytes(x))
}
fn enumerated(x: i64) -> Vec<u8> {
    tlv(&[0x0a], &int_bytes(x))
}
fn octets(b: &[u8]) -> Vec<u8> {
    tlv(&[0x04], b)
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x30], &parts.concat())
}
fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(&[0x31], &parts.concat())
}
fn ctx(n: u32, content: &[u8]) -> Vec<u8> {
    let mut tag = vec![];
    if n < 31 {
        tag.push(0xa0 | n as u8);
    } else {
        tag.push(0xbf);
        let mut groups = vec![];
        let mut m = n;
        while m > 0 {
            groups.push((m & 0x7f) as u8);
            m >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        for (i, g) in groups.iter().enumerate() {
            tag.push(if i < last { g | 0x80 } else { *g });
        }
    }
    tlv(&tag, content)
}

#[derive(Clone)]
pub struct Kd {
    pub level: i64,
    pub challenge: Vec<u8>,
    pub boot_key: Vec<u8>,
    pub locked: bool,
    pub state: i64,
    pub package: String,
    pub digest: Vec<u8>,
}

pub fn grapheneos_kd(challenge: &[u8]) -> Kd {
    Kd {
        level: 1,
        challenge: challenge.to_vec(),
        boot_key: vec![0x42; 32],
        locked: true,
        state: 1,
        package: crate::names::DEFAULT_AGENT_PACKAGE.into(),
        digest: vec![0xa5; 32],
    }
}

fn build_kd(k: &Kd) -> Vec<u8> {
    let app_id = seq(&[
        set(&[seq(&[octets(k.package.as_bytes()), int(1)])]),
        set(&[octets(&k.digest)]),
    ]);
    let sw = seq(&[ctx(709, &octets(&app_id))]);
    let rot = seq(&[
        octets(&k.boot_key),
        tlv(&[0x01], &[if k.locked { 0xff } else { 0x00 }]),
        enumerated(k.state),
        octets(&[0x11; 32]),
    ]);
    let hw = seq(&[
        ctx(704, &rot),
        ctx(705, &int(160000)),
        ctx(706, &int(202611)),
        ctx(718, &int(20261105)),
        ctx(719, &int(20261105)),
    ]);
    seq(&[
        int(400),
        enumerated(k.level),
        int(400),
        enumerated(k.level),
        octets(&k.challenge),
        octets(&[]),
        sw,
        hw,
    ])
}

#[test]
fn synthetic_key_description_roundtrip() {
    let kd = keydesc::parse(&build_kd(&grapheneos_kd(b"abc"))).unwrap();
    assert_eq!(kd.challenge, b"abc");
    let rot = kd.hardware_enforced.root_of_trust.unwrap();
    assert_eq!(rot.verified_boot_state, VerifiedBootState::SelfSigned);
    assert_eq!(rot.verified_boot_key, vec![0x42; 32]);
    assert_eq!(kd.hardware_enforced.os_patch_level, Some(202611));
}

#[test]
fn key_description_rejects_garbage_and_trailing_data() {
    assert!(keydesc::parse(&[0x30, 0x00]).is_err());
    let mut kd = build_kd(&grapheneos_kd(b"abc"));
    kd.push(0x00);
    assert!(keydesc::parse(&kd).is_err());
}

// ---- synthetic chains ------------------------------------------------------

const OID_KD: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

pub struct SynChain {
    pub ders: Vec<Vec<u8>>,
    pub root: Anchor,
}

/// Test root -> intermediate -> leaf. `ext_in_intermediate` also puts a key
/// description into the intermediate.
pub fn synthetic(kd: &Kd, ext_in_intermediate: bool) -> SynChain {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        SerialNumber,
    };
    let validity = |p: &mut CertificateParams| {
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2027, 1, 1);
    };
    let root_key = KeyPair::generate().unwrap();
    let mut rp = CertificateParams::new(vec![]).unwrap();
    rp.distinguished_name.push(
        DnType::CommonName,
        "sxprov TEST ROOT (never trusted outside tests)",
    );
    rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    rp.serial_number = Some(SerialNumber::from(vec![0x01]));
    validity(&mut rp);
    let root = rp.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::from_params(&rp, &root_key);

    let int_key = KeyPair::generate().unwrap();
    let mut ip = CertificateParams::new(vec![]).unwrap();
    ip.distinguished_name
        .push(DnType::CommonName, "sxprov test intermediate");
    ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ip.serial_number = Some(SerialNumber::from(vec![0x0a, 0xbc, 0xde]));
    if ext_in_intermediate {
        ip.custom_extensions
            .push(CustomExtension::from_oid_content(OID_KD, build_kd(kd)));
    }
    validity(&mut ip);
    let inter = ip.signed_by(&int_key, &root_issuer).unwrap();
    let int_issuer = Issuer::from_params(&ip, &int_key);

    let leaf_key = KeyPair::generate().unwrap();
    let mut lp = CertificateParams::new(vec![]).unwrap();
    lp.distinguished_name
        .push(DnType::CommonName, "Android Keystore Key");
    lp.serial_number = Some(SerialNumber::from(vec![0x01]));
    lp.custom_extensions
        .push(CustomExtension::from_oid_content(OID_KD, build_kd(kd)));
    validity(&mut lp);
    let leaf = lp.signed_by(&leaf_key, &int_issuer).unwrap();

    let root_der = root.der().to_vec();
    SynChain {
        ders: vec![leaf.der().to_vec(), inter.der().to_vec(), root_der.clone()],
        root: Anchor::from_der("test-root", &root_der).unwrap(),
    }
}

pub const CHALLENGE: &[u8] = &[7u8; 32];

pub fn gos_keys() -> GrapheneOsKeys {
    GrapheneOsKeys {
        keys: BTreeSet::from([vec![0x42; 32], vec![0x43; 32]]),
        timestamp: 1_776_709_772,
    }
}

pub fn revocation(json: &str) -> RevocationList {
    RevocationList::parse(json.as_bytes()).unwrap()
}

fn policy() -> Policy {
    Policy {
        agent_package: crate::names::DEFAULT_AGENT_PACKAGE.into(),
        agent_digest: Some(vec![0xa5; 32]),
        messenger_package: Some("org.example.messenger".into()),
        messenger_digest: None,
        revocation_max_age_days: 7,
        grapheneos_warn_age_days: 90,
        stale_confirmed: false,
    }
}

fn pixel() -> Reported {
    Reported {
        manufacturer: Some("Google".into()),
        model: Some("Pixel 8".into()),
        codename: Some("shiba".into()),
        android_version: Some("16".into()),
    }
}

fn messenger(digest: u8) -> Option<MessengerEvidence> {
    Some(MessengerEvidence {
        installed: true,
        version_name: Some("7.1.4".into()),
        version_code: Some(7014),
        signing_cert_sha256: vec![vec![digest; 32]],
        package_manager_agrees: true,
        error: None,
    })
}

struct Case {
    kd: Kd,
    ext_in_intermediate: bool,
    challenge: Vec<u8>,
    reported: Reported,
    revocation: String,
    rev_fetched: u64,
    gos_fetched: u64,
    policy: Policy,
    wrong_root: bool,
    messenger: Option<MessengerEvidence>,
}

impl Case {
    fn new() -> Case {
        Case {
            kd: grapheneos_kd(CHALLENGE),
            ext_in_intermediate: false,
            challenge: CHALLENGE.to_vec(),
            reported: pixel(),
            revocation: r#"{"entries":{"ffff":{"status":"REVOKED"}}}"#.into(),
            rev_fetched: T_SYN - DAY,
            gos_fetched: T_SYN - DAY,
            policy: policy(),
            wrong_root: false,
            messenger: messenger(0x5c),
        }
    }

    fn run(&self) -> verify::Report {
        let c = synthetic(&self.kd, self.ext_in_intermediate);
        let anchors = if self.wrong_root {
            synthetic(&self.kd, false).root.clone()
        } else {
            c.root.clone()
        };
        let anchors = [anchors];
        let rev = revocation(&self.revocation);
        let gos = gos_keys();
        let trust = Trust {
            anchors: &anchors,
            revocation: ListState {
                list: &rev,
                meta: &meta(self.rev_fetched),
            },
            grapheneos: ListState {
                list: &gos,
                meta: &meta(self.gos_fetched),
            },
        };
        let ev = Evidence {
            chain: c.ders,
            challenge: self.challenge.clone(),
            agent_keystore: Some("tee".into()),
            agent_error: None,
            reported: self.reported.clone(),
            messenger: self.messenger.clone(),
        };
        verify::evaluate(&ev, &trust, &self.policy, T_SYN)
    }
}

pub fn meta(fetched_at: u64) -> Meta {
    crate::trust::cache::meta_for("test", fetched_at, None, b"")
}

fn status(r: &verify::Report, id: &str) -> Status {
    r.checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"))
        .status
}

#[test]
fn grapheneos_pass_with_messenger_not_pinned() {
    let r = Case::new().run();
    assert_eq!(r.tier, Tier::HardenedPixel);
    for id in [
        "chain",
        "revocation",
        "challenge",
        "security_level",
        "root_of_trust",
        "app_identity",
    ] {
        assert_eq!(status(&r, id), Status::Pass, "{id}: {:?}", r.checks);
    }
    assert_eq!(status(&r, "patch_levels"), Status::Info);
    assert_eq!(status(&r, "messenger"), Status::Unverified);
    assert_eq!(r.overall, Overall::OsPassMessengerUnverified);
    assert_eq!(r.overall_label, "OS PASS, messenger UNVERIFIED");
    assert!(!r.stale_revocation_list);
}

#[test]
fn grapheneos_full_pass_with_messenger_pinned() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    let r = c.run();
    assert_eq!(r.overall, Overall::Pass);
    assert_eq!(r.overall.exit_code(), crate::exit::OK);
}

#[test]
fn messenger_wrong_signature_fails() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5d; 32]);
    assert_eq!(c.run().overall, Overall::Fail);
}

#[test]
fn messenger_package_manager_disagreeing_with_base_apk_fails() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.messenger.as_mut().unwrap().package_manager_agrees = false;
    let r = c.run();
    assert_eq!(r.overall, Overall::Fail);
    assert_eq!(status(&r, "messenger"), Status::Fail);
}

#[test]
fn messenger_without_a_package_is_unverified() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.policy.messenger_package = None;
    let r = c.run();
    assert_eq!(r.overall, Overall::OsPassMessengerUnverified);
    assert_eq!(status(&r, "messenger"), Status::Unverified);
}

#[test]
fn messenger_not_installed_is_unverified() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.messenger = Some(MessengerEvidence::default());
    assert_eq!(c.run().overall, Overall::OsPassMessengerUnverified);
}

#[test]
fn unlisted_key_is_unknown_device_never_pass() {
    let mut c = Case::new();
    c.kd.boot_key = vec![0x99; 32];
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    let r = c.run();
    assert_eq!(status(&r, "root_of_trust"), Status::UnknownDevice);
    assert_eq!(r.overall, Overall::UnknownDevice);
    assert_eq!(r.overall.exit_code(), crate::exit::UNKNOWN_DEVICE);
    let rot = r.checks.iter().find(|c| c.id == "root_of_trust").unwrap();
    assert!(rot.evidence.iter().any(|e| e.contains("trust refresh")));
    // Never PASS, and the messenger is not evaluated on an unknown device.
    assert_eq!(status(&r, "messenger"), Status::Unverified);
    assert!(!r.overall_label.contains("PASS"));
}

/// Boot key rule: only the signed GrapheneOS list decides. The model the
/// device reports is shown, never used: a listed key passes with any reported
/// model, an unlisted key is UNKNOWN DEVICE with any reported model.
#[test]
fn boot_key_rule_ignores_reported_model() {
    let models = [
        pixel(),
        Reported {
            manufacturer: Some("Google".into()),
            model: Some("Pixel 9 Pro".into()),
            codename: Some("caiman".into()),
            android_version: Some("17".into()),
        },
        Reported {
            manufacturer: Some("Google".into()),
            ..Default::default()
        },
    ];
    for reported in models {
        let mut listed = Case::new();
        listed.reported = reported.clone();
        let r = listed.run();
        assert_eq!(status(&r, "root_of_trust"), Status::Pass, "{reported:?}");
        let rot = r.checks.iter().find(|c| c.id == "root_of_trust").unwrap();
        assert!(rot
            .evidence
            .iter()
            .any(|e| e.contains("reported model") && e.contains("not checked")));

        let mut unlisted = Case::new();
        unlisted.reported = reported.clone();
        unlisted.kd.boot_key = vec![0x99; 32];
        let r = unlisted.run();
        assert_eq!(
            status(&r, "root_of_trust"),
            Status::UnknownDevice,
            "{reported:?}"
        );
        assert_eq!(r.overall, Overall::UnknownDevice);
    }
}

#[test]
fn unlocked_bootloader_fails() {
    let mut c = Case::new();
    c.kd.locked = false;
    let r = c.run();
    assert_eq!(status(&r, "root_of_trust"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn unlocked_pixel_is_hardened_fail_not_normal_tier() {
    let mut c = Case::new();
    c.kd.locked = false;
    c.kd.state = 2; // Unverified
    c.kd.boot_key = vec![0; 32];
    let r = c.run();
    assert_eq!(r.tier, Tier::HardenedPixel);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn stock_pixel_is_hardened_fail() {
    let mut c = Case::new();
    c.kd.state = 0; // Verified: stock OS
    c.kd.boot_key = vec![0x77; 32];
    let r = c.run();
    assert_eq!(r.tier, Tier::HardenedPixel);
    assert_eq!(status(&r, "root_of_trust"), Status::Fail);
}

#[test]
fn wrong_challenge_fails() {
    let mut c = Case::new();
    c.challenge = vec![8u8; 32];
    let r = c.run();
    assert_eq!(status(&r, "challenge"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn wrong_agent_digest_fails() {
    let mut c = Case::new();
    c.kd.digest = vec![0xa6; 32];
    let r = c.run();
    assert_eq!(status(&r, "app_identity"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn wrong_agent_package_fails() {
    let mut c = Case::new();
    c.kd.package = "com.example.other".into();
    assert_eq!(status(&c.run(), "app_identity"), Status::Fail);
}

#[test]
fn agent_digest_not_configured_is_unverified() {
    let mut c = Case::new();
    c.policy.agent_digest = None;
    let r = c.run();
    assert_eq!(status(&r, "app_identity"), Status::Unverified);
    assert_eq!(r.overall, Overall::Unverified);
}

#[test]
fn software_security_level_fails() {
    let mut c = Case::new();
    c.kd.level = 0;
    let r = c.run();
    assert_eq!(status(&r, "security_level"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn revoked_intermediate_fails_hex_and_decimal() {
    for key in ["abcde", "703710"] {
        let mut c = Case::new();
        c.revocation = format!(
            r#"{{"entries":{{"{key}":{{"status":"SUSPENDED","reason":"KEY_COMPROMISE"}}}}}}"#
        );
        let r = c.run();
        assert_eq!(status(&r, "revocation"), Status::Fail, "{key}");
        assert_eq!(r.overall, Overall::Fail);
    }
}

#[test]
fn wrong_root_fails() {
    let mut c = Case::new();
    c.wrong_root = true;
    let r = c.run();
    assert_eq!(status(&r, "chain"), Status::Fail);
    // Checks that rest on the chain are not evaluated.
    assert_eq!(status(&r, "root_of_trust"), Status::Unverified);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn extension_outside_leaf_fails() {
    let mut c = Case::new();
    c.ext_in_intermediate = true;
    let r = c.run();
    assert_eq!(status(&r, "chain"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn stale_list_without_confirmation_is_never_pass() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.rev_fetched = T_SYN - 8 * DAY;
    let r = c.run();
    assert!(r.stale_revocation_list);
    assert_eq!(status(&r, "revocation"), Status::Unverified);
    assert_eq!(r.overall, Overall::Unverified);
}

#[test]
fn stale_list_with_confirmation_marks_pass_as_stale() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.policy.stale_confirmed = true;
    c.rev_fetched = T_SYN - 8 * DAY;
    let r = c.run();
    assert_eq!(r.overall, Overall::Pass);
    assert!(r.stale_revocation_list);
    assert!(r.overall_label.contains("STALE"));
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["stale_revocation_list"], true);
}

#[test]
fn revocation_threshold_boundary() {
    assert!(!verify::revocation_stale(T_SYN - 7 * DAY, 7, T_SYN));
    assert!(verify::revocation_stale(T_SYN - 7 * DAY - 1, 7, T_SYN));
    assert!(!verify::revocation_stale(T_SYN - 10 * DAY, 14, T_SYN));
}

#[test]
fn old_grapheneos_list_warns_but_needs_no_confirmation() {
    let mut c = Case::new();
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    c.gos_fetched = T_SYN - 91 * DAY;
    let r = c.run();
    assert_eq!(r.overall, Overall::Pass);
    assert!(r.grapheneos_key_list.over_threshold);
    assert!(r.warnings.iter().any(|w| w.contains("GrapheneOS key list")));
    let mut c = Case::new();
    c.gos_fetched = T_SYN - 89 * DAY;
    assert!(!c.run().grapheneos_key_list.over_threshold);
}

#[test]
fn normal_phone_tier_is_never_pass() {
    let mut c = Case::new();
    c.kd.state = 0; // Verified: stock OS
    c.kd.boot_key = vec![0x77; 32];
    c.reported.manufacturer = Some("samsung".into());
    c.policy.messenger_digest = Some(vec![0x5c; 32]);
    let r = c.run();
    assert_eq!(r.tier, Tier::NormalPhone);
    assert_eq!(r.overall, Overall::NormalTier);
    assert_eq!(r.overall_label, warning::NORMAL_TIER_LABEL);
    assert!(!r.overall_label.contains("PASS"));
    assert_eq!(r.overall.exit_code(), crate::exit::NORMAL_TIER);
    assert!(r.warnings.iter().any(|w| w == warning::NORMAL_TIER_WARNING));
}

#[test]
fn normal_phone_wrong_messenger_signature_fails() {
    let mut c = Case::new();
    c.kd.state = 0;
    c.kd.boot_key = vec![0x77; 32];
    c.reported.manufacturer = Some("samsung".into());
    c.policy.messenger_digest = Some(vec![0x5d; 32]);
    let r = c.run();
    assert_eq!(r.tier, Tier::NormalPhone);
    assert_eq!(r.overall, Overall::Fail);
}

#[test]
fn non_pixel_with_selfsigned_is_hardened_tier() {
    let mut c = Case::new();
    c.reported.manufacturer = Some("other".into());
    c.kd.boot_key = vec![0x99; 32];
    let r = c.run();
    assert_eq!(r.tier, Tier::HardenedPixel);
    assert_eq!(r.overall, Overall::UnknownDevice);
}

#[test]
fn no_chain_from_agent_fails_on_pixel() {
    let rev = revocation(r#"{"entries":{}}"#);
    let gos = gos_keys();
    let anchors: [Anchor; 0] = [];
    let trust = Trust {
        anchors: &anchors,
        revocation: ListState {
            list: &rev,
            meta: &meta(T_SYN),
        },
        grapheneos: ListState {
            list: &gos,
            meta: &meta(T_SYN),
        },
    };
    let ev = Evidence {
        challenge: CHALLENGE.to_vec(),
        agent_error: Some("install failed".into()),
        reported: pixel(),
        ..Default::default()
    };
    let r = verify::evaluate(&ev, &trust, &policy(), T_SYN);
    assert_eq!(r.overall, Overall::Fail);
    assert!(r.checks[0].evidence[0].contains("install failed"));
}

#[test]
fn real_stock_pixel_chain_is_hardened_fail_with_reasons() {
    let roots = google_roots().unwrap();
    let rev = revocation(r#"{"entries":{}}"#);
    let gos = gos_keys();
    let trust = Trust {
        anchors: &roots,
        revocation: ListState {
            list: &rev,
            meta: &meta(T_FRANKEL),
        },
        grapheneos: ListState {
            list: &gos,
            meta: &meta(T_FRANKEL),
        },
    };
    let ev = Evidence {
        chain: pem_chain(FRANKEL),
        challenge: b"146aaf16-7814-4e44-acdb-e5d652a7b602".to_vec(),
        reported: pixel(),
        ..Default::default()
    };
    let r = verify::evaluate(&ev, &trust, &policy(), T_FRANKEL);
    assert_eq!(r.tier, Tier::HardenedPixel);
    assert_eq!(status(&r, "chain"), Status::Pass);
    assert_eq!(status(&r, "revocation"), Status::Pass);
    assert_eq!(status(&r, "challenge"), Status::Pass);
    assert_eq!(status(&r, "security_level"), Status::Pass);
    assert_eq!(status(&r, "root_of_trust"), Status::Fail);
    assert_eq!(status(&r, "app_identity"), Status::Fail);
    assert_eq!(r.overall, Overall::Fail);
}
