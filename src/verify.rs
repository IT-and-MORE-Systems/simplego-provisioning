// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Verification result logic. Pure: takes the evidence collected from the
//! device, the trust material and the time, and returns the checks with their
//! evidence and the overall result. No PASS without checked evidence.

use crate::attest::chain::{self, Anchor, ChainReport};
use crate::attest::keydesc::{self, KeyDescription, SecurityLevel, VerifiedBootState};
use crate::trust::cache::Meta;
use crate::trust::lists::{GrapheneOsKeys, RevocationList};
use crate::util::{fmt_age, fmt_unix, hex};
use crate::warning;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Unverified,
    /// Root of trust: SelfSigned with a key not in the GrapheneOS list.
    UnknownDevice,
    /// Shown only, not judged (patch levels, reported values).
    Info,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Unverified => "UNVERIFIED",
            Status::UnknownDevice => "UNKNOWN DEVICE",
            Status::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub status: Status,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    HardenedPixel,
    NormalPhone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Overall {
    /// Hardened tier, every check passed, messenger pinned and matching.
    Pass,
    /// Hardened tier, OS attestation passed, messenger not verified.
    OsPassMessengerUnverified,
    Fail,
    Unverified,
    UnknownDevice,
    /// Normal-phone tier, basic checks only. Never a hardened PASS.
    NormalTier,
}

impl Overall {
    pub fn label(self) -> &'static str {
        match self {
            Overall::Pass => "PASS",
            Overall::OsPassMessengerUnverified => "OS PASS, messenger UNVERIFIED",
            Overall::Fail => "FAIL",
            Overall::Unverified => "UNVERIFIED",
            Overall::UnknownDevice => "UNKNOWN DEVICE",
            Overall::NormalTier => warning::NORMAL_TIER_LABEL,
        }
    }

    pub fn exit_code(self) -> i32 {
        use crate::exit;
        match self {
            Overall::Pass => exit::OK,
            Overall::OsPassMessengerUnverified | Overall::Unverified => exit::UNVERIFIED,
            Overall::Fail => exit::FAIL,
            Overall::UnknownDevice => exit::UNKNOWN_DEVICE,
            Overall::NormalTier => exit::NORMAL_TIER,
        }
    }
}

/// Values reported by the device over adb. Not proof.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Reported {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub codename: Option<String>,
    pub android_version: Option<String>,
}

/// Messenger package data read by the agent through PackageManager.
/// The messenger as installed: the signer of its pulled `base.apk` and
/// whether the package manager records that same certificate
/// (`crate::installed`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct MessengerEvidence {
    pub installed: bool,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    #[serde(serialize_with = "ser_hex_list")]
    pub signing_cert_sha256: Vec<Vec<u8>>,
    /// `dumpsys package` records exactly the certificate of the pulled
    /// `base.apk`.
    pub package_manager_agrees: bool,
    /// Why it could not be read, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl MessengerEvidence {
    pub fn from_installed(i: Option<crate::installed::InstalledApk>) -> MessengerEvidence {
        match i {
            None => MessengerEvidence::default(),
            Some(i) => MessengerEvidence {
                installed: true,
                package_manager_agrees: i.package_manager_agrees(),
                version_name: i.version_name,
                version_code: i.version_code.map(|v| v as i64),
                signing_cert_sha256: crate::util::unhex(&i.signer_sha256).into_iter().collect(),
                error: None,
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub chain: Vec<Vec<u8>>,
    pub challenge: Vec<u8>,
    /// Keystore backing the agent requested ("strongbox" or "tee").
    pub agent_keystore: Option<String>,
    /// Why the agent produced no chain, if it did not.
    pub agent_error: Option<String>,
    pub reported: Reported,
    pub messenger: Option<MessengerEvidence>,
}

pub struct ListState<'a, T> {
    pub list: &'a T,
    pub meta: &'a Meta,
}

pub struct Trust<'a> {
    pub anchors: &'a [Anchor],
    pub revocation: ListState<'a, RevocationList>,
    pub grapheneos: ListState<'a, GrapheneOsKeys>,
}

pub struct Policy {
    pub agent_package: String,
    pub agent_digest: Option<Vec<u8>>,
    /// The messenger to check, if one is known (`--messenger-package` or a
    /// fixed `messenger_package`).
    pub messenger_package: Option<String>,
    pub messenger_digest: Option<Vec<u8>>,
    pub revocation_max_age_days: u64,
    pub grapheneos_warn_age_days: u64,
    /// The operator confirmed a PASS on a stale revocation list.
    pub stale_confirmed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListAge {
    /// Where the cached list came from (Tor download or manually placed).
    pub source: String,
    pub fetched_at: String,
    pub age: String,
    pub age_seconds: u64,
    pub last_modified: Option<String>,
    pub threshold_days: u64,
    pub over_threshold: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tier: Tier,
    pub overall: Overall,
    pub overall_label: String,
    /// True when the result rests on a revocation list older than the
    /// threshold (only possible after operator confirmation).
    pub stale_revocation_list: bool,
    pub revocation_list: ListAge,
    pub grapheneos_key_list: ListAge,
    pub reported: Reported,
    pub checks: Vec<Check>,
    pub warnings: Vec<String>,
    pub chain: Option<ChainReport>,
    pub key_description: Option<KeyDescription>,
}

pub fn list_age(meta: &Meta, threshold_days: u64, now: u64) -> ListAge {
    let age = now.saturating_sub(meta.fetched_at);
    ListAge {
        source: meta.source_label(),
        fetched_at: fmt_unix(meta.fetched_at),
        age: fmt_age(age),
        age_seconds: age,
        last_modified: meta.last_modified.clone(),
        threshold_days,
        over_threshold: age > threshold_days * 86_400,
    }
}

/// True if the revocation list is past its threshold and needs confirmation.
pub fn revocation_stale(fetched_at: u64, max_age_days: u64, now: u64) -> bool {
    now.saturating_sub(fetched_at) > max_age_days * 86_400
}

pub fn evaluate(ev: &Evidence, trust: &Trust, policy: &Policy, now: u64) -> Report {
    let rev_age = list_age(trust.revocation.meta, policy.revocation_max_age_days, now);
    let gos_age = list_age(trust.grapheneos.meta, policy.grapheneos_warn_age_days, now);
    let mut warnings = Vec::new();
    if rev_age.over_threshold {
        warnings.push(format!(
            "Google revocation list is {} old (threshold {} days). Run `trust refresh`.",
            rev_age.age, policy.revocation_max_age_days
        ));
    }
    if gos_age.over_threshold {
        warnings.push(format!(
            "GrapheneOS key list is {} old (warning threshold {} days). Run `trust refresh`.",
            gos_age.age, policy.grapheneos_warn_age_days
        ));
    }

    let chain_rep = if ev.chain.is_empty() {
        None
    } else {
        Some(chain::verify(&ev.chain, trust.anchors, now))
    };
    let (kd, kd_err) = match chain_rep.as_ref().and_then(|c| c.key_description.as_ref()) {
        Some(bytes) => match keydesc::parse(bytes) {
            Ok(k) => (Some(k), None),
            Err(e) => (None, Some(e)),
        },
        None => (None, None),
    };
    let chain_ok = chain_rep.as_ref().map(|c| c.ok()).unwrap_or(false) && kd.is_some();
    let rot = kd
        .as_ref()
        .and_then(|k| k.hardware_enforced.root_of_trust.clone());

    let tier = classify(&ev.reported, rot.as_ref(), trust.grapheneos.list);
    let stale = rev_age.over_threshold;

    let mut checks = Vec::new();
    match tier {
        Tier::HardenedPixel => {
            checks.push(check_chain(ev, chain_rep.as_ref(), kd_err.as_deref()));
            checks.push(check_revocation(
                chain_rep.as_ref(),
                trust,
                &rev_age,
                stale,
                policy.stale_confirmed,
            ));
            checks.push(check_challenge(ev, kd.as_ref(), chain_ok));
            checks.push(check_security_level(ev, kd.as_ref(), chain_ok));
            checks.push(check_root_of_trust(
                &ev.reported,
                rot.as_ref(),
                trust,
                chain_ok,
            ));
            checks.push(check_app_identity(kd.as_ref(), policy, chain_ok));
            checks.push(check_patch_levels(kd.as_ref(), chain_ok));
            let os_pass = checks
                .iter()
                .all(|c| matches!(c.status, Status::Pass | Status::Info));
            checks.push(check_messenger(ev.messenger.as_ref(), policy, os_pass));
        }
        Tier::NormalPhone => {
            checks.push(reported_check(
                "model",
                "Model (reported by the device)",
                ev.reported.model.as_deref(),
            ));
            checks.push(reported_check(
                "android_version",
                "Android version (reported by the device)",
                ev.reported.android_version.as_deref(),
            ));
            checks.push(check_messenger(ev.messenger.as_ref(), policy, true));
            checks.push(normal_tier_attestation_info(
                chain_rep.as_ref(),
                kd.as_ref(),
                ev,
            ));
        }
    }

    let overall = overall(tier, &checks);
    if tier == Tier::NormalPhone {
        warnings.push(warning::NORMAL_TIER_WARNING.to_string());
    }
    let stale_pass = stale && matches!(overall, Overall::Pass | Overall::OsPassMessengerUnverified);
    let mut overall_label = overall.label().to_string();
    if stale_pass {
        overall_label = format!("{overall_label} ({})", warning::STALE_REVOCATION_NOTE);
    }
    Report {
        tier,
        overall,
        overall_label,
        stale_revocation_list: stale,
        revocation_list: rev_age,
        grapheneos_key_list: gos_age,
        reported: ev.reported.clone(),
        checks,
        warnings,
        chain: chain_rep,
        key_description: kd,
    }
}

/// Hardened tier: a Pixel (reported manufacturer Google), or any device whose
/// attestation shows SelfSigned or a GrapheneOS key. A Pixel that fails is a
/// hardened-tier FAIL, never silently a normal phone.
fn classify(reported: &Reported, rot: Option<&keydesc::RootOfTrust>, gos: &GrapheneOsKeys) -> Tier {
    let is_pixel = reported
        .manufacturer
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("google"))
        .unwrap_or(false);
    let attested_custom = rot
        .map(|r| {
            r.verified_boot_state == VerifiedBootState::SelfSigned
                || gos.contains(&r.verified_boot_key)
        })
        .unwrap_or(false);
    if is_pixel || attested_custom {
        Tier::HardenedPixel
    } else {
        Tier::NormalPhone
    }
}

fn overall(tier: Tier, checks: &[Check]) -> Overall {
    let any = |s: Status| checks.iter().any(|c| c.status == s);
    if any(Status::Fail) {
        return Overall::Fail;
    }
    if tier == Tier::NormalPhone {
        return Overall::NormalTier;
    }
    if any(Status::UnknownDevice) {
        return Overall::UnknownDevice;
    }
    let os_unverified = checks
        .iter()
        .filter(|c| c.id != "messenger")
        .any(|c| c.status == Status::Unverified);
    if os_unverified {
        return Overall::Unverified;
    }
    match checks
        .iter()
        .find(|c| c.id == "messenger")
        .map(|c| c.status)
    {
        Some(Status::Pass) => Overall::Pass,
        _ => Overall::OsPassMessengerUnverified,
    }
}

fn check(id: &'static str, title: &'static str, status: Status, evidence: Vec<String>) -> Check {
    Check {
        id,
        title,
        status,
        evidence,
    }
}

const UNTRUSTED: &str = "not evaluated: the attestation chain is not trusted";

fn check_chain(ev: &Evidence, rep: Option<&ChainReport>, kd_err: Option<&str>) -> Check {
    let title = "Certificate chain up to a pinned Google root";
    let Some(rep) = rep else {
        let why = ev
            .agent_error
            .clone()
            .unwrap_or_else(|| "the agent returned no chain".into());
        return check(
            "chain",
            title,
            Status::Fail,
            vec![format!("no attestation chain: {why}")],
        );
    };
    let mut e = vec![format!("{} certificates", rep.certs.len())];
    for c in &rep.certs {
        e.push(format!(
            "[{}] serial {} valid {} to {} subject {}",
            c.index, c.serial_hex, c.not_before, c.not_after, c.subject
        ));
    }
    if let Some(a) = &rep.anchor {
        e.push(format!(
            "anchored at pinned root {a} (trust/google-roots, matched by public key)"
        ));
    }
    e.extend(rep.notes.iter().cloned());
    e.extend(rep.errors.iter().cloned());
    if let Some(err) = kd_err {
        e.push(format!("key description cannot be parsed: {err}"));
    }
    let ok = rep.ok() && kd_err.is_none();
    check(
        "chain",
        title,
        if ok { Status::Pass } else { Status::Fail },
        e,
    )
}

fn check_revocation(
    rep: Option<&ChainReport>,
    trust: &Trust,
    age: &ListAge,
    stale: bool,
    confirmed: bool,
) -> Check {
    let title = "Revocation (Google attestation status list)";
    let mut e = vec![format!(
        "list {}; fetched {} ({} ago), Last-Modified {}",
        age.source,
        age.fetched_at,
        age.age,
        age.last_modified.as_deref().unwrap_or("unknown")
    )];
    let Some(rep) = rep.filter(|r| !r.certs.is_empty()) else {
        e.push("no certificates to check".into());
        return check("revocation", title, Status::Unverified, e);
    };
    let mut hit = false;
    for c in &rep.certs {
        if let Some((key, entry)) = trust.revocation.list.lookup(&c.serial_hex, &c.serial_dec) {
            hit = true;
            e.push(format!(
                "certificate {} serial {} is listed as {} (key {key}, reason {}, expires {}, comment {})",
                c.index,
                c.serial_hex,
                entry.status,
                entry.reason.as_deref().unwrap_or("none"),
                entry.expires.as_deref().unwrap_or("none"),
                entry.comment.as_deref().unwrap_or("none")
            ));
        }
    }
    if hit {
        return check("revocation", title, Status::Fail, e);
    }
    e.push(format!(
        "none of {} serials listed (matched as hex and decimal)",
        rep.certs.len()
    ));
    if stale {
        if confirmed {
            e.push(format!("list is STALE; {}", warning::STALE_REVOCATION_NOTE));
            return check("revocation", title, Status::Pass, e);
        }
        e.push("list is STALE and the operator did not confirm".into());
        return check("revocation", title, Status::Unverified, e);
    }
    check("revocation", title, Status::Pass, e)
}

fn check_challenge(ev: &Evidence, kd: Option<&KeyDescription>, chain_ok: bool) -> Check {
    let title = "Challenge matches this run";
    let Some(kd) = kd.filter(|_| chain_ok) else {
        return check(
            "challenge",
            title,
            Status::Unverified,
            vec![UNTRUSTED.into()],
        );
    };
    let e = vec![
        format!("expected {} (created for this run)", hex(&ev.challenge)),
        format!("attested {}", hex(&kd.challenge)),
    ];
    let ok = !ev.challenge.is_empty() && kd.challenge == ev.challenge;
    check(
        "challenge",
        title,
        if ok { Status::Pass } else { Status::Fail },
        e,
    )
}

fn check_security_level(ev: &Evidence, kd: Option<&KeyDescription>, chain_ok: bool) -> Check {
    let title = "Attestation security level (TEE or StrongBox)";
    let Some(kd) = kd.filter(|_| chain_ok) else {
        return check(
            "security_level",
            title,
            Status::Unverified,
            vec![UNTRUSTED.into()],
        );
    };
    let mut e = vec![
        format!(
            "attestationSecurityLevel {}",
            kd.attestation_security_level.label()
        ),
        format!("keyMintSecurityLevel {}", kd.keymint_security_level.label()),
        format!(
            "attestationVersion {}, keyMintVersion {}",
            kd.attestation_version, kd.keymint_version
        ),
    ];
    if let Some(k) = &ev.agent_keystore {
        e.push(format!("agent requested {k}"));
    }
    let hw = |l: SecurityLevel| {
        matches!(
            l,
            SecurityLevel::TrustedEnvironment | SecurityLevel::StrongBox
        )
    };
    let ok = hw(kd.attestation_security_level) && hw(kd.keymint_security_level);
    check(
        "security_level",
        title,
        if ok { Status::Pass } else { Status::Fail },
        e,
    )
}

fn check_root_of_trust(
    reported: &Reported,
    rot: Option<&keydesc::RootOfTrust>,
    trust: &Trust,
    chain_ok: bool,
) -> Check {
    let title = "Root of trust (locked, SelfSigned, official GrapheneOS key)";
    if !chain_ok {
        return check(
            "root_of_trust",
            title,
            Status::Unverified,
            vec![UNTRUSTED.into()],
        );
    }
    let Some(r) = rot else {
        return check(
            "root_of_trust",
            title,
            Status::Fail,
            vec!["no rootOfTrust in the hardware-enforced list".into()],
        );
    };
    let gos = trust.grapheneos.list;
    let mut e = vec![
        format!("deviceLocked {}", r.device_locked),
        format!("verifiedBootState {:?}", r.verified_boot_state),
        format!("verifiedBootKey {}", hex(&r.verified_boot_key)),
        format!(
            "GrapheneOS key list: {} keys, signed timestamp {}, signature checked with trust/grapheneos/allowed_signers",
            gos.keys.len(),
            fmt_unix(gos.timestamp)
        ),
        format!(
            "reported model {} ({}), reported by the device and shown only: the signed list has \
             no model mapping, so the model is not checked",
            reported.model.as_deref().unwrap_or("?"),
            reported.codename.as_deref().unwrap_or("?")
        ),
    ];
    let mut fail = false;
    if !r.device_locked {
        e.push("FAIL: bootloader is unlocked".into());
        fail = true;
    }
    if r.verified_boot_state != VerifiedBootState::SelfSigned {
        e.push(format!(
            "FAIL: verifiedBootState is {:?}, GrapheneOS gives SelfSigned{}",
            r.verified_boot_state,
            if r.verified_boot_state == VerifiedBootState::Verified {
                " (Verified means the stock OS)"
            } else {
                ""
            }
        ));
        fail = true;
    }
    let listed = gos.contains(&r.verified_boot_key);
    if fail {
        return check("root_of_trust", title, Status::Fail, e);
    }
    if !listed {
        e.push(
            "verifiedBootKey is not in the signed GrapheneOS key list: the model may be newer than \
             the list, or the OS is not an official GrapheneOS build. Run `trust refresh` and verify again."
                .into(),
        );
        return check("root_of_trust", title, Status::UnknownDevice, e);
    }
    e.push("verifiedBootKey is an official GrapheneOS key".into());
    check("root_of_trust", title, Status::Pass, e)
}

fn check_app_identity(kd: Option<&KeyDescription>, policy: &Policy, chain_ok: bool) -> Check {
    let title = "App identity (agent package and signing certificate)";
    let Some(kd) = kd.filter(|_| chain_ok) else {
        return check(
            "app_identity",
            title,
            Status::Unverified,
            vec![UNTRUSTED.into()],
        );
    };
    let app = kd
        .software_enforced
        .attestation_application_id
        .as_ref()
        .or(kd.hardware_enforced.attestation_application_id.as_ref());
    let Some(app) = app else {
        return check(
            "app_identity",
            title,
            Status::Fail,
            vec!["no attestationApplicationId".into()],
        );
    };
    let mut e: Vec<String> = app
        .packages
        .iter()
        .map(|p| format!("package {} version {}", p.name, p.version))
        .collect();
    e.extend(
        app.signature_digests
            .iter()
            .map(|d| format!("signature digest {}", hex(d))),
    );
    let pkg_ok = app.packages.len() == 1 && app.packages[0].name == policy.agent_package;
    if !pkg_ok {
        e.push(format!(
            "FAIL: expected exactly the package {}",
            policy.agent_package
        ));
        return check("app_identity", title, Status::Fail, e);
    }
    let Some(want) = &policy.agent_digest else {
        e.push("agent signing digest is not configured (agent_signing_cert_sha256)".into());
        return check("app_identity", title, Status::Unverified, e);
    };
    e.push(format!(
        "expected digest {} (config agent_signing_cert_sha256)",
        hex(want)
    ));
    let ok = app.signature_digests.len() == 1 && &app.signature_digests[0] == want;
    if !ok {
        e.push("FAIL: signing digest does not match".into());
    }
    check(
        "app_identity",
        title,
        if ok { Status::Pass } else { Status::Fail },
        e,
    )
}

fn check_patch_levels(kd: Option<&KeyDescription>, chain_ok: bool) -> Check {
    let title = "OS version and patch levels (shown, no minimum enforced yet)";
    let Some(kd) = kd.filter(|_| chain_ok) else {
        return check(
            "patch_levels",
            title,
            Status::Unverified,
            vec![UNTRUSTED.into()],
        );
    };
    let hw = &kd.hardware_enforced;
    let sw = &kd.software_enforced;
    let show = |name: &str, h: Option<i64>, s: Option<i64>| match (h, s) {
        (Some(v), _) => format!("{name} {v} (hardware-enforced)"),
        (None, Some(v)) => format!("{name} {v} (software-enforced only)"),
        (None, None) => format!("{name} not present"),
    };
    let e = vec![
        show("osVersion", hw.os_version, sw.os_version),
        show("osPatchLevel", hw.os_patch_level, sw.os_patch_level),
        show(
            "vendorPatchLevel",
            hw.vendor_patch_level,
            sw.vendor_patch_level,
        ),
        show("bootPatchLevel", hw.boot_patch_level, sw.boot_patch_level),
    ];
    check("patch_levels", title, Status::Info, e)
}

fn check_messenger(m: Option<&MessengerEvidence>, policy: &Policy, os_pass: bool) -> Check {
    let title = "Messenger package and signature";
    let Some(pkg) = &policy.messenger_package else {
        return check(
            "messenger",
            title,
            Status::Unverified,
            vec!["no messenger package: none given (--messenger-package or a fixed messenger_package), and not exactly one app offers the activation provider".into()],
        );
    };
    let mut e = vec![format!("package {pkg}")];
    if !os_pass {
        e.push("not evaluated: OS attestation did not pass".into());
        return check("messenger", title, Status::Unverified, e);
    }
    let Some(m) = m else {
        e.push("not read".into());
        return check("messenger", title, Status::Unverified, e);
    };
    if let Some(err) = &m.error {
        e.push(format!("installed package not readable: {err}"));
        return check("messenger", title, Status::Unverified, e);
    }
    if !m.installed {
        e.push("not installed".into());
        return check("messenger", title, Status::Unverified, e);
    }
    e.push(format!(
        "versionName {} versionCode {}",
        m.version_name.as_deref().unwrap_or("?"),
        m.version_code
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".into())
    ));
    e.extend(m.signing_cert_sha256.iter().map(|d| {
        format!(
            "signing certificate SHA-256 {} (installed base.apk)",
            hex(d)
        )
    }));
    if !m.package_manager_agrees {
        e.push(
            "FAIL: the package manager records another certificate than the installed base.apk"
                .into(),
        );
        return check("messenger", title, Status::Fail, e);
    }
    e.push("the package manager records the same certificate (dumpsys package)".into());
    let Some(want) = &policy.messenger_digest else {
        e.push("messenger signature: not pinned, UNVERIFIED (messenger_signing_cert_sha256 not configured)".into());
        return check("messenger", title, Status::Unverified, e);
    };
    e.push(format!(
        "expected {} (config messenger_signing_cert_sha256)",
        hex(want)
    ));
    let ok = m.signing_cert_sha256.len() == 1 && &m.signing_cert_sha256[0] == want;
    if !ok {
        e.push("FAIL: signing certificate does not match".into());
    }
    check(
        "messenger",
        title,
        if ok { Status::Pass } else { Status::Fail },
        e,
    )
}

fn reported_check(id: &'static str, title: &'static str, v: Option<&str>) -> Check {
    match v {
        Some(v) => check(id, title, Status::Info, vec![v.to_string()]),
        None => check(id, title, Status::Unverified, vec!["not reported".into()]),
    }
}

fn normal_tier_attestation_info(
    rep: Option<&ChainReport>,
    kd: Option<&KeyDescription>,
    ev: &Evidence,
) -> Check {
    let title = "Attestation (information only on the normal-phone tier)";
    let mut e = Vec::new();
    match (rep, kd) {
        (Some(r), Some(k)) => {
            e.push(format!(
                "chain {} at root {}",
                if r.ok() { "valid" } else { "NOT valid" },
                r.anchor.as_deref().unwrap_or("none")
            ));
            e.push(format!(
                "security level {}",
                k.attestation_security_level.label()
            ));
            if let Some(rot) = &k.hardware_enforced.root_of_trust {
                e.push(format!(
                    "verifiedBootState {:?}, deviceLocked {}",
                    rot.verified_boot_state, rot.device_locked
                ));
            }
        }
        _ => e.push(format!(
            "no usable attestation: {}",
            ev.agent_error
                .as_deref()
                .unwrap_or("chain missing or not parseable")
        )),
    }
    check("attestation_info", title, Status::Info, e)
}

fn ser_hex_list<S: serde::Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for b in v {
        seq.serialize_element(&hex(b))?;
    }
    seq.end()
}
