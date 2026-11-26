// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The device side of `verify`, shared with `deliver`: load the trust
//! material, run the agent once (attestation), read the messenger as
//! installed (its pulled `base.apk` and the package manager's record, not
//! through the agent), and evaluate. The same function serves both commands, so a delivery's
//! attestation is exactly the one `verify` reports.

use crate::attest::chain::Anchor;
use crate::config::Config;
use crate::device::{self, parse::Listed, DeviceInfo, Tools};
use crate::trust::cache::{Cache, Loaded, GOS_FILE, REVOCATION_FILE};
use crate::trust::lists::{GrapheneOsKeys, RevocationList};
use crate::verify::{self, Overall, Report, Tier};
use crate::{agent, exit, names, trust};

pub struct TrustMaterial {
    pub anchors: Vec<Anchor>,
    pub rev: Loaded<RevocationList>,
    pub gos: Loaded<GrapheneOsKeys>,
}

pub fn load_trust(cfg: &Config) -> Result<TrustMaterial, (i32, String)> {
    let anchors = trust::google_roots().map_err(|e| {
        (
            exit::TRUST_MISSING,
            format!("embedded Google roots invalid: {e}"),
        )
    })?;
    let cache = Cache::new(&cfg.trust_cache_dir);
    let rev = cache.load_revocation().map_err(|e| {
        (
            exit::TRUST_MISSING,
            format!(
                "refusing to verify: no usable revocation list ({REVOCATION_FILE}: {e}). Run `{} trust refresh`.",
                names::BINARY
            ),
        )
    })?;
    let gos = cache.load_grapheneos().map_err(|e| {
        (
            exit::TRUST_MISSING,
            format!(
                "refusing to verify: no usable GrapheneOS key list ({GOS_FILE}: {e}). Run `{} trust refresh`.",
                names::BINARY
            ),
        )
    })?;
    Ok(TrustMaterial { anchors, rev, gos })
}

impl TrustMaterial {
    pub fn revocation_stale(&self, cfg: &Config, now: u64) -> bool {
        verify::revocation_stale(self.rev.meta.fetched_at, cfg.revocation_max_age_days, now)
    }
}

pub struct Attested {
    pub info: DeviceInfo,
    pub report: Report,
    pub log: Vec<String>,
}

impl Attested {
    /// Hardened tier and every OS check passed (the messenger check aside).
    pub fn os_pass(&self) -> bool {
        self.report.tier == Tier::HardenedPixel
            && matches!(
                self.report.overall,
                Overall::Pass | Overall::OsPassMessengerUnverified
            )
    }
}

/// Describes the device, runs the agent with `challenge` (the agent is
/// installed and removed again), reads `messenger_package` as installed (its
/// `base.apk` is pulled into a private temporary folder) and evaluates the
/// evidence.
#[allow(clippy::too_many_arguments)]
pub fn attest(
    tools: &Tools,
    target: &Listed,
    cfg: &Config,
    tm: &TrustMaterial,
    challenge: Vec<u8>,
    now: u64,
    stale_confirmed: bool,
    messenger_package: Option<&str>,
) -> Result<Attested, (i32, String)> {
    if cfg.agent_apk.is_empty() || !std::path::Path::new(&cfg.agent_apk).is_file() {
        return Err((
            exit::CONFIG,
            format!("agent_apk {:?} is not a file", cfg.agent_apk),
        ));
    }
    let info = device::describe(tools, target, messenger_package);
    let reported = verify::Reported {
        manufacturer: info.manufacturer.clone(),
        model: info.model.clone(),
        codename: info.codename.clone(),
        android_version: info.android_version.clone(),
    };
    let session = agent::Session {
        tools,
        serial: &target.serial,
        agent_package: &cfg.agent_package,
    };
    let mut log = Vec::new();
    let agent_result = session.run(&cfg.agent_apk, &challenge, &mut log);
    let (chain, keystore, agent_error) = match agent_result {
        Ok(r) => (r.chain, r.keystore, r.error),
        Err(e) => (Vec::new(), None, Some(e)),
    };
    let messenger = messenger_package.map(|pkg| {
        let read = crate::deliver_cmd::WorkDir::new()
            .and_then(|w| crate::installed::read(tools, &target.serial, pkg, &w.0));
        match read {
            Ok(i) => verify::MessengerEvidence::from_installed(i),
            Err(e) => verify::MessengerEvidence {
                error: Some(e),
                ..Default::default()
            },
        }
    });
    let ev = verify::Evidence {
        chain,
        challenge,
        agent_keystore: keystore,
        agent_error,
        reported,
        messenger,
    };
    let trust_in = verify::Trust {
        anchors: &tm.anchors,
        revocation: verify::ListState {
            list: &tm.rev.value,
            meta: &tm.rev.meta,
        },
        grapheneos: verify::ListState {
            list: &tm.gos.value,
            meta: &tm.gos.meta,
        },
    };
    let policy = verify::Policy {
        agent_package: cfg.agent_package.clone(),
        agent_digest: cfg.agent_digest(),
        messenger_package: messenger_package.map(str::to_string),
        messenger_digest: cfg.messenger_digest(),
        revocation_max_age_days: cfg.revocation_max_age_days,
        grapheneos_warn_age_days: cfg.grapheneos_keys_warn_age_days,
        stale_confirmed,
    };
    let report = verify::evaluate(&ev, &trust_in, &policy, now);
    Ok(Attested { info, report, log })
}
