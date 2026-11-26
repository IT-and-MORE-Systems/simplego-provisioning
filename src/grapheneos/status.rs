// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The installed GrapheneOS version compared with the channel files.
//!
//! The build is matched by its build time (`ro.build.date.utc`, the second
//! field of a channel file) and version (`ro.build.version.incremental`):
//! equal to the release file is a `release` build, equal to the security
//! preview file a `security preview` build. Everything the phone reports
//! here is reported, not attested; `verify` proves the OS.

use super::channel::{ChannelInfo, Release};
use super::ReleaseSetting;
use crate::util::{fmt_age, fmt_unix};
use serde::Serialize;
use std::collections::BTreeMap;

const DAY: u64 = 86_400;

/// What the phone reports about its OS (from `getprop`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Installed {
    pub codename: Option<String>,
    pub version: Option<String>,
    pub build_time: Option<u64>,
    pub display_id: Option<String>,
    pub security_patch: Option<String>,
    pub bootloader_locked: Option<bool>,
}

impl Installed {
    pub fn from_props(p: &BTreeMap<String, String>) -> Installed {
        let g = |k: &str| p.get(k).filter(|v| !v.is_empty()).cloned();
        Installed {
            codename: g("ro.product.device"),
            version: g("ro.build.version.incremental"),
            build_time: g("ro.build.date.utc").and_then(|v| v.parse().ok()),
            display_id: g("ro.build.display.id"),
            security_patch: g("ro.build.version.security_patch"),
            bootloader_locked: g("ro.boot.flash.locked").map(|v| v == "1"),
        }
    }

    /// GrapheneOS as reported: the build number has the release format
    /// (ten digits) and is the incremental version.
    pub fn looks_grapheneos(&self) -> bool {
        match (&self.display_id, &self.version) {
            (Some(d), Some(v)) => d == v && super::valid_version(v) && self.build_time.is_some(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildType {
    /// The channel's release build.
    Release,
    /// The security preview build of the channel's release.
    SecurityPreview,
    /// GrapheneOS, but neither current file names this build.
    NotInChannel,
    NotGrapheneOs,
    /// No channel file to compare with.
    Unknown,
}

impl BuildType {
    pub fn as_str(self) -> &'static str {
        match self {
            BuildType::Release => "release",
            BuildType::SecurityPreview => "security preview",
            BuildType::NotInChannel => "not in the current channel files",
            BuildType::NotGrapheneOs => "not GrapheneOS",
            BuildType::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    UpToDate,
    UpdateAvailable,
    Unknown,
    NotGrapheneOs,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsStatus {
    pub installed: Installed,
    pub grapheneos: bool,
    pub build_type: BuildType,
    pub build_type_label: &'static str,
    pub channel: String,
    pub release_setting: &'static str,
    pub stable: Option<ChannelInfo>,
    pub security_preview: Option<ChannelInfo>,
    /// The build the setting asks for and its type.
    pub target: Option<ChannelInfo>,
    pub target_build_type: Option<&'static str>,
    pub outcome: Outcome,
    /// "up to date", "update available (N days behind)", "unknown (offline)" ...
    pub result: String,
    pub days_behind: Option<u64>,
    /// Days behind the channel's release (the `deliver` age rule).
    pub days_behind_stable: Option<u64>,
    pub stable_source: String,
    pub preview_source: String,
    pub offline: bool,
}

pub fn evaluate(
    inst: &Installed,
    rel: &Release,
    channel: &str,
    setting: ReleaseSetting,
    now: u64,
) -> OsStatus {
    let mut s = OsStatus {
        installed: inst.clone(),
        grapheneos: inst.looks_grapheneos(),
        build_type: BuildType::Unknown,
        build_type_label: BuildType::Unknown.as_str(),
        channel: channel.into(),
        release_setting: setting.as_str(),
        stable: rel.stable.info.clone(),
        security_preview: rel.preview.info.clone(),
        target: None,
        target_build_type: None,
        outcome: Outcome::Unknown,
        result: String::new(),
        days_behind: None,
        days_behind_stable: None,
        stable_source: rel.stable.source(now),
        preview_source: if rel.preview.absent {
            format!("no security preview file ({})", rel.preview.source(now))
        } else {
            rel.preview.source(now)
        },
        offline: rel.stable.offline,
    };
    if !s.grapheneos {
        s.build_type = BuildType::NotGrapheneOs;
        s.build_type_label = s.build_type.as_str();
        s.outcome = Outcome::NotGrapheneOs;
        s.result = format!(
            "not GrapheneOS (the phone reports {})",
            inst.display_id.as_deref().unwrap_or("no build number")
        );
        return s;
    }
    let (v, t) = (
        inst.version.clone().unwrap_or_default(),
        inst.build_time.unwrap_or(0),
    );
    let Some((target, target_preview)) = rel.target(setting) else {
        s.result = if rel.stable.offline {
            "unknown (offline)".into()
        } else {
            format!(
                "unknown ({})",
                rel.stable.error.as_deref().unwrap_or("no channel file")
            )
        };
        return s;
    };
    let is = |c: &Option<ChannelInfo>| {
        c.as_ref()
            .is_some_and(|c| c.version == v && c.build_time == t)
    };
    s.build_type = if is(&s.stable) {
        BuildType::Release
    } else if is(&s.security_preview) {
        BuildType::SecurityPreview
    } else {
        BuildType::NotInChannel
    };
    s.build_type_label = s.build_type.as_str();
    s.target_build_type = Some(if target_preview {
        BuildType::SecurityPreview.as_str()
    } else {
        BuildType::Release.as_str()
    });
    let stable_time = s.stable.as_ref().map(|c| c.build_time).unwrap_or(0);
    s.days_behind_stable = Some(stable_time.saturating_sub(t) / DAY);
    s.target = Some(target.clone());
    if t >= target.build_time {
        s.outcome = Outcome::UpToDate;
        s.days_behind = Some(0);
        s.result = match (s.build_type, setting) {
            (BuildType::SecurityPreview, ReleaseSetting::Stable) => {
                "up to date (security preview, newer than stable)".into()
            }
            (BuildType::SecurityPreview, ReleaseSetting::Newest) => {
                "up to date (security preview)".into()
            }
            (BuildType::Release, _) => "up to date".into(),
            _ => "up to date (newer than the channel files; build not listed there)".into(),
        };
    } else {
        let days = (target.build_time - t) / DAY;
        s.outcome = Outcome::UpdateAvailable;
        s.days_behind = Some(days);
        s.result = format!(
            "update available ({days} days behind): {} {}",
            if target_preview {
                "security preview"
            } else {
                "release"
            },
            target.version
        );
    }
    if s.offline {
        s.result.push_str(" (offline: cached channel file)");
    }
    s
}

/// The status lines printed by `os status`, `verify` and `deliver`.
pub fn lines(s: &OsStatus, now: u64) -> Vec<String> {
    let i = &s.installed;
    let mut l = vec![format!(
        "GrapheneOS status (reported by the phone, not attested): {}",
        s.result
    )];
    l.push(format!(
        "  installed: {} {} ({}), build time {}, build type {}, patch level {}",
        i.codename.as_deref().unwrap_or("?"),
        i.version.as_deref().unwrap_or("?"),
        i.display_id.as_deref().unwrap_or("?"),
        i.build_time.map(fmt_unix).unwrap_or_else(|| "?".into()),
        s.build_type_label,
        i.security_patch.as_deref().unwrap_or("?")
    ));
    let show = |c: &Option<ChannelInfo>| {
        c.as_ref()
            .map(|c| format!("{} (built {})", c.version, fmt_unix(c.build_time)))
            .unwrap_or_else(|| "none".into())
    };
    l.push(format!(
        "  channel {}: release {}; security preview {}; setting grapheneos_release = {}",
        s.channel,
        show(&s.stable),
        show(&s.security_preview),
        s.release_setting
    ));
    if let Some(t) = &s.target {
        l.push(format!(
            "  current build for this setting: {} {}",
            s.target_build_type.unwrap_or("?"),
            t.version
        ));
    }
    l.push(format!("  release file: {}", s.stable_source));
    l.push(format!("  security preview file: {}", s.preview_source));
    if s.offline {
        if let Some(t) = &s.stable {
            l.push(format!(
                "  note: offline; the result is against the cached channel file ({} old build {})",
                fmt_age(now.saturating_sub(t.build_time)),
                t.version
            ));
        }
    }
    l
}

#[cfg(test)]
mod tests {
    use super::super::channel::Lookup;
    use super::*;

    fn lookup(info: Option<(&str, u64, &str)>, offline: bool, absent: bool) -> Lookup {
        Lookup {
            name: "x".into(),
            url: "https://releases.grapheneos.org/x".into(),
            info: info.map(|(v, t, ch)| ChannelInfo {
                version: v.into(),
                build_time: t,
                codename: "bluejay".into(),
                channel: ch.into(),
            }),
            absent,
            offline,
            fetched_at: if offline && info.is_none() {
                None
            } else {
                Some(1_795_000_000)
            },
            last_modified: None,
            error: None,
        }
    }

    fn rel(preview: bool) -> Release {
        Release {
            stable: lookup(Some(("2026111800", 1_794_968_526, "stable")), false, false),
            preview: if preview {
                lookup(
                    Some(("2026111801", 1_794_968_527, "stable-security-preview")),
                    false,
                    false,
                )
            } else {
                lookup(None, false, true)
            },
        }
    }

    fn phone(v: &str, t: u64) -> Installed {
        Installed {
            codename: Some("bluejay".into()),
            version: Some(v.into()),
            build_time: Some(t),
            display_id: Some(v.into()),
            security_patch: Some("2026-11-05".into()),
            bootloader_locked: Some(true),
        }
    }

    const NOW: u64 = 1_795_000_000;

    #[test]
    fn preview_phone_with_both_settings() {
        let p = phone("2026111801", 1_794_968_527);
        let s = evaluate(&p, &rel(true), "stable", ReleaseSetting::Stable, NOW);
        assert_eq!(s.build_type, BuildType::SecurityPreview);
        assert_eq!(s.result, "up to date (security preview, newer than stable)");
        assert_eq!(s.outcome, Outcome::UpToDate);
        let s = evaluate(&p, &rel(true), "stable", ReleaseSetting::Newest, NOW);
        assert_eq!(s.result, "up to date (security preview)");
        assert_eq!(s.target_build_type, Some("security preview"));
        assert!(lines(&s, NOW)
            .iter()
            .any(|l| l.contains("build type security preview")));
    }

    #[test]
    fn release_phone_and_old_phone() {
        let p = phone("2026111800", 1_794_968_526);
        let s = evaluate(&p, &rel(true), "stable", ReleaseSetting::Stable, NOW);
        assert_eq!(
            (s.build_type, s.result.as_str()),
            (BuildType::Release, "up to date")
        );
        // With `newest` the preview is the current build, one second newer.
        let s = evaluate(&p, &rel(true), "stable", ReleaseSetting::Newest, NOW);
        assert_eq!(s.outcome, Outcome::UpdateAvailable);
        assert_eq!(
            s.result,
            "update available (0 days behind): security preview 2026111801"
        );
        assert_eq!(s.days_behind_stable, Some(0));
        // No preview file: newest is the release.
        let s = evaluate(&p, &rel(false), "stable", ReleaseSetting::Newest, NOW);
        assert_eq!(s.result, "up to date");
        // 40 days old.
        let old = phone("2026100900", 1_794_968_526 - 40 * DAY);
        let s = evaluate(&old, &rel(true), "stable", ReleaseSetting::Stable, NOW);
        assert_eq!(s.build_type, BuildType::NotInChannel);
        assert_eq!(
            s.result,
            "update available (40 days behind): release 2026111800"
        );
        assert_eq!(s.days_behind_stable, Some(40));
    }

    #[test]
    fn not_grapheneos_and_offline() {
        let mut stock = phone("14213454", 1_794_968_526);
        stock.display_id = Some("BP2A.250605.031".into());
        let s = evaluate(&stock, &rel(true), "stable", ReleaseSetting::Newest, NOW);
        assert_eq!(s.outcome, Outcome::NotGrapheneOs);
        assert_eq!(
            s.result,
            "not GrapheneOS (the phone reports BP2A.250605.031)"
        );
        let off = Release {
            stable: lookup(None, true, false),
            preview: lookup(None, true, false),
        };
        let p = phone("2026111801", 1_794_968_527);
        let s = evaluate(&p, &off, "stable", ReleaseSetting::Newest, NOW);
        assert_eq!(s.result, "unknown (offline)");
        assert_eq!(s.outcome, Outcome::Unknown);
        let cached = Release {
            stable: lookup(Some(("2026111800", 1_794_968_526, "stable")), true, false),
            preview: lookup(None, true, true),
        };
        let s = evaluate(&p, &cached, "stable", ReleaseSetting::Stable, NOW);
        assert!(
            s.result.ends_with("(offline: cached channel file)"),
            "{}",
            s.result
        );
        assert_eq!(s.build_type, BuildType::NotInChannel);
    }
}
