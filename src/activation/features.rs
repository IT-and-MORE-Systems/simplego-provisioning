// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The feature profile, the optional `features` object of the payload
//! (format document section 12.1, amended in 12.4).
//!
//! Optional in the payload, fail closed inside: an unknown switch name, an
//! unknown value, a `null` value, a duplicate key or a missing
//! `profile_version` refuses the whole file. Serde refuses them while the
//! payload is parsed (section 6 step 5), so they are `bad_payload`.
//!
//! `features_profile` is the first 16 lowercase hex characters of SHA-256
//! over the canonical JSON of the object as issued: keys sorted, no spaces,
//! UTF-8, nothing normalized (an explicit `ask` and a missing switch give
//! different values). It is computed from the checked object, never from
//! the bytes of the file.

use super::payload::DeviceClass;
use serde::{Deserialize, Deserializer, Serialize};

pub const PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureValue {
    On,
    Off,
    Ask,
}

impl FeatureValue {
    pub fn as_str(self) -> &'static str {
        match self {
            FeatureValue::On => "on",
            FeatureValue::Off => "off",
            FeatureValue::Ask => "ask",
        }
    }
}

/// A present key must carry a value: `null` is refused, not read as a
/// missing switch.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<FeatureValue>, D::Error> {
    FeatureValue::deserialize(d).map(Some)
}

/// The switches of section 12.1. A missing switch is `None` (not fixed,
/// like `ask`). New names are added to the table of the format document
/// before they are added here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Features {
    pub profile_version: u32,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub groups: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub channels: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub preset_servers: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub calls: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub files: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub voice_messages: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub calculator_disguise: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub laptop_link: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub developer_tools: Option<FeatureValue>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub vault: Option<FeatureValue>,
}

/// Switches that exist only on the desktop (section 12.1 table).
pub const DESKTOP_ONLY: [&str; 3] = ["developer_tools", "laptop_link", "vault"];

impl Features {
    /// Every present switch, sorted by name.
    pub fn switches(&self) -> Vec<(&'static str, FeatureValue)> {
        let all = [
            ("calculator_disguise", self.calculator_disguise),
            ("calls", self.calls),
            ("channels", self.channels),
            ("developer_tools", self.developer_tools),
            ("files", self.files),
            ("groups", self.groups),
            ("laptop_link", self.laptop_link),
            ("preset_servers", self.preset_servers),
            ("vault", self.vault),
            ("voice_messages", self.voice_messages),
        ];
        all.into_iter()
            .filter_map(|(n, v)| v.map(|v| (n, v)))
            .collect()
    }

    /// The value of a switch by name (`None`: missing).
    pub fn get(&self, name: &str) -> Option<FeatureValue> {
        self.switches()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    /// Section 6 step 5: the field rules.
    pub fn check(&self) -> Result<(), String> {
        if self.profile_version != PROFILE_VERSION {
            return Err("features: profile_version must be 1".into());
        }
        Ok(())
    }

    /// Section 6 step 6, after the device class: a switch of another device
    /// class may be `off` or `ask`, never `on`.
    pub fn check_class(&self, class: DeviceClass) -> Result<(), String> {
        if class == DeviceClass::Phone {
            for (name, v) in self.switches() {
                if v == FeatureValue::On && DESKTOP_ONLY.contains(&name) {
                    return Err(format!(
                        "features: {name} exists only on the desktop; a phone file may set it off or ask, not on"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Keys sorted (through `serde_json::Value`, whose map is sorted while
    /// the `preserve_order` feature is off), no spaces, UTF-8.
    pub fn canonical_json(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).unwrap_or_default();
        serde_json::to_vec(&v).unwrap_or_default()
    }

    /// `features_profile`: the first 16 lowercase hex characters of SHA-256
    /// over the canonical JSON.
    pub fn profile(&self) -> String {
        crate::util::hex(&crate::util::sha256(&self.canonical_json()))[..16].to_string()
    }

    /// `features_fixed`: the switches with `on` or `off`, sorted by name, as
    /// `name:value` separated by commas (empty when none is fixed).
    pub fn fixed(&self) -> String {
        self.switches()
            .into_iter()
            .filter(|(_, v)| *v != FeatureValue::Ask)
            .map(|(n, v)| format!("{n}:{}", v.as_str()))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Any switch fixed (`on` or `off`).
    pub fn fixes_any(&self) -> bool {
        !self.fixed().is_empty()
    }

    /// How `self` changes `before` (section 12.1: an update that changes the
    /// profile is shown first, and a switch that goes from `off` to `on` or
    /// `ask` is named explicitly). One line per changed switch; the
    /// unfixing lines first.
    pub fn changes_from(&self, before: Option<&Features>) -> Vec<String> {
        let empty = Features::default();
        let before = before.unwrap_or(&empty);
        let names = [
            "calculator_disguise",
            "calls",
            "channels",
            "developer_tools",
            "files",
            "groups",
            "laptop_link",
            "preset_servers",
            "vault",
            "voice_messages",
        ];
        let show = |v: Option<FeatureValue>| v.map(FeatureValue::as_str).unwrap_or("missing");
        let (mut unfixed, mut other) = (Vec::new(), Vec::new());
        for n in names {
            let (a, b) = (before.get(n), self.get(n));
            if a == b {
                continue;
            }
            let line = format!("{n}: {} -> {}", show(a), show(b));
            if a == Some(FeatureValue::Off) {
                unfixed.push(format!("{line} (NO LONGER FIXED OFF)"));
            } else {
                other.push(line);
            }
        }
        unfixed.extend(other);
        unfixed
    }
}

/// Reads a `--features FILE`: exactly the `features` object of section
/// 12.1, with the same rules as inside a payload.
pub fn parse_features_file(text: &str) -> Result<Features, String> {
    let f: Features =
        super::strict::from_slice(text.as_bytes()).map_err(|e| format!("features file: {e}"))?;
    f.check()?;
    Ok(f)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use FeatureValue::*;

    /// The example of section 12.1.
    pub fn example() -> Features {
        Features {
            profile_version: 1,
            groups: Some(Off),
            channels: Some(Off),
            preset_servers: Some(Off),
            calls: Some(On),
            files: Some(On),
            voice_messages: Some(On),
            calculator_disguise: Some(On),
            ..Features::default()
        }
    }

    #[test]
    fn canonical_form_and_profile() {
        let f = example();
        assert_eq!(
            String::from_utf8(f.canonical_json()).unwrap(),
            r#"{"calculator_disguise":"on","calls":"on","channels":"off","files":"on","groups":"off","preset_servers":"off","profile_version":1,"voice_messages":"on"}"#
        );
        // Computed in Step 0 with serde_json 1.0.154 from the same string.
        assert_eq!(f.profile(), "82c3232f78958958");
        assert_eq!(
            f.fixed(),
            "calculator_disguise:on,calls:on,channels:off,files:on,groups:off,preset_servers:off,voice_messages:on"
        );
        // A struct alone would serialize in declaration order.
        let direct = String::from_utf8(serde_json::to_vec(&f).unwrap()).unwrap();
        assert!(
            direct.starts_with(r#"{"profile_version":1,"groups""#),
            "{direct}"
        );
        // ask and missing mean the same but hash differently (12.4).
        let mut ask = f.clone();
        ask.vault = Some(Ask);
        assert_ne!(ask.profile(), f.profile());
        assert_eq!(ask.fixed(), f.fixed());
        let none = Features {
            profile_version: 1,
            ..Features::default()
        };
        assert_eq!(none.canonical_json(), br#"{"profile_version":1}"#);
        assert_eq!(none.fixed(), "");
        assert!(!none.fixes_any());
    }

    #[test]
    fn fail_closed_reading() {
        let ok = r#"{"profile_version":1,"groups":"off","vault":"ask"}"#;
        let f = parse_features_file(ok).unwrap();
        assert_eq!(f.groups, Some(Off));
        assert_eq!(f.calls, None);
        for (bad, want) in [
            (r#"{"profile_version":1,"group":"off"}"#, "unknown field"),
            (
                r#"{"profile_version":1,"groups":"maybe"}"#,
                "unknown variant",
            ),
            (r#"{"profile_version":1,"groups":"OFF"}"#, "unknown variant"),
            (r#"{"profile_version":1,"groups":null}"#, "expected value"),
            (r#"{"profile_version":1,"groups":false}"#, "expected value"),
            (
                r#"{"profile_version":1,"groups":"off","groups":"on"}"#,
                "duplicate field",
            ),
            (r#"{"groups":"off"}"#, "missing field `profile_version`"),
            (r#"{"profile_version":1.0}"#, "invalid type"),
            (r#"{"profile_version":"1"}"#, "invalid type"),
            (r#"{"profile_version":-1}"#, "invalid value"),
            (r#"{"profile_version":2}"#, "profile_version must be 1"),
            (r#"[]"#, "expected a JSON object"),
            (r#"[1,"off"]"#, "expected a JSON object"),
        ] {
            let e = parse_features_file(bad).unwrap_err();
            assert!(e.contains(want), "{bad}: {e}");
        }
    }

    #[test]
    fn device_class_rule() {
        let mut f = example();
        for name in DESKTOP_ONLY {
            for (v, phone_ok) in [(On, false), (Off, true), (Ask, true)] {
                let mut g = f.clone();
                match name {
                    "developer_tools" => g.developer_tools = Some(v),
                    "laptop_link" => g.laptop_link = Some(v),
                    _ => g.vault = Some(v),
                }
                assert_eq!(
                    g.check_class(DeviceClass::Phone).is_ok(),
                    phone_ok,
                    "{name} {v:?}"
                );
                assert!(g.check_class(DeviceClass::Desktop).is_ok());
            }
        }
        f.groups = Some(On);
        assert!(f.check_class(DeviceClass::Phone).is_ok());
    }

    #[test]
    fn change_summary() {
        let before = example();
        let mut after = example();
        after.groups = Some(Ask);
        after.calls = Some(Off);
        after.files = None;
        let c = after.changes_from(Some(&before));
        assert_eq!(
            c,
            vec![
                "groups: off -> ask (NO LONGER FIXED OFF)".to_string(),
                "calls: on -> off".to_string(),
                "files: on -> missing".to_string(),
            ]
        );
        assert!(before.changes_from(Some(&before)).is_empty());
        assert_eq!(example().changes_from(None).len(), 7);
    }
}
