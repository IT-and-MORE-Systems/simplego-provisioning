// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Reference implementation of the app-side order of checks (format document
//! section 6). `inspect` and the test vectors use it; the apps implement the
//! same order in their own code.

use super::code::Code;
use super::container::{parse, KDF_ARGON2ID, KDF_UPDATE_KEY};
use super::features::Features;
use super::keys::TrustedKey;
use super::payload::{DeviceClass, Kind, Payload, RawPayload};
use super::Refusal;
use zeroize::Zeroizing;

/// What an installation stores after an import.
#[derive(Debug, Clone)]
pub struct Install {
    pub device_class: DeviceClass,
    pub customer_ref: String,
    pub update_key: Zeroizing<[u8; 32]>,
    pub last_sequence: u64,
    /// The installed feature profile (section 12.1), `None` without one.
    pub features: Option<Features>,
}

// Used by the tests and vectors; the apps implement the same steps.
#[cfg_attr(not(test), allow(dead_code))]
impl Install {
    /// Section 6 activation step 7: keep the update key and the activation's
    /// `sequence` as the last applied sequence.
    pub fn from_activation(p: &Payload) -> Result<Install, Refusal> {
        Ok(Install {
            device_class: p.device_class,
            customer_ref: p.customer_ref.clone(),
            update_key: p
                .update_key_bytes()
                .ok_or_else(|| Refusal::BadPayload("update_key".into()))?,
            last_sequence: p.sequence,
            features: p.features.clone(),
        })
    }

    /// Section 6 update step 7. An update without `features` leaves the
    /// installed profile unchanged; with `features` it replaces the whole
    /// profile (section 12.4).
    pub fn apply(&mut self, p: &Payload) {
        self.last_sequence = p.sequence;
        if let Some(k) = p.update_key_bytes() {
            self.update_key = k;
        }
        if let Some(f) = &p.features {
            self.features = Some(f.clone());
        }
    }
}

/// Activation file: steps 1 to 6. Step 6 in the order of the format
/// document (clarified 2026-11-21 11:00): device class, network mode value,
/// server and support address rules.
pub fn import_activation(
    file: &[u8],
    trusted: &[TrustedKey],
    code_input: &str,
    device_class: DeviceClass,
) -> Result<Payload, Refusal> {
    let v = parse(file)?.verify(trusted)?;
    if v.header().kdf_alg != KDF_ARGON2ID {
        return Err(Refusal::NotAnActivationFile);
    }
    let code = Code::parse_input(code_input).map_err(Refusal::BadCode)?;
    let plain = v.decrypt_with_code(&code)?;
    let raw = RawPayload::from_json(&plain)?;
    raw.check_fields(Kind::Activation)?;
    if raw.device_class != device_class {
        return Err(Refusal::DeviceClassMismatch);
    }
    raw.check_class_rules()?;
    let p = raw.into_payload()?;
    p.check_addresses()?;
    Ok(p)
}

/// Update file: steps 1 to 5 (the confirmation of step 6 is the app's):
/// the fields, customer, device class and sequence first, then, as for an
/// activation file, the network mode value and the address rules.
pub fn import_update(
    file: &[u8],
    trusted: &[TrustedKey],
    install: &Install,
) -> Result<Payload, Refusal> {
    let v = parse(file)?.verify(trusted)?;
    if v.header().kdf_alg != KDF_UPDATE_KEY {
        return Err(Refusal::NotAnUpdateFile);
    }
    let plain = v.decrypt_with_update_key(&install.update_key)?;
    let raw = RawPayload::from_json(&plain)?;
    raw.check_fields(Kind::Update)?;
    if raw.customer_ref != install.customer_ref {
        return Err(Refusal::CustomerMismatch);
    }
    if raw.device_class != install.device_class {
        return Err(Refusal::DeviceClassMismatch);
    }
    if raw.sequence <= install.last_sequence {
        return Err(Refusal::ReplayedSequence);
    }
    raw.check_class_rules()?;
    let p = raw.into_payload()?;
    p.check_addresses()?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::container::build_update;
    use crate::activation::keys::Signer;
    use crate::activation::payload::tests::sample;
    use crate::activation::payload::NetworkMode;

    #[test]
    fn update_sequence_and_replay() {
        let s = Signer::from_seed(&[4; 32]).unwrap();
        let trusted = [s.trusted("t")];
        let key = [7u8; 32];
        let mut install = Install {
            device_class: DeviceClass::Phone,
            customer_ref: "TEST-CUSTOMER-0001".into(),
            update_key: Zeroizing::new(key),
            last_sequence: 0,
            features: None,
        };
        let file = |seq: u64, new_key: Option<[u8; 32]>| {
            let mut p = sample(Kind::Update, NetworkMode::TorRequired);
            p.sequence = seq;
            p.update_key = new_key.map(|k| crate::util::hex(&k));
            build_update(&p.to_json(), &key, [seq as u8; 12], &s).unwrap()
        };
        let one = file(1, None);
        let p = import_update(&one, &trusted, &install).unwrap();
        install.apply(&p);
        assert_eq!(install.last_sequence, 1);
        assert_eq!(
            import_update(&one, &trusted, &install).unwrap_err(),
            Refusal::ReplayedSequence
        );
        let three = file(3, Some([8; 32]));
        let p = import_update(&three, &trusted, &install).unwrap();
        install.apply(&p);
        assert_eq!(*install.update_key, [8; 32]);
        // An update under the old key no longer matches the stored key.
        assert_eq!(
            import_update(&file(4, None), &trusted, &install).unwrap_err(),
            Refusal::WrongUpdateKey
        );
        // Another customer or device class under the right key.
        install.update_key = Zeroizing::new(key);
        install.customer_ref = "TEST-CUSTOMER-0002".into();
        assert_eq!(
            import_update(&file(9, None), &trusted, &install).unwrap_err(),
            Refusal::CustomerMismatch
        );
        install.customer_ref = "TEST-CUSTOMER-0001".into();
        install.device_class = DeviceClass::Desktop;
        assert_eq!(
            import_update(&file(9, None), &trusted, &install).unwrap_err(),
            Refusal::DeviceClassMismatch
        );
        assert_eq!(
            import_activation(&one, &trusted, "482913x105377", DeviceClass::Phone).unwrap_err(),
            Refusal::NotAnActivationFile
        );
    }

    /// Section 6 step 6 order (clarified 2026-11-21 11:00): device class,
    /// then the network mode value, then the server and support rules.
    #[test]
    fn order_of_step_6() {
        use crate::activation::code::Code;
        use crate::activation::container::build_activation;
        let s = Signer::from_seed(&[5; 32]).unwrap();
        let trusted = [s.trusted("t")];
        let code = Code::parse_input("482913x105377").unwrap();
        let file = |json: Vec<u8>| build_activation(&json, &code, [3; 16], [4; 12], &s).unwrap();
        let import = |json: Vec<u8>, class| {
            import_activation(&file(json), &trusted, "482913x105377", class).map(|_| ())
        };
        let mut p = sample(Kind::Activation, NetworkMode::TorOptional);
        p.servers.xftp[0] = p.servers.xftp[0].replace(",xftp-a.example.invalid", "");
        let broken_rule = p.to_json();
        let mut bad_mode: serde_json::Value = serde_json::from_slice(&broken_rule).unwrap();
        bad_mode["network_mode"] = "tor".into();
        let bad_mode = bad_mode.to_string().into_bytes();
        let mut bad_fp = p.clone();
        bad_fp.servers.smp[0] = "smp://TEST-ONLY-FINGERPRINT-SMP@smp-a.example.invalid".into();
        // Device class first.
        for j in [&broken_rule, &bad_mode, &bad_fp.to_json()] {
            assert_eq!(
                import(j.clone(), DeviceClass::Desktop).unwrap_err(),
                Refusal::DeviceClassMismatch
            );
        }
        // Then the mode value, before any address rule.
        assert!(
            matches!(import(bad_mode, DeviceClass::Phone), Err(Refusal::BadPayload(e)) if e.contains("network mode must be"))
        );
        // Then the address rules: a fingerprint before the mode rules.
        assert!(
            matches!(import(bad_fp.to_json(), DeviceClass::Phone), Err(Refusal::BadPayload(e)) if e.contains("servers.smp[0]") && e.contains("key hash"))
        );
        assert!(
            matches!(import(broken_rule, DeviceClass::Phone), Err(Refusal::NetworkModeRule(e)) if e.contains("servers.xftp[0]"))
        );
        // A step 5 field error still comes before the device class.
        let mut no_id = sample(Kind::Activation, NetworkMode::TorRequired);
        no_id.file_id = "x".into();
        assert!(
            matches!(import(no_id.to_json(), DeviceClass::Desktop), Err(Refusal::BadPayload(e)) if e.contains("file_id"))
        );
    }
}
