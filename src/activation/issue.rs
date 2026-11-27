// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Issuing activation and update files against the admin store. No prompts
//! here: the CLI asks for passphrases and passes an unlocked signer.
//!
//! Every built file is checked once more with the reference import before
//! it is returned. The store data is only changed when everything succeeded.

use super::code::Code;
use super::container::{build_activation, build_update, update_key_id};
use super::directory::{Directory, DirectoryInput, Role};
use super::features::Features;
use super::import::{import_activation, import_update, Install};
use super::keys::{is_test_key, Signer};
use super::payload::{is_valid_customer_ref, DeviceClass, Kind, NetworkMode, Payload, Servers};
use super::rng::{bytes, Rand};
use super::store::{
    Customer, DirectoryDevice, DirectorySet, FeatureProfiles, Issue, PreviousKey, StoreData,
};
use crate::util::{hex, mask_serial, unhex};
use zeroize::Zeroizing;

pub struct Request {
    pub customer_ref: String,
    pub device_class: DeviceClass,
    pub network_mode: NetworkMode,
    pub smp: Vec<String>,
    pub xftp: Vec<String>,
    pub support_address: String,
    pub serial: Option<String>,
    /// `--features FILE`: replaces the customer's stored profile for this
    /// device class. Without it the stored profile, if any, is written.
    pub features: Option<Features>,
    /// `--directory FILE`, activation files only; needs `serial`.
    pub directory: Option<DirectoryInput>,
}

/// The feature profile a file for this request carries: the given one, or
/// the customer's stored one for the device class (section 12.1).
pub fn features_for(data: &StoreData, req: &Request) -> Option<Features> {
    req.features.clone().or_else(|| {
        data.customers
            .get(&req.customer_ref)
            .and_then(|c| c.features.get(req.device_class).cloned())
    })
}

/// How `--features` changes the stored profile, one line per switch, the
/// unfixed `off` switches first and named (section 12.1). Empty without
/// `--features` or without a change.
pub fn features_change(data: &StoreData, req: &Request) -> Vec<String> {
    let Some(new) = &req.features else {
        return Vec::new();
    };
    let old = data
        .customers
        .get(&req.customer_ref)
        .and_then(|c| c.features.get(req.device_class));
    new.changes_from(old)
}

/// The directory checks against the customer's set (section 12.2, store
/// kept minimal): the same groups for every device, exactly one owner.
/// Returns the set's id, or `None` when a new set is created.
fn directory_set_id(
    data: &StoreData,
    req: &Request,
    d: &DirectoryInput,
) -> Result<Option<String>, String> {
    let serial = req
        .serial
        .as_deref()
        .ok_or("--directory needs --serial (the device of the directory entry)")?;
    let Some(set) = data
        .customers
        .get(&req.customer_ref)
        .and_then(|c| c.directory_set.as_ref())
    else {
        return Ok(None);
    };
    if set.groups_sha256 != Directory::groups_sha256(&d.groups) {
        return Err(format!(
            "the groups differ from the {} group(s) of customer {}'s directory set ({} device(s) issued); every device of a set gets the same groups in the same order",
            set.groups,
            req.customer_ref,
            set.devices.len()
        ));
    }
    if d.role == Role::Owner {
        if let Some(o) = set
            .devices
            .iter()
            .find(|x| x.role == Role::Owner && x.serial != serial)
        {
            return Err(format!(
                "customer {}'s directory set already has an owner device ({}); a set has exactly one owner",
                req.customer_ref,
                mask_serial(&o.serial)
            ));
        }
    }
    Ok(Some(set.set_id.clone()))
}

pub struct Issued {
    pub file: Vec<u8>,
    /// Only for activation files. Shown once, never stored.
    pub code: Option<Code>,
    pub issue: Issue,
}

/// `--servers` file: one `smp://` or `xftp://` address per line, empty lines
/// and `#` lines ignored. Errors never echo a line (it holds a password).
pub fn parse_servers_file(text: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let (mut smp, mut xftp) = (Vec::new(), Vec::new());
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with("smp://") {
            smp.push(l.to_string());
        } else if l.starts_with("xftp://") {
            xftp.push(l.to_string());
        } else {
            return Err(format!(
                "servers file line {}: expected an smp:// or xftp:// address",
                n + 1
            ));
        }
    }
    Ok((smp, xftp))
}

/// `--support` file: the support address on one line.
pub fn parse_support_file(text: &str) -> Result<String, String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    match lines.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err("support file: no address".into()),
        _ => Err("support file: more than one address".into()),
    }
}

fn refuse_test_key(signer: &Signer) -> Result<(), String> {
    if is_test_key(&signer.public()) {
        return Err("refusing the TEST ONLY signing key: files for customers need the real activation signing key".into());
    }
    Ok(())
}

fn key_bytes(hex_key: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let v = Zeroizing::new(unhex(hex_key).ok_or("damaged update key in the store")?);
    if v.len() != 32 {
        return Err("damaged update key in the store".into());
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&v);
    Ok(k)
}

#[allow(clippy::too_many_arguments)]
fn payload(
    req: &Request,
    kind: Kind,
    file_id: String,
    issued_at: &str,
    update_key: Option<String>,
    sequence: u64,
    features: Option<Features>,
    directory: Option<Directory>,
) -> Payload {
    Payload {
        payload_version: 1,
        kind,
        file_id,
        issued_at: issued_at.to_string(),
        customer_ref: req.customer_ref.clone(),
        device_class: req.device_class,
        network_mode: req.network_mode,
        servers: Servers {
            smp: req.smp.clone(),
            xftp: req.xftp.clone(),
        },
        support_address: req.support_address.clone(),
        update_key,
        sequence,
        features,
        directory,
    }
}

/// Checks the request alone (customer reference, addresses, mode rules,
/// the given feature profile and directory with every rule of section 12)
/// before any passphrase is asked.
pub fn precheck(req: &Request, kind: Kind) -> Result<(), String> {
    if !is_valid_customer_ref(&req.customer_ref) {
        return Err("customer reference: only A-Z a-z 0-9 -, 1 to 32 characters".into());
    }
    if req.directory.is_some() {
        if kind == Kind::Update {
            return Err(
                "--directory is for activation files only; an update never carries a directory"
                    .into(),
            );
        }
        if req.serial.is_none() {
            return Err("--directory needs --serial (the device of the directory entry)".into());
        }
    }
    let p = payload(
        req,
        kind,
        "0".repeat(32),
        "2026-01-01T00:00:00Z",
        Some("0".repeat(64)),
        1,
        req.features.clone(),
        req.directory
            .as_ref()
            .map(|d| d.to_directory(&"0".repeat(32))),
    );
    p.validate(kind).map_err(|e| e.to_string())
}

pub fn activation(
    data: &mut StoreData,
    req: &Request,
    signer: &Signer,
    rng: &mut dyn Rand,
    issued_at: &str,
) -> Result<Issued, String> {
    refuse_test_key(signer)?;
    activation_signed(data, req, signer, rng, issued_at)
}

/// For a test file only (`sxprov deliver --test-delivery` and `activation
/// issue --test-delivery`, both with `allow_test_key_for_test_deliveries`):
/// requires the TEST ONLY key and refuses every other key, so a real key can
/// never sign a test file. The code is the fixed lab code
/// (`code::LAB_CODE`), never a random one.
pub fn activation_test_delivery(
    data: &mut StoreData,
    req: &Request,
    signer: &Signer,
    rng: &mut dyn Rand,
    issued_at: &str,
) -> Result<Issued, String> {
    if !is_test_key(&signer.public()) {
        return Err(
            "a test delivery is signed only with the TEST ONLY key; refusing this key".into(),
        );
    }
    activation_signed(data, req, signer, rng, issued_at)
}

/// The code follows the key, not the caller: a file signed with the TEST
/// ONLY key always gets the fixed lab code, a file signed with any other
/// key never does.
fn activation_signed(
    data: &mut StoreData,
    req: &Request,
    signer: &Signer,
    rng: &mut dyn Rand,
    issued_at: &str,
) -> Result<Issued, String> {
    let lab_code = is_test_key(&signer.public());
    precheck(req, Kind::Activation)?;
    let existing = data.customers.get(&req.customer_ref);
    let (key_hex, sequence) = match existing {
        Some(c) => (Zeroizing::new(c.update_key.clone()), c.last_sequence),
        None => (Zeroizing::new(hex(&*Zeroizing::new(bytes::<32>(rng)?))), 0),
    };
    let key = key_bytes(&key_hex)?;
    let code = if lab_code {
        Code::lab()
    } else {
        Code::generate(rng)?
    };
    let file_id = hex(&bytes::<16>(rng)?);
    let features = features_for(data, req);
    // Drawn only with a directory, so files without one come from the same
    // random sequence as before.
    let set_id = match &req.directory {
        Some(d) => Some(match directory_set_id(data, req, d)? {
            Some(id) => (id, false),
            None => (hex(&bytes::<16>(rng)?), true),
        }),
        None => None,
    };
    let directory = match (&req.directory, &set_id) {
        (Some(d), Some((id, _))) => Some(d.to_directory(id)),
        _ => None,
    };
    let p = payload(
        req,
        Kind::Activation,
        file_id,
        issued_at,
        Some(key_hex.to_string()),
        sequence,
        features.clone(),
        directory,
    );
    p.validate(Kind::Activation).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(p.to_json());
    let file = build_activation(&plain, &code, bytes(rng)?, bytes(rng)?, signer)?;
    let canon = Zeroizing::new(String::from_utf8_lossy(code.canonical()).to_string());
    let back = import_activation(&file, &[signer.trusted("signer")], &canon, req.device_class)
        .map_err(|e| format!("self-check of the new file failed: {e}"))?;
    if back != p {
        return Err("self-check of the new file failed: payload differs".into());
    }
    let issue = Issue {
        file_id: p.file_id.clone(),
        kind: Kind::Activation,
        customer_ref: req.customer_ref.clone(),
        device_class: req.device_class,
        network_mode: req.network_mode,
        issued_at: issued_at.to_string(),
        key_id: hex(&signer.key_id()),
        sequence,
        update_key_id: hex(&update_key_id(&key)),
        rotated: false,
        serial: req.serial.clone(),
        code_masked: Some(code.masked()),
        features_profile: features.as_ref().map(Features::profile),
        features_fixed: features.as_ref().map(Features::fixed),
        directory_role: req.directory.as_ref().map(|d| d.role),
    };
    if existing.is_none() {
        data.customers.insert(
            req.customer_ref.clone(),
            Customer {
                update_key: key_hex.to_string(),
                previous_update_keys: Vec::new(),
                last_sequence: 0,
                created_at: issued_at.to_string(),
                features: FeatureProfiles::default(),
                directory_set: None,
            },
        );
    }
    let c = data
        .customers
        .get_mut(&req.customer_ref)
        .ok_or("customer disappeared")?;
    if let Some(f) = &req.features {
        c.features.set(req.device_class, f.clone());
    }
    if let (Some(d), Some((set_id, new))) = (&req.directory, set_id) {
        if new {
            c.directory_set = Some(DirectorySet {
                set_id,
                groups_sha256: Directory::groups_sha256(&d.groups),
                groups: d.groups.len(),
                created_at: issued_at.to_string(),
                devices: Vec::new(),
            });
        }
        let serial = req.serial.clone().unwrap_or_default();
        if let Some(set) = c.directory_set.as_mut() {
            set.devices.retain(|x| x.serial != serial);
            set.devices.push(DirectoryDevice {
                serial,
                device_class: req.device_class,
                role: d.role,
                file_id: issue.file_id.clone(),
                issued_at: issued_at.to_string(),
            });
        }
    }
    data.issues.push(issue.clone());
    Ok(Issued {
        file,
        code: Some(code),
        issue,
    })
}

/// Update file with the next sequence. `rotate` puts a new update key into
/// the payload. `under` issues under an earlier key (by update key id) for
/// installations that missed a rotation; the payload then carries the
/// current key.
pub fn update(
    data: &mut StoreData,
    req: &Request,
    signer: &Signer,
    rng: &mut dyn Rand,
    issued_at: &str,
    rotate: bool,
    under: Option<[u8; 16]>,
) -> Result<Issued, String> {
    refuse_test_key(signer)?;
    precheck(req, Kind::Update)?;
    if rotate && under.is_some() {
        return Err("--rotate-update-key and --under-key-id cannot be combined".into());
    }
    let c = data.customers.get(&req.customer_ref).ok_or_else(|| {
        format!(
            "no update key for customer {}: issue an activation file first",
            req.customer_ref
        )
    })?;
    let current = key_bytes(&c.update_key)?;
    let enc_key = match under {
        None => current.clone(),
        Some(id) => {
            let mut found = None;
            for k in std::iter::once(&c.update_key)
                .chain(c.previous_update_keys.iter().map(|p| &p.update_key))
            {
                let b = key_bytes(k)?;
                if update_key_id(&b) == id {
                    found = Some(b);
                }
            }
            found.ok_or("no update key with this id for the customer")?
        }
    };
    let new_key = if rotate {
        Some(Zeroizing::new(bytes::<32>(rng)?))
    } else {
        None
    };
    let carried = match (&new_key, *enc_key != *current) {
        (Some(n), _) => Some(hex(&**n)),
        (None, true) => Some(c.update_key.clone()),
        (None, false) => None,
    };
    let sequence = c.last_sequence + 1;
    let file_id = hex(&bytes::<16>(rng)?);
    // Every update re-states the stored profile, so an installation that
    // missed an update gets the whole profile from the next one.
    let features = features_for(data, req);
    let p = payload(
        req,
        Kind::Update,
        file_id,
        issued_at,
        carried,
        sequence,
        features.clone(),
        None,
    );
    p.validate(Kind::Update).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(p.to_json());
    let file = build_update(&plain, &enc_key, bytes(rng)?, signer)?;
    let install = Install {
        device_class: req.device_class,
        customer_ref: req.customer_ref.clone(),
        update_key: enc_key.clone(),
        last_sequence: sequence - 1,
        features: None,
    };
    let back = import_update(&file, &[signer.trusted("signer")], &install)
        .map_err(|e| format!("self-check of the new file failed: {e}"))?;
    if back != p {
        return Err("self-check of the new file failed: payload differs".into());
    }
    let issue = Issue {
        file_id: p.file_id.clone(),
        kind: Kind::Update,
        customer_ref: req.customer_ref.clone(),
        device_class: req.device_class,
        network_mode: req.network_mode,
        issued_at: issued_at.to_string(),
        key_id: hex(&signer.key_id()),
        sequence,
        update_key_id: hex(&update_key_id(&enc_key)),
        rotated: rotate,
        serial: req.serial.clone(),
        code_masked: None,
        features_profile: features.as_ref().map(Features::profile),
        features_fixed: features.as_ref().map(Features::fixed),
        directory_role: None,
    };
    let c = data
        .customers
        .get_mut(&req.customer_ref)
        .ok_or("customer disappeared")?;
    c.last_sequence = sequence;
    if let Some(f) = &req.features {
        c.features.set(req.device_class, f.clone());
    }
    if let Some(n) = new_key {
        let old = std::mem::replace(&mut c.update_key, hex(&*n));
        c.previous_update_keys.push(PreviousKey {
            update_key: old,
            retired_at: issued_at.to_string(),
        });
    }
    data.issues.push(issue.clone());
    Ok(Issued {
        file,
        code: None,
        issue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::keys::KeyFile;
    use crate::activation::payload::tests::sample;
    use crate::activation::rng::SeededRand;

    fn req(class: DeviceClass) -> Request {
        let p = sample(Kind::Activation, NetworkMode::TorRequired);
        Request {
            customer_ref: "TEST-CUSTOMER-0001".into(),
            device_class: class,
            network_mode: NetworkMode::TorRequired,
            smp: p.servers.smp.clone(),
            xftp: p.servers.xftp.clone(),
            support_address: p.support_address.clone(),
            serial: Some("TESTSERIAL01".into()),
            features: None,
            directory: None,
        }
    }

    #[test]
    fn files_and_inputs() {
        let (s, x) = parse_servers_file(
            "# test\n\nsmp://A@h.example.invalid\n  xftp://B@h.example.invalid  \n",
        )
        .unwrap();
        assert_eq!((s.len(), x.len()), (1, 1));
        let e = parse_servers_file("smp://A:SECRETPW@h\nhttp://x\n").unwrap_err();
        assert!(e.contains("line 2") && !e.contains("SECRETPW"));
        assert_eq!(
            parse_support_file("# c\nsimplex:/contact#/?x\n").unwrap(),
            "simplex:/contact#/?x"
        );
        assert!(parse_support_file("a\nb\n").is_err());
        assert!(parse_support_file("\n").is_err());
        let mut r = req(DeviceClass::Phone);
        r.customer_ref = "Max Mustermann".into();
        assert!(precheck(&r, Kind::Activation).is_err());
        let mut r = req(DeviceClass::Phone);
        r.network_mode = NetworkMode::Direct;
        assert!(precheck(&r, Kind::Activation)
            .unwrap_err()
            .contains("network mode"));
    }

    #[test]
    fn test_key_refused_for_issue_and_update() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key");
        let test_signer = KeyFile::read(&p).unwrap().unlock(None).unwrap();
        let mut data = StoreData::default();
        let mut r = SeededRand::new(b"tk");
        let e = activation(
            &mut data,
            &req(DeviceClass::Phone),
            &test_signer,
            &mut r,
            "2026-11-19T18:00:00Z",
        )
        .err()
        .unwrap();
        assert!(e.contains("TEST ONLY"));
        let e = update(
            &mut data,
            &req(DeviceClass::Phone),
            &test_signer,
            &mut r,
            "2026-11-19T18:00:00Z",
            false,
            None,
        )
        .err()
        .unwrap();
        assert!(e.contains("TEST ONLY"));
        assert!(data.issues.is_empty() && data.customers.is_empty());
    }

    #[test]
    fn test_deliveries_get_the_fixed_lab_code_real_ones_a_random_code() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key");
        let test_signer = KeyFile::read(&p).unwrap().unlock(None).unwrap();
        let mut data = StoreData::default();
        let mut r = SeededRand::new(b"lab");
        let t = "2026-11-26T18:00:00Z";
        for _ in 0..2 {
            let a = activation_test_delivery(
                &mut data,
                &req(DeviceClass::Phone),
                &test_signer,
                &mut r,
                t,
            )
            .unwrap();
            let c = a.code.as_ref().unwrap();
            assert_eq!(c.canonical(), crate::activation::code::LAB_CODE.as_bytes());
            assert_eq!(a.issue.code_masked.as_deref(), Some("7*****+*****2"));
        }
        // A real key never gets the lab code.
        let s = Signer::from_seed(&[12; 32]).unwrap();
        let mut data = StoreData::default();
        let a = activation(&mut data, &req(DeviceClass::Phone), &s, &mut r, t).unwrap();
        assert_ne!(
            a.code.as_ref().unwrap().canonical(),
            crate::activation::code::LAB_CODE.as_bytes()
        );
        // A real key is refused on the test delivery path.
        assert!(
            activation_test_delivery(&mut data, &req(DeviceClass::Phone), &s, &mut r, t).is_err()
        );
    }

    /// The stored profile per customer and device class, written into every
    /// file; an update without --features re-states it, one with it
    /// replaces it (section 12.4).
    #[test]
    fn feature_profiles_are_stored_and_restated() {
        use crate::activation::features::tests::example;
        use crate::activation::features::FeatureValue;
        let s = Signer::from_seed(&[13; 32]).unwrap();
        let trusted = [s.trusted("t")];
        let mut data = StoreData::default();
        let mut r = SeededRand::new(b"features");
        let t = "2026-11-27T10:00:00Z";
        let mut rq = req(DeviceClass::Phone);
        rq.features = Some(example());
        assert_eq!(features_change(&data, &rq).len(), 7);
        let a = activation(&mut data, &rq, &s, &mut r, t).unwrap();
        let code = String::from_utf8(a.code.as_ref().unwrap().canonical().to_vec()).unwrap();
        let p = import_activation(&a.file, &trusted, &code, DeviceClass::Phone).unwrap();
        assert_eq!(p.features, Some(example()));
        assert_eq!(
            a.issue.features_profile.as_deref(),
            Some("82c3232f78958958")
        );
        assert_eq!(a.issue.features_fixed, Some(example().fixed()));
        let c = &data.customers["TEST-CUSTOMER-0001"];
        assert_eq!(c.features.phone, Some(example()));
        assert_eq!(c.features.desktop, None);
        let mut phone = Install::from_activation(&p).unwrap();
        // Another device class has its own profile: none here.
        let d = activation(&mut data, &req(DeviceClass::Desktop), &s, &mut r, t).unwrap();
        assert_eq!(d.issue.features_profile, None);
        // An update without --features carries the stored profile.
        let u1 = update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            false,
            None,
        )
        .unwrap();
        let p1 = import_update(&u1.file, &trusted, &phone).unwrap();
        assert_eq!(p1.features, Some(example()));
        phone.apply(&p1);
        // With --features it replaces the stored profile; the change names
        // the switch that is no longer fixed off.
        let mut new = example();
        new.groups = Some(FeatureValue::Ask);
        let mut rq = req(DeviceClass::Phone);
        rq.features = Some(new.clone());
        assert_eq!(
            features_change(&data, &rq),
            vec!["groups: off -> ask (NO LONGER FIXED OFF)".to_string()]
        );
        let u2 = update(&mut data, &rq, &s, &mut r, t, false, None).unwrap();
        phone.apply(&import_update(&u2.file, &trusted, &phone).unwrap());
        assert_eq!(phone.features, Some(new.clone()));
        assert_eq!(
            data.customers["TEST-CUSTOMER-0001"].features.phone,
            Some(new)
        );
        // A desktop-only switch on for a phone is refused before anything.
        let mut bad = example();
        bad.vault = Some(FeatureValue::On);
        let mut rq = req(DeviceClass::Phone);
        rq.features = Some(bad.clone());
        assert!(precheck(&rq, Kind::Activation)
            .unwrap_err()
            .contains("vault"));
        let mut rq = req(DeviceClass::Desktop);
        rq.features = Some(bad);
        precheck(&rq, Kind::Activation).unwrap();
    }

    fn directory_input(role: &str, groups: &[&str]) -> DirectoryInput {
        let p = sample(Kind::Activation, NetworkMode::TorRequired);
        let s = crate::activation::hosts::parse_server(&p.servers.smp[0], "smp").unwrap();
        let groups: Vec<serde_json::Value> = groups
            .iter()
            .map(|n| {
                serde_json::json!({"name": n, "direct_contacts": true,
                    "link": crate::activation::hosts::tests::group_link_on(&s, n)})
            })
            .collect();
        crate::activation::directory::parse_directory_file(
            &serde_json::json!({"display_name": "TEST Anna", "role": role, "groups": groups})
                .to_string(),
        )
        .unwrap()
    }

    /// The minimal directory store: a set per customer, the same groups
    /// for every device, exactly one owner, no names or links stored.
    #[test]
    fn directory_sets() {
        let s = Signer::from_seed(&[14; 32]).unwrap();
        let trusted = [s.trusted("t")];
        let mut data = StoreData::default();
        let mut r = SeededRand::new(b"directory");
        let t = "2026-11-27T10:00:00Z";
        let with = |serial: &str, role: &str, groups: &[&str]| {
            let mut rq = req(DeviceClass::Phone);
            rq.serial = Some(serial.into());
            rq.directory = Some(directory_input(role, groups));
            rq
        };
        let a = activation(
            &mut data,
            &with("TESTSERIAL01", "owner", &["TEST Kanzlei", "TEST Team"]),
            &s,
            &mut r,
            t,
        )
        .unwrap();
        let code = String::from_utf8(a.code.as_ref().unwrap().canonical().to_vec()).unwrap();
        let p = import_activation(&a.file, &trusted, &code, DeviceClass::Phone).unwrap();
        let d = p.directory.as_ref().unwrap();
        assert_eq!(d.groups.len(), 2);
        assert_eq!(a.issue.directory_role, Some(Role::Owner));
        let set = data.customers["TEST-CUSTOMER-0001"]
            .directory_set
            .clone()
            .unwrap();
        assert_eq!(set.set_id, d.set_id);
        assert_eq!(set.devices.len(), 1);
        assert_eq!(set.groups, 2);
        let stored = serde_json::to_string(&data).unwrap();
        assert!(
            !stored.contains("TEST Anna")
                && !stored.contains("TEST Kanzlei")
                && !stored.contains("/g#"),
            "{stored}"
        );
        // A member on another phone: the same set id.
        let b = activation(
            &mut data,
            &with("TESTSERIAL02", "member", &["TEST Kanzlei", "TEST Team"]),
            &s,
            &mut r,
            t,
        )
        .unwrap();
        let code = String::from_utf8(b.code.as_ref().unwrap().canonical().to_vec()).unwrap();
        let q = import_activation(&b.file, &trusted, &code, DeviceClass::Phone).unwrap();
        assert_eq!(q.directory.as_ref().unwrap().set_id, d.set_id);
        // Other groups, or their order changed: refused.
        let e = activation(
            &mut data,
            &with("TESTSERIAL03", "member", &["TEST Team", "TEST Kanzlei"]),
            &s,
            &mut r,
            t,
        )
        .err()
        .unwrap();
        assert!(e.contains("groups differ"), "{e}");
        // A second owner on another phone: refused; re-issue to the owner: fine.
        let e = activation(
            &mut data,
            &with("TESTSERIAL02", "owner", &["TEST Kanzlei", "TEST Team"]),
            &s,
            &mut r,
            t,
        )
        .err()
        .unwrap();
        assert!(
            e.contains("already has an owner") && !e.contains("TESTSERIAL01"),
            "{e}"
        );
        activation(
            &mut data,
            &with("TESTSERIAL01", "owner", &["TEST Kanzlei", "TEST Team"]),
            &s,
            &mut r,
            t,
        )
        .unwrap();
        assert_eq!(
            data.customers["TEST-CUSTOMER-0001"]
                .directory_set
                .as_ref()
                .unwrap()
                .devices
                .len(),
            2
        );
        // No serial, or an update: refused before anything.
        let mut rq = with("X", "member", &["TEST Kanzlei"]);
        rq.serial = None;
        assert!(precheck(&rq, Kind::Activation)
            .unwrap_err()
            .contains("--serial"));
        let rq = with("TESTSERIAL01", "member", &["TEST Kanzlei"]);
        assert!(precheck(&rq, Kind::Update)
            .unwrap_err()
            .contains("activation files only"));
        assert!(update(&mut data, &rq, &s, &mut r, t, false, None).is_err());
    }

    #[test]
    fn issue_update_rotate_and_reach_missed_installations() {
        let s = Signer::from_seed(&[11; 32]).unwrap();
        let trusted = [s.trusted("t")];
        let mut data = StoreData::default();
        let mut r = SeededRand::new(b"issue");
        let t = "2026-11-19T18:00:00Z";
        let a = activation(&mut data, &req(DeviceClass::Phone), &s, &mut r, t).unwrap();
        let code = String::from_utf8(a.code.as_ref().unwrap().canonical().to_vec()).unwrap();
        let p = import_activation(&a.file, &trusted, &code, DeviceClass::Phone).unwrap();
        assert_eq!(p.sequence, 0);
        let mut phone = Install::from_activation(&p).unwrap();
        let mut stale = phone.clone();
        assert_eq!(a.issue.code_masked.as_deref().unwrap().len(), 13);
        // Updates 1 and 2, the second rotates the key.
        let u1 = update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            false,
            None,
        )
        .unwrap();
        phone.apply(&import_update(&u1.file, &trusted, &phone).unwrap());
        let u2 = update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            true,
            None,
        )
        .unwrap();
        let p2 = import_update(&u2.file, &trusted, &phone).unwrap();
        assert!(p2.update_key.is_some());
        phone.apply(&p2);
        let c = &data.customers["TEST-CUSTOMER-0001"];
        assert_eq!(c.last_sequence, 2);
        assert_eq!(c.previous_update_keys.len(), 1);
        // A later activation carries the current key and sequence 2, so the
        // new installation refuses the replayed update 1.
        let a2 = activation(&mut data, &req(DeviceClass::Desktop), &s, &mut r, t).unwrap();
        let code2 = String::from_utf8(a2.code.as_ref().unwrap().canonical().to_vec()).unwrap();
        let p = import_activation(&a2.file, &trusted, &code2, DeviceClass::Desktop).unwrap();
        assert_eq!(p.sequence, 2);
        let desktop = Install::from_activation(&p).unwrap();
        assert_eq!(*desktop.update_key, *phone.update_key);
        // The stale installation missed the rotation: a normal update does
        // not reach it, one under the earlier key does and carries the current key.
        let u3 = update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            false,
            None,
        )
        .unwrap();
        assert!(import_update(&u3.file, &trusted, &stale).is_err());
        let old_id = update_key_id(&stale.update_key);
        let u4 = update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            false,
            Some(old_id),
        )
        .unwrap();
        let p4 = import_update(&u4.file, &trusted, &stale).unwrap();
        stale.apply(&p4);
        assert_eq!(*stale.update_key, *phone.update_key);
        assert!(update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            false,
            Some([0; 16])
        )
        .is_err());
        assert!(update(
            &mut data,
            &req(DeviceClass::Phone),
            &s,
            &mut r,
            t,
            true,
            Some(old_id)
        )
        .is_err());
        let mut other = req(DeviceClass::Phone);
        other.customer_ref = "TEST-CUSTOMER-0002".into();
        assert!(update(&mut data, &other, &s, &mut r, t, false, None).is_err());
        assert_eq!(data.issues.len(), 6);
        // The fleet log never holds a full code or a key.
        let json = serde_json::to_string(&data.issues).unwrap();
        assert!(
            !json.contains(&code)
                && !json.contains(&data.customers["TEST-CUSTOMER-0001"].update_key)
        );
    }
}
