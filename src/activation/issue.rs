// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Issuing activation and update files against the admin store. No prompts
//! here: the CLI asks for passphrases and passes an unlocked signer.
//!
//! Every built file is checked once more with the reference import before
//! it is returned. The store data is only changed when everything succeeded.

use super::code::Code;
use super::container::{build_activation, build_update, update_key_id};
use super::import::{import_activation, import_update, Install};
use super::keys::{is_test_key, Signer};
use super::payload::{is_valid_customer_ref, DeviceClass, Kind, NetworkMode, Payload, Servers};
use super::rng::{bytes, Rand};
use super::store::{Customer, Issue, PreviousKey, StoreData};
use crate::util::{hex, unhex};
use zeroize::Zeroizing;

pub struct Request {
    pub customer_ref: String,
    pub device_class: DeviceClass,
    pub network_mode: NetworkMode,
    pub smp: Vec<String>,
    pub xftp: Vec<String>,
    pub support_address: String,
    pub serial: Option<String>,
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

fn payload(
    req: &Request,
    kind: Kind,
    file_id: String,
    issued_at: &str,
    update_key: Option<String>,
    sequence: u64,
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
    }
}

/// Checks the request alone (customer reference, addresses, mode rules)
/// before any passphrase is asked.
pub fn precheck(req: &Request, kind: Kind) -> Result<(), String> {
    if !is_valid_customer_ref(&req.customer_ref) {
        return Err("customer reference: only A-Z a-z 0-9 -, 1 to 32 characters".into());
    }
    let p = payload(
        req,
        kind,
        "0".repeat(32),
        "2026-01-01T00:00:00Z",
        Some("0".repeat(64)),
        1,
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

/// For a test delivery only (`sxprov deliver --test-delivery` with
/// `allow_test_key_for_test_deliveries`): requires the TEST ONLY key and
/// refuses every other key, so a real key can never sign a test file.
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

fn activation_signed(
    data: &mut StoreData,
    req: &Request,
    signer: &Signer,
    rng: &mut dyn Rand,
    issued_at: &str,
) -> Result<Issued, String> {
    precheck(req, Kind::Activation)?;
    let existing = data.customers.get(&req.customer_ref);
    let (key_hex, sequence) = match existing {
        Some(c) => (Zeroizing::new(c.update_key.clone()), c.last_sequence),
        None => (Zeroizing::new(hex(&*Zeroizing::new(bytes::<32>(rng)?))), 0),
    };
    let key = key_bytes(&key_hex)?;
    let code = Code::generate(rng)?;
    let file_id = hex(&bytes::<16>(rng)?);
    let p = payload(
        req,
        Kind::Activation,
        file_id,
        issued_at,
        Some(key_hex.to_string()),
        sequence,
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
    };
    if existing.is_none() {
        data.customers.insert(
            req.customer_ref.clone(),
            Customer {
                update_key: key_hex.to_string(),
                previous_update_keys: Vec::new(),
                last_sequence: 0,
                created_at: issued_at.to_string(),
            },
        );
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
    let p = payload(req, Kind::Update, file_id, issued_at, carried, sequence);
    p.validate(Kind::Update).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(p.to_json());
    let file = build_update(&plain, &enc_key, bytes(rng)?, signer)?;
    let install = Install {
        device_class: req.device_class,
        customer_ref: req.customer_ref.clone(),
        update_key: enc_key.clone(),
        last_sequence: sequence - 1,
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
    };
    let c = data
        .customers
        .get_mut(&req.customer_ref)
        .ok_or("customer disappeared")?;
    c.last_sequence = sequence;
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
