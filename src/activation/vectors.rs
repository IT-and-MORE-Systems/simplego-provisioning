// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Test vector generator for `tests/fixtures/sxact/` (format document
//! section 10). Signed only with the TEST ONLY key. Deterministic: salts,
//! nonces, codes, update keys and file ids come from a fixed seed, so
//! regenerating gives identical bytes.
//!
//! Check (default):   cargo test vectors
//! Regenerate:        SXACT_WRITE_VECTORS=1 cargo test vectors
//!
//! Every expected result is computed with the reference import
//! (`import.rs`) and must equal the intended result, so the generator also
//! tests the reader.

use super::code::Code;
use super::container::{assemble, build_activation, build_update, update_key_id, Header};
use super::hosts::tests::{fake43, fake_onion, key_hash, long_support, short_link};
use super::import::{import_activation, import_update, Install};
use super::keys::{KeyFile, Signer, TrustedKey};
use super::payload::{DeviceClass, Kind, NetworkMode, Payload, Servers};
use super::rng::{bytes, SeededRand};
use crate::util::hex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SEED: &[u8] = b"SXACT v1 test vectors, TEST ONLY";
const ISSUED_AT: &str = "2026-11-19T12:00:00Z";
const CUSTOMER: &str = "TEST-CUSTOMER-0001";
const OTHER_CUSTOMER: &str = "TEST-CUSTOMER-0002";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sxact")
}

struct Hosts {
    smp_onion: String,
    xftp_onion: String,
    support_onion: String,
}

fn hosts() -> Hosts {
    Hosts {
        smp_onion: fake_onion("testonlysmpa"),
        xftp_onion: fake_onion("testonlyxftpa"),
        support_onion: fake_onion("testonlysupport"),
    }
}

/// A long contact address as simplexmq writes it, with a synthetic key hash,
/// sender id and X25519 key (`hosts::tests::long_support`).
fn support(onion: Option<&str>, clear: Option<&str>) -> String {
    let hosts: Vec<&str> = onion.into_iter().chain(clear).collect();
    long_support("simplex:", &hosts)
}

/// Server key hashes: SHA-256 over a `TEST-ONLY-...` seed, unpadded
/// base64url (format document section 7, amended 2026-11-21 11:00).
fn smp(hosts: &[&str]) -> String {
    smp_with(&key_hash("TEST-ONLY-SMP-1"), hosts)
}

fn smp_with(fingerprint: &str, hosts: &[&str]) -> String {
    format!("smp://{fingerprint}:TEST-ONLY-PASSWORD@{}", hosts.join(","))
}

fn xftp(hosts: &[&str]) -> String {
    format!(
        "xftp://{}:TEST-ONLY-PASSWORD@{}:443",
        key_hash("TEST-ONLY-XFTP-1"),
        hosts.join(",")
    )
}

/// A `tor_optional` support address with a clearnet host in `srv`: refused
/// since the amendment of 2026-11-23 (section 7). The
/// refused files written before it keep it, so they stay byte-identical.
fn support_with_clearnet(h: &Hosts) -> String {
    support(
        Some(h.support_onion.as_str()),
        Some("support.example.invalid"),
    )
}

/// The servers and support address for a mode, all hosts synthetic. In
/// `tor_optional` the support address has only an onion host (section 7,
/// amended 2026-11-23).
fn servers_for(h: &Hosts, mode: NetworkMode) -> (Servers, String) {
    let (so, xo, po) = (
        h.smp_onion.as_str(),
        h.xftp_onion.as_str(),
        h.support_onion.as_str(),
    );
    match mode {
        NetworkMode::TorRequired => (
            Servers {
                smp: vec![smp(&[so])],
                xftp: vec![xftp(&[xo])],
            },
            support(Some(po), None),
        ),
        NetworkMode::TorOptional => (
            Servers {
                smp: vec![smp(&[so, "smp-a.example.invalid"])],
                xftp: vec![xftp(&[xo, "xftp-a.example.invalid"])],
            },
            support(Some(po), None),
        ),
        NetworkMode::Direct => (
            Servers {
                smp: vec![smp(&["smp-a.example.invalid"])],
                xftp: vec![xftp(&["xftp-a.example.invalid"])],
            },
            support(None, Some("support.example.invalid")),
        ),
    }
}

struct Gen {
    rng: SeededRand,
    test: Signer,
    trusted: Vec<TrustedKey>,
    hosts: Hosts,
    files: Vec<(String, Vec<u8>)>,
    vectors: Vec<Value>,
}

#[derive(Clone)]
enum Expect {
    Ok,
    Refused(&'static str),
}

impl Gen {
    fn payload(
        &mut self,
        kind: Kind,
        class: DeviceClass,
        mode: NetworkMode,
        customer: &str,
        key: Option<&[u8; 32]>,
        sequence: u64,
    ) -> Payload {
        let (servers, support_address) = servers_for(&self.hosts, mode);
        Payload {
            payload_version: 1,
            kind,
            file_id: hex(&bytes::<16>(&mut self.rng).unwrap()),
            issued_at: ISSUED_AT.into(),
            customer_ref: customer.into(),
            device_class: class,
            network_mode: mode,
            servers,
            support_address,
            update_key: key.map(|k| hex(k)),
            sequence,
        }
    }

    fn add_file(&mut self, name: &str, data: Vec<u8>) {
        self.files.push((name.to_string(), data));
    }

    fn file(&self, name: &str) -> Vec<u8> {
        self.files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.clone())
            .unwrap()
    }

    fn activation_file(&mut self, name: &str, p: &Payload, code: &Code) {
        let salt = bytes(&mut self.rng).unwrap();
        let nonce = bytes(&mut self.rng).unwrap();
        let f = build_activation(&p.to_json(), code, salt, nonce, &self.test).unwrap();
        self.add_file(name, f);
    }

    fn update_file(&mut self, name: &str, p: &Payload, key: &[u8; 32]) {
        let nonce = bytes(&mut self.rng).unwrap();
        let f = build_update(&p.to_json(), key, nonce, &self.test).unwrap();
        self.add_file(name, f);
    }

    /// Re-signs the file with a changed header (the test key signs, so the
    /// only defect is the changed field).
    fn header_variant(&mut self, name: &str, from: &str, f: impl Fn(&mut Header)) {
        let src = self.file(from);
        let mut hb = [0u8; 66];
        hb.copy_from_slice(&src[..66]);
        let mut h = Header::from_bytes(&hb);
        f(&mut h);
        let ct = &src[66..src.len() - 64];
        let mut out = assemble(&h, ct, &self.test);
        if name == "refused-bad-magic.sxact" {
            // The magic is not part of the Header struct: change it, re-sign.
            out[0] = b'X';
            let sig = self
                .test
                .sign(&[b"SXACT-v1-SIG\0".as_slice(), &out[..66], ct].concat());
            let n = out.len();
            out[n - 64..].copy_from_slice(&sig);
        }
        self.add_file(name, out);
    }

    fn activation_vector(
        &mut self,
        name: &str,
        file: &str,
        code: &str,
        app_class: DeviceClass,
        expect: Expect,
        note: &str,
    ) {
        let data = self.file(file);
        let got = import_activation(&data, &self.trusted, code, app_class);
        let mut v = json!({
            "name": name, "file": file, "kind": "activation",
            "trusted_public_key_hex": hex(&self.test.public()),
            "code": code, "app_device_class": app_class.as_str(), "note": note,
        });
        check(&mut v, got, &expect);
        self.vectors.push(v);
    }

    fn update_vector(
        &mut self,
        name: &str,
        file: &str,
        install: &Install,
        expect: Expect,
        note: &str,
    ) {
        let data = self.file(file);
        let got = import_update(&data, &self.trusted, install);
        let mut v = json!({
            "name": name, "file": file, "kind": "update",
            "trusted_public_key_hex": hex(&self.test.public()),
            "installation": {
                "customer_ref": install.customer_ref, "device_class": install.device_class.as_str(),
                "update_key_hex": hex(&*install.update_key), "update_key_id_hex": hex(&update_key_id(&install.update_key)),
                "last_sequence": install.last_sequence,
            },
            "note": note,
        });
        check(&mut v, got, &expect);
        self.vectors.push(v);
    }

    /// A structure refusal: the result does not depend on code or state.
    fn format_vector(&mut self, name: &str, file: &str, code: &str, expect: Expect, note: &str) {
        self.activation_vector(name, file, code, DeviceClass::Phone, expect, note);
        let v = self.vectors.last_mut().unwrap();
        v["kind"] = json!("any");
    }
}

fn check(v: &mut Value, got: Result<Payload, super::Refusal>, expect: &Expect) {
    match (expect, got) {
        (Expect::Ok, Ok(p)) => {
            v["expected"] = json!("ok");
            v["expected_payload"] = serde_json::to_value(&p).unwrap();
        }
        (Expect::Refused(want), Err(r)) if r.code() == *want => {
            v["expected"] = json!(want);
            v["reason"] = json!(r.to_string());
        }
        (e, got) => panic!(
            "vector {}: wanted {}, got {:?}",
            v["name"],
            match e {
                Expect::Ok => "ok",
                Expect::Refused(w) => w,
            },
            got.map(|p| p.file_id.clone())
        ),
    }
}

fn canon(c: &Code) -> String {
    String::from_utf8(c.canonical().to_vec()).unwrap()
}

/// Builds every file and `vectors.json`.
fn generate() -> (Vec<(String, Vec<u8>)>, String) {
    let key_path = dir().join("keys/sxact-TEST-ONLY-signing-key");
    let test = KeyFile::read(&key_path).unwrap().unlock(None).unwrap();
    let mut g = Gen {
        rng: SeededRand::new(SEED),
        trusted: vec![test.trusted("TEST ONLY")],
        test,
        hosts: hosts(),
        files: Vec::new(),
        vectors: Vec::new(),
    };
    use DeviceClass::*;
    use Expect::*;
    use NetworkMode::*;
    let key1: [u8; 32] = bytes(&mut g.rng).unwrap();
    let key1_rotated: [u8; 32] = bytes(&mut g.rng).unwrap();
    let key2: [u8; 32] = bytes(&mut g.rng).unwrap();
    let unknown = Signer::from_seed(&bytes(&mut g.rng).unwrap()).unwrap();
    let code_phone = Code::generate(&mut g.rng).unwrap();
    let code_desktop = Code::generate(&mut g.rng).unwrap();
    let code_misc = Code::generate(&mut g.rng).unwrap();
    let (cp, cd, cm) = (canon(&code_phone), canon(&code_desktop), canon(&code_misc));
    let install = |class: DeviceClass, key: &[u8; 32], seq: u64| Install {
        device_class: class,
        customer_ref: CUSTOMER.into(),
        update_key: Zeroizing::new(*key),
        last_sequence: seq,
    };

    // Valid activation files.
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        0,
    );
    g.activation_file("activation-phone.sxact", &p, &code_phone);
    let p = g.payload(
        Kind::Activation,
        Desktop,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        0,
    );
    g.activation_file("activation-desktop.sxact", &p, &code_desktop);
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorOptional,
        CUSTOMER,
        Some(&key1),
        0,
    );
    g.activation_file("activation-mode-tor-optional.sxact", &p, &code_misc);
    let p = g.payload(Kind::Activation, Phone, Direct, CUSTOMER, Some(&key1), 0);
    g.activation_file("activation-mode-direct.sxact", &p, &code_misc);
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        5,
    );
    g.activation_file("activation-phone-sequence-5.sxact", &p, &code_misc);

    g.activation_vector(
        "activation-phone",
        "activation-phone.sxact",
        &cp,
        Phone,
        Ok,
        "valid phone activation file, mode tor_required, sequence 0",
    );
    g.activation_vector(
        "activation-desktop",
        "activation-desktop.sxact",
        &cd,
        Desktop,
        Ok,
        "valid desktop activation file, mode tor_required, sequence 0",
    );
    g.activation_vector(
        "activation-mode-tor-optional",
        "activation-mode-tor-optional.sxact",
        &cm,
        Phone,
        Ok,
        "every server address has an onion and a clearnet host; the support address has only an onion host (support only over Tor, section 7 amended 2026-11-23)",
    );
    g.activation_vector(
        "activation-mode-direct",
        "activation-mode-direct.sxact",
        &cm,
        Phone,
        Ok,
        "every address has a clearnet host",
    );
    g.activation_vector(
        "activation-phone-sequence-5",
        "activation-phone-sequence-5.sxact",
        &cm,
        Phone,
        Ok,
        "activation issued after updates 1 to 5; the app stores 5 as its last applied sequence",
    );
    let display = code_phone.display().to_string();
    g.activation_vector(
        "code-display-form",
        "activation-phone.sxact",
        &format!("{display} ="),
        Phone,
        Ok,
        "the code as on the card with spaces and a trailing =",
    );
    // The earlier case of this name held only spaces, because the phone
    // code's operator is +. It now holds a capital X, against the file whose
    // code has the operator x; the other characters follow at the end.
    assert_eq!(&cm[6..7], "x");
    g.activation_vector(
        "code-alternative-characters",
        "activation-mode-tor-optional.sxact",
        &format!("{}X{}", &cm[..6], &cm[7..]),
        Phone,
        Ok,
        "capital X for x (the file's code has the operator x)",
    );

    // Valid update files.
    let p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    g.update_file("update-phone.sxact", &p, &key1);
    let p = g.payload(Kind::Update, Desktop, TorRequired, CUSTOMER, None, 2);
    g.update_file("update-desktop.sxact", &p, &key1);
    let p = g.payload(
        Kind::Update,
        Phone,
        TorOptional,
        CUSTOMER,
        Some(&key1_rotated),
        3,
    );
    g.update_file("update-phone-rotate-key.sxact", &p, &key1);
    g.update_vector(
        "update-phone",
        "update-phone.sxact",
        &install(Phone, &key1, 0),
        Ok,
        "valid phone update, sequence 1, after activation-phone",
    );
    g.update_vector(
        "update-desktop",
        "update-desktop.sxact",
        &install(Desktop, &key1, 0),
        Ok,
        "valid desktop update, sequence 2, after activation-desktop",
    );
    g.update_vector("update-phone-rotate-key", "update-phone-rotate-key.sxact", &install(Phone, &key1, 1), Ok, "sequence 3, changes the mode to tor_optional (less strict, named in the summary) and carries a new update_key that replaces the stored one; its support address has only an onion host (section 7 amended 2026-11-23)");

    // Refused: code.
    let wrong = if cp.ends_with('9') {
        format!("{}8", &cp[..12])
    } else {
        format!("{}9", &cp[..12])
    };
    g.activation_vector(
        "refused-wrong-code",
        "activation-phone.sxact",
        &wrong,
        Phone,
        Refused("wrong_code"),
        "a well-formed code that is not the file's code",
    );
    let bad = format!("{}a", &cp[..12]);
    g.activation_vector(
        "refused-code-wrong-character",
        "activation-phone.sxact",
        &bad,
        Phone,
        Refused("bad_code"),
        "refused before any key derivation",
    );
    g.activation_vector(
        "refused-code-too-short",
        "activation-phone.sxact",
        &cp[..12],
        Phone,
        Refused("bad_code"),
        "12 characters after mapping",
    );
    g.activation_vector(
        "refused-device-class",
        "activation-desktop.sxact",
        &cd,
        Phone,
        Refused("device_class_mismatch"),
        "a desktop file imported by the phone app",
    );

    // Refused: key and signature.
    let p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    let nonce = bytes(&mut g.rng).unwrap();
    g.add_file(
        "refused-unknown-key.sxact",
        build_update(&p.to_json(), &key1, nonce, &unknown).unwrap(),
    );
    g.format_vector(
        "refused-unknown-key",
        "refused-unknown-key.sxact",
        &cp,
        Refused("unknown_key"),
        "signed with a key that is not in the trusted list",
    );
    let base = g.file("activation-phone.sxact");
    for (name, offset, note) in [
        (
            "refused-altered-header.sxact",
            20usize,
            "one byte of the salt changed",
        ),
        (
            "refused-altered-ciphertext.sxact",
            100,
            "one byte of the ciphertext changed",
        ),
        (
            "refused-altered-signature.sxact",
            base.len() - 10,
            "one byte of the signature changed",
        ),
    ] {
        let mut f = base.clone();
        f[offset] ^= 0x01;
        g.add_file(name, f);
        g.format_vector(
            name.trim_end_matches(".sxact"),
            name,
            &cp,
            Refused("bad_signature"),
            note,
        );
    }

    // Refused: structure and bounds (re-signed with the test key).
    let mut truncated = base.clone();
    truncated.pop();
    g.add_file("refused-truncated.sxact", truncated);
    g.format_vector(
        "refused-truncated",
        "refused-truncated.sxact",
        &cp,
        Refused("length_mismatch"),
        "last byte missing",
    );
    let mut trailing = base.clone();
    trailing.push(0);
    g.add_file("refused-trailing-bytes.sxact", trailing);
    g.format_vector(
        "refused-trailing-bytes",
        "refused-trailing-bytes.sxact",
        &cp,
        Refused("length_mismatch"),
        "one byte after the signature",
    );
    let big_ct = vec![0x5au8; 64 * 1024 - 66 - 64 + 1];
    let mut h = Header::activation([0x11; 16], [0x22; 12], g.test.key_id(), big_ct.len() - 16);
    h.ct_len = big_ct.len() as u32;
    let big = assemble(&h, &big_ct, &g.test);
    g.add_file("refused-too-large.sxact", big);
    g.format_vector(
        "refused-too-large",
        "refused-too-large.sxact",
        &cp,
        Refused("too_large"),
        "65537 bytes, consistent header, valid signature",
    );
    type Change = fn(&mut Header);
    let variants: [(&str, Change, &str, &str); 12] = [
        (
            "refused-bad-magic.sxact",
            |_| {},
            "bad_magic",
            "magic XXACT",
        ),
        (
            "refused-wrong-version.sxact",
            |h| h.version = 2,
            "unsupported_version",
            "version 2",
        ),
        (
            "refused-kdf-m-too-low.sxact",
            |h| h.kdf_m_kib = 65_535,
            "kdf_params_out_of_bounds",
            "m 65535 KiB, below 64 MiB",
        ),
        (
            "refused-kdf-m-too-high.sxact",
            |h| h.kdf_m_kib = 262_145,
            "kdf_params_out_of_bounds",
            "m 262145 KiB, above 256 MiB",
        ),
        (
            "refused-kdf-t-too-low.sxact",
            |h| h.kdf_t = 2,
            "kdf_params_out_of_bounds",
            "t 2, below 3",
        ),
        (
            "refused-kdf-t-too-high.sxact",
            |h| h.kdf_t = 11,
            "kdf_params_out_of_bounds",
            "t 11, above 10",
        ),
        (
            "refused-kdf-p-zero.sxact",
            |h| h.kdf_p = 0,
            "kdf_params_out_of_bounds",
            "p 0",
        ),
        (
            "refused-kdf-p-too-high.sxact",
            |h| h.kdf_p = 5,
            "kdf_params_out_of_bounds",
            "p 5, above 4",
        ),
        (
            "refused-unknown-kdf-alg.sxact",
            |h| h.kdf_alg = 3,
            "unknown_kdf_alg",
            "kdf_alg 3",
        ),
        (
            "refused-unknown-aead-alg.sxact",
            |h| h.aead_alg = 2,
            "unknown_aead_alg",
            "aead_alg 2",
        ),
        (
            "refused-unknown-sig-alg.sxact",
            |h| h.sig_alg = 2,
            "unknown_sig_alg",
            "sig_alg 2",
        ),
        (
            "refused-ct-len-mismatch.sxact",
            |h| h.ct_len -= 1,
            "length_mismatch",
            "ct_len one less than the ciphertext",
        ),
    ];
    for (name, change, want, note) in variants {
        g.header_variant(name, "activation-phone.sxact", change);
        g.format_vector(
            name.trim_end_matches(".sxact"),
            name,
            &cp,
            Refused(want),
            &format!("{note}; re-signed with the test key"),
        );
    }
    g.header_variant(
        "refused-update-kdf-params-not-zero.sxact",
        "update-phone.sxact",
        |h| h.kdf_t = 3,
    );
    g.format_vector(
        "refused-update-kdf-params-not-zero",
        "refused-update-kdf-params-not-zero.sxact",
        &cp,
        Refused("kdf_params_out_of_bounds"),
        "update file (kdf_alg 2) with t 3; re-signed with the test key",
    );

    // Refused: network mode rules (valid signature, the payload breaks the rule).
    type Rule = (
        &'static str,
        NetworkMode,
        fn(&Hosts) -> (Servers, String),
        &'static str,
    );
    let rules: [Rule; 5] = [
        (
            "refused-mode-tor-required-without-onion",
            TorRequired,
            |h| {
                let (mut s, sup) = servers_for(h, TorRequired);
                s.smp = vec![smp(&["smp-a.example.invalid"])];
                (s, sup)
            },
            "tor_required, an SMP address without an onion host",
        ),
        (
            "refused-mode-tor-optional-without-clearnet",
            TorOptional,
            |h| {
                let (mut s, _) = servers_for(h, TorOptional);
                s.xftp = vec![xftp(&[h.xftp_onion.as_str()])];
                (s, support_with_clearnet(h))
            },
            "tor_optional, an XFTP address with only an onion host (the servers come first; its support address also carries a clearnet host, refused too since 2026-11-23)",
        ),
        (
            "refused-mode-tor-optional-without-onion",
            TorOptional,
            |h| {
                let (mut s, _) = servers_for(h, TorOptional);
                s.smp = vec![smp(&["smp-a.example.invalid"])];
                (s, support_with_clearnet(h))
            },
            "tor_optional, an SMP address with only a clearnet host (the servers come first; its support address also carries a clearnet host, refused too since 2026-11-23)",
        ),
        (
            "refused-mode-direct-without-clearnet",
            Direct,
            |h| {
                let (mut s, sup) = servers_for(h, Direct);
                s.smp = vec![smp(&[h.smp_onion.as_str()])];
                (s, sup)
            },
            "direct, an SMP address with only an onion host",
        ),
        (
            "refused-mode-support-address",
            TorOptional,
            |h| {
                let (s, _) = servers_for(h, TorOptional);
                (s, support_with_clearnet(h))
            },
            "tor_optional, valid servers; the support address carries a clearnet host in srv= next to its onion queue host (support only over Tor, section 7 amended 2026-11-23)",
        ),
    ];
    for (name, mode, servers, note) in rules {
        let mut p = g.payload(Kind::Activation, Phone, mode, CUSTOMER, Some(&key1), 0);
        let (s, sup) = servers(&g.hosts);
        p.servers = s;
        p.support_address = sup;
        let file = format!("{name}.sxact");
        g.activation_file(&file, &p, &code_misc);
        g.activation_vector(name, &file, &cm, Phone, Refused("network_mode_rule"), note);
    }

    // Refused: payload rules (update files, no key derivation needed).
    let mut bad_onion = g.hosts.smp_onion.clone().into_bytes();
    bad_onion[20] = if bad_onion[20] == b'a' { b'b' } else { b'a' };
    let bad_onion = String::from_utf8(bad_onion).unwrap();
    let mut p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    p.servers.smp = vec![smp(&[bad_onion.as_str()])];
    g.update_file("refused-invalid-onion-checksum.sxact", &p, &key1);
    g.update_vector("refused-invalid-onion-checksum", "refused-invalid-onion-checksum.sxact", &install(Phone, &key1, 0), Refused("bad_payload"), "an SMP host that looks like a v3 onion name but has a wrong checksum; it never counts as clearnet");
    let mut p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    p.support_address = "simplex:/a#TEST-ONLY-SHORT-LINK".into();
    g.update_file("refused-support-short-link.sxact", &p, &key1);
    g.update_vector(
        "refused-support-short-link",
        "refused-support-short-link.sxact",
        &install(Phone, &key1, 0),
        Refused("bad_payload"),
        "the simplex:/a#... short link form is refused (only https://<host>/a#... is accepted)",
    );

    // Refused: update rules.
    let p = g.payload(Kind::Update, Phone, TorRequired, OTHER_CUSTOMER, None, 1);
    g.update_file("refused-update-other-customer-key.sxact", &p, &key2);
    g.update_vector(
        "refused-update-other-customer-key",
        "refused-update-other-customer-key.sxact",
        &install(Phone, &key1, 0),
        Refused("wrong_update_key"),
        "an update for another customer, under that customer's update key",
    );
    let p = g.payload(Kind::Update, Phone, TorRequired, OTHER_CUSTOMER, None, 1);
    g.update_file("refused-update-other-customer-ref.sxact", &p, &key1);
    g.update_vector(
        "refused-update-other-customer-ref",
        "refused-update-other-customer-ref.sxact",
        &install(Phone, &key1, 0),
        Refused("customer_mismatch"),
        "under the right update key, but customer_ref is another customer",
    );
    g.update_vector(
        "refused-update-replayed",
        "update-phone.sxact",
        &install(Phone, &key1, 1),
        Refused("replayed_sequence"),
        "update-phone (sequence 1) again after it was applied",
    );
    let p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 3);
    g.update_file("update-phone-sequence-3.sxact", &p, &key1);
    g.update_vector(
        "update-phone-sequence-3",
        "update-phone-sequence-3.sxact",
        &install(Phone, &key1, 2),
        Ok,
        "valid when the installation has applied sequence 2",
    );
    g.update_vector(
        "refused-update-older-than-activation",
        "update-phone-sequence-3.sxact",
        &install(Phone, &key1, 5),
        Refused("replayed_sequence"),
        "after activation-phone-sequence-5 (last applied sequence 5), update 3 is refused",
    );
    g.update_vector(
        "refused-update-device-class",
        "update-desktop.sxact",
        &install(Phone, &key1, 0),
        Refused("device_class_mismatch"),
        "a desktop update on a phone installation",
    );

    // Refused: kind does not match the container.
    let p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    g.activation_file(
        "refused-kind-update-in-activation-container.sxact",
        &p,
        &code_misc,
    );
    g.activation_vector(
        "refused-kind-update-in-activation-container",
        "refused-kind-update-in-activation-container.sxact",
        &cm,
        Phone,
        Refused("kind_mismatch"),
        "kdf_alg 1 container, payload kind update",
    );
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        1,
    );
    g.update_file(
        "refused-kind-activation-in-update-container.sxact",
        &p,
        &key1,
    );
    g.update_vector(
        "refused-kind-activation-in-update-container",
        "refused-kind-activation-in-update-container.sxact",
        &install(Phone, &key1, 0),
        Refused("kind_mismatch"),
        "kdf_alg 2 container, payload kind activation",
    );

    // Short contact links for the support address (section 7, amended
    // 2026-11-21 00:41 and 10:30). Generated after every earlier file, so
    // the seeded sequence, and with it every earlier file, is unchanged.
    let onion = g.hosts.support_onion.clone();
    let c = format!("c={}", fake43("TEST-ONLY-KEY-HASH"));
    let key = fake43("TEST-ONLY-LINK-KEY");
    let mut p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        0,
    );
    p.support_address = short_link(&onion, &c);
    g.activation_file("activation-support-short-link.sxact", &p, &code_misc);
    g.activation_vector(
        "activation-support-short-link",
        "activation-support-short-link.sxact",
        &cm,
        Phone,
        Ok,
        "mode tor_required, the support address is a short link https://<onion>/a#<key>?c=<key hash> on a valid v3 onion host",
    );
    let mut p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
    p.support_address = short_link(&onion, &c);
    g.update_file("update-support-short-link.sxact", &p, &key1);
    g.update_vector(
        "update-support-short-link",
        "update-support-short-link.sxact",
        &install(Phone, &key1, 0),
        Ok,
        "sequence 1 after activation-phone: changes the support address from the long form to a short link on the same onion host",
    );
    let short_refusals: Vec<(&str, String, &'static str, &str)> = vec![
        (
            "refused-short-link-clearnet-tor-required",
            short_link("support.example.invalid", &c),
            "network_mode_rule",
            "tor_required, the short link host is a clearnet host",
        ),
        (
            "refused-short-link-simplex-form",
            format!("simplex:/a#{key}?h={onion}&{c}"),
            "bad_payload",
            "the simplex:/a#... form of a short link is not accepted",
        ),
        (
            "refused-short-link-invitation",
            format!("https://{onion}/i#TEST-ONLY-LINK-ID/{key}?{c}"),
            "bad_payload",
            "a one-time invitation link (/i#) is not a contact address",
        ),
        (
            "refused-short-link-unknown-parameter",
            short_link(&onion, &format!("{c}&x=TEST-ONLY")),
            "bad_payload",
            "a short link parameter other than h, p and c",
        ),
        (
            "refused-short-link-malformed-key",
            format!("https://{onion}/a#{}?{c}", &key[..42]),
            "bad_payload",
            "the key is 42 characters instead of 43 characters of unpadded base64url",
        ),
        (
            "refused-short-link-without-c",
            short_link(&onion, ""),
            "bad_payload",
            "a short link without c (the server key hash), which is required",
        ),
    ];
    for (name, addr, want, note) in short_refusals {
        let mut p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
        p.support_address = addr;
        let file = format!("{name}.sxact");
        g.update_file(&file, &p, &key1);
        g.update_vector(name, &file, &install(Phone, &key1, 0), Refused(want), note);
    }

    // Format document amended 2026-11-21 11:00. Appended
    // after every earlier file, so the seeded sequence of the earlier files
    // stays the same.
    //
    // Alternative code characters (section 3), one case per group.
    let code_divide = Code::parse_input(&format!("{}:{}", &cp[..6], &cp[7..])).unwrap();
    let code_minus = Code::parse_input(&format!("{}-{}", &cp[..6], &cp[7..])).unwrap();
    let (cdiv, cmin) = (canon(&code_divide), canon(&code_minus));
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        0,
    );
    g.activation_file("activation-code-divide.sxact", &p, &code_divide);
    let p = g.payload(
        Kind::Activation,
        Phone,
        TorRequired,
        CUSTOMER,
        Some(&key1),
        0,
    );
    g.activation_file("activation-code-minus.sxact", &p, &code_minus);
    g.activation_vector(
        "activation-code-divide",
        "activation-code-divide.sxact",
        &cdiv,
        Phone,
        Ok,
        "valid phone activation file whose code has the operator : (\u{f7} on the card)",
    );
    g.activation_vector(
        "activation-code-minus",
        "activation-code-minus.sxact",
        &cmin,
        Phone,
        Ok,
        "valid phone activation file whose code has the operator -",
    );
    let (a, b) = (&cm[..6], &cm[7..]);
    let (c, d) = (&cp[..6], &cp[7..]);
    let alternatives: Vec<(&str, &str, String, &str)> = vec![
        (
            "code-alternative-times-sign",
            "activation-mode-tor-optional.sxact",
            format!("{a}\u{d7}{b}"),
            "the multiplication sign U+00D7 (as on the card) for x",
        ),
        (
            "code-alternative-asterisk",
            "activation-mode-tor-optional.sxact",
            format!("{a}*{b}"),
            "* for x",
        ),
        (
            "code-alternative-division-sign",
            "activation-code-divide.sxact",
            format!("{c}\u{f7}{d}"),
            "the division sign U+00F7 (as on the card) for :",
        ),
        (
            "code-alternative-slash",
            "activation-code-divide.sxact",
            format!("{c}/{d}"),
            "/ for :",
        ),
        (
            "code-alternative-minus-sign",
            "activation-code-minus.sxact",
            format!("{c}\u{2212}{d}"),
            "the minus sign U+2212 for -",
        ),
        (
            "code-alternative-spaces-and-equals",
            "activation-phone.sxact",
            format!(" {c} + {d} = "),
            "spaces before, between and after the parts and a trailing =, all dropped",
        ),
    ];
    for (name, file, code, note) in alternatives {
        g.activation_vector(name, file, &code, Phone, Ok, note);
    }

    // Desktop activation files for the other two modes.
    for (name, mode, note) in [
        (
            "activation-desktop-mode-tor-optional",
            TorOptional,
            "valid desktop activation file, mode tor_optional: every server address has an onion and a clearnet host; the support address has only an onion host (section 7 amended 2026-11-23)",
        ),
        (
            "activation-desktop-mode-direct",
            Direct,
            "valid desktop activation file, mode direct: every address has a clearnet host",
        ),
    ] {
        let p = g.payload(Kind::Activation, Desktop, mode, CUSTOMER, Some(&key1), 0);
        let file = format!("{name}.sxact");
        g.activation_file(&file, &p, &code_desktop);
        g.activation_vector(name, &file, &cd, Desktop, Ok, note);
    }

    // Server fingerprints (section 7, amended 2026-11-21 11:00).
    let fp31 = {
        // 31 bytes as unpadded base64url: 42 characters, canonical.
        let mut raw = super::hosts::b64url_decode(&key_hash("TEST-ONLY-SMP-1")).unwrap();
        raw.truncate(31);
        <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(&raw)
    };
    assert_eq!(fp31.len(), 42);
    let fingerprint_refusals: Vec<(&str, Servers, String, &str)> = {
        let (s, sup) = servers_for(&g.hosts, TorRequired);
        let so = g.hosts.smp_onion.clone();
        let po = g.hosts.support_onion.clone();
        vec![
            (
                "refused-fingerprint-placeholder",
                Servers {
                    smp: vec![smp_with("TEST-ONLY-FINGERPRINT-SMP", &[so.as_str()])],
                    xftp: s.xftp.clone(),
                },
                sup.clone(),
                "the SMP fingerprint is the placeholder of the first vectors, not a 32-byte key hash",
            ),
            (
                "refused-fingerprint-31-bytes",
                Servers {
                    smp: vec![smp_with(&fp31, &[so.as_str()])],
                    xftp: s.xftp.clone(),
                },
                sup.clone(),
                "the SMP fingerprint is 31 bytes (42 characters of base64url), not 32",
            ),
            (
                "refused-fingerprint-support-placeholder",
                s.clone(),
                support(Some(po.as_str()), None).replacen(
                    &key_hash("TEST-ONLY-SUPPORT-SMP-1"),
                    "TEST-ONLY-FINGERPRINT-SUPPORT",
                    1,
                ),
                "the server in the smp parameter of the support address has the placeholder fingerprint",
            ),
        ]
    };
    for (name, servers, sup, note) in fingerprint_refusals {
        let mut p = g.payload(Kind::Update, Phone, TorRequired, CUSTOMER, None, 1);
        p.servers = servers;
        p.support_address = sup;
        let file = format!("{name}.sxact");
        g.update_file(&file, &p, &key1);
        g.update_vector(
            name,
            &file,
            &install(Phone, &key1, 0),
            Refused("bad_payload"),
            note,
        );
    }

    // Several rules broken at once: the device class is reported first
    // (section 6 step 6, clarified 2026-11-21 11:00).
    let mut p = g.payload(
        Kind::Activation,
        Desktop,
        TorOptional,
        CUSTOMER,
        Some(&key1),
        0,
    );
    p.servers.xftp = vec![xftp(&[g.hosts.xftp_onion.as_str()])];
    p.support_address = support_with_clearnet(&g.hosts);
    g.activation_file(
        "refused-device-class-and-mode-rule.sxact",
        &p,
        &code_desktop,
    );
    g.activation_vector(
        "refused-device-class-and-mode-rule",
        "refused-device-class-and-mode-rule.sxact",
        &cd,
        Phone,
        Refused("device_class_mismatch"),
        "a desktop file whose XFTP address breaks tor_optional (onion host only), imported by the phone app: the device class is checked first",
    );
    g.activation_vector(
        "refused-device-class-and-mode-rule-on-desktop",
        "refused-device-class-and-mode-rule.sxact",
        &cd,
        Desktop,
        Refused("network_mode_rule"),
        "the same file imported by the desktop app: the mode rule",
    );

    let doc = json!({
        "format": "SXACT version 1 (activation-file-format.md, version 1 with the amendments of 2026-11-19 23:10, 2026-11-21 00:41, 2026-11-21 10:30 and 2026-11-21 11:00)",
        "warning": "TEST ONLY. Signed with the TEST ONLY key. Apps trust this key only in debug and test builds; a release build fails if it is in the trusted list.",
        "test_key": {
            "public_key_hex": hex(&g.test.public()),
            "key_id_hex": hex(&g.test.key_id()),
            "openssh_public_key_file": "keys/sxact-TEST-ONLY-signing-key.pub",
        },
        "generator": "src/activation/vectors.rs in simplego-provisioning (SXACT_WRITE_VECTORS=1 cargo test vectors)",
        "vectors": g.vectors,
    });
    let text = format!("{}\n", serde_json::to_string_pretty(&doc).unwrap());
    (g.files, text)
}

#[test]
fn vectors_are_deterministic_and_match_the_committed_fixtures() {
    let (files, json_text) = generate();
    let d = dir();
    if std::env::var_os("SXACT_WRITE_VECTORS").is_some() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "sxact") {
                std::fs::remove_file(p).unwrap();
            }
        }
        for (name, data) in &files {
            std::fs::write(d.join(name), data).unwrap();
        }
        std::fs::write(d.join("vectors.json"), &json_text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(d.join("vectors.json"))
        .expect("vectors.json missing: run SXACT_WRITE_VECTORS=1 cargo test vectors");
    assert_eq!(
        committed.replace("\r\n", "\n"),
        json_text,
        "vectors.json differs from the generator output"
    );
    let mut on_disk: Vec<String> = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".sxact"))
        .collect();
    on_disk.sort();
    let mut names: Vec<String> = files.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    assert_eq!(on_disk, names);
    for (name, data) in &files {
        assert_eq!(
            &std::fs::read(d.join(name)).unwrap(),
            data,
            "{name} differs from the generator output"
        );
    }
    // Every file is named in vectors.json, and only the TEST ONLY key signs.
    let doc: Value = serde_json::from_str(&json_text).unwrap();
    for n in &names {
        assert!(
            doc["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["file"] == *n),
            "{n} has no vector"
        );
    }
}
