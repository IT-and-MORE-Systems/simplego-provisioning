// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! CLI commands `activation ...` and `store ...`.
//!
//! Passphrases and the activation code are read from the terminal without
//! echo. The activation code is printed once to the terminal and never
//! written to a file or log.

use crate::activation::code::Code;
use crate::activation::container::{self, update_key_id, KDF_ARGON2ID, KDF_UPDATE_KEY};
use crate::activation::hosts::{mask_server, mask_support, parse_server, parse_support};
use crate::activation::issue::{self, parse_servers_file, parse_support_file, Request};
use crate::activation::keys::{is_test_key, key_id, read_public, KeyFile, TrustedKey};
use crate::activation::payload::{DeviceClass, Kind, NetworkMode, PayloadOf, RawPayload};
use crate::activation::rng::SystemRand;
use crate::activation::store::{self, Store, StoreError, STORE_KDF};
use crate::activation::Refusal;
use crate::config::Config;
use crate::{exit, names, util};
use base64ct::{Base64, Encoding};
use serde_json::json;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct ActOpts {
    pub json: bool,
    pub show_serial: bool,
    pub serial: Option<String>,
    pub customer_ref: Option<String>,
    pub device_class: Option<String>,
    pub network_mode: Option<String>,
    pub servers: Option<PathBuf>,
    pub support: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub rotate_update_key: bool,
    pub under_key_id: Option<String>,
    pub trusted: Vec<PathBuf>,
    pub code: bool,
    pub update_key_from_store: Option<String>,
    pub update_key_file: Option<PathBuf>,
    pub update_key_prompt: bool,
}

const UPDATE_KEY_FORM: &str =
    "the update key must be exactly 64 lowercase hex characters (a file may end with one newline)";

/// 64 lowercase hex characters into a 32-byte key.
fn parse_update_key_hex(s: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if s.len() != 64 {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut k = Zeroizing::new([0u8; 32]);
    for (i, b) in k.iter_mut().enumerate() {
        *b = (val(s[2 * i])? << 4) | val(s[2 * i + 1])?;
    }
    Some(k)
}

/// Reads `--update-key-file`: a regular file holding the 64 lowercase hex
/// characters of an update key, optionally followed by one `\n`. Refused if
/// group or others have any permission on it (it must be 0600 or 0400).
/// The read buffer is wiped.
pub fn read_update_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    use std::io::Read;
    let shown = path.display();
    let f = std::fs::File::open(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{shown} may be read by group or others (mode {mode:04o}); run chmod 600 on it, nothing was read"
            ));
        }
    }
    if meta.len() > 65 {
        return Err(format!("{shown}: {UPDATE_KEY_FORM}"));
    }
    let mut data = Zeroizing::new(Vec::with_capacity(66));
    f.take(66)
        .read_to_end(&mut data)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    let body = data.strip_suffix(b"\n").unwrap_or(&data);
    parse_update_key_hex(body).ok_or_else(|| format!("{shown}: {UPDATE_KEY_FORM}"))
}

/// Reads the update key from the terminal without echo.
fn prompt_update_key() -> Result<Zeroizing<[u8; 32]>, String> {
    let typed = prompt("update key (64 lowercase hex characters, not shown): ")?;
    parse_update_key_hex(typed.trim().as_bytes()).ok_or_else(|| UPDATE_KEY_FORM.to_string())
}

fn err(code: i32, msg: impl std::fmt::Display) -> i32 {
    eprintln!("{}: {msg}", names::BINARY);
    code
}

fn store_err(e: StoreError) -> i32 {
    err(exit::STORE, e)
}

fn prompt(msg: &str) -> Result<Zeroizing<String>, String> {
    crate::deliver_cmd::terminal_secret(msg, None)
}

pub fn store_path(cfg: &Config) -> Result<PathBuf, String> {
    match &cfg.admin_store_path {
        Some(p) => Ok(p.clone()),
        None => store::default_path()
            .ok_or_else(|| "HOME is not set; set admin_store_path in the config".into()),
    }
}

/// Takes the store lock before the passphrase is asked, so a second sxprov
/// process fails at once (exit 12). The returned store holds the lock until
/// the command drops it, after its last write.
fn open_store(cfg: &Config) -> Result<Store, i32> {
    let path = store_path(cfg).map_err(|e| err(exit::STORE, e))?;
    let lock = Store::lock_for_open(&path).map_err(store_err)?;
    let pass = prompt("store passphrase: ").map_err(|e| err(exit::STORE, e))?;
    Store::open_locked(lock, &pass).map_err(store_err)
}

// ---- store -------------------------------------------------------------------

pub fn cmd_store_init(cfg: &Config) -> i32 {
    let path = match store_path(cfg).map_err(|e| err(exit::STORE, e)) {
        Ok(p) => p,
        Err(c) => return c,
    };
    let lock = match Store::lock_for_init(&path) {
        Ok(l) => l,
        Err(e) => return store_err(e),
    };
    let path = lock.store_path().to_path_buf();
    println!("creating the admin store at {}", path.display());
    println!(
        "choose a store passphrase (at least {} characters); without it the store cannot be opened",
        store::MIN_PASSPHRASE_CHARS
    );
    let (a, b) = match (
        prompt("new store passphrase: "),
        prompt("repeat the passphrase: "),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return err(exit::STORE, e),
    };
    if *a != *b {
        return err(exit::STORE, "the passphrases differ; nothing was created");
    }
    match Store::init_locked(lock, &a, STORE_KDF, &mut SystemRand::new()) {
        Ok(_) => {
            println!(
                "admin store created (encrypted, mode 0600): {}",
                path.display()
            );
            exit::OK
        }
        Err(e) => store_err(e),
    }
}

pub fn cmd_store_list(cfg: &Config, o: &ActOpts) -> i32 {
    let s = match open_store(cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let serial = |v: &Option<String>| -> String {
        match v {
            Some(x) if o.show_serial => x.clone(),
            Some(x) => util::mask_serial(x),
            None => "-".into(),
        }
    };
    let customers: Vec<_> = s
        .data
        .customers
        .iter()
        .map(|(r, c)| {
            json!({"customer_ref": r, "issues": s.data.issues.iter().filter(|i| &i.customer_ref == r).count(),
                   "last_sequence": c.last_sequence, "earlier_update_keys": c.previous_update_keys.len(),
                   "created_at": c.created_at})
        })
        .collect();
    let issues: Vec<_> = s
        .data
        .issues
        .iter()
        .map(|i| {
            json!({"issued_at": i.issued_at, "kind": i.kind, "customer_ref": i.customer_ref, "device_class": i.device_class,
                   "network_mode": i.network_mode, "sequence": i.sequence, "file_id": i.file_id, "key_id": i.key_id,
                   "update_key_id": i.update_key_id, "rotated": i.rotated, "serial": serial(&i.serial),
                   "code": i.code_masked.clone().unwrap_or_else(|| "-".into())})
        })
        .collect();
    if o.json {
        let v = json!({"store": s.path(), "customers": customers, "issues": issues});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return exit::OK;
    }
    println!("admin store: {}", s.path().display());
    println!("\ncustomers ({}):", customers.len());
    for c in &customers {
        println!(
            "  {:<20} issues {:<4} last sequence {:<4} earlier update keys {:<2} created {}",
            c["customer_ref"].as_str().unwrap_or(""),
            c["issues"],
            c["last_sequence"],
            c["earlier_update_keys"],
            c["created_at"].as_str().unwrap_or("")
        );
    }
    println!("\nissues ({}):", issues.len());
    for i in &issues {
        println!(
            "  {} {:<10} {:<20} {:<7} {:<12} seq {:<4} file {} key {} serial {} code {}{}",
            i["issued_at"].as_str().unwrap_or(""),
            i["kind"].as_str().unwrap_or(""),
            i["customer_ref"].as_str().unwrap_or(""),
            i["device_class"].as_str().unwrap_or(""),
            i["network_mode"].as_str().unwrap_or(""),
            i["sequence"],
            i["file_id"].as_str().unwrap_or(""),
            &i["key_id"].as_str().unwrap_or("")[..8.min(i["key_id"].as_str().unwrap_or("").len())],
            i["serial"].as_str().unwrap_or(""),
            i["code"].as_str().unwrap_or(""),
            if i["rotated"].as_bool() == Some(true) {
                " (rotated update key)"
            } else {
                ""
            }
        );
    }
    exit::OK
}

// ---- activation pubkey -------------------------------------------------------

pub fn cmd_pubkey(o: &ActOpts) -> i32 {
    let Some(path) = &o.key else {
        return err(exit::USAGE, "activation pubkey needs --key PUBFILE");
    };
    let public = match read_public(path) {
        Ok(k) => k,
        Err(e) => return err(exit::SIGNING_KEY, e),
    };
    let id = util::hex(&key_id(&public));
    let test = is_test_key(&public);
    if o.json {
        let v = json!({"key_id": id, "public_key_hex": util::hex(&public),
                       "public_key_base64": Base64::encode_string(&public), "test_key": test});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("key_id:              {id}");
        println!("public key (hex):    {}", util::hex(&public));
        println!("public key (base64): {}", Base64::encode_string(&public));
        if test {
            println!(
                "NOTE: this is the TEST ONLY key; apps trust it only in debug and test builds"
            );
        }
    }
    exit::OK
}

// ---- activation issue / update -----------------------------------------------

fn request(o: &ActOpts, cmd: &str) -> Result<Request, i32> {
    let need = |v: &Option<String>, name: &str| {
        v.clone()
            .ok_or_else(|| err(exit::USAGE, format!("{cmd} needs {name}")))
    };
    let need_path = |v: &Option<PathBuf>, name: &str| {
        v.clone()
            .ok_or_else(|| err(exit::USAGE, format!("{cmd} needs {name}")))
    };
    let customer_ref = need(&o.customer_ref, "--customer-ref")?;
    let device_class = DeviceClass::parse(&need(&o.device_class, "--device-class")?)
        .map_err(|e| err(exit::USAGE, e))?;
    let network_mode = NetworkMode::parse(&need(&o.network_mode, "--network-mode")?)
        .map_err(|e| err(exit::USAGE, e))?;
    let servers = need_path(&o.servers, "--servers FILE")?;
    let support = need_path(&o.support, "--support FILE")?;
    let read = |p: &Path| {
        std::fs::read_to_string(p).map(Zeroizing::new).map_err(|e| {
            err(
                exit::ACTIVATION_INPUT,
                format!("cannot read {}: {e}", p.display()),
            )
        })
    };
    let (smp, xftp) =
        parse_servers_file(&read(&servers)?).map_err(|e| err(exit::ACTIVATION_INPUT, e))?;
    let support_address =
        parse_support_file(&read(&support)?).map_err(|e| err(exit::ACTIVATION_INPUT, e))?;
    Ok(Request {
        customer_ref,
        device_class,
        network_mode,
        smp,
        xftp,
        support_address,
        serial: o.serial.clone(),
    })
}

/// Reads the signing key file, refuses the test key and unprotected keys,
/// then asks for the passphrase.
fn signing_key(o: &ActOpts, cmd: &str) -> Result<KeyFile, i32> {
    let path = o
        .key
        .as_ref()
        .ok_or_else(|| err(exit::USAGE, format!("{cmd} needs --key PRIVFILE")))?;
    let kf = KeyFile::read(path).map_err(|e| err(exit::SIGNING_KEY, e))?;
    if is_test_key(&kf.public) {
        return Err(err(
            exit::SIGNING_KEY,
            "refusing the TEST ONLY signing key: files for customers need the real activation signing key",
        ));
    }
    if !kf.is_encrypted() {
        return Err(err(
            exit::SIGNING_KEY,
            "the activation signing key must be passphrase protected (ssh-keygen -p)",
        ));
    }
    Ok(kf)
}

fn issue_common(cfg: &Config, o: &ActOpts, kind: Kind) -> i32 {
    let cmd = if kind == Kind::Activation {
        "activation issue"
    } else {
        "activation update"
    };
    if kind == Kind::Activation && !std::io::stdout().is_terminal() {
        return err(
            exit::ACTIVATION_INPUT,
            "activation issue prints the activation code once and needs a terminal on standard output (no redirection)",
        );
    }
    let req = match request(o, cmd) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if let Err(e) = issue::precheck(&req, kind) {
        return err(exit::ACTIVATION_INPUT, e);
    }
    let under = match &o.under_key_id {
        Some(h) => match util::unhex(h).filter(|b| b.len() == 16) {
            Some(b) => {
                let mut id = [0u8; 16];
                id.copy_from_slice(&b);
                Some(id)
            }
            None => {
                return err(
                    exit::USAGE,
                    "--under-key-id needs 32 hex characters (an update key id)",
                )
            }
        },
        None => None,
    };
    if kind == Kind::Activation && (o.rotate_update_key || under.is_some()) {
        return err(
            exit::USAGE,
            "--rotate-update-key and --under-key-id are for activation update only",
        );
    }
    let Some(out) = o.out.clone() else {
        return err(exit::USAGE, format!("{cmd} needs --out FILE"));
    };
    if out.exists() {
        return err(
            exit::ACTIVATION_INPUT,
            format!("{} already exists; choose a new --out file", out.display()),
        );
    }
    let kf = match signing_key(o, cmd) {
        Ok(k) => k,
        Err(c) => return c,
    };
    let mut st = match open_store(cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let pass = match prompt("passphrase of the activation signing key: ") {
        Ok(p) => p,
        Err(e) => return err(exit::SIGNING_KEY, e),
    };
    let signer = match kf.unlock(Some(&pass)) {
        Ok(s) => s,
        Err(e) => return err(exit::SIGNING_KEY, e),
    };
    drop(pass);
    let now = util::fmt_unix(util::now_unix());
    let mut rng = SystemRand::new();
    let result = match kind {
        Kind::Activation => issue::activation(&mut st.data, &req, &signer, &mut rng, &now),
        Kind::Update => issue::update(
            &mut st.data,
            &req,
            &signer,
            &mut rng,
            &now,
            o.rotate_update_key,
            under,
        ),
    };
    drop(signer);
    let issued = match result {
        Ok(i) => i,
        Err(e) => return err(exit::ACTIVATION_INPUT, e),
    };
    if let Err(e) = st.save(&mut rng) {
        return err(exit::STORE, format!("{e}; no file was written"));
    }
    if let Err(e) = store::write_new_private(&out, &issued.file) {
        let _ = std::fs::remove_file(&out);
        return err(
            exit::ACTIVATION_INPUT,
            format!(
                "cannot write {}: {e}. The issue is recorded in the store (file_id {}), but no file exists; issue a new one",
                out.display(),
                issued.issue.file_id
            ),
        );
    }
    let i = &issued.issue;
    println!(
        "{} file written: {} ({} bytes, mode 0600)",
        kind.as_str(),
        out.display(),
        issued.file.len()
    );
    println!(
        "  file_id {}, customer {}, {}, {}, sequence {}, signing key_id {}, update key id {}{}",
        i.file_id,
        i.customer_ref,
        i.device_class.as_str(),
        i.network_mode.as_str(),
        i.sequence,
        i.key_id,
        i.update_key_id,
        if i.rotated {
            ", carries a NEW update key"
        } else {
            ""
        }
    );
    println!("  recorded in the admin store; the store keeps no copy of the file");
    if let Some(code) = &issued.code {
        println!("\nACTIVATION CODE (shown once, not stored anywhere):\n");
        println!("    {}\n", code.display().as_str());
        println!("Write it on the activation card now. It cannot be shown again; a lost code means a new file with a new code.");
    }
    exit::OK
}

pub fn cmd_issue(cfg: &Config, o: &ActOpts) -> i32 {
    issue_common(cfg, o, Kind::Activation)
}

pub fn cmd_update(cfg: &Config, o: &ActOpts) -> i32 {
    issue_common(cfg, o, Kind::Update)
}

// ---- activation inspect ------------------------------------------------------

fn masked_payload<M: serde::Serialize>(p: &PayloadOf<M>) -> serde_json::Value {
    let servers = |list: &[String], scheme: &str| -> Vec<String> {
        list.iter()
            .map(|a| {
                parse_server(a, scheme)
                    .map(|s| mask_server(&s))
                    .unwrap_or_else(|e| format!("INVALID: {e}"))
            })
            .collect()
    };
    let support = match parse_support(&p.support_address) {
        Ok(s) => mask_support(&s),
        Err(e) => json!({"invalid": e}),
    };
    json!({
        "payload_version": p.payload_version, "kind": p.kind, "file_id": p.file_id, "issued_at": p.issued_at,
        "customer_ref": p.customer_ref, "device_class": p.device_class, "network_mode": p.network_mode,
        "sequence": p.sequence,
        "servers": {"smp": servers(&p.servers.smp, "smp"), "xftp": servers(&p.servers.xftp, "xftp")},
        "support_address": support,
        "update_key": if p.update_key.is_some() { "present (hidden)" } else { "absent" },
    })
}

pub fn cmd_inspect(cfg_loader: &dyn Fn() -> Result<Config, i32>, o: &ActOpts, file: &str) -> i32 {
    let secrets_given = [
        o.code,
        o.update_key_from_store.is_some(),
        o.update_key_file.is_some(),
        o.update_key_prompt,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if secrets_given > 1 {
        return err(
            exit::USAGE,
            "give at most one of --code, --update-key-from-store, --update-key-file, --update-key-prompt",
        );
    }
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return err(exit::ACTIVATION_INPUT, format!("cannot read {file}: {e}")),
    };
    let mut trusted = Vec::new();
    for p in &o.trusted {
        match read_public(p) {
            Ok(k) => trusted.push(TrustedKey::new(
                &p.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                k,
            )),
            Err(e) => return err(exit::ACTIVATION_INPUT, e),
        }
    }
    let mut out = json!({"file": file, "size": bytes.len()});
    let mut lines = vec![format!("file: {file} ({} bytes)", bytes.len())];
    let finish = |out: serde_json::Value, lines: Vec<String>, code: i32| -> i32 {
        if o.json {
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        } else {
            for l in lines {
                println!("{l}");
            }
        }
        code
    };
    let parsed = match container::parse(&bytes) {
        Ok(p) => p,
        Err(r) => {
            out["result"] = json!({"refused": r.code(), "reason": r.to_string()});
            lines.push(format!("REFUSED: {r} ({})", r.code()));
            return finish(out, lines, exit::ACTIVATION_REFUSED);
        }
    };
    let h = parsed.header.clone();
    let kind = if h.kdf_alg == KDF_ARGON2ID {
        "activation"
    } else {
        "update"
    };
    out["header"] = json!({"version": h.version, "kdf_alg": h.kdf_alg, "kdf_m_kib": h.kdf_m_kib, "kdf_t": h.kdf_t,
        "kdf_p": h.kdf_p, "salt": util::hex(&h.salt), "aead_alg": h.aead_alg, "nonce": util::hex(&h.nonce),
        "sig_alg": h.sig_alg, "key_id": util::hex(&h.key_id), "ct_len": h.ct_len, "container_kind": kind});
    lines.push(format!(
        "header: SXACT v{}, {} file, kdf_alg {} (m {} KiB, t {}, p {}), aead_alg {} (AES-256-GCM), sig_alg {} (Ed25519), ct_len {}",
        h.version, kind, h.kdf_alg, h.kdf_m_kib, h.kdf_t, h.kdf_p, h.aead_alg, h.sig_alg, h.ct_len
    ));
    if h.kdf_alg == KDF_UPDATE_KEY {
        lines.push(format!("update key id: {}", util::hex(&h.salt)));
    }
    lines.push(format!("signing key_id: {}", util::hex(&h.key_id)));
    let verified = match parsed.verify(&trusted) {
        Ok(v) => {
            out["trusted"] = json!(true);
            out["signature"] = json!("valid");
            lines.push(format!("trusted: yes ({})", v.signer_name));
            lines.push("signature: valid".into());
            v
        }
        Err(r) => {
            let (t, s) = match r {
                Refusal::UnknownKey => (
                    "no",
                    "not checked (the key is not in the given trusted list)",
                ),
                _ => ("yes", "INVALID"),
            };
            out["trusted"] = json!(t == "yes");
            out["signature"] = json!(s);
            out["result"] = json!({"refused": r.code(), "reason": r.to_string()});
            lines.push(format!(
                "trusted: {t}{}",
                if trusted.is_empty() {
                    " (no --trusted key given)"
                } else {
                    ""
                }
            ));
            lines.push(format!("signature: {s}"));
            lines.push(format!("REFUSED: {r} ({})", r.code()));
            return finish(out, lines, exit::ACTIVATION_REFUSED);
        }
    };
    let plain = if o.code {
        if h.kdf_alg != KDF_ARGON2ID {
            return err(exit::USAGE, "--code is for activation files; use --update-key-from-store REF, --update-key-file FILE or --update-key-prompt for an update file");
        }
        let input = match prompt("activation code: ") {
            Ok(c) => c,
            Err(e) => return err(exit::ACTIVATION_INPUT, e),
        };
        let code = match Code::parse_input(&input) {
            Ok(c) => c,
            Err(e) => {
                let r = Refusal::BadCode(e);
                out["result"] = json!({"refused": r.code(), "reason": r.to_string()});
                lines.push(format!("REFUSED: {r} ({})", r.code()));
                return finish(out, lines, exit::ACTIVATION_REFUSED);
            }
        };
        Some(verified.decrypt_with_code(&code))
    } else if let Some(r) = &o.update_key_from_store {
        if h.kdf_alg != KDF_UPDATE_KEY {
            return err(
                exit::USAGE,
                "--update-key-from-store is for update files; use --code for an activation file",
            );
        }
        let cfg = match cfg_loader() {
            Ok(c) => c,
            Err(c) => return c,
        };
        let st = match open_store(&cfg) {
            Ok(s) => s,
            Err(c) => return c,
        };
        let Some(c) = st.data.customers.get(r) else {
            return err(exit::STORE, format!("no customer {r} in the admin store"));
        };
        let mut key = None;
        for k in std::iter::once(&c.update_key)
            .chain(c.previous_update_keys.iter().map(|p| &p.update_key))
        {
            if let Some(b) = util::unhex(k).filter(|b| b.len() == 32) {
                let mut a = Zeroizing::new([0u8; 32]);
                a.copy_from_slice(&b);
                if update_key_id(&a) == h.salt {
                    key = Some(a);
                }
            }
        }
        match key {
            Some(k) => Some(verified.decrypt_with_update_key(&k)),
            None => Some(Err(Refusal::WrongUpdateKey)),
        }
    } else if o.update_key_file.is_some() || o.update_key_prompt {
        if h.kdf_alg != KDF_UPDATE_KEY {
            return err(
                exit::USAGE,
                "--update-key-file and --update-key-prompt are for update files; use --code for an activation file",
            );
        }
        let key = match &o.update_key_file {
            Some(f) => read_update_key_file(f),
            None => prompt_update_key(),
        };
        let key = match key {
            Ok(k) => k,
            Err(e) => return err(exit::ACTIVATION_INPUT, e),
        };
        // The key (Zeroizing) is wiped when it goes out of scope here.
        Some(verified.decrypt_with_update_key(&key))
    } else {
        None
    };
    let Some(plain) = plain else {
        out["result"] = json!(
            "signature valid; payload not decrypted (use --code, --update-key-from-store REF, --update-key-file FILE or --update-key-prompt)"
        );
        lines.push("payload: not decrypted (use --code for an activation file; --update-key-from-store REF, --update-key-file FILE or --update-key-prompt for an update file)".into());
        return finish(out, lines, exit::OK);
    };
    // Section 6 steps 5 and 6 without the device class, which only the app
    // knows: the fields, the network mode value, then the address rules.
    let result = plain.and_then(|pt| {
        let raw = RawPayload::from_json(&pt)?;
        let container_kind = if h.kdf_alg == KDF_ARGON2ID {
            Kind::Activation
        } else {
            Kind::Update
        };
        let v = raw
            .check_fields(container_kind)
            .and_then(|()| raw.clone().into_payload())
            .and_then(|p| p.check_addresses());
        Ok((raw, v))
    });
    match result {
        Err(r) => {
            out["result"] = json!({"refused": r.code(), "reason": r.to_string()});
            lines.push(format!("REFUSED: {r} ({})", r.code()));
            finish(out, lines, exit::ACTIVATION_REFUSED)
        }
        Ok((p, v)) => {
            let m = masked_payload(&p);
            lines.push("payload (hosts masked, passwords and the update key hidden):".into());
            for l in serde_json::to_string_pretty(&m).unwrap_or_default().lines() {
                lines.push(format!("  {l}"));
            }
            out["payload"] = m;
            match v {
                Ok(()) => {
                    out["result"] = json!("ok");
                    lines.push("result: ok, the payload passes every rule of the format".into());
                    finish(out, lines, exit::OK)
                }
                Err(r) => {
                    out["result"] = json!({"refused": r.code(), "reason": r.to_string()});
                    lines.push(format!("REFUSED: {r} ({})", r.code()));
                    finish(out, lines, exit::ACTIVATION_REFUSED)
                }
            }
        }
    }
}

// Every test here uses Unix file modes; on other systems the module is empty.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::activation::store::tests::temp_dir;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sxact")
    }

    /// The installation's update key of a vector in vectors.json.
    fn vector_key(name: &str) -> String {
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixtures().join("vectors.json")).unwrap())
                .unwrap();
        doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()["installation"]["update_key_hex"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[cfg(unix)]
    fn write_mode(p: &Path, data: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::remove_file(p);
        std::fs::write(p, data).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn update_key_file_rules() {
        let d = temp_dir("keyfile");
        let p = d.join("update.key");
        let key = vector_key("update-phone");
        for ok in [format!("{key}\n"), key.clone()] {
            write_mode(&p, ok.as_bytes(), 0o600);
            let k = read_update_key_file(&p).unwrap();
            assert_eq!(util::hex(&*k), key);
        }
        write_mode(&p, key.as_bytes(), 0o400);
        assert!(read_update_key_file(&p).is_ok());
        for mode in [0o640, 0o604, 0o620, 0o644] {
            write_mode(&p, key.as_bytes(), mode);
            let e = read_update_key_file(&p).unwrap_err();
            assert!(
                e.contains("may be read by group or others"),
                "{mode:o}: {e}"
            );
        }
        for bad in [
            format!("{key}\r\n"),
            format!("{key}\n\n"),
            format!(" {key}"),
            key.to_uppercase(),
            key[..63].to_string(),
            format!("{key}0"),
            String::new(),
        ] {
            write_mode(&p, bad.as_bytes(), 0o600);
            let e = read_update_key_file(&p).unwrap_err();
            assert!(e.contains("64 lowercase hex"), "{bad:?}: {e}");
            assert!(!e.contains(&key[..16]), "the key is never shown: {e}");
        }
        assert!(read_update_key_file(&d.join("missing.key")).is_err());
        assert!(read_update_key_file(&d).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn inspect(file: &str, key_file: Option<PathBuf>, code: bool) -> i32 {
        let o = ActOpts {
            trusted: vec![fixtures().join("keys/sxact-TEST-ONLY-signing-key.pub")],
            update_key_file: key_file,
            code,
            json: true,
            ..Default::default()
        };
        let path = fixtures().join(file);
        cmd_inspect(&|| Err(exit::CONFIG), &o, path.to_str().unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn inspect_with_update_key_file_on_the_vectors() {
        let d = temp_dir("inspect-keyfile");
        let p = d.join("update.key");
        write_mode(
            &p,
            format!("{}\n", vector_key("update-phone")).as_bytes(),
            0o600,
        );
        for f in [
            "update-phone.sxact",
            "update-desktop.sxact",
            "update-phone-rotate-key.sxact",
            "update-support-short-link.sxact",
        ] {
            assert_eq!(inspect(f, Some(p.clone()), false), exit::OK, "{f}");
        }
        // A payload rule is still checked after decryption.
        assert_eq!(
            inspect("refused-short-link-without-c.sxact", Some(p.clone()), false),
            exit::ACTIVATION_REFUSED
        );
        // The other customer's update file does not open with this key.
        assert_eq!(
            inspect(
                "refused-update-other-customer-key.sxact",
                Some(p.clone()),
                false
            ),
            exit::ACTIVATION_REFUSED
        );
        // An activation file needs --code, not an update key.
        assert_eq!(
            inspect("activation-phone.sxact", Some(p.clone()), false),
            exit::USAGE
        );
        // At most one secret source.
        assert_eq!(
            inspect("update-phone.sxact", Some(p.clone()), true),
            exit::USAGE
        );
        // A readable key file is refused before anything is decrypted.
        write_mode(&p, vector_key("update-phone").as_bytes(), 0o644);
        assert_eq!(
            inspect("update-phone.sxact", Some(p.clone()), false),
            exit::ACTIVATION_INPUT
        );
        // Without a secret, inspect checks the signature only.
        assert_eq!(inspect("update-phone.sxact", None, false), exit::OK);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
