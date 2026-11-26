// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! CLI glue for `deliver`, `undeliver`, `handover`, `apk inspect` and the
//! test store: prompts, flags, trust loading, the private work directory.
//!
//! Real deliveries keep every prompt (passphrases without echo, typed
//! confirmations) and show the activation code only on a terminal. With
//! `--test-delivery`, and only then, the passphrases come from files, `--yes`
//! replaces the typed confirmations (never the STALE confirmation of the
//! revocation list), and the code goes to standard output.

use crate::activation::rng::SystemRand;
use crate::activation::store::{Store, STORE_KDF};
use crate::config::Config;
use crate::deliver::{self, DeliverArgs, Env, Secret, Ui};
use crate::device::Tools;
use crate::util::now_unix;
use crate::verify_run::{self, TrustMaterial};
use crate::{apk, exit, names, util};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct DelOpts {
    pub d: DeliverArgs,
    pub test_device: bool,
    pub yes: bool,
    pub confirm_stale: bool,
    pub store_pass_file: Option<PathBuf>,
    pub key_pass_file: Option<PathBuf>,
    pub json: bool,
    pub offline: bool,
    /// `undeliver --discard-test-setup` (test phones only).
    pub discard_test_setup: bool,
}

fn err(code: i32, msg: impl std::fmt::Display) -> i32 {
    eprintln!("{}: {msg}", names::BINARY);
    code
}

/// Reads a test passphrase file: a regular file not readable by group or
/// others, one line (a trailing newline is dropped).
pub fn read_pass_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{shown} may be read by group or others (mode {mode:04o}); run chmod 600 on it"
            ));
        }
    }
    let raw = Zeroizing::new(std::fs::read(path).map_err(|e| format!("cannot read {shown}: {e}"))?);
    let body = raw.strip_suffix(b"\n").unwrap_or(&raw);
    let s = std::str::from_utf8(body).map_err(|_| format!("{shown} is not UTF-8"))?;
    if s.is_empty() || s.contains('\n') {
        return Err(format!("{shown} must hold exactly one line"));
    }
    Ok(Zeroizing::new(s.to_string()))
}

pub(crate) struct TerminalUi;

/// What replaces a typed word when there is no terminal, if anything.
fn word_flag(word: &str) -> &'static str {
    match word {
        "WIPE" => " (on a test phone, --test-device --yes replaces it)",
        "NORMAL TIER" => " (in a test delivery, --yes replaces it)",
        "STALE" => " (or give --confirm-stale-revocation-list)",
        _ => "",
    }
}

/// A passphrase from the terminal. Without a terminal on standard input it
/// stops at once and names the flag that replaces it in a test run; it
/// never waits on `/dev/tty` unseen.
pub(crate) fn terminal_secret(
    prompt: &str,
    flag: Option<&str>,
) -> Result<Zeroizing<String>, String> {
    if !std::io::stdin().is_terminal() {
        let what = prompt.trim().trim_end_matches(':');
        return Err(match flag {
            Some(f) => format!(
                "no terminal on standard input to ask for the {what}; run it in a terminal, or in a test run give {f}"
            ),
            None => format!(
                "no terminal on standard input to ask for the {what}; run it in a terminal"
            ),
        });
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read from the terminal: {e}"))
}

impl Ui for TerminalUi {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String> {
        terminal_secret(what.prompt(), Some(what.test_flag()))
    }
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String> {
        if !std::io::stdin().is_terminal() {
            return Err(format!(
                "no terminal on standard input to type {word}{}",
                word_flag(word)
            ));
        }
        eprint!("{question}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        Ok(line.trim() == word)
    }
    fn show_code(&mut self, code: &str) {
        println!("\nACTIVATION CODE (shown once, not stored anywhere):\n");
        println!("    {code}\n");
        println!("Write it on the activation card now. It cannot be shown again.\n");
    }
}

struct TestUi {
    store: Option<Zeroizing<String>>,
    key: Option<Zeroizing<String>>,
    yes: bool,
}

impl Ui for TestUi {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String> {
        let v = match what {
            Secret::StorePassphrase => &self.store,
            Secret::SigningKeyPassphrase => &self.key,
        };
        v.clone().ok_or_else(|| match what {
            Secret::StorePassphrase => "--test-store-passphrase-file is needed".to_string(),
            Secret::SigningKeyPassphrase => "--test-key-passphrase-file is needed".to_string(),
        })
    }
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String> {
        if self.yes {
            eprintln!("{question}{word} (--yes, test delivery)");
            return Ok(true);
        }
        TerminalUi.confirm(word, question)
    }
    fn show_code(&mut self, code: &str) {
        println!("\nTEST ACTIVATION CODE (test delivery, TEST ONLY key): {code}\n");
    }
}

/// `--json`: the activation code in the one event that shows it; every
/// other question goes to the inner prompts.
struct JsonCodeUi {
    inner: Box<dyn Ui>,
    test: bool,
}

impl Ui for JsonCodeUi {
    fn secret(&mut self, what: Secret) -> Result<Zeroizing<String>, String> {
        self.inner.secret(what)
    }
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String> {
        self.inner.confirm(word, question)
    }
    fn show_code(&mut self, code: &str) {
        println!(
            "{}",
            serde_json::json!({"event": "activation_code", "code": code, "test": self.test,
                               "message": "shown once, not stored anywhere"})
        );
    }
}

fn make_ui(cfg: &Config, o: &DelOpts) -> Result<Box<dyn Ui>, i32> {
    let inner = make_ui_inner(cfg, o)?;
    if o.json {
        return Ok(Box::new(JsonCodeUi {
            inner,
            test: o.d.test_delivery,
        }));
    }
    Ok(inner)
}

fn make_ui_inner(cfg: &Config, o: &DelOpts) -> Result<Box<dyn Ui>, i32> {
    let test_flags = o.yes || o.store_pass_file.is_some() || o.key_pass_file.is_some();
    if !o.d.test_delivery {
        if test_flags {
            return Err(err(
                exit::USAGE,
                "--yes and the --test-*-passphrase-file options are only for --test-delivery",
            ));
        }
        return Ok(Box::new(TerminalUi));
    }
    if !cfg.allow_test_key_for_test_deliveries {
        return Err(err(
            exit::SIGNING_KEY,
            "--test-delivery needs allow_test_key_for_test_deliveries = true in the config",
        ));
    }
    let read = |p: &Option<PathBuf>| -> Result<Option<Zeroizing<String>>, i32> {
        match p {
            Some(p) => read_pass_file(p).map(Some).map_err(|e| err(exit::USAGE, e)),
            None => Ok(None),
        }
    };
    Ok(Box::new(TestUi {
        store: read(&o.store_pass_file)?,
        key: read(&o.key_pass_file)?,
        yes: o.yes,
    }))
}

/// A private directory for this run (mode 0700), removed afterwards.
pub(crate) struct WorkDir(pub(crate) PathBuf);

impl WorkDir {
    pub(crate) fn new() -> Result<WorkDir, String> {
        let mut r = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut r)
            .map_err(|_| "no system randomness")?;
        let d = std::env::temp_dir().join(format!("sxprov-deliver-{}", util::hex(&r)));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&d)
            .map_err(|e| format!("cannot create {}: {e}", d.display()))?;
        Ok(WorkDir(d))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn challenge() -> Result<Vec<u8>, String> {
    let mut c = vec![0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut c)
        .map_err(|_| "no system randomness".to_string())?;
    Ok(c)
}

pub(crate) fn sleep(d: Duration) {
    std::thread::sleep(d)
}

pub(crate) fn tools(cfg: &Config) -> Tools {
    Tools {
        adb: cfg.adb_path.clone(),
        fastboot: cfg.fastboot_path.clone(),
    }
}

/// Loads the trust material and handles a stale revocation list (typed
/// STALE or `--confirm-stale-revocation-list`; `--yes` never covers it).
fn trust(cfg: &Config, o: &DelOpts) -> Result<(TrustMaterial, bool), i32> {
    trust_with(cfg, o.confirm_stale, "deliver")
}

/// The trust material, with the STALE confirmation of a stale revocation
/// list (`--confirm-stale-revocation-list` or typed; `--yes` never covers it).
pub(crate) fn trust_with(
    cfg: &Config,
    confirm_stale: bool,
    what: &str,
) -> Result<(TrustMaterial, bool), i32> {
    let tm = verify_run::load_trust(cfg).map_err(|(c, e)| err(c, e))?;
    let now = now_unix();
    if !tm.revocation_stale(cfg, now) {
        return Ok((tm, false));
    }
    let age = util::fmt_age(now.saturating_sub(tm.rev.meta.fetched_at));
    eprintln!(
        "WARNING: the Google revocation list is {age} old (threshold {} days). Run `{} trust refresh` if possible.",
        cfg.revocation_max_age_days,
        names::BINARY
    );
    if confirm_stale {
        eprintln!("operator confirmation given with --confirm-stale-revocation-list");
        return Ok((tm, true));
    }
    match TerminalUi.confirm(
        "STALE",
        &format!("Type STALE to {what} against the stale list anyway: "),
    ) {
        Ok(true) => Ok((tm, true)),
        Ok(false) => Err(err(
            exit::STALE_NOT_CONFIRMED,
            "not confirmed; nothing was run",
        )),
        Err(e) => Err(err(
            exit::STALE_NOT_CONFIRMED,
            format!("{e}; nothing was run"),
        )),
    }
}

fn need(o: &DelOpts, cmd: &str) -> Result<(), i32> {
    let d = &o.d;
    let missing = [
        (d.serial.is_empty(), "--serial SERIAL"),
        (d.apk.as_os_str().is_empty(), "--apk FILE"),
        (d.customer_ref.is_empty(), "--customer-ref REF"),
        (d.network_mode.is_empty(), "--network-mode MODE"),
        (d.servers.as_os_str().is_empty(), "--servers FILE"),
        (d.support.as_os_str().is_empty(), "--support FILE"),
        (d.key.as_os_str().is_empty(), "--key PRIVFILE"),
    ];
    if let Some((_, name)) = missing.iter().find(|(m, _)| *m) {
        return Err(err(exit::USAGE, format!("{cmd} needs {name}")));
    }
    Ok(())
}

pub fn cmd_deliver(cfg: &Config, o: &DelOpts) -> i32 {
    if let Err(c) = need(o, "deliver") {
        return c;
    }
    if !o.d.dry_run && !o.d.test_delivery && !o.json && !std::io::stdout().is_terminal() {
        return err(
            exit::DELIVERY_REFUSED,
            "deliver shows the activation code once and needs a terminal on standard output (no redirection)",
        );
    }
    let mut ui = match make_ui(cfg, o) {
        Ok(u) => u,
        Err(c) => return c,
    };
    let tm = if o.d.normal_tier {
        None
    } else {
        match trust(cfg, o) {
            Ok(t) => Some(t),
            Err(c) => return c,
        }
    };
    let work = match WorkDir::new() {
        Ok(w) => w,
        Err(e) => return err(exit::DEVICE, e),
    };
    let mut ch = challenge;
    let mut rng = SystemRand::new();
    let now = now_unix;
    let offline = o.offline;
    // Over Tor only (socks5h); none with --offline. Used for SimpleX's
    // repository; the GrapheneOS status makes its own.
    let http = if offline || o.d.fdroid_apk.is_none() {
        None
    } else {
        match crate::grapheneos::TorHttp::new(
            &cfg.tor_socks_proxy,
            Duration::from_secs(60),
            cfg.download_idle(),
        ) {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("network: offline ({e})");
                None
            }
        }
    };
    let os_status = move |i: &crate::grapheneos::status::Installed| {
        crate::os_cmd::status_of(cfg, i, &cfg.grapheneos_channel, offline)
    };
    let mut env = Env {
        cfg,
        tools: tools(cfg),
        ui: ui.as_mut(),
        now: &now,
        challenge: &mut ch,
        rng: &mut rng,
        sleep: &sleep,
        trust: tm.as_ref().map(|(t, _)| t),
        stale_confirmed: tm.as_ref().map(|(_, s)| *s).unwrap_or(false),
        work_dir: work.0.clone(),
        ui_retries: 20,
        os_status: Some(&os_status),
        http: http.as_ref().map(|h| h as &dyn crate::grapheneos::Http),
    };
    let mut out = std::io::stdout();
    deliver::deliver(&mut env, &mut out, &o.d)
}

fn small_env_cmd(
    cfg: &Config,
    o: &DelOpts,
    f: impl FnOnce(&mut Env, &mut dyn Write) -> i32,
) -> i32 {
    let mut ui = match make_ui(cfg, o) {
        Ok(u) => u,
        Err(c) => return c,
    };
    let mut ch = challenge;
    let mut rng = SystemRand::new();
    let now = now_unix;
    let mut env = Env {
        cfg,
        tools: tools(cfg),
        ui: ui.as_mut(),
        now: &now,
        challenge: &mut ch,
        rng: &mut rng,
        sleep: &sleep,
        trust: None,
        stale_confirmed: false,
        work_dir: std::env::temp_dir(),
        ui_retries: 10,
        os_status: None,
        http: None,
    };
    let mut out = std::io::stdout();
    f(&mut env, &mut out)
}

pub fn cmd_undeliver(cfg: &Config, o: &DelOpts) -> i32 {
    if o.d.serial.is_empty() {
        return err(exit::USAGE, "undeliver needs --serial SERIAL");
    }
    small_env_cmd(cfg, o, |env, out| {
        deliver::undo::undeliver(
            env,
            out,
            &o.d.serial,
            deliver::undo::UndoOpts {
                test_device: o.test_device,
                discard_test_setup: o.discard_test_setup,
                json: o.json,
            },
        )
    })
}

pub fn cmd_handover(cfg: &Config, o: &DelOpts) -> i32 {
    if o.d.serial.is_empty() {
        return err(exit::USAGE, "handover needs --serial SERIAL");
    }
    small_env_cmd(cfg, o, |env, out| {
        deliver::undo::handover(env, out, &o.d.serial, o.json)
    })
}

/// `store init --test-delivery --test-store-passphrase-file FILE`: a
/// throwaway store for test deliveries, without a terminal.
pub fn cmd_test_store_init(cfg: &Config, o: &DelOpts) -> i32 {
    if !cfg.allow_test_key_for_test_deliveries {
        return err(
            exit::STORE,
            "a test store needs allow_test_key_for_test_deliveries = true in the config",
        );
    }
    let Some(f) = &o.store_pass_file else {
        return err(
            exit::USAGE,
            "store init --test-delivery needs --test-store-passphrase-file FILE",
        );
    };
    let pass = match read_pass_file(f) {
        Ok(p) => p,
        Err(e) => return err(exit::USAGE, e),
    };
    let path = match deliver::store_path(cfg) {
        Ok(p) => p,
        Err(e) => return err(exit::STORE, e),
    };
    let lock = match Store::lock_for_init(&path) {
        Ok(l) => l,
        Err(e) => return err(exit::STORE, e),
    };
    match Store::init_locked(lock, &pass, STORE_KDF, &mut SystemRand::new()) {
        Ok(_) => {
            println!(
                "TEST admin store created (encrypted, mode 0600): {}",
                path.display()
            );
            exit::OK
        }
        Err(e) => err(exit::STORE, e),
    }
}

pub fn cmd_apk_inspect(file: &str, json: bool) -> i32 {
    match apk::inspect(Path::new(file)) {
        Ok(i) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&i).unwrap_or_default());
            } else {
                println!("package:      {}", i.package);
                println!("versionCode:  {}", i.version_code);
                println!("versionName:  {}", i.version_name.as_deref().unwrap_or("-"));
                println!("size:         {} bytes", i.size);
                println!("SHA-256:      {}", i.sha256);
                println!("signer ({}): {}", i.scheme, i.signer_sha256);
                if let Some(w) = i.key_warning() {
                    println!("WARNING:      {w}");
                }
                for f in &i.link_filters {
                    println!(
                        "web links:    {} schemes {} hosts {}{}{}",
                        f.component,
                        f.schemes.join(","),
                        if f.hosts.is_empty() {
                            "-".to_string()
                        } else {
                            f.hosts.join(",")
                        },
                        if f.auto_verify { " autoVerify" } else { "" },
                        if f.unresolved.is_empty() {
                            ""
                        } else {
                            " (references not resolved)"
                        }
                    );
                }
                let unresolved = i.unresolved_links();
                if !unresolved.is_empty() {
                    println!("WARNING:      not resolved here: {}", unresolved.join(", "));
                }
                let hosts = i.auto_verify_hosts();
                println!(
                    "app link verification at install: {}",
                    if hosts.is_empty() {
                        "none".to_string()
                    } else {
                        format!("{} host(s): {}", hosts.len(), hosts.join(", "))
                    }
                );
                println!("(signature block and content digest verified)");
            }
            exit::OK
        }
        Err(e) => err(exit::DELIVERY_APK, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test runs have no terminal on standard input (`</dev/null`): every
    /// question stops at once and names what replaces it.
    #[test]
    fn no_terminal_stops_at_once_and_names_the_flag() {
        if std::io::stdin().is_terminal() {
            eprintln!("skipped: standard input is a terminal");
            return;
        }
        let t0 = std::time::Instant::now();
        let e = TerminalUi.secret(Secret::StorePassphrase).unwrap_err();
        assert!(e.contains("--test-store-passphrase-file FILE"), "{e}");
        assert!(e.contains("store passphrase"), "{e}");
        let e = TerminalUi.secret(Secret::SigningKeyPassphrase).unwrap_err();
        assert!(e.contains("--test-key-passphrase-file FILE"), "{e}");
        let e = TerminalUi.confirm("WIPE", "Type WIPE: ").unwrap_err();
        assert!(e.contains("--test-device --yes"), "{e}");
        let e = TerminalUi.confirm("STALE", "Type STALE: ").unwrap_err();
        assert!(e.contains("--confirm-stale-revocation-list"), "{e}");
        let e = terminal_secret("store passphrase: ", None).unwrap_err();
        assert!(e.contains("run it in a terminal"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
