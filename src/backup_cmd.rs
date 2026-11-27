// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! CLI `backup ...`, and the automatic backup at the end of every command.
//!
//! Every command takes `--json`: then standard output carries one event per
//! line (as `deliver`), never the recovery code or a password. The backup
//! that runs by itself at the end of another command (after a store or
//! config write, or when the last good backup is older than 24 hours) and
//! the warnings report on standard error, so a command's own output stays
//! as it was.

use crate::activation::rng::{Rand, SystemRand};
use crate::activation::store::{self, Store};
use crate::activation::storekey::{self, Creds};
use crate::backup::engine::{self, Events, Outcome};
use crate::backup::state::{self, Destination, State, Target};
use crate::backup::ui::{self, Secrets};
use crate::backup::{agefile, code, container, dest, keys};
use crate::config::Config;
use crate::util::{fmt_age, fmt_unix, hex, now_unix};
use crate::{exit, names};
use base64ct::{Base64, Encoding};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct BackupOpts {
    pub json: bool,
    pub from: Option<PathBuf>,
    pub to: Option<PathBuf>,
    pub replace: bool,
    /// `backup now --scheduled`: only when the last good backup is older
    /// than 24 hours (the hourly timer).
    pub scheduled: bool,
    pub code_fd: Option<i32>,
    pub confirm_fd: Option<i32>,
    pub credentials: Option<PathBuf>,
    pub forget_old: bool,
    pub allow_unencrypted_disk: bool,
}

/// Text lines, or `--json` events, to standard output (or standard error
/// for the automatic run).
pub struct Out {
    pub json: bool,
    pub stderr: bool,
}

impl Out {
    fn write(&self, s: &str) {
        if self.stderr {
            eprintln!("{s}");
        } else {
            println!("{s}");
            let _ = std::io::stdout().flush();
        }
    }
}

impl Events for Out {
    fn event(&mut self, v: serde_json::Value) {
        if self.json {
            self.write(&v.to_string());
        }
    }
    fn line(&mut self, s: &str) {
        if !self.json {
            if self.stderr {
                self.write(&format!("{}: {s}", names::BINARY));
            } else {
                self.write(s);
            }
        }
    }
}

fn fail(o: &mut Out, code: i32, msg: impl std::fmt::Display) -> i32 {
    o.event(json!({"event": "error", "exit": code, "message": msg.to_string()}));
    if !o.json {
        eprintln!("{}: {msg}", names::BINARY);
    }
    code
}

fn store_path(cfg: &Config) -> Result<PathBuf, String> {
    crate::activation_cmd::store_path(cfg)
}

fn config_text(cfg: &Config) -> Option<String> {
    cfg.loaded_from
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
}

fn open_store(cfg: &Config) -> Result<Store, String> {
    let p = store_path(cfg)?;
    let lock = Store::lock_for_open(&p).map_err(|e| e.to_string())?;
    Store::open_locked(lock, &Creds::system())
        .map(|(s, _)| s)
        .map_err(|e| e.to_string())
}

fn load_state(store: &Path) -> Result<State, String> {
    State::load(store)?.ok_or_else(|| "backups are not set up: run `sxprov backup init`".into())
}

fn secrets(o: &BackupOpts) -> Result<Box<dyn Secrets>, String> {
    match (o.code_fd, o.confirm_fd) {
        (_, Some(c)) => Ok(Box::new(ui::Fds::new(o.code_fd, c)?)),
        (Some(_), None) => Err("--code-fd needs --confirm-fd".into()),
        (None, None) => Ok(Box::new(ui::Terminal)),
    }
}

fn via(o: &BackupOpts) -> &'static str {
    if o.confirm_fd.is_some() {
        "code-fd"
    } else {
        "terminal"
    }
}

/// Reports a run and gives its exit code.
fn report_run(r: &engine::RunReport, out: &mut Out) -> i32 {
    let failed = r
        .results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Failed(_)))
        .count();
    let skipped = r
        .results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::NotConnected(_)))
        .count();
    let written = r.written();
    out.event(
        json!({"event": "backup_done", "file": r.file, "written": written,
                     "not_connected": skipped, "failed": failed}),
    );
    out.line(&format!(
        "backup {}: {written} destination(s) written and checked, {skipped} not connected, {failed} failed",
        r.file
    ));
    if failed > 0 || written == 0 {
        exit::BACKUP
    } else {
        exit::OK
    }
}

/// Asks the backup password or the recovery code once.
fn ask_secret(s: &mut dyn Secrets, out: &mut Out) -> Result<Zeroizing<String>, String> {
    out.event(json!({"event": "ask", "what": "backup_password_or_recovery_code"}));
    s.ask(
        "backup password or recovery code",
        "backup password or recovery code: ",
    )
}

pub fn cmd(cfg: &Config, o: &BackupOpts, words: &[&str]) -> i32 {
    let mut out = Out {
        json: o.json,
        stderr: false,
    };
    if (o.code_fd.is_some() || o.confirm_fd.is_some())
        && !matches!(
            words,
            ["init"] | ["new-code"] | ["password"] | ["drill"] | ["restore"]
        )
    {
        return fail(
            &mut out,
            exit::USAGE,
            "--code-fd and --confirm-fd are for init, new-code, password, drill and restore",
        );
    }
    let code = match words {
        ["init"] => cmd_init(cfg, o, &mut out),
        ["now"] => cmd_now(cfg, o, &mut out),
        ["list"] => cmd_list(cfg, o, &mut out),
        ["verify"] => cmd_verify(cfg, &mut out),
        ["restore"] => cmd_restore(cfg, o, &mut out),
        ["drill"] => cmd_drill(cfg, o, &mut out),
        ["password"] => cmd_password(cfg, o, &mut out),
        ["new-code"] => cmd_new_code(cfg, o, &mut out),
        ["destination", "add", "folder", name, path] => cmd_dest_add(
            cfg,
            name,
            Target::Folder {
                path: PathBuf::from(path),
            },
            &mut out,
        ),
        ["destination", "add", "webdav", name, url] => match &o.credentials {
            Some(c) => cmd_dest_add(
                cfg,
                name,
                Target::Webdav {
                    url: url.to_string(),
                    credentials: absolute(c),
                },
                &mut out,
            ),
            None => fail(
                &mut out,
                exit::USAGE,
                "destination add webdav needs --credentials FILE",
            ),
        },
        ["destination", "remove", name] => cmd_dest_remove(cfg, name, &mut out),
        ["destination", "list"] => cmd_list(cfg, o, &mut out),
        ["timer", "install"] => cmd_timer(cfg, true, &mut out, &Timer::system()),
        ["timer", "remove"] => cmd_timer(cfg, false, &mut out, &Timer::system()),
        _ => fail(&mut out, exit::USAGE, "unknown backup command"),
    };
    if !matches!(words, ["timer", _]) {
        print_warnings(cfg, &mut out);
    }
    code
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

// ---- init, password, new code ---------------------------------------------

fn cmd_init(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::STORE, e),
    };
    match State::load(st.path()) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return fail(
                out,
                exit::BACKUP,
                "backups are set up already; use `backup password` or `backup new-code`",
            )
        }
        Err(e) => return fail(out, exit::BACKUP, e),
    }
    let mut s = match secrets(o) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::USAGE, e),
    };
    let mut rng = SystemRand::new();
    out.line("setting up the backups of the admin store");
    out.line("1. a recovery code is shown once: write it on paper");
    out.line("2. a backup password (at least 12 characters), typed twice");
    let seed = match code::new_seed(&mut rng) {
        Ok(x) => x,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let ct = config_text(cfg);
    let env = RunEnv {
        config_text: ct.as_deref(),
        tor: &cfg.tor_socks_proxy,
    };
    match setup_seed(&st, &seed, None, s.as_mut(), o, &mut rng, out, "init", &env) {
        Ok(c) => c,
        Err((c, e)) => fail(out, c, e),
    }
}

/// What a run needs besides the store: the config text and the Tor proxy.
pub struct RunEnv<'a> {
    pub config_text: Option<&'a str>,
    pub tor: &'a str,
}

/// Shows and confirms the code, sets the password, writes the state, runs
/// the first backup and drills it with the seed still in memory.
#[allow(clippy::too_many_arguments)]
fn setup_seed(
    st: &Store,
    seed: &[u8; code::SEED_LEN],
    keep: Option<State>,
    s: &mut dyn Secrets,
    o: &BackupOpts,
    rng: &mut dyn Rand,
    out: &mut Out,
    why: &str,
    env: &RunEnv,
) -> Result<i32, (i32, String)> {
    ui::show_and_confirm(s, seed, rng, via(o), out).map_err(|e| (exit::BACKUP_SECRET, e))?;
    let pw = ui::new_password(s, out).map_err(|e| (exit::BACKUP_SECRET, e))?;
    out.line("wrapping the recovery seed under the backup password (scrypt, work factor 20)");
    let wrapped =
        agefile::wrap_seed(seed, &pw, agefile::WRAP_LOG_N).map_err(|e| (exit::BACKUP, e))?;
    match agefile::unwrap_seed(&wrapped, &pw) {
        Ok(back) if *back == *seed => {}
        _ => {
            return Err((
                exit::BACKUP,
                "the wrapped seed does not open again; nothing was set up".into(),
            ))
        }
    }
    drop(pw);
    let now = now_unix();
    let mut state = match keep {
        Some(mut k) => {
            k.recipient = keys::recipient(seed);
            k.wrapped_seed = Base64::encode_string(&wrapped);
            k.last_drill_unix = None;
            k
        }
        None => {
            engine::new_state(st.path(), seed, &wrapped, now, rng).map_err(|e| (exit::BACKUP, e))?
        }
    };
    state.save(st.path()).map_err(|e| (exit::BACKUP, e))?;
    out.event(json!({"event": "backup_set_up", "recipient": state.recipient}));
    out.line(&format!(
        "backup recipient (public, kept here): {}",
        state.recipient
    ));
    let r = engine::run(st, &mut state, env.config_text, env.tor, now, why, out)
        .map_err(|e| (exit::BACKUP, e))?;
    let code = report_run(&r, out);
    // The first drill, with the seed still in memory: the X25519 stanza
    // opens with the seed's identity, the whole content restores.
    let local = state.destination(state::LOCAL).cloned();
    let w = state
        .written_at(state::LOCAL)
        .into_iter()
        .rev()
        .find(|w| w.verified)
        .cloned();
    if let (Some(d), Some(w)) = (local, w) {
        let file = read_from(&d, &w.file, "").map_err(|e| (exit::BACKUP, e))?;
        let summary =
            engine::drill_file(&file, seed, Some(&w), &state, st.key(), st.path(), rng)
                .map_err(|e| (exit::BACKUP, format!("the first restore check failed: {e}")))?;
        state.last_drill_unix = Some(now_unix());
        state.save(st.path()).map_err(|e| (exit::BACKUP, e))?;
        out.event(
            json!({"event": "drill_ok", "file": w.file, "destination": d.name, "content": summary}),
        );
        out.line(&format!(
            "restore check of {} with the new key: ok ({summary})",
            w.file
        ));
    }
    Ok(code)
}

fn read_from(d: &Destination, file: &str, tor: &str) -> Result<Vec<u8>, String> {
    match dest::open(d, tor)? {
        dest::Reach::Ready(r) => r.get(file),
        dest::Reach::NotConnected(why) => Err(format!("{}: not connected ({why})", d.name)),
    }
}

/// The seed from the backup password or the recovery code, checked
/// against the state's recipient.
fn current_seed(
    state: &State,
    s: &mut dyn Secrets,
    out: &mut Out,
) -> Result<code::Seed, (i32, String)> {
    let typed = ask_secret(s, out).map_err(|e| (exit::BACKUP_SECRET, e))?;
    let wrapped = Base64::decode_vec(&state.wrapped_seed)
        .map_err(|_| (exit::BACKUP, "the backup state is damaged".to_string()))?;
    let (seed, how) =
        engine::seed_from_secret(&typed, &wrapped).map_err(|e| (exit::BACKUP_SECRET, e))?;
    if keys::recipient(&seed) != state.recipient {
        return Err((
            exit::BACKUP_SECRET,
            format!("this {how} belongs to another backup key"),
        ));
    }
    out.event(json!({"event": "secret_accepted", "as": how}));
    Ok(seed)
}

fn cmd_password(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut state = match load_state(st.path()) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let mut s = match secrets(o) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::USAGE, e),
    };
    out.line("changing the backup password: first the current password or the recovery code");
    let seed = match current_seed(&state, s.as_mut(), out) {
        Ok(x) => x,
        Err((c, e)) => return fail(out, c, e),
    };
    let pw = match ui::new_password(s.as_mut(), out) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::BACKUP_SECRET, e),
    };
    let wrapped = match agefile::wrap_seed(&seed, &pw, agefile::WRAP_LOG_N) {
        Ok(w) => w,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    if agefile::unwrap_seed(&wrapped, &pw).map(|b| *b == *seed) != Ok(true) {
        return fail(
            out,
            exit::BACKUP,
            "the new wrapped seed does not open again; nothing was changed",
        );
    }
    state.wrapped_seed = Base64::encode_string(&wrapped);
    if let Err(e) = state.save(st.path()) {
        return fail(out, exit::BACKUP, e);
    }
    out.event(json!({"event": "backup_password_changed"}));
    out.line("backup password changed; older backups keep the old password (the recovery code opens all of them)");
    match engine::run(
        &st,
        &mut state,
        config_text(cfg).as_deref(),
        &cfg.tor_socks_proxy,
        now_unix(),
        "password changed",
        out,
    ) {
        Ok(r) => report_run(&r, out),
        Err(e) => fail(out, exit::BACKUP, e),
    }
}

fn cmd_new_code(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let state = match load_state(st.path()) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let mut s = match secrets(o) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::USAGE, e),
    };
    if o.forget_old {
        out.line("--forget-old: the old password and code are not asked; older backups stay readable only with them");
        match s.confirm("FORGET OLD BACKUPS", "type FORGET OLD BACKUPS to go on: ") {
            Ok(true) => {}
            Ok(false) => {
                return fail(
                    out,
                    exit::BACKUP_SECRET,
                    "not confirmed; nothing was changed",
                )
            }
            Err(e) => return fail(out, exit::BACKUP_SECRET, e),
        }
    } else {
        out.line("a new recovery code: first the current password or the recovery code");
        if let Err((c, e)) = current_seed(&state, s.as_mut(), out) {
            return fail(out, c, e);
        }
    }
    let mut rng = SystemRand::new();
    let seed = match code::new_seed(&mut rng) {
        Ok(x) => x,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    out.line("older backups still need the old recovery code or the old password");
    let ct = config_text(cfg);
    let env = RunEnv {
        config_text: ct.as_deref(),
        tor: &cfg.tor_socks_proxy,
    };
    match setup_seed(
        &st,
        &seed,
        Some(state),
        s.as_mut(),
        o,
        &mut rng,
        out,
        "new recovery code",
        &env,
    ) {
        Ok(c) => c,
        Err((c, e)) => fail(out, c, e),
    }
}

// ---- now, list, verify -------------------------------------------------------

fn cmd_now(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let path = match store_path(cfg) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::STORE, e),
    };
    if o.scheduled {
        // The hourly timer: only when the last good one is older than a day.
        match State::load(&path) {
            Ok(Some(s))
                if s.last_good()
                    .is_some_and(|t| now_unix().saturating_sub(t) < engine::DAILY_SECS) =>
            {
                out.event(
                    json!({"event": "backup_not_due", "last_good": s.last_good().map(fmt_unix)}),
                );
                out.line("the last good backup is younger than 24 hours; nothing to do");
                return exit::OK;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                return fail(
                    out,
                    exit::BACKUP,
                    "backups are not set up: run `sxprov backup init`",
                )
            }
            Err(e) => return fail(out, exit::BACKUP, e),
        }
    }
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) if o.scheduled && e.contains("in use by another sxprov process") => {
            out.event(json!({"event": "backup_skipped", "reason": "store in use"}));
            out.line(
                "the store is in use by another sxprov command; the next hourly run tries again",
            );
            return exit::OK;
        }
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut state = match load_state(st.path()) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let why = if o.scheduled { "daily" } else { "backup now" };
    match engine::run(
        &st,
        &mut state,
        config_text(cfg).as_deref(),
        &cfg.tor_socks_proxy,
        now_unix(),
        why,
        out,
    ) {
        Ok(r) => report_run(&r, out),
        Err(e) => fail(out, exit::BACKUP, e),
    }
}

fn target_text(t: &Target) -> String {
    match t {
        Target::Folder { path } => format!("folder {}", path.display()),
        Target::Webdav { url, .. } => format!("webdav {url} (over Tor)"),
    }
}

fn cmd_list(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let path = match store_path(cfg) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let state = match load_state(&path) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let now = now_unix();
    if o.json {
        let dests: Vec<_> = state
            .destinations
            .iter()
            .map(|d| {
                let files: Vec<_> = state
                    .written_at(&d.name)
                    .iter()
                    .map(|w| json!({"file": w.file, "size": w.size, "sha256": w.sha256,
                                    "created_utc": fmt_unix(w.created_unix), "verified": w.verified}))
                    .collect();
                json!({"name": d.name, "target": d.target, "on_laptop": d.on_laptop,
                       "files": files,
                       "last_failure": state.last_failure.iter().find(|f| f.0 == d.name)
                           .map(|f| json!({"at": fmt_unix(f.1), "reason": f.2}))})
            })
            .collect();
        out.event(json!({"event": "backup_list", "recipient": state.recipient,
                         "last_good": state.last_good().map(fmt_unix),
                         "last_good_off_laptop": state.last_good_off_laptop().map(fmt_unix),
                         "last_drill": state.last_drill_unix.map(fmt_unix),
                         "destinations": dests}));
        return exit::OK;
    }
    println!("backup recipient: {}", state.recipient);
    let ago = |t: Option<u64>| match t {
        Some(t) => format!("{} ({} ago)", fmt_unix(t), fmt_age(now.saturating_sub(t))),
        None => "never".into(),
    };
    println!("last good backup: {}", ago(state.last_good()));
    println!(
        "last good backup off the laptop: {}",
        ago(state.last_good_off_laptop())
    );
    println!("last restore drill: {}", ago(state.last_drill_unix));
    for d in &state.destinations {
        let files = state.written_at(&d.name);
        println!(
            "\n{} ({}{}): {} file(s)",
            d.name,
            target_text(&d.target),
            if d.on_laptop { ", on this laptop" } else { "" },
            files.len()
        );
        for w in files.iter().rev().take(5) {
            println!(
                "  {} {:>8} bytes {}",
                w.file,
                w.size,
                if w.verified { "checked" } else { "NOT CHECKED" }
            );
        }
        if files.len() > 5 {
            println!("  ... and {} older", files.len() - 5);
        }
        if let Some(f) = state.last_failure.iter().find(|f| f.0 == d.name) {
            println!("  last failure {}: {}", fmt_unix(f.1), f.2);
        }
    }
    exit::OK
}

fn cmd_verify(cfg: &Config, out: &mut Out) -> i32 {
    let path = match store_path(cfg) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let state = match load_state(&path) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    match engine::verify_all(&state, &cfg.tor_socks_proxy, out) {
        Ok((ok, bad)) => {
            out.event(json!({"event": "verify_done", "ok": ok, "failed": bad}));
            out.line(&format!("{ok} file(s) ok, {bad} failed"));
            if bad > 0 {
                exit::BACKUP
            } else {
                exit::OK
            }
        }
        Err(e) => fail(out, exit::BACKUP, e),
    }
}

// ---- drill, restore -----------------------------------------------------------

fn cmd_drill(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut state = match load_state(st.path()) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let mut files: Vec<(String, Vec<u8>, Option<state::Written>)> = Vec::new();
    if let Some(f) = &o.from {
        match std::fs::read(f) {
            Ok(b) => files.push((f.display().to_string(), b, None)),
            Err(e) => {
                return fail(
                    out,
                    exit::BACKUP,
                    format!("cannot read {}: {e}", f.display()),
                )
            }
        }
    } else {
        for (d, w) in engine::newest_per_destination(&state) {
            match read_from(&d, &w.file, &cfg.tor_socks_proxy) {
                Ok(b) => files.push((format!("{}:{}", d.name, w.file), b, Some(w))),
                Err(e) => {
                    out.event(
                        json!({"event": "drill_skipped", "destination": d.name, "reason": e}),
                    );
                    out.line(&format!("drill: {} skipped: {e}", d.name));
                }
            }
        }
    }
    if files.is_empty() {
        return fail(
            out,
            exit::BACKUP,
            "no backup file to drill (none checked, or no destination connected)",
        );
    }
    let mut s = match secrets(o) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::USAGE, e),
    };
    out.line(&format!(
        "restore drill of {} backup file(s); the backup password (or the recovery code) is typed once",
        files.len()
    ));
    let typed = match ask_secret(s.as_mut(), out) {
        Ok(t) => t,
        Err(e) => return fail(out, exit::BACKUP_SECRET, e),
    };
    let mut rng = SystemRand::new();
    let (mut failed, mut secret_failed) = (0, 0);
    for (label, file, w) in &files {
        let r = container::parse(file)
            .map(|p| p.wrapped_seed)
            .and_then(|ws| {
                engine::seed_from_secret(&typed, &ws)
                    .map(|x| x.0)
                    .inspect_err(|_| {
                        secret_failed += 1;
                    })
            })
            .and_then(|seed| {
                engine::drill_file(
                    file,
                    &seed,
                    w.as_ref(),
                    &state,
                    st.key(),
                    st.path(),
                    &mut rng,
                )
            });
        match r {
            Ok(summary) => {
                out.event(json!({"event": "drill_ok", "file": label, "content": summary}));
                out.line(&format!("drill {label}: ok ({summary})"));
            }
            Err(e) => {
                failed += 1;
                out.event(json!({"event": "drill_failed", "file": label, "reason": e}));
                out.line(&format!("DRILL FAILED {label}: {e}"));
            }
        }
    }
    drop(typed);
    if failed > 0 {
        // Only the password or code was wrong: the backups are not at fault.
        return if secret_failed == failed {
            exit::BACKUP_SECRET
        } else {
            exit::BACKUP
        };
    }
    state.last_drill_unix = Some(now_unix());
    if let Err(e) = state.save(st.path()) {
        return fail(out, exit::BACKUP, e);
    }
    out.event(json!({"event": "drill_done", "files": files.len()}));
    out.line("restore drill passed; every temporary file is deleted");
    // The passphrase copy of `store migrate` goes after the first drill.
    let v1 = st.path().with_file_name(format!(
        "{}{}",
        st.path().file_name().unwrap_or_default().to_string_lossy(),
        store::V1_COPY_SUFFIX
    ));
    if v1.exists() {
        match std::fs::remove_file(&v1) {
            Ok(()) => {
                out.event(json!({"event": "passphrase_copy_deleted", "file": v1}));
                out.line(&format!(
                    "deleted the passphrase copy {} (first successful drill)",
                    v1.display()
                ));
            }
            Err(e) => out.line(&format!("could not delete {}: {e}", v1.display())),
        }
    }
    exit::OK
}

fn stamp(t: u64) -> String {
    container::file_name(t)
        .trim_start_matches("bk-")
        .trim_end_matches(".bin")
        .to_string()
}

fn cmd_restore(cfg: &Config, o: &BackupOpts, out: &mut Out) -> i32 {
    let Some(from) = &o.from else {
        return fail(out, exit::USAGE, "backup restore needs --from FILE");
    };
    if o.replace && o.to.is_some() {
        return fail(out, exit::USAGE, "--replace and --to exclude each other");
    }
    if o.allow_unencrypted_disk && !cfg.allow_test_key_for_test_deliveries {
        return fail(
            out,
            exit::USAGE,
            "--allow-unencrypted-disk is only for a throwaway test config",
        );
    }
    let file = match std::fs::read(from) {
        Ok(b) => b,
        Err(e) => {
            return fail(
                out,
                exit::BACKUP,
                format!("cannot read {}: {e}", from.display()),
            )
        }
    };
    let parsed = match container::parse(&file) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let wrapped = parsed.wrapped_seed.clone();
    let live = match store_path(cfg) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut s = match secrets(o) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::USAGE, e),
    };
    let typed = match ask_secret(s.as_mut(), out) {
        Ok(t) => t,
        Err(e) => return fail(out, exit::BACKUP_SECRET, e),
    };
    let (seed, how) = match engine::seed_from_secret(&typed, &wrapped) {
        Ok(x) => x,
        Err(e) => return fail(out, exit::BACKUP_SECRET, e),
    };
    drop(typed);
    let opened = match engine::open_with_seed(&file, &seed) {
        Ok(x) => x,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let d = &opened.restored.data;
    out.event(
        json!({"event": "restore_opened", "with": how, "created_utc": opened.manifest.created_utc,
                     "app_version": opened.manifest.app_version, "customers": d.customers.len(),
                     "issues": d.issues.len(), "deliveries": d.deliveries.len()}),
    );
    out.line(&format!(
        "backup of {} (sxprov {}), opened with the {how}: {} customers, {} issues, {} deliveries; every SHA-256 checked",
        opened.manifest.created_utc,
        opened.manifest.app_version,
        d.customers.len(),
        d.issues.len(),
        d.deliveries.len()
    ));
    let now = now_unix();
    let creds = Creds::system();
    let target = if o.replace {
        live.clone()
    } else if let Some(dir) = &o.to {
        absolute(dir).join("admin-store.sxdb")
    } else if live.exists() {
        live.with_file_name(format!("restored-{}", stamp(now)))
            .join("admin-store.sxdb")
    } else {
        live.clone()
    };
    let r = if o.replace {
        replace_live(
            &live,
            &opened,
            s.as_mut(),
            o.allow_unencrypted_disk,
            &creds,
            now,
            out,
        )
    } else {
        restore_new(&target, &opened, o.allow_unencrypted_disk, &creds)
    };
    let backend = match r {
        Ok(b) => b,
        Err(e) if e.starts_with(NOT_CONFIRMED) => return fail(out, exit::BACKUP_SECRET, e),
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let kp = storekey::key_path(&target, backend);
    if let Some(c) = &opened.restored.config {
        let cp = target.with_file_name(format!("provisioning.restored-{}.toml", stamp(now)));
        match store::write_new_private(&cp, c.as_bytes()) {
            Ok(()) => out.line(&format!(
                "the config of the backup (without machine paths) is in {}; the live config was not touched",
                cp.display()
            )),
            Err(e) => out.line(&format!("could not write {}: {e}", cp.display())),
        }
    }
    // On the configured path (a new laptop, or --replace) the backups go on.
    if target == live {
        match State::load(&live) {
            Ok(Some(st)) if st.recipient != opened.recipient => out.line(
                "note: this backup was made with another recovery code than the current backup key",
            ),
            Ok(Some(_)) => {}
            Ok(None) => match engine::new_state(&live, &seed, &opened.wrapped_seed, now, &mut SystemRand::new())
                .and_then(|s| s.save(&live))
            {
                Ok(()) => out.line("backups set up again from the backup's key and password (destination `local`); add the other destinations again"),
                Err(e) => out.line(&format!("the backup state could not be written: {e}")),
            },
            Err(e) => out.line(&format!("backup state: {e}")),
        }
    }
    out.event(
        json!({"event": "restored", "store": target, "store_key": kp,
                     "store_key_backend": backend.id()}),
    );
    out.line(&format!(
        "restored: {} (store key: {}, {})",
        target.display(),
        backend.describe(),
        kp.display()
    ));
    exit::OK
}

/// Restores into a new location: refuses an existing store there.
fn restore_new(
    target: &Path,
    o: &engine::Opened,
    allow: bool,
    creds: &Creds,
) -> Result<storekey::Backend, String> {
    let lock = Store::lock_for_init(target).map_err(|e| e.to_string())?;
    let (backend, _) = storekey::choose(target, creds, allow)?;
    store::write_new_private(target, &o.restored.store_file)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    if let Err(e) = storekey::write(target, backend, &o.restored.key, creds) {
        let _ = std::fs::remove_file(target);
        return Err(e);
    }
    let check = Store::open_locked(lock, creds).map_err(|e| e.to_string());
    match check {
        Ok((s, _)) if s.data == o.restored.data => Ok(backend),
        Ok(_) => Err("the restored store reads back differently".into()),
        Err(e) => Err(format!("the restored store does not open: {e}")),
    }
}

const NOT_CONFIRMED: &str = "REPLACE was not typed";

/// `--replace`: the live store and its key move aside to
/// `<store>.before-restore-<time>`, after a typed `REPLACE`.
fn replace_live(
    live: &Path,
    o: &engine::Opened,
    s: &mut dyn Secrets,
    allow: bool,
    creds: &Creds,
    now: u64,
    out: &mut Out,
) -> Result<storekey::Backend, String> {
    let lock = Store::lock_for_open(live).map_err(|e| e.to_string())?;
    out.event(json!({"event": "ask", "what": "confirm_replace"}));
    if !s.confirm(
        "REPLACE",
        "type REPLACE to put the backup in place of the live store: ",
    )? {
        return Err(format!("{NOT_CONFIRMED}; the live store was not touched"));
    }
    let name = live
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let aside = live.with_file_name(format!("{name}.before-restore-{}", stamp(now)));
    let old_keys = storekey::present(live);
    std::fs::rename(live, &aside).map_err(|e| format!("cannot move the live store aside: {e}"))?;
    for b in &old_keys {
        let _ = std::fs::rename(storekey::key_path(live, *b), storekey::key_path(&aside, *b));
    }
    let undo = || {
        let _ = std::fs::remove_file(live);
        for b in [storekey::Backend::Tpm, storekey::Backend::File] {
            let _ = std::fs::remove_file(storekey::key_path(live, b));
        }
        let _ = std::fs::rename(&aside, live);
        for b in &old_keys {
            let _ = std::fs::rename(storekey::key_path(&aside, *b), storekey::key_path(live, *b));
        }
    };
    let r = (|| {
        let (backend, _) = storekey::choose(live, creds, allow)?;
        store::write_new_private(live, &o.restored.store_file).map_err(|e| e.to_string())?;
        storekey::write(live, backend, &o.restored.key, creds)?;
        Ok::<_, String>(backend)
    })();
    let backend = match r {
        Ok(b) => b,
        Err(e) => {
            undo();
            return Err(format!("{e}; the live store was put back"));
        }
    };
    match Store::open_locked(lock, creds) {
        Ok((st, _)) if st.data == o.restored.data => {
            out.line(&format!(
                "the store before the restore is kept as {}",
                aside.display()
            ));
            Ok(backend)
        }
        _ => {
            undo();
            Err("the restored store does not open; the live store was put back".into())
        }
    }
}

// ---- destinations ---------------------------------------------------------------

fn valid_name(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && n != state::LOCAL
}

fn cmd_dest_add(cfg: &Config, name: &str, target: Target, out: &mut Out) -> i32 {
    if !valid_name(name) {
        return fail(
            out,
            exit::USAGE,
            "a destination name is 1 to 32 of a-z, 0-9 and -, and not `local`",
        );
    }
    let st = match open_store(cfg) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut state = match load_state(st.path()) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    if state.destination(name).is_some() {
        return fail(
            out,
            exit::USAGE,
            format!("a destination {name} exists already"),
        );
    }
    let mut rng = SystemRand::new();
    let id = match crate::activation::rng::bytes::<16>(&mut rng) {
        Ok(b) => hex(&b),
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let target = match target {
        Target::Folder { path } => match dest::add_folder(&path, &id, false) {
            Ok(p) => Target::Folder { path: p },
            Err(e) => return fail(out, exit::BACKUP, e),
        },
        t @ Target::Webdav { .. } => t,
    };
    let d = Destination {
        name: name.into(),
        id,
        target,
        on_laptop: false,
        added_unix: now_unix(),
    };
    match dest::open(&d, &cfg.tor_socks_proxy) {
        Ok(dest::Reach::Ready(r)) => {
            if let Err(e) = dest::probe(r.as_ref(), &mut rng) {
                return fail(
                    out,
                    exit::BACKUP,
                    format!("the probe file failed: {e}; nothing was added"),
                );
            }
        }
        Ok(dest::Reach::NotConnected(why)) => {
            return fail(
                out,
                exit::BACKUP,
                format!("not reachable: {why}; nothing was added"),
            )
        }
        Err(e) => return fail(out, exit::BACKUP, format!("{e}; nothing was added")),
    }
    state.destinations.push(d.clone());
    if let Err(e) = state.save(st.path()) {
        return fail(out, exit::BACKUP, e);
    }
    out.event(json!({"event": "destination_added", "name": name, "target": d.target}));
    out.line(&format!(
        "destination {name} added ({}); a probe file was written, read back and deleted",
        target_text(&d.target)
    ));
    match engine::run(
        &st,
        &mut state,
        config_text(cfg).as_deref(),
        &cfg.tor_socks_proxy,
        now_unix(),
        "destination added",
        out,
    ) {
        Ok(r) => report_run(&r, out),
        Err(e) => fail(out, exit::BACKUP, e),
    }
}

fn cmd_dest_remove(cfg: &Config, name: &str, out: &mut Out) -> i32 {
    if name == state::LOCAL {
        return fail(
            out,
            exit::USAGE,
            "the local destination stays; it is the copy on this laptop",
        );
    }
    let path = match store_path(cfg) {
        Ok(p) => p,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let _lock = match Store::lock_for_open(&path) {
        Ok(l) => l,
        Err(e) => return fail(out, exit::STORE, e),
    };
    let mut state = match load_state(&path) {
        Ok(s) => s,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    let Some(d) = state.destination(name).cloned() else {
        return fail(out, exit::USAGE, format!("no destination {name}"));
    };
    let n = state.written_at(name).len();
    state.destinations.retain(|x| x.name != name);
    state.written.retain(|w| w.destination != name);
    state.clear_failure(name);
    if let Err(e) = state.save(&path) {
        return fail(out, exit::BACKUP, e);
    }
    out.event(json!({"event": "destination_removed", "name": name, "files_left_there": n}));
    out.line(&format!(
        "destination {name} removed; its {n} backup file(s) stay there ({}) and are no longer rotated",
        target_text(&d.target)
    ));
    exit::OK
}

// ---- timer ------------------------------------------------------------------------

pub struct Timer {
    pub unit_dir: Option<PathBuf>,
    pub systemctl: PathBuf,
}

impl Timer {
    fn system() -> Timer {
        let dir = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|c| c.join("systemd/user"));
        Timer {
            unit_dir: dir,
            systemctl: PathBuf::from("systemctl"),
        }
    }
    fn run(&self, args: &[&str]) -> Result<(), String> {
        let o = std::process::Command::new(&self.systemctl)
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("cannot run systemctl: {e}"))?;
        if o.status.success() {
            Ok(())
        } else {
            Err(format!(
                "systemctl --user {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            ))
        }
    }
}

pub const UNIT: &str = "sxprov-backup";

/// A path systemd takes in `ExecStart=` without quoting rules.
fn unit_safe(p: &Path) -> Result<String, String> {
    let s = p.to_str().ok_or("a path is not UTF-8")?;
    if !p.is_absolute()
        || s.chars()
            .any(|c| c.is_whitespace() || "\"'\\%$;".contains(c))
    {
        return Err(format!(
            "{s}: for the timer the path must be absolute, without spaces, quotes, %, $, \\ or ;"
        ));
    }
    Ok(s.to_string())
}

pub fn unit_files(exe: &Path, config: &Path) -> Result<(String, String), String> {
    let service = format!(
        "# Written by `sxprov backup timer install`. Removed by `sxprov backup timer remove`.\n\
         [Unit]\nDescription=SimpleGo Provisioning: backup of the admin store when the last one is older than 24 hours\n\n\
         [Service]\nType=oneshot\nExecStart={} --config {} backup now --scheduled\n",
        unit_safe(exe)?,
        unit_safe(config)?
    );
    let timer = "# Written by `sxprov backup timer install`.\n\
         [Unit]\nDescription=SimpleGo Provisioning: hourly check for the daily backup\n\n\
         [Timer]\nOnCalendar=hourly\nPersistent=true\nRandomizedDelaySec=300\n\n\
         [Install]\nWantedBy=timers.target\n"
        .to_string();
    Ok((service, timer))
}

pub fn cmd_timer(cfg: &Config, install: bool, out: &mut Out, t: &Timer) -> i32 {
    let Some(dir) = &t.unit_dir else {
        return fail(
            out,
            exit::BACKUP,
            "HOME is not set; no systemd user unit folder",
        );
    };
    let svc = dir.join(format!("{UNIT}.service"));
    let tmr = dir.join(format!("{UNIT}.timer"));
    if !install {
        let _ = t.run(&["disable", "--now", &format!("{UNIT}.timer")]);
        let _ = std::fs::remove_file(&svc);
        let _ = std::fs::remove_file(&tmr);
        let r = t.run(&["daemon-reload"]);
        out.event(json!({"event": "timer_removed"}));
        out.line("backup timer removed");
        return match r {
            Ok(()) => exit::OK,
            Err(e) => fail(out, exit::BACKUP, e),
        };
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return fail(out, exit::BACKUP, format!("cannot find this sxprov: {e}")),
    };
    let Some(config) = cfg.loaded_from.clone() else {
        return fail(out, exit::BACKUP, "the config path is unknown");
    };
    let (s, tm) = match unit_files(&exe, &config) {
        Ok(x) => x,
        Err(e) => return fail(out, exit::BACKUP, e),
    };
    if let Err(e) = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&svc, s))
        .and_then(|_| std::fs::write(&tmr, tm))
    {
        return fail(
            out,
            exit::BACKUP,
            format!("cannot write the units in {}: {e}", dir.display()),
        );
    }
    if let Err(e) = t
        .run(&["daemon-reload"])
        .and_then(|_| t.run(&["enable", "--now", &format!("{UNIT}.timer")]))
    {
        return fail(out, exit::BACKUP, e);
    }
    out.event(json!({"event": "timer_installed", "service": svc, "timer": tmr}));
    out.line(&format!(
        "backup timer installed: hourly, writes when the last good backup is older than 24 hours ({})",
        tmr.display()
    ));
    out.line("a user timer runs while you are logged in; for runs without a login an administrator can run `loginctl enable-linger` for this user");
    exit::OK
}

// ---- after every command ------------------------------------------------------------

/// The warnings, to the given output (stderr for other commands).
pub fn print_warnings(cfg: &Config, out: &mut Out) {
    let Ok(path) = store_path(cfg) else { return };
    if !path.exists() {
        return;
    }
    let state = State::load(&path).ok().flatten();
    for (kind, text) in engine::warnings(state.as_ref(), now_unix()) {
        out.event(json!({"event": "backup_warning", "kind": kind, "text": text}));
        if !out.json {
            eprintln!("{}: WARNING: {text}", names::BINARY);
        }
    }
}

/// At the end of every command but `backup ...`: a backup after a store or
/// config write, or when the last good one is older than 24 hours; then the
/// warnings. Everything on standard error.
pub fn after_command(cfg: &Config, json: bool) {
    let mut out = Out { json, stderr: true };
    let Ok(path) = store_path(cfg) else { return };
    if !path.exists() {
        return;
    }
    let state = State::load(&path).ok().flatten();
    let due = match &state {
        Some(s) => {
            store::was_written()
                || s.last_good()
                    .is_none_or(|t| now_unix().saturating_sub(t) >= engine::DAILY_SECS)
        }
        None => false,
    };
    if due {
        let why = if store::was_written() {
            "after a store write"
        } else {
            "older than 24 hours"
        };
        match open_store(cfg) {
            Ok(st) => {
                if let Ok(Some(mut s)) = State::load(st.path()) {
                    match engine::run(
                        &st,
                        &mut s,
                        config_text(cfg).as_deref(),
                        &cfg.tor_socks_proxy,
                        now_unix(),
                        why,
                        &mut out,
                    ) {
                        Ok(r) => {
                            report_run(&r, &mut out);
                        }
                        Err(e) => {
                            out.event(json!({"event": "backup_failed", "reason": e}));
                            if !json {
                                eprintln!("{}: BACKUP FAILED: {e}", names::BINARY);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                out.event(json!({"event": "backup_skipped", "reason": e}));
                if !json {
                    eprintln!("{}: backup skipped: {e}", names::BINARY);
                }
            }
        }
    }
    print_warnings(cfg, &mut out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::store::tests::{init_test_store, one_at_a_time, temp_dir};
    use crate::backup::ui::Scripted;

    fn cfg_for(d: &Path, store: &Path) -> Config {
        let text = format!(
            "trust_cache_dir = \"{dir}/trust\"\nadb_path = \"{dir}/adb\"\nfastboot_path = \"\"\n\
             agent_apk = \"{dir}/agent.apk\"\nagent_signing_cert_sha256 = \"{a5}\"\n\
             admin_store_path = \"{}\"\nallow_test_key_for_test_deliveries = true\n",
            store.display(),
            dir = d.display(),
            a5 = "a5".repeat(32),
        );
        let p = d.join("provisioning.toml");
        std::fs::write(&p, &text).unwrap();
        let mut c = Config::parse(&text).unwrap();
        c.loaded_from = Some(p);
        c
    }

    fn scripted(a: &[&str]) -> Scripted {
        Scripted {
            answers: a.iter().map(|s| s.to_string()).collect(),
            shown: vec![],
        }
    }

    fn quiet() -> Out {
        Out {
            json: true,
            stderr: true,
        }
    }

    /// init, a drill, a password change, a new code, a restore into a new
    /// place and with --replace: every step through the commands' own code
    /// with scripted answers (work factor 20 runs here, several times).
    #[test]
    fn init_drill_password_new_code_restore() {
        let _g = one_at_a_time();
        let d = temp_dir("backup-cmds");
        let sp = d.join("store/admin.sxdb");
        let mut st = init_test_store(&sp, b"cmds");
        st.data.issues.clear();
        st.save(&mut crate::activation::rng::SeededRand::new(b"c"))
            .unwrap();
        drop(st);
        let cfg = cfg_for(&d, &sp);
        let o = BackupOpts::default();
        // init: the code shown once, group confirmed, password twice.
        let st = open_store(&cfg).unwrap();
        let mut s = scripted(&["{group}", "TEST-ONLY backup pw 1", "TEST-ONLY backup pw 1"]);
        let mut rng = crate::activation::rng::SeededRand::new(b"seed");
        let seed = code::new_seed(&mut rng).unwrap();
        let env = RunEnv {
            config_text: Some("adb_path = \"/x\"\n"),
            tor: "",
        };
        assert_eq!(
            setup_seed(
                &st,
                &seed,
                None,
                &mut s,
                &o,
                &mut rng,
                &mut quiet(),
                "init",
                &env
            ),
            Ok(exit::OK)
        );
        assert_eq!(s.shown.len(), 1);
        let state = State::load(&sp).unwrap().unwrap();
        assert!(state.last_drill_unix.is_some());
        assert_eq!(state.written.len(), 1);
        let file = state::local_folder(&sp).join(&state.written[0].file);
        drop(st);
        // The state and the backup hold neither the code nor the password.
        let raw_state = std::fs::read_to_string(state::path(&sp)).unwrap();
        let c = code::encode(&seed);
        for f in [raw_state.as_bytes().to_vec(), std::fs::read(&file).unwrap()] {
            assert!(!f.windows(32).any(|w| w == c.as_bytes()));
            assert!(!f.windows(21).any(|w| w == b"TEST-ONLY backup pw 1"));
        }
        // A wrong confirmation three times: nothing set up.
        let st = open_store(&cfg).unwrap();
        let mut s = scripted(&["XXXX", "XXXX", "XXXX"]);
        assert!(setup_seed(
            &st,
            &seed,
            Some(state.clone()),
            &mut s,
            &o,
            &mut rng,
            &mut quiet(),
            "x",
            &env
        )
        .is_err());
        assert_eq!(State::load(&sp).unwrap().unwrap(), state);
        drop(st);
        // password: the old one, then a new one twice.
        let mut s = scripted(&[
            "TEST-ONLY backup pw 1",
            "TEST-ONLY backup pw 2",
            "TEST-ONLY backup pw 2",
        ]);
        let st = open_store(&cfg).unwrap();
        let mut stt = State::load(&sp).unwrap().unwrap();
        let seed2 = current_seed(&stt, &mut s, &mut quiet()).unwrap();
        assert_eq!(*seed2, *seed);
        let pw = ui::new_password(&mut s, &mut quiet()).unwrap();
        stt.wrapped_seed = Base64::encode_string(&agefile::wrap_seed(&seed, &pw, 20).unwrap());
        stt.save(&sp).unwrap();
        engine::run(&st, &mut stt, None, "", now_unix() + 5, "pw", &mut quiet()).unwrap();
        drop(st);
        // drill: the new password opens the new file; the recovery code
        // opens the old one.
        let newest = engine::newest_per_destination(&stt)[0].1.clone();
        let nf = state::local_folder(&sp).join(&newest.file);
        let st = open_store(&cfg).unwrap();
        let ws = container::parse(&std::fs::read(&nf).unwrap())
            .unwrap()
            .wrapped_seed;
        let (sd, _) = engine::seed_from_secret("TEST-ONLY backup pw 2", &ws).unwrap();
        engine::drill_file(
            &std::fs::read(&nf).unwrap(),
            &sd,
            Some(&newest),
            &stt,
            st.key(),
            &sp,
            &mut rng,
        )
        .unwrap();
        let old_ws = container::parse(&std::fs::read(&file).unwrap())
            .unwrap()
            .wrapped_seed;
        assert!(engine::seed_from_secret("TEST-ONLY backup pw 2", &old_ws).is_err());
        assert!(engine::seed_from_secret(&code::grouped(&c), &old_ws).is_ok());
        drop(st);
        // restore into a new place (the live store exists): a new folder.
        let to = d.join("elsewhere");
        let ro = BackupOpts {
            from: Some(nf.clone()),
            to: Some(to.clone()),
            confirm_fd: None,
            ..Default::default()
        };
        let opened = engine::open_with_seed(&std::fs::read(&nf).unwrap(), &sd).unwrap();
        let b = restore_new(
            &to.join("admin-store.sxdb"),
            &opened,
            true,
            &Creds::system(),
        )
        .unwrap();
        assert_eq!(b, storekey::Backend::File);
        let rs = crate::activation::store::tests::open_test_store(&to.join("admin-store.sxdb"));
        assert_eq!(rs.data, opened.restored.data);
        drop(rs);
        assert!(restore_new(
            &to.join("admin-store.sxdb"),
            &opened,
            true,
            &Creds::system()
        )
        .is_err());
        let _ = ro;
        // --replace: refused without REPLACE, done with it; the old store is kept aside.
        let before = std::fs::read(&sp).unwrap();
        let mut s = scripted(&["no"]);
        assert!(replace_live(
            &sp,
            &opened,
            &mut s,
            true,
            &Creds::system(),
            1,
            &mut quiet()
        )
        .is_err());
        assert_eq!(std::fs::read(&sp).unwrap(), before);
        let mut s = scripted(&["REPLACE"]);
        replace_live(
            &sp,
            &opened,
            &mut s,
            true,
            &Creds::system(),
            2,
            &mut quiet(),
        )
        .unwrap();
        let aside = sp.with_file_name(format!("admin.sxdb.before-restore-{}", stamp(2)));
        assert_eq!(std::fs::read(&aside).unwrap(), before);
        assert!(storekey::key_path(&aside, storekey::Backend::File).exists());
        assert_eq!(
            crate::activation::store::tests::open_test_store(&sp).data,
            opened.restored.data
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn timer_units() {
        let (s, t) = unit_files(
            Path::new("/usr/local/bin/sxprov"),
            Path::new("/home/op/.config/sxprov/provisioning.toml"),
        )
        .unwrap();
        assert!(s.contains("ExecStart=/usr/local/bin/sxprov --config /home/op/.config/sxprov/provisioning.toml backup now --scheduled"));
        assert!(t.contains("OnCalendar=hourly") && t.contains("Persistent=true"));
        assert!(unit_files(Path::new("/my dir/sxprov"), Path::new("/c.toml")).is_err());
        assert!(unit_files(Path::new("sxprov"), Path::new("/c.toml")).is_err());
        assert!(unit_files(Path::new("/x/sxprov"), Path::new("/c%n.toml")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn timer_install_and_remove_with_a_fake_systemctl() {
        use std::os::unix::fs::PermissionsExt;
        let _g = one_at_a_time();
        let d = temp_dir("backup-timer");
        let log = d.join("calls");
        let fake = d.join("systemctl");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\necho \"$*\" >> {}\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let t = Timer {
            unit_dir: Some(d.join("units")),
            systemctl: fake,
        };
        let sp = d.join("admin.sxdb");
        let mut cfg = cfg_for(&d, &sp);
        cfg.loaded_from = Some(PathBuf::from("/abs/provisioning.toml"));
        let exe_ok = std::env::current_exe()
            .map(|e| unit_safe(&e).is_ok())
            .unwrap_or(false);
        if exe_ok {
            assert_eq!(cmd_timer(&cfg, true, &mut quiet(), &t), exit::OK);
            assert!(d.join("units/sxprov-backup.timer").exists());
            let calls = std::fs::read_to_string(&log).unwrap();
            assert!(calls.contains("--user daemon-reload"), "{calls}");
            assert!(
                calls.contains("--user enable --now sxprov-backup.timer"),
                "{calls}"
            );
        }
        assert_eq!(cmd_timer(&cfg, false, &mut quiet(), &t), exit::OK);
        assert!(!d.join("units/sxprov-backup.timer").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn destination_names() {
        assert!(valid_name("usb-1") && valid_name("nextcloud"));
        for bad in ["", "local", "USB", "a b", "x/y", &"a".repeat(33)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
