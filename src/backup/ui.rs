// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! What the backup commands ask, and the one place the recovery code is
//! shown.
//!
//! Terminal: the code goes to the controlling terminal (`/dev/tty`) only,
//! never to standard output or error, inside the alternate screen
//! (`ESC[?1049h`), which xterm, VTE, Konsole, tmux and Windows Terminal keep
//! out of the scrollback; after Enter the screen is cleared, `ESC[3J`
//! clears the scrollback as well, and the alternate screen is left. The
//! confirmation (one group of 4 characters, chosen at random) and every
//! password are read without echo. A terminal that records the session on
//! purpose (`script`, asciinema, tmux `pipe-pane`) cannot be prevented.
//!
//! The assistant: `--code-fd N --confirm-fd M`. The code is written to file
//! descriptor N only (one line: the 8 groups), the answers (the 4
//! characters, then the passwords) are read as lines from M. The `--json`
//! stream on standard output never holds the code or a password.

use super::code;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use zeroize::Zeroizing;

pub trait Secrets {
    /// A hidden answer (password, recovery code, the 4 characters).
    fn ask(&mut self, what: &str, prompt: &str) -> Result<Zeroizing<String>, String>;
    /// Shows the code once; returns when the operator has written it down.
    fn show_code(&mut self, grouped: &str) -> Result<(), String>;
    /// A typed word (`REPLACE`, `FORGET OLD BACKUPS`).
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String>;
}

pub struct Terminal;

fn tty() -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "no terminal to show the recovery code on (run it in a terminal, or give --code-fd and --confirm-fd)".to_string())
}

impl Secrets for Terminal {
    fn ask(&mut self, _what: &str, prompt: &str) -> Result<Zeroizing<String>, String> {
        crate::deliver_cmd::terminal_secret(prompt, None)
    }
    fn show_code(&mut self, grouped: &str) -> Result<(), String> {
        if !std::io::stdin().is_terminal() {
            return Err("no terminal on standard input; run it in a terminal, or give --code-fd and --confirm-fd".into());
        }
        let mut t = tty()?;
        let (l1, l2) = grouped.split_at(grouped.len().min(19));
        let screen = Zeroizing::new(format!(
            "\x1b[?1049h\x1b[2J\x1b[H\
             RECOVERY CODE of the admin store backups (shown once, never stored):\r\n\r\n\
             \x20   {l1}\r\n\
             \x20  {l2}\r\n\r\n\
             Write it on paper now, in two lines as shown. With it, or with the\r\n\
             backup password, every backup can be restored. Keep it apart from\r\n\
             the laptop. It is never shown again.\r\n\r\n\
             Press Enter when it is written down. "
        ));
        t.write_all(screen.as_bytes()).map_err(|e| e.to_string())?;
        t.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        let r = BufReader::new(t.try_clone().map_err(|e| e.to_string())?).read_line(&mut line);
        let _ = t.write_all(b"\x1b[2J\x1b[3J\x1b[H\x1b[?1049l\x1b[3J");
        let _ = t.flush();
        r.map(|_| ()).map_err(|e| e.to_string())
    }
    fn confirm(&mut self, word: &str, question: &str) -> Result<bool, String> {
        use crate::deliver::Ui;
        crate::deliver_cmd::TerminalUi.confirm(word, question)
    }
}

/// The assistant's channels (`--code-fd`, `--confirm-fd`).
pub struct Fds {
    code: Option<std::fs::File>,
    answers: BufReader<std::fs::File>,
}

fn open_fd(n: i32, write: bool) -> Result<std::fs::File, String> {
    if n < 3 {
        return Err(format!(
            "file descriptor {n} is standard input, output or error; give another one"
        ));
    }
    std::fs::OpenOptions::new()
        .read(!write)
        .write(write)
        .open(format!("/dev/fd/{n}"))
        .map_err(|e| format!("file descriptor {n} is not open: {e}"))
}

impl Fds {
    pub fn new(code_fd: Option<i32>, confirm_fd: i32) -> Result<Fds, String> {
        Ok(Fds {
            code: code_fd.map(|n| open_fd(n, true)).transpose()?,
            answers: BufReader::new(open_fd(confirm_fd, false)?),
        })
    }
}

impl Secrets for Fds {
    fn ask(&mut self, what: &str, _prompt: &str) -> Result<Zeroizing<String>, String> {
        let mut line = Zeroizing::new(String::new());
        let n = self
            .answers
            .read_line(&mut line)
            .map_err(|e| format!("--confirm-fd: {e}"))?;
        if n == 0 {
            return Err(format!("--confirm-fd closed before the {what}"));
        }
        let t = line.trim_end_matches(['\n', '\r']);
        Ok(Zeroizing::new(t.to_string()))
    }
    fn show_code(&mut self, grouped: &str) -> Result<(), String> {
        let f = self
            .code
            .as_mut()
            .ok_or("--code-fd is needed to hand over the recovery code")?;
        let line = Zeroizing::new(format!("{grouped}\n"));
        f.write_all(line.as_bytes())
            .and_then(|_| f.flush())
            .map_err(|e| format!("--code-fd: {e}"))?;
        // The descriptor is closed now: the code went out once.
        self.code = None;
        Ok(())
    }
    fn confirm(&mut self, word: &str, _q: &str) -> Result<bool, String> {
        Ok(self.ask(word, "")?.as_str() == word)
    }
}

/// Scripted answers, for the tests.
#[cfg(test)]
pub struct Scripted {
    pub answers: std::collections::VecDeque<String>,
    pub shown: Vec<String>,
}

#[cfg(test)]
impl Secrets for Scripted {
    fn ask(&mut self, what: &str, prompt: &str) -> Result<Zeroizing<String>, String> {
        let a = self
            .answers
            .pop_front()
            .ok_or(format!("no scripted answer for {what}"))?;
        // `{group}`: the group the prompt asks for, of the code shown last.
        if a == "{group}" {
            let n: usize = prompt
                .split_whitespace()
                .skip_while(|w| *w != "group")
                .nth(1)
                .and_then(|n| n.parse().ok())
                .ok_or(format!("no group number in {prompt:?}"))?;
            let code: String = self
                .shown
                .last()
                .cloned()
                .unwrap_or_default()
                .replace(' ', "");
            return Ok(code::group(&code, n).unwrap());
        }
        Ok(Zeroizing::new(a))
    }
    fn show_code(&mut self, grouped: &str) -> Result<(), String> {
        self.shown.push(grouped.to_string());
        Ok(())
    }
    fn confirm(&mut self, word: &str, _q: &str) -> Result<bool, String> {
        Ok(self.ask(word, "")?.as_str() == word)
    }
}

/// A new backup password, twice; at least 12 characters, a strength hint
/// only, never a rule about character classes.
pub fn new_password(
    s: &mut dyn Secrets,
    ev: &mut dyn super::engine::Events,
) -> Result<Zeroizing<String>, String> {
    for _ in 0..3 {
        ev.event(serde_json::json!({"event": "ask", "what": "new_backup_password"}));
        let a = s.ask(
            "new backup password",
            "new backup password (at least 12 characters): ",
        )?;
        if a.chars().count() < 12 {
            ev.line("the backup password needs at least 12 characters");
            ev.event(serde_json::json!({"event": "refused", "what": "new_backup_password", "reason": "shorter than 12 characters"}));
            continue;
        }
        ev.event(serde_json::json!({"event": "ask", "what": "new_backup_password_again"}));
        let b = s.ask("new backup password again", "repeat the backup password: ")?;
        if *a != *b {
            ev.line("the two passwords differ");
            ev.event(serde_json::json!({"event": "refused", "what": "new_backup_password", "reason": "the two differ"}));
            continue;
        }
        if a.chars().count() < 16 {
            ev.line("hint: a longer password (four or more random words) is stronger");
        }
        return Ok(a);
    }
    Err("no backup password was set".into())
}

/// Shows the code and asks for one group of it, chosen at random; at most
/// three attempts.
pub fn show_and_confirm(
    s: &mut dyn Secrets,
    seed: &[u8; code::SEED_LEN],
    rng: &mut dyn crate::activation::rng::Rand,
    via: &str,
    ev: &mut dyn super::engine::Events,
) -> Result<(), String> {
    let c = code::encode(seed);
    s.show_code(&code::grouped(&c))?;
    ev.event(serde_json::json!({"event": "recovery_code_shown", "via": via}));
    for _ in 0..3 {
        let g = crate::activation::rng::uniform_u32(rng, 1, 8)? as usize;
        ev.event(serde_json::json!({"event": "ask", "what": "recovery_code_group", "group": g}));
        let typed = s.ask(
            "recovery code group",
            &format!("type group {g} of the recovery code (4 characters): "),
        )?;
        let want = code::group(&c, g).ok_or("group")?;
        if *code::normalise(&typed) == *want {
            ev.event(serde_json::json!({"event": "recovery_code_confirmed"}));
            return Ok(());
        }
        ev.event(serde_json::json!({"event": "recovery_code_confirm_failed", "group": g}));
        ev.line("that is not the group; check what you wrote down");
    }
    Err("the recovery code was not confirmed; nothing was set up".into())
}
