// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Running the official `flash-all.sh` unchanged (decided 2026-11-24).
//!
//! The script calls plain `fastboot`, so a private folder first in `PATH`
//! holds the `fastboot` it gets:
//!
//! - on Linux (the Debian laptop): a link to the configured fastboot;
//! - on WSL with the Windows `fastboot.exe` (a WSL2 development machine): the stand-in
//!   below. `fastboot.exe` ends its lines with CRLF, which breaks the
//!   script's own checks (`product` would read `bluejay\r`). The stand-in
//!   runs `fastboot.exe` with the same arguments and environment, removes
//!   only the `\r` from its standard output and standard error (kept
//!   apart), and exits with fastboot's exit code. Nothing else.
//!
//! `ANDROID_SERIAL` selects the phone for every fastboot call of the script
//! (it passes no `-s`); under WSL `WSLENV` carries it to the Windows process.
//! Standard input is closed. Every output line goes to the log with every
//! serial masked.

use crate::util::mask_serial;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The stand-in for `fastboot.exe` (bash, `pipefail`).
pub fn standin_script(fastboot_exe: &str) -> String {
    let quoted = format!("'{}'", fastboot_exe.replace('\'', r"'\''"));
    format!(
        "#!/bin/bash\n\
         # sxprov fastboot stand-in: runs {quoted} with the same arguments,\n\
         # removes only the carriage returns from its output, keeps its exit code.\n\
         set -o pipefail\n\
         {{ {quoted} \"$@\" 2>&1 1>&3 3>&- | tr -d '\\r' 1>&2 3>&-; }} 3>&1 | tr -d '\\r'\n"
    )
}

fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return Some(PathBuf::from(program));
    }
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(program))
            .find(|f| f.is_file())
    })
}

/// Creates `dir` (new, mode 0700) holding `fastboot`: the stand-in or a
/// link to the configured binary.
pub fn prepare_tools(dir: &Path, fastboot_path: &str, standin: bool) -> Result<PathBuf, String> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let target = which(fastboot_path)
        .ok_or_else(|| format!("fastboot {fastboot_path:?} not found in PATH"))?;
    let abs = std::fs::canonicalize(&target)
        .map_err(|e| format!("fastboot {}: {e}", target.display()))?;
    let fb = dir.join("fastboot");
    if standin {
        std::fs::write(&fb, standin_script(&abs.to_string_lossy()))
            .map_err(|e| format!("cannot write {}: {e}", fb.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fb, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot chmod {}: {e}", fb.display()))?;
        }
    } else {
        #[cfg(unix)]
        std::os::unix::fs::symlink(&abs, &fb)
            .map_err(|e| format!("cannot link {}: {e}", fb.display()))?;
        #[cfg(not(unix))]
        return Err("flashing needs Linux or WSL".into());
    }
    Ok(dir.to_path_buf())
}

/// Masks the target serial everywhere and the first word of a `fastboot
/// devices` line (`SERIAL<TAB>fastboot`), whoever it belongs to.
pub fn mask_line(line: &str, serial: &str) -> String {
    let mut s = if serial.is_empty() {
        line.to_string()
    } else {
        line.replace(serial, &mask_serial(serial))
    };
    let mut it = s.split_whitespace();
    if let (Some(first), Some(second)) = (it.next(), it.next()) {
        if (second == "fastboot" || second == "fastbootd") && !first.starts_with('*') {
            let m = mask_serial(first);
            s = s.replacen(first, &m, 1);
        }
    }
    s
}

pub struct ScriptRun {
    pub exit_code: Option<i32>,
    pub lines: usize,
}

/// Runs `bash flash-all.sh` in `script_dir`. Each line, masked, goes to
/// `log_file` and to `out`.
pub fn run_script(
    script_dir: &Path,
    tools_dir: &Path,
    serial: &str,
    windows_fastboot: bool,
    tmp_dir: &Path,
    log_file: &Path,
    out: &mut dyn FnMut(&str),
) -> Result<ScriptRun, String> {
    if !script_dir.join("flash-all.sh").is_file() {
        return Err(format!("{} holds no flash-all.sh", script_dir.display()));
    }
    let path = match std::env::var_os("PATH") {
        Some(p) => {
            let mut v = vec![tools_dir.to_path_buf()];
            v.extend(std::env::split_paths(&p));
            std::env::join_paths(v).map_err(|e| e.to_string())?
        }
        None => tools_dir.as_os_str().to_os_string(),
    };
    let mut cmd = Command::new("bash");
    cmd.arg("flash-all.sh")
        .current_dir(script_dir)
        .env("ANDROID_SERIAL", serial)
        .env("PATH", path)
        .env("TMPDIR", tmp_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if windows_fastboot {
        let mut w = std::env::var("WSLENV").unwrap_or_default();
        if !w
            .split(':')
            .any(|x| x.split('/').next() == Some("ANDROID_SERIAL"))
        {
            if !w.is_empty() {
                w.push(':');
            }
            w.push_str("ANDROID_SERIAL");
        }
        cmd.env("WSLENV", w);
    }
    let mut log = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(log_file)
        .map_err(|e| format!("cannot create the log {}: {e}", log_file.display()))?;
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start bash flash-all.sh: {e}"))?;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let mut readers = Vec::new();
    for pipe in [
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            let r = std::io::BufReader::new(pipe);
            for l in r.split(b'\n') {
                let Ok(l) = l else { break };
                let _ = tx.send(
                    String::from_utf8_lossy(&l)
                        .trim_end_matches('\r')
                        .to_string(),
                );
            }
        }));
    }
    drop(tx);
    let mut lines = 0;
    for l in rx {
        let m = mask_line(&l, serial);
        let _ = writeln!(log, "{m}");
        out(&m);
        lines += 1;
    }
    for r in readers {
        let _ = r.join();
    }
    let status = child.wait().map_err(|e| format!("flash-all.sh: {e}"))?;
    let _ = log.sync_all();
    Ok(ScriptRun {
        exit_code: status.code(),
        lines,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn masking() {
        assert_eq!(
            mask_line("ABCDEF123456\tfastboot", "ABCDEF123456"),
            "**********56\tfastboot"
        );
        assert_eq!(
            mask_line("OTHER9999\t fastboot", "ABCDEF123456"),
            "*******99\t fastboot"
        );
        assert_eq!(
            mask_line("< waiting for ABCDEF123456 >", "ABCDEF123456"),
            "< waiting for **********56 >"
        );
        assert_eq!(
            mask_line("Sending 'boot_a' (65536 KB)", "X1"),
            "Sending 'boot_a' (65536 KB)"
        );
    }

    /// The stand-in against a stand-in "fastboot.exe" that prints CRLF on
    /// both streams and exits with the code it is given.
    #[test]
    fn standin_strips_cr_keeps_streams_and_exit_code() {
        let d = crate::activation::store::tests::temp_dir("standin");
        let exe = d.join("fastboot it's.exe");
        std::fs::write(
            &exe,
            "#!/bin/sh\nprintf 'out %s|%s\\r\\n' \"$1\" \"$ANDROID_SERIAL\"\nprintf 'product: bluejay\\r\\n' >&2\nexit \"$2\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700)).unwrap();
        let tools = prepare_tools(&d.join("tools"), &exe.to_string_lossy(), true).unwrap();
        let script = std::fs::read_to_string(tools.join("fastboot")).unwrap();
        assert!(
            script.contains("'\\''"),
            "the quote in the path is escaped: {script}"
        );
        for code in [0, 1, 7] {
            let o = Command::new(tools.join("fastboot"))
                .args(["a b", &code.to_string()])
                .env("ANDROID_SERIAL", "SER1")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert_eq!(o.status.code(), Some(code));
            assert_eq!(String::from_utf8_lossy(&o.stdout), "out a b|SER1\n");
            assert_eq!(String::from_utf8_lossy(&o.stderr), "product: bluejay\n");
        }
        // The script's own product check works through the stand-in ...
        let check = "product=$(fastboot getvar product 0 2>&1 | grep \"product:\" | cut -d ' ' -f 2)\n[ $product = \"bluejay\" ]\n";
        let ok = Command::new("bash")
            .args(["-c", check])
            .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
            .status()
            .unwrap();
        assert!(ok.success());
        // ... and fails without it (the CRLF problem).
        let raw = d.join("raw");
        std::fs::create_dir(&raw).unwrap();
        std::os::unix::fs::symlink(&exe, raw.join("fastboot")).unwrap();
        let bad = Command::new("bash")
            .args(["-c", check])
            .env("PATH", format!("{}:/usr/bin:/bin", raw.display()))
            .status()
            .unwrap();
        assert!(!bad.success());
        // A link, not a stand-in, on Linux.
        let t2 = prepare_tools(&d.join("tools2"), &exe.to_string_lossy(), false).unwrap();
        assert!(std::fs::symlink_metadata(t2.join("fastboot"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
