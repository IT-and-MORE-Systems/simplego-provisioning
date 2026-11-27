// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The admin store's random 256-bit key. Nobody types it.
//!
//! Where it lives is detected at run time and named in the output:
//! - **TPM 2.0**: where `/dev/tpmrm0` exists and `systemd-creds has-tpm2`
//!   succeeds, the key is sealed with `systemd-creds --user encrypt
//!   --with-key=tpm2 --tpm2-pcrs=` (user scope, no PCR binding, so a
//!   firmware, kernel or Secure Boot update never locks the operator out)
//!   into `<store>.key.cred`. A copy of that file is useless off this
//!   machine.
//! - **Key file**: otherwise `<store>.key`, mode 0600, in the store's
//!   directory (mode 0700). On Linux outside WSL a new key file is only
//!   written onto an encrypted disk (dm-crypt, also LVM on LUKS), unless a
//!   throwaway test config allows otherwise. In WSL it is a plain file.
//!
//! Both hold the same text: `sxprov-store-key-v1 <64 lowercase hex>` and a
//! newline. The backup carries that text as `admin/store-key`, so a restore
//! on a new laptop works without the old laptop's TPM.

use super::rng::{bytes, Rand};
use super::store::write_new_private;
use crate::util::{hex, unhex};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub type StoreKey = Zeroizing<[u8; 32]>;

pub const TEXT_PREFIX: &str = "sxprov-store-key-v1 ";
/// The credential name sealed into the TPM blob; decryption checks it.
pub const CRED_NAME: &str = "sxprov-store-key";
const TPM_DEVICE: &str = "/dev/tpmrm0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Tpm,
    File,
}

impl Backend {
    /// Stable name for `--json`.
    pub fn id(self) -> &'static str {
        match self {
            Backend::Tpm => "tpm",
            Backend::File => "file",
        }
    }
    pub fn describe(self) -> &'static str {
        match self {
            Backend::Tpm => "sealed with the TPM 2.0 (systemd-creds, user scope, no PCR binding)",
            Backend::File => "key file, mode 0600",
        }
    }
}

/// `<store>.key` or `<store>.key.cred`.
pub fn key_path(store: &Path, b: Backend) -> PathBuf {
    let mut name = store.file_name().unwrap_or_default().to_os_string();
    name.push(match b {
        Backend::Tpm => ".key.cred",
        Backend::File => ".key",
    });
    store.with_file_name(name)
}

/// The `systemd-creds` program (a fake one in the tests).
#[derive(Debug, Clone)]
pub struct Creds {
    pub program: PathBuf,
    /// The TPM device whose presence is checked first.
    pub device: PathBuf,
}

impl Creds {
    pub fn system() -> Creds {
        Creds {
            program: PathBuf::from("systemd-creds"),
            device: PathBuf::from(TPM_DEVICE),
        }
    }

    /// Ok when the TPM can seal the key: the device exists and
    /// `systemd-creds has-tpm2` reports full support. Err says why not.
    pub fn tpm_available(&self) -> Result<(), String> {
        if !self.device.exists() {
            return Err(format!("no {}", self.device.display()));
        }
        let out = Command::new(&self.program)
            .arg("has-tpm2")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("{} not usable: {e}", self.program.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err("systemd-creds has-tpm2 reports no full TPM 2.0 support".into())
        }
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use std::io::Write;
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.program.display()))?;
        if let Some(mut si) = child.stdin.take() {
            si.write_all(input)
                .map_err(|e| format!("systemd-creds: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("systemd-creds: {e}"))?;
        let stdout = Zeroizing::new(out.stdout);
        if !out.status.success() {
            return Err(format!(
                "systemd-creds {} failed: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(stdout)
    }

    fn seal(&self, plain: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let name = format!("--name={CRED_NAME}");
        self.run(
            &[
                "--user",
                "encrypt",
                "--with-key=tpm2",
                "--tpm2-pcrs=",
                &name,
                "-",
                "-",
            ],
            plain,
        )
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let name = format!("--name={CRED_NAME}");
        self.run(&["--user", "decrypt", &name, "-", "-"], blob)
    }
}

/// The key as the text of the key file.
pub fn to_text(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("{TEXT_PREFIX}{}\n", hex(key)))
}

/// Parses the key text: the prefix, 64 lowercase hex characters, one
/// newline. Anything else is refused.
pub fn from_text(t: &[u8]) -> Result<StoreKey, String> {
    const FORM: &str = "a store key is `sxprov-store-key-v1 ` and 64 lowercase hex characters";
    let s = std::str::from_utf8(t).map_err(|_| FORM.to_string())?;
    let s = s.strip_suffix('\n').ok_or(FORM)?;
    let h = s.strip_prefix(TEXT_PREFIX).ok_or(FORM)?;
    if h.len() != 64 || !h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(FORM.into());
    }
    let v = Zeroizing::new(unhex(h).ok_or(FORM)?);
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&v);
    Ok(k)
}

/// Reads a key file: a regular file (no link), not readable by group or
/// others.
fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.file_type().is_file() {
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
    if meta.len() > 64 * 1024 {
        return Err(format!("{shown} is too large for a store key"));
    }
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read {shown}: {e}"))
}

/// Which key files exist next to the store.
pub fn present(store: &Path) -> Vec<Backend> {
    [Backend::Tpm, Backend::File]
        .into_iter()
        .filter(|b| std::fs::symlink_metadata(key_path(store, *b)).is_ok())
        .collect()
}

/// Loads the store's key. Exactly one key file must be next to the store.
pub fn load(store: &Path, creds: &Creds) -> Result<(StoreKey, Backend), String> {
    match present(store).as_slice() {
        [b] => Ok((load_backend(store, *b, creds)?, *b)),
        [] => Err(format!(
            "no store key next to {}: expected {} or {}",
            store.display(),
            key_path(store, Backend::Tpm).display(),
            key_path(store, Backend::File).display()
        )),
        _ => Err(format!(
            "two store keys next to {} ({} and {}); remove the one that does not belong to the store",
            store.display(),
            key_path(store, Backend::Tpm).display(),
            key_path(store, Backend::File).display()
        )),
    }
}

pub fn load_backend(store: &Path, b: Backend, creds: &Creds) -> Result<StoreKey, String> {
    let p = key_path(store, b);
    let raw = read_private(&p)?;
    match b {
        Backend::File => from_text(&raw).map_err(|e| format!("{}: {e}", p.display())),
        Backend::Tpm => {
            let plain = creds.unseal(&raw)?;
            from_text(&plain).map_err(|e| format!("{} (unsealed): {e}", p.display()))
        }
    }
}

/// Writes `key` next to the store (refuses an existing file) and reads it
/// back the way every later command will. On any failure nothing stays.
pub fn write(store: &Path, b: Backend, key: &[u8; 32], creds: &Creds) -> Result<(), String> {
    let p = key_path(store, b);
    if !present(store).is_empty() {
        return Err(format!(
            "a store key already exists next to {}",
            store.display()
        ));
    }
    let text = to_text(key);
    let data = match b {
        Backend::File => Zeroizing::new(text.as_bytes().to_vec()),
        Backend::Tpm => creds.seal(text.as_bytes())?,
    };
    write_new_private(&p, &data).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    let back = load_backend(store, b, creds);
    match back {
        Ok(k) if *k == *key => Ok(()),
        Ok(_) => {
            let _ = std::fs::remove_file(&p);
            Err(format!("{} reads back a different key", p.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&p);
            Err(format!("{} does not read back: {e}", p.display()))
        }
    }
}

/// A new random key, written with `write`.
pub fn create(
    store: &Path,
    b: Backend,
    creds: &Creds,
    rng: &mut dyn Rand,
) -> Result<StoreKey, String> {
    let key = Zeroizing::new(bytes::<32>(rng)?);
    write(store, b, &key, creds)?;
    Ok(key)
}

pub fn remove(store: &Path, b: Backend) {
    let _ = std::fs::remove_file(key_path(store, b));
}

/// Where a new key goes, and why: the TPM if it can seal, else a key file.
/// A key file outside WSL on Linux needs an encrypted disk unless
/// `allow_unencrypted` (a throwaway test config only).
pub fn choose(
    store: &Path,
    creds: &Creds,
    allow_unencrypted: bool,
) -> Result<(Backend, String), String> {
    let why_not = match creds.tpm_available() {
        Ok(()) => return Ok((Backend::Tpm, "TPM 2.0 found".into())),
        Err(e) => e,
    };
    if crate::device::running_in_wsl() {
        return Ok((
            Backend::File,
            format!("WSL, {why_not}; the disk encryption is not checked in WSL"),
        ));
    }
    let dir = store.parent().unwrap_or(Path::new("/"));
    match encrypted_disk(dir) {
        Ok(true) => Ok((
            Backend::File,
            format!("{why_not}; on an encrypted disk (dm-crypt)"),
        )),
        Ok(false) | Err(_) if allow_unencrypted => Ok((
            Backend::File,
            format!("{why_not}; disk encryption NOT checked (--allow-unencrypted-disk, test config)"),
        )),
        Ok(false) => Err(format!(
            "{why_not}, and {} is not on an encrypted disk (dm-crypt): a key file there would leave the store open to anyone with the disk; set up disk encryption or a TPM",
            dir.display()
        )),
        Err(e) => Err(format!(
            "{why_not}, and the disk encryption of {} cannot be checked: {e}",
            dir.display()
        )),
    }
}

/// True if `dir` lies on a dm-crypt device (directly or below LVM).
pub fn encrypted_disk(dir: &Path) -> Result<bool, String> {
    encrypted_disk_in(dir, Path::new("/proc/self/mountinfo"), Path::new("/sys"))
}

fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            let v = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok());
            if let Some(v) = v {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `encrypted_disk` with the mount table and sysfs given (for the tests).
pub fn encrypted_disk_in(dir: &Path, mountinfo: &Path, sys: &Path) -> Result<bool, String> {
    let mut existing = dir.to_path_buf();
    while !existing.exists() {
        match existing.parent() {
            Some(p) => existing = p.to_path_buf(),
            None => break,
        }
    }
    let canon = std::fs::canonicalize(&existing).unwrap_or(existing);
    let table = std::fs::read_to_string(mountinfo)
        .map_err(|e| format!("cannot read {}: {e}", mountinfo.display()))?;
    // Longest mount point that contains the path.
    let mut best: Option<(usize, String, String)> = None;
    for line in table.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else {
            continue;
        };
        if f.len() < 5 || f.len() < sep + 3 {
            continue;
        }
        let mp = PathBuf::from(unescape_mount(f[4]));
        if canon.starts_with(&mp) {
            let depth = mp.components().count();
            if best.as_ref().is_none_or(|b| depth >= b.0) {
                best = Some((depth, f[2].to_string(), unescape_mount(f[sep + 2])));
            }
        }
    }
    let (_, majmin, source) = best.ok_or("no mount point found")?;
    let majmin = device_of(&source).unwrap_or(majmin);
    let start = sys.join("dev/block").join(&majmin);
    Ok(crypt_below(&start, sys, 0))
}

/// The `major:minor` of a `/dev/...` mount source (btrfs shows `0:N` in
/// the mount table).
fn device_of(source: &str) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !source.starts_with("/dev/") {
            return None;
        }
        let r = std::fs::metadata(source).ok()?.rdev();
        let major = ((r >> 8) & 0xfff) | ((r >> 32) & !0xfff);
        let minor = (r & 0xff) | ((r >> 12) & !0xff);
        Some(format!("{major}:{minor}"))
    }
    #[cfg(not(unix))]
    {
        let _ = source;
        None
    }
}

fn crypt_below(node: &Path, sys: &Path, depth: u8) -> bool {
    if depth > 8 {
        return false;
    }
    if let Ok(u) = std::fs::read_to_string(node.join("dm/uuid")) {
        if u.trim_start().starts_with("CRYPT-") {
            return true;
        }
    }
    // A partition's device lists no slaves; its parent disk is never a
    // dm-crypt device, so only `slaves` is followed.
    let Ok(rd) = std::fs::read_dir(node.join("slaves")) else {
        return false;
    };
    rd.flatten()
        .any(|e| crypt_below(&sys.join("class/block").join(e.file_name()), sys, depth + 1))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::activation::rng::SeededRand;
    use crate::activation::store::tests::{one_at_a_time, temp_dir};

    /// A fake `systemd-creds`: "seals" by prefixing `FAKE-TPM:`, refuses
    /// a blob without it, and answers `has-tpm2` with the exit code in
    /// `has_tpm2`. It checks that encryption names the credential, uses
    /// `--with-key=tpm2` and turns PCR binding off.
    #[cfg(unix)]
    pub fn fake_creds(dir: &Path, has_tpm2: i32) -> Creds {
        use std::os::unix::fs::PermissionsExt;
        let prog = dir.join("fake-systemd-creds");
        let script = format!(
            "#!/bin/sh\n\
             case \"$1\" in has-tpm2) exit {has_tpm2};; esac\n\
             [ \"$1\" = --user ] || {{ echo 'no --user' >&2; exit 9; }}\n\
             case \"$2\" in\n\
             encrypt) [ \"$3\" = --with-key=tpm2 ] && [ \"$4\" = --tpm2-pcrs= ] && [ \"$5\" = --name={CRED_NAME} ] || {{ echo \"bad args $*\" >&2; exit 9; }}\n\
               printf 'FAKE-TPM:'; cat;;\n\
             decrypt) [ \"$3\" = --name={CRED_NAME} ] || exit 9\n\
               d=$(cat); case \"$d\" in FAKE-TPM:*) printf '%s\\n' \"${{d#FAKE-TPM:}}\";; *) echo 'cannot unseal' >&2; exit 1;; esac;;\n\
             *) exit 9;;\n\
             esac\n"
        );
        std::fs::write(&prog, script).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dev = dir.join("tpmrm0");
        std::fs::write(&dev, b"").unwrap();
        Creds {
            program: prog,
            device: dev,
        }
    }

    /// A key file next to a test store, made with a seeded generator.
    pub fn test_key(store: &Path, seed: &[u8]) -> StoreKey {
        create(
            store,
            Backend::File,
            &Creds::system(),
            &mut SeededRand::new(seed),
        )
        .unwrap()
    }

    #[test]
    fn text_form_is_strict() {
        let k = [0xabu8; 32];
        let t = to_text(&k);
        assert_eq!(
            t.as_str(),
            format!("sxprov-store-key-v1 {}\n", "ab".repeat(32))
        );
        assert_eq!(*from_text(t.as_bytes()).unwrap(), k);
        for bad in [
            format!("sxprov-store-key-v1 {}", "ab".repeat(32)),
            format!("sxprov-store-key-v1 {}\n", "AB".repeat(32)),
            format!("sxprov-store-key-v1 {}\n", "ab".repeat(31)),
            format!("sxprov-store-key-v2 {}\n", "ab".repeat(32)),
            format!("sxprov-store-key-v1 {}\n\n", "ab".repeat(32)),
            format!(" sxprov-store-key-v1 {}\n", "ab".repeat(32)),
        ] {
            assert!(from_text(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_file_round_trip_and_refusals() {
        use std::os::unix::fs::PermissionsExt;
        let _g = one_at_a_time();
        let d = temp_dir("storekey-file");
        let store = d.join("admin.sxdb");
        let k = test_key(&store, b"k");
        let p = key_path(&store, Backend::File);
        assert_eq!(p, d.join("admin.sxdb.key"));
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (back, b) = load(&store, &Creds::system()).unwrap();
        assert_eq!((*back, b), (*k, Backend::File));
        // A second key is refused, the first stays.
        assert!(create(
            &store,
            Backend::File,
            &Creds::system(),
            &mut SeededRand::new(b"x")
        )
        .is_err());
        assert_eq!(*load(&store, &Creds::system()).unwrap().0, *k);
        // Readable by others: refused.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&store, &Creds::system())
            .unwrap_err()
            .contains("chmod 600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Two keys next to the store: refused.
        std::fs::write(key_path(&store, Backend::Tpm), b"x").unwrap();
        assert!(load(&store, &Creds::system())
            .unwrap_err()
            .contains("two store keys"));
        std::fs::remove_file(key_path(&store, Backend::Tpm)).unwrap();
        // A link instead of a file: refused.
        std::fs::rename(&p, d.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(d.join("elsewhere"), &p).unwrap();
        assert!(load(&store, &Creds::system())
            .unwrap_err()
            .contains("not a regular file"));
        std::fs::remove_file(&p).unwrap();
        assert!(load(&store, &Creds::system())
            .unwrap_err()
            .contains("no store key"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn tpm_backend_through_systemd_creds() {
        let _g = one_at_a_time();
        let d = temp_dir("storekey-tpm");
        let store = d.join("admin.sxdb");
        let creds = fake_creds(&d, 0);
        let (b, why) = choose(&store, &creds, false).unwrap();
        assert_eq!(b, Backend::Tpm, "{why}");
        let k = create(&store, Backend::Tpm, &creds, &mut SeededRand::new(b"tpm")).unwrap();
        let blob = std::fs::read(key_path(&store, Backend::Tpm)).unwrap();
        assert!(blob.starts_with(b"FAKE-TPM:"));
        let (back, b) = load(&store, &creds).unwrap();
        assert_eq!((*back, b), (*k, Backend::Tpm));
        // A blob the TPM cannot unseal: refused, with systemd-creds' reason.
        std::fs::write(key_path(&store, Backend::Tpm), b"garbage").unwrap();
        assert!(load(&store, &creds).unwrap_err().contains("cannot unseal"));
        // No TPM device, or has-tpm2 not fully supported: not the TPM.
        let no_dev = Creds {
            device: d.join("none"),
            ..creds.clone()
        };
        assert!(no_dev.tpm_available().unwrap_err().contains("no "));
        let partial = fake_creds(&temp_dir("storekey-tpm2"), 1);
        assert!(partial.tpm_available().is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_seal_leaves_no_key() {
        let _g = one_at_a_time();
        let d = temp_dir("storekey-sealfail");
        let store = d.join("admin.sxdb");
        let mut creds = fake_creds(&d, 0);
        creds.program = d.join("missing-program");
        assert!(create(&store, Backend::Tpm, &creds, &mut SeededRand::new(b"f")).is_err());
        assert!(present(&store).is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_disk_detection_on_a_fake_sysfs() {
        let _g = one_at_a_time();
        let d = temp_dir("storekey-dmcrypt");
        let sys = d.join("sys");
        // dm-1 (LVM, root) on dm-0 (LUKS); sda2 (plain) for /boot; 0:40 btrfs.
        for (dev, uuid, slaves) in [
            ("254:0", Some("CRYPT-LUKS2-abc-luks"), vec![]),
            ("254:1", Some("LVM-xyz"), vec!["dm-0"]),
            ("8:2", None, vec![]),
        ] {
            let n = sys.join("dev/block").join(dev);
            std::fs::create_dir_all(n.join("slaves")).unwrap();
            if let Some(u) = uuid {
                std::fs::create_dir_all(n.join("dm")).unwrap();
                std::fs::write(n.join("dm/uuid"), format!("{u}\n")).unwrap();
            }
            for s in slaves {
                std::fs::write(n.join("slaves").join(s), b"").unwrap();
            }
        }
        std::fs::create_dir_all(sys.join("class/block")).unwrap();
        std::os::unix::fs::symlink(sys.join("dev/block/254:0"), sys.join("class/block/dm-0"))
            .unwrap();
        let root = d.join("root");
        std::fs::create_dir_all(root.join("boot")).unwrap();
        std::fs::create_dir_all(root.join("home/op")).unwrap();
        std::fs::create_dir_all(root.join("plain dir")).unwrap();
        let mi = d.join("mountinfo");
        let r = root.display().to_string();
        let rs = r.replace(' ', "\\040");
        std::fs::write(
            &mi,
            format!(
                "21 1 254:1 / {r} rw - ext4 none rw\n\
                 22 21 8:2 / {r}/boot rw - ext4 none rw\n\
                 23 21 8:2 / {rs}/plain\\040dir rw shared:1 - ext4 none rw\n"
            ),
        )
        .unwrap();
        assert!(encrypted_disk_in(&root.join("home/op/.local/share/sxprov"), &mi, &sys).unwrap());
        assert!(!encrypted_disk_in(&root.join("boot"), &mi, &sys).unwrap());
        assert!(!encrypted_disk_in(&root.join("plain dir"), &mi, &sys).unwrap());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
