// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! POSIX ustar, only what the backup format allows (section 4): regular
//! files, mode 0600, mtime 0, relative `/`-separated paths without `..`.
//! The reader refuses everything else: links, directories, devices, pax and
//! GNU extension headers, absolute paths, `.` or `..` or empty components,
//! duplicate paths, a wrong checksum, data after the end marker.

const BLOCK: usize = 512;
/// Largest member and largest archive a reader accepts.
pub const MAX_MEMBER: usize = 128 * 1024 * 1024;

pub struct Member {
    pub path: String,
    pub data: Vec<u8>,
}

/// Names the path and the size only, never the content.
impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Member({}, {} bytes)", self.path, self.data.len())
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data);
    }
}

/// A path the format allows.
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.contains('\0')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
        && p.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn octal(field: &mut [u8], v: u64) {
    let w = field.len() - 1;
    let s = format!("{v:0w$o}");
    field[..w].copy_from_slice(s.as_bytes());
    field[w] = 0;
}

/// Splits a path into ustar `prefix` and `name`.
fn split(p: &str) -> Option<(&str, &str)> {
    if p.len() <= 100 {
        return Some(("", p));
    }
    let b = p.as_bytes();
    (0..p.len())
        .rev()
        .filter(|i| b[*i] == b'/')
        .find(|i| *i <= 155 && p.len() - i - 1 <= 100)
        .map(|i| (&p[..i], &p[i + 1..]))
}

pub fn write(members: &[Member]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let mut out = zeroize::Zeroizing::new(Vec::new());
    for m in members {
        if !valid_path(&m.path) {
            return Err(format!("invalid member path {:?}", m.path));
        }
        let (prefix, name) = split(&m.path).ok_or(format!("path too long: {}", m.path))?;
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut h[100..108], 0o600);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], m.data.len() as u64);
        octal(&mut h[136..148], 0);
        h[148..156].copy_from_slice(b"        ");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        octal(&mut h[329..337], 0);
        octal(&mut h[337..345], 0);
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        let s = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&m.data);
        let pad = (BLOCK - m.data.len() % BLOCK) % BLOCK;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 2 * BLOCK));
    Ok(out)
}

/// A NUL- or space-terminated octal field.
fn parse_octal(f: &[u8]) -> Option<u64> {
    let s: &[u8] = match f.iter().position(|b| *b == 0) {
        Some(i) => &f[..i],
        None => f,
    };
    let s = std::str::from_utf8(s).ok()?.trim_matches(' ');
    if s.is_empty() || !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    u64::from_str_radix(s, 8).ok()
}

fn text(f: &[u8]) -> Result<&str, String> {
    let end = f.iter().position(|b| *b == 0).unwrap_or(f.len());
    if f[end..].iter().any(|b| *b != 0) {
        return Err("a text field continues after its NUL".into());
    }
    std::str::from_utf8(&f[..end]).map_err(|_| "a path is not text".to_string())
}

pub fn read(archive: &[u8]) -> Result<Vec<Member>, String> {
    if !archive.len().is_multiple_of(BLOCK) {
        return Err("the archive is not a whole number of 512-byte blocks".into());
    }
    let mut out: Vec<Member> = Vec::new();
    let mut at = 0;
    loop {
        if at + BLOCK > archive.len() {
            return Err("the archive has no end marker".into());
        }
        let h = &archive[at..at + BLOCK];
        if h.iter().all(|b| *b == 0) {
            // End: two zero blocks, then only zero blocks (record padding).
            if at + 2 * BLOCK > archive.len() {
                return Err("the end marker is one block, not two".into());
            }
            if archive[at..].iter().any(|b| *b != 0) {
                return Err("data after the end marker".into());
            }
            return Ok(out);
        }
        let stored = parse_octal(&h[148..156]).ok_or("a header checksum is not octal")?;
        let mut sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        sum = sum - h[148..156].iter().map(|b| u64::from(*b)).sum::<u64>() + 8 * 32;
        if sum != stored {
            return Err("a header checksum does not match".into());
        }
        if &h[257..263] != b"ustar\0" || &h[263..265] != b"00" {
            return Err("not a POSIX ustar header".into());
        }
        match h[156] {
            b'0' => {}
            t => {
                return Err(format!(
                    "member type {:?} refused: only regular files",
                    t as char
                ))
            }
        }
        let name = text(&h[0..100])?;
        let prefix = text(&h[345..500])?;
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if !valid_path(&path) {
            return Err(format!("member path {path:?} refused"));
        }
        if !text(&h[157..257])?.is_empty() {
            return Err(format!("{path}: a link name"));
        }
        let mode = parse_octal(&h[100..108]).ok_or("a mode is not octal")?;
        if mode != 0o600 {
            return Err(format!("{path}: mode {mode:04o}, not 0600"));
        }
        let mtime = parse_octal(&h[136..148]).ok_or("an mtime is not octal")?;
        if mtime != 0 {
            return Err(format!("{path}: mtime {mtime}, not 0"));
        }
        let size = parse_octal(&h[124..136]).ok_or("a size is not octal")? as usize;
        if size > MAX_MEMBER {
            return Err(format!("{path}: too large"));
        }
        let start = at + BLOCK;
        let end = start.checked_add(size).ok_or("size overflow")?;
        if end > archive.len() {
            return Err(format!("{path}: truncated"));
        }
        if out.iter().any(|m| m.path == path) {
            return Err(format!("{path}: twice in the archive"));
        }
        out.push(Member {
            path,
            data: archive[start..end].to_vec(),
        });
        at = start + size.div_ceil(BLOCK) * BLOCK;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, d: &[u8]) -> Member {
        Member {
            path: p.into(),
            data: d.to_vec(),
        }
    }

    #[test]
    fn round_trip() {
        let long = format!("admin/organizer/{}/{}", "a".repeat(90), "b".repeat(60));
        let a = write(&[
            m("manifest.json", b"{}"),
            m("admin/x", &[7; 1000]),
            m(&long, b""),
        ])
        .unwrap();
        assert_eq!(a.len() % 512, 0);
        let r = read(&a).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].path, "manifest.json");
        assert_eq!(r[1].data, vec![7; 1000]);
        assert_eq!(r[2].path, long);
        // Record padding (zero blocks) after the end marker is accepted.
        let mut padded = a.to_vec();
        padded.extend([0u8; 10240]);
        assert_eq!(read(&padded).unwrap().len(), 3);
    }

    fn header_of(a: &mut [u8], f: impl FnOnce(&mut [u8])) {
        f(&mut a[..512]);
        a[148..156].copy_from_slice(b"        ");
        let sum: u32 = a[..512].iter().map(|b| u32::from(*b)).sum();
        a[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    #[test]
    fn refusals() {
        let good = write(&[m("admin/x", b"data")]).unwrap().to_vec();
        type Case = (&'static str, Box<dyn Fn(&mut [u8])>);
        let cases: Vec<Case> = vec![
            ("type", Box::new(|h| h[156] = b'2')),
            ("type", Box::new(|h| h[156] = b'5')),
            ("type", Box::new(|h| h[156] = b'x')),
            ("type", Box::new(|h| h[156] = b'L')),
            (
                "mode",
                Box::new(|h| h[100..108].copy_from_slice(b"0000644\0")),
            ),
            (
                "mtime",
                Box::new(|h| h[136..148].copy_from_slice(b"00000000001\0")),
            ),
            (
                "refused",
                Box::new(|h| h[..8].copy_from_slice(b"../x\0\0\0\0")),
            ),
            (
                "refused",
                Box::new(|h| h[..8].copy_from_slice(b"/etc/x\0\0")),
            ),
            (
                "refused",
                Box::new(|h| h[..8].copy_from_slice(b"a//x\0\0\0\0")),
            ),
            (
                "refused",
                Box::new(|h| h[..8].copy_from_slice(b"./x\0\0\0\0\0")),
            ),
            ("link name", Box::new(|h| h[157] = b'y')),
            ("ustar", Box::new(|h| h[257] = b'X')),
        ];
        for (want, f) in cases {
            let mut a = good.clone();
            header_of(&mut a, f);
            let e = read(&a).err().unwrap_or_default();
            assert!(e.contains(want), "{want}: {e}");
        }
        // A changed byte without a new checksum.
        let mut a = good.clone();
        a[0] = b'b';
        assert!(read(&a).unwrap_err().contains("checksum"));
        // Twice the same path, data after the end, truncated, no end.
        let two = write(&[m("a", b"1"), m("a", b"2")]);
        assert!(two.is_ok());
        assert!(read(&two.unwrap()).unwrap_err().contains("twice"));
        let mut after = good.clone();
        after.extend(write(&[m("b", b"x")]).unwrap().iter());
        assert!(read(&after).unwrap_err().contains("after the end"));
        assert!(read(&good[..1024]).is_err());
        assert!(read(&good[..512 * 2 + 512]).is_err());
        assert!(write(&[m("../x", b"")]).is_err());
    }
}
