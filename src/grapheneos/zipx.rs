// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Unpacks a verified factory image (a ZIP of about 2 GB holding 4.6 GB of
//! images) without holding an entry in memory: stored and deflated entries,
//! streamed, each checked against its CRC-32 and size. Every name must lie
//! inside the one top folder `<codename>-install-<version>/`; no `..`, no
//! absolute path, no backslash, no duplicate. No ZIP64 (the images are
//! below 4 GiB).

use crate::apk::zip::{le16, le32, Layout};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const CD_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC: [u32; 256] = crc_table();

pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for b in data {
        c = CRC[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    method: u16,
    flags: u16,
    crc: u32,
    comp_size: u64,
    pub size: u64,
    local_offset: u64,
}

fn safe_name(name: &str, top: &str) -> Result<(), String> {
    let inside = name
        .strip_prefix(top)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or_else(|| format!("{name:?} is not inside {top}/"))?;
    if name.contains('\\')
        || name.contains('\0')
        || name.starts_with('/')
        || inside
            .split('/')
            .any(|c| c == ".." || c == "." || (c.is_empty() && !inside.ends_with('/')))
    {
        return Err(format!("unsafe name in the image: {name:?}"));
    }
    Ok(())
}

/// The entries of the archive, checked.
pub fn entries(f: &mut File, size: u64, top: &str) -> Result<(Layout, Vec<Entry>), String> {
    let layout = Layout::read(f, size)?;
    let cd = &layout.cd;
    let mut out: Vec<Entry> = Vec::new();
    let mut i = 0;
    while i < cd.len() {
        if i + 46 > cd.len() || le32(cd, i) != CD_SIG {
            return Err("damaged central directory".into());
        }
        let n = le16(cd, i + 28) as usize;
        let x = le16(cd, i + 30) as usize;
        let c = le16(cd, i + 32) as usize;
        if i + 46 + n + x + c > cd.len() {
            return Err("damaged central directory".into());
        }
        let name = std::str::from_utf8(&cd[i + 46..i + 46 + n])
            .map_err(|_| "a name in the image is not UTF-8")?
            .to_string();
        safe_name(&name, top)?;
        if out.iter().any(|e| e.name == name) {
            return Err(format!("{name} is in the image more than once"));
        }
        let e = Entry {
            name,
            flags: le16(cd, i + 8),
            method: le16(cd, i + 10),
            crc: le32(cd, i + 16),
            comp_size: le32(cd, i + 20) as u64,
            size: le32(cd, i + 24) as u64,
            local_offset: le32(cd, i + 42) as u64,
        };
        if [e.comp_size, e.size, e.local_offset].contains(&0xffff_ffff) {
            return Err("ZIP64 entries are not supported".into());
        }
        if e.flags & 1 != 0 {
            return Err(format!("{} is encrypted", e.name));
        }
        if e.method != 0 && e.method != 8 {
            return Err(format!(
                "{}: unsupported compression method {}",
                e.name, e.method
            ));
        }
        out.push(e);
        i += 46 + n + x + c;
    }
    if out.is_empty() {
        return Err("the image holds no files".into());
    }
    Ok((layout, out))
}

fn copy_entry(f: &mut File, layout: &Layout, e: &Entry, out: &mut dyn Write) -> Result<(), String> {
    let mut lh = [0u8; 30];
    f.seek(SeekFrom::Start(e.local_offset))
        .and_then(|_| f.read_exact(&mut lh))
        .map_err(|x| format!("read error: {x}"))?;
    if le32(&lh, 0) != LOCAL_SIG {
        return Err(format!("{}: damaged local header", e.name));
    }
    let data_at = e.local_offset + 30 + le16(&lh, 26) as u64 + le16(&lh, 28) as u64;
    if data_at + e.comp_size > layout.cd_offset {
        return Err(format!("{}: data runs past the entries", e.name));
    }
    f.seek(SeekFrom::Start(data_at))
        .map_err(|x| format!("read error: {x}"))?;
    let mut src = BufReader::with_capacity(1 << 20, (&mut *f).take(e.comp_size));
    let mut crc = 0u32;
    let mut written = 0u64;
    let mut emit = |b: &[u8]| -> Result<(), String> {
        crc = crc32_update(crc, b);
        written += b.len() as u64;
        if written > e.size {
            return Err(format!("{}: more data than the directory says", e.name));
        }
        out.write_all(b).map_err(|x| format!("write error: {x}"))
    };
    let mut inbuf = vec![0u8; 1 << 20];
    match e.method {
        0 => loop {
            let n = src
                .read(&mut inbuf)
                .map_err(|x| format!("read error: {x}"))?;
            if n == 0 {
                break;
            }
            emit(&inbuf[..n])?;
        },
        _ => {
            use miniz_oxide::inflate::stream::{inflate, InflateState};
            use miniz_oxide::{DataFormat, MZFlush, MZStatus};
            let mut st = InflateState::new_boxed(DataFormat::Raw);
            let mut outbuf = vec![0u8; 1 << 20];
            let mut have = 0usize;
            let mut eof = false;
            loop {
                if have == 0 && !eof {
                    have = src
                        .read(&mut inbuf)
                        .map_err(|x| format!("read error: {x}"))?;
                    eof = have == 0;
                }
                let flush = if eof { MZFlush::Finish } else { MZFlush::None };
                let r = inflate(&mut st, &inbuf[..have], &mut outbuf, flush);
                inbuf.copy_within(r.bytes_consumed..have, 0);
                have -= r.bytes_consumed;
                emit(&outbuf[..r.bytes_written])?;
                match r.status {
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(_) => {
                        if eof && r.bytes_written == 0 && r.bytes_consumed == 0 {
                            return Err(format!("{}: compressed data ends early", e.name));
                        }
                    }
                    Err(miniz_oxide::MZError::Buf) if !eof || have > 0 => {}
                    Err(x) => return Err(format!("{}: cannot inflate ({x:?})", e.name)),
                }
            }
        }
    }
    if written != e.size {
        return Err(format!("{}: size differs from the directory", e.name));
    }
    if crc != e.crc {
        return Err(format!("{}: CRC-32 differs from the directory", e.name));
    }
    Ok(())
}

/// Unpacks every entry below `dest` (which must not exist yet) and returns
/// the path of the top folder.
pub fn extract(zip: &Path, dest: &Path, top: &str) -> Result<PathBuf, String> {
    let mut f = File::open(zip).map_err(|e| format!("cannot open {}: {e}", zip.display()))?;
    let size = f
        .metadata()
        .map_err(|e| format!("cannot read {}: {e}", zip.display()))?
        .len();
    let (layout, list) = entries(&mut f, size, top)?;
    std::fs::create_dir(dest).map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    std::fs::create_dir(dest.join(top))
        .map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    for e in &list {
        let p = dest.join(&e.name);
        if e.name.ends_with('/') {
            std::fs::create_dir_all(&p)
                .map_err(|x| format!("cannot create {}: {x}", p.display()))?;
            continue;
        }
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)
                .map_err(|x| format!("cannot create {}: {x}", d.display()))?;
        }
        let mut o = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(|x| format!("cannot create {}: {x}", p.display()))?;
        let mut w = std::io::BufWriter::with_capacity(1 << 20, &mut o);
        copy_entry(&mut f, &layout, e, &mut w)?;
        w.flush().map_err(|x| format!("write error: {x}"))?;
    }
    Ok(dest.join(top))
}

/// Test only: a ZIP with stored and deflated entries.
#[cfg(test)]
pub fn build_for_tests(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data, deflate) in files {
        let comp = if *deflate {
            miniz_oxide::deflate::compress_to_vec(data, 6)
        } else {
            data.to_vec()
        };
        let crc = crc32_update(0, data);
        let off = out.len() as u32;
        let method: u16 = if *deflate { 8 } else { 0 };
        let mut lh = Vec::new();
        lh.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        lh.extend_from_slice(&20u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&method.to_le_bytes());
        lh.extend_from_slice(&[0, 0, 0x21, 0]);
        lh.extend_from_slice(&crc.to_le_bytes());
        lh.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
        lh.extend_from_slice(&(name.len() as u16).to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&lh);
        out.extend_from_slice(&comp);
        cd.extend_from_slice(&CD_SIG.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&[0, 0, 0x21, 0]);
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 8]);
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_value() {
        assert_eq!(crc32_update(0, b"123456789"), 0xcbf4_3926);
        let a = crc32_update(0, b"1234");
        assert_eq!(crc32_update(a, b"56789"), 0xcbf4_3926);
    }

    #[test]
    fn extract_stored_and_deflated_and_refuse_bad_names() {
        let d = crate::activation::store::tests::temp_dir("zipx");
        let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let z = build_for_tests(&[
            ("top/flash-all.sh", b"#!/bin/sh\necho hi\n", false),
            ("top/super_1.img", &big, true),
            ("top/sub/", b"", false),
            ("top/sub/a.txt", b"a", true),
        ]);
        let zp = d.join("x.zip");
        std::fs::write(&zp, &z).unwrap();
        let top = extract(&zp, &d.join("out"), "top").unwrap();
        assert_eq!(std::fs::read(top.join("super_1.img")).unwrap(), big);
        assert_eq!(std::fs::read(top.join("sub/a.txt")).unwrap(), b"a");
        assert!(extract(&zp, &d.join("out"), "top").is_err(), "dest exists");
        for bad in ["../x", "top/../x", "/top/x", "top\\x", "other/x", "top/./x"] {
            let z = build_for_tests(&[(bad, b"x", false)]);
            std::fs::write(&zp, &z).unwrap();
            assert!(extract(&zp, &d.join("bad"), "top").is_err(), "{bad}");
            assert!(!d.join("bad").exists());
        }
        // A changed byte in a deflated entry: CRC or inflate error.
        let mut z = build_for_tests(&[("top/a.img", &big, true)]);
        z[200] ^= 0x55;
        std::fs::write(&zp, &z).unwrap();
        assert!(extract(&zp, &d.join("crc"), "top").is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
