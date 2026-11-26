// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! The parts of the ZIP format an APK check needs: the end of central
//! directory record, the central directory, and one entry's data (stored or
//! deflated). No ZIP64: an APK this tool accepts is far below 4 GiB.

use std::io::{Read, Seek, SeekFrom};

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;
const EOCD_MIN: usize = 22;
/// Largest central directory read into memory.
const MAX_CD: u64 = 64 * 1024 * 1024;
/// Largest entry inflated (the manifest is a few KiB).
const MAX_ENTRY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Layout {
    pub cd_offset: u64,
    /// The EOCD record and comment, as in the file.
    pub eocd: Vec<u8>,
    pub cd: Vec<u8>,
}

pub fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
pub fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Layout {
    pub fn read<R: Read + Seek>(f: &mut R, size: u64) -> Result<Layout, String> {
        if size < EOCD_MIN as u64 {
            return Err("not a ZIP file (too short)".into());
        }
        let tail_len = size.min((EOCD_MIN + 0xffff) as u64) as usize;
        let mut tail = vec![0u8; tail_len];
        f.seek(SeekFrom::Start(size - tail_len as u64))
            .and_then(|_| f.read_exact(&mut tail))
            .map_err(|e| format!("read error: {e}"))?;
        // The last EOCD whose comment length reaches exactly to the end.
        let mut found = None;
        for i in (0..=tail_len - EOCD_MIN).rev() {
            if le32(&tail, i) == EOCD_SIG && i + EOCD_MIN + le16(&tail, i + 20) as usize == tail_len
            {
                found = Some(i);
                break;
            }
        }
        let i = found.ok_or("not a ZIP file (no end of central directory record)")?;
        let eocd = tail[i..].to_vec();
        let eocd_offset = size - (tail_len - i) as u64;
        if le16(&eocd, 4) != 0 || le16(&eocd, 6) != 0 || le16(&eocd, 8) != le16(&eocd, 10) {
            return Err("multi-disk ZIP files are not APKs".into());
        }
        let cd_size = le32(&eocd, 12) as u64;
        let cd_offset = le32(&eocd, 16) as u64;
        if cd_offset == 0xffff_ffff || cd_size == 0xffff_ffff {
            return Err("ZIP64 is not supported".into());
        }
        if cd_offset + cd_size != eocd_offset {
            return Err("central directory does not end at the end record".into());
        }
        if cd_size > MAX_CD {
            return Err("central directory too large".into());
        }
        let mut cd = vec![0u8; cd_size as usize];
        f.seek(SeekFrom::Start(cd_offset))
            .and_then(|_| f.read_exact(&mut cd))
            .map_err(|e| format!("read error: {e}"))?;
        Ok(Layout {
            cd_offset,
            eocd,
            cd,
        })
    }
}

struct Entry {
    method: u16,
    flags: u16,
    comp_size: u64,
    uncomp_size: u64,
    local_offset: u64,
}

fn find(layout: &Layout, name: &str) -> Result<Entry, String> {
    let cd = &layout.cd;
    let mut i = 0;
    let mut hit = None;
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
        if &cd[i + 46..i + 46 + n] == name.as_bytes() {
            if hit.is_some() {
                return Err(format!("{name} is in the archive more than once"));
            }
            hit = Some(Entry {
                flags: le16(cd, i + 8),
                method: le16(cd, i + 10),
                comp_size: le32(cd, i + 20) as u64,
                uncomp_size: le32(cd, i + 24) as u64,
                local_offset: le32(cd, i + 42) as u64,
            });
        }
        i += 46 + n + x + c;
    }
    hit.ok_or_else(|| format!("{name} not found in the archive"))
}

/// The names of all entries in the central directory, in order.
pub fn names(layout: &Layout) -> Result<Vec<String>, String> {
    let cd = &layout.cd;
    let mut i = 0;
    let mut out = Vec::new();
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
            .map_err(|_| "an entry name is not UTF-8")?;
        out.push(name.to_string());
        i += 46 + n + x + c;
    }
    Ok(out)
}

/// The uncompressed data of entry `name`.
pub fn read_entry<R: Read + Seek>(
    f: &mut R,
    layout: &Layout,
    name: &str,
) -> Result<Vec<u8>, String> {
    let e = find(layout, name)?;
    if e.flags & 1 != 0 {
        return Err(format!("{name} is encrypted"));
    }
    if e.uncomp_size as usize > MAX_ENTRY || e.comp_size as usize > MAX_ENTRY {
        return Err(format!("{name} is too large"));
    }
    let mut lh = [0u8; 30];
    f.seek(SeekFrom::Start(e.local_offset))
        .and_then(|_| f.read_exact(&mut lh))
        .map_err(|e| format!("read error: {e}"))?;
    if le32(&lh, 0) != LOCAL_SIG {
        return Err(format!("{name}: damaged local header"));
    }
    let data_at = e.local_offset + 30 + le16(&lh, 26) as u64 + le16(&lh, 28) as u64;
    if data_at + e.comp_size > layout.cd_offset {
        return Err(format!("{name}: data runs past the entries"));
    }
    let mut data = vec![0u8; e.comp_size as usize];
    f.seek(SeekFrom::Start(data_at))
        .and_then(|_| f.read_exact(&mut data))
        .map_err(|e| format!("read error: {e}"))?;
    let out = match e.method {
        0 => data,
        8 => miniz_oxide::inflate::decompress_to_vec_with_limit(&data, MAX_ENTRY)
            .map_err(|_| format!("{name}: cannot inflate"))?,
        m => return Err(format!("{name}: unsupported compression method {m}")),
    };
    if out.len() as u64 != e.uncomp_size {
        return Err(format!("{name}: size differs from the directory"));
    }
    Ok(out)
}
