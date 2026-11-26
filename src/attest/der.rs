// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Minimal strict DER reader for the attestation extension. The KeyDescription
//! uses context tags above 30 (for example [704]), written in the high tag
//! number form, so tags are decoded here directly.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const BOOLEAN: Tag = Tag::universal(1, false);
    pub const INTEGER: Tag = Tag::universal(2, false);
    pub const OCTET_STRING: Tag = Tag::universal(4, false);
    pub const NULL: Tag = Tag::universal(5, false);
    pub const OID: Tag = Tag::universal(6, false);
    pub const ENUMERATED: Tag = Tag::universal(10, false);
    pub const SEQUENCE: Tag = Tag::universal(16, true);
    pub const SET: Tag = Tag::universal(17, true);

    const fn universal(number: u32, constructed: bool) -> Tag {
        Tag {
            class: Class::Universal,
            constructed,
            number,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
}

pub type Result<T> = std::result::Result<T, String>;

pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn byte(&mut self) -> Result<u8> {
        let (&b, rest) = self.data.split_first().ok_or("DER: unexpected end")?;
        self.data = rest;
        Ok(b)
    }

    fn read_tag(&mut self) -> Result<Tag> {
        let b = self.byte()?;
        let class = match b >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            _ => Class::Private,
        };
        let constructed = b & 0x20 != 0;
        let mut number = (b & 0x1f) as u32;
        if number == 0x1f {
            number = 0;
            let mut first = true;
            loop {
                let c = self.byte()?;
                if first && c == 0x80 {
                    return Err("DER: non-minimal tag number".into());
                }
                first = false;
                if number > (u32::MAX >> 7) {
                    return Err("DER: tag number too large".into());
                }
                number = (number << 7) | (c & 0x7f) as u32;
                if c & 0x80 == 0 {
                    break;
                }
            }
            if number < 0x1f {
                return Err("DER: high tag form for a low tag number".into());
            }
        }
        Ok(Tag {
            class,
            constructed,
            number,
        })
    }

    fn read_len(&mut self) -> Result<usize> {
        let b = self.byte()?;
        if b < 0x80 {
            return Ok(b as usize);
        }
        let n = (b & 0x7f) as usize;
        if n == 0 {
            return Err("DER: indefinite length".into());
        }
        if n > 4 {
            return Err("DER: length too large".into());
        }
        let mut len = 0usize;
        for i in 0..n {
            let c = self.byte()?;
            if i == 0 && c == 0 {
                return Err("DER: non-minimal length".into());
            }
            len = (len << 8) | c as usize;
        }
        if len < 0x80 {
            return Err("DER: non-minimal length".into());
        }
        Ok(len)
    }

    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let tag = self.read_tag()?;
        let len = self.read_len()?;
        if len > self.data.len() {
            return Err("DER: length beyond end of data".into());
        }
        let (value, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(Tlv { tag, value })
    }

    /// One element and its whole encoding (tag, length and value), for a
    /// digest over the element as it appears.
    pub fn read_raw(&mut self) -> Result<(Tlv<'a>, &'a [u8])> {
        let before = self.data;
        let t = self.read()?;
        Ok((t, &before[..before.len() - self.data.len()]))
    }

    pub fn expect(&mut self, tag: Tag) -> Result<&'a [u8]> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(format!("DER: expected {tag:?}, found {:?}", t.tag));
        }
        Ok(t.value)
    }

    pub fn finish(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err("DER: trailing data".into())
        }
    }
}

/// Decodes a DER INTEGER value as i64.
pub fn int(v: &[u8]) -> Result<i64> {
    if v.is_empty() || v.len() > 8 {
        return Err("DER: integer size".into());
    }
    if v.len() > 1 && ((v[0] == 0 && v[1] & 0x80 == 0) || (v[0] == 0xff && v[1] & 0x80 != 0)) {
        return Err("DER: non-minimal integer".into());
    }
    let mut x: i64 = if v[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in v {
        x = (x << 8) | b as i64;
    }
    Ok(x)
}

pub fn boolean(v: &[u8]) -> Result<bool> {
    match v {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err("DER: invalid BOOLEAN".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_tag_number() {
        // [704] EXPLICIT, constructed, context: bf 85 40, length 3, INTEGER 5
        let data = [0xbf, 0x85, 0x40, 0x03, 0x02, 0x01, 0x05];
        let mut r = Reader::new(&data);
        let t = r.read().unwrap();
        assert_eq!(t.tag.class, Class::Context);
        assert!(t.tag.constructed);
        assert_eq!(t.tag.number, 704);
        let mut inner = Reader::new(t.value);
        assert_eq!(int(inner.expect(Tag::INTEGER).unwrap()).unwrap(), 5);
        r.finish().unwrap();
    }

    #[test]
    fn rejects_bad_encodings() {
        assert!(Reader::new(&[0x04, 0x80]).read().is_err()); // indefinite
        assert!(Reader::new(&[0x04, 0x81, 0x01, 0x00]).read().is_err()); // non-minimal len
        assert!(Reader::new(&[0x04, 0x05, 0x00]).read().is_err()); // short
        assert!(int(&[0x00, 0x01]).is_err());
        assert_eq!(int(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(int(&[0xff]).unwrap(), -1);
        assert!(boolean(&[0x01]).is_err());
    }
}
