// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Android binary XML (the compiled `AndroidManifest.xml`): the `<manifest>`
//! element's `package`, `versionCode`, `versionCodeMajor` and `versionName`
//! attributes, and the intent filters of activities that take web links
//! (`http`/`https` schemes, their hosts and `android:autoVerify`).
//!
//! App link verification: when an app with an
//! `autoVerify` web filter is installed, Android fetches
//! `https://HOST/.well-known/assetlinks.json` for each host. The delivery
//! reads these hosts from the APK before it installs anything.

use super::zip::{le16, le32};
use serde::Serialize;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const UTF8_FLAG: u32 = 0x100;

pub const ATTR_NAME: u32 = 0x0101_0003;
pub const ATTR_SCHEME: u32 = 0x0101_0027;
pub const ATTR_HOST: u32 = 0x0101_0028;
pub const ATTR_VERSION_CODE: u32 = 0x0101_021b;
pub const ATTR_VERSION_NAME: u32 = 0x0101_021c;
pub const ATTR_AUTO_VERIFY: u32 = 0x0101_04ee;
pub const ATTR_VERSION_CODE_MAJOR: u32 = 0x0101_0576;

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub package: String,
    pub version_code: u64,
    pub version_name: Option<String>,
}

fn strings(b: &[u8], at: usize) -> Result<Vec<String>, String> {
    let hs = le16(b, at + 2) as usize;
    let size = le32(b, at + 4) as usize;
    if hs < 28 || at + size > b.len() {
        return Err("damaged string pool".into());
    }
    let count = le32(b, at + 8) as usize;
    let flags = le32(b, at + 16);
    let start = le32(b, at + 20) as usize;
    if count > 1_000_000 || at + hs + count * 4 > at + size || at + start > at + size {
        return Err("damaged string pool".into());
    }
    let end = at + size;
    let mut out = Vec::with_capacity(count);
    for k in 0..count {
        let mut p = at + start + le32(b, at + hs + k * 4) as usize;
        let s = if flags & UTF8_FLAG != 0 {
            let len8 = |p: &mut usize| -> Result<usize, String> {
                let a = *b.get(*p).ok_or("damaged string")? as usize;
                *p += 1;
                if a & 0x80 != 0 {
                    let c = *b.get(*p).ok_or("damaged string")? as usize;
                    *p += 1;
                    Ok(((a & 0x7f) << 8) | c)
                } else {
                    Ok(a)
                }
            };
            let _chars = len8(&mut p)?;
            let n = len8(&mut p)?;
            if p + n > end {
                return Err("damaged string".into());
            }
            String::from_utf8_lossy(&b[p..p + n]).into_owned()
        } else {
            if p + 2 > end {
                return Err("damaged string".into());
            }
            let mut n = le16(b, p) as usize;
            p += 2;
            if n & 0x8000 != 0 {
                if p + 2 > end {
                    return Err("damaged string".into());
                }
                n = ((n & 0x7fff) << 16) | le16(b, p) as usize;
                p += 2;
            }
            if p + 2 * n > end {
                return Err("damaged string".into());
            }
            let units: Vec<u16> = (0..n).map(|i| le16(b, p + 2 * i)).collect();
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Ok(out)
}

/// Reads the `<manifest>` element.
pub fn manifest_info(b: &[u8]) -> Result<Manifest, String> {
    if b.len() < 8 || le16(b, 0) != RES_XML_TYPE {
        return Err("not a binary XML file".into());
    }
    let total = (le32(b, 4) as usize).min(b.len());
    let mut at = le16(b, 2) as usize;
    let mut pool: Option<Vec<String>> = None;
    let mut res_ids: Vec<u32> = Vec::new();
    while at + 8 <= total {
        let ty = le16(b, at);
        let hs = le16(b, at + 2) as usize;
        let size = le32(b, at + 4) as usize;
        if size < 8 || hs > size || at + size > total {
            return Err("damaged chunk".into());
        }
        match ty {
            RES_STRING_POOL_TYPE if pool.is_none() => pool = Some(strings(b, at)?),
            RES_XML_RESOURCE_MAP_TYPE => {
                res_ids = (0..(size - hs) / 4)
                    .map(|i| le32(b, at + hs + 4 * i))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool = pool.as_ref().ok_or("element before the string pool")?;
                let ext = at + hs;
                if ext + 20 > at + size {
                    return Err("damaged element".into());
                }
                let name = le32(b, ext + 4) as usize;
                if pool.get(name).map(String::as_str) != Some("manifest") {
                    return Err("the first element is not <manifest>".into());
                }
                let attr_start = le16(b, ext + 8) as usize;
                let attr_size = le16(b, ext + 10) as usize;
                let attr_count = le16(b, ext + 12) as usize;
                if attr_size < 20 || ext + attr_start + attr_count * attr_size > at + size {
                    return Err("damaged attributes".into());
                }
                let (mut package, mut code, mut major, mut vname) = (None, None, 0u64, None);
                for k in 0..attr_count {
                    let a = ext + attr_start + k * attr_size;
                    let name_idx = le32(b, a + 4) as usize;
                    let raw = le32(b, a + 8);
                    let dtype = b[a + 15];
                    let data = le32(b, a + 16);
                    let res = res_ids.get(name_idx).copied();
                    let aname = pool.get(name_idx).map(String::as_str).unwrap_or("");
                    let string_val = || -> Option<String> {
                        if raw != u32::MAX {
                            pool.get(raw as usize).cloned()
                        } else if dtype == TYPE_STRING {
                            pool.get(data as usize).cloned()
                        } else {
                            None
                        }
                    };
                    let int_val = || -> Option<u64> {
                        match dtype {
                            TYPE_INT_DEC | TYPE_INT_HEX => Some(data as u64),
                            _ => None,
                        }
                    };
                    // `package` has no namespace and no resource id.
                    if res.is_none() && aname == "package" {
                        package = string_val();
                    } else if res == Some(ATTR_VERSION_CODE) {
                        code = Some(int_val().ok_or("versionCode is not an integer")?);
                    } else if res == Some(ATTR_VERSION_CODE_MAJOR) {
                        major = int_val().ok_or("versionCodeMajor is not an integer")?;
                    } else if res == Some(ATTR_VERSION_NAME) {
                        vname = string_val();
                    }
                }
                let package = package.ok_or("<manifest> has no package attribute")?;
                let code = code.ok_or("<manifest> has no versionCode")?;
                return Ok(Manifest {
                    package,
                    version_code: (major << 32) | code,
                    version_name: vname,
                });
            }
            _ => {}
        }
        at += size;
    }
    Err("no <manifest> element".into())
}

/// An intent filter of an activity (or activity alias) that takes web
/// links, or one whose scheme, host or `autoVerify` is a resource reference
/// (not resolved here: that would need `resources.arsc`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkFilter {
    /// The activity's `android:name` ("?" if it is a reference).
    pub component: String,
    pub auto_verify: bool,
    pub schemes: Vec<String>,
    pub hosts: Vec<String>,
    /// The attributes given as references, e.g. `host=@0x7f1300a1`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
}

impl LinkFilter {
    pub fn is_web(&self) -> bool {
        self.schemes
            .iter()
            .any(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
    }
}

/// An attribute value as far as this reader needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    Str(String),
    Int(u32),
    Ref(u32),
    Other,
}

struct Attr {
    res: Option<u32>,
    val: Val,
}

enum Event {
    Start(String, Vec<Attr>),
    End(String),
}

/// Every start and end element of the document, in order.
fn events(b: &[u8]) -> Result<Vec<Event>, String> {
    if b.len() < 8 || le16(b, 0) != RES_XML_TYPE {
        return Err("not a binary XML file".into());
    }
    let total = (le32(b, 4) as usize).min(b.len());
    let mut at = le16(b, 2) as usize;
    let mut pool: Option<Vec<String>> = None;
    let mut res_ids: Vec<u32> = Vec::new();
    let mut out = Vec::new();
    while at + 8 <= total {
        let ty = le16(b, at);
        let hs = le16(b, at + 2) as usize;
        let size = le32(b, at + 4) as usize;
        if size < 8 || hs > size || at + size > total {
            return Err("damaged chunk".into());
        }
        match ty {
            RES_STRING_POOL_TYPE if pool.is_none() => pool = Some(strings(b, at)?),
            RES_XML_RESOURCE_MAP_TYPE => {
                res_ids = (0..(size - hs) / 4)
                    .map(|i| le32(b, at + hs + 4 * i))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE | RES_XML_END_ELEMENT_TYPE => {
                let pool = pool.as_ref().ok_or("element before the string pool")?;
                let ext = at + hs;
                let need = if ty == RES_XML_START_ELEMENT_TYPE {
                    20
                } else {
                    8
                };
                if ext + need > at + size {
                    return Err("damaged element".into());
                }
                let name = pool
                    .get(le32(b, ext + 4) as usize)
                    .cloned()
                    .ok_or("element name outside the string pool")?;
                if ty == RES_XML_END_ELEMENT_TYPE {
                    out.push(Event::End(name));
                } else {
                    let attr_start = le16(b, ext + 8) as usize;
                    let attr_size = le16(b, ext + 10) as usize;
                    let attr_count = le16(b, ext + 12) as usize;
                    if attr_size < 20 || ext + attr_start + attr_count * attr_size > at + size {
                        return Err("damaged attributes".into());
                    }
                    let mut attrs = Vec::with_capacity(attr_count);
                    for k in 0..attr_count {
                        let a = ext + attr_start + k * attr_size;
                        let name_idx = le32(b, a + 4) as usize;
                        let raw = le32(b, a + 8);
                        let dtype = b[a + 15];
                        let data = le32(b, a + 16);
                        let val = if raw != u32::MAX {
                            pool.get(raw as usize)
                                .cloned()
                                .map(Val::Str)
                                .unwrap_or(Val::Other)
                        } else {
                            match dtype {
                                TYPE_STRING => pool
                                    .get(data as usize)
                                    .cloned()
                                    .map(Val::Str)
                                    .unwrap_or(Val::Other),
                                TYPE_REFERENCE | TYPE_ATTRIBUTE => Val::Ref(data),
                                TYPE_INT_DEC | TYPE_INT_HEX | TYPE_INT_BOOLEAN => Val::Int(data),
                                _ => Val::Other,
                            }
                        };
                        attrs.push(Attr {
                            res: res_ids.get(name_idx).copied(),
                            val,
                        });
                    }
                    out.push(Event::Start(name, attrs));
                }
            }
            _ => {}
        }
        at += size;
    }
    Ok(out)
}

fn attr(attrs: &[Attr], res: u32) -> Option<&Val> {
    attrs.iter().find(|a| a.res == Some(res)).map(|a| &a.val)
}

/// The intent filters of activities and activity aliases that take web
/// links (scheme `http` or `https`), and every filter with a scheme, host
/// or `autoVerify` given as a reference. Filters with other schemes only
/// (`simplex:`, `market:`, ...) are left out: Android never verifies them.
pub fn link_filters(b: &[u8]) -> Result<Vec<LinkFilter>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut component: Option<String> = None;
    let mut cur: Option<LinkFilter> = None;
    for ev in events(b)? {
        match ev {
            Event::Start(name, attrs) => {
                let parent = stack.last().map(String::as_str);
                match (name.as_str(), parent) {
                    ("activity" | "activity-alias", Some("application")) => {
                        component = Some(match attr(&attrs, ATTR_NAME) {
                            Some(Val::Str(s)) => s.clone(),
                            _ => "?".into(),
                        });
                    }
                    ("intent-filter", Some("activity" | "activity-alias")) => {
                        let mut f = LinkFilter {
                            component: component.clone().unwrap_or_default(),
                            ..Default::default()
                        };
                        match attr(&attrs, ATTR_AUTO_VERIFY) {
                            Some(Val::Int(v)) => f.auto_verify = *v != 0,
                            Some(Val::Str(s)) => f.auto_verify = s == "true",
                            Some(Val::Ref(r)) => {
                                f.auto_verify = true;
                                f.unresolved.push(format!("autoVerify=@0x{r:08x}"));
                            }
                            _ => {}
                        }
                        cur = Some(f);
                    }
                    ("data", Some("intent-filter")) => {
                        if let Some(f) = cur.as_mut() {
                            for (res, what, list) in [
                                (ATTR_SCHEME, "scheme", &mut f.schemes),
                                (ATTR_HOST, "host", &mut f.hosts),
                            ] {
                                match attr(&attrs, res) {
                                    Some(Val::Str(s)) => list.push(s.clone()),
                                    Some(Val::Ref(r)) => {
                                        f.unresolved.push(format!("{what}=@0x{r:08x}"))
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
                stack.push(name);
            }
            Event::End(name) => {
                if stack.last() != Some(&name) {
                    return Err(format!("damaged element nesting at </{name}>"));
                }
                stack.pop();
                match name.as_str() {
                    "intent-filter" => {
                        if let Some(f) = cur.take() {
                            if f.is_web() || !f.unresolved.is_empty() {
                                out.push(f);
                            }
                        }
                    }
                    "activity" | "activity-alias" => component = None,
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

/// The hosts Android verifies at install (`autoVerify` web filters),
/// sorted, without duplicates.
pub fn auto_verify_hosts(filters: &[LinkFilter]) -> Vec<String> {
    let mut v: Vec<String> = filters
        .iter()
        .filter(|f| f.auto_verify && f.is_web())
        .flat_map(|f| f.hosts.iter().map(|h| h.to_ascii_lowercase()))
        .collect();
    v.sort();
    v.dedup();
    v
}
