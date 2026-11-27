// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Objects only. A struct derived with serde also reads a JSON array of its
//! fields in order (`[1, "off", ...]` for `{"profile_version": 1, ...}`).
//! The payload and the objects of section 12 must be JSON objects, so they
//! are read through [`MapOnly`], which refuses anything but an object and
//! keeps serde's checks for duplicate, unknown and missing fields.

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::marker::PhantomData;

/// `T`, read only from a JSON object.
pub struct MapOnly<T>(pub T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = T;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        d.deserialize_map(V(PhantomData)).map(MapOnly)
    }
}

/// For `deserialize_with` on an optional object field: present means an
/// object (`null` and any other type are refused, not read as absent).
pub fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    MapOnly::<T>::deserialize(d).map(|m| Some(m.0))
}

/// For `deserialize_with` on a list of objects.
pub fn objects<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Vec::<MapOnly<T>>::deserialize(d).map(|v| v.into_iter().map(|m| m.0).collect())
}

/// A whole JSON text that must be one object.
pub fn from_slice<'de, T: Deserialize<'de>>(b: &'de [u8]) -> serde_json::Result<T> {
    serde_json::from_slice::<MapOnly<T>>(b).map(|m| m.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct S {
        a: u32,
        #[serde(default, deserialize_with = "objects")]
        list: Vec<T>,
    }
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct T {
        x: bool,
    }

    #[test]
    fn only_objects() {
        let s: S = from_slice(br#"{"a":1,"list":[{"x":true}]}"#).unwrap();
        assert_eq!(s.list, vec![T { x: true }]);
        // What serde alone would accept.
        assert!(serde_json::from_slice::<S>(br#"[1,[]]"#).is_ok());
        for bad in [
            &br#"[1,[]]"#[..],
            br#"{"a":1,"list":[[true]]}"#,
            br#"{"a":1,"a":2}"#,
            br#"{"a":1,"b":2}"#,
            br#"{}"#,
            br#"null"#,
        ] {
            assert!(
                from_slice::<S>(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
