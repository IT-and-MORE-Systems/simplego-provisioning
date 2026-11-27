// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Recovery seed and recovery code (backup format section 3.1).
//!
//! Seed: 18 random bytes. Checksum: the first 2 bytes of SHA-256 over
//! `SimpleGo recovery code v1` and the seed. Code: seed and checksum (160
//! bits) in Crockford base32, most significant bit first, 32 characters,
//! shown as 8 groups of 4. Input: any case, spaces and hyphens ignored, `O`
//! read as `0`, `I` and `L` as `1`; then exactly 32 characters of the
//! alphabet, else refused; then the checksum must match.

use crate::activation::rng::{bytes, Rand};
use zeroize::Zeroizing;

pub const SEED_LEN: usize = 18;
pub type Seed = Zeroizing<[u8; SEED_LEN]>;
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECKSUM_LABEL: &[u8] = b"SimpleGo recovery code v1";

#[derive(Debug, PartialEq, Eq)]
pub enum CodeError {
    Length,
    Alphabet(char),
    Checksum,
}

impl std::fmt::Display for CodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeError::Length => f.write_str("a recovery code has 32 characters (8 groups of 4)"),
            CodeError::Alphabet(c) => write!(f, "{c:?} is not in a recovery code"),
            CodeError::Checksum => f.write_str("This code has a typo"),
        }
    }
}

/// A new seed from the system generator.
pub fn new_seed(rng: &mut dyn Rand) -> Result<Seed, String> {
    Ok(Zeroizing::new(bytes::<SEED_LEN>(rng)?))
}

pub fn checksum(seed: &[u8; SEED_LEN]) -> [u8; 2] {
    let mut input = Zeroizing::new(CHECKSUM_LABEL.to_vec());
    input.extend_from_slice(seed);
    let h = Zeroizing::new(crate::util::sha256(&input));
    [h[0], h[1]]
}

/// The 32 characters, without spaces.
pub fn encode(seed: &[u8; SEED_LEN]) -> Zeroizing<String> {
    let mut all = Zeroizing::new([0u8; 20]);
    all[..SEED_LEN].copy_from_slice(seed);
    all[SEED_LEN..].copy_from_slice(&checksum(seed));
    let mut out = Zeroizing::new(String::with_capacity(32));
    for i in 0..32 {
        // Bits 5i .. 5i+5 of the 160, most significant first.
        let mut v = 0u8;
        for b in 0..5 {
            let bit = 5 * i + b;
            v = v << 1 | (all[bit / 8] >> (7 - bit % 8)) & 1;
        }
        out.push(ALPHABET[v as usize] as char);
    }
    out
}

/// `000G 40R4 0M30 ...`: 8 groups of 4.
pub fn grouped(code: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(39));
    for (i, c) in code.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Group `n` (1 to 8) of a code.
pub fn group(code: &str, n: usize) -> Option<Zeroizing<String>> {
    if !(1..=8).contains(&n) || code.len() != 32 {
        return None;
    }
    Some(Zeroizing::new(code[(n - 1) * 4..n * 4].to_string()))
}

/// Normalises typed input: upper case, without spaces and hyphens, `O` as
/// `0`, `I` and `L` as `1`.
pub fn normalise(input: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(32));
    for c in input.chars() {
        match c.to_ascii_uppercase() {
            ' ' | '-' => {}
            'O' => out.push('0'),
            'I' | 'L' => out.push('1'),
            u => out.push(u),
        }
    }
    out
}

pub fn parse(input: &str) -> Result<Seed, CodeError> {
    let s = normalise(input);
    if s.chars().count() != 32 {
        return Err(CodeError::Length);
    }
    let mut all = Zeroizing::new([0u8; 20]);
    for (i, c) in s.chars().enumerate() {
        let v = ALPHABET
            .iter()
            .position(|a| *a as char == c)
            .ok_or(CodeError::Alphabet(c))? as u8;
        for b in 0..5 {
            let bit = 5 * i + b;
            if v >> (4 - b) & 1 == 1 {
                all[bit / 8] |= 1 << (7 - bit % 8);
            }
        }
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&all[..SEED_LEN]);
    if checksum(&seed) != all[SEED_LEN..] {
        return Err(CodeError::Checksum);
    }
    Ok(seed)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const V1_SEED: [u8; 18] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
    pub const V1_CODE: &str = "000G 40R4 0M30 E209 185G R38E 1W81 3K8K";

    /// Vector V1, the code half.
    #[test]
    fn vector_v1_code() {
        assert_eq!(crate::util::hex(&checksum(&V1_SEED)), "cd13");
        assert_eq!(grouped(&encode(&V1_SEED)).as_str(), V1_CODE);
        assert_eq!(group(&encode(&V1_SEED), 8).unwrap().as_str(), "3K8K");
    }

    /// Vector V2, every line.
    #[test]
    fn vector_v2_parsing() {
        for ok in [
            "000G 40R4 0M30 E209 185G R38E 1W81 3K8K",
            "000g-40r4-0m30-e209-185g-r38e-1w81-3k8k",
            "000G40R40M30E209185GR38E1W813K8K",
            "O00G 40R4 0M30 E209 185G R38E 1W81 3K8K",
        ] {
            assert_eq!(*parse(ok).unwrap(), V1_SEED, "{ok}");
        }
        assert_eq!(
            parse("000G 40R4 0M30 E209 185G R38E 1W81 3K80").err(),
            Some(CodeError::Checksum)
        );
        assert_eq!(CodeError::Checksum.to_string(), "This code has a typo");
        assert_eq!(
            parse("000G 40R4 0M30 E209 185G R38E 1W81").err(),
            Some(CodeError::Length)
        );
        assert_eq!(
            parse("000G U0R4 0M30 E209 185G R38E 1W81 3K8K").err(),
            Some(CodeError::Alphabet('U'))
        );
    }

    #[test]
    fn random_seeds_round_trip() {
        let mut r = crate::activation::rng::SeededRand::new(b"codes");
        for _ in 0..200 {
            let s = new_seed(&mut r).unwrap();
            let c = encode(&s);
            assert_eq!(*parse(&c).unwrap(), *s);
            assert_eq!(*parse(&c.to_lowercase()).unwrap(), *s);
        }
    }
}
