// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Random bytes. Issuing uses the system generator; the test vectors use a
//! seeded generator so that regenerating them gives identical bytes.

use zeroize::Zeroize;

pub trait Rand {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), String>;
}

/// The operating system's cryptographic random generator (through `ring`).
pub struct SystemRand(ring::rand::SystemRandom);

impl SystemRand {
    pub fn new() -> SystemRand {
        SystemRand(ring::rand::SystemRandom::new())
    }
}

impl Rand for SystemRand {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), String> {
        ring::rand::SecureRandom::fill(&self.0, out).map_err(|_| "no system randomness".into())
    }
}

/// Deterministic generator for tests and test vectors only:
/// block i = SHA-256(seed || i as u64 big-endian). Never used for issuing.
#[cfg(test)]
pub struct SeededRand {
    seed: Vec<u8>,
    counter: u64,
    buf: Vec<u8>,
}

#[cfg(test)]
impl SeededRand {
    pub fn new(seed: &[u8]) -> SeededRand {
        SeededRand {
            seed: seed.to_vec(),
            counter: 0,
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
impl Rand for SeededRand {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), String> {
        for b in out.iter_mut() {
            if self.buf.is_empty() {
                let mut input = self.seed.clone();
                input.extend_from_slice(&self.counter.to_be_bytes());
                self.counter += 1;
                let mut block = crate::util::sha256(&input);
                block.reverse();
                self.buf = block;
            }
            *b = self.buf.pop().unwrap_or(0);
        }
        Ok(())
    }
}

/// A uniform number in `lo..=hi`, by rejection sampling (no modulo bias).
pub fn uniform_u32(r: &mut dyn Rand, lo: u32, hi: u32) -> Result<u32, String> {
    let range = u64::from(hi - lo) + 1;
    let zone = (1u64 << 32) / range * range;
    loop {
        let mut b = [0u8; 4];
        r.fill(&mut b)?;
        let x = u64::from(u32::from_be_bytes(b));
        b.zeroize();
        if x < zone {
            return Ok(lo + (x % range) as u32);
        }
    }
}

pub fn bytes<const N: usize>(r: &mut dyn Rand) -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    r.fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_is_deterministic_and_uniform_stays_in_range() {
        let mut a = SeededRand::new(b"seed");
        let mut b = SeededRand::new(b"seed");
        let x: [u8; 50] = bytes(&mut a).unwrap();
        let y: [u8; 50] = bytes(&mut b).unwrap();
        assert_eq!(x, y);
        let mut c = SeededRand::new(b"other");
        let z: [u8; 50] = bytes(&mut c).unwrap();
        assert_ne!(x, z);
        for _ in 0..2000 {
            let v = uniform_u32(&mut a, 100_000, 999_999).unwrap();
            assert!((100_000..=999_999).contains(&v));
        }
        for _ in 0..200 {
            assert!(uniform_u32(&mut a, 0, 3).unwrap() <= 3);
        }
    }
}
