// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Activation code (format document section 3): two numbers 100000 to 999999
//! and one operator out of `+ - × ÷`.
//!
//! Canonical form (key derivation input): 13 ASCII bytes, first number,
//! ASCII operator (`+ - x :`), second number. The code is never stored or
//! logged; the bytes are wiped when the value is dropped.

use super::rng::{uniform_u32, Rand};
use zeroize::{Zeroize, Zeroizing};

pub const CODE_LEN: usize = 13;

/// The fixed lab code of every delivery to a test phone (`deliver
/// --test-delivery`, TEST ONLY key, throwaway test config), published and
/// TEST ONLY. Customer phones always get a random code.
pub const LAB_CODE: &str = "727272+727272";
const OPERATORS: [u8; 4] = *b"+-x:";

pub struct Code([u8; CODE_LEN]);

impl Drop for Code {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Code {
    /// Two numbers uniform in 100000..=999999 and one operator uniform out of
    /// four, from the given generator (the system generator when issuing).
    pub fn generate(r: &mut dyn Rand) -> Result<Code, String> {
        let a = Zeroizing::new(uniform_u32(r, 100_000, 999_999)?);
        let op = OPERATORS[uniform_u32(r, 0, 3)? as usize];
        let b = Zeroizing::new(uniform_u32(r, 100_000, 999_999)?);
        let mut out = [0u8; CODE_LEN];
        write_digits(&mut out[0..6], *a);
        out[6] = op;
        write_digits(&mut out[7..13], *b);
        Ok(Code(out))
    }

    /// The fixed lab code (`LAB_CODE`), for test phones only.
    pub fn lab() -> Code {
        let mut out = [0u8; CODE_LEN];
        out.copy_from_slice(LAB_CODE.as_bytes());
        Code(out)
    }

    /// The 13 canonical ASCII bytes, the Argon2id password.
    pub fn canonical(&self) -> &[u8] {
        &self.0
    }

    /// Form on the activation card, for example `482913 × 105377`.
    pub fn display(&self) -> Zeroizing<String> {
        let op = match self.0[6] {
            b'x' => "×",
            b':' => "÷",
            b'+' => "+",
            _ => "-",
        };
        let s = std::str::from_utf8(&self.0).unwrap_or("");
        Zeroizing::new(format!("{} {op} {}", &s[0..6], &s[7..13]))
    }

    /// Masked form for the fleet log: first digit, `*****`, ASCII operator,
    /// `*****`, last digit.
    pub fn masked(&self) -> String {
        format!(
            "{}*****{}*****{}",
            self.0[0] as char, self.0[6] as char, self.0[12] as char
        )
    }

    /// Maps typed input (section 3) and checks it. Anything that is not
    /// exactly 13 valid bytes afterwards is refused without trying it.
    pub fn parse_input(input: &str) -> Result<Code, String> {
        let mut mapped = Zeroizing::new(String::with_capacity(input.len()));
        for c in input.chars() {
            match c {
                '×' | 'X' | '*' => mapped.push('x'),
                '÷' | '/' => mapped.push(':'),
                '\u{2212}' => mapped.push('-'),
                ' ' => {}
                other => mapped.push(other),
            }
        }
        if mapped.ends_with('=') {
            mapped.pop();
        }
        let b = mapped.as_bytes();
        if b.len() != CODE_LEN {
            return Err(format!(
                "the code must be two six-digit numbers and one operator ({} characters after mapping, need {CODE_LEN})",
                mapped.chars().count()
            ));
        }
        let number_ok =
            |n: &[u8]| matches!(n[0], b'1'..=b'9') && n[1..].iter().all(u8::is_ascii_digit);
        if !number_ok(&b[0..6]) || !OPERATORS.contains(&b[6]) || !number_ok(&b[7..13]) {
            return Err(
                "the code has an invalid character (numbers 100000 to 999999, operator + - x :)"
                    .into(),
            );
        }
        let mut out = [0u8; CODE_LEN];
        out.copy_from_slice(b);
        Ok(Code(out))
    }
}

fn write_digits(out: &mut [u8], mut v: u32) {
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (v % 10) as u8;
        v /= 10;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::rng::SeededRand;

    fn canon(s: &str) -> Result<String, String> {
        Code::parse_input(s).map(|c| String::from_utf8(c.canonical().to_vec()).unwrap())
    }

    #[test]
    fn lab_code_is_a_valid_code() {
        let c = Code::lab();
        assert_eq!(c.canonical(), b"727272+727272");
        assert_eq!(&*c.display(), "727272 + 727272");
        assert_eq!(c.masked(), "7*****+*****2");
        assert_eq!(
            Code::parse_input("727272 + 727272").unwrap().canonical(),
            c.canonical()
        );
    }

    #[test]
    fn generated_codes_are_well_formed_and_round_trip() {
        let mut r = SeededRand::new(b"codes");
        let mut ops = [0usize; 4];
        for _ in 0..400 {
            let c = Code::generate(&mut r).unwrap();
            let s = std::str::from_utf8(c.canonical()).unwrap().to_string();
            assert_eq!(canon(&s).unwrap(), s);
            assert_eq!(canon(&c.display()).unwrap(), s);
            ops[OPERATORS
                .iter()
                .position(|o| *o == c.canonical()[6])
                .unwrap()] += 1;
            let m = c.masked();
            assert_eq!(m.len(), 13);
            assert_eq!(&m[1..6], "*****");
            assert_eq!(&m[7..12], "*****");
        }
        assert!(ops.iter().all(|n| *n > 50), "{ops:?}");
    }

    #[test]
    fn input_mapping() {
        let want = "482913x105377";
        for s in [
            "482913x105377",
            "482913 × 105377",
            "482913 X 105377",
            "482913*105377",
            "482913 x 105377 =",
            "482913x105377=",
            " 482913  x  105377 = ",
        ] {
            assert_eq!(canon(s).unwrap(), want, "{s:?}");
        }
        assert_eq!(canon("482913 ÷ 105377").unwrap(), "482913:105377");
        assert_eq!(canon("482913/105377").unwrap(), "482913:105377");
        assert_eq!(canon("482913 \u{2212} 105377").unwrap(), "482913-105377");
        assert_eq!(canon("482913 + 105377").unwrap(), "482913+105377");
        assert_eq!(
            Code::parse_input("482913 x 105377")
                .unwrap()
                .display()
                .as_str(),
            "482913 × 105377"
        );
    }

    #[test]
    fn bad_codes_refused() {
        for s in [
            "",
            "482913x10537",
            "482913x1053777",
            "082913x105377",
            "482913x005377",
            "48291ax105377",
            "482913%105377",
            "482913x105377==",
            "482913=x105377",
            "482913\tx105377",
            "482913\u{00a0}x105377",
            "４82913x105377",
            "482913.105377",
        ] {
            assert!(Code::parse_input(s).is_err(), "{s:?}");
        }
    }
}
