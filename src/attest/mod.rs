// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Android key attestation: chain validation and KeyDescription parsing.

pub mod chain;
pub mod der;
pub mod keydesc;

#[cfg(test)]
pub mod tests;
