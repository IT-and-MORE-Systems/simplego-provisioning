// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! SimpleGo backups, format v1 (`backup-format.md`; section numbers refer
//! to it): one container for every product, encrypted with age to a public
//! key, so automatic backups need no secret on the device. This module
//! builds product `admin-store` (section 5.3).

pub mod admin;
pub mod agefile;
pub mod code;
pub mod container;
#[cfg(test)]
mod crosscheck;
pub mod dest;
pub mod engine;
pub mod keys;
pub mod state;
pub mod tar;
pub mod ui;
