// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Shared operator texts. The later install flow reuses `NORMAL_TIER_WARNING`
//! before installing on a normal phone (start protocol section 3).

/// Result label for the normal-phone tier. Deliberately not "PASS".
pub const NORMAL_TIER_LABEL: &str = "NORMAL-TIER: basic checks only";

/// Plain statement of what the normal-phone tier does not give.
pub const NORMAL_TIER_WARNING: &str = "\
WARNING: normal-phone tier. This phone is not a hardened SimpleGo device.
- There is no hardened operating system.
- There is no bootloader lock under our control.
- There is no hardware attestation of our software stack.
- Google services are present on the phone.
Only basic checks were run (model, Android version, messenger present and its
signature). This result is not equivalent to a hardened-tier PASS.";

/// Shown when a PASS rests on a stale revocation list.
pub const STALE_REVOCATION_NOTE: &str = "\
based on a STALE revocation list (operator confirmed)";
