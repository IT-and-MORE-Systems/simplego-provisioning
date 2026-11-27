// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Process exit codes. Stable: scripts depend on them. Documented in docs/USAGE.md.

/// Command succeeded. For `verify`: full PASS.
pub const OK: i32 = 0;
/// `verify`: at least one check failed (FAIL).
pub const FAIL: i32 = 1;
/// Wrong command line.
pub const USAGE: i32 = 2;
/// Config file missing or invalid.
pub const CONFIG: i32 = 3;
/// `verify`: no check failed, but at least one is UNVERIFIED (for example
/// "OS PASS, messenger UNVERIFIED").
pub const UNVERIFIED: i32 = 4;
/// `verify`: the device model is not in the GrapheneOS key list.
pub const UNKNOWN_DEVICE: i32 = 5;
/// `verify`: normal-phone tier, basic checks only. Never a hardened PASS.
pub const NORMAL_TIER: i32 = 6;
/// Trust material missing or invalid: the tool refuses to verify.
pub const TRUST_MISSING: i32 = 7;
/// Device or tool error: adb or fastboot missing, no device, agent failure.
pub const DEVICE: i32 = 8;
/// The revocation list is stale and the operator did not confirm.
pub const STALE_NOT_CONFIRMED: i32 = 9;
/// `trust refresh` or `trust import` failed (Tor unreachable, download,
/// file or signature failure).
pub const REFRESH_FAILED: i32 = 10;
/// `activation inspect`: the file is refused (format, untrusted key,
/// signature, code, payload) or its signature could not be checked.
pub const ACTIVATION_REFUSED: i32 = 11;
/// Admin store missing, wrong passphrase, damaged, path inside a git
/// repository, in use by another sxprov process (store lock), or a write
/// failed.
pub const STORE: i32 = 12;
/// Signing key unreadable, not Ed25519, not passphrase protected, wrong
/// passphrase, or the TEST ONLY key given to `issue` or `update`.
pub const SIGNING_KEY: i32 = 13;
/// `activation issue` or `update`: invalid servers or support file, network
/// mode rule broken, unknown customer, output file exists, no terminal.
/// `activation inspect`: unreadable file, or an update key file readable by
/// group or others or not 64 lowercase hex characters.
pub const ACTIVATION_INPUT: i32 = 14;
/// `deliver`: refused before anything was written to the phone (device not
/// found or not in state `device`, attestation without OS PASS, messenger
/// set up by a customer or installed without `--reinstall`, normal tier not
/// confirmed). The record says `failed at step 1` to `3`.
pub const DELIVERY_REFUSED: i32 = 15;
/// `deliver`: an APK file is refused (unreadable, signature block invalid,
/// wrong package, signer not the configured one, messenger signer not
/// pinned without `--accept-unverified-messenger`, Orbot signer not set).
pub const DELIVERY_APK: i32 = 16;
/// `deliver`: a write step on the phone failed (install, battery exception,
/// Orbot, activation, system calculator), or the delivery needs the file
/// import (a fixed feature profile or a directory entry) and the messenger
/// does not report it (after step 8 or in step 12, nothing issued). The
/// record says `failed at step N`.
pub const DELIVERY_FAILED: i32 = 17;
/// `deliver`: every write step ran but the final check failed (status, the
/// reported feature profile, battery exception, calculator, installed
/// signer through the package manager or `base.apk` differs from the file,
/// attestation after install).
pub const DELIVERY_CHECK: i32 = 18;
/// `undeliver`: refused (no `--test-device`, no record, `setup=done` or
/// state unreadable) or a step failed.
pub const UNDELIVER: i32 = 19;
/// `handover`: refused (no delivered record, not confirmed, state not
/// `activation=yes setup=open`) or the device still answers over adb.
pub const HANDOVER: i32 = 20;
/// `flash`: refused before anything changed on the phone (device not found
/// or not in state `device`, codename without a pinned key, a delivery
/// record without `--test-device`, a customer's messenger, not confirmed).
pub const FLASH_REFUSED: i32 = 21;
/// `os fetch` or `flash`: no channel file, download failed, signature
/// check failed (the file is deleted), or the image cannot be unpacked.
pub const OS_IMAGE: i32 = 22;
/// `flash`: OEM unlocking is off and could not be turned on.
pub const FLASH_OEM_UNLOCK: i32 = 23;
/// `flash`: a bootloader step: reboot into the bootloader, the phone not in
/// fastboot or another device in fastboot mode, unlock or lock not
/// confirmed in time, the phone not back over adb after the setup.
pub const FLASH_BOOTLOADER: i32 = 24;
/// `flash`: the official flash script failed.
pub const FLASH_SCRIPT: i32 = 25;
/// `flash`: the attestation after the flash failed (no OS PASS, another
/// verified boot key, another version, not locked).
pub const FLASH_CHECK: i32 = 26;
/// `os status`: an update is available.
pub const OS_OUTDATED: i32 = 27;
/// `os status`: the result is unknown (offline with nothing cached) or the
/// phone is not on GrapheneOS.
pub const OS_UNKNOWN: i32 = 28;
/// `backup`: a destination failed (write, read back, check, rotation),
/// nothing was written anywhere, backups are not set up, a drill or a
/// restore failed, a timer step failed.
pub const BACKUP: i32 = 29;
/// `backup`: wrong backup password or recovery code, the recovery code not
/// confirmed, a typed confirmation not given.
pub const BACKUP_SECRET: i32 = 30;
