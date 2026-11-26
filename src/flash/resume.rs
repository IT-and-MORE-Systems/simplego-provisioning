// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! `flash --resume`: continues a flash from a phone that is already in
//! fastboot mode, for example after an
//! unlock that was confirmed on the phone after `flash` had given up.
//!
//! Checked before anything is written: exactly one device in fastboot mode
//! and it is the given serial; its `product` has a pinned GrapheneOS key and
//! equals the image's codename; no delivery record (unless `--test-device`);
//! the typed `WIPE` (or `--yes` with `--test-device`); the image present in
//! the cache and verified. Then `unlocked` decides where it continues:
//!
//! - unlocked: step 7 (the official script), 8, 9, 10
//! - locked, and the newest `flashes` record of this phone and version
//!   failed at step 8 or 9 (the lock was confirmed late, or the setup wait
//!   ran out): step 9, 10
//! - locked otherwise: step 6 (unlock), 7, 8, 9, 10
//!
//! The run writes a normal `flashes` record with `resumed_at_step`.

use super::*;
use crate::grapheneos::image::ImageCache;

impl Run<'_, '_, '_, '_, '_> {
    pub(super) fn go_resume(&mut self) -> Result<(), Failure> {
        let codename = self.resume_step1()?;
        let (version, build_type) = self.target(&codename)?;
        self.rec.new_version = version.clone();
        self.rec.new_build_type = build_type.clone();
        self.step2(&codename, &version, &build_type)?;
        let v = self.resume_image(&codename, &version)?;
        self.rec.image_sha256 = v.sha256.clone();
        let at = self.resume_point(&version)?;
        self.rec.resumed_at_step = Some(at);
        self.say.event(json!({"event": "resume", "step": at}));
        if at <= 6 {
            self.step6()?;
        }
        if at <= 7 {
            self.step7(&codename, &version)?;
            self.step8()?;
        }
        let target = self.step9()?;
        self.step10(&codename, &version, target)
    }

    fn resume_step1(&mut self) -> Result<String, Failure> {
        self.start(1, "device in fastboot mode (resume)");
        let list = device::fastboot_devices(&self.env.tools)
            .map(|o| device::parse::parse_fastboot_devices(&o))
            .or_else(|e| fail(1, exit::FLASH_REFUSED, e))?;
        let serials: Vec<&str> = list.iter().map(|d| d.serial.as_str()).collect();
        if serials != [self.a.serial.as_str()] {
            let n = serials.len();
            let mine = serials.contains(&self.a.serial.as_str());
            return fail(
                1,
                exit::FLASH_REFUSED,
                format!(
                    "--resume needs exactly one device in fastboot mode and it must be {}: {n} listed{}",
                    mask_serial(&self.a.serial),
                    if mine { "" } else { ", none of them with this serial" }
                ),
            );
        }
        let product = device::fastboot_getvar(&self.env.tools, &self.a.serial, "product")
            .or_else(|e| fail(1, exit::FLASH_REFUSED, e))?;
        let Some(codename) = product.filter(|p| crate::grapheneos::valid_codename(p)) else {
            return fail(
                1,
                exit::FLASH_REFUSED,
                "fastboot reports no valid product for this phone",
            );
        };
        self.rec.codename = codename.clone();
        self.say.info(format!(
            "{} in fastboot mode, product {codename}, the only device in fastboot mode",
            mask_serial(&self.a.serial)
        ));
        if boot_key(&self.env.boot_keys, &codename).is_none() {
            return fail(
                1,
                exit::FLASH_REFUSED,
                format!(
                    "no pinned GrapheneOS verified boot key for {codename}; flashing it is refused"
                ),
            );
        }
        let records = self
            .store
            .data
            .deliveries
            .iter()
            .filter(|d| d.serial == self.a.serial)
            .count();
        if records > 0 {
            if !self.a.test_device {
                return fail(
                    1,
                    exit::FLASH_REFUSED,
                    format!("this phone has {records} delivery record(s) in the admin store; flashing would wipe a delivered phone. Refused (a test phone needs --test-device)"),
                );
            }
            self.say.info(format!(
                "{records} delivery record(s) for this phone: flashed anyway (--test-device); the delivery is lost"
            ));
        }
        self.say.info(
            "in fastboot mode the messenger's state cannot be read; the phone was checked when the flash began",
        );
        Ok(codename)
    }

    /// The image must already be in the cache and verified; `--resume`
    /// downloads nothing.
    fn resume_image(&mut self, codename: &str, version: &str) -> Result<image::Verified, Failure> {
        self.start(3, "factory image");
        let cache = ImageCache {
            root: self.env.cache_dir.clone(),
        };
        match cache.verified(codename, version) {
            Some(v) => {
                self.say.info(format!(
                    "present and verified: {} (SHA-256 {}, verified {})",
                    v.file, v.sha256, v.verified_at
                ));
                Ok(v)
            }
            None => fail(
                3,
                exit::OS_IMAGE,
                format!(
                    "{}.zip is not verified in the cache; --resume downloads nothing. Run sxprov os fetch --device {codename} --version {version} first",
                    top_folder(codename, version)
                ),
            ),
        }
    }

    fn unlocked_now(&self) -> Result<bool, String> {
        let v = device::fastboot_getvar(&self.env.tools, &self.a.serial, "unlocked")?;
        match v.as_deref() {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            other => Err(format!("fastboot getvar unlocked answered {other:?}")),
        }
    }

    /// Where the run continues, from `unlocked` and the newest record.
    fn resume_point(&mut self, version: &str) -> Result<u8, Failure> {
        let u = self
            .unlocked_now()
            .or_else(|e| fail(5, exit::FLASH_BOOTLOADER, e))?;
        if u {
            self.unlocked_once = true;
            self.say.info(
                "the bootloader is unlocked (the phone's data is wiped): continuing at step 7, the official script",
            );
            return Ok(7);
        }
        let last = self
            .store
            .data
            .flashes
            .iter()
            .rev()
            .find(|f| f.serial == self.a.serial);
        let lock_done = last.is_some_and(|f| {
            f.new_version == version
                && (f.result == "failed at step 8" || f.result == "failed at step 9")
        });
        if lock_done {
            self.say.info(format!(
                "the bootloader is locked and the last flash of this phone ({}) {}: continuing at step 9, the setup",
                version,
                last.map(|f| f.result.as_str()).unwrap_or_default()
            ));
            return Ok(9);
        }
        self.say.info(
            "the bootloader is locked: continuing at step 6, the unlock (it wipes the phone)",
        );
        Ok(6)
    }
}
