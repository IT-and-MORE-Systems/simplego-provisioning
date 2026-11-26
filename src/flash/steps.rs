// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Steps 1 (target) to 10 of `flash`; see the parent module.

use super::*;

impl Run<'_, '_, '_, '_, '_> {
    fn channels(&self) -> Channels<'_> {
        Channels {
            base: &self.env.cfg.grapheneos_release_base,
            cache_dir: self.env.cache_dir.clone(),
            http: self.env.http,
            now: (self.env.now)(),
        }
    }

    /// The version to flash and its build type, and the phone's status now.
    pub(super) fn target(&mut self, codename: &str) -> Result<(String, String), Failure> {
        let now = (self.env.now)();
        let setting = self.env.cfg.release_setting();
        let rel = self.channels().release(codename, &self.channel);
        if let Some(inst) = &self.installed {
            let st = status::evaluate(inst, &rel, &self.channel, setting, now);
            for l in status::lines(&st, now) {
                self.say.info(l);
            }
            self.say.event(json!({"event": "os_status", "status": st}));
            self.rec.old_build_type = Some(st.build_type_label.to_string());
        }
        let label = |v: &str| {
            if rel.preview.info.as_ref().is_some_and(|c| c.version == v) {
                "security preview"
            } else if rel.stable.info.as_ref().is_some_and(|c| c.version == v) {
                "release"
            } else {
                "not in the current channel files"
            }
        };
        let (v, bt) = match &self.a.version {
            Some(v) => (v.clone(), label(v).to_string()),
            None => match rel.target(setting) {
                Some((c, preview)) => (
                    c.version.clone(),
                    if preview {
                        "security preview"
                    } else {
                        "release"
                    }
                    .to_string(),
                ),
                None => {
                    return fail(
                        1,
                        exit::OS_IMAGE,
                        format!(
                            "no channel file for {codename} {} ({}); give --version VERSION",
                            self.channel,
                            rel.stable.source(now)
                        ),
                    )
                }
            },
        };
        self.say.info(format!(
            "image to flash: GrapheneOS {v} for {codename}, build type {bt} (grapheneos_release = {}{})",
            setting.as_str(),
            if self.a.version.is_some() {
                ", --version given"
            } else {
                ""
            }
        ));
        self.say.event(json!({"event": "target", "codename": codename, "version": v,
                              "build_type": bt, "setting": setting.as_str(), "channel": self.channel}));
        Ok((v, bt))
    }

    pub(super) fn step2(&mut self, codename: &str, version: &str, bt: &str) -> Result<(), Failure> {
        self.start(2, "what will happen");
        self.say.info(format!(
            "This phone will be WIPED COMPLETELY, TWICE: when the bootloader is unlocked and again when it is \
             locked. Everything on it is lost. Then GrapheneOS {version} ({bt}) for {codename} is installed with \
             the official flash-all.sh of the signed factory image, the bootloader is locked again, and you set \
             the phone up."
        ));
        if self.a.dry_run {
            self.say
                .info("dry run: no confirmation asked, nothing will be changed");
            return Ok(());
        }
        if self.a.yes {
            self.say.info("confirmed with --yes (test device)");
            return Ok(());
        }
        let ok = self
            .env
            .ui
            .confirm(
                "WIPE",
                "Type WIPE to wipe this phone and install GrapheneOS: ",
            )
            .or_else(|e| {
                fail(
                    2,
                    exit::FLASH_REFUSED,
                    format!("flash needs a typed WIPE: {e}"),
                )
            })?;
        if !ok {
            return fail(2, exit::FLASH_REFUSED, "not confirmed; nothing was changed");
        }
        Ok(())
    }

    pub(super) fn step3(
        &mut self,
        codename: &str,
        version: &str,
    ) -> Result<image::Verified, Failure> {
        self.start(3, "factory image");
        let cache = ImageCache {
            root: self.env.cache_dir.clone(),
        };
        if let Some(v) = cache.verified(codename, version) {
            self.say.info(format!(
                "present and verified: {} (SHA-256 {}, verified {})",
                v.file, v.sha256, v.verified_at
            ));
            return Ok(v);
        }
        let Some(http) = self.env.http else {
            return fail(
                3,
                exit::OS_IMAGE,
                format!(
                    "{}.zip is not in the cache and the network is off (--offline or no Tor)",
                    top_folder(codename, version)
                ),
            );
        };
        let t0 = (self.env.now)();
        let mut lines = Vec::new();
        let r = image::fetch(
            &cache,
            http,
            &self.env.cfg.grapheneos_release_base,
            codename,
            version,
            self.env.signers,
            self.env.now,
            &mut |l| lines.push(l.to_string()),
        );
        for l in lines {
            self.say.info(l.trim());
        }
        self.time("download", t0);
        r.or_else(|e| fail(3, exit::OS_IMAGE, e))
    }

    pub(super) fn plan(&mut self, codename: &str, version: &str) {
        let s = mask_serial(&self.a.serial);
        let top = top_folder(codename, version);
        let standin = if self.env.standin {
            " (fastboot = the CRLF stand-in for fastboot.exe)"
        } else {
            ""
        };
        for l in [
            "DRY RUN: steps 1 to 3 ran; nothing below is done, nothing is stored.".to_string(),
            "step 4: OEM unlocking read in Developer options (am start, uiautomator dump, rm); turned on there if off".into(),
            format!("step 5: adb -s {s} reboot bootloader; wait for {s} in fastboot devices; refuse if another device is in fastboot mode; fastboot -s {s} getvar product"),
            format!("step 6: fastboot -s {s} getvar unlocked; if no: fastboot -s {s} flashing unlock, then: {MSG_UNLOCK}"),
            format!("step 7: signature checked again, {top}.zip unpacked, then in {top}/: ANDROID_SERIAL={s} bash flash-all.sh{standin}"),
            format!("step 8: fastboot -s {s} flashing lock, then: {MSG_LOCK}"),
            "step 9: you start the phone, set it up, turn on USB debugging and allow this computer".into(),
            "step 10: attestation as verify (OS PASS, the GrapheneOS key of this codename, the flashed version, locked); the flashes record".into(),
        ] {
            self.say.info(l);
        }
    }

    pub(super) fn step4(&mut self) -> Result<(), Failure> {
        self.start(4, "OEM unlocking");
        let sleep = self.env.sleep;
        let retries = self.env.ui_retries;
        let mut log = Vec::new();
        let outcome = {
            let p = self.phone();
            let mut d = devopts::DevOpts {
                phone: &p,
                sleep,
                retries,
                log: &mut log,
            };
            d.ensure_on()
        };
        for l in &log {
            self.say.info(l);
        }
        match outcome.or_else(|e| fail(4, exit::FLASH_OEM_UNLOCK, e))? {
            devopts::Outcome::AlreadyOn | devopts::Outcome::TurnedOn => Ok(()),
            devopts::Outcome::Manual(why) => {
                self.say.info(format!(
                    "OEM unlocking could not be turned on over adb: {why}"
                ));
                self.say.operator(devopts::MANUAL);
                let ok = self
                    .env
                    .ui
                    .confirm("DONE", "Type DONE when OEM unlocking is on: ")
                    .or_else(|e| {
                        fail(
                            4,
                            exit::FLASH_OEM_UNLOCK,
                            format!("OEM unlocking is off and there is no terminal to wait for you ({e}); turn it on and run flash again"),
                        )
                    })?;
                if !ok {
                    return fail(4, exit::FLASH_OEM_UNLOCK, "not confirmed");
                }
                let mut log = Vec::new();
                let st = {
                    let p = self.phone();
                    devopts::DevOpts {
                        phone: &p,
                        sleep,
                        retries,
                        log: &mut log,
                    }
                    .read_state()
                };
                match st.or_else(|e| fail(4, exit::FLASH_OEM_UNLOCK, e))? {
                    Some(devopts::Oem::On) => {
                        self.say.info("OEM unlocking: on");
                        Ok(())
                    }
                    _ => fail(
                        4,
                        exit::FLASH_OEM_UNLOCK,
                        "OEM unlocking is still not shown as on",
                    ),
                }
            }
        }
    }

    fn fastboot_list(&self) -> Result<Vec<String>, String> {
        device::fastboot_devices(&self.env.tools).map(|o| {
            device::parse::parse_fastboot_devices(&o)
                .into_iter()
                .map(|d| d.serial)
                .collect()
        })
    }

    pub(super) fn step5(&mut self, codename: &str) -> Result<(), Failure> {
        self.start(5, "reboot into the bootloader");
        let o = device::adb(&self.env.tools, &self.a.serial, &["reboot", "bootloader"])
            .or_else(|e| fail(5, exit::FLASH_BOOTLOADER, e))?;
        if !o.status.success() {
            return fail(
                5,
                exit::FLASH_BOOTLOADER,
                format!(
                    "adb reboot bootloader failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            );
        }
        let mut seen = None;
        for i in 0..self.env.polls.fastboot_appear {
            if i > 0 {
                (self.env.sleep)(self.env.polls.interval);
            }
            if let Ok(l) = self.fastboot_list() {
                if l.contains(&self.a.serial) {
                    seen = Some(l);
                    break;
                }
            }
        }
        let Some(list) = seen else {
            return fail(
                5,
                exit::FLASH_BOOTLOADER,
                "the phone did not show in fastboot devices",
            );
        };
        if list.len() > 1 {
            return fail(
                5,
                exit::FLASH_BOOTLOADER,
                format!(
                    "{} devices are in fastboot mode; only this phone may be. Nothing was flashed",
                    list.len()
                ),
            );
        }
        let product = device::fastboot_getvar(&self.env.tools, &self.a.serial, "product")
            .or_else(|e| fail(5, exit::FLASH_BOOTLOADER, e))?;
        if product.as_deref() != Some(codename) {
            return fail(
                5,
                exit::FLASH_BOOTLOADER,
                format!("fastboot reports product {product:?}, the image is for {codename}"),
            );
        }
        self.say.info(format!(
            "in the bootloader, product {codename}, the only device in fastboot mode"
        ));
        Ok(())
    }

    fn unlocked(&self) -> Result<Option<bool>, String> {
        if !self.fastboot_list()?.contains(&self.a.serial) {
            return Ok(None);
        }
        let v = device::fastboot_getvar(&self.env.tools, &self.a.serial, "unlocked")?;
        match v.as_deref() {
            Some("yes") => Ok(Some(true)),
            Some("no") => Ok(Some(false)),
            other => Err(format!("fastboot getvar unlocked answered {other:?}")),
        }
    }

    /// Polls until `unlocked` is `want` (the phone may reboot meanwhile),
    /// with a `waiting_for_user` report every `report_every` polls.
    fn wait_unlocked(&mut self, want: bool, polls: u32, action: &str, msg: &str) -> bool {
        let total = self.env.polls.confirm_secs;
        let every = self.env.polls.report_every.max(1);
        for i in 0..polls {
            if i > 0 {
                (self.env.sleep)(self.env.polls.interval);
            }
            if i % every == 0 {
                self.say.waiting(action, Polls::left(total, i, polls), msg);
            }
            if let Ok(Some(u)) = self.unlocked() {
                if u == want {
                    return true;
                }
            }
        }
        false
    }

    pub(super) fn step6(&mut self) -> Result<(), Failure> {
        self.start(6, "bootloader unlock");
        let u = self
            .unlocked()
            .or_else(|e| fail(6, exit::FLASH_BOOTLOADER, e))?;
        if u == Some(true) {
            self.say.info("the bootloader is already unlocked");
            return Ok(());
        }
        let total = Duration::from_secs(self.env.polls.confirm_secs);
        let o = device::fastboot(
            &self.env.tools,
            &self.a.serial,
            &["flashing", "unlock"],
            total.max(device::FASTBOOT_TIMEOUT),
        )
        .or_else(|e| fail(6, exit::FLASH_BOOTLOADER, e))?;
        if !o.status.success() {
            return fail(
                6,
                exit::FLASH_BOOTLOADER,
                format!(
                    "fastboot flashing unlock failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            );
        }
        self.say.operator(MSG_UNLOCK);
        let t0 = (self.env.now)();
        let ok = self.wait_unlocked(
            true,
            self.env.polls.unlock,
            "press_volume_down_unlock",
            MSG_UNLOCK,
        );
        self.time("unlock_wait", t0);
        if !ok {
            return fail(
                6,
                exit::FLASH_BOOTLOADER,
                format!(
                    "the unlock was not confirmed on the phone within {} s",
                    total.as_secs()
                ),
            );
        }
        self.unlocked_once = true;
        self.say
            .info("bootloader unlocked (the phone's data is wiped)");
        Ok(())
    }

    pub(super) fn step7(&mut self, codename: &str, version: &str) -> Result<(), Failure> {
        self.start(7, "official flash script");
        let cache = ImageCache {
            root: self.env.cache_dir.clone(),
        };
        let zip = cache.zip(codename, version);
        let sig = cache.sig(codename, version);
        let t0 = (self.env.now)();
        self.say
            .info("checking the signature of the image again before unpacking");
        let (sha, _) = image::verify_file(&zip, &sig, self.env.signers).or_else(|e| {
            fail(
                7,
                exit::OS_IMAGE,
                format!("the cached image no longer verifies: {e}"),
            )
        })?;
        if sha != self.rec.image_sha256 {
            return fail(
                7,
                exit::OS_IMAGE,
                "the cached image changed since it was verified",
            );
        }
        let tag = bytes::<6>(self.env.rng)
            .map(|b| hex(&b))
            .unwrap_or_default();
        let dest = cache.dir(version).join(format!("unpacked-{tag}"));
        let top = top_folder(codename, version);
        let dir = crate::grapheneos::zipx::extract(&zip, &dest, &top)
            .or_else(|e| fail(7, exit::OS_IMAGE, format!("unpacking failed: {e}")))?;
        self.unpacked = Some(dir.clone());
        self.time("unpack", t0);
        let tools_dir = self.env.work_dir.join(format!("tools-{tag}"));
        standin::prepare_tools(&tools_dir, &self.env.tools.fastboot, self.env.standin)
            .or_else(|e| fail(7, exit::FLASH_SCRIPT, e))?;
        let tmp = dest.join("tmp");
        if let Err(e) = std::fs::create_dir(&tmp) {
            return fail(7, exit::FLASH_SCRIPT, e.to_string());
        }
        if let Err(e) = std::fs::create_dir_all(&self.env.log_dir) {
            return fail(
                7,
                exit::FLASH_SCRIPT,
                format!("cannot create {}: {e}", self.env.log_dir.display()),
            );
        }
        let log = self.env.log_dir.join(format!(
            "flash-{}-{}.log",
            fmt_unix(t0).replace(':', ""),
            self.rec.flash_id
        ));
        self.say.info(format!(
            "running bash flash-all.sh in {} (log {})",
            dir.display(),
            log.display()
        ));
        self.say
            .info("Do not touch the phone while the script runs.");
        let t1 = (self.env.now)();
        let mut lines = Vec::new();
        let r = standin::run_script(
            &dir,
            &tools_dir,
            &self.a.serial,
            self.env.standin,
            &tmp,
            &log,
            &mut |l| lines.push(l.to_string()),
        );
        let _ = std::fs::remove_dir_all(&tools_dir);
        for l in &lines {
            if self.a.json {
                self.say.event(json!({"event": "script", "line": l}));
            } else {
                self.say.o.line(format!("    | {l}"));
            }
        }
        self.time("flash_script", t1);
        let r = r.or_else(|e| fail(7, exit::FLASH_SCRIPT, e))?;
        if r.exit_code != Some(0) {
            return fail(
                7,
                exit::FLASH_SCRIPT,
                format!(
                    "flash-all.sh failed (exit {:?}); log {}",
                    r.exit_code,
                    log.display()
                ),
            );
        }
        let u = self
            .unlocked()
            .or_else(|e| fail(7, exit::FLASH_SCRIPT, e))?;
        if u != Some(true) {
            return fail(
                7,
                exit::FLASH_SCRIPT,
                "after the script the phone is not in fastboot mode, unlocked",
            );
        }
        self.say
            .info(format!("flash-all.sh finished (exit 0, {} lines)", r.lines));
        let _ = std::fs::remove_dir_all(&dest);
        self.unpacked = None;
        Ok(())
    }

    pub(super) fn step8(&mut self) -> Result<(), Failure> {
        self.start(8, "bootloader lock");
        let total = Duration::from_secs(self.env.polls.confirm_secs);
        let o = device::fastboot(
            &self.env.tools,
            &self.a.serial,
            &["flashing", "lock"],
            total.max(device::FASTBOOT_TIMEOUT),
        )
        .or_else(|e| fail(8, exit::FLASH_BOOTLOADER, e))?;
        if !o.status.success() {
            return fail(
                8,
                exit::FLASH_BOOTLOADER,
                format!(
                    "fastboot flashing lock failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            );
        }
        self.say.operator(MSG_LOCK);
        let t0 = (self.env.now)();
        let ok = self.wait_unlocked(
            false,
            self.env.polls.lock,
            "press_volume_down_lock",
            MSG_LOCK,
        );
        self.time("lock_wait", t0);
        if !ok {
            return fail(
                8,
                exit::FLASH_BOOTLOADER,
                format!(
                    "the lock was not confirmed on the phone within {} s",
                    total.as_secs()
                ),
            );
        }
        self.say
            .info("bootloader locked (the phone's data is wiped again)");
        Ok(())
    }

    pub(super) fn step9(&mut self) -> Result<device::parse::Listed, Failure> {
        self.start(9, "start and set up the phone");
        self.say.operator(MSG_SETUP);
        let t0 = (self.env.now)();
        let mut last = String::new();
        let (polls, total) = (self.env.polls.setup, self.env.polls.setup_secs);
        let every = self.env.polls.report_every.max(1);
        for i in 0..polls {
            if i > 0 {
                (self.env.sleep)(self.env.polls.interval);
            }
            if i % every == 0 {
                self.say.waiting(
                    "complete_phone_setup",
                    Polls::left(total, i, polls),
                    MSG_SETUP,
                );
            }
            let Ok(out) = device::adb_devices(&self.env.tools) else {
                continue;
            };
            let l = device::parse::parse_adb_devices(&out);
            let me: Vec<_> = l.iter().filter(|d| d.serial == self.a.serial).collect();
            let state = match me.as_slice() {
                [d] => d.mode.as_str().to_string(),
                [] => "not connected over adb yet".into(),
                _ => "listed more than once".into(),
            };
            if state != last {
                self.say.info(format!("phone: {state}"));
                if state == "unauthorized" {
                    self.say
                        .info("allow this computer on the phone (USB debugging dialog)");
                }
                last = state;
            }
            if let [d] = me.as_slice() {
                if d.mode == Mode::Adb {
                    self.time("setup_wait", t0);
                    return Ok((*d).clone());
                }
            }
        }
        self.time("setup_wait", t0);
        fail(
            9,
            exit::FLASH_BOOTLOADER,
            "the phone did not come back over adb (USB debugging allowed) in time",
        )
    }

    pub(super) fn step10(
        &mut self,
        codename: &str,
        version: &str,
        target: device::parse::Listed,
    ) -> Result<(), Failure> {
        self.start(10, "attestation");
        let t0 = (self.env.now)();
        let challenge = (self.env.challenge)().or_else(|e| fail(10, exit::DEVICE, e))?;
        let trust = self.env.trust.expect("checked at the start");
        let at = verify_run::attest(
            &self.env.tools,
            &target,
            self.env.cfg,
            trust,
            challenge,
            (self.env.now)(),
            self.env.stale_confirmed,
            None,
        )
        .or_else(|(c, e)| fail(10, c, e))?;
        self.time("attestation", t0);
        for l in &at.log {
            self.say.info(format!("agent: {l}"));
        }
        for c in &at.report.checks {
            self.say.info(format!("[{}] {}", c.status.label(), c.title));
        }
        self.rec.attestation = Some(at.report.overall_label.clone());
        let rot = at
            .report
            .key_description
            .as_ref()
            .and_then(|k| k.hardware_enforced.root_of_trust.clone());
        let key = rot.as_ref().map(|r| hex(&r.verified_boot_key));
        self.rec.verified_boot_key = key.clone();
        if !at.os_pass() {
            return fail(
                10,
                exit::FLASH_CHECK,
                format!("attestation after the flash: {}", at.report.overall_label),
            );
        }
        let want = boot_key(&self.env.boot_keys, codename)
            .unwrap_or_default()
            .to_string();
        if key.as_deref() != Some(want.as_str()) {
            return fail(
                10,
                exit::FLASH_CHECK,
                format!(
                    "the verified boot key is {}, not the GrapheneOS key for {codename} ({want})",
                    key.unwrap_or_default()
                ),
            );
        }
        if !rot.as_ref().is_some_and(|r| r.device_locked) {
            return fail(
                10,
                exit::FLASH_CHECK,
                "the attestation says the bootloader is not locked",
            );
        }
        let got = at.info.os.version.clone().unwrap_or_default();
        if got != version {
            return fail(
                10,
                exit::FLASH_CHECK,
                format!("the phone reports GrapheneOS {got:?}, not the flashed {version}"),
            );
        }
        self.say.info(format!(
            "OS PASS; verified boot key {want} (GrapheneOS, {codename}); version {version} ({}); bootloader locked",
            self.rec.new_build_type
        ));
        let d = &self.rec.durations;
        let parts: Vec<String> = [
            "download",
            "unlock_wait",
            "unpack",
            "flash_script",
            "lock_wait",
            "setup_wait",
            "attestation",
        ]
        .iter()
        .filter_map(|k| d.get(*k).map(|s| format!("{k} {}m{:02}s", s / 60, s % 60)))
        .collect();
        let line = format!(
            "FLASHED: GrapheneOS {version} ({}) on {}; times: {}",
            self.rec.new_build_type,
            self.rec.serial_masked,
            parts.join(", ")
        );
        if self.a.json {
            self.say
                .event(json!({"event": "flashed", "version": version,
                                  "build_type": self.rec.new_build_type, "durations": d}));
        } else {
            self.say.o.line(format!("\n{line}"));
        }
        Ok(())
    }
}
