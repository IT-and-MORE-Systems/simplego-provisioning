// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Config file (`config/provisioning.toml`, git-ignored). Template:
//! `config/provisioning.example.toml`.

use crate::names;
use crate::util::is_sha256_hex;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const ENV_CONFIG: &str = "SXPROV_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "config/provisioning.toml";
/// Limits of `flash_confirm_timeout_secs` (one minute to one day).
pub const CONFIRM_TIMEOUT_MIN: u64 = 60;
pub const CONFIRM_TIMEOUT_MAX: u64 = 86_400;
/// Limits of `download_idle_timeout_secs` (ten seconds to one hour).
pub const DOWNLOAD_IDLE_MIN: u64 = 10;
pub const DOWNLOAD_IDLE_MAX: u64 = 3_600;
/// Limits of `fdroid_repo_wait_secs` (one minute to one hour).
pub const FDROID_REPO_WAIT_MIN: u64 = 60;
pub const FDROID_REPO_WAIT_MAX: u64 = 3_600;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// SHA-256 (hex) of the agent signing certificate, pinned through
    /// `attestationApplicationId`.
    #[serde(default)]
    pub agent_signing_cert_sha256: String,
    #[serde(default = "default_agent_package")]
    pub agent_package: String,
    /// Path to the signed agent APK on the admin machine.
    #[serde(default)]
    pub agent_apk: String,
    /// A fixed messenger package for every delivery. Empty (the default):
    /// `deliver` takes the package from the messenger APK, the record keeps
    /// it, and the read-only commands take it from `--messenger-package`.
    #[serde(default)]
    pub messenger_package: String,
    /// Optional pattern every delivered messenger package must match: `*`
    /// stands for any run of package name characters, everything else is
    /// literal (for example `app.*`). Empty: any valid package name.
    #[serde(default)]
    pub messenger_package_pattern: String,
    /// Authority of the messenger's activation provider; `{package}` is
    /// replaced by the messenger package.
    #[serde(default = "default_provider_authority")]
    pub messenger_provider_authority: String,
    /// SHA-256 (hex) of the messenger signing certificate. Empty until the
    /// messenger release signing identity exists.
    #[serde(default)]
    pub messenger_signing_cert_sha256: String,
    #[serde(default = "default_tor_proxy")]
    pub tor_socks_proxy: String,
    pub trust_cache_dir: PathBuf,
    #[serde(default = "default_revocation_days")]
    pub revocation_max_age_days: u64,
    #[serde(default = "default_gos_days")]
    pub grapheneos_keys_warn_age_days: u64,
    /// adb binary. On WSL2 this may be the Windows `adb.exe` (APK paths are
    /// then converted with `wslpath -w`).
    #[serde(default = "default_adb")]
    pub adb_path: String,
    /// fastboot binary. Empty disables fastboot: no fastboot command is run.
    #[serde(default = "default_fastboot")]
    pub fastboot_path: String,
    /// Encrypted admin store (update keys, fleet log). Default
    /// `~/.local/share/sxprov/admin-store.sxdb`; never inside a repository.
    #[serde(default)]
    pub admin_store_path: Option<PathBuf>,
    /// System calculator hidden at delivery (`pm disable-user`). On phones
    /// with another calculator package, that name.
    #[serde(default = "default_calculator")]
    pub system_calculator_package: String,
    #[serde(default = "default_orbot_package")]
    pub orbot_package: String,
    /// SHA-256 (hex) of the Orbot signing certificate. Empty: `deliver
    /// --orbot-apk` is refused.
    #[serde(default)]
    pub orbot_signing_cert_sha256: String,
    /// Lets `deliver --test-delivery` sign with the TEST ONLY key. Only in a
    /// throwaway test config, never in the config of real deliveries.
    #[serde(default)]
    pub allow_test_key_for_test_deliveries: bool,
    /// Where GrapheneOS channel files and factory images come from (over
    /// Tor only). HTTPS, no trailing slash.
    #[serde(default = "default_release_base")]
    pub grapheneos_release_base: String,
    /// GrapheneOS release channel: `stable`, `beta` or `alpha`.
    #[serde(default = "default_channel")]
    pub grapheneos_channel: String,
    /// Which build counts as current: `newest` (the security preview build
    /// when the channel has one, otherwise the release) or `stable` (the
    /// release only).
    #[serde(default = "default_release")]
    pub grapheneos_release: String,
    /// Channel files and verified factory images. Default
    /// `~/.cache/simplego-provisioning/grapheneos`. On WSL with the Windows
    /// `fastboot.exe` it must be on a Windows drive (`/mnt/c/...`).
    #[serde(default)]
    pub grapheneos_cache_dir: Option<PathBuf>,
    /// `deliver` refuses a phone more than this many days behind the stable
    /// channel (unless `--allow-outdated-os`).
    #[serde(default = "default_max_os_age")]
    pub max_os_age_days: u64,
    /// Logs of the flash script (serials masked). Default: `logs` in the
    /// GrapheneOS cache folder.
    #[serde(default)]
    pub flash_log_dir: Option<PathBuf>,
    /// How long `flash` waits for the unlock and the lock to be confirmed on
    /// the phone, in seconds.
    #[serde(default = "default_confirm_timeout")]
    pub flash_confirm_timeout_secs: u64,
    /// The F-Droid client installed at delivery,
    /// and its signing certificate SHA-256. Empty: `--fdroid-apk` is
    /// refused.
    #[serde(default = "default_fdroid_package")]
    pub fdroid_package: String,
    #[serde(default = "default_fdroid_signer")]
    pub fdroid_signing_cert_sha256: String,
    /// SimpleX's own F-Droid repository (HTTPS, no trailing slash) and its
    /// fingerprint (SHA-256 of the index signing certificate).
    #[serde(default = "default_simplex_repo_url")]
    pub simplex_repo_url: String,
    #[serde(default = "default_simplex_repo_fingerprint")]
    pub simplex_repo_fingerprint: String,
    /// The normal SimpleX app and its pinned signing certificate SHA-256.
    #[serde(default = "default_simplex_app_package")]
    pub simplex_app_package: String,
    #[serde(default = "default_simplex_app_signer")]
    pub simplex_app_signing_cert_sha256: String,
    /// How long step 11 of `deliver` waits for SimpleX's repository in the
    /// F-Droid client (the client fetches it over Tor), in seconds. After
    /// 240 seconds without it the repository intent is sent once more.
    #[serde(default = "default_fdroid_repo_wait")]
    pub fdroid_repo_wait_secs: u64,
    /// A download over Tor that receives no byte for this many seconds is
    /// given up and continued on a new Tor circuit (at most 3 attempts).
    #[serde(default = "default_download_idle")]
    pub download_idle_timeout_secs: u64,
    /// The file this config was loaded from (absolute), for the backup of
    /// `admin/config.toml` and the backup timer. Not a config key.
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
}

fn default_agent_package() -> String {
    names::DEFAULT_AGENT_PACKAGE.into()
}
fn default_provider_authority() -> String {
    names::DEFAULT_PROVIDER_AUTHORITY.into()
}
fn default_tor_proxy() -> String {
    names::DEFAULT_TOR_PROXY.into()
}
fn default_revocation_days() -> u64 {
    7
}
fn default_gos_days() -> u64 {
    90
}
fn default_adb() -> String {
    "adb".into()
}
fn default_fastboot() -> String {
    "fastboot".into()
}
fn default_calculator() -> String {
    "com.android.calculator2".into()
}
fn default_release_base() -> String {
    crate::grapheneos::DEFAULT_RELEASE_BASE.into()
}
fn default_channel() -> String {
    "stable".into()
}
fn default_release() -> String {
    "newest".into()
}
fn default_max_os_age() -> u64 {
    30
}
// The pins below were each confirmed from two official sources on
// 2026-11-24.
fn default_fdroid_package() -> String {
    "org.fdroid.fdroid".into()
}
fn default_fdroid_signer() -> String {
    "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab".into()
}
fn default_simplex_repo_url() -> String {
    "https://app.simplex.chat/fdroid/repo".into()
}
fn default_simplex_repo_fingerprint() -> String {
    "9f358ff284d1f71656a2bfaf0e005deae6aa14143720e089f11ff2ddcfeb01ba".into()
}
fn default_simplex_app_package() -> String {
    "chat.simplex.app".into()
}
fn default_simplex_app_signer() -> String {
    "3c52c4fd3cad1c07c9b00a7080e358fab9fefcb8af5aec147765f16d0f21ad85".into()
}
fn default_confirm_timeout() -> u64 {
    900
}
fn default_fdroid_repo_wait() -> u64 {
    600
}
fn default_download_idle() -> u64 {
    120
}
fn default_orbot_package() -> String {
    crate::deliver::orbot::PACKAGE_DEFAULT.into()
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(explicit: Option<&Path>) -> Result<(Config, PathBuf), String> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os(ENV_CONFIG) {
                Some(p) => PathBuf::from(p),
                None => PathBuf::from(DEFAULT_CONFIG_PATH),
            },
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        let mut cfg =
            Config::parse(&text).map_err(|e| format!("config {}: {e}", path.display()))?;
        cfg.loaded_from = Some(std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone()));
        Ok((cfg, path))
    }

    fn validate(&self) -> Result<(), String> {
        // A marked placeholder (REPLACE_...) is accepted so that `devices`,
        // `verify` and `trust import` work before the proxy is known;
        // `trust refresh` refuses to run with it.
        if !self.tor_socks_proxy.starts_with("socks5h://") && !is_placeholder(&self.tor_socks_proxy)
        {
            return Err(format!(
                "tor_socks_proxy must use socks5h:// so DNS also goes through Tor, got {:?}",
                self.tor_socks_proxy
            ));
        }
        if self.revocation_max_age_days == 0 || self.grapheneos_keys_warn_age_days == 0 {
            return Err("age thresholds must be at least 1 day".into());
        }
        for (name, p) in [
            ("system_calculator_package", &self.system_calculator_package),
            ("orbot_package", &self.orbot_package),
            ("fdroid_package", &self.fdroid_package),
            ("simplex_app_package", &self.simplex_app_package),
        ] {
            if !crate::agent::valid_package(p) {
                return Err(format!("{name} must be a package name, got {p:?}"));
            }
        }
        let u = &self.simplex_repo_url;
        if !u.starts_with("https://") || u.ends_with('/') || u.contains(char::is_whitespace) {
            return Err(format!(
                "simplex_repo_url must be an https:// URL without a trailing slash, got {u:?}"
            ));
        }
        let base = &self.grapheneos_release_base;
        if !base.starts_with("https://")
            || base.ends_with('/')
            || base.contains(char::is_whitespace)
        {
            return Err(format!(
                "grapheneos_release_base must be an https:// URL without a trailing slash, got {base:?}"
            ));
        }
        if !crate::grapheneos::valid_channel(&self.grapheneos_channel) {
            return Err(format!(
                "grapheneos_channel must be stable, beta or alpha, got {:?}",
                self.grapheneos_channel
            ));
        }
        if crate::grapheneos::ReleaseSetting::parse(&self.grapheneos_release).is_none() {
            return Err(format!(
                "grapheneos_release must be newest or stable, got {:?}",
                self.grapheneos_release
            ));
        }
        if self.max_os_age_days == 0 {
            return Err("max_os_age_days must be at least 1".into());
        }
        if !(CONFIRM_TIMEOUT_MIN..=CONFIRM_TIMEOUT_MAX).contains(&self.flash_confirm_timeout_secs) {
            return Err(format!(
                "flash_confirm_timeout_secs must be from {CONFIRM_TIMEOUT_MIN} to {CONFIRM_TIMEOUT_MAX}, got {}",
                self.flash_confirm_timeout_secs
            ));
        }
        if !(FDROID_REPO_WAIT_MIN..=FDROID_REPO_WAIT_MAX).contains(&self.fdroid_repo_wait_secs) {
            return Err(format!(
                "fdroid_repo_wait_secs must be from {FDROID_REPO_WAIT_MIN} to {FDROID_REPO_WAIT_MAX}, got {}",
                self.fdroid_repo_wait_secs
            ));
        }
        if !(DOWNLOAD_IDLE_MIN..=DOWNLOAD_IDLE_MAX).contains(&self.download_idle_timeout_secs) {
            return Err(format!(
                "download_idle_timeout_secs must be from {DOWNLOAD_IDLE_MIN} to {DOWNLOAD_IDLE_MAX}, got {}",
                self.download_idle_timeout_secs
            ));
        }
        for (name, p) in [
            ("grapheneos_cache_dir", &self.grapheneos_cache_dir),
            ("flash_log_dir", &self.flash_log_dir),
        ] {
            if p.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
                return Err(format!(
                    "{name} must not be empty (leave it out for the default)"
                ));
            }
        }
        if self.adb_path.is_empty() {
            return Err("adb_path must be set".into());
        }
        if !self.messenger_package.is_empty()
            && !crate::agent::valid_package(&self.messenger_package)
        {
            return Err(format!(
                "messenger_package must be a package name or empty, got {:?}",
                self.messenger_package
            ));
        }
        if !self.messenger_package_pattern.is_empty()
            && !valid_package_pattern(&self.messenger_package_pattern)
        {
            return Err(format!(
                "messenger_package_pattern may hold only a-z A-Z 0-9 _ . and *, got {:?}",
                self.messenger_package_pattern
            ));
        }
        if !self.messenger_package.is_empty()
            && !self.messenger_package_pattern.is_empty()
            && !package_matches(&self.messenger_package_pattern, &self.messenger_package)
        {
            return Err(format!(
                "messenger_package {:?} does not match messenger_package_pattern {:?}",
                self.messenger_package, self.messenger_package_pattern
            ));
        }
        if !valid_authority(&self.provider_authority("a.b")) {
            return Err(format!(
                "messenger_provider_authority must be a provider authority ({{package}} and a-z A-Z 0-9 _ .), got {:?}",
                self.messenger_provider_authority
            ));
        }
        if let Some(p) = &self.admin_store_path {
            if p.as_os_str().is_empty() {
                return Err(
                    "admin_store_path must not be empty (leave it out for the default)".into(),
                );
            }
        }
        if self.trust_cache_dir.as_os_str().is_empty() {
            return Err("trust_cache_dir must be set".into());
        }
        for (name, v) in [
            ("agent_signing_cert_sha256", &self.agent_signing_cert_sha256),
            (
                "messenger_signing_cert_sha256",
                &self.messenger_signing_cert_sha256,
            ),
            ("orbot_signing_cert_sha256", &self.orbot_signing_cert_sha256),
            (
                "fdroid_signing_cert_sha256",
                &self.fdroid_signing_cert_sha256,
            ),
            ("simplex_repo_fingerprint", &self.simplex_repo_fingerprint),
            (
                "simplex_app_signing_cert_sha256",
                &self.simplex_app_signing_cert_sha256,
            ),
        ] {
            if !v.is_empty() && !is_sha256_hex(v) && !is_placeholder(v) {
                return Err(format!("{name} must be 64 hex digits or empty"));
            }
        }
        Ok(())
    }

    /// The pinned agent digest, or None if not configured.
    pub fn agent_digest(&self) -> Option<Vec<u8>> {
        pinned(&self.agent_signing_cert_sha256)
    }

    /// The idle limit of downloads over Tor.
    pub fn download_idle(&self) -> Duration {
        Duration::from_secs(self.download_idle_timeout_secs)
    }

    /// The pinned messenger digest, or None if not configured.
    pub fn messenger_digest(&self) -> Option<Vec<u8>> {
        pinned(&self.messenger_signing_cert_sha256)
    }

    /// The fixed messenger package, if the config names one.
    pub fn fixed_messenger(&self) -> Option<&str> {
        (!self.messenger_package.is_empty()).then_some(self.messenger_package.as_str())
    }

    /// Whether `package` may be delivered as the messenger: a valid package
    /// name, equal to `messenger_package` when that is set, and matching
    /// `messenger_package_pattern` when that is set.
    pub fn check_messenger_package(&self, package: &str) -> Result<(), String> {
        if !crate::agent::valid_package(package) {
            return Err(format!("{package:?} is not a valid package name"));
        }
        if let Some(fixed) = self.fixed_messenger() {
            if package != fixed {
                return Err(format!(
                    "the messenger package {package} is not the configured messenger_package {fixed}"
                ));
            }
        }
        if !self.messenger_package_pattern.is_empty()
            && !package_matches(&self.messenger_package_pattern, package)
        {
            return Err(format!(
                "the messenger package {package} does not match messenger_package_pattern {:?}",
                self.messenger_package_pattern
            ));
        }
        Ok(())
    }

    /// The activation provider's authority for this messenger package.
    pub fn provider_authority(&self, package: &str) -> String {
        self.messenger_provider_authority
            .replace("{package}", package)
    }

    /// The GrapheneOS cache folder (config or default).
    pub fn grapheneos_cache(&self) -> Result<PathBuf, String> {
        match &self.grapheneos_cache_dir {
            Some(p) => Ok(p.clone()),
            None => std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".cache/simplego-provisioning/grapheneos"))
                .ok_or_else(|| "HOME is not set; set grapheneos_cache_dir in the config".into()),
        }
    }

    /// Where the flash logs go (config or `logs` in the cache folder).
    pub fn flash_logs(&self) -> Result<PathBuf, String> {
        match &self.flash_log_dir {
            Some(p) => Ok(p.clone()),
            None => Ok(self.grapheneos_cache()?.join("logs")),
        }
    }

    pub fn release_setting(&self) -> crate::grapheneos::ReleaseSetting {
        crate::grapheneos::ReleaseSetting::parse(&self.grapheneos_release)
            .unwrap_or(crate::grapheneos::ReleaseSetting::Newest)
    }

    /// The pinned F-Droid client digest, or None if not configured.
    pub fn fdroid_digest(&self) -> Option<Vec<u8>> {
        pinned(&self.fdroid_signing_cert_sha256)
    }

    /// The pinned SimpleX app digest and repository fingerprint, both
    /// needed for the SimpleX app step (lowercase hex).
    pub fn simplex_pins(&self) -> Option<(String, String)> {
        let a = pinned(&self.simplex_app_signing_cert_sha256)?;
        let r = pinned(&self.simplex_repo_fingerprint)?;
        Some((crate::util::hex(&a), crate::util::hex(&r)))
    }

    /// The pinned Orbot digest, or None if not configured.
    pub fn orbot_digest(&self) -> Option<Vec<u8>> {
        pinned(&self.orbot_signing_cert_sha256)
    }
}

pub fn is_placeholder(v: &str) -> bool {
    v.starts_with("REPLACE_")
}

fn pinned(v: &str) -> Option<Vec<u8>> {
    if is_sha256_hex(v) {
        crate::util::unhex(v)
    } else {
        None
    }
}

/// A messenger package pattern: package name characters and `*`.
pub fn valid_package_pattern(p: &str) -> bool {
    !p.is_empty()
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '*')
}

/// Whether `package` matches `pattern`, where `*` stands for any run (also
/// empty) of package name characters and every other character is literal.
pub fn package_matches(pattern: &str, package: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| m(rest, &s[i..])),
            Some((c, rest)) => s.first() == Some(c) && m(rest, &s[1..]),
        }
    }
    m(pattern.as_bytes(), package.as_bytes())
}

/// A content provider authority: dot-separated names of a-z A-Z 0-9 _.
pub fn valid_authority(a: &str) -> bool {
    !a.is_empty()
        && a.split('.').all(|seg| {
            !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../config/provisioning.example.toml");

    #[test]
    fn example_config_parses_with_nothing_pinned() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(c.agent_package, names::DEFAULT_AGENT_PACKAGE);
        assert_eq!(c.fixed_messenger(), None);
        assert_eq!(
            c.messenger_provider_authority,
            names::DEFAULT_PROVIDER_AUTHORITY
        );
        assert_eq!(c.revocation_max_age_days, 7);
        assert_eq!(c.grapheneos_keys_warn_age_days, 90);
        assert!(c.agent_digest().is_none());
        assert!(c.messenger_digest().is_none());
    }

    #[test]
    fn messenger_package_pattern_and_authority() {
        let base = "trust_cache_dir = \"/tmp/x\"
";
        let c = Config::parse(base).unwrap();
        assert!(c.check_messenger_package("org.example.messenger").is_ok());
        assert!(c.check_messenger_package("bad").is_err());
        assert_eq!(
            c.provider_authority("org.example.messenger"),
            "org.example.messenger.activation"
        );
        let c = Config::parse(&format!(
            "{base}messenger_package_pattern = \"org.example.*\"
"
        ))
        .unwrap();
        assert!(c.check_messenger_package("org.example.m1").is_ok());
        let e = c.check_messenger_package("com.other.m1").unwrap_err();
        assert!(
            e.contains("does not match messenger_package_pattern"),
            "{e}"
        );
        let c = Config::parse(&format!(
            "{base}messenger_package = \"org.example.fixed\"
"
        ))
        .unwrap();
        assert_eq!(c.fixed_messenger(), Some("org.example.fixed"));
        let e = c.check_messenger_package("org.example.other").unwrap_err();
        assert!(e.contains("is not the configured messenger_package"), "{e}");
        let c = Config::parse(&format!(
            "{base}messenger_provider_authority = \"{{package}}.provider.v1\"
"
        ))
        .unwrap();
        assert_eq!(c.provider_authority("a.b"), "a.b.provider.v1");
        for bad in [
            "messenger_package = \"x\"",
            "messenger_package_pattern = \"org.e;x\"",
            "messenger_provider_authority = \"{package}/x\"",
            "messenger_provider_authority = \"\"",
            "messenger_package = \"a.b\"
messenger_package_pattern = \"c.*\"",
        ] {
            assert!(
                Config::parse(&format!(
                    "{base}{bad}
"
                ))
                .is_err(),
                "{bad}"
            );
        }
        assert!(package_matches("a.*", "a.b.c"));
        assert!(package_matches("*.b", "a.b"));
        assert!(!package_matches("a.*", "b.a"));
        assert!(package_matches("a.b", "a.b") && !package_matches("a.b", "a.bc"));
    }

    #[test]
    fn download_idle_limits() {
        let base = "trust_cache_dir = \"/tmp/x\"\n";
        assert_eq!(Config::parse(base).unwrap().download_idle_timeout_secs, 120);
        for bad in [9, 3601] {
            assert!(Config::parse(&format!("{base}download_idle_timeout_secs = {bad}\n")).is_err());
        }
    }

    #[test]
    fn fdroid_repo_wait_limits() {
        let base = "trust_cache_dir = \"/tmp/x\"\n";
        assert_eq!(Config::parse(base).unwrap().fdroid_repo_wait_secs, 600);
        assert!(Config::parse(&format!("{base}fdroid_repo_wait_secs = 60\n")).is_ok());
        for bad in [59, 3601] {
            assert!(Config::parse(&format!("{base}fdroid_repo_wait_secs = {bad}\n")).is_err());
        }
    }

    #[test]
    fn clearnet_or_local_dns_proxy_rejected() {
        for p in ["socks5://127.0.0.1:9050", "http://127.0.0.1:8080", ""] {
            let t = format!("trust_cache_dir = \"/tmp/x\"\ntor_socks_proxy = \"{p}\"\n");
            assert!(Config::parse(&t).is_err(), "{p}");
        }
    }

    #[test]
    fn bad_digest_rejected() {
        let t = "trust_cache_dir = \"/tmp/x\"\nagent_signing_cert_sha256 = \"abc\"\n";
        assert!(Config::parse(t).is_err());
        let ok = format!(
            "trust_cache_dir = \"/tmp/x\"\nagent_signing_cert_sha256 = \"{}\"\n",
            "AB".repeat(32)
        );
        assert_eq!(
            Config::parse(&ok).unwrap().agent_digest().unwrap(),
            vec![0xab; 32]
        );
    }

    #[test]
    fn tor_proxy_placeholder_accepted_by_config() {
        let t = "trust_cache_dir = \"/x\"\ntor_socks_proxy = \"REPLACE_WITH_GATEWAY_SOCKS\"\n";
        assert!(Config::parse(t).is_ok());
    }

    #[test]
    fn fastboot_can_be_disabled() {
        let c = Config::parse("trust_cache_dir = \"/x\"\nfastboot_path = \"\"\n").unwrap();
        assert!(c.fastboot_path.is_empty());
        assert!(Config::parse("trust_cache_dir = \"/x\"\nadb_path = \"\"\n").is_err());
    }

    #[test]
    fn grapheneos_settings() {
        let c = Config::parse(
            "trust_cache_dir = \"/x\"
",
        )
        .unwrap();
        assert_eq!(c.grapheneos_release_base, "https://releases.grapheneos.org");
        assert_eq!(c.grapheneos_channel, "stable");
        assert_eq!(c.grapheneos_release, "newest");
        assert_eq!(c.max_os_age_days, 30);
        assert_eq!(c.flash_confirm_timeout_secs, 900);
        for bad in [
            "flash_confirm_timeout_secs = 59",
            "flash_confirm_timeout_secs = 86401",
            "grapheneos_release_base = \"http://releases.grapheneos.org\"",
            "grapheneos_release_base = \"https://releases.grapheneos.org/\"",
            "grapheneos_channel = \"nightly\"",
            "grapheneos_release = \"preview\"",
            "max_os_age_days = 0",
            "grapheneos_cache_dir = \"\"",
        ] {
            assert!(
                Config::parse(&format!(
                    "trust_cache_dir = \"/x\"
{bad}
"
                ))
                .is_err(),
                "{bad}"
            );
        }
        let c = Config::parse(
            "trust_cache_dir = \"/x\"
grapheneos_release = \"stable\"
",
        )
        .unwrap();
        assert_eq!(
            c.release_setting(),
            crate::grapheneos::ReleaseSetting::Stable
        );
    }

    #[test]
    fn second_messenger_settings() {
        let c = Config::parse("trust_cache_dir = \"/x\"\n").unwrap();
        assert_eq!(c.fdroid_package, "org.fdroid.fdroid");
        assert_eq!(c.simplex_app_package, "chat.simplex.app");
        assert_eq!(c.simplex_repo_url, "https://app.simplex.chat/fdroid/repo");
        assert!(c.fdroid_digest().is_some());
        let (app, repo) = c.simplex_pins().unwrap();
        assert!(app.starts_with("3c52c4fd") && repo.starts_with("9f358ff2"));
        // The fingerprint as SimpleX prints it (upper case) is accepted.
        let c = Config::parse(
            "trust_cache_dir = \"/x\"\nsimplex_repo_fingerprint = \"9F358FF284D1F71656A2BFAF0E005DEAE6AA14143720E089F11FF2DDCFEB01BA\"\n",
        )
        .unwrap();
        assert!(c.simplex_pins().unwrap().1.starts_with("9f358ff2"));
        let c =
            Config::parse("trust_cache_dir = \"/x\"\nfdroid_signing_cert_sha256 = \"\"\n").unwrap();
        assert!(c.fdroid_digest().is_none());
        for bad in [
            "simplex_repo_url = \"http://app.simplex.chat/fdroid/repo\"",
            "simplex_repo_url = \"https://app.simplex.chat/fdroid/repo/\"",
            "simplex_repo_fingerprint = \"9F35\"",
            "simplex_app_package = \"chat simplex\"",
            "fdroid_signing_cert_sha256 = \"xyz\"",
        ] {
            assert!(
                Config::parse(&format!("trust_cache_dir = \"/x\"\n{bad}\n")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::parse("trust_cache_dir = \"/x\"\nflash = true\n").is_err());
    }
}
