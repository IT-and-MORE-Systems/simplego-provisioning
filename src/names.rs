// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Names that may change later. Each lives here only.

/// Binary name, taken from `[[bin]]` in Cargo.toml.
pub const BINARY: &str = env!("CARGO_BIN_NAME");

/// Product name, as `--version` and the apps show it.
pub const PRODUCT: &str = "SimpleGo Provisioning";

/// Version from `Cargo.toml` (`MAJOR.MINOR.PATCH-stage`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build number of this release. A release build may set it with
/// `SXPROV_BUILD_NUMBER` at build time; raise the default with every tagged
/// release (see docs/release-info/).
pub const BUILD: &str = match option_env!("SXPROV_BUILD_NUMBER") {
    Some(b) => b,
    None => "1",
};

/// "SimpleGo Provisioning 0.1.0 alpha (build N)".
pub fn version_line() -> String {
    format!(
        "{PRODUCT} {} (build {BUILD})",
        VERSION.replacen('-', " ", 1)
    )
}

/// The version as the records keep it: "0.1.0-alpha+N".
pub fn version_tag() -> String {
    format!("{VERSION}+{BUILD}")
}

/// Default package name (applicationId) of the attestation agent. Overridable
/// in the config; the agent build takes it from `sxprov.agentPackage` in
/// agent/gradle.properties.
pub const DEFAULT_AGENT_PACKAGE: &str = "dev.simplego.provisioning.agent";

/// Fully qualified instrumentation class of the agent. Its Java package is the
/// fixed namespace of the agent build, independent of the applicationId.
pub const AGENT_INSTRUMENTATION: &str = "dev.simplego.provisioning.agent.AttestInstrumentation";

/// Default authority of the messenger's activation provider; `{package}` is
/// the messenger package of the delivery.
pub const DEFAULT_PROVIDER_AUTHORITY: &str = "{package}.activation";

/// Default Tor SOCKS proxy. `socks5h` so that DNS also goes through Tor.
pub const DEFAULT_TOR_PROXY: &str = "socks5h://127.0.0.1:9050";

/// Upstream URLs fetched by `trust refresh`.
pub const URL_REVOCATION_STATUS: &str = "https://android.googleapis.com/attestation/status";
pub const URL_GRAPHENEOS_KEYS: &str = "https://grapheneos.org/attestation.json";
pub const URL_GRAPHENEOS_KEYS_SIG: &str = "https://grapheneos.org/attestation.json.sig";

#[cfg(test)]
mod tests {
    #[test]
    fn version_line_and_tag() {
        let l = super::version_line();
        assert!(
            l.starts_with("SimpleGo Provisioning 0.1.0 alpha (build "),
            "{l}"
        );
        assert!(l.ends_with(')'), "{l}");
        assert!(super::version_tag().starts_with("0.1.0-alpha+"));
    }
}
