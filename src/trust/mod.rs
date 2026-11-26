// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
//! Trust store: pinned Google roots (committed, embedded in the binary), and
//! the local cache of the two downloaded lists.

pub mod cache;
pub mod lists;
pub mod refresh;
pub mod sshsig;

use crate::attest::chain::Anchor;

/// Committed Google attestation roots (trust/google-roots/, see SOURCES.md).
/// Production code can only load these; test roots are injected in tests.
const GOOGLE_ROOTS: &[(&str, &str)] = &[
    (
        "google-root-rsa-2016",
        include_str!("../../trust/google-roots/google-root-rsa-2016.pem"),
    ),
    (
        "google-root-rsa-2019",
        include_str!("../../trust/google-roots/google-root-rsa-2019.pem"),
    ),
    (
        "google-root-rsa-2021",
        include_str!("../../trust/google-roots/google-root-rsa-2021.pem"),
    ),
    (
        "google-root-rsa-2022",
        include_str!("../../trust/google-roots/google-root-rsa-2022.pem"),
    ),
    (
        "google-root-ecdsa-p384-2025",
        include_str!("../../trust/google-roots/google-root-ecdsa-p384-2025.pem"),
    ),
];

pub fn google_roots() -> Result<Vec<Anchor>, String> {
    GOOGLE_ROOTS
        .iter()
        .map(|(name, pem)| Anchor::from_pem(name, pem))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::chain::spki_sha256;

    /// The embedded roots must match trust/google-roots/SOURCES.md.
    #[test]
    fn roots_match_sources() {
        let roots = google_roots().unwrap();
        assert_eq!(roots.len(), 5);
        let rsa = "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae";
        let ec = "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec";
        for r in &roots {
            let want = if r.name.contains("ecdsa") { ec } else { rsa };
            assert_eq!(spki_sha256(r), want, "{}", r.name);
        }
        let sources = include_str!("../../trust/google-roots/SOURCES.md");
        for r in &roots {
            assert!(
                sources.contains(&r.name),
                "{} missing in SOURCES.md",
                r.name
            );
        }
    }
}
