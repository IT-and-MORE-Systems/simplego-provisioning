# Contributing to SimpleGo Provisioning

Thank you for considering contributing to SimpleGo Provisioning!

---

## Code of Conduct

This project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Getting Started

### Before You Start

1. Check existing issues - Your idea might already be discussed
2. Read the documentation - Familiarize yourself with the README, docs/ARCHITECTURE.md and docs/SECURITY_MODEL.md
3. Discuss first - For significant changes, open an issue before coding

### Types of Contributions

| Contribution | Description |
|--------------|-------------|
| Bug Reports | Found a bug? Let us know! |
| Feature Requests | Have an idea? We would love to hear it! |
| Documentation | Typos, clarifications, examples |
| Code | Bug fixes, features, refactoring |
| Device Testing | Run `verify` and the read-only commands on other GrapheneOS devices and report the output (serials masked) |

---

## Development Setup

### Prerequisites

| Component | Version |
|-----------|---------|
| Debian | 13 (trixie), x86_64 (or WSL2) |
| Rust | 1.98.1 (pinned in `rust-toolchain.toml`), target `x86_64-unknown-linux-musl` |
| musl-tools | as shipped by Debian 13 |
| JDK (agent only) | 17 |
| Android SDK (agent only) | build-tools 36.0.0, platform android-36 |

Build and test steps are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Every change must pass:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

---

## Rules for Changes

1. **Proven, not reported.** A check that decides PASS rests on attestation, a signature or our own reader of a file, never on what the phone reports about itself.
2. **Nothing installed before the network lock.** No change may install an app on a phone before the lock is proven, except the lock itself.
3. **No secrets, no customer data.** Never commit server or onion addresses of real servers, keys, keystores, passwords, activation codes, serials, data read from a real phone, or the per-delivery package name. Test data is synthetic and labelled TEST ONLY; recorded phone output goes to the git-ignored `tests/fixtures/local/`.
4. **One device only.** Every adb or fastboot command names its device (`-s`), has standard input closed, and goes to the one phone the operator chose.
5. **Tor only.** Every network access goes through the configured `socks5h` proxy; there is no clearnet fallback.
6. **Tests without a phone.** New phone steps come with a fake adb scenario.
7. **SPDX header.** Every new source file starts with `SPDX-License-Identifier: AGPL-3.0-or-later` and the copyright line.

### Commit Messages

Conventional Commits, one module per commit; each commit builds and its tests pass on its own:

```
feat(deliver): prove the network lock before any install
fix(apk): refuse a v1-only APK
docs(usage): describe the activation file transfer
```

### Pull Requests

- One topic per pull request
- Describe what you tested: with the fake adb, and on which device if any
- No phone data, serials or codes in the description or the logs
