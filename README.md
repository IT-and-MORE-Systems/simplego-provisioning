<p align="center">
  <img src=".github/assets/simplego_simplego-provisioning_banner.png" alt="SimpleGo Provisioning" width="1200" height="250">
</p>

<h1 align="center">SimpleGo Provisioning</h1>

<p align="center">
  <strong>The admin tool that turns a GrapheneOS phone into a verified, delivered SimpleGo phone.</strong><br>
  Hardware attestation, signed and encrypted activation files, a network lock before any app is installed, and a fleet record for every phone.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="#status"><img src="https://img.shields.io/badge/version-0.1.0--alpha-orange.svg" alt="Version"></a>
  <a href="#getting-started"><img src="https://img.shields.io/badge/platform-Debian%2013%20x86__64-lightgrey.svg" alt="Platform"></a>
  <a href="https://simplego.dev"><img src="https://img.shields.io/badge/web-simplego.dev-blue.svg" alt="Website"></a>
</p>

---

SimpleGo Provisioning (`sxprov`) runs on the operator's admin laptop. It detects a phone on USB, proves with hardware key attestation that the phone runs an untouched GrapheneOS with a locked bootloader, installs GrapheneOS where needed with the official flash script, and delivers the phone: Orbot as the network lock, the SimpleGo Messenger, the normal SimpleX app from SimpleX's own repository, the customer's activation, and a record in an encrypted admin store.

It is built around one rule: nothing is trusted because the phone says so. The OS is proven by an attestation chain up to Google's roots and a GrapheneOS key from a signed list; every APK is checked on the laptop with our own reader against a pinned signer; and no app is installed while the phone can still reach the network outside Tor.

---

## Security

| Layer | What sxprov does | What it protects against |
|:------|:-----------------|:-------------------------|
| **Attestation** | A fresh challenge, a hardware-backed key (StrongBox or TEE), the chain up to a pinned Google root, Google's revocation list, `deviceLocked`, `SelfSigned` and a verified boot key from the signature-checked GrapheneOS list. | A phone with a modified OS, an unlocked bootloader or a revoked key passing as a SimpleGo phone. |
| **APK checks** | Our own APK reader: signature block (v3.1, v3, v2), content digest over the whole file, signer pinned in the config; the installed `base.apk` read again after the install and compared with the package manager's record. | A wrong or swapped APK, a package that differs from the checked file. |
| **Network lock** | The always-on VPN with lockdown is proven at run time before any other app is installed; Android's app link verifier is disabled first. | An app announcing itself to the clear net at install time. |
| **Activation files** | Ed25519 signature, AES-256-GCM under the activation code (Argon2id) or the customer's update key, strict address rules, replay protection by sequence. | A forged or altered configuration, a configuration that leaks to clearnet servers. |
| **Admin store** | Encrypted at rest (Argon2id, AES-256-GCM), atomic writes, exclusive lock, never inside a repository. | Update keys and fleet records on a lost or copied laptop. |
| **Network** | Every download over Tor (`socks5h`), no clearnet fallback; GrapheneOS images checked by signature. | Leaks of the operator's address, tampered downloads. |

---

## Use cases

- **Verify a phone** before it is handed out or after it comes back: `sxprov verify`.
- **Deliver a phone** to a customer: GrapheneOS check, network lock, messenger, SimpleX app, activation, final check and record, in one checked run: `sxprov deliver`.
- **Install or update GrapheneOS** with the official, signature-checked factory image: `sxprov os status`, `os fetch`, `flash`.
- **Issue configuration**: signed and encrypted activation and update files for the apps: `sxprov activation issue`, `update`, `inspect`.

---

## Getting Started

SimpleGo Provisioning is in alpha. It is used by IT & MORE Systems on its own admin laptops.

### Build from source

On Debian 13 (trixie), x86_64, with the Rust toolchain pinned in `rust-toolchain.toml`:

```bash
sudo apt install musl-tools
cargo build --release --bin sxprov --target x86_64-unknown-linux-musl
cargo test
```

The result is a static binary, `target/x86_64-unknown-linux-musl/release/sxprov`. The attestation agent (`agent/`) is a small Android app built with Gradle; see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

### Configure

Copy `config/provisioning.example.toml` to `config/provisioning.toml` (git-ignored) and fill in the pins, the Tor SOCKS proxy and the paths. Configuration that is not public (the admin store, keys, customer data, server addresses, the per-delivery messenger package) is supplied at provisioning time and never committed. See [docs/USAGE.md](docs/USAGE.md#configuration).

### Use

```bash
sxprov --version
sxprov trust refresh
sxprov verify --serial SERIAL --messenger-package PKG
sxprov deliver --serial SERIAL --apk messenger.apk --customer-ref C-1001 --network-mode tor_required \
    --servers servers.txt --support support.txt --key /media/KEY/sxact-signing-key \
    --orbot-apk orbot.apk --fdroid-apk F-Droid.apk
```

---

## Status

Version `0.1.0-alpha`. Verification, delivery (with the network lock and the normal SimpleX app) and the GrapheneOS status and download have run on a Pixel 6a with GrapheneOS; what has not run on a phone yet is listed in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#device-tests).

---

## Documentation

| Resource | Link |
|:---------|:-----|
| Commands and configuration | [docs/USAGE.md](docs/USAGE.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Security model | [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) |
| Development, build and tests | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| Release notes | [docs/release-info/](docs/release-info/) |
| Contributing guidelines | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Legal notices | [docs/LEGAL.md](docs/LEGAL.md), [docs/TRADEMARK.md](docs/TRADEMARK.md), [docs/DISCLAIMER.md](docs/DISCLAIMER.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |

Security vulnerabilities should be reported privately via GitHub's [vulnerability reporting](https://github.com/IT-and-MORE-Systems/simplego-provisioning/security) feature; see [SECURITY.md](SECURITY.md).

---

## License

| Component | License |
|:----------|:--------|
| Software (`sxprov`, the attestation agent) | [AGPL-3.0-or-later](LICENSE) |
| Third-party components | see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [docs/LEGAL.md](docs/LEGAL.md) |

## Acknowledgments

[GrapheneOS](https://grapheneos.org/) (hardened phone OS, signed key list and factory images) - [Android key attestation](https://developer.android.com/privacy-and-security/security-key-attestation) and [android/keyattestation](https://github.com/android/keyattestation) (sample chains) - [Tor](https://www.torproject.org/) and [Orbot](https://guardianproject.info/apps/org.torproject.android/) (anonymous networking) - [SimpleX Chat](https://simplex.chat/) (messaging protocol and the SimpleX app) - [F-Droid](https://f-droid.org/) (app updates) - [ring](https://github.com/briansmith/ring), [RustCrypto](https://github.com/RustCrypto), [rustls](https://github.com/rustls/rustls) and [ureq](https://github.com/algesten/ureq) (cryptography and HTTPS)

---

<p align="center">
  <i>SimpleGo Provisioning is an independent open-source project by IT and More Systems, Recklinghausen, Germany.</i><br>
  <i>SimpleGo uses the open-source SimpleX Messaging Protocol (AGPL-3.0) for interoperable message delivery and Tor for anonymous networking.</i><br>
  <i>It is not affiliated with or endorsed by any third party. See <a href="docs/DISCLAIMER.md">docs/DISCLAIMER.md</a> for full legal notices.</i>
</p>

<p align="center">
  <strong>SimpleGo Provisioning - Proven before it is trusted.</strong>
</p>
