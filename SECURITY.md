# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

SimpleGo Provisioning is in active pre-release development (alpha). Security
updates are applied to the latest version on the main branch only.

## Reporting a Vulnerability

If you discover a security vulnerability in SimpleGo Provisioning, please
report it privately using GitHub's **Private Vulnerability Reporting** feature
on this repository. Do NOT open a public issue for security vulnerabilities.

**What to expect:**
- Acknowledgment within 72 hours
- Status update within 7 days
- Coordinated disclosure after a fix is available

**What to include:**
- Description of the vulnerability
- Steps to reproduce (if applicable), with the `sxprov --version` line
- Affected component (attestation, APK reader, delivery steps, network lock, activation files, admin store, GrapheneOS download and flash, attestation agent)
- Impact assessment

Never include real activation codes, update keys, server addresses, serials
or other customer data in a report.

## Scope

SimpleGo Provisioning is the admin tool that verifies, flashes and delivers
SimpleGo phones. Security-relevant areas include:
- Hardware key attestation: chain building to the pinned Google roots, the revocation check, the root of trust, the GrapheneOS key list and its signature check, the challenge
- The APK reader: ZIP, binary manifest, the APK signature scheme v2, v3 and v3.1 blocks, content digests
- The delivery order: the network lock before any install, the app link verifier, the final checks of the installed apps
- The activation file format: signature, encryption, key derivation, address and network mode rules, replay protection
- The encrypted admin store, its lock and its atomic writes
- Downloads over Tor: SimpleX's F-Droid index, GrapheneOS channel files and factory images, their signature checks
- The attestation agent and every command sent to a phone over adb (argument quoting, one device only)

## Contact

For non-vulnerability security questions, open a regular GitHub issue.
