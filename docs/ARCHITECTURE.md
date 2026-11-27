# Architecture

SimpleGo Provisioning has two programs: `sxprov`, a static command line tool
for the admin laptop, and a small attestation agent that `sxprov` installs on
a phone for the few seconds of one attestation. Everything else on the phone
is done through adb.

## Parts

| Part | Where | What it does |
|---|---|---|
| CLI | `src/main.rs`, `src/*_cmd.rs` | Parses options, loads the config, runs one command, prints text or `--json` events, returns a stable exit code (`src/exit.rs`). |
| Device access | `src/device/` | The one place that runs adb and fastboot: always `-s SERIAL`, standard input closed, arguments checked for shell safety. Parsers for their output. |
| Attestation | `src/attest/`, `src/verify.rs`, `src/verify_run.rs`, `src/agent.rs` | Installs the agent, sends the challenge, takes the certificate chain back, validates it against the pinned roots and the lists, and evaluates the KeyDescription. `verify.rs` is pure: evidence in, checks and a result out. |
| Trust material | `src/trust/`, `trust/` | Google's attestation roots and the GrapheneOS signing key (committed, embedded in the binary); the revocation list and the GrapheneOS key list (downloaded over Tor, cached with metadata, SSHSIG-verified). |
| APK reader | `src/apk/` | ZIP, Android binary XML and the APK Signing Block (v2, v3, v3.1), in pure Rust: package, version, signer, content digest, `autoVerify` web hosts. Used for every APK before it is installed and for every installed `base.apk` afterwards. |
| Installed apps | `src/installed.rs` | Reads an installed app without the agent: the pulled `base.apk` through the APK reader, cross-checked with `dumpsys package`; finds installed messengers by their activation provider. |
| Delivery | `src/deliver/` | The checked 15-step delivery, `undeliver` for test phones and `handover`. Submodules: the network lock (`lock.rs`, Orbot as today's provider), app link verification (`applinks.rs`), Orbot's screens (`orbot.rs`), the SimpleX app and the F-Droid client (`simplex.rs`, `appsteps.rs`), the messenger's activation provider (`provider.rs`, `phone.rs`). |
| F-Droid index | `src/fdroid/` | SimpleX's signed F-Droid index: `entry.jar` (PKCS#7, SHA-256 and RSA), `entry.json`, `index-v2.json`, rollback protection, the choice of APK. |
| GrapheneOS | `src/grapheneos/`, `src/flash/` | Channel files and status, factory image download with resume and signature check, unpacking, and `flash`, which runs the official `flash-all.sh` unchanged and guides the operator through the bootloader steps. |
| Activation files | `src/activation/` | The `.sxact` format: container, payload, address rules, the feature profile (`features.rs`) and customer directory (`directory.rs`, with the group links in `hosts.rs`), Argon2id, Ed25519, AES-256-GCM, the issuing logic and the encrypted admin store (`store.rs`) with its random store key (`storekey.rs`: TPM through `systemd-creds`, else a key file). `import.rs` is the reference for the apps' order of checks. |
| Backups | `src/backup/`, `src/backup_cmd.rs` | SimpleGo backup format v1 for product `admin-store`: recovery code and seed (`code.rs`), the derived age key pair (`keys.rs`), the age layer with the file-key check (`agefile.rs`, the `age` crate), container and manifest (`container.rs`), a strict ustar (`tar.rs`), the members (`admin.rs`), destinations (`dest.rs`: folder, WebDAV over Tor), the state file (`state.rs`), runs, checks, rotation, drill, warnings (`engine.rs`), what is asked and the recovery code screen (`ui.rs`). The CLI and the automatic run at the end of every command are in `backup_cmd.rs`. |
| Agent | `agent/` | An Android instrumentation in Java without permissions, UI or package visibility. It creates a hardware-backed key with the challenge, returns its attestation chain and deletes the key. |
| Fakes | `tests/support/` | A fake adb and fastboot that simulate a phone for the tests. |

## Data flow

1. **Trust.** `trust refresh` downloads the revocation list and the
   GrapheneOS key list over Tor into the trust cache; the GrapheneOS list is
   accepted only with a valid signature from the pinned key and never older
   than the cached one.
2. **Verify.** `sxprov` creates a random challenge, installs the agent, runs
   it, uninstalls it, and validates the returned chain: the root against the
   pinned roots, every serial against the revocation list, the challenge, the
   security level, the root of trust (locked, `SelfSigned`, a listed
   GrapheneOS key) and the agent's own identity. The messenger, if named, is
   read from its installed `base.apk`.
3. **Deliver.** The APK files are read on the laptop first. On the phone:
   the app link verifier is disabled, Orbot is installed, the network lock is
   turned on and proven, and only then the messenger, the F-Droid client and
   the SimpleX app are installed. The activation file and code are issued
   from the admin store and sent to the messenger's provider. The final check
   attests again and reads every installed app back. A record goes into the
   admin store.
4. **Flash.** The factory image is downloaded over Tor and its signature
   checked against the pinned GrapheneOS key; the official script installs
   it; the attestation afterwards proves the result.

## Trust boundaries

| Boundary | What crosses it | How it is checked |
|---|---|---|
| Phone to laptop | Every adb output, the agent's result | Device reports are shown as reported and never decide a PASS; the attestation chain is validated cryptographically; installed APKs are read with our reader. |
| Network to laptop | Revocation list, GrapheneOS key list, channel files, factory images, SimpleX's index and APK | Only over Tor (`socks5h`); signatures (GrapheneOS SSHSIG, F-Droid PKCS#7), pinned fingerprints and signers, sizes and SHA-256 from signed indexes, rollback checks. The unsigned channel files only choose a version; the image is always signature-checked. |
| Operator to laptop | Passphrases, the activation signing key, typed confirmations | Prompts without echo; the key is passphrase protected and wiped after use; dangerous steps need a typed word; no prompt without a terminal. |
| Laptop to phone | Commands, APKs, the activation file and code | One device by serial; every APK checked before install; the code only as the argument of one provider call, shown once, stored masked. |
| Laptop at rest | Admin store, config | The store is encrypted, written atomically, locked against a second process and refused inside a repository; the config holds no secret. |

## Configuration and secrets

The repository holds no secret and no customer data. What is not public comes
in at provisioning time: the config (`config/provisioning.toml`, git-ignored),
the admin store, the activation signing key, the servers and support files of
each customer, and the messenger APK with its per-delivery package name.
Public facts stay in the source: the Google roots, the GrapheneOS key, and the
pinned signers of Orbot, the F-Droid client and the SimpleX app.
