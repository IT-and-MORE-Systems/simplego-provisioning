# Development

How to build `sxprov` and the attestation agent, how the tests work, and what
has run on a real phone. The command reference is [USAGE.md](USAGE.md).

## Versions

| Component | Version |
|---|---|
| Rust | 1.98.1, pinned in `rust-toolchain.toml`, with the `x86_64-unknown-linux-musl` target |
| musl C compiler | `musl-tools` (Debian), for `ring` |
| Admin laptop | Debian 13, x86_64 |
| JDK (agent) | 17 |
| Gradle (agent) | 9.9.1 through the wrapper, distribution SHA-256 pinned in `agent/gradle/wrapper/gradle-wrapper.properties` |
| Android Gradle Plugin | 9.5.1, compileSdk and targetSdk 36, minSdk 28 |
| Android SDK | build-tools 36.0.0, platform android-36 |

## Version and build number

The version is `version` in `Cargo.toml` (`MAJOR.MINOR.PATCH-stage`, today
`0.2.0-alpha`). The build number is `BUILD` in `src/names.rs`; a release build
may set it with `SXPROV_BUILD_NUMBER` at build time. `sxprov --version` prints
"SimpleGo Provisioning 0.2.0 alpha (build N)", and the delivery and flash
records keep `0.2.0-alpha+N` as `sxprov_version`, backups as `app_version`. Every release has a git tag
`vX.Y.Z-stage` and a file in [release-info/](release-info/).

## Rust tool

The result is a static binary for the admin laptop (Debian, x86_64), with no
glibc dependency. On a Debian machine:

    sudo apt install musl-tools
    export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME=~"
    cargo build --release --bin sxprov --target x86_64-unknown-linux-musl
    ldd target/x86_64-unknown-linux-musl/release/sxprov   # "statically linked"

`--remap-path-prefix` keeps local paths out of the binary.

On Windows, build through WSL2 from the Windows folder and keep the build
output in a WSL cache directory, so the slow Windows mount only holds sources:

    wsl
    cd /mnt/c/<path>/simplego-provisioning
    export CARGO_TARGET_DIR=~/.cache/simplego-provisioning/target
    export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME=~"
    cargo build --release --bin sxprov --target x86_64-unknown-linux-musl

Tests need no phone:

    cargo test
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

Argon2id and scrypt with the real parameters are slow without
optimisation, so `Cargo.toml` builds `argon2`, `blake2`, `scrypt`, `salsa20`,
`pbkdf2` and `sha2` with `opt-level = 3` in dev and test builds too.

The backup format is cross-checked with the official `age` tool (for example
unpacked from Debian's signed `age` package):

    X=$(mktemp -d)
    SXPROV_CROSS_DIR=$X cargo test cross_export -- --ignored
    python3 -I tools/age_crosscheck.py /path/to/age /path/to/age-keygen $X
    SXPROV_CROSS_DIR=$X cargo test cross_import -- --ignored --nocapture

The script has the tool open our files (the V1 identity, the work factor 20
wrapped seed through a pseudo terminal) and write its own, which
`cross_import` then opens with our reader.

The CI workflow (`.github/workflows/ci.yml`) runs the same on every push and
pull request: format, clippy, all tests, and the musl release build. It needs
no secret.

### Third-party notices

A release ships `THIRD_PARTY_NOTICES.md` next to the binary: every crate
built into `sxprov` with its licence and the licence texts. Regenerate it
after a dependency change, from the locked dependency tree and the crate
sources in the local Cargo registry (no network):

    cargo fetch --locked
    python3 tools/third_party_notices.py

The same script refreshes the dependency table in
[LEGAL.md](LEGAL.md). CI fails when either file is out of date.

## Attestation agent (`agent/`)

The agent is a minimal Android app (Java, no third-party libraries), used
only to attest: `verify`, and steps 2 and 14 of `deliver` and step 10 of
`flash`.

- It requests no permissions, has no activities or UI, and declares no
  package visibility (`<queries>`): it sees no other app.
- It writes nothing to storage and deletes its key before it returns.
- Its package name is `sxprov.agentPackage` in `agent/gradle.properties`
  (`dev.simplego.provisioning.agent`), which must match `agent_package` in
  the config.

It is built on Windows (or any machine with the Android SDK) with Gradle.
`agent/local.properties` with `sdk.dir` is git-ignored.

    $env:JAVA_HOME = 'C:\Program Files\Java\jdk-17'
    $env:SXPROV_AGENT_SIGNING_PROPERTIES = "$env:USERPROFILE\.simplego-provisioning\agent-signing.properties"
    cd agent
    .\gradlew.bat assembleRelease
    sxprov apk inspect build\outputs\apk\release\sxprov-agent-release.apk

Put the printed signer SHA-256 into `agent_signing_cert_sha256`.

### Signing

The signing key never enters the repository, not even the development key.
The build reads the keystore from outside, in one of two ways:

- `SXPROV_AGENT_SIGNING_PROPERTIES`: path to a properties file outside the
  repository, with `storeFile`, `storePassword`, `keyAlias` and
  `keyPassword`.
- Or the four variables `SXPROV_AGENT_KEYSTORE`,
  `SXPROV_AGENT_KEYSTORE_PASSWORD`, `SXPROV_AGENT_KEY_ALIAS` and
  `SXPROV_AGENT_KEY_PASSWORD`.

If the values are missing, or the keystore or properties file lies inside the
repository, the build fails with a message. The debug variant is disabled, so
there is no debug-key fallback. Switching to the production key changes only
these external values.

### Transport

The agent is an `<instrumentation>`. `sxprov` runs:

    adb -s SERIAL shell am instrument -w -r -e challenge HEX \
        dev.simplego.provisioning.agent/dev.simplego.provisioning.agent.AttestInstrumentation

The agent returns the certificate chain (base64 DER) and the keystore it used
(`strongbox` or `tee`) in the instrumentation result bundle, which adb prints
as `INSTRUMENTATION_RESULT:` lines. No file, broadcast or socket is involved.
`sxprov` uninstalls the agent on every path; an agent left over from an
interrupted run (for example after Ctrl-C) is removed before the next
install.

Installed apps (the messenger, Orbot, the F-Droid client, the SimpleX app)
are never read through the agent: `sxprov` pulls their `base.apk`, reads it
with its own APK reader, and compares the certificate with the package
manager's record from `dumpsys package` (`src/installed.rs`).

## Local files outside the repository

Never commit them. `.gitignore` names the ones that live inside the folder
(`config/provisioning.toml`, the store, issued `.sxact` files, signing keys,
keystores, `dist/`, `tests/fixtures/local/`).

- `config/provisioning.toml`: the local config, copied from
  `config/provisioning.example.toml`.
- The admin store (`~/.local/share/sxprov/admin-store.sxdb` by default) and
  its backup `admin-store.sxdb.bak`; `sxprov` refuses a store path inside a
  git repository.
- The activation signing key (passphrase protected, kept offline).
- `%USERPROFILE%\.simplego-provisioning\` on Windows (in WSL
  `/mnt/c/Users/<user>/.simplego-provisioning/`):
  - `agent-dev.p12` and `agent-signing.properties`: the development signing
    key of the agent and its values (development only);
  - `manual-trust/`: lists placed by hand for `trust import`.
- `dist/`: built test packages, downloaded APKs and the GrapheneOS cache of a
  test run.
- `tests/fixtures/local/`: data recorded from real phones.

## Test fixtures

Everything committed under `tests/` is public or synthetic. Data read from a
real phone stays in the git-ignored `tests/fixtures/local/`.

- `tests/fixtures/chains/`: real Pixel attestation chains from
  https://github.com/android/keyattestation (`testdata/`, Apache-2.0; licence
  copied there). They carry model-level ID tags only: no serial, IMEI or
  MEID, and an empty `uniqueId`; a unit test checks this for every chain.
  The tests run at fixed times inside each chain's validity.
- `tests/fixtures/trust/`: the real signed GrapheneOS key list as fetched on
  2026-11-17, and four real entries of Google's public revocation list.
- `tests/fixtures/grapheneos/`: the public signature and channel files of a
  GrapheneOS factory image (see its `SOURCE.md`).
- `tests/fixtures/apk/`: the compiled manifests of the public Orbot, F-Droid
  and SimpleX APKs (see its `SOURCE.md`).
- `tests/fixtures/device/`, `tests/fixtures/agent/`: adb, fastboot and
  instrumentation output written by hand in the real format, serials masked.
  See `tests/fixtures/device/README.md`.
- `tests/fixtures/fdroid/`: SimpleX's public `entry.jar` and
  `index-v2.json`, and a TEST ONLY RSA key with its certificate for synthetic
  repositories (`src/fdroid/testrepo.rs`); see its `SOURCE.md`.
- `tests/fixtures/sxact/`: the `.sxact` test vectors for the app imports,
  signed only with the TEST ONLY key in `tests/fixtures/sxact/keys/` (which
  `sxprov` refuses for issuing), with `vectors.json` (expected result and
  payload per file) and a README for the app developers. Every host is a
  `*.example.invalid` or a synthetic `testonly...onion` name, every key hash
  and DH key is synthetic. Generated deterministically by
  `src/activation/vectors.rs`; `cargo test vectors` checks that the
  committed files match. Apps compare against `expected` only; `reason` and
  `note` are text for humans.
- Synthetic APKs (`src/apk/testapk.rs`): binary manifest, ZIP and a v2 or v3
  signature block (ECDSA P-256) from keys that exist only in the test
  process; the real agent APK is read too when it has been built.
- Synthetic attestation chains (`src/attest/tests.rs`), made at run time from
  a test root, cover the cases no public sample shows: GrapheneOS
  `SelfSigned` with a listed and an unlisted key, unlocked bootloader, stock
  OS, wrong challenge, wrong agent digest or package, revoked serial (hex and
  decimal), Software security level, wrong root, extension outside the leaf,
  stale lists, normal tier.
- `tests/support/fake_adb.rs` (with `fake_screens.rs` and
  `fake_fastboot.rs`): the fake adb and fastboot of the delivery and flash
  tests, an example target (`cargo test` builds it; a release build with
  `--bin sxprov` does not). The tests link it into a scenario folder as
  `adb`, where it keeps a simulated phone in `state.json`: devices,
  properties, packages and uids, battery exceptions, the messenger's
  activation provider with the optional file import, the Orbot, F-Droid and
  Settings screens with their dialogs, failing screen reads, Orbot's VPN and
  Android's lockdown, `dumpsys` output and the app link verifier. Every
  address in it is a documentation address (RFC 5737). It logs every call to
  `calls.log`: arguments only, never standard input, the serial as
  `<serial>` and the code as `<code>`. Set `SXPROV_FAKE_ADB_LOG_DIR` to keep
  each scenario's call log. The scenarios are in `src/deliver/tests.rs` and
  `src/flash/tests.rs`.

The `.gitleaks.toml` allowlist names the TEST ONLY activation key by path and
fingerprint, so a secret scan of the repository does not report it.

## Device tests

What has run against a real phone (a Pixel 6a with GrapheneOS, test
deliveries with the TEST ONLY key):

- `deliver` on the hardened tier with Orbot, the SimpleX app and the F-Droid
  client, in the order with the network lock before any install, the app link
  verifier disabled and the app link proof; `undeliver --test-device`,
  `--discard-test-setup` (2026-11-23 to 2026-11-25);
- `verify`, `os status` and `os fetch`; `flash` up to the bootloader unlock
  (the flash and the lock after it were done by hand with the same official
  `flash-all.sh`, so a full `flash` run is still to come).

Not on a phone yet:

- 0.1.0-alpha changes: the messenger package taken from the APK, the
  activation provider found by `dumpsys package providers`, the provider
  authority template, the messenger's signer read from its `base.apk` and
  `dumpsys package` instead of the agent, and `verify --messenger-package`
  (fake adb only);
- `handover` (by design only against the fake adb; it ends adb access);
- `deliver` on the normal tier, the provider with file import, and
  `--reinstall` (fake adb only);
- `flash --resume`, the confirmation timeout reports and the no-terminal
  stops (fake adb and fake fastboot only);
- `undeliver` of a phone whose Orbot was there before the delivery (fake adb
  only).
