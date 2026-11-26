# APK manifest fixtures

The compiled `AndroidManifest.xml` of three public APKs, unchanged, for the
web link intent filter reader (`src/apk/axml.rs`).
Extracted from the files the delivery uses, each checked against its
SHA-256 first:

| Fixture | APK | APK SHA-256 |
|---|---|---|
| `simplex-7.1.4-397-AndroidManifest.xml` | `chat.simplex.app_aarch64_397.apk` from `https://app.simplex.chat/fdroid/repo` | `6339d21c530ebbd6e8bbab34d29a7de874f1c579ee3df7a5d360ff56f7b0df42` |
| `fdroid-2.0.3-2000053-AndroidManifest.xml` | `F-Droid.apk` 2.0.3 from `https://f-droid.org/F-Droid.apk` | `dac55a0d17b1edf7e7286b48cfbd70c7c52fbb32a00af062c68830a437c47959` |
| `orbot-17.9.8-RC-1-AndroidManifest.xml` | `Orbot-17.9.8-RC-1-tor-0.4.9.17-1-g75a2abad5-fullperm-arm64-v8a-release.apk` | `f9acaa06b7651e1f070106b8d033722c746af863a4fe806f80b68a9ac56bdd25` |

The expected values in the tests were read independently with the Android
SDK's `aapt2 dump xmltree` (build-tools 36.0.0).
