# Sample attestation chains

Source: https://github.com/android/keyattestation, directory `testdata/`,
fetched 2026-11-17 from
`https://raw.githubusercontent.com/android/keyattestation/main/testdata/<device>/<sdk>/<name>.pem`.
Licence: Apache License 2.0 (`LICENSE-android-keyattestation`). Files are
renamed `<device>_<sdk>_<name>.pem`; each is a full chain, leaf first.

| File | Device | Attestation | Root |
|---|---|---|---|
| caiman_sdk36_TEE_EC_RKP.pem | Pixel 9 Pro, Android 16 | version 400, TEE | Google RSA (2019 certificate) |
| caiman_sdk36_SB_EC_RKP.pem | Pixel 9 Pro, Android 16 | version 300, StrongBox | Google RSA (2019 certificate) |
| tegu_sdk36_TEE_EC_2026_ROOT.pem | codename tegu, Android 16 | version 400, TEE | Google ECDSA P-384 |
| frankel_sdk37_TEE_EC_2026.pem | codename frankel, Android 17 | version 500, TEE | Google ECDSA P-384 |

Checked, for all four chains, by the unit test
`real_chains_carry_no_device_identifiers`: no device-unique identifiers (no
attestationIdSerial, IMEI, MEID or second IMEI, tags 713, 714, 715, 723;
`uniqueId` empty). The caiman chains carry model-level ID tags (brand, device,
product, manufacturer, model).

The certificate serial numbers in the chains are certificate serials, not
device serials. The second certificate of each chain is a short-lived Remote
Key Provisioning certificate of one of Google's test devices; it is public in
the source repository and identifies no device of ours.

The caiman chains have an all-zero verifiedBootKey with state Verified, which
is probably sanitized test data; they are not used for key matching.
