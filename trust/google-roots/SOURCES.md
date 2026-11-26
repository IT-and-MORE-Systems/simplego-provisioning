# Google key attestation roots

Fetched 2026-11-17. Public certificates. Embedded into `sxprov` at build time
(`src/trust/mod.rs`) and checked against this file by a unit test.

Sources:

- [D] https://developer.android.com/privacy-and-security/security-key-attestation
  (page "Last updated 2026-07-09"): two current trust anchors and three
  "previously issued" RSA root certificates.
- [R] https://android.googleapis.com/attestation/root (JSON array of PEM;
  Last-Modified 2025-07-29): the two current trust anchors only. Byte
  identical to the two current anchors on [D].

All four RSA certificates carry the same RSA 4096 key. Current devices chain
to different ones (for example Pixel 9 Pro on Android 16 to the 2019
certificate, which [R] does not list), so `sxprov` matches the chain root by
public key, as [D] phrases it. GrapheneOS AttestationServer bundles the same
five certificates.

| File | Name in sxprov | Key | Serial | Valid | SHA-256 of DER | Source |
|---|---|---|---|---|---|---|
| google-root-rsa-2022.pem | google-root-rsa-2022 | RSA 4096 | F1C172A699EAF51D | 2022-03-20 to 2042-03-15 | cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc | [D], [R] |
| google-root-ecdsa-p384-2025.pem | google-root-ecdsa-p384-2025 | ECDSA P-384 | 84A9D0297B0EB58AE7FF0E80DE760605 | 2025-07-17 to 2035-07-15 | 6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0 | [D], [R] |
| google-root-rsa-2016.pem | google-root-rsa-2016 | RSA 4096 | E8FA196314D2FA18 | 2016-05-26 to 2026-05-24 (expired) | c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5 | [D] |
| google-root-rsa-2019.pem | google-root-rsa-2019 | RSA 4096 | D50FF25BA3F2D6B3 | 2019-11-22 to 2034-11-18 | 1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc | [D] |
| google-root-rsa-2021.pem | google-root-rsa-2021 | RSA 4096 | C36B7C44B9AE1831 | 2021-11-17 to 2036-11-13 | ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a | [D] |

Public key (SubjectPublicKeyInfo) SHA-256:

- RSA (all four RSA files): feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae
- ECDSA P-384: 3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec

Subjects: the RSA certificates have subject `serialNumber=f92009e853b6b045`;
the ECDSA root has `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US`.

Root rotation: [D] states that the ECDSA P-384 root "will begin signing
attestation certificate chains on February 1, 2026". The date 2026-04-10
(Remote Key Provisioning devices use only the new root) is not stated on [D];
it appears only in third-party write-ups. Both roots are trusted either way.

Check a file:

    openssl x509 -in google-root-rsa-2022.pem -outform DER | sha256sum
