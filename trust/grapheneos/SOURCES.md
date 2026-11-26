# GrapheneOS verified boot key list: signing key

`allowed_signers` is the public key GrapheneOS signs its verified boot key
list with. Embedded into `sxprov` at build time (`src/trust/lists.rs`).

- Source: https://grapheneos.org/allowed_signers, fetched 2026-11-17
- SHA-256 of the file: 344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0
- Principal: contact@grapheneos.org
- Key: ssh-ed25519, fingerprint SHA256:AhgHif0mei+9aNyKLfMZBh2yptHdw/aN7Tlh/j2eFwM

The list itself is downloaded by `sxprov trust refresh` (through Tor) into the
trust cache, never committed:

- https://grapheneos.org/attestation.json: `{"verifiedBootKeys": [...], "timestamp": N}`,
  lowercase hex SHA-256 values. There is no device model mapping in the file.
- https://grapheneos.org/attestation.json.sig: SSHSIG, namespace
  `attestation keys`, hash sha512.

Equivalent manual check:

    ssh-keygen -Y verify -f allowed_signers -I contact@grapheneos.org \
        -n "attestation keys" -s attestation.json.sig < attestation.json

Guide: https://grapheneos.org/articles/attestation-compatibility-guide. The
guide recommends checking the `timestamp` to block rollback to an older list;
`trust refresh` refuses a list older than the cached one.

Key rotation: a new `allowed_signers` would be signed with the old key at
https://grapheneos.org/allowed_signers.sig. A rotation is a reviewed commit to
this directory, never an automatic update.
