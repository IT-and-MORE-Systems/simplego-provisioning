# SXACT test vectors (TEST ONLY)

Test files for the activation and update file imports of the phone app and
the desktop app. Format: SXACT version 1, as described in the activation
file format document (version 1 with the amendments of
2026-11-19 23:10, 2026-11-21 00:41 "Short links", 2026-11-21 10:30
"Short link grammar" and 2026-11-21 11:00 "Server fingerprint" and the
order of checks, and 2026-11-23 "Support address in `tor_optional`").

Every file here is signed with the **TEST ONLY** key in `keys/`. Apps may
trust this key only in debug and test builds. A release build must fail if
the test key is in its trusted list. `sxprov activation issue` and
`activation update` refuse the test key, so no test file can reach a
customer.

All addresses are synthetic: onion names start with `testonly` (they are
valid v3 names with a correct checksum, but no such service exists),
clearnet hosts are under `example.invalid` (the reserved top-level domain
`.invalid`, RFC 6761, so they can never reach a real host), and every
password says `TEST-ONLY`. Fingerprints, the support queue's sender id and
its X25519 key are SHA-256 over visibly fake seeds (section "What changed
on 2026-11-21").

## Files

- `keys/sxact-TEST-ONLY-signing-key.pub`: the test public key (OpenSSH).
- `keys/sxact-TEST-ONLY-signing-key`: its private key, no passphrase. Used
  only by the vector generator.
- `keys/sxact-TEST-ONLY-signing-key-encrypted`: the same key with the
  passphrase `TEST-ONLY-PASSPHRASE`, for the unlock tests of `sxprov`.
- `*.sxact`: the test files.
- `vectors.json`: what each file must give.

Test key:

- public key (hex): `7e632f9ed88c102d35eb087388cdc7601b9c9f70d24bb81c921fc22d651a51d4`
- key_id (hex): `dbbf11596d8029cbde96c679267d911e`

## How to use vectors.json

`vectors` is a list. One file can appear in several entries (for example
`activation-phone.sxact` with the right code, with the code in the card's
display form, and with a wrong code). Each entry has:

- `name`: a short name for the case.
- `file`: the file in this folder.
- `kind`:
  - `activation`: run your activation import with `code` (exactly as
    typed, so your input mapping is tested too) on an app of
    `app_device_class`.
  - `update`: run your update import on an installation in the state of
    `installation`: `customer_ref`, `device_class`, the stored
    `update_key_hex` (its id `update_key_id_hex`) and `last_sequence`.
  - `any`: the file must be refused in steps 1 to 3 of the order of checks
    (structure, bounds, trusted key, signature), before any code or update
    key is used. `code` is given for apps that only have a combined
    entry point.
- `trusted_public_key_hex`: the only key in the trusted list for this test.
- `expected`: `ok`, or the reason the file must be refused. This is the
  only field your test compares results against, and it is binding.
- `expected_payload`: for `ok`, the payload your import must produce,
  field by field.
- `reason`, `note`: plain-English explanations for humans. Do not compare
  against them: their wording may change between generator versions
  without any change to the file or to `expected` (for example the
  `reason` of `refused-support-short-link` changed on 2026-11-21, its
  `expected` stayed `bad_payload`).

After an `ok` activation the installation stores the update key and the
activation's `sequence` as its last applied sequence. After an `ok` update
it stores the new `sequence` and, if the payload carries one, the new
`update_key`.

## Refusal reasons

Your app may word its messages differently; the reason tells you at which
check the file must stop.

| Reason | Check |
|---|---|
| `too_large` | the file is larger than 64 KiB |
| `length_mismatch` | the length is not exactly 66 + ct_len + 64 (truncated, trailing bytes, wrong ct_len) |
| `bad_magic` | the first 5 bytes are not `SXACT` |
| `unsupported_version` | version is not 1 |
| `unknown_kdf_alg`, `unknown_aead_alg`, `unknown_sig_alg` | an algorithm number other than the ones of version 1 |
| `kdf_params_out_of_bounds` | Argon2id m below 65536 KiB or above 262144 KiB, t below 3 or above 10, p 0 or above 4; for an update file m, t and p not all zero |
| `unknown_key` | the key_id is not in the trusted list |
| `bad_signature` | the signature does not verify ("this file was not issued by IT & MORE Systems"); do not ask for the code |
| `bad_code` | the code is not exactly 13 valid bytes after the input mapping; refused without trying it |
| `wrong_code` | the GCM tag fails with the derived key ("the code does not match this file") |
| `wrong_update_key` | the update key id in the salt field is not the stored one ("this update is not for this installation") |
| `bad_payload` | a required field is missing or invalid (also: a fingerprint that is not a 32-byte key hash, an invalid or upper-case v3 onion name, a network mode value other than the three, a support address outside the accepted grammar) |
| `kind_mismatch` | the payload `kind` does not match the container's kdf_alg |
| `network_mode_rule` | an address (server or support) breaks the rule of the network mode |
| `device_class_mismatch` | the file is for the other device class |
| `customer_mismatch` | the update's `customer_ref` is not the installation's |
| `replayed_sequence` | the update's `sequence` is not greater than the last applied one |

## Support short links (added 2026-11-21)

The support address may be a SimpleX short contact link in the strict form
of the format document (section 7, short link grammar amended 2026-11-21
10:30):

    https://<host>/a#<key>[?<param>(&<param>)*]

- `<key>`: exactly 43 characters of unpadded base64url (32 bytes,
  canonical: the unused low bits of the last character are zero).
- Parameters, each at most once, in any order: `h=<host>(,<host>)*`
  (further hosts, comma raw or `%2C`), `p=<port>` (1 to 65535, decimal, no
  leading zero), `c=<key hash>` (43 characters of unpadded base64url).
  `c` is required.
- Hosts for the network mode rules: the host in front of `/a` plus every
  host in `h`. Each one follows the host rules (a valid v3 onion name or a
  clearnet host; an invalid `.onion` is refused).
- Refused (`bad_payload`): a missing `c`, any other parameter, a port in
  front of `/a`, upper case `/A#`, `/a/#`, a missing or malformed key, the
  `simplex:/a#...` form, and the link types `i` (invitation), `c`
  (channel), `g` (group) and `r` (chat relay).

| Vector | Expected |
|---|---|
| `activation-support-short-link` | `ok`: tor_required, short link on a `testonly` onion host |
| `update-support-short-link` | `ok`: changes the support address from the long form to a short link |
| `refused-short-link-clearnet-tor-required` | `network_mode_rule` |
| `refused-short-link-simplex-form` | `bad_payload` |
| `refused-short-link-invitation` | `bad_payload` |
| `refused-short-link-unknown-parameter` | `bad_payload` |
| `refused-short-link-malformed-key` | `bad_payload` |
| `refused-short-link-without-c` | `bad_payload` |
| `refused-support-short-link` (since 2026-11-19) | `bad_payload`: the `simplex:/a#...` form |

No new refusal reason was needed. When these vectors were added, the
earlier `.sxact` files stayed byte-identical; since 2026-11-21 (next
section) every file with a payload has new bytes.

## What changed on 2026-11-23 (support address in `tor_optional`)

Format document section 7, amended 2026-11-23: in
`tor_optional` the support address needs a valid onion host and must not
carry a clearnet host, counted over every queue (after `;`), its host and
its `srv=` hosts (for a short link: the link host and the `h` hosts).
Support is reachable only over Tor. `tor_required` and `direct` are
unchanged; the server addresses in `tor_optional` still need both kinds.

Exactly four files changed, with the same names and `expected` values:

| File | `expected` | Now |
|---|---|---|
| `activation-mode-tor-optional.sxact` | `ok` | support address with only its onion host (the `srv=` clearnet host is gone) |
| `activation-desktop-mode-tor-optional.sxact` | `ok` | as above |
| `update-phone-rotate-key.sxact` | `ok` | as above |
| `refused-mode-support-address.sxact` | `network_mode_rule` | `tor_optional`, valid servers, the support address carries a clearnet host in `srv=` next to its onion queue host |

The vectors using these files (`code-alternative-characters`,
`code-alternative-times-sign`, `code-alternative-asterisk` use
`activation-mode-tor-optional.sxact`) keep their codes. Every other file is
byte-identical. `refused-mode-tor-optional-without-clearnet`,
`refused-mode-tor-optional-without-onion` and
`refused-device-class-and-mode-rule` still carry a clearnet support host;
their servers break the rule first, so their `expected` and `reason` stay
the same (only two `note` texts say so now).

## What changed on 2026-11-21

A run of the desktop app's activation core against the real SimpleX core
found four problems in these vectors, all on our side:

1. Every server address carried the placeholder fingerprint
   `TEST-ONLY-FINGERPRINT-SMP` (or `-XFTP`). The SimpleX core needs the
   server's key hash, 32 bytes, and refuses such an address.
2. `code-alternative-characters` held only spaces (`' 784822+583218 '`),
   because the phone file's code has the operator `+`, which has no
   alternative character.
3. The support address was refused by the real core (`invalidConnReq` from
   `APIConnectPlan`): its fingerprint, sender id and `dh` key were not
   valid.
4. There was a desktop activation file only for `tor_required`.

What the generator does now:

- Fingerprints are SHA-256 over `TEST-ONLY-SMP-1`, `TEST-ONLY-XFTP-1` and
  `TEST-ONLY-SUPPORT-SMP-1`, written as 43 characters of unpadded base64url.
  Passwords stay `TEST-ONLY-PASSWORD` (simplexmq accepts it).
- The support address is a long contact address in the form a SimpleX
  client writes it: `simplex:/contact#/?v=2-7&smp=<queue>`, the queue
  `smp://<key hash>@<host>/<sender id>#/?v=1-4&dh=<key>&q=c`, percent-encoded
  once, with further hosts in `srv` (that is how upstream writes a queue
  whose versions start at 1). The sender id is the first 24 bytes of
  SHA-256 over `TEST-ONLY-SUPPORT-SENDER-ID-1`; the `dh` key is an X25519
  public key (DER, 44 bytes) whose 32 key bytes are SHA-256 over
  `TEST-ONLY-SUPPORT-DH-1`. Its `=` padding appears as `%253D`, because the
  queue's parameters are escaped once more inside `smp`. The short link
  vectors keep their synthetic form; they cannot be resolved offline in any
  case.
- The vectors were checked against the simplexmq source (pinned commit
  `fdbcb24d86460977382e1237591cd505c3b37fa1`), not against a running core.

Every file with a payload therefore has new bytes. File names, `expected`
values and the key files are the same as before; `refused-too-large.sxact`
(no payload) is unchanged too. The only change to an existing entry besides
its bytes, `reason` and `expected_payload`: `code-alternative-characters`
now uses `activation-mode-tor-optional.sxact` (code operator `x`) and the
code `735276X490904`, so it really tests a capital X.

New entries:

| Vector | File | Expected |
|---|---|---|
| `activation-code-divide` | `activation-code-divide.sxact` (operator `:`) | `ok` |
| `activation-code-minus` | `activation-code-minus.sxact` (operator `-`) | `ok` |
| `code-alternative-times-sign` | `activation-mode-tor-optional.sxact` | `ok`: `×` for `x` |
| `code-alternative-asterisk` | `activation-mode-tor-optional.sxact` | `ok`: `*` for `x` |
| `code-alternative-division-sign` | `activation-code-divide.sxact` | `ok`: `÷` for `:` |
| `code-alternative-slash` | `activation-code-divide.sxact` | `ok`: `/` for `:` |
| `code-alternative-minus-sign` | `activation-code-minus.sxact` | `ok`: U+2212 for `-` |
| `code-alternative-spaces-and-equals` | `activation-phone.sxact` | `ok`: spaces between the parts and a trailing `=` |
| `activation-desktop-mode-tor-optional` | `activation-desktop-mode-tor-optional.sxact` | `ok` |
| `activation-desktop-mode-direct` | `activation-desktop-mode-direct.sxact` | `ok` |
| `refused-fingerprint-placeholder` | `refused-fingerprint-placeholder.sxact` | `bad_payload`: the old placeholder |
| `refused-fingerprint-31-bytes` | `refused-fingerprint-31-bytes.sxact` | `bad_payload`: 42 characters, 31 bytes |
| `refused-fingerprint-support-placeholder` | `refused-fingerprint-support-placeholder.sxact` | `bad_payload`: the placeholder inside the support address |
| `refused-device-class-and-mode-rule` | `refused-device-class-and-mode-rule.sxact` | `device_class_mismatch`: a desktop file that also breaks tor_optional, imported by the phone app |
| `refused-device-class-and-mode-rule-on-desktop` | `refused-device-class-and-mode-rule.sxact` | `network_mode_rule`: the same file on the desktop app |

`×` is U+00D7 and `÷` is U+00F7, the signs printed on the card.
`vectors.json` holds every code as UTF-8, exactly as it is to be typed.

### Order of checks

When a payload breaks several rules, `expected` is the first one in this
order (format document section 6, clarified 2026-11-21 11:00):

1. Step 5, the fields: payload version, `kind` against the container
   (`kind_mismatch`), file id, time, customer reference, update key,
   sequence (`bad_payload`). For an update file then: customer
   (`customer_mismatch`), device class (`device_class_mismatch`), sequence
   (`replayed_sequence`).
2. Step 6: the device class (`device_class_mismatch`), then the network mode
   value (`bad_payload` unless it is `tor_required`, `tor_optional` or
   `direct`), then the server and support address rules: every address is
   parsed (fingerprint, password, hosts: `bad_payload`), then the network
   mode rules (`network_mode_rule`).

An app that reads `network_mode` into an enum while parsing would report a
bad mode value before a wrong device class. The vectors do not contain that
case, but the format document's order is binding all the same.

## Regenerating

The generator is the test `src/activation/vectors.rs` in this repository.
It uses a fixed seed for salts, nonces, codes, update keys and file ids, so
regenerating gives identical bytes; `cargo test vectors` checks that the
committed files match. To write them again:

    SXACT_WRITE_VECTORS=1 cargo test vectors
