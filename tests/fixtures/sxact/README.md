# SXACT test vectors (TEST ONLY)

Test files for the activation and update file imports of the phone app and
the desktop app. Format: SXACT version 1, as described in the activation
file format document (version 1 with the amendments of
2026-11-19 23:10, 2026-11-21 00:41 "Short links", 2026-11-21 10:30
"Short link grammar" and 2026-11-21 11:00 "Server fingerprint" and the
order of checks, 2026-11-23 "Support address in `tor_optional`", and
section 12 "Feature profile and customer directory" of 2026-11-27 with its
amendments 12.4).

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
- `expected_features_profile`, `expected_features_fixed` (section 12, only
  where the installation has a feature profile after an `ok` import): the
  `features_profile` and `features_fixed` your `status` must report.
- `installation.features`, `installation.features_profile` (update vectors
  of section 12): the profile the installation has before the update.
- `group_links` (vectors with a `directory`): the group links of the
  payload in plain text, for a check with the real SimpleX core. Test
  values only.
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
| `bad_payload` | a required field is missing or invalid (also: a fingerprint that is not a 32-byte key hash, an invalid or upper-case v3 onion name, a network mode value other than the three, a support address outside the accepted grammar; section 12: anything refused inside `features` or `directory`, a group link outside the grammar or not on one of `servers.smp`, a `directory` in an update file) |
| `kind_mismatch` | the payload `kind` does not match the container's kdf_alg |
| `network_mode_rule` | an address (server, support or group link) breaks the rule of the network mode |
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

## Feature profile and customer directory (added 2026-11-27)

Format document section 12 with the amendments of 12.4. Two optional
payload objects, still format version 1. Outside them, unknown top-level
fields are still ignored (section 7); inside them every rule fails closed:
a name, value or field your app does not know refuses the whole file.

### `features` (section 12.1)

    "features": {"profile_version": 1, "groups": "off", "calls": "on", ...}

- `profile_version` required, the integer `1` (`1.0` is refused).
- Switches: `groups`, `channels`, `preset_servers`, `calls`, `files`,
  `voice_messages`, `calculator_disguise` (phone and desktop);
  `laptop_link`, `developer_tools`, `vault` (desktop only). Values `on`,
  `off`, `ask`; a missing switch is not fixed, like `ask`.
- Refused (`bad_payload`): an unknown switch, an unknown value (also upper
  case), `null` for a switch or for the whole object, a duplicate key
  (never read as the last value: check your JSON reader, several keep the
  last one silently), a missing `profile_version`, an array instead of the
  object, and a desktop-only switch `on` in a phone file (`off` and `ask`
  are accepted there).
- In an update: without `features` the installed profile stays unchanged;
  with `features` it replaces the whole profile (12.4).
- `features_profile`: the first 16 lowercase hex characters of SHA-256 over
  the canonical JSON of the object as issued: keys sorted, no spaces, UTF-8,
  `profile_version` written as `1`. Nothing is normalized: an explicit
  `ask` and a missing switch give different values (compare
  `activation-phone-features-missing-switch` and
  `activation-phone-features-explicit-ask`). Compute it from your checked
  object, not from the file's bytes. The example object of section 12.1
  gives `82c3232f78958958`.
- `features_fixed`: the switches with `on` or `off`, sorted by name, as
  `name:value` joined by `,` (empty when none is fixed).

### `directory` (section 12.2)

    "directory": {"directory_version": 1, "set_id": "<32 hex>",
      "display_name": "...", "role": "owner",
      "groups": [{"name": "...", "link": "https://<host>/g#<key>?c=<key hash>", "direct_contacts": true}]}

- Only in activation files; in an update file it is refused (`bad_payload`).
- `directory_version` the integer `1`; `set_id` 32 lowercase hex
  characters; `role` `owner` or `member`; 1 to 20 groups;
  `direct_contacts` `true` or `false`; every field required, no other
  field in the object or in a group.
- `display_name` and every group `name`: 1 to 50 characters and a valid
  SimpleX name as the v7.1.4 core accepts it unchanged (12.4): it starts
  with a letter or digit, has no leading or trailing space, no two spaces
  or two hyphens in a row, none of `. , ; / \ # @ ' " ` ~`. The generator
  writes only Latin letters (also accented letters and umlauts), digits,
  spaces and hyphens. Apps check the core's rule.
- Group links (12.4): only the short form `https://<host>/g#<key>?...`
  with the grammar of the support short link (`c` required, `h` and `p` the
  only other parameters). Refused (`bad_payload`): the long form
  `simplex:/contact#/?...&data=...`, `simplex:/g#...`, upper case `G`,
  `/g/#`, and the types `a`, `i`, `c` (channels) and `r`.
- Hosts for the network mode rules: the link host plus every `h` host; the
  rule is the servers' rule (in `tor_optional` an onion host and a clearnet
  host, unlike the support address).
- The server of every group link (its hosts in order, its port and its key
  hash `c`, compared as bytes) must equal one of `servers.smp`
  (`bad_payload` otherwise).

The synthetic group links are built like the other test addresses: on the
vectors' SMP server (`testonly...onion`, in `tor_optional` with
`smp-a.example.invalid` in `h`), the key SHA-256 over
`TEST-ONLY-GROUP-LINK-KEY-<n>`, `c` the server's key hash. The generator's
link writer reproduces the short link strings of the simplexmq tests byte
for byte (`tests/AgentTests/ConnectionRequestTests.hs` at `fdbcb24d`). They
were not yet parsed by a running core; that check is still open.

### Order of checks with section 12

1. Step 5: the fields as above, then inside `features` and `directory`
   (structure, names, values, versions, `set_id`, names, the number of
   groups, a `directory` in an update file). Like every field rule this
   comes before the identity checks of an update
   (`refused-update-directory-other-customer` is `bad_payload`).
2. Step 6: the device class, then the desktop-only switch rule, then the
   network mode value, then the addresses: every address parsed (servers,
   support address, group link grammar), then the network mode rules over
   all of them (`network_mode_rule`), then the group link server match
   (`bad_payload`).

### Vectors

| Vector | Expected |
|---|---|
| `activation-phone-features` | `ok`: every switch, on, off and ask; desktop-only switches off or ask |
| `activation-desktop-features` | `ok`: every switch, `laptop_link` and `vault` on |
| `activation-phone-features-missing-switch` | `ok`: only two switches |
| `activation-phone-features-explicit-ask` | `ok`: the same plus `files` ask: same `features_fixed`, other `features_profile` |
| `activation-phone-features-nothing-fixed` | `ok`: only `profile_version`, `features_fixed` empty |
| `activation-phone-features-desktop-switch-off` | `ok`: `vault` off in a phone file |
| `refused-features-unknown-switch` | `bad_payload` |
| `refused-features-unknown-value` | `bad_payload` |
| `refused-features-missing-profile-version` | `bad_payload` |
| `refused-features-profile-version-2` | `bad_payload` |
| `refused-features-profile-version-float` | `bad_payload`: `1.0` |
| `refused-features-null` | `bad_payload` |
| `refused-features-duplicate-switch` | `bad_payload`: `groups` twice |
| `refused-features-phone-desktop-switch-on` | `bad_payload`: `vault` on in a phone file |
| `update-phone-features-change` | `ok`: replaces the profile; `groups` off to ask is named in the summary |
| `update-phone-without-features` | `ok`: the installed profile stays (expected values are the installation's) |
| `refused-update-features-phone-desktop-switch-on` | `bad_payload` |
| `activation-phone-directory` | `ok`: two groups, role owner, umlauts and a hyphen in the name |
| `activation-desktop-directory-tor-optional` | `ok`: one group, the link with `h` |
| `refused-directory-group-link-clearnet-tor-required` | `network_mode_rule` |
| `refused-directory-group-link-other-server` | `bad_payload`: another onion host |
| `refused-directory-group-link-other-key-hash` | `bad_payload`: the right host, another `c` |
| `refused-directory-group-link-without-c` | `bad_payload` |
| `refused-directory-group-link-contact-address` | `bad_payload`: `/a#` |
| `refused-directory-group-link-channel` | `bad_payload`: `/c#` |
| `refused-directory-group-link-simplex-form` | `bad_payload` |
| `refused-directory-group-link-long-form` | `bad_payload` |
| `refused-directory-unknown-field` | `bad_payload` |
| `refused-directory-group-unknown-field` | `bad_payload` |
| `refused-directory-unknown-role` | `bad_payload` |
| `refused-directory-version-2` | `bad_payload` |
| `refused-directory-display-name-dot` | `bad_payload`: `TEST Dr. Weber` |
| `refused-directory-display-name-51-characters` | `bad_payload` |
| `refused-directory-group-name-double-space` | `bad_payload` |
| `refused-directory-no-groups` | `bad_payload` |
| `refused-directory-set-id-upper-case` | `bad_payload` |
| `refused-update-directory` | `bad_payload` |
| `refused-update-directory-other-customer` | `bad_payload`: the field rule before the identity check |

Every earlier `.sxact` file and the key files are byte-identical. In
`vectors.json` only the `format` line of the earlier content changed; the
new entries are added at the end.

## Regenerating

The generator is the test `src/activation/vectors.rs` in this repository.
It uses a fixed seed for salts, nonces, codes, update keys and file ids, so
regenerating gives identical bytes; `cargo test vectors` checks that the
committed files match. To write them again:

    SXACT_WRITE_VECTORS=1 cargo test vectors
