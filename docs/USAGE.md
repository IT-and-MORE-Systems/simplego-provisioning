# Usage

The command reference of `sxprov`, SimpleGo Provisioning. Building it, the
agent and the tests are described in [DEVELOPMENT.md](DEVELOPMENT.md); what
each check proves in [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Commands

    sxprov --version
    sxprov devices [--serial SERIAL] [--messenger-package PKG] [--json] [--show-serial]
    sxprov verify [--serial SERIAL] [--messenger-package PKG] [--json] [--show-serial] [--confirm-stale-revocation-list]
    sxprov trust status [--json]
    sxprov trust refresh
    sxprov trust import DIR
    sxprov store init
    sxprov store list [--json] [--show-serial]
    sxprov activation pubkey --key PUBFILE [--json]
    sxprov activation issue --customer-ref REF --device-class phone|desktop --network-mode MODE \
        --servers FILE --support FILE --key PRIVFILE [--serial SERIAL] --out FILE
    sxprov activation update --customer-ref REF --device-class phone|desktop --network-mode MODE \
        --servers FILE --support FILE --key PRIVFILE [--rotate-update-key | --under-key-id ID] --out FILE
    sxprov activation inspect FILE [--trusted PUBFILE ...] [--code | --update-key-from-store REF |
        --update-key-file FILE | --update-key-prompt] [--json]
    sxprov deliver --serial SERIAL --apk FILE --customer-ref REF --network-mode MODE \
        --servers FILE --support FILE --key PRIVFILE [--orbot-apk FILE [--fdroid-apk FILE]] \
        [--normal-tier] [--reinstall] [--accept-unverified-messenger] [--confirm-stale-revocation-list] \
        [--dry-run] [--json] \
        [--test-delivery --test-store-passphrase-file FILE --test-key-passphrase-file FILE [--yes]]
    sxprov undeliver --serial SERIAL --test-device [--discard-test-setup] [--json]
        [--test-delivery --test-store-passphrase-file FILE]
    sxprov handover --serial SERIAL [--json]
    sxprov apk inspect FILE [--json]
    sxprov store init --test-delivery --test-store-passphrase-file FILE
    sxprov os status --serial SERIAL [--channel CHANNEL] [--offline] [--json]
    sxprov os fetch --device CODENAME [--channel CHANNEL | --version VERSION] [--json]
    sxprov flash --serial SERIAL [--channel CHANNEL | --version VERSION] [--dry-run] [--offline] [--json] \
        [--test-device [--yes] [--test-store-passphrase-file FILE]] [--confirm-stale-revocation-list]
    sxprov flash --resume --serial SERIAL [--version VERSION] [--test-device [--yes]] [--json]
    sxprov config show [--json]
    sxprov config set KEY VALUE [--json]

`verify` and `deliver` also take `--offline` (channel files from the cache
only); `deliver` takes `--allow-outdated-os`.

No command waits for terminal input it cannot get: a passphrase or a typed
confirmation asked with no terminal on standard input stops at once, with a
message that names what replaces it in a test run
(`--test-store-passphrase-file FILE`, `--test-key-passphrase-file FILE`,
`--test-device --yes`, `--yes`, `--confirm-stale-revocation-list`).

`-s` is short for `--serial`. Every command takes `--config PATH`. Without it,
the tool uses `$SXPROV_CONFIG`, then `config/provisioning.toml`.

The binary name is set once, in `[[bin]]` of `Cargo.toml`; the code reads it
from there. `sxprov --version` prints "SimpleGo Provisioning 0.1.0 alpha
(build N)".

### The messenger package

The messenger has its own package name per delivery. `deliver` takes it from
the messenger APK and the delivery record keeps it; `undeliver` and
`handover` read it from the record. `verify` and `devices` look at the
messenger given with `--messenger-package PKG`, else a fixed
`messenger_package` of the config, else the one installed app that offers the
activation provider (`dumpsys package providers`); with none or several such
apps they name no messenger and say why. The config may fix the
package (`messenger_package`) or restrict it (`messenger_package_pattern`,
for example `org.example.*`). The activation provider's authority is
`messenger_provider_authority` with `{package}` replaced (default
`{package}.activation`).

### `devices`

Lists every phone that `adb devices -l` and `fastboot devices` show.

Commands go to one phone only, because other phones on the same machine may
belong to someone else:

- the phone chosen with `--serial`, or
- the only phone, if exactly one is listed.

Every other phone is only listed (mode, and model from `adb devices -l`), and
no command is sent to it.

For the queried phone it reports:

- the mode (adb, fastboot, unauthorized, offline)
- model and codename, Android version, build ID and security patch level
- a GrapheneOS hint
- the bootloader state
- whether the messenger is installed, with its versionName and versionCode

Serials are masked unless you pass `--show-serial`.

Everything shown here is reported by the device and is not verified. The
GrapheneOS hint is only a hint; attestation is the proof.

The messenger is the one of "The messenger package" (given, fixed, or found
by its activation provider); the output names how it was found. Its signing
certificate is not read here; `verify` reads it from the installed
`base.apk`.

### `verify`

`verify` needs exactly one phone in adb mode: with several phones connected,
choose one with `--serial`. It runs these steps:

1. Loads the trust material and refuses to run if a list is missing.
2. Asks for confirmation if the revocation list is stale.
3. Creates a fresh 32-byte random challenge.
4. Installs the agent and runs one attestation.
5. Uninstalls the agent. This happens in every outcome.
6. Evaluates the result.

Each check is reported as PASS, FAIL, UNVERIFIED, UNKNOWN DEVICE or INFO,
together with the evidence: the values compared and where the expected value
came from.

Hardened Pixel class. All of these must pass for a PASS:

1. Chain: every signature is valid up to a pinned Google root, and every
   certificate is within its validity period.
2. Revocation: no serial in the chain is on Google's list. Serials are matched
   as hex and as decimal, because the live list contains both forms.
3. Challenge: the attested challenge equals this run's challenge.
4. Security level: TEE or StrongBox, never Software.
5. Root of trust: `deviceLocked`, `SelfSigned`, and a `verifiedBootKey` that is
   in the signature-checked GrapheneOS key list.
   - The list has no device model mapping, so the key is matched against the
     whole list. Each key belongs to one model. The model the device reports
     is shown, never checked.
   - A key that is not in the list gives `UNKNOWN DEVICE`, never PASS, with
     the hint to run `trust refresh` and verify again.
6. App identity: `attestationApplicationId` names the agent package, and its
   only signing digest equals `agent_signing_cert_sha256`.
7. Patch levels: shown, with no minimum enforced yet.
8. Messenger: only evaluated after checks 1 to 6 pass, for the messenger of
   "The messenger package" (without one it is UNVERIFIED). Not through the agent: the installed `base.apk` is pulled
   into a private temporary folder and read with our APK reader, and the
   package manager's own record (`dumpsys package`: the signature hash and
   the versionCode) must name the same certificate, else FAIL.
   - While `messenger_signing_cert_sha256` is empty, this check is
     UNVERIFIED and the overall result is `OS PASS, messenger UNVERIFIED`.

Checks 3 to 7 rest on the chain. When the chain is not trusted, they are
UNVERIFIED.

## Activation files

One app build serves every customer. Each installation gets its customer
configuration (the customer's SMP and XFTP servers, our support address, the
network mode) from one `.sxact` file: signed with Ed25519 and encrypted with
AES-256-GCM. The format is defined in the activation file format document
(version 1, with the amendments of 2026-11-19 23:10); `src/activation/`
implements it.

- Activation file: the first configuration of an installation, encrypted
  under the activation code (Argon2id, 64 MiB, 3 passes). The code is two
  six-digit numbers and an operator, for example `482913 × 105377`; it comes
  on the activation card, separately from the file.
- Update file: a later change of servers, support address or network mode,
  encrypted under the customer's update key, without a new code. Each update
  has the next `sequence`, so an old update cannot be replayed. An
  activation file carries the customer's current sequence, so an
  installation activated later refuses older updates too.

Network modes: `tor_required` (every address has an onion host),
`tor_optional` (every server address has an onion host and a clearnet
host; the support address has an onion host and no clearnet host, because
support is reachable only over Tor: format section 7, amended
2026-11-23), `direct` (every address has a clearnet host). The rule is
checked for every server address and for every queue of the support address
(its host and its `srv` hosts; for a short link the link host and the `h`
hosts) when issuing, and again by the apps. Onion hosts must be valid v3 names (checksum and version byte) in
lower case; an invalid `.onion` host is refused.

### Server addresses

`smp://<fingerprint>[:<password>]@<host>[,<host>...][:<port>]`, and the same
with `xftp://`. The rules are a strict subset of what simplexmq parses
(`Protocol.hs` `serverStrP` at the pinned commit
`fdbcb24d86460977382e1237591cd505c3b37fa1`):

- Fingerprint (format document section 7, "Server fingerprint", amended
  2026-11-21 11:00): the server's key hash, 32 bytes as canonical base64url,
  43 characters without padding or 44 with one trailing `=`. `sxprov`
  refuses anything else when issuing (`issue`, `update`) and when reading
  (`inspect`, the self-check), with the error "the fingerprint must be the
  server key hash". The
  client compares it with the SHA-256 fingerprint of the server's identity
  certificate, so another length could never connect.
- Password: printable ASCII without space, `@`, `:` and `/` (upstream
  `basicAuth`).
- Hosts: valid lower-case v3 onion names or clearnet names of
  `A-Z a-z 0-9 . -`; port 1 to 65535.

The same fingerprint rule holds for the server inside the `smp` parameter of
a long support address. A short link's `c` is already a 43-character key
hash.

### Order of checks

When a payload breaks several rules, the refusal names the first one in the
order of the format document, section 6 (clarified 2026-11-21 11:00): the
fields of step 5 (version, kind, file id, time, customer reference, update
key, sequence; for an update also customer, device class and sequence of
the installation), then step 6: the device class, then the network mode
value, then the server and support address rules (each address parsed,
then the network mode rules). `src/activation/import.rs` is the reference
for the apps; `inspect` and the self-check after `issue` read in the same
order (`inspect` has no app, so it skips the device class).

### Signing key

`issue` and `update` sign with the activation signing key that the operator
creates and keeps offline. `sxprov` expects:

- an OpenSSH Ed25519 private key file, passphrase protected (as written by
  `ssh-keygen -t ed25519`);
- its path with `--key`; it is read from there only, after a passphrase
  prompt, and wiped from memory after signing. An unprotected key is
  refused.

`activation pubkey --key FILE.pub` reads the OpenSSH public key and prints
the `key_id` (first 16 bytes of SHA-256 over the raw 32-byte key) and the raw
public key in hex and base64, ready for the apps' trusted lists.

### Trusted key list

Apps trust a list of activation keys, never a single key, so a new key can be
added by an app update before an old one is retired. `inspect` takes the
list as one `--trusted PUBFILE` per key. A file whose `key_id` is not in the
list is refused, and the signature is always checked before anything is
decrypted.

### Test key rule

`tests/fixtures/sxact/keys/sxact-TEST-ONLY-signing-key` is a separate test
key pair (comment `TEST ONLY, never trusted in release builds`). It exists
only for the test vectors. `issue` and `update` refuse it by its `key_id`,
so a test file can never reach a customer. Apps may trust it only in debug
and test builds; a release build must fail if it is in the trusted list.

### `activation issue`

    sxprov activation issue --customer-ref C-1001 --device-class phone --network-mode tor_required \
        --servers servers.txt --support support.txt --key /media/KEY/sxact-signing-key \
        --serial SERIAL --out C-1001-phone.sxact

- `--servers`: a text file with one `smp://` or `xftp://` address per line;
  empty lines and `#` lines are ignored. At least one of each.
- `--support`: a file with the support contact address on one line, in the
  long form `simplex:/contact#/?v=...&smp=...` or
  `https://<host>/contact#/?...` (see "Long support addresses" below), or as
  a short contact link `https://<host>/a#...` (see "Support short links"
  below).
- `--customer-ref`: an opaque reference (`A-Z a-z 0-9 -`, at most 32), never
  a name or other personal data.

It checks the input and the network mode rule first, then asks for the store
passphrase and the key passphrase. It creates the customer's update key on
first use, generates the code with the system random generator, builds and
signs the file, checks it once more with the same reader the apps use,
records the issue in the store and writes the file with mode 0600 (an
existing file is never overwritten). The code is printed once, in its card
form, with the note that it is not stored. It is never written to a file or
log, so `issue` refuses to run when standard output is redirected.

### `activation update`

Same inputs as `issue`. Issues an update file under the customer's stored
update key with the next sequence and records it.

- `--rotate-update-key`: the update carries a new update key that replaces
  the stored one. The store keeps every earlier key. Rotate only on a
  suspected leak (for example a stolen device), not routinely.
- `--under-key-id ID`: issues the update under an earlier update key (by its
  id, as `store list` and `inspect` show it), for installations that missed
  a rotation. The update then carries the current configuration and the
  current key.

One update file serves every installation of the customer with that device
class; phones and desktops get one file each.

### Long support addresses

A strict subset of simplexmq `Agent/Protocol.hs` (`connReqUriP` and
`StrEncoding SMPQueueUri`), as a SimpleX client writes it:

    simplex:/contact#/?v=<agent versions>&smp=<queue>[%3B<queue>...]
    https://<host>/contact#/?v=...&smp=...

- Only the parameters `v` (a version range such as `2-7`) and `smp`, each
  once. The host in front of `/contact` is only link notation.
- `smp` is percent-encoded once; queues are separated by `;` (`%3B`),
  because the comma separates the hosts of one server. Each queue is
  `smp://<key hash>@<host>[,<host>...][:<port>]/<sender id>#/?<params>` with
  no password, a base64url sender id and the params `v` (SMP client
  versions, highest at least 2), `dh` (an X25519 public key, 44 bytes DER,
  base64url, usually with its `=` escaped twice as `%253D`), and optionally
  `srv` (further hosts, which count for the network mode rules), `q` (`m` or
  `c`) and `k` (`s`). Anything else is refused.

### Support short links

The support address may be a SimpleX short contact link, in the strict form
of the format document (section 7, short link grammar amended 2026-11-21
10:30):

    https://<host>/a#<key>[?<param>(&<param>)*]

- `<key>`: exactly 43 characters of unpadded base64url (32 bytes,
  canonical).
- Parameters, each at most once, in any order: `h=<host>(,<host>)*`
  (further hosts, comma raw or `%2C`), `p=<port>` (1 to 65535, decimal, no
  leading zero) and `c=<key hash>` (43 characters of unpadded base64url, the
  SHA-256 fingerprint of the server's identity certificate). `c` is
  required.
- The hosts checked by the network mode rules are the host in front of `/a`
  plus every `h` host. Each one follows the host rules: a valid v3 onion
  name or a clearnet host; an invalid `.onion` is refused, never clearnet.
- Refused, each with its own error: a missing `c`, any other parameter, a
  repeated or malformed parameter, a port in front of `/a` (`host:port`),
  upper case `/A#`, `/a/#`, a missing or malformed key, the `simplex:/a#...`
  form and the link types `i` (one-time invitation), `c` (channel), `g`
  (group) and `r` (chat relay).
- Messages and `inspect` never show the key, the key hash or a full host:
  hosts are masked, key and key hash are shortened to their first and last
  4 characters.

Why this is safe, checked in simplex-chat `v7.1.4`
(`62ea5dc4afb73a0256ba0088f0ae85be750afc99`) and the simplexmq commit it
pins (`fdbcb24d86460977382e1237591cd505c3b37fa1`): the link data is stored
in the address's own queue record on the SMP server named in the link; a
client resolves the link on that server, refuses data whose queue does not
match it, and sends the contact request to that server, so every server on
the address side is named in the link. `c` authenticates the server (TLS
identity check). Without `c`, a client replaces a link whose single host is
one of its preset servers by that preset's full host list, which is why
`c` is required.

The customer's app also connects to the reply queue that the support
profile creates on one of its own servers after it accepts a contact
request. No address form names that server, so configure the support
profile with only our own onion SMP servers.

### `activation inspect`

Shows the header, the `key_id`, whether the key is in the given trusted list
and whether the signature is valid. To decrypt, give at most one of:

- `--code` for an activation file (asked at a prompt, never given as an
  argument);
- `--update-key-from-store REF` for an update file (the customer's current
  and earlier update keys from the admin store);
- `--update-key-file FILE` for an update file: a file holding the 64 lowercase
  hex characters of the update key, optionally followed by one newline. It is
  refused, and not read, if group or others have any permission on it
  (`chmod 600`). The key is never a command line value, so it does not land
  in the shell history;
- `--update-key-prompt` for an update file: the update key typed without
  echo.

The key is wiped from memory after use. `inspect` then shows the payload
with every host masked (`abcd...wxyz.onion`), every password and the update
key hidden, and whether the payload passes every rule. Exit code 0 only if
the file passes. Without any of the four, only the signature is checked.

### Admin store

`sxprov store init` creates the encrypted admin store; every other store
command asks for its passphrase. Default path
`~/.local/share/sxprov/admin-store.sxdb`, settable as `admin_store_path` in
the config. A path inside a git repository is refused.

- It holds per customer (`customer_ref`): the update key, the earlier update
  keys after a rotation, the last sequence and when the customer was
  created.
- It holds the fleet log: per issued file the `file_id`, kind,
  `customer_ref`, device class, network mode, `issued_at`, signing `key_id`,
  sequence, update key id, the optional device serial, and for activation
  files the code masked as first digit, `*****`, operator, `*****`, last
  digit (`4*****x*****7`).
- It holds the delivery records (`deliveries`, since content version 2):
  delivery id, masked and full serial (the full serial only here, inside the
  encrypted store), device class and tier, `test`, model, GrapheneOS build
  and patch level, attestation result, messenger package, version code and
  name, APK SHA-256, signer digest and whether it was verified (`UNVERIFIED`
  while not pinned), `--reinstall`, Orbot package, version, APK SHA-256,
  signer and whether this delivery installed it, `file_id` and
  `network_mode` of the activation, `file_transferred`, the masked code, the
  disabled calculator package, `customer_ref`, start and end time, the
  result (`delivered`, `failed at step N`, `undone`) with the reason of a
  failure, and the undo and handover times.
- It never holds a copy of an issued file, a full activation code, a name
  or a server password. A lost file is replaced by a new file with a new
  code.
- Content version 2 adds the delivery records. A version 1
  store is migrated when it is opened (no deliveries yet) and written as
  version 2 on the next save. An older `sxprov` refuses a version 2 store
  instead of dropping records; a newer version is refused, never rewritten.
- Encrypted at rest: Argon2id (64 MiB, 3 passes, 1 lane, random salt) from
  the store passphrase (at least 12 characters), AES-256-GCM, own header
  `SXDB` version 1.
- Written atomically (temporary file, fsync, rename); the previous version
  is kept as `admin-store.sxdb.bak`; mode 0600. A wrong passphrase gives a
  clear error and changes nothing.

The update keys are secrets like the server passwords: include the store in
the encrypted backup of the admin data, never copy it into a repository or a
document.

`sxprov store list` shows the customers (reference, number of issues, last
sequence) and the issues. Serials are masked unless `--show-serial`.

Lock: every command that uses the store (`store init`, `store list`,
`activation issue`, `activation update`, `activation inspect
--update-key-from-store`, `deliver`, `undeliver`, `handover`) takes an
exclusive advisory lock (`flock`) on `admin-store.sxdb.lock` next to the
store, mode 0600, before it asks for a passphrase, and holds it until the
command ends, after its last write. A
second `sxprov` process gets "the admin store is in use by another sxprov
process" with exit code 12 at once; it never waits and never writes. The
lock file holds no data. A lock file left behind after a crash is harmless,
because the kernel drops the lock when its process ends. Never delete the
lock file while a command runs: a second process would then lock a new file
and both could write.

## Delivery

`sxprov deliver` turns a phone that already runs GrapheneOS with a locked
bootloader into a delivered SimpleGo phone. Each step is checked before the
next; any failure stops, prints what was done so far and what to do, and
writes nothing to the store except a record `failed at step N`. The order
follows one rule: **no app is installed before the network lock is
active**, except the lock itself (see "The network lock" and "App link
verification" below). Before step 1 the messenger APK's package is read
and checked against the config (see "The messenger package"):

1. **Device.** Exactly one listed device with `--serial`, in adb state
   `device`. Any other connected device is ignored and never addressed. A
   serial that is missing, listed twice, `unauthorized` or `offline` is
   refused.
2. **Tier.** Hardened tier (default): the same attestation as `verify`
   (`src/verify_run.rs`, the agent is installed and removed again); OS PASS
   is required, the messenger may be absent. Normal tier (`--normal-tier`):
   no attestation, only the Android version and a reachable package manager;
   then the normal-tier warning, naming what is missing (no hardened OS, no
   bootloader lock, no attestation, Google services present), and a typed
   confirmation `NORMAL TIER`. Without a terminal it is refused.
3. **Customer phone.** Every installed messenger counts, whatever its
   package name: this delivery's package and every app that offers the
   activation provider (`dumpsys package providers`, the authority of the
   config's template). For each, `status` is asked: with `setup=done` (a
   customer's installation) the delivery is refused, also with
   `--reinstall`; a messenger under another package is refused (undeliver
   it first); this delivery's package with `setup=open` is refused unless
   `--reinstall`. An installed messenger whose state cannot be read is
   refused.
4. **APK files**, read on the laptop with the Rust reader of `src/apk/`
   (no `apksigner`): package name, version code, SHA-256 of the file, the
   signer certificate digest, and the web link intent filters of the
   manifest (hosts with `android:autoVerify`, see "App link verification").
   The signature block is verified (signature,
   key against certificate, chunked content digest over the whole file);
   scheme v3.1, else v3, else v2; v1-only APKs are refused. The digest must
   equal `messenger_signing_cert_sha256`; while that is empty, only with
   `--accept-unverified-messenger`, and the record and the
   output say `messenger UNVERIFIED`. The Orbot APK is checked the same way
   against `orbot_package` and `orbot_signing_cert_sha256` (`--orbot-apk` is
   refused while that digest is empty). RSA signer keys under 2048 bits are
   verified with ring's legacy PKCS#1 v1.5 verifier and reported with a
   WARNING line: official Orbot releases are signed with the Tor Project's
   RSA 1024 key (`a454b87a...1dfd5b`, the "Tor Project signing key" pinned in
   the Guardian Project's NetCipher `OrbotHelper`). RSA-PSS and keys under
   1024 bits are refused. With `--fdroid-apk`: the F-Droid client APK
   against `fdroid_package` and `fdroid_signing_cert_sha256`, and the SimpleX
   app from SimpleX's repository (index checked, APK downloaded over Tor and
   checked against the index and `simplex_app_signing_cert_sha256`); a phone
   that already has either app is refused here.
5. **App link verification off**: the verifier
   `com.android.statementservice` disabled for user 0, before anything is
   installed (see below).
6. **Orbot install** (optional, `--orbot-apk`): install; notification
   permission granted with `pm grant`, the exact-alarm app op set with
   `appops set org.torproject.android SCHEDULE_EXACT_ALARM allow` and the
   battery exception `dumpsys deviceidle whitelist +org.torproject.android`,
   each checked (Power User Mode needs the first two, and Orbot asks for the
   battery exception; set here, no dialog shows).
7. **The network lock** (with `--fdroid-apk`): Orbot's VPN for the apps
   already on the phone, the always-on VPN with lockdown, proven before any
   other app is installed (see below). Without `--fdroid-apk`, Orbot for
   SOCKS only: Orbot is started and set up for SOCKS only through its screen with `uiautomator dump` and `input tap`, as
   device-tested with Orbot 17.9.8-RC-1 on the Pixel 6a: More tab, Orbot
   Settings, General: Start Orbot on Boot on, Open Proxy on All Interfaces
   off, Power User Mode on (SOCKS and HTTP proxy without the VPN, so no
   system VPN consent dialog); Debug: Tor SOCKS 9050; Connect tab, connect
   switch on; the flow stops if the system VPN consent dialog shows, and
   waits for the status "Connected". Elements are found by resource id or
   text, never by fixed coordinates; a missing element stops with its name.
   A failed screen read (`uiautomator dump` fails while a screen changes) is
   retried. The dump file (`/data/local/tmp/sxprov-ui.xml`) is deleted after
   every read, also after a failed one. Then a listener on `127.0.0.1:9050`
   must show in `/proc/net/tcp` or `tcp6`. There is no manual Orbot step.
   Another Orbot version may change the screens; the flow then stops with
   the name of the missing element. Orbot leaves this flow when the
   messenger carries Tor itself.
8. **Messenger install.** `adb install` (`-r` only with `--reinstall`), the
   package is listed with the file's version code; then the battery
   exception `dumpsys deviceidle whitelist +PACKAGE`, checked in the list
   (`user,PACKAGE,<uid>`).
9. **F-Droid client and SimpleX app** (with `--fdroid-apk`): installed, not
   started; see below.
10. **The two apps added to the network lock's VPN** (with
    `--fdroid-apk`), the lock proven again; see below.
11. **F-Droid client** (with `--fdroid-apk`): see below.
12. **Activation.** The activation file and code are issued with the `issue`
   logic (store and signing key passphrases are asked before step 1, so a
   wrong passphrase stops before anything is written; network mode rules and
   the self-check apply). The provider's `status` decides the transfer:
   - with file import (capability `file_import=yes` in `status`, a
     proposed name not yet confirmed by the messenger): the file over
     standard input with `content write --uri content://AUTHORITY/file`,
     then `activate` with the code; `status` must report the issued
     `file_id` and `network_mode`;
   - without (today's messenger): only the code with `activate`; the
     record says `file_transferred=false`, and the output says that the
     phone uses its built-in servers and that its configuration must reach
     it later (an open point).
   The code goes to the phone only as the `--arg` of that one `content call`.
   It is shown once on the terminal for the activation card, never written
   to disk, never logged, and stored only masked. Every other output line
   has the code and the full serial removed. Accepted for now: during that
   one call the code is briefly visible in the process list of the laptop
   (the adb command line) and of the phone (the `content` command line).
13. **System calculator** (`system_calculator_package`, default
   `com.android.calculator2`): `pm disable-user --user 0`, checked with
   `pm list packages -d`. A missing package stops the hardened tier and is
   a warning in the normal tier.
14. **Final check.** `status` gives `activation=yes` and `setup=open`; the
   battery exception is listed; the calculator is disabled; in the hardened
   tier the agent runs once more and the attestation must give OS PASS
   again. The installed messenger's `base.apk` is pulled into a private
   temporary directory and read with the same Rust reader: its signer must
   equal the file's; the package manager's record (`dumpsys package`) must
   name the same certificate and the file's versionCode. Any difference is
   a failure, never UNVERIFIED. The Orbot
   `base.apk` is checked the same way, and with `--fdroid-apk` the part
   below, the network lock proven a third time, and the app link proof.
15. **Fleet record** in the admin store (record type `deliveries`, see
    "Admin store"), with the messenger package and the sxprov version.

Exit code of a finished delivery: 0 with a pinned and matching messenger
signer, 4 when the messenger is `UNVERIFIED` (as `verify`).

`--dry-run` runs steps 1 to 4 read only (the attestation included; with
`--fdroid-apk` SimpleX's index is checked, the APK is not downloaded, so its
app link hosts are read in a real delivery only), then prints every command
of steps 5 to 14 it would send. It writes nothing to
the phone and nothing to the store, and asks for no passphrase.

`--json` prints one JSON object per line: `step` (with `console_step`
"Orbot" for steps 6 and 7, the first in the operator console's deliver
stepper, and "SimpleX app" for steps 9 to 11), `info` for every text line,
`simplex_index`, `network_lock` (step 7: provider, apps, lockdown, the mode
line), `vpn` (step 10), `app_links` (step 5 and the final check: the
verifier, its state, the host states), `activation_code` (the one event with
the code), `delivered`, `failed`, `record`. A real delivery with `--json` may
write to a pipe (the guided assistant); without it, it needs a terminal.

### The normal SimpleX app

Every delivered phone gets the official, unchanged SimpleX app
`chat.simplex.app`, "the normal SimpleX app for all your SimpleX contacts".
It comes from SimpleX's own F-Droid repository and updates from there with
the F-Droid client, over Tor only. The customer creates the profile; the
delivery creates nothing in it and never starts it. Our messenger stays out
of the VPN, on Orbot's SOCKS port 9050 over loopback. The two apps share
nothing; our app never reads or opens the other one. With `--fdroid-apk
F-Droid.apk` (and `--orbot-apk`, hardened tier only):

- **Step 4.** `F-Droid.apk` (from f-droid.org) with package `fdroid_package`
  and signer `fdroid_signing_cert_sha256`. SimpleX's index, checked in pure
  Rust (`src/fdroid/`): `entry.jar` must hold exactly the manifest, one
  `.SF`, its `.RSA` and `entry.json`; the PKCS#7 signature must use SHA-256
  and RSA (SHA-1 is refused), its certificate must have the SHA-256
  `simplex_repo_fingerprint`, and the signature, the `.SF` and the manifest
  must match down to `entry.json`. Its `timestamp` must not be older than
  the newest one in the admin store (no rollback); an index older than 180
  days gives a warning. `index-v2.json` must have the size and SHA-256 that
  `entry.json` names and name the configured repository. The version is the
  highest versionCode that is not a beta (no release channel, no `beta`,
  `alpha`, `rc` in the name), fits the phone's ABI and SDK and is signed by
  exactly `simplex_app_signing_cert_sha256`; its file name must be a plain
  name. The APK comes over Tor, with the size and SHA-256 of the index, and
  the APK reader then checks package, versionCode and the signer against
  the pin (independently of the index).
- **Step 7**, the network lock (next section): Orbot's VPN for the
  GrapheneOS System Updater and App Store, the consent, lockdown, proven.
- **Step 9.** Only after the lock is proven. A phone that already has
  either app was refused in step 4 (a customer's own SimpleX app is never
  touched; undeliver a test phone first). Both are installed with `adb
  install`, the SimpleX app with `-i org.fdroid.fdroid` so the F-Droid
  client is its installer of record and can update it; both get a battery
  exception; neither is started (`notLaunched=true`).
- **Step 10.** The two apps added to Orbot's "Choose apps" while its VPN
  runs (next section): exactly four apps then, the SimpleX app, the F-Droid
  client, the System Updater (`app.seamlessupdate.client`) and the App Store
  (`app.grapheneos.apps`), any other app unchecked; the lock proven again.
- **Step 11.** Only now the F-Droid client starts for the first time (its
  notification permission granted before with `pm grant`, so no system
  dialog): its own "Connect via SOCKS proxy" set to `127.0.0.1:9050` (a
  second layer; the summary then reads "Uses 127.0.0.1:9050 to connect"),
  then `am start -a android.intent.action.VIEW -d
  'fdroidrepos://app.simplex.chat/fdroid/repo?fingerprint=<pin>'` and one
  tap on the button "Add repository" (the screen's title has the same
  text); the client's one-time hints ("Got it") are closed. The client
  checks the fingerprint itself as well. When the client cannot fetch the
  repository ("Error connecting to the repository", seen on the 6a for the
  first fetch right after the proxy was set), the flow goes back and sends
  the intent again, at most three times. The client fetches the repository
  over Tor, which can take minutes: one timed wait of
  `fdroid_repo_wait_secs` (default 600) covers the repository on the "Add
  repository" screen, the tap, and the repository in the client afterwards;
  when it is not shown 240 seconds after the last intent, the intent is sent
  once more; every 30 seconds a line (with `--json` a `waiting` event with
  `remaining_secs`) gives the time left; at the limit the step fails and
  names how often the intent was sent.
- **Step 14.** Both apps with their pinned signers: the pulled `base.apk`
  read with our APK reader (SHA-256 of the signer equal to the pin), and
  the package manager's own record from `dumpsys package` (its signature,
  Java's `Arrays.hashCode` of the certificate as `signatures:[2136bace]`,
  equal to that of the base.apk's certificate, and the versionCode). The
  agent is not used for them: it may see only the messenger (its
  `<queries>`, Android 11 package visibility). the
  SimpleX app's installer of record and `stopped`/`notLaunched`; the
  network lock proven again (with no mode change since step 7); the
  F-Droid client started afresh (`am start -S`, never through a disguised
  "Calculator" launcher alias), its repository list, and SimpleX's details
  showing the pinned signing key fingerprint. For the report it also lists the established TCP
  connections of our messenger, the SimpleX app and the F-Droid client from
  `/proc/net/tcp` and `tcp6` (to `127.0.0.1:9050`, and to other addresses,
  which for the two apps run inside the VPN).
- The fleet record keeps the versions, APK SHA-256 and signers of both apps,
  the installer, the repository with its index time and SHA-256, the VPN
  app list, consent, always-on and lockdown, and the settings found before.

The betas: the customer's F-Droid client may later offer versions SimpleX
publishes without a release channel (betas); that is accepted. The
f-droid.org repository stays enabled in the client (its own SimpleX build is
signed by another key, so the client never crosses over).

What is not checked: the activation file's content on the phone when the app
has no file import (today); that Orbot keeps running after a reboot (never
rebooted here; GrapheneOS asks for the PIN before adb after a reboot); the
messenger's release signing identity (not pinned yet).

### The network lock

The rule since 2026-11-25: **no app is installed before the network lock is
active**, except the lock itself. The lock is the system's always-on VPN
with "Block connections without VPN" (lockdown): every app uid outside the
VPN has no network, the apps inside it go through Tor. Its provider today is
Orbot (`src/deliver/lock.rs`, `Provider::Orbot`). When our messenger carries
Tor itself, Orbot leaves the delivery and another
provider takes its place in that module; the order of the delivery does not
change. Why: an app installed with the network open is announced to the
clear net by Android's app link verification (next section), as an
earlier test delivery showed.

- **Step 4.** The lock provider is installed before the lock, so its APK may
  declare no `autoVerify` web host and no unresolved reference (Orbot
  17.9.8 declares none). Without a lock (no `--fdroid-apk`: Orbot for SOCKS
  only, or no Orbot) an APK with `autoVerify` hosts is refused; the
  messenger declares none.
- **Step 7.** The VPN consent as the app op `ACTIVATE_VPN allow` before
  Orbot starts (no system dialog; the flow stops if the dialog shows);
  Power User Mode off (it means "without the VPN"), start on boot on, open
  proxy off, SOCKS 9050; on "Choose apps" exactly the apps already on the
  phone that go through Tor, the GrapheneOS System Updater and App Store;
  connect. On the real screens (Pixel 6a, 2026-11-24) "Choose apps" is
  tapped on its label, the apps are found with the list's search field (the
  list is alphabetical, chosen apps are not moved to the top), and the list
  is left with "Navigate up" (the back key only closes the keyboard). Then
  Settings > VPN (opened in a fresh task) > Orbot's gear: "Always-on VPN"
  and "Block connections without VPN" on, confirming "Require VPN
  connection?" with "Turn on" (`settings put` of these keys has no run-time
  effect, tested on the 6a). Then the **proof**, before anything else is
  installed:
  - `settings get secure always_on_vpn_app` is Orbot and
    `always_on_vpn_lockdown` is `1`;
  - the newest `[LockdownAlwaysOn] Mode changed` line of `dumpsys
    vpn_management` reads `lockdown=true alwaysOn=true`; it is kept as the
    baseline;
  - the "Lockdown filtering rules" of `dumpsys connectivity` block every app
    uid of `pm list packages -U` except Orbot's;
  - `dumpsys connectivity` shows a connected VPN owned by Orbot that carries
    exactly the uids of the wanted packages (found by name; the apps' SDK
    sandbox uids, app id 20000 to 29999, count as the apps);
  - `127.0.0.1:9050` listens.

  Not proven: the delivery stops at step 7 (exit 17), nothing else was
  installed. Our messenger is among the blocked uids and reaches Orbot over
  loopback.
- **Step 10.** After the installs, the F-Droid client and the SimpleX app
  are added on Orbot's "Choose apps" while its VPN runs. Orbot saves the
  list and restarts its VPN with it (`RESTART_VPN`: the tun is closed and set
  up again); the always-on VPN and lockdown are the system's and stay, and
  during the gap lockdown blocks every app. The proof runs again with the
  four apps, and no mode change line may be newer than the baseline of step
  7. It runs a third time in the final check.
- The record keeps `lock`: the provider, the apps at the lock, the mode line,
  and whether the proof after the apps passed.

### App link verification

When an app with `android:autoVerify` web intent filters is installed,
Android's verifier `com.android.statementservice` fetches
`https://HOST/.well-known/assetlinks.json` for each host. The SimpleX app
declares 22 hosts (`simplex.chat`, `smp*.simplex.im`,
`smp*.simplexonflux.com`), the F-Droid client 4 (`f-droid.org`,
`staging.f-droid.org`, `cloudflare.f-droid.org`, `fdroid.link`); the
messenger, Orbot and the agent declare none. Under lockdown the verification
does not fail, it waits: JobScheduler never bypasses the lockdown block, and
the queued work runs as soon as the verifier's uid has a network again (from
the GrapheneOS sources, branch `17`, and the 6a).

- **Step 4** reads each APK's hosts (`apk inspect` prints them too). The
  attestation agent is read before step 1, because step 2 installs it before
  the lock: an agent with any `autoVerify` host or an unresolved reference
  is refused (exit 16).
- **Step 5** disables the verifier for user 0 before anything is installed
  (`pm disable-user --user 0 com.android.statementservice`, checked with `pm
  list packages -d`). A phone that refuses it stops here (exit 17), nothing
  installed. Already disabled: left so, and `undeliver` leaves it so. Not on
  the phone: noted.
- **Final check:** `pm get-app-links --user 0 PKG` for every installed app
  with hosts: no host may be `verified` or `approved` (that would mean the
  fetch went out: exit 18). The verifier must still be disabled and have no
  TCP socket outside loopback (exit 18). Its jobs and its uid's network
  state from `dumpsys jobscheduler com.android.statementservice` are
  recorded as read.
- The record keeps `app_links`: the verifier, whether this delivery disabled
  it, the hosts per APK, their states, the jobs and sockets.

With the verifier disabled, app links of every app on the phone open in the
browser or a chooser instead of the app itself.

### Test deliveries

`--test-delivery` is for the operator's own test phones only. It needs
`allow_test_key_for_test_deliveries = true` in a throwaway test config and
the TEST ONLY key; every other key is refused, and a real delivery refuses the
TEST ONLY key. Only then the passphrases come from
`--test-store-passphrase-file` and `--test-key-passphrase-file` (one line,
mode 0600), `--yes` replaces the typed confirmations (never the `STALE`
confirmation of the revocation list), and the code is printed to standard
output. The record is marked `test`. A throwaway test store is created with
`sxprov store init --test-delivery --test-store-passphrase-file FILE`.

### `undeliver` (test phones only)

    sxprov undeliver --serial SERIAL --test-device [--discard-test-setup] [--json] \
        [--test-delivery --test-store-passphrase-file FILE]

`undeliver` refuses without `--test-device`. It reads the store, so without
a terminal (a test run, the operator console) it needs the test flags of a
test delivery: `--test-delivery` with `--test-store-passphrase-file FILE`
(the throwaway test store of the test delivery). It works only while the
messenger reports `setup=open`; that is read before anything is changed. In
this order:

1. the messenger's state (`setup=done` refused, unless `--discard-test-setup`);
2. every app with `autoVerify` web hosts that this delivery installed (the
   SimpleX app, the F-Droid client) uninstalled **while lockdown still
   holds**, so a verification waiting since its install cannot go out;
3. the always-on VPN and its lockdown off in Settings (back to what the
   delivery found);
4. the messenger uninstalled (the battery exception goes with it);
5. Orbot uninstalled only if the record says this delivery installed it (an
   Orbot that was there before gets its VPN consent app op, its switches and
   its app list back as found); Settings must no longer name Orbot as the
   always-on VPN;
6. the system calculator enabled again;
7. the app link verifier enabled again (`pm enable --user 0
   com.android.statementservice`), last, if this delivery disabled it. The
   output says that link verification works again only after the next
   reboot: Android looks the verifier up once, at boot.

Each step is checked; the record is marked `undone`.

`--discard-test-setup` (test only) also undoes a test phone whose messenger
was set up (`setup=done`), for instance to deliver it again. It is refused
unless all of these hold: `--test-device`; a throwaway test config
(`allow_test_key_for_test_deliveries = true`); the record is a test
delivery; the store holds only test deliveries and issues signed with the
TEST ONLY key (never the real store); the record's activation is in the
store as signed with the TEST ONLY key. Before anything is removed it prints
which app data goes: the messenger's profile on the phone (its app data is
deleted with the uninstall). It asks for nothing beyond the test flags above.
Without it, `setup=done` stays refused.

### `handover`

`sxprov handover --serial SERIAL` is separate on purpose, because it ends adb
access. It needs a delivered record and `status` `activation=yes
setup=open`, shows the record, asks for `HANDOVER` typed in full, runs
`settings put global adb_enabled 0`, and then requires that the device drops
out of `adb devices` or goes offline. The time is recorded. Tested only
against the fake adb.

### Open points

- The messenger's release signing identity is not pinned yet, so
  deliveries need `--accept-unverified-messenger` and say `UNVERIFIED`.
- File transfer at provisioning: the capability name in `status` and the
  transport are proposals until the messenger confirms them; today's
  messenger is activated with the code only. An update file cannot reach a
  phone activated with the code only, because an update needs the update key
  that only the activation file import stores (format section 5 and 6);
  how such a phone gets its first configuration is open.
- Source archives (AGPL corresponding source of what a phone receives) are
  not built here; each record keeps the versions and SHA-256 values of the
  messenger and Orbot APKs they need.
- Orbot leaves the delivery once the messenger carries Tor itself.

## GrapheneOS

### Channel files and the security preview

GrapheneOS publishes one channel file per device and channel on
`https://releases.grapheneos.org` (`grapheneos_release_base`):
`<codename>-<channel>`, for example `bluejay-stable`, one line
`VERSION BUILD_TIME CODENAME CHANNEL`:

    2026111800 1794968526 bluejay stable

`BUILD_TIME` is in Unix seconds and equals `ro.build.date.utc` of that build
on a phone. Next to it, `<codename>-<channel>-security-preview` names the
security preview build of the release (all AOSP patches of the coming
bulletins, published by GrapheneOS as a separate signed build):

    2026111801 1794968527 bluejay stable-security-preview

This file is not described on grapheneos.org; it was found on 2026-11-24 next
to the documented ones (same host and format, channel field
`stable-security-preview`) and names exactly the build the Pixel 6a received
(`ro.build.date.utc` 1794968527). A 404 means "no security preview build"; the
release is used then. The images are always checked by signature, so the
channel files only choose a version.

The channel files are not signed; only Tor protects them. They are fetched
through `tor_socks_proxy` only and cached in `grapheneos_cache_dir/channels/`
with their fetch time. Every output names the source and the fetch time;
offline (`--offline`, or Tor not reachable) the cached copy is used and its
age shown.

`grapheneos_release` decides which build counts as current and is flashed
by default: `newest` (default: the security preview when there is one, not
older than the release) or `stable` (the release only).

### `os status`

    sxprov os status --serial SERIAL [--channel stable] [--offline] [--json]

Read only. Shows the codename, the installed version
(`ro.build.version.incremental`), its build time and **build type**
(`release`, `security preview`, `not in the current channel files`, or
`not GrapheneOS` with the OS the phone reports), the patch level, the
bootloader lock (reported), OEM unlocking (read from the Developer options
screen; `getprop sys.oem_unlock_allowed` is not readable by the shell), both
channel files with source and fetch time, and the result:

- `up to date`, `up to date (security preview)`, or with
  `grapheneos_release = stable` `up to date (security preview, newer than stable)`
- `update available (N days behind): <type> <version>`
- `unknown (offline)` (no Tor and nothing cached), `not GrapheneOS (...)`

Everything here is reported by the phone; `verify` proves the OS. The same
status lines appear in `verify` (and `"os_status"` in `verify --json`) and in
`deliver`, its dry run included. `deliver` refuses a phone that is more than
`max_os_age_days` (default 30) behind the stable channel unless
`--allow-outdated-os`; an unknown status is shown, not refused. The delivery
record keeps the version, build type and status.

Exit codes: 0 up to date, 27 update available, 28 unknown or not GrapheneOS.

### `os fetch`

    sxprov os fetch --device CODENAME [--channel stable | --version VERSION]

Downloads `CODENAME-install-VERSION.zip` and its `.sig` over Tor into
`grapheneos_cache_dir/VERSION/`. Without `--version` the version comes from
the channel files and `grapheneos_release`. The signature is checked in pure
Rust, streamed (SSHSIG, namespace `factory images`, principal
`contact@grapheneos.org`, SHA-512) against the key pinned in
`trust/grapheneos/allowed_signers`, the same key that signs the attestation
key list (identical on releases.grapheneos.org, grapheneos.org and the
website source on GitHub, checked 2026-11-23). It is never taken from the
download. Equivalent manual check:

    ssh-keygen -Y verify -f trust/grapheneos/allowed_signers -I contact@grapheneos.org \
        -n "factory images" -s FILE.zip.sig < FILE.zip

The download goes to `.zip.part` and resumes there (HTTP Range); a broken
transfer is retried five times and can be resumed by running the command
again; a server that ignores the range restarts cleanly from 0. A stalled
transfer (see "Downloads over Tor") is not retried beyond its three attempts. Only a
verified image gets its final name and a `.verified.json` (SHA-256, size,
time, source). A failed signature deletes the zip and the signature and
stops. A zip already in the cache but not yet verified is checked, not
downloaded again.

### `flash`

    sxprov flash --serial SERIAL [--channel stable | --version VERSION] [--test-device] [--yes] [--dry-run]

Installs GrapheneOS on one phone with the **official `flash-all.sh` of the
verified image, unchanged**. `sxprov` prepares, selects the phone with
`ANDROID_SERIAL`, watches and checks; the flash sequence is the script's.
fastboot 35.0.1 or newer is needed (`fastboot_path`).

Order, each step checked before the next:

1. One device with this serial in adb state `device`; its codename must have
   a pinned GrapheneOS verified boot key (today `bluejay`, from the official
   install guide); refused if the admin store has a delivery record for the
   phone (unless `--test-device`) or the messenger reports `setup=done`
   (always). The status lines show the phone's current version.
2. What will happen, in plain words: the phone is wiped completely, twice.
   Typed `WIPE`; `--yes` replaces it only together with `--test-device`.
3. The image present and verified, otherwise fetched (`os fetch`).
   `--dry-run` stops here and prints the plan; nothing is stored.
4. OEM unlocking: read on the Developer options screen and, if off, turned
   on there (row tap, then the dialog's Enable; elements by text or resource
   id, each dump deleted on the phone). If the phone asks for its PIN or the
   switch is greyed out, nothing is typed: **manual step**: "On the phone:
   open Settings > System > Developer options and turn on "OEM unlocking"
   (enter the phone's PIN if it asks, then tap Enable)." The tool waits for a
   typed `DONE` (without a terminal it stops) and reads the switch again.
5. `adb reboot bootloader`, then the serial must show in `fastboot devices`;
   refused if more than one device is in fastboot mode; `getvar product`
   must be the image's codename.
6. If locked: `fastboot flashing unlock`, then **manual step**: "On the
   phone: press volume down to select Unlock the bootloader, then press
   power." `getvar unlocked` is polled until `yes`, for
   `flash_confirm_timeout_secs` (default 900 seconds); every 30 seconds a
   line (and with `--json` a `waiting_for_user` event, action
   `press_volume_down_unlock`) gives the time left.
7. The signature is checked again, the zip is unpacked (streamed, each entry
   checked against its CRC-32, names only inside
   `<codename>-install-<version>/`), and `bash flash-all.sh` runs there with
   `ANDROID_SERIAL` set, standard input closed, `TMPDIR` on disk, and its
   output in `flash_log_dir` (every serial masked). The phone is not touched
   while it runs. On success the unpacked copy is removed; after a failure it
   is kept for a manual run.
8. `fastboot flashing lock`, then **manual step**: "On the phone: press
   volume down to select Lock the bootloader, then press power." Polled
   until `unlocked: no`, with the same time limit and reports (action
   `press_volume_down_lock`).
9. **Manual step**: start the phone (Start is selected, press power),
   complete the setup and leave the preset switch on the last setup screen
   as it is, so that OEM unlocking is turned off again; enable Developer
   options (Settings > About phone > tap Build number 7 times), turn on USB
   debugging and allow this computer. The tool waits (up to 60 minutes,
   reports every 30 seconds, action `complete_phone_setup`) until the phone
   is in adb state `device`.
10. The same attestation as `verify`: OS PASS, the verified boot key equal to
    the GrapheneOS key for this codename, the installed version equal to the
    flashed one, the bootloader locked. A `flashes` record goes into the
    admin store (codename, old and new version and build type, image
    SHA-256, verified boot key, result, times per part; the serial only
    inside the encrypted store).

A failure prints what was done, the state of the phone and what to do next
(for example "STILL UNLOCKED: run fastboot -s <serial> flashing lock").
`--json` prints one JSON object per line (`step`, `info`, `operator`,
`waiting_for_user` with `action`, `remaining_secs` and `message`,
`os_status`, `target` with the build type, `resume`, `script`, `flashed` or
`failed`, `record`).

**`flash --resume`** continues from a phone that is already in fastboot mode,
for example after an unlock confirmed on the phone after `flash` gave up.
Before anything is written: exactly one device in fastboot mode and it is
`--serial`; its `product` has a pinned key and is the image's codename; no
delivery record unless `--test-device`; the typed `WIPE` (or `--yes` with
`--test-device`); the image already verified in the cache (`--resume`
downloads nothing; run `os fetch` first). Then `getvar unlocked` decides:
unlocked continues at step 7 (the official script), then 8 to 10; locked
after a run of this version that failed at step 8 or 9 (the lock confirmed
late, or the setup wait ran out) continues at step 9; locked otherwise
continues at step 6 (the unlock wipes the phone). The run writes a normal
`flashes` record with `resumed_at_step`.

**How the script runs.** The script calls plain `fastboot`. A private folder
first in `PATH` holds that `fastboot`:

- Debian laptop: a link to `fastboot_path` (Google's platform-tools r35.0.2
  or newer, checked against the SHA-256 the GrapheneOS guide publishes:
  Debian 13's `fastboot` 1:34.0.5 is too old). Keep
  `android-sdk-platform-tools-common` for the udev rules, and stop `fwupd`
  before flashing (`sudo systemctl stop fwupd.service`; it claims fastboot
  devices).
- WSL2 with the Windows `fastboot.exe`: a stand-in, because
  `fastboot.exe` prints CRLF and the script's own checks would read the
  product as `bluejay\r` and stop. The stand-in runs `fastboot.exe` with the
  same arguments and environment, removes only the `\r` from its standard
  output and standard error (kept apart) and exits with fastboot's exit code.
  `WSLENV` passes `ANDROID_SERIAL` to the Windows process.
  `grapheneos_cache_dir` must be on a Windows drive (`/mnt/c/...`) so that
  `fastboot.exe` reaches the image files.

Exit codes 21 to 26, see "Exit codes".

### `config show` and `config set`

    sxprov config show [--json]
    sxprov config set KEY VALUE [--json]

The settings the assistant shows on its settings page: `grapheneos_release`,
`grapheneos_channel`, `tor_socks_proxy`, `adb_path`, `fastboot_path`,
`grapheneos_cache_dir`, `max_os_age_days`, `flash_confirm_timeout_secs`,
`orbot_package`, `orbot_signing_cert_sha256`, `fdroid_package`,
`fdroid_signing_cert_sha256`, `simplex_repo_url`, `simplex_repo_fingerprint`,
`simplex_app_package`, `simplex_app_signing_cert_sha256`,
`system_calculator_package`. `show --json`
lists each with its value, whether the file sets it (else the default
applies), its type and allowed values. `set` checks the value (choice,
`socks5h://HOST:PORT`, 64 hex digits, package name, whole days, no control
characters, seconds from 60 to 86400, an `https://` URL without a trailing
slash), then parses and validates the whole config with it as `sxprov`
loads it, and only then writes the file (temporary file and rename, same
mode, other lines and comments kept). A refused value changes nothing. No
other key can be set this way, and the config holds no secret.

## Device classes

- **Hardened Pixel.** The device reports manufacturer Google, or its
  attestation shows `SelfSigned` or a GrapheneOS key. It gets the full
  verification above.
  - An unlocked Pixel, or a Pixel on the stock OS, is a hardened-tier FAIL
    with the reasons.
  - It is never silently treated as a normal phone.
- **Normal phone.** Any other device. Only the basic checks run: model,
  Android version, and whether the messenger is present with its signature.
  - The result label is `NORMAL-TIER: basic checks only`, never PASS.
  - The warning in `src/warning.rs` is printed with it. The later install
    flow reuses that text.

## Trust material

- `trust/google-roots/` holds the Google attestation roots: four RSA
  certificates sharing one key, and the ECDSA P-384 root from 2025.
  - They are committed and embedded into the binary.
  - `SOURCES.md` lists the source URLs and SHA-256 values.
  - The chain root is matched by public key.
- `trust/grapheneos/allowed_signers` is the GrapheneOS public signing key.
  It is committed and embedded.
- The trust cache (`trust_cache_dir`, outside the repository, mode 0700)
  holds the two lists. Each file has a `.meta.json` with the fetch time, the
  HTTP `Last-Modified`, the SHA-256 and the source.

`trust refresh` fetches the lists only through `tor_socks_proxy`, which must
be a `socks5h://` URL so DNS also goes through Tor. There is no clearnet
fallback. Until the proxy is known, `tor_socks_proxy` may hold a marked
placeholder (`REPLACE_...`): the other commands work, and `trust refresh`
refuses to run.

### Downloads over Tor

Every download (`trust refresh`, the GrapheneOS channel files and factory
images, SimpleX's index and APK) goes through `tor_socks_proxy` with a fresh
SOCKS username and password per request, so Tor puts it on a circuit of its
own. There is no total time limit (an image is 2 GB), but an idle limit: when
no byte arrives for `download_idle_timeout_secs` (default 120), that attempt
is given up and the download continues on a new circuit from the byte it
reached (HTTP Range), at most three attempts in all; then it fails with "stalled
over Tor", the URL and the byte. A request without an answer (connect 60 s,
response 180 s) is tried again the same way. A refused connection to the
proxy (Tor not running) fails at once.

- The GrapheneOS list is accepted only with a valid SSHSIG signature
  (namespace `attestation keys`), and only if it is not older than the cached
  list.
- On any failure the previous copy stays.

`trust import DIR` takes lists that an operator placed by hand, for example
when no Tor proxy runs. `DIR` holds `status.json` (the Google status list),
`attestation.json` and `attestation.json.sig`; the usual place is
`manual-trust/` in the local folder (see [DEVELOPMENT.md](DEVELOPMENT.md)).

- The same checks as for a download apply: the signature and rollback check
  for the GrapheneOS list, and parsing for the revocation list.
- The source is recorded and shown as "manually placed".
- The age counts from the file's modification time.
- `Last-Modified` is taken from `<file>.headers.txt` next to the file, if
  present (the response headers saved with `curl -D`); otherwise it is shown
  as unknown. For example, through the Tor Browser's SOCKS port:

      curl.exe --proxy socks5h://127.0.0.1:9150 -fsS -D status.json.headers.txt -o status.json https://android.googleapis.com/attestation/status

Age rules:

| List | Missing | Over threshold |
|---|---|---|
| Google revocation list | `verify` refuses | Older than `revocation_max_age_days` (default 7): warning, and the operator must confirm (type `STALE`, or pass `--confirm-stale-revocation-list`). A PASS then carries the label "based on a STALE revocation list" and `"stale_revocation_list": true` in `--json`. |
| GrapheneOS key list | `verify` refuses | Older than `grapheneos_keys_warn_age_days` (default 90): warning only. |

There is never a PASS without a revocation check. `trust status` and every
`verify` show the source and age of both lists.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; for `verify`: full PASS |
| 1 | `verify`: FAIL |
| 2 | usage error |
| 3 | config missing or invalid |
| 4 | `verify`: UNVERIFIED, including "OS PASS, messenger UNVERIFIED" |
| 5 | `verify`: UNKNOWN DEVICE |
| 6 | `verify`: NORMAL-TIER, basic checks only |
| 7 | trust material missing or invalid; verification refused |
| 8 | device or tool error (adb or fastboot missing, no device, agent failure) |
| 9 | stale revocation list not confirmed |
| 10 | `trust refresh` or `trust import` failed |
| 11 | `activation inspect`: the file is refused (structure, untrusted key, signature, code, payload) |
| 12 | admin store missing, wrong passphrase, damaged, path inside a git repository, in use by another sxprov process, or a write failed |
| 13 | signing key unreadable, not Ed25519, not passphrase protected, wrong passphrase, or the TEST ONLY key |
| 14 | `activation issue` or `update`: invalid servers or support file, network mode rule broken, unknown customer, output file exists, or no terminal for the code; `activation inspect`: unreadable file, or an update key file that is readable by others or not 64 lowercase hex characters |
| 15 | `deliver`: refused before anything was written to the phone: device not found, listed twice or not in state `device`; attestation without OS PASS; messenger set up by a customer (`setup=done`), another messenger installed, or this delivery's messenger installed without `--reinstall`, or a state unreadable; normal tier not confirmed or no terminal for the confirmation; no terminal for the code (real delivery) |
| 16 | `deliver`: an APK file is refused (unreadable, a messenger package the config does not allow, signature block invalid, wrong package, signer not the configured one, messenger signer not pinned without `--accept-unverified-messenger`, `orbot_signing_cert_sha256` empty; with `--fdroid-apk`: the F-Droid client or SimpleX APK, SimpleX's index (fingerprint, signature, rollback, size and digest), or Tor missing); `apk inspect`: the file is refused |
| 17 | `deliver`: a write step on the phone failed (the app link verifier not disabled, install, battery exception, Orbot, the network lock not proven, the F-Droid client or SimpleX app, Orbot's VPN and its app list, the VPN consent, port 9050, the lockdown, the F-Droid client's set-up, activation, system calculator) |
| 18 | `deliver`: every write step ran, but the final check failed (status, battery exception, calculator, installed signer through the package manager or `base.apk` differs from the file, attestation after the install, the network lock, an app link host verified or approved, the verifier enabled again or with a socket outside loopback) |
| 19 | `undeliver`: refused (no `--test-device`, no record, `setup=done` without `--discard-test-setup`, a refused `--discard-test-setup`, state unreadable) or a step failed |
| 20 | `handover`: refused (no delivered record, not confirmed, no terminal, status not `activation=yes setup=open`) or the device still answers over adb |
| 21 | `flash`: refused before anything changed on the phone (device not found or not in state `device`, codename without a pinned GrapheneOS key, a delivery record without `--test-device`, a messenger with `setup=done`, `WIPE` not typed) |
| 22 | `os fetch` or `flash`: no channel file, download failed, signature check failed (the file is deleted), image cannot be unpacked |
| 23 | `flash`: OEM unlocking is off and could not be turned on |
| 24 | `flash`: a bootloader step: reboot into the bootloader, the phone not in fastboot or another device in fastboot mode, unlock or lock not confirmed in time, the phone not back over adb after the setup |
| 25 | `flash`: the official flash script failed |
| 26 | `flash`: the attestation after the flash failed (no OS PASS, another verified boot key, another version, not locked) |
| 27 | `os status`: an update is available |
| 28 | `os status`: unknown (offline, nothing cached) or not GrapheneOS |

The source of truth is `src/exit.rs`.

## Configuration

Copy `config/provisioning.example.toml` to `config/provisioning.toml`. That
file is git-ignored. It holds:

- the agent signing certificate digest, package and APK path
- the messenger: optionally a fixed `messenger_package`, a
  `messenger_package_pattern`, the provider authority template
  `messenger_provider_authority` (default `{package}.activation`), and the
  signing digest `messenger_signing_cert_sha256` (empty until the release
  signing identity exists; see "The messenger package")
- the Tor SOCKS proxy
- the trust cache directory
- the two age thresholds
- `adb_path` and `fastboot_path`
- `admin_store_path` (optional): the encrypted admin store
- `system_calculator_package` (default `com.android.calculator2`): the
  calculator `deliver` hides
- `orbot_package` (default `org.torproject.android`) and
  `orbot_signing_cert_sha256` (empty: `deliver --orbot-apk` is refused)
- `allow_test_key_for_test_deliveries` (default false): only in a throwaway
  test config, see "Test deliveries"
- `grapheneos_release_base` (default `https://releases.grapheneos.org`),
  `grapheneos_channel` (`stable`), `grapheneos_release` (`newest` or
  `stable`, default `newest`), `grapheneos_cache_dir` (default
  `~/.cache/simplego-provisioning/grapheneos`), `max_os_age_days` (30),
  `flash_log_dir` (default `logs` in the cache folder),
  `flash_confirm_timeout_secs` (900): see "GrapheneOS"
- `download_idle_timeout_secs` (120, 10 to 3600): see "Downloads over Tor"
- `fdroid_package` (`org.fdroid.fdroid`), `fdroid_signing_cert_sha256`,
  `simplex_repo_url` (`https://app.simplex.chat/fdroid/repo`),
  `simplex_repo_fingerprint`, `simplex_app_package` (`chat.simplex.app`),
  `simplex_app_signing_cert_sha256`, `fdroid_repo_wait_secs` (600, 60 to
  3600): the normal SimpleX app (see
  "Delivery"). The defaults are the pins confirmed on 2026-11-24, each from
  two official sources (the F-Droid client signer: f-droid.org's signing
  keys page and F-Droid's `ClientWhitelist.java`; the app signer: SimpleX's
  signed index and `SIMPLEX_KEY` in SimpleX's reproducible-build script).
  The repository fingerprint has one document on two channels
  (simplex.chat/fdroid and its source on GitHub), and equals the
  certificate the repository signs with; the app signer pin is the hard
  check. An empty pin refuses `--fdroid-apk`.

adb and fastboot are not bundled. The tool uses the ones installed on the
machine, and `devices` reports their versions. An empty `fastboot_path`
disables fastboot: no fastboot command is run.

On a WSL2 development machine with the phone attached to Windows, set `adb_path` to the
Windows adb (`/mnt/c/Users/<user>/AppData/Local/Android/Sdk/platform-tools/adb.exe`).
When `adb_path` ends in `.exe` and the tool runs in WSL, the agent APK path is
converted with `wslpath -w` for `adb install`.

On the Debian admin laptop (Debian 13): adb comes from Debian (`adb`, `android-sdk-platform-tools-common`), so
`adb_path = "/usr/bin/adb"`. Debian's `fastboot` (1:34.0.5) is too old for
`flash`; `fastboot_path` points to Google's platform-tools (see "GrapheneOS",
`flash`). The
working user must be in `plugdev` (effective after the next login). Give
`sxprov` a Tor SOCKS port of its own, with `IsolateDestAddr`, apart from the
port other programs use, and set `tor_socks_proxy` to it (for example
`socks5h://127.0.0.1:PORT`). A Tor kill switch must let local programs reach
it over loopback.

Relative paths in the config (`agent_apk`, `trust_cache_dir`) are resolved
against the current directory, so a test package can keep everything in its
own folder and run `sxprov` from there.

