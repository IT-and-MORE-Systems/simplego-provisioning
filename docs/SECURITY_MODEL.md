# Security Model

What SimpleGo Provisioning proves, what it relies on, and what it does not
protect. The exact checks and their messages are in [USAGE.md](USAGE.md).

## Assets

- The customer's phone: that it runs an untouched GrapheneOS with a locked
  bootloader, carries the right apps signed by the right keys, and never
  reached the network outside Tor during the delivery.
- The customer's configuration: servers, support address and network mode,
  delivered only to that customer's installation.
- The operator's secrets: the activation signing key, the customers' update
  keys and the fleet records in the admin store, and the store's backups.
- The operator's network identity: every download goes over Tor.

## Threats considered

- A phone that lies: a modified OS, an unlocked bootloader, a leaked or
  revoked attestation key, a replayed attestation, or an agent that is not
  ours.
- A wrong APK: swapped, repackaged, signed by someone else, or replaced on
  the phone after the check.
- The network: tampered downloads, a stale or rolled-back key list or index,
  clearnet leaks of the operator's address, and an app announcing itself to
  the clear net while it is installed.
- A forged, altered or replayed activation or update file, or a
  configuration that would make an app connect outside Tor.
- A lost or copied admin laptop, and a lost or damaged admin store.
- An operator mistake: the wrong phone, a customer's phone, a second
  process writing the store.

## Attestation

- A fresh 32-byte random challenge per run; the agent generates a
  hardware-backed key (StrongBox, else TEE) with it and returns the chain.
- The chain must verify up to one of the pinned Google roots (matched by
  public key), every certificate within its validity, no serial on Google's
  revocation list (hex and decimal). There is never a PASS without a
  revocation check; a list older than `revocation_max_age_days` needs the
  operator's confirmation and the PASS says so.
- The KeyDescription (parsed by our own strict DER reader) must carry this
  run's challenge, security level TEE or StrongBox, `deviceLocked`,
  `SelfSigned` and a verified boot key from the GrapheneOS key list. The list
  is accepted only with a valid SSHSIG signature by the pinned GrapheneOS key
  (namespace `attestation keys`) and never older than the cached copy. A key
  that is not listed gives UNKNOWN DEVICE, never PASS.
- `attestationApplicationId` must name the agent package with exactly the
  pinned agent signing digest, so a different app cannot answer in the
  agent's place.
- What the phone reports through adb (model, build, bootloader properties,
  the GrapheneOS hint) is shown as reported and never decides a PASS.

## APKs

- Every APK is read on the laptop with our own reader before it is
  installed: the signing block (v3.1, else v3, else v2; v1-only refused),
  the signature, the key against the certificate, and the chunked content
  digest over the whole file. The signer must equal the pin of its role
  (messenger, Orbot, F-Droid client, SimpleX app, agent).
- The SimpleX app comes from SimpleX's own F-Droid repository: the signed
  index (PKCS#7 with SHA-256 and RSA, the pinned repository fingerprint,
  rollback protection) names the file's size and SHA-256; the APK's signer is
  checked against its own pin independently of the index.
- After the install, every installed `base.apk` is pulled and read again,
  and the package manager's own record (`dumpsys package`: the certificate's
  hash and the versionCode) must name the same certificate. A difference is a
  failure, never UNVERIFIED. The agent never reads other apps; it has no
  package visibility.

## The network lock

The rule: **no app is installed before the network lock is active**, except
the lock itself.

- The lock is the system's always-on VPN with "Block connections without
  VPN" (lockdown); its provider today is Orbot. Every app uid outside the VPN
  has no network; the apps inside it go through Tor.
- It is proven at run time before anything else is installed: the settings,
  the newest lockdown mode change in `dumpsys vpn_management`, the lockdown
  filtering rules of `dumpsys connectivity` (every app uid blocked except the
  provider's), the VPN's owner and its exact list of app uids, and the SOCKS
  listener. Not proven: the delivery stops with nothing else installed.
- It is proven again after the apps are added to the VPN and in the final
  check, with no mode change since the first proof.
- The lock provider itself is installed before the lock, so its APK may
  declare no `autoVerify` web host.

## App link verification

Android's verifier (`com.android.statementservice`) fetches
`/.well-known/assetlinks.json` from every `autoVerify` web host of an app at
install time, outside any app's control. The delivery disables the verifier
for user 0 before anything is installed, reads every APK's hosts on the
laptop, refuses an agent or a lock provider that declares any, and proves in
the final check that no host was verified or approved and that the verifier
has no socket outside loopback. `undeliver` removes those apps while lockdown
still holds and enables the verifier again last.

## Activation and update files

- One app build serves every customer; each installation gets its
  configuration from one `.sxact` file, signed with Ed25519 by the
  operator's activation signing key and encrypted with AES-256-GCM.
- An activation file is encrypted under a key derived with Argon2id (64 MiB,
  3 passes) from the activation code, two six-digit numbers and an operator
  that travel on the activation card, apart from the file. The code is shown
  once, never written to disk or logged, and stored only masked.
- An update file is encrypted under the customer's update key, carries the
  next sequence (no replay), and may rotate the update key.
- The apps trust a list of activation keys, check the signature before they
  decrypt anything, and apply strict rules to every address: valid v3 onion
  names, fingerprints that are server key hashes, and the network mode
  (`tor_required`, `tor_optional`, `direct`) checked for every server and
  every queue of the support address. `issue` checks the same rules and reads
  the file back with the apps' reader before it is written.
- The TEST ONLY key that signs the test vectors is refused for issuing by its
  key id; release builds of the apps must not trust it.

## Feature profile and customer directory

- Both are optional objects inside the signed and encrypted payload (format
  section 12), so nobody without our signing key can add, change or remove
  a switch or a group, and nobody without the code or the update key can
  read them.
- Inside both objects the rules fail closed: an unknown name, value or
  field, a duplicate key, `null` or an array instead of an object refuses
  the whole file, so an app never silently skips a switch or a group. An
  app built before section 12 would ignore both objects (unknown top-level
  fields are ignored), so no app may report the file import to `sxprov`
  before it implements section 12, and `deliver` refuses a fixed profile or
  a directory entry when the app does not report the file import, before
  anything is issued.
- `off` means off in the app's backend, not only hidden; `deliver` compares
  the `features_profile` and `features_fixed` the app reports with what it
  issued and fails on a difference.
- Group links are accepted only as short links whose server is one of the
  customer's SMP servers in the same file, and they follow the network
  mode rule, so a directory can never send a device to a server that is
  not the customer's or around Tor. The SimpleX core joins on the link's own
  server.
- Display names and group names must be valid SimpleX names, so the set-up
  on the device cannot fail on a name after the import.
- What our side keeps: the feature profile per customer and device class,
  and per customer set only a random `set_id`, a SHA-256 of the group list,
  the number of groups and the role per device serial. No display name and
  no group link is stored on the admin laptop; the display name exists only
  inside the encrypted file, which is not kept either. The organizer
  profile that creates the groups (a later version) is deleted after the
  handover, so our side then holds nothing of the customer's social graph.

## The admin store

- Encrypted at rest with AES-256-GCM under a random 256-bit store key, own
  header with a key id, mode 0600. Nobody types the key: no password in
  normal operation, by design.
- The key is sealed with the laptop's TPM 2.0 (`systemd-creds --user`, no
  PCR binding) where there is one, so a copy of the key file is useless off
  the laptop; otherwise it is a 0600 key file, written only onto an
  encrypted disk (dm-crypt) outside WSL. So the store rests on the disk
  encryption, the operator's account and, with a TPM, this laptop; no longer
  on a second secret in the operator's head.
- A passphrase store of an earlier version is moved once with `store
  migrate` (the passphrase typed a last time, the result checked with the
  key read back before the passphrase file is set aside).
- Written atomically (temporary file, fsync, rename), the previous version
  kept as `.bak`; a wrong key changes nothing.
- An exclusive lock: a second `sxprov` process is refused at once and never
  writes.
- Refused inside a git repository. It never holds a copy of an issued file,
  a full code, a name (also no directory display name), a group link or a
  server password.

## Backups

- Format v1 of every SimpleGo product: age (age-encryption.org/v1) to an
  X25519 recipient, so automatic backups hold no secret and need none on the
  laptop. The private key is derived from an 18-byte seed that exists only as
  the recovery code on paper (shown once, out of the scrollback, never stored
  or logged) and wrapped under the backup password (scrypt, work factor 20)
  in every backup. No SimpleGo-specific cryptography.
- A backup holds the store and its key, so whoever has a backup file and the
  backup password or the recovery code can open every update key. The
  copies off the laptop (USB stick, WebDAV/Nextcloud over Tor) are only as
  strong as that password: at least 12 characters, and each guess costs an
  attacker scrypt with 1 GiB.
- After every write the file is read back from the destination and checked
  in full with the file key kept in memory during encryption; a failed check
  never deletes anything, and rotation deletes only files of our own list.
  The monthly drill (the password typed once) proves the part that cannot be
  checked unattended: that the seed's key opens the files.
- Readers refuse anything the format does not allow (magic line, header,
  stanzas, tar member types, modes, times, paths, manifest hashes) before a
  single file is restored; a restore never writes over the live store
  without `--replace` and a typed `REPLACE`.
- WebDAV only over Tor (`socks5h`), `https://` or a `.onion` host; the
  credentials in a 0600 file of their own, never in a backup.

## Signing key passphrase

The activation signing key stays an offline, passphrase-protected key, by
design: `activation issue`, `activation update` and every real `deliver`
ask for its passphrase when they sign. That is the one password typed in
normal operation, on purpose. Test deliveries type nothing: they sign with
the TEST ONLY key, whose passphrase comes from a file, and the store opens
with its store key.

## Operator safety

- Commands go to one phone only, chosen by serial; other connected phones are
  listed and never addressed.
- A messenger set up by a customer (`setup=done`), whatever its package name
  (found by its activation provider), stops `deliver` and `flash`; a delivery
  record stops `flash` unless the phone is a test device.
- Wiping and handing over need a typed word; nothing that needs a terminal
  runs without one.
- Serials are masked in every output unless asked; recorded phone data never
  enters the repository.

## Not protected

- A phone after the check: attestation proves the state at the time of the
  check.
- The admin laptop while it runs unlocked: any program running as the
  operator user can read the store key and so the store (before
  0.2.0-alpha it also needed the store passphrase). The TPM binding
  protects copies of the key file, not a running session.
- A backup copy together with a weak backup password, or the paper with
  the recovery code.
- The operator's choice of pins: a wrong pin in the config is trusted.
- The activation code during the one provider call: it is briefly visible in
  the process lists of the laptop and the phone.
- The unsigned GrapheneOS channel files choose a version only through Tor;
  the image itself is always signature-checked.
- Alpha software, not audited.
