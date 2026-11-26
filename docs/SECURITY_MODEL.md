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
  keys and the fleet records in the admin store.
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
- A lost or copied admin laptop.
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

## The admin store

- Encrypted at rest: Argon2id (64 MiB, 3 passes) from a passphrase of at
  least 12 characters, AES-256-GCM, own header, mode 0600.
- Written atomically (temporary file, fsync, rename), the previous version
  kept as backup; a wrong passphrase changes nothing.
- An exclusive lock: a second `sxprov` process is refused at once and never
  writes.
- Refused inside a git repository. It never holds a copy of an issued file,
  a full code, a name or a server password.

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
- The admin laptop while it runs unlocked with the store open.
- The operator's choice of pins: a wrong pin in the config is trusted.
- The activation code during the one provider call: it is briefly visible in
  the process lists of the laptop and the phone.
- The unsigned GrapheneOS channel files choose a version only through Tor;
  the image itself is always signature-checked.
- Alpha software, not audited.
