# F-Droid repository files used as test fixtures

Public files, fetched over Tor on 2026-11-24 from SimpleX's own F-Droid
repository `https://app.simplex.chat/fdroid/repo` (`Last-Modified: Sat, 14
Nov 2026 22:50:19 GMT`). No data from a phone.

- `simplex-entry.jar` (3,262 bytes, SHA-256
  `10de75bdd828883c3f7ecb470c2bba23b33a043c2494949c352d8c771152381c`): the
  signed entry of index v2. Signed with the repository key whose
  certificate SHA-256 is the repository fingerprint
  `9f358ff284d1f71656a2bfaf0e005deae6aa14143720e089f11ff2ddcfeb01ba`.
- `simplex-index-v2.json` (111,025 bytes, SHA-256
  `b3c0246b7d96ebf928757c0d0db02504ad9cdb31bbf3616ba2bd6a5e5a7b7e14`, as
  named in `entry.json`): the index with `chat.simplex.app`, 60 entries.

Made for the tests only, never trusted anywhere:

- `test-only-repo-key-pkcs1.der` and `test-only-repo-cert.der`: an RSA 2048 key (PKCS#1 DER)
  and its self-signed certificate (`CN=TEST ONLY F-Droid repo signer, never
  trusted`), created with openssl for the synthetic repositories of the
  delivery tests. The tests sign `entry.jar` files with it at run time.
