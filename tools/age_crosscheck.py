# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems
"""Cross-check of the backup format with the official age tool.

    python3 -I tools/age_crosscheck.py AGE AGE_KEYGEN DIR

AGE and AGE_KEYGEN are the official tools (for example from Debian's signed
`age` package, unpacked). DIR must hold what `cargo test cross_export --
--ignored` wrote there with SXPROV_CROSS_DIR=DIR. The script

1. has the tool decrypt our age file with the V1 identity and compares the
   plaintext with our tar;
2. has age-keygen derive the recipient of the V1 identity;
3. has the tool decrypt our wrapped seed with the passphrase (through a
   pseudo terminal, as the tool reads passphrases only from a terminal);
4. has the tool encrypt our tar to the V1 recipient (tool.age) and the seed
   with the passphrase (tool-wrapped.age), for `cross_import`.
"""

import os
import pty
import subprocess
import sys

PASS = b"TEST-ONLY crosscheck password"


def with_passphrase(argv, answers):
    """Runs argv on a pseudo terminal and types each answer after a prompt."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    out = b""
    pending = list(answers)
    while True:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if pending and b"passphrase" in out.lower().split(b"\n")[-1]:
            os.write(fd, pending.pop(0) + b"\n")
            out += b"\n"
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out


def main():
    age, keygen, d = sys.argv[1], sys.argv[2], sys.argv[3]
    p = lambda n: os.path.join(d, n)  # noqa: E731
    ok = True

    r = subprocess.run([age, "-d", "-i", p("id.txt"), p("ours.age")], capture_output=True)
    same = r.returncode == 0 and r.stdout == open(p("ours.tar"), "rb").read()
    print(f"1. age -d -i (V1 identity) ours.age: exit {r.returncode}, plaintext equals our tar: {same}")
    ok &= same

    r = subprocess.run([keygen, "-y", p("id.txt")], capture_output=True)
    want = open(p("recipient.txt")).read().strip()
    got = r.stdout.decode().strip()
    print(f"2. age-keygen -y (V1 identity): {got} equals V1 recipient: {got == want}")
    ok &= got == want

    code, out = with_passphrase([age, "-d", "-o", p("tool-seed.bin"), p("ours-wrapped.age")], [PASS])
    seed_ok = code == 0 and open(p("tool-seed.bin"), "rb").read() == open(p("seed.bin"), "rb").read()
    print(f"3. age -d ours-wrapped.age (passphrase, work factor 20): exit {code}, seed equals V1: {seed_ok}")
    ok &= seed_ok

    r = subprocess.run([age, "-r", want, "-o", p("tool.age"), p("ours.tar")], capture_output=True)
    print(f"4a. age -r (V1 recipient) -o tool.age: exit {r.returncode}")
    ok &= r.returncode == 0
    code, out = with_passphrase([age, "-p", "-o", p("tool-wrapped.age"), p("seed.bin")], [PASS, PASS])
    print(f"4b. age -p -o tool-wrapped.age seed.bin: exit {code}")
    ok &= code == 0

    print("TOOL SIDE OK" if ok else "TOOL SIDE FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
