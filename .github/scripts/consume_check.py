#!/usr/bin/env python3
"""Consume the *published* package and check it against independent oracles.

Used by the `consume` workflow (manual dispatch, after a release) and runnable
by hand:

    python3 .github/scripts/consume_check.py
    python3 .github/scripts/consume_check.py --version 0.83.0

Unit tests in this repository only prove "the library passed its own tests".
This proves the artefact a consumer downloads still works: it runs
`moon add cc06b/mooncry` (resolving whatever the registry says is latest, or
--version), builds a real executable against it, and compares the output with
oracles that are not this library.

Expectations are computed at run time wherever an independent oracle exists:
  * SHA-256 / SHA-512 / SHA3-256 / BLAKE2b / HMAC / PBKDF2 -> Python hashlib
  * ZUC-128 and ZUC-256 keystreams -> the official GM/T 0001.1-2012 and
    ZUC-256 all-zero key/IV vectors. These two are the only inlined constants:
    CI has no compiled reference to ask, and both were cross-checked against a
    locally compiled GmSSL oracle when agent_box/_tools/_consume_check.py ran
    them (that variant derives every expectation at run time, WSL included).
  * rejection paths (forged AEAD tag, wrong-length MAC) -> must be false/Err

It also checks the one property that a unit test inside this repository cannot
see: that `cc06b/mooncry/internal` really is unimportable from a downstream
module. The Falcon layer moved there in v0.88.0 and the isolation is a compiler
rule, so this pins it against toolchain changes -- and it distinguishes
"blocked by the internal visibility rule" from "the registry did not ship the
package", which would look similar and mean the opposite.

Exit code 0 = every check passed.
"""
import argparse
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile

MSG = b"consume-check message"
# GM/T 0001.1-2012 example 1 (all-zero key and IV), first two keystream words
ZUC128_ZERO = "27bede74018082da"
# ZUC-256 all-zero key/IV, first two keystream words
ZUC256_ZERO = "58d03ad62e032ce2"

MAIN = r'''
fn main {
  let msg = b"consume-check message"
  println("sha256=" + @lib.bytes_to_hex(@lib.sha256(msg)))
  println("sha512=" + @lib.bytes_to_hex(@lib.sha512(msg)))
  println("sha3_256=" + @lib.bytes_to_hex(@lib.sha3_256(msg)))
  println("blake2b=" + @lib.bytes_to_hex(@lib.blake2b(msg, 64)))
  println("hmac256=" + @lib.bytes_to_hex(@lib.hmac_sha256(b"key", msg)))
  println("pbkdf2=" + @lib.bytes_to_hex(@lib.pbkdf2_hmac_sha256(b"pw", b"salt", 1000, 32)))
  let z = Bytes::make(16, b'\x00')
  println("zuc128=" + @lib.bytes_to_hex(@lib.zuc_keystream(z, z, 2)))
  let k32 = Bytes::make(32, b'\x00')
  let iv23 = Bytes::make(23, b'\x00')
  println("zuc256=" + @lib.bytes_to_hex(@lib.zuc256_keystream(k32, iv23, 2)))
  let key = Bytes::make(32, b'\x07')
  let nonce = Bytes::make(12, b'\x08')
  let ct = @lib.chacha20_poly1305_encrypt(key, nonce, b"aad", msg)
  println("aead_ok=" + (match @lib.chacha20_poly1305_decrypt_or(key, nonce, b"aad", ct) {
    Ok(_) => true
    Err(_) => false
  }).to_string())
  let bad = ct.to_array()
  bad[bad.length() - 1] = (bad[bad.length() - 1].to_int() ^ 1).to_byte()
  println("aead_forged=" + (match @lib.chacha20_poly1305_decrypt_or(
    key, nonce, b"aad", Bytes::from_array(bad)) {
    Ok(_) => true
    Err(_) => false
  }).to_string())
  let m1024 = Bytes::make(1024, b'\x5a')
  let mac = @lib.zuc_eia3_mac(z, 0U, 0, 0, 8192, m1024)
  println("eia3_ok=" + @lib.zuc_eia3_verify(z, 0U, 0, 0, 8192, m1024, mac).to_string())
  println("eia3_badtag=" + @lib.zuc_eia3_verify(z, 0U, 0, 0, 8192, m1024, b"").to_string())
}
'''


def sh(argv, cwd=None, timeout=900):
    r = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def check_internal_isolated(version):
    """A downstream module must NOT be able to import cc06b/mooncry/internal.

    Separate project on purpose: a package that fails to solve poisons the whole
    module's build plan, which would break the positive checks above.
    """
    root = tempfile.mkdtemp(prefix="mooncry-leak-")
    try:
        os.makedirs(os.path.join(root, "leak"))
        with open(os.path.join(root, "moon.mod"), "w") as f:
            f.write('name = "probe/leak"\nversion = "0.1.0"\n')
        with open(os.path.join(root, "leak", "moon.pkg"), "w") as f:
            f.write('import {\n  "cc06b/mooncry/internal",\n}\n\n'
                    'pkgtype(kind: "executable")\n')
        with open(os.path.join(root, "leak", "main.mbt"), "w") as f:
            f.write("fn main {\n  println(@internal.fp_of(3).to_string())\n}\n")
        want = ("cc06b/mooncry@" + version) if version else "cc06b/mooncry"
        rc, out = sh(["moon", "add", want], cwd=root, timeout=300)
        if rc != 0:
            print("== internal isolation: moon add FAILED ==\n" + out[-800:])
            return False
        rc, out = sh(["moon", "check"], cwd=root, timeout=600)
        blocked = "internal visibility rules" in out
        missing = "Cannot find import" in out
        print("== importing cc06b/mooncry/internal from a consumer ==")
        if blocked:
            print("   OK    refused by the compiler (internal visibility rules)")
            return True
        if rc == 0:
            print("   FAIL  the internal package IMPORTED AND BUILT")
            return False
        print("   FAIL  refused, but not by the visibility rule%s" %
              (" -- the registry did not ship the package" if missing else ""))
        print(out[-800:])
        return False
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="", help="require this exact version")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    root = tempfile.mkdtemp(prefix="mooncry-consume-")
    try:
        os.makedirs(os.path.join(root, "main"))
        with open(os.path.join(root, "moon.mod"), "w") as f:
            f.write('name = "probe/consume"\nversion = "0.1.0"\n')
        # moon.pkg is not JSON in current toolchains
        with open(os.path.join(root, "main", "moon.pkg"), "w") as f:
            f.write('import {\n  "cc06b/mooncry/lib",\n}\n\npkgtype(kind: "executable")\n')
        with open(os.path.join(root, "main", "main.mbt"), "w") as f:
            f.write(MAIN)

        want = ("cc06b/mooncry@" + args.version) if args.version else "cc06b/mooncry"
        rc, out = sh(["moon", "add", want], cwd=root, timeout=300)
        print("== moon add %s -> rc=%d" % (want, rc))
        if rc != 0:
            print(out[-1500:])
            return 1
        for line in out.split("\n"):
            if "cc06b/mooncry@" in line:
                print("   " + line.strip())
        if args.version and ("cc06b/mooncry@" + args.version) not in out:
            mod = open(os.path.join(root, "moon.mod")).read()
            if args.version not in mod:
                print("   FAIL: resolved something other than " + args.version)
                print(mod)
                return 1

        rc, out = sh(["moon", "run", "main"], cwd=root, timeout=900)
        if rc != 0:
            print("== build/run FAILED ==\n" + out[-2000:])
            return 1
        got = {}
        for line in out.split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                got[k.strip()] = v.strip()

        expect = {
            "sha256": hashlib.sha256(MSG).hexdigest(),
            "sha512": hashlib.sha512(MSG).hexdigest(),
            "sha3_256": hashlib.sha3_256(MSG).hexdigest(),
            "blake2b": hashlib.blake2b(MSG, digest_size=64).hexdigest(),
            "hmac256": hmac.new(b"key", MSG, hashlib.sha256).hexdigest(),
            "pbkdf2": hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000, 32).hex(),
            "zuc128": ZUC128_ZERO,
            "zuc256": ZUC256_ZERO,
            "aead_ok": "true",
            "aead_forged": "false",
            "eia3_ok": "true",
            "eia3_badtag": "false",
        }
        print("== comparison ==")
        fails = 0
        for k, want_v in expect.items():
            have = got.get(k)
            ok = (have or "").lower() == want_v.lower()
            print("   %-5s %-12s %s" % ("OK" if ok else "FAIL", k, (have or "<missing>")[:64]))
            if not ok:
                print("         want %s" % want_v[:64])
                fails += 1
        missing = set(expect) - set(got)
        if missing:
            print("   FAIL: no output for %s" % sorted(missing))
            fails += len(missing)
        print("\n%d checks, %d failed" % (len(expect), fails))
        if not check_internal_isolated(args.version):
            fails += 1
        print("%s" % ("all checks passed" if not fails else "FAILURES: %d" % fails))
        return 1 if fails else 0
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
