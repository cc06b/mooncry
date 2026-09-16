#!/usr/bin/env python3
"""Rotate the hostile-input suite's seeds and re-run it. CI-friendly twin of
agent_box/_tools/_rotate_fuzz_seeds.py (repo-relative, `moon` from PATH).

    python3 .github/scripts/rotate_fuzz_seeds.py --rounds 3

lib/robust*_test.mbt drives every fuzz suite from fixed `rb_rng(0x..)` literals,
which is what makes a failure reproducible on all three targets. The cost is that
the suites only ever walk one corpus, so an assertion that happens to hold for
those inputs stays green forever. This rewrites every seed to a fresh random
value, runs the suites, and reports; in CI the workspace is discarded, so the
committed seeds are never touched.

A red round is a FINDING, not a flake: it means some assertion depended on the
specific corpus. The failing seed set is printed so it can be reproduced.
"""
import argparse
import io
import os
import re
import subprocess
import sys
import time

NL = chr(10)
FILES = ["lib/robust_test.mbt", "lib/robust_der_test.mbt", "lib/robust_stream_test.mbt"]
SEED_RE = re.compile(r"rb_rng\(0x([0-9A-Fa-f]+)UL\)")


def rotate():
    changed = {}
    for f in FILES:
        if not os.path.isfile(f):
            continue
        s = io.open(f, encoding="utf-8").read()

        def sub(m):
            new = "%012X" % (int.from_bytes(os.urandom(6), "big") & 0xFFFFFFFFFFFF)
            changed.setdefault(f, []).append((m.group(1), new))
            return "rb_rng(0x%sUL)" % new

        s2 = SEED_RE.sub(sub, s)
        if s2 != s:
            io.open(f, "w", encoding="utf-8", newline="\n").write(s2)
    return changed


NL = chr(10)
SNAPSHOT = {}


def snapshot():
    """Remember the on-disk contents so restore() puts back exactly what was
    there. The local twin of this script originally used `git checkout --`,
    which silently discards uncommitted edits in the same files; CI workspaces
    are disposable, but keeping one behaviour in both copies avoids surprises."""
    for f in FILES:
        if os.path.isfile(f):
            SNAPSHOT[f] = io.open(f, encoding="utf-8").read()


def restore():
    for f, text in SNAPSHOT.items():
        io.open(f, "w", encoding="utf-8", newline=NL).write(text)


def run(filt):
    r = subprocess.run(["moon", "test", "--release", "-f", filt],
                       capture_output=True, text=True, timeout=3600)
    out = r.stdout + r.stderr
    m = re.search(r"Total tests: (\d+), passed: (\d+), failed: (\d+)", out)
    return r.returncode, (m.groups() if m else None), out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--filter", default="robust*")
    ap.add_argument("--no-restore", action="store_true",
                    help="leave the rotated seeds in the working tree")
    args = ap.parse_args()

    snapshot()
    bad = 0
    for i in range(args.rounds):
        ch = rotate()
        n = sum(len(v) for v in ch.values())
        if not n:
            print("no rb_rng seeds found; nothing to rotate")
            return 1
        t0 = time.time()
        rc, totals, out = run(args.filter)
        ok = rc == 0 and totals and totals[2] == "0"
        print("round %d: %d seeds rotated -> %s in %.0fs%s"
              % (i + 1, n, "PASS" if ok else "FAIL", time.time() - t0,
                 "" if ok else " totals=%s" % (totals,)), flush=True)
        if not ok:
            bad += 1
            print("failing seed set (old -> new):")
            for f, pairs in ch.items():
                for a, b in pairs:
                    print("  %s %s -> %s" % (f, a, b))
            for line in out.split("\n"):
                if "FAILED" in line:
                    print("  " + line.strip()[:220])
            if not args.no_restore:
                restore()
            break
        if not args.no_restore:
            restore()
    print("%d/%d rounds passed" % (args.rounds - bad, args.rounds))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
