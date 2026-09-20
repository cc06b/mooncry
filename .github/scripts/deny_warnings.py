#!/usr/bin/env python3
"""Fail on any compiler warning that is not on the tracked-debt list.

    moon check 2>&1 | tee /tmp/check.log
    python3 .github/scripts/deny_warnings.py /tmp/check.log

CI used to run `moon check --deny-warn`, which denies every warning. moonc
v0.10.14 (2026-09-18) added `test_unqualified_package` (warning 0025): it wants
`@lib.foo` rather than a bare `foo` in every blackbox test, and this repository
has 7402 such call sites across ~200 test files. Qualifying them is mechanical
but large, and it is tracked as debt rather than done under time pressure -- so
this script denies every warning *except* the enumerated ones, which preserves
the property `--deny-warn` was there for: a warning of any other kind still
fails the build.

An allowed warning that stops appearing is reported but does not fail: the
trigger may be a toolchain change rather than something this repository did.
"""
import collections
import re
import sys

ALLOWED = {
    # moonc v0.10.14+: blackbox tests should qualify library symbols with
    # `@lib.`. 7402 sites at the time of writing; see API_1.0_PLAN.md §10.
    "test_unqualified_package",
}


def main():
    if len(sys.argv) < 2:
        print("usage: deny_warnings.py <logfile>")
        return 2
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    kinds = collections.Counter(re.findall(r"Warning \(([A-Za-z0-9_]+)\)", text))
    print("warning kinds seen: %s" % (dict(kinds) or "none"))
    for k in sorted(ALLOWED):
        if k in kinds:
            print("   allowed (tracked debt): %s x%d" % (k, kinds[k]))
        else:
            print("   NOTE: %s is allow-listed but did not appear -- the debt "
                  "may be paid, or the toolchain renamed it" % k)
    unexpected = {k: v for k, v in kinds.items() if k not in ALLOWED}
    if unexpected:
        for k, v in sorted(unexpected.items()):
            print("::error::unexpected compiler warning %s (x%d) -- fix it, or "
                  "add it to ALLOWED in .github/scripts/deny_warnings.py with a "
                  "reason" % (k, v))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
