#!/usr/bin/env python3
"""Fail if any tracked text source contains a raw control byte.

    python3 .github/scripts/check_no_control_bytes.py

Why this exists: v0.92.0 shipped two files where a Python heredoc had turned
`b'\\x00'` into an actual NUL byte (and three more escapes into 0x01-0x03). moonc
accepts a raw byte inside a byte literal -- it is the same value as its escape --
so the build, the tests and `moon check` were all green, and `moon fmt --check`
only failed in CI, reporting "Binary files differ". A published archive should
not contain sources that git considers binary.

Scans every tracked file with a text-ish extension; tabs, newlines and carriage
returns are of course allowed.
"""
import subprocess
import sys

EXTS = ["*.mbt", "*.md", "*.pkg", "*.mod", "*.py", "*.yml", "*.yaml", "*.json"]


def main():
    files = subprocess.run(
        ["git", "ls-files"] + EXTS,
        capture_output=True, text=True, check=True).stdout.split()
    bad = []
    for f in files:
        try:
            data = open(f, "rb").read()
        except OSError:
            continue
        hits = [(i, b) for i, b in enumerate(data) if b < 9 or 13 < b < 32]
        if hits:
            bad.append("%s: %d control byte(s), first 0x%02x at offset %d"
                       % (f, len(hits), hits[0][1], hits[0][0]))
    if bad:
        print("::error::raw control bytes in tracked sources -- write \\xNN "
              "escapes instead:")
        for b in bad:
            print("   " + b)
        return 1
    print("%d tracked text files scanned, none contains a raw control byte"
          % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
