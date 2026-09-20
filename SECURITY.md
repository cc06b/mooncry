# Security policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository — the
"Report a vulnerability" button under the *Security* tab, which opens a private
security advisory. Do **not** open a public issue for something that is
exploitable.

Please include:

- the version (`moon.mod`'s `version`, or the registry version you installed);
- the target you built for (`wasm-gc`, `js`, `native`) — this library's `Int` is
  32-bit on wasm and 64-bit on native, and a few behaviours differ between them
  by design, so the target is part of the report;
- a minimal reproduction, ideally as a `test` block. Aborts cannot be asserted
  from a blackbox test, so if your case involves one, a short program is enough;
- what you expected instead.

There is no bug bounty. Reports are handled by the maintainer directly; expect
an acknowledgement rather than a service-level time.

## Supported versions

One: **the latest published minor**. This project is in `0.x`, where each minor
may contain breaking changes (they are listed in `CHANGELOG.md`, and the API
contracts are machine-checked in CI). Security fixes are applied to the current
minor and released as a patch (`0.x.y+1`); older minors are not maintained.

## What counts as a vulnerability

In scope, and treated as bugs:

- a **wrong answer** — a digest, signature, MAC, key, ciphertext or shared
  secret that disagrees with the standard or with another implementation;
- a **verification that accepts** something it should reject (a forged tag, a
  malleable encoding, a low-order point, an off-curve key, a non-canonical DER
  blob);
- a **trap or abort reachable from peer-controlled input** — the contract is
  that anything crossing a trust boundary is reported as a value (`Bool`,
  `Result`), never as an abort, because an abort in a long-lived process is a
  denial of service;
- **silent acceptance of a parameter that changes the answer**: a length, a
  count, an enum, or an offset that produces material no other implementation
  reproduces;
- a **memory-safety** problem: reading past an input, or writing past a buffer.

Out of scope, because they are documented properties rather than defects — the
README's [Security & performance boundaries](README.md#security--performance-boundaries)
section is the authoritative list:

- **AES, GHASH, ZUC and Falcon keygen/sign are not constant-time.** They use
  precomputed tables and branch on secret-dependent values. This is a stated
  limitation, not a surprise; if you need side-channel resistance against a
  local attacker, this library is the wrong choice for those primitives. What
  *is* constant-time: the tag and signature **comparisons** (`bytes_equal`,
  every verifier), and X25519/X448.
- **The library contains no RNG at all.** Every key, nonce, `ikm` and
  `rand` callback is caller-supplied. Reusing a `(key, nonce)` pair, or passing
  weak randomness in, is the caller's decision; `falcon_test_rng_*` in particular
  is a deterministic test stream and must never be used for real material.
- **Aborts on caller-shape errors.** A wrong-length key or IV in your own code
  aborts loudly by design; that is the two-tier contract, and the `_or` /
  `Result` variants exist for the cases where the input is not yours.
- **MD5, SHA-1 and the PKCS#1 v1.5 / CBC constructions** are included for
  compatibility. Their cryptographic weaknesses are the algorithms', not this
  implementation's.

## Process

1. Report privately, as above.
2. The maintainer confirms or asks for more detail, and states whether the
   report is in scope.
3. A fix lands with a **regression test** — in this repository a fix without a
   test that fails before it and passes after is not considered done. Parameter
   and shape guards additionally get a *teeth* check: the guard is temporarily
   removed or tightened to prove the test really exercises it.
4. A patch version is published to mooncakes, `CHANGELOG.md` describes the issue
   in enough detail to identify affected callers, and the advisory is published.
   The CI `consume` job then verifies that the published artifact — not just this
   working tree — resolves and passes against independent oracles.

Embargo: if you need coordinated disclosure, say so in the report and propose a
date.
