# mooncry

A pure-MoonBit, zero-dependency native cryptographic library for the MoonBit
ecosystem. No FFI, no C — every primitive is implemented in plain MoonBit and
verified against official standard vectors.

## Highlights

- **Correct** — every algorithm is checked against FIPS / NIST / RFC test
  vectors plus large-data million-`a` vectors. 70 tests, run with
  `moon test --deny-warn`.
- **Fast where it matters** — hex / Base64 encoding are O(n); AES MixColumns
  uses precomputed GF(2^8) tables (~5x over bit-sliced math); throughput is
  measured by `moon bench`.
- **Fail-fast input validation** — AES / ChaCha20 / hex functions abort with a
  clear message on wrong key / IV / nonce / tag lengths instead of producing
  garbage.
- **Single source of truth** — one-shot hash entry points delegate to the
  streaming hashers, so the incremental and one-shot paths share one
  implementation.

> The implementations are correct and tested but have **not** been formally
> audited. See [Security & performance boundaries](#security--performance-boundaries).

## Repositories

- **GitHub** (canonical): <https://github.com/cc06b/mooncry>
- **Gitlink** (mirror): <https://www.gitlink.org.cn/CC01/mooncry_mirror>

Both are kept in sync. To add the mirror locally:

```bash
git remote add gitlink https://www.gitlink.org.cn/CC01/mooncry_mirror.git
git push gitlink master
```

## Algorithms

### Hash functions
- **MD5** (RFC 1321) — 128-bit digest
- **SHA-224 / SHA-256** (FIPS 180-4) — 224 / 256-bit digest
- **SHA-384 / SHA-512** (FIPS 180-4) — 384 / 512-bit digest
- **SHA-3** (FIPS 202) — SHA3-224 / 256 / 384 / 512 (Keccak-f[1600] sponge)

### Extendable-output functions (XOF)
- **SHAKE128 / SHAKE256** (FIPS 202) — variable-length output

### Message authentication
- **HMAC-SHA256 / HMAC-SHA512** (RFC 2104)

### Symmetric ciphers
- **AES-CBC** (NIST SP 800-38A) — PKCS#7 padding, 128/192/256-bit keys, IV prepended
- **AES-GCM** (NIST SP 800-38D) — authenticated encryption with AAD, 96-bit nonce
- **AES-CTR** (NIST SP 800-38A) — 128-bit big-endian counter, stream cipher
- **ChaCha20** (RFC 8439) — 256-bit key, 96-bit nonce, stream cipher (not an AEAD)

### Key derivation
- **HKDF-SHA256** (RFC 5869) — extract + expand
- **PBKDF2-HMAC-SHA256** (RFC 8018) — password-based key derivation

### Encoding
- **Base64** (RFC 4648) — standard alphabet with padding
- **Hex** — bytes ↔ lowercase hex

### Streaming API
MD5, SHA-224, SHA-256, SHA-384, and SHA-512 support incremental
`new` / `update` / `finalize` for streaming or large inputs.

## Installation

```bash
moon add cc06b/mooncry
```

## Quick start

Create a new project, add the dependency, then import the `lib` package and
call its functions through the `@lib` alias. **Dependencies are declared in
`moon.pkg` (per-package), not as a top-level `import` statement**, and
`assert_true` is only available inside `test` blocks — so use `println` in
`main`.

```bash
moon new myapp
cd myapp
moon add cc06b/mooncry
```

Edit `cmd/main/moon.pkg` to import the library:

```toml
import {
  "cc06b/mooncry/lib",
}

options(
  "is-main": true,
)
```

Edit `cmd/main/main.mbt`:

```moonbit
fn main {
  // SHA-256 one-shot
  let digest = @lib.sha256(b"Hello, world!")
  println("SHA-256: " + @lib.bytes_to_hex(digest))

  // AES-GCM round-trip (256-bit key, 96-bit nonce, with AAD)
  let key = Bytes::make(32, b'\x00')
  let iv = Bytes::make(12, b'\x00')
  let (ciphertext, tag) = @lib.aes_gcm_encrypt(b"secret data", key, iv, b"aad")
  let (plaintext, ok) = @lib.aes_gcm_decrypt(ciphertext, key, iv, b"aad", tag)
  let status = if ok { "OK" } else { "FAIL" }
  println("AES-GCM round-trip: " + status)
  println("Recovered: " + @lib.bytes_to_hex(plaintext))
}
```

Run it:

```bash
moon run cmd/main
```

```
SHA-256: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
AES-GCM round-trip: OK
Recovered: 7365637265742064617461
```

A larger runnable example that validates the implementation against NIST/RFC
standard vectors lives in [`cmd/main`](cmd/main/main.mbt) of the repository
itself. Run it with `moon run cmd/main`.

## Public API

All functions live in the `lib` package (`cc06b/mooncry/lib`), called as
`@lib.<fn>` after declaring the import in your `moon.pkg`.

| Function | Description |
| --- | --- |
| `md5(data : Bytes) -> Bytes` | MD5 one-shot, 16-byte digest |
| `sha224(data : Bytes) -> Bytes` | SHA-224 one-shot, 28-byte digest |
| `sha256(data : Bytes) -> Bytes` | SHA-256 one-shot, 32-byte digest |
| `sha384(data : Bytes) -> Bytes` | SHA-384 one-shot, 48-byte digest |
| `sha512(data : Bytes) -> Bytes` | SHA-512 one-shot, 64-byte digest |
| `sha3_224 / sha3_256 / sha3_384 / sha3_512(data : Bytes) -> Bytes` | SHA-3 (FIPS 202) |
| `shake_128(data : Bytes, out_len : Int) -> Bytes` | SHAKE128 XOF, `out_len` bytes |
| `shake_256(data : Bytes, out_len : Int) -> Bytes` | SHAKE256 XOF, `out_len` bytes |
| `hmac_sha256(key : Bytes, message : Bytes) -> Bytes` | HMAC-SHA256 (RFC 2104) |
| `hmac_sha512(key : Bytes, message : Bytes) -> Bytes` | HMAC-SHA512 (RFC 2104) |
| `aes_encrypt_cbc(data, key, iv) -> Bytes` | AES-CBC encrypt (IV prepended, PKCS#7) |
| `aes_decrypt_cbc(data, key, iv) -> Bytes` | AES-CBC decrypt (reads prepended IV) |
| `aes_gcm_encrypt(pt, key, iv, aad) -> (Bytes, Bytes)` | AES-GCM encrypt → (ciphertext, 16-byte tag) |
| `aes_gcm_decrypt(ct, key, iv, aad, tag) -> (Bytes, Bool)` | AES-GCM decrypt, constant-time tag verify |
| `aes_ctr(data, key, iv) -> Bytes` | AES-CTR encrypt/decrypt (symmetric) |
| `chacha20_xor(input, key, nonce, counter) -> Bytes` | ChaCha20 encrypt/decrypt (symmetric) |
| `hkdf_sha256(ikm, salt, info, len) -> Bytes` | HKDF-SHA256 (RFC 5869) |
| `pbkdf2_hmac_sha256(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA256 (RFC 8018) |
| `base64_encode(data : Bytes) -> String` | Base64 encode (RFC 4648) |
| `base64_decode(encoded : String) -> Bytes` | Base64 decode |
| `bytes_to_hex(data : Bytes) -> String` | Bytes → lowercase hex |
| `hex_to_bytes(hex : String) -> Bytes` | hex → Bytes (rejects odd length / non-hex) |
| `bytes_equal(a : Bytes, b : Bytes) -> Bool` | Constant-time comparison |

Streaming hashers (`<algo>_new` / `_update` / `_finalize`) are available for
MD5, SHA-224, SHA-256, SHA-384, and SHA-512.

AES-CBC/GCM/CTR keys may be 128, 192, or 256 bits; the nonce for GCM and
ChaCha20 is 96 bits (12 bytes), the recommended length per spec. Wrong lengths
cause an `abort` with a descriptive message.

## Security & performance boundaries

- **Not audited.** The code is correct against known vectors but has had no
  formal security review. Do not use it to protect high-value assets without an
  independent audit.
- **AES is not constant-time.** MixColumns uses precomputed GF(2^8) lookup
  tables (`mul2/3/9/11/13/14`) for ~5x throughput. This leaks key-dependent
  table indices through the CPU cache — acceptable for many use cases but
  **not side-channel-safe** against a local attacker. (GHASH and the GCM tag /
  CBC PKCS#7 *verification* are still bit-sliced and constant-time.)
- **Nonce reuse is catastrophic** for AES-GCM and ChaCha20. Never reuse a
  (key, nonce) pair. The library does not track nonces — generate a fresh one
  per message (e.g. a counter or a CSPRNG).
- **PBKDF2 is a KDF, not a password hasher.** For interactive password storage
  prefer Argon2 / bcrypt / scrypt elsewhere; PBKDF2 is included for
  compatibility with existing protocols.
- **MD5 is collision-broken.** It is included for legacy compatibility only —
  do not sign or authenticate with it.
- **Inputs are validated, not silently padded.** Wrong key / IV / nonce / tag
  lengths `abort` immediately rather than producing wrong output.
- **No RNG.** The library provides deterministic primitives; obtain keys, IVs,
  and nonces from a secure source.

## Performance

Throughput is measured by the `lib` benchmark suite (`moon bench`), on 1 KiB
inputs:

```bash
moon bench
```

| Algorithm | 1 KiB (approx.) |
| --- | --- |
| MD5 | ~6.9 µs |
| SHA-256 | ~4.5 µs |
| SHA-512 | ~8.1 µs |
| HMAC-SHA256 | ~14.9 µs |
| ChaCha20 | ~23.8 µs |
| AES-256-CBC | ~165 µs (table-based GF mul) |
| AES-256-GCM | ~170 µs (table-based) |
| Base64 encode | ~5.5 µs |
| Hex encode | ~3.4 µs |

Hashes, ChaCha20, and hex/Base64 are throughput-bound by the algorithm; AES
trades constant-time property for ~5x speed via lookup tables (see
[Security & performance boundaries](#security--performance-boundaries)).

## Testing

Every algorithm is verified against official standard vectors:

```bash
moon test
```

Coverage: MD5 (RFC 1321), SHA-2 family (FIPS 180-4 + million-`a`), SHA-3
(NIST KAT), SHAKE (FIPS 202), HMAC (RFC 4231), HKDF (RFC 5869), PBKDF2
(RFC 6070), AES-CBC/GCM/CTR (NIST SP 800-38A/D), ChaCha20 (RFC 8439), Base64
(RFC 4648), hex round-trip, and streaming-vs-one-shot consistency. 70 tests.

## Development

The CI (`.github/workflows/moonbit-ci.yml`) installs the latest MoonBit
toolchain and runs the four required checks — `moon check --deny-warn`,
`moon fmt --check`, `moon info`, `moon test --deny-warn` — and verifies that
no build artifacts are tracked. Run them locally:

```bash
moon check --deny-warn
moon fmt --check
moon info
moon test --deny-warn
moon bench          # run the benchmark suite
```

The module manifest is `moon.mod` (TOML); per-package manifests are
`moon.pkg` (TOML). Build outputs (`_build/`, generated `.mbti`) are
gitignored and must not be committed.

## Publishing (maintainers)

`moon.mod` declares `name = "cc06b/mooncry"`, license `Apache-2.0`.
Publishing requires the owner of the `cc06b` namespace to be logged in:

```bash
moon login            # one time, with the account that owns cc06b
moon publish          # publishes the current version
```

Before publishing, ensure all four checks above pass and the tree is clean.

## License

Apache-2.0