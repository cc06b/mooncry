# mooncry

A pure-MoonBit implementation of common cryptographic primitives. No external
dependencies; runs anywhere MoonBit runs.

This is a self-contained reference/teaching implementation. It is **not** a
hardened, audited production library. Constant-time practices are used where
noted (tag comparison, PKCS#7 verification), but the implementations have not
been reviewed for side-channel resistance.

## Algorithms

### Hash functions
- **MD5** (RFC 1321) — 128-bit digest
- **SHA-256** (FIPS 180-4) — 256-bit digest
- **SHA-512** (FIPS 180-4) — 512-bit digest

### Message authentication
- **HMAC-SHA256** (RFC 2104)

### Symmetric ciphers
- **AES-CBC** (NIST SP 800-38A) — PKCS#7 padding, 128/192/256-bit keys
- **AES-GCM** (NIST SP 800-38D) — authenticated encryption with AAD, 128/192/256-bit keys, 96-bit nonce
- **ChaCha20** (RFC 8439) — 256-bit key, 96-bit nonce, 32-bit block counter (stream cipher, not an AEAD)

### Encoding
- **Base64** (RFC 4648) — standard alphabet with padding

### Streaming API
MD5, SHA-256, and SHA-512 support incremental `update` / `finalize` for
streaming or large inputs:

- `md5_new()` / `md5_update()` / `md5_finalize()`
- `sha256_new()` / `sha256_update()` / `sha256_finalize()`
- `sha512_new()` / `sha512_update()` / `sha512_finalize()`

## Installation

```bash
moon add cc06b/mooncry
```

## Quick start

```moonbit
import @cc06b/mooncry/lib as crypto

fn main {
  // One-shot hash
  let digest = crypto.sha256(b"Hello, world!")
  println(crypto.bytes_to_hex(digest))

  // Streaming hash
  let hasher = crypto.sha256_new()
  crypto.sha256_update(hasher, b"Hello, ")
  crypto.sha256_update(hasher, b"world!")
  let result = crypto.sha256_finalize(hasher)
  println(crypto.bytes_to_hex(result))

  // AES-GCM (256-bit key, 96-bit nonce, with AAD)
  let key = Bytes::make(32, b'\x00')
  let iv = Bytes::make(12, b'\x00')
  let (ciphertext, tag) = crypto.aes_gcm_encrypt(b"secret data", key, iv, b"aad")
  let (plaintext, ok) = crypto.aes_gcm_decrypt(ciphertext, key, iv, b"aad", tag)
  assert_true(ok)
  ignore(plaintext)
}
```

## Public API

All functions live in the `lib` package (`@cc06b/mooncry/lib`).

| Function | Description |
| --- | --- |
| `md5(data : Bytes) -> Bytes` | MD5 one-shot, 16-byte digest |
| `sha256(data : Bytes) -> Bytes` | SHA-256 one-shot, 32-byte digest |
| `sha512(data : Bytes) -> Bytes` | SHA-512 one-shot, 64-byte digest |
| `hmac_sha256(key : Bytes, message : Bytes) -> Bytes` | HMAC-SHA256 |
| `aes_encrypt_cbc(data, key, iv) -> Bytes` | AES-CBC encrypt (IV prepended, PKCS#7) |
| `aes_decrypt_cbc(data, key, iv) -> Bytes` | AES-CBC decrypt (reads prepended IV) |
| `aes_gcm_encrypt(pt, key, iv, aad) -> (Bytes, Bytes)` | AES-GCM encrypt → (ciphertext, 16-byte tag) |
| `aes_gcm_decrypt(ct, key, iv, aad, tag) -> (Bytes, Bool)` | AES-GCM decrypt, constant-time tag verify |
| `chacha20_xor(input, key, nonce, counter) -> Bytes` | ChaCha20 encrypt/decrypt (symmetric) |
| `base64_encode(data : Bytes) -> String` | Base64 encode (RFC 4648) |
| `base64_decode(encoded : String) -> Bytes` | Base64 decode |
| `bytes_to_hex(data : Bytes) -> String` | Lowercase hex |
| `bytes_equal(a : Bytes, b : Bytes) -> Bool` | Constant-time comparison |

CBC/GCM keys may be 128, 192, or 256 bits; the nonce for GCM and ChaCha20 is
96 bits (12 bytes), the recommended length per spec.

## Testing

Every algorithm is verified against official standard vectors:

```bash
moon test
```

Coverage:

- **MD5** — RFC 1321 vectors (empty, `"a"`, `"abc"`, `"message digest"`, alphabet) + one-million-`a`
- **SHA-256** — FIPS 180-4 §B.1 (empty, `"abc"`, 56-byte boundary) + one-million-`a`
- **SHA-512** — FIPS 180-4 §B.3 (empty, `"abc"`, 112-byte block boundary) + one-million-`a`
- **HMAC-SHA256** — RFC 4231 cases 1 & 2
- **AES-CBC** — NIST SP 800-38A F.2.1 (128) and F.2.5 (256), plus round-trips
- **AES-GCM** — NIST SP 800-38D test cases (128: TC1–4; 256: TC13–14), plus tamper detection
- **ChaCha20** — RFC 8439 §2.3.2 block function (canonical keystream), multi-block, round-trip
- **Base64** — RFC 4648 vectors (all length classes)
- **Streaming** — MD5/SHA-256/SHA-512 streaming matches one-shot, incl. 1-byte chunk feeding

## Development

The CI (`.github/workflows/moonbit-ci.yml`) runs the four required MoonBit
checks: `moon check --deny-warn`, `moon fmt --check`, `moon info`, and
`moon test --deny-warn`, and verifies that no build artifacts are tracked.

Run them locally:

```bash
moon check --deny-warn
moon fmt --check
moon info
moon test --deny-warn
```

## Publishing (maintainers)

The module metadata (`moon.mod.json`: name `cc06b/mooncry`, repository
`github.com/cc06b/mooncry`, license `Apache-2.0`, version `0.1.0`) is set up
for [mooncakes.io](https://mooncakes.io). Publishing requires the owner of the
`cc06b` namespace to be logged in:

```bash
moon login            # one time, with the account that owns cc06b
moon publish          # publishes the current version
```

Before publishing, ensure all four checks above pass and the tree is clean
(`moon clean` to drop `_build/` and generated `.mbti` files, which are
gitignored and must not be committed).

## License

Apache-2.0
