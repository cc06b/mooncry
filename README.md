# mooncry

A pure MoonBit implementation of common cryptographic primitives. No external dependencies, runs everywhere MoonBit runs.

## Algorithms

### Hash Functions
- **MD5** (RFC 1321) — 128-bit digest
- **SHA-256** (FIPS 180-4) — 256-bit digest
- **SHA-512** (FIPS 180-4) — 512-bit digest

### Message Authentication
- **HMAC-SHA256** (RFC 2104)

### Symmetric Ciphers
- **AES-CBC** (NIST SP 800-38A) — PKCS#7 padding, 128/192/256-bit keys
- **AES-GCM** (NIST SP 800-38D) — authenticated encryption with AAD, 128/192/256-bit keys
- **ChaCha20** (RFC 8439) — 256-bit stream cipher

### Encoding
- **Base64** (RFC 4648) — standard alphabet with padding

### Streaming API
All hash functions support incremental `update` / `finalize` for streaming or large data:
- `md5_new()` / `md5_update()` / `md5_finalize()`
- `sha256_new()` / `sha256_update()` / `sha256_finalize()`
- `sha512_new()` / `sha512_update()` / `sha512_finalize()`

## Installation

```bash
moon add cc06b/mooncry
```

## Quick Start

```moonbit
import @cc06b/mooncry/lib as crypto

fn main() -> Unit {
  // One-shot hash
  let digest = crypto.sha256(b"Hello, world!")
  println(crypto.bytes_to_hex(digest))

  // Streaming hash
  let hasher = crypto.sha256_new()
  crypto.sha256_update(hasher, b"Hello, ")
  crypto.sha256_update(hasher, b"world!")
  let result = crypto.sha256_finalize(hasher)
  println(crypto.bytes_to_hex(result))

  // AES-GCM encrypt
  let key = Bytes::make(32, b'\x00') // 256-bit key
  let iv = Bytes::make(12, b'\x00')  // 96-bit nonce
  let (ciphertext, tag) = crypto.aes_gcm_encrypt(b"secret data", key, iv, b"aad")
  let (plaintext, ok) = crypto.aes_gcm_decrypt(ciphertext, key, iv, b"aad", tag)
  assert(ok)
}
```

## Testing

All algorithms are verified against official standard vectors:

```bash
moon test
```

Test coverage includes:
- MD5: RFC 1321 test vectors
- SHA-256 / SHA-512: FIPS 180-4 standard vectors
- HMAC-SHA256: RFC 4231 test cases
- AES-CBC: NIST SP 800-38A F.2.1
- AES-GCM: NIST SP 800-38D test vectors
- ChaCha20: RFC 8439 Section 2.3.2 block function
- Base64: RFC 4648 test vectors

## License

Apache-2.0
