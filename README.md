# mooncry

A pure-MoonBit, zero-dependency native cryptographic library for the MoonBit
ecosystem. No FFI, no C — every primitive is implemented in plain MoonBit and
verified against official standard vectors.

## Highlights

- **Correct** — every algorithm is checked against FIPS / NIST / RFC test
  vectors, and cross-validated against reference implementations
  (pycryptodome, cryptography, hashlib, libsodium, zlib) plus randomized
  differential testing. 471 tests, run with `moon test --deny-warn`.
- **Broad** — MD5, **SHA-1**, the SHA-2 and SHA-3 families (incl. **SHA-512/224
  and SHA-512/256**), **Keccak-256**,
  SHAKE/**cSHAKE** XOFs, **KMAC128/256**, BLAKE2b, **BLAKE2s**, BLAKE3,
  **RIPEMD-160**,
  HMAC (incl. HMAC-SHA3), Poly1305, CMAC-AES, **keyed BLAKE2b/2s**, **GMAC**,
  AES-CBC/GCM/CTR/**CCM**/**KW**/**SIV**, ChaCha20,
  **Salsa20**, ChaCha20-Poly1305 AEAD, **XChaCha20 / XChaCha20-Poly1305**
  (24-byte nonce), HKDF, PBKDF2, **scrypt**, **Argon2**,
  **RSA (PKCS1-v1.5/OAEP/PSS)**, **ECDSA P-256**, **Ed25519** (incl.
  **Ed25519ctx / Ed25519ph**), **X25519**,
  **HOTP/TOTP** (incl. **SHA-256/SHA-512** variants), SipHash-2-4, CRC32/CRC32C/**CRC-64**/**Adler-32**, a sealed-box AEAD envelope, Base64, Hex.
- **Fast where it matters** — hex / Base64 encoding are O(n); AES MixColumns
  uses precomputed GF(2^8) tables (~5x over bit-sliced math); throughput is
  measured by `moon bench`.
- **Fail-fast input validation** — AES / ChaCha20 / SHAKE / hex functions abort
  with a clear message on wrong key / IV / nonce / tag lengths instead of
  producing garbage. Graceful `Result`-returning variants (`hex_to_bytes_or`,
  `base64_decode_or`) are provided for callers that prefer to branch on error.
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
- **SHA-512/224 / SHA-512/256** (FIPS 180-4 §5.3.6) — truncated SHA-512 variants
- **SHA-3** (FIPS 202) — SHA3-224 / 256 / 384 / 512 (Keccak-f[1600] sponge)
- **Keccak-256** (original Keccak submission, domain 0x01) — the Ethereum hash
- **BLAKE2b** (RFC 7693) — 1..64-byte digest; **keyed** variant (MAC, 1..64-byte key)
- **BLAKE2s** (RFC 7693) — 1..32-byte digest (32-bit words, 64-byte blocks);
  **keyed** variant (MAC, 1..32-byte key)
- **RIPEMD-160** (Dobbertin et al. 1996) — 160-bit digest (Bitcoin legacy)
- **BLAKE3** (BLAKE3 spec) — 32-byte default digest, XOF (arbitrary-length via tree-Merkle)

### Extendable-output functions (XOF)
- **SHAKE128 / SHAKE256** (FIPS 202) — variable-length output
- **cSHAKE128 / cSHAKE256** (NIST SP 800-185) — customizable XOFs
  (function name N + customization string S; degenerate to SHAKE when both empty)

### Message authentication
- **HMAC-SHA256 / HMAC-SHA512** (RFC 2104)
- **HMAC-SHA3-256 / HMAC-SHA3-512** (RFC 2104 over FIPS 202)
- **HMAC-SHA3-224 / HMAC-SHA3-384** (RFC 2104 over FIPS 202)
- **Poly1305** (RFC 8439) — one-time MAC
- **AES-CMAC** (NIST SP 800-38B) — 128-bit tag, 128/192/256-bit keys
- **KMAC128 / KMAC256** (NIST SP 800-185) — Keccak-based MAC with
  customization string; **KMACXOF128 / KMACXOF256** variable-length variants
- **GMAC** (NIST SP 800-38D) — AES-GCM authentication-only mode (16-byte tag)

### Symmetric ciphers / AEAD
- **AES-CBC** (NIST SP 800-38A) — PKCS#7 padding, 128/192/256-bit keys, IV prepended
- **AES-GCM** (NIST SP 800-38D) — authenticated encryption with AAD, 96-bit nonce
- **AES-CCM** (NIST SP 800-38C / RFC 3610) — CBC-MAC + CTR AEAD, 7..13-byte
  nonce, 4..16-byte tag
- **Adler-32** (RFC 1950) — zlib rolling checksum
- **AES-CTR** (NIST SP 800-38A) — 128-bit big-endian counter, stream cipher
- **ChaCha20** (RFC 8439) — 256-bit key, 96-bit nonce, stream cipher
- **Salsa20** (eSTREAM, 20-round) — 16/32-byte key, 8-byte nonce, stream
  cipher
- **ChaCha20-Poly1305** (RFC 8439) — AEAD (ciphertext || 16-byte tag)
- **XChaCha20** (draft-irtf-cfrg-xchacha) — ChaCha20 with a 24-byte nonce
  via HChaCha20 subkey derivation
- **XChaCha20-Poly1305** (draft-irtf-cfrg-xchacha / libsodium IETF) — AEAD
  with a 24-byte nonce (ciphertext || 16-byte tag)

### Key derivation
- **HKDF-SHA256** (RFC 5869) — extract + expand
- **HKDF-SHA512** (RFC 5869) — extract + expand over SHA-512
- **HKDF-SHA3-256** (RFC 5869 over FIPS 202)
- **PBKDF2-HMAC-SHA256** (RFC 8018) — password-based key derivation
- **PBKDF2-HMAC-SHA1** (RFC 8018 / RFC 6070 vectors) — legacy KDF (WPA2)
- **PBKDF2-HMAC-SHA512** (RFC 8018) — password-based key derivation
- **PBKDF2-HMAC-SHA3-256** (RFC 8018 over FIPS 202)
- **scrypt** (RFC 7914) — memory-hard password-based KDF (Salsa20/8 + BlockMix + ROMix)

### Checksums / PRFs
- **CRC32** (IEEE 802.3, poly 0xEDB88320 reflected)
- **CRC32C** (Castagnoli, poly 0x82F63B78 reflected) — iSCSI / ext4
- **CRC-64/XZ** (poly 0x42F0E1EBA9EA3693 reflected) — xz / lzma
- **CRC-64/GO-ISO** (poly 0x000000000000001B reflected) — Go hash/crc64 ISO
- **SipHash-2-4** (Aumasson & Bernstein 2012) — 64-bit short-input PRF

### Composite envelope
- **Sealed box** — versioned AEAD envelope: HKDF-SHA256 (key derivation) +
  AES-256-GCM (AEAD). Wire format: `version(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`.

### Asymmetric (RSA)
- **RSAES-PKCS1-v1.5** (RFC 8017 §7.2) — public-key encryption (decrypt is
  deterministic; encrypt takes caller-supplied padding randomness — no RNG)
- **RSAES-OAEP** (RFC 8017 §7.1) — SHA-256 + MGF1-SHA256 (decrypt deterministic;
  encrypt takes a caller-supplied 32-byte seed)
- **RSASSA-PKCS1-v1.5** (RFC 8017 §8.2) — sign/verify over SHA-256
  (deterministic)
- **RSASSA-PSS** (RFC 8017 §8.1) — SHA-256 + MGF1-SHA256, caller-supplied salt

### Asymmetric signatures (Ed25519)
- **Ed25519** (RFC 8032, ed25519-sha-512) — deterministic sign/verify.
- **Ed25519ctx / Ed25519ph** (RFC 8032 §7.2/§7.3) — context-bound and
  pre-hashed variants (dom2 domain separation)
  Field arithmetic over GF(2^255-19) uses `@bigint`; the twisted-Edwards
  base point is recovered from y = 4/5. Signing is deterministic (no RNG).

### Key agreement (X25519)
- **X25519** (RFC 7748) — Diffie-Hellman over Curve25519 via the
  x-coordinate-only Montgomery ladder. Reuses the GF(2^255-19) field ops.

### Encoding
- **Base64** (RFC 4648) — standard alphabet with padding
- **Hex** — bytes ↔ lowercase hex

### Streaming API
MD5, SHA-224/256/384/512, SHA3-224/256/384/512, and SHAKE128/256 support
incremental `new` / `update` / `finalize` for streaming or large inputs.

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

pkgtype(kind: "executable")
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

  // Sealed-box envelope: HKDF-SHA256 derives the AES-256-GCM key from a
  // master key + context, then encrypts into a versioned envelope.
  let master = Bytes::make(32, b'\x07')
  let nonce = Bytes::make(12, b'\x01')
  let envelope = @lib.sealed_box_seal(master, nonce, b"plaintext", b"aad", b"tenant-1")
  match @lib.sealed_box_open(master, envelope, b"aad", b"tenant-1") {
    Ok(pt) => println("Sealed box: " + @lib.bytes_to_hex(pt))
    Err(msg) => println("Sealed box failed: " + msg)
  }
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
| `sha224 / sha256 / sha384 / sha512(data : Bytes) -> Bytes` | SHA-2 family (FIPS 180-4) |
| `sha512_224 / sha512_256(data : Bytes) -> Bytes` | SHA-512/224 / SHA-512/256 (FIPS 180-4 §5.3.6) |
| `ripemd160(data : Bytes) -> Bytes` | RIPEMD-160, 20-byte digest |
| `sha3_224 / sha3_256 / sha3_384 / sha3_512(data : Bytes) -> Bytes` | SHA-3 (FIPS 202) |
| `keccak_256(data : Bytes) -> Bytes` | Keccak-256 (legacy 0x01 padding, Ethereum), 32 bytes |
| `shake_128 / shake_256(data : Bytes, out_len : Int) -> Bytes` | SHAKE XOF, `out_len` bytes |
| `cshake_128 / cshake_256(data, n, s : Bytes, out_len : Int) -> Bytes` | cSHAKE (SP 800-185); N=S="" ⇒ SHAKE |
| `kmac_128 / kmac_256(key, data, s : Bytes, out_len : Int) -> Bytes` | KMAC fixed-length MAC (SP 800-185) |
| `kmac_xof_128 / kmac_xof_256(key, data, s : Bytes, out_len : Int) -> Bytes` | KMACXOF variable-length variant |
| `blake2b(data : Bytes, out_len : Int) -> Bytes` | BLAKE2b (RFC 7693), `out_len` 1..64 |
| `blake2b_keyed(data, key : Bytes, out_len : Int) -> Bytes` | keyed BLAKE2b (MAC), key 1..64 |
| `blake2s(data : Bytes, out_len : Int) -> Bytes` | BLAKE2s (RFC 7693), `out_len` 1..32 |
| `blake2s_keyed(data, key : Bytes, out_len : Int) -> Bytes` | keyed BLAKE2s (MAC), key 1..32 |
| `blake3(data : Bytes) -> Bytes` | BLAKE3, 32-byte digest |
| `blake3_xof(data : Bytes, out_len : Int) -> Bytes` | BLAKE3 XOF (arbitrary-length) |
| `hmac_sha256 / hmac_sha512(key, msg : Bytes) -> Bytes` | HMAC (RFC 2104) |
| `hmac_sha3_256 / hmac_sha3_512(key, msg : Bytes) -> Bytes` | HMAC over SHA-3 (RFC 2104 + FIPS 202) |
| `hmac_sha3_224 / hmac_sha3_384(key, msg : Bytes) -> Bytes` | HMAC over SHA3-224/384 (RFC 2104 + FIPS 202) |
| `poly1305(key, msg : Bytes) -> Bytes` | Poly1305 MAC (RFC 8439), 16-byte tag |
| `cmac_aes(data, key : Bytes) -> Bytes` | AES-CMAC (NIST SP 800-38B), 16-byte tag |
| `aes_encrypt_cbc / aes_decrypt_cbc(data, key, iv) -> Bytes` | AES-CBC (IV prepended, PKCS#7) |
| `aes_gcm_encrypt(pt, key, iv, aad) -> (Bytes, Bytes)` | AES-GCM encrypt → (ct, 16-byte tag) |
| `aes_gcm_decrypt(ct, key, iv, aad, tag) -> (Bytes, Bool)` | AES-GCM decrypt, constant-time tag verify |
| `aes_ccm_encrypt(pt, key, nonce, aad, mac_len) -> Bytes` | AES-CCM AEAD (SP 800-38C) → ct ‖ tag |
| `aes_ccm_decrypt(input, key, nonce, aad, mac_len) -> Bytes` | AES-CCM decrypt, aborts on tag mismatch |
| `gmac(key, iv, aad) -> Bytes` | GMAC (SP 800-38D), 16-byte tag |
| `gmac_verify(key, iv, aad, tag) -> Bool` | GMAC constant-time tag verify |
| `aes_ctr(data, key, iv) -> Bytes` | AES-CTR encrypt/decrypt (symmetric) |
| `chacha20_xor(input, key, nonce, counter) -> Bytes` | ChaCha20 encrypt/decrypt (symmetric) |
| `salsa20_keystream_block(key, nonce, counter) -> Bytes` | Salsa20 keystream block (64 bytes) |
| `salsa20_xor(key, nonce, counter, data) -> Bytes` | Salsa20 stream cipher encrypt/decrypt (symmetric) |
| `chacha20_poly1305_encrypt(key, nonce, aad, pt) -> Bytes` | ChaCha20-Poly1305 AEAD → ct ‖ tag |
| `chacha20_poly1305_decrypt(key, nonce, aad, input) -> Bytes` | AEAD decrypt, aborts on tag mismatch |
| `hchacha20(key, in16 : Bytes) -> Bytes` | HChaCha20 subkey derivation (draft-irtf-cfrg-xchacha §2.2) |
| `xchacha20_xor(input, key, nonce24, counter) -> Bytes` | XChaCha20 stream cipher, 24-byte nonce (symmetric) |
| `xchacha20_poly1305_encrypt(key, nonce24, aad, pt) -> Bytes` | XChaCha20-Poly1305 AEAD → ct ‖ tag |
| `xchacha20_poly1305_decrypt(key, nonce24, aad, input) -> Bytes` | XChaCha20-Poly1305 AEAD decrypt, aborts on tag mismatch |
| `hotp_sha256 / hotp_sha512(key, counter, digits) -> String` | HOTP (RFC 4226) with HMAC-SHA256/512 |
| `totp_sha256 / totp_sha512(key, unix_time, step, digits) -> String` | TOTP (RFC 6238) with HMAC-SHA256/512 |
| `ed25519ctx_sign(seed, msg, ctx) / ed25519ctx_verify(pk, msg, sig, ctx)` | Ed25519ctx (RFC 8032), ctx 1..255 bytes |
| `ed25519ph_sign(seed, msg, ctx) / ed25519ph_verify(pk, msg, sig, ctx)` | Ed25519ph (RFC 8032), SHA-512 prehash |
| `adler32(data : Bytes) -> Bytes` | Adler-32 (RFC 1950), 4-byte big-endian |
| `hkdf_sha256(salt, ikm, info, len) -> Bytes` | HKDF-SHA256 (RFC 5869) |
| `hkdf_sha512(salt, ikm, info, len) -> Bytes` | HKDF-SHA512 (RFC 5869) |
| `pbkdf2_hmac_sha256(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA256 (RFC 8018) |
| `pbkdf2_hmac_sha512(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA512 (RFC 8018) |
| `pbkdf2_hmac_sha1(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA1 (RFC 8018) |
| `hkdf_sha3_256(salt, ikm, info, len) -> Bytes` | HKDF-SHA3-256 (RFC 5869 over FIPS 202) |
| `pbkdf2_hmac_sha3_256(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA3-256 (RFC 8018 over FIPS 202) |
| `scrypt(password, salt, n, r, p, dklen) -> Bytes` | scrypt memory-hard KDF (RFC 7914), `n` power of two |
| `rsa_pkcs1_v15_encrypt(msg, n, e, rand_ps) -> Bytes` | RSAES-PKCS1-v1.5 encrypt (RFC 8017 §7.2) |
| `rsa_pkcs1_v15_decrypt(ct, n, d) -> Bytes` | RSAES-PKCS1-v1.5 decrypt |
| `rsa_pkcs1_v15_sign(msg, n, d) -> Bytes` | RSASSA-PKCS1-v1.5 sign (SHA-256) |
| `rsa_pkcs1_v15_verify(msg, sig, n, e) -> Bool` | RSASSA-PKCS1-v1.5 verify |
| `rsa_oaep_encrypt(msg, n, e, seed, label) -> Bytes` | RSAES-OAEP encrypt (SHA-256) |
| `rsa_oaep_decrypt(ct, n, d, label) -> Bytes` | RSAES-OAEP decrypt |
| `rsa_pss_sign(msg, n, d, salt) -> Bytes` | RSASSA-PSS sign (SHA-256) |
| `rsa_pss_verify(msg, sig, n, e, salt_len) -> Bool` | RSASSA-PSS verify |
| `ed25519_public_key(seed) -> Bytes` | Derive 32-byte Ed25519 public key |
| `ed25519_sign(seed, message) -> Bytes` | Ed25519 sign (RFC 8032), 64-byte sig |
| `ed25519_verify(public_key, message, sig) -> Bool` | Ed25519 verify |
| `x25519(scalar, u) -> Bytes` | X25519 scalar mult (RFC 7748), DH shared secret |
| `x25519_public_key(private_key) -> Bytes` | Derive X25519 public key (base u=9) |
| `crc32 / crc32c(data : Bytes) -> Bytes` | CRC-32 (IEEE) / CRC-32C, 4-byte big-endian |
| `crc64_xz / crc64_go_iso(data : Bytes) -> Bytes` | CRC-64/XZ / CRC-64/GO-ISO, 8-byte big-endian |
| `siphash_2_4(key, data : Bytes) -> Bytes` | SipHash-2-4 (64-bit), key 16 bytes → 8 bytes |
| `sealed_box_seal(master_key, nonce, pt, aad, ctx) -> Bytes` | AEAD envelope (HKDF + AES-256-GCM) |
| `sealed_box_open(master_key, envelope, aad, ctx) -> Result[Bytes, String]` | Open envelope, `Err` on auth failure |
| `base64_encode(data : Bytes) -> String` | Base64 encode (RFC 4648) |
| `base64_decode(encoded : String) -> Bytes` | Base64 decode |
| `base64_decode_or(encoded : String) -> Result[Bytes, String]` | Base64 decode, `Err` on malformed input |
| `bytes_to_hex(data : Bytes) -> String` | Bytes → lowercase hex |
| `hex_to_bytes(hex : String) -> Bytes` | hex → Bytes (aborts on bad input) |
| `hex_to_bytes_or(hex : String) -> Result[Bytes, String]` | hex → Bytes, `Err` on bad input |
| `bytes_equal(a, b : Bytes) -> Bool` | Constant-time comparison |

Streaming hashers (`<algo>_new` / `sha3_update` / `sha3_finalize` /
`shake_finalize`) are available for MD5, SHA-224/256/384/512, SHA3-224/256/384/512,
and SHAKE128/256, plus SHA-512/224 / SHA-512/256 (`sha512_224_new` /
`sha512_256_new` with `sha512_update`). For SHA-3/SHAKE, `sha3_update` is shared and the finalize
method depends on the variant (`sha3_finalize` for fixed-length, `shake_finalize(h, out_len)` for XOF).

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
  **not side-channel-safe** against a local attacker. Since v0.19.0 GHASH also
  uses precomputed 4-bit tables (keyed by the GCM hash subkey), so it is no
  longer bit-sliced and is likewise **not side-channel-safe**; the GCM
  *tag comparison* and CBC PKCS#7 *verification* remain constant-time
  (no early exit on mismatch).
- **Nonce reuse is catastrophic** for AES-GCM and ChaCha20(-Poly1305). Never
  reuse a (key, nonce) pair. The library does not track nonces — generate a
  fresh one per message (e.g. a counter or CSPRNG).
- **PBKDF2 is a KDF, not a password hasher.** For interactive password storage
  prefer Argon2 / bcrypt / scrypt elsewhere; PBKDF2 is included for
  compatibility with existing protocols.
- **MD5 is collision-broken.** It is included for legacy compatibility only —
  do not sign or authenticate with it.
- **BLAKE3 supports arbitrary-length input** via the tree-Merkle mode (verified
  vs the reference `blake3` Python package up to 5000 bytes).
- **Inputs are validated, not silently padded.** Wrong key / IV / nonce / tag
  lengths `abort` immediately rather than producing wrong output.
- **No RNG.** The library provides deterministic primitives; obtain keys, IVs,
  and nonces from a secure source.

## Performance

Throughput is measured by the `lib` benchmark suite (`moon bench`) on 1 KiB
inputs. Figures below are from the development sandbox; absolute numbers vary
by host — run `moon bench` locally for comparable figures.

```bash
moon bench
```

| Algorithm | 1 KiB (approx.) |
| --- | --- |
| MD5 | ~8.5 µs |
| SHA-256 | ~16 µs |
| SHA-512 | ~14 µs |
| SHA3-256 | ~140 µs |
| SHAKE128 1KiB (out=32) | ~80 µs |
| SHAKE256 1KiB (out=64) | ~92 µs |
| BLAKE2b | ~27 µs |
| BLAKE3 | ~46 µs |
| HMAC-SHA256 | ~23 µs |
| HMAC-SHA3-256 | ~213 µs |
| HMAC-SHA3-512 | ~338 µs |
| AES-128-CMAC | ~347 µs |
| SipHash-2-4 | ~4.2 µs |
| CRC32 / CRC32C | ~4.7 µs |
| sealed_box_seal | ~588 µs (HKDF + AES-256-GCM) |
| scrypt (N=1024,r=8,p=1,dk32) | ~84 ms (memory-hard KDF) |
| Argon2id (t=1,m=64,p=1,dk16) | ~1 ms (memory-hard KDF) |
| ECDSA P-256 sign | ~13 ms (Jacobian, was ~270 ms affine) |
| ECDSA P-256 verify | ~24 ms (Jacobian, was ~540 ms affine) |
| AES-256-SIV encrypt 1KiB | ~950 µs (S2V + AES-CTR) |
| AES-128-KW wrap 32B | ~146 µs |
| ChaCha20 | ~48 µs |
| ChaCha20-Poly1305 encrypt | ~73 µs (was ~456 µs) |
| Poly1305 MAC | ~7 µs (was ~387 µs, BigInt) |
| AES-256-CBC | ~315 µs (table-based GF mul) |
| AES-256-GCM | ~487 µs (GHASH 4-bit tables) |
| Base64 encode | ~10 µs |
| Hex encode | ~6.7 µs |

**v0.18.0 perf pass.** The Keccak-f[1600] state was flattened from a
nested 5×5 `Array[Array[UInt64]]` to a flat 25-lane array (removing the
inner-array indirection from the hot permutation loop), and ChaCha20 now
expands the key/nonce words once per call instead of per block. Measured
on 1 KiB inputs: SHAKE128 ~123 → ~80 µs (**-35%**), SHAKE256 ~136 → ~92 µs
(**-32%**), ChaCha20 ~54 → ~48 µs (**-11%**).

**v0.19.0 perf pass.** GHASH (the GF(2^128) multiply inside AES-GCM) was
rewritten from a 128-iteration bit-serial loop to a precomputed 4-bit
table (32 nibble lookups + XORs per multiply), cutting AES-256-GCM from
~507 to ~487 µs/KiB. Poly1305 was rewritten from per-block `@bigint`
arithmetic to 5-limb radix-2^26 arithmetic with UInt64 partial products
("donna" style): Poly1305 drops from ~387 to ~7 µs/KiB (**-98%**), which
takes ChaCha20-Poly1305 AEAD from ~456 to ~73 µs/KiB (**-84%**) and also
speeds up XChaCha20-Poly1305 and the sealed-box envelope.

**v0.20.0 perf pass.** ECDSA P-256 point arithmetic moved from affine to
Jacobian projective coordinates. Affine double/add each need one
Fermat-exponentiation modular inverse (~256 field muls), so a 256-bit
scalar multiplication cost ~384 inverses; Jacobian double/add need none,
inverting only once when converting back to affine. All field
subtractions stay non-negative (the X25519 BigInt lesson). Measured on
one host: sign ~270 → ~13 ms and verify ~540 → ~24 ms (**~21-23x**).
Signatures are byte-identical to before (RFC 6979 deterministic k is
unchanged), so no compatibility break.

Hashes, ChaCha20, and hex/Base64 are throughput-bound by the algorithm; AES
trades constant-time property for ~5x speed via lookup tables (see
[Security & performance boundaries](#security--performance-boundaries)).

## Testing

Every algorithm is verified against official standard vectors:

```bash
moon test
```

Coverage: MD5 (RFC 1321), SHA-2 family (FIPS 180-4 + million-`a`), SHA-3
(NIST KAT), SHAKE (FIPS 202), BLAKE2b (RFC 7693 + hashlib), BLAKE3 (python
blake3), HMAC (RFC 4231), **HMAC-SHA3** (hashlib), **Poly1305** (RFC 8439),
**AES-CMAC** (NIST SP 800-38B + pycryptodome), ChaCha20-Poly1305 (RFC 8439 +
pycryptodome), HKDF (RFC 5869), PBKDF2 (RFC 6070), **scrypt** (RFC 7914 +
hashlib.scrypt), AES-CBC/GCM/CTR (NIST SP
800-38A/D), ChaCha20 (RFC 8439), **RSA** (RFC 8017 PKCS1-v1.5/OAEP/PSS +
pycryptodome), **Ed25519** (RFC 8032 + cryptography lib), **X25519** (RFC 7748 + cryptography lib), **CRC32/CRC32C** (zlib + manual ref),
**SipHash-2-4** (Python reference), **Salsa20** (eSTREAM + pycryptodome), **SHA-1** (hashlib) + **HOTP/TOTP** (RFC 4226/6238), Base64 (RFC 4648), hex round-trip,
**Keccak-256 / cSHAKE128/256 / KMAC128/256/XOF** (NIST SP 800-185 official
samples + pycryptodome, differential-tested), **CRC-64/XZ + CRC-64/GO-ISO**
(CRC RevEng check values), **SHA-512/224 / SHA-512/256** (FIPS 180-4 +
hashlib), **BLAKE2s** (RFC 7693 + hashlib), **HMAC-SHA3-224/384** (stdlib
hmac), **XChaCha20 / XChaCha20-Poly1305** (draft-irtf-cfrg-xchacha official
vectors + libsodium, differential-tested), **TOTP-SHA256/512** (RFC 6238
Table 1, all 12 rows), **HKDF-SHA512 / PBKDF2-HMAC-SHA512** (RFC 5869
construction anchored on TC1 + hashlib), **RIPEMD-160** (official paper
suite incl. million-`a`, + hashlib), **AES-CCM** (RFC 3610 Packet Vector
#1 + pycryptodome), **Ed25519ctx / Ed25519ph** (RFC 8032 §7.2/§7.3 official
vectors), **GMAC** (pycryptodome GCM), **keyed BLAKE2b/2s** (hashlib keyed),
**Adler-32** (zlib), **PBKDF2-HMAC-SHA1** (RFC 6070 official suite),
**sealed-box** round-trip + tamper, and property-based round-trip checks
(deterministic PRNG) for every cipher + streaming-vs-one-shot consistency.
**471 tests.**

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

The module manifest is `moon.mod` (TOML); per-package manifests are `moon.pkg`
(TOML). Build outputs (`_build/`, generated `.mbti`) are gitignored and must
not be committed.

## Publishing (maintainers)

`moon.mod` declares `name = "cc06b/mooncry"`, license `Apache-2.0`. Publishing
requires the owner of the `cc06b` namespace to be logged in:

```bash
moon login            # one time, with the account that owns cc06b
moon publish          # publishes the current version
```

Before publishing, ensure all four checks above pass and the tree is clean.

## License

Apache-2.0
