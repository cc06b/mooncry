# mooncry

A pure-MoonBit, zero-dependency native cryptographic library for the MoonBit
ecosystem. No FFI, no C — every primitive is implemented in plain MoonBit and
verified against official standard vectors.

## Highlights

- **Correct** — every algorithm is checked against FIPS / NIST / RFC test
  vectors, and cross-validated against reference implementations
  (pycryptodome, cryptography, hashlib, libsodium, zlib) plus randomized
  differential testing. 1177 tests, run with `moon test --deny-warn`.
- **Broad** — MD5, **SHA-1**, the SHA-2 and SHA-3 families (incl. **SHA-512/224
  and SHA-512/256**), **Keccak-256**,
  SHAKE/**cSHAKE** XOFs, **KMAC128/256**, BLAKE2b, **BLAKE2s**, BLAKE3,
  **RIPEMD-160**,
  HMAC (incl. HMAC-SHA3), Poly1305, CMAC-AES, **keyed BLAKE2b/2s**, **GMAC**,
  AES-CBC/GCM/CTR/**CCM**/**KW**/**SIV**, ChaCha20,
  **Salsa20**, ChaCha20-Poly1305 AEAD, **XChaCha20 / XChaCha20-Poly1305**
  (24-byte nonce), HKDF, PBKDF2, **scrypt**, **Argon2**,
  **RSA (PKCS1-v1.5/OAEP/PSS**, incl. multi-hash `_with` variants**)**,
  **ECDSA P-256 / secp256k1**, **SM2** (GB/T 32918, Chinese national standard), **Ed25519** (incl.
  **Ed25519ctx / Ed25519ph**), **Ed448** (incl. contexts), **X25519 / X448**,
  **ML-KEM-512/768/1024** (FIPS 203 post-quantum KEM),
  **HOTP/TOTP** (incl. **SHA-256/SHA-512** variants), SipHash-2-4, CRC32/CRC32C/**CRC-64**/**Adler-32**, a sealed-box AEAD envelope, Base64, Hex.
- **Fast where it matters** — hex / Base64 encoding are O(n); AES MixColumns
  uses precomputed GF(2^8) tables (~5x over bit-sliced math); throughput is
  measured by `moon bench`.
- **Fail-fast on misuse, graceful on hostile input** — AES / ChaCha20 / SHAKE /
  hex functions abort with a clear message on wrong key / IV / nonce / tag
  lengths instead of producing garbage. Where the *content* (not just the
  length) crosses a trust boundary — a peer's ciphertext, signature, public
  key, or an encoded blob — every failure is reported as a value instead:
  `Bool` (verifiers, GCM), `Option` (GCM-SIV, HPKE open, hybrid open), or
  `Result` (SIV, KW, sealed box, and the `_or` family below). A dedicated
  [robustness suite](#testing) fuzzes each of those entry points with
  truncated, extended, bit-flipped and wiped inputs.
- **Graceful `_or` variants** — `hex_to_bytes_or`, `base64_decode_or`,
  `chacha20_poly1305_decrypt_or`, `xchacha20_poly1305_decrypt_or`,
  `aes_ccm_decrypt_or`, `aes_decrypt_cbc_or`, `sm4_cbc_decrypt_or`,
  `rsa_oaep_decrypt_or` (+ `_with_or` / `_crt_or`),
  `rsa_pkcs1_v15_decrypt_or` (+ `_crt_or`), `ml_kem_*_encaps_or` /
  `ml_kem_*_decaps_or`, `ml_kem_*_hybrid_seal_or` (+ `_seal_init_or`),
  `rsa_oaep_encrypt_or` (+ `_with_or`) / `rsa_pkcs1_v15_encrypt_or`,
  `sm2_encrypt_or` / `sm2_encrypt_with_k_or` / `sm2_seal_or` / `sm2_open_or`,
  `sm2_ct_to_der_or` / `sm2_ct_from_der_or` / `sm2_sig_to_der_or` /
  `sm2_sig_from_der_or` / `sm2_pk_to_spki_der_or` / `sm2_spki_der_to_pk_or` /
  `sm2_pk_to_pem_or` / `sm2_pk_from_pem_or` / `sm2_pkcs8_der_to_sk_or` /
  `sm2_sk_from_pem_or`,
  `xwing_encaps_or` / `xwing_decaps_or`, `x25519_or` /
  `x448_or`, and the HPKE `*_or` setup/encap/decap family return `Result` so
  network-facing code never traps on malformed input. The RSA decryption ones
  return a single uniform error for every padding failure (no
  Bleichenbacher/Manger oracle through error text), and so do the SM2 envelope
  and ML-KEM hybrid openers — a truncated blob, a wrong-length key and a failed
  tag are deliberately indistinguishable there too.
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
- **SM3** (GB/T 32905-2016) — Chinese national hash standard, 256-bit digest;
  streaming API (`sm3_new/sm3_update/sm3_finalize`)

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
- **GMAC** (NIST SP 800-38D) — AES-GCM authentication-only mode (16-byte
  tag); one-shot and incremental (`gmac_new` / `gmac_update` /
  `gmac_finalize`)

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
- **SM4** (GB/T 32907-2016) — Chinese national block cipher, 128-bit
  block/key, 32-round Feistel; single-block encrypt/decrypt with reusable
  round keys
- **SM4-CTR / SM4-CBC / SM4-GCM** — modes of operation (GCM reuses the
  cipher-independent GHASH); **HMAC-SM3** (RFC 2104). Vectors cross-checked
  against openssl's SM4/SM3
- **HKDF-SM3 / PBKDF2-SM3** (RFC 5869 / RFC 2898 over HMAC-SM3) and SM2
  signature DER encode/decode (openssl ASN.1 form) — vectors from openssl
- **SM2 key serialization** — PKCS#8 / SPKI in DER and PEM, byte-identical
  to openssl 3.x encodings (verified against PEMs openssl produced and
  consumed); strict decoders with malformed-input rejection
- **SM2 sealed envelope** (GM/T 0009 style) — `sm2_seal/sm2_open`: fresh
  SM4 key + IV wrapped to the recipient, payload under SM4-GCM
- **ZUC-128** (GM/T 0001.1-2012 / 3GPP TS 35.221) — the Chinese national
  stream cipher behind LTE/NR confidentiality and integrity: a 16-cell LFSR
  over GF(2^31−1), bit reorganization, and the F function with the S0/S1
  S-boxes. Raw keystream and stream XOR are exposed directly
- **128-EEA3** (3GPP TS 35.222) — the ZUC confidentiality algorithm
  (`f8`): COUNT/BEARER/DIRECTION build the IV, and the output is masked to an
  exact **bit** length
- **128-EIA3** (3GPP TS 35.223) — the ZUC integrity algorithm (`f9`):
  bit-oriented MAC-I over the message, with a constant-time *tag check*
  (`zuc_eia3_verify`). Neither mode authenticates on its own; pair EEA3 with
  EIA3 the way PDCP does
- **ZUC-256** (GM/T 0001.2 / TS 35.221 v17+) — the 256-bit-key variant: a
  32-byte key and a 23-byte IV carrying eight 6-bit frame parameters, packed
  into the same engine. Keystream (`zuc256_keystream`), raw stream mode
  (`zuc256_xor`) and a MAC with a 32-, 64- or 128-bit tag (`zuc256_mac`,
  `zuc256_mac_verify`); the tag sizes are domain-separated by the D-matrix row,
  so a short tag is never a prefix of a longer one

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
- **SM2 encryption** (GB/T 32918.4) — C1||C3||C2 raw form plus DER
  (openssl ASN.1) encode/decode; SM3 counter KDF; cross-proven against
  openssl pkeyutl SM2 decrypt
- **SM2** (GB/T 32918.2/.5) — Chinese national signature standard over
  sm2p256v1; SM3-based Z value binds signer ID, curve, and public key;
  raw r||s (64-byte) signatures; reuses the generic Barrett/Jacobian EC
  engine (SM2's a = p-3, the P-256 fast-doubling case)

### Key agreement (X25519)
- **X25519** (RFC 7748) — Diffie-Hellman over Curve25519 via the
  x-coordinate-only Montgomery ladder. Reuses the GF(2^255-19) field ops.

### Encoding
- **Base64** (RFC 4648) — standard alphabet with padding
- **Hex** — bytes ↔ lowercase hex

### Streaming API
MD5, SHA-224/256/384/512, SHA3-224/256/384/512, and SHAKE128/256 support
incremental `new` / `update` / `finalize` for streaming or large inputs.
For byte-at-a-time streams prefer `sha256_update_byte` /
`sha224_update_byte` over `update(hasher, Bytes::make(1, b))`: no `Bytes`
allocation and a minimal hot path (~1.3x one-shot cost vs ~3.7x for
1-byte `update` chunks).

**A hasher is single-use.** `finalize` pads the internal state in place, so
calling it twice — or calling `update` after it — produces a *wrong digest
with no error*. Create a new hasher per message. To fork a stream mid-way
(e.g. to try two suffixes) use `sha256_clone` / `sha512_clone` /
`sha3_clone` / `sm3_clone` and finalize the copy — and clone *before*
finalizing the original, since a clone of a finalized hasher copies the
padded state (measured: it hashes to neither suffix).

**Incremental MAC and AEAD states are single-use the same way.**
`gmac_finalize` folds the length block into its accumulator and
`ml_kem_hybrid_stream_final` encrypts the residue and finishes Poly1305;
neither resets. A second finalize, an update after finalize, or reusing the
state for an unrelated message yields a *different tag or blob with no error*
— measured for GMAC, not assumed. One state per message; `gmac_new` /
`gmac_new_iv` / `ml_kem_*_hybrid_seal_init` are cheap. (`poly1305_finalize`
happens to be repeatable today, which is not a contract — treat every finalize
as consuming its state.)

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
| `sm3(data : Bytes) -> Bytes` | SM3 (GB/T 32905), 32-byte digest |
| `sm3_new() / sm3_update(h, data) / sm3_finalize(h)` | SM3 streaming hasher |
| `sm3_clone(h) -> Sm3Hasher` | Deep-copy an SM3 hasher (prefix reuse) |
| `sm4_encrypt(key, block) / sm4_decrypt(key, block)` | SM4 (GB/T 32907) single-block with a 16-byte key |
| `sm4_expand_key(key)` + `sm4_encrypt_block(rk, data, off)` / `sm4_decrypt_block(rk, data, off)` | SM4 with reusable round keys; `rk` must be the 32 words `sm4_expand_key` returns and `off` must leave a whole 16-byte block in `data` |
| `sm2_public_key(sk) -> Bytes` | SM2 public key (uncompressed 65 bytes) from a 32-byte secret key |
| `sm2_sign(sk, msg, id, rand) -> Bytes` | SM2 signature (r\|\|s, 64 bytes); `rand(32)` supplies the nonce k |
| `sm2_sign_with_k(sk, msg, id, k) -> Bytes` | SM2 sign with explicit nonce (deterministic; aborts on degenerate k) |
| `sm2_verify(pk, msg, id, sig) -> Bool` | SM2 verify (rejects off-curve keys and out-of-range r/s) |
| `sm4_ctr(key, iv, data) / sm4_cbc_encrypt / sm4_cbc_decrypt` | SM4 modes (CTR 128-bit BE counter; CBC raw, no padding) |
| `sm4_gcm_encrypt(pt, key, iv, aad)` / `sm4_gcm_decrypt(ct, key, iv, aad, tag)` | SM4-GCM AEAD (12-byte IV, 16-byte tag; RFC 8998 TLS building block); `sm4_gcm_decrypt_or` reports the reason as `Err` |
| `zuc_init(key, iv) -> ZucState` / `zuc_next_word(st)` | ZUC-128 core: 16-byte key/IV, then one 32-bit keystream word per call |
| `zuc_keystream(key, iv, nwords) -> Bytes` | ZUC-128 keystream as 4*nwords big-endian bytes |
| `zuc_xor(key, iv, data) -> Bytes` | ZUC-128 in raw stream mode (any length, no padding); not the 3GPP mode |
| `zuc_eea3_encrypt(key, count, bearer, direction, nbits, data)` / `zuc_eea3_decrypt` | 128-EEA3 (TS 35.222, `f8`) over an exact **bit** length; `count : UInt`, `bearer` 0..31, `direction` 0/1 |
| `zuc_eia3_mac(key, count, bearer, direction, nbits, data) -> Bytes` | 128-EIA3 (TS 35.223, `f9`): 4-byte big-endian MAC-I |
| `zuc_eia3_verify(key, count, bearer, direction, nbits, data, mac) -> Bool` | Constant-time MAC-I check; false (not a trap) on a wrong-length tag |
| `zuc256_init(key, iv) -> ZucState` / `zuc256_keystream(key, iv, nwords)` / `zuc256_xor(key, iv, data)` | ZUC-256 (32-byte key, 23-byte IV) — same engine as ZUC-128, different key schedule |
| `zuc256_mac(key, iv, macbits, nbits, data) -> Bytes` | ZUC-256 MAC with a 32/64/128-bit tag over an exact bit length |
| `zuc256_mac_verify(key, iv, macbits, nbits, data, mac) -> Bool` | Constant-time check; false (not a trap) on a wrong-length tag |
| `hmac_sm3(key, msg) -> Bytes` | HMAC-SM3 (RFC 2104, 64-byte block, 32-byte MAC) |
| `sm2_encrypt(pk, msg, rand) / sm2_encrypt_with_k(pk, msg, k)` | SM2 encryption (GB/T 32918.4), raw C1\|\|C3\|\|C2; `sm2_encrypt_or` / `sm2_encrypt_with_k_or` for a peer-supplied `pk` |
| `sm2_decrypt(sk, ct) -> (Bytes, Bool)` / `sm2_decrypt_or(sk, ct)` | SM2 decryption (false / `Err` on tamper or wrong key, GCM convention); the `_or` form carries one uniform message for all six rejection reasons |
| `sm2_ct_to_der(ct) / sm2_ct_from_der(der)` | openssl-compatible ASN.1 DER ciphertext conversion; the decoder is strict DER (see below), and `sm2_ct_to_der_or` / `sm2_ct_from_der_or` report a malformed encoding instead of aborting or returning a bare flag |
| `sm2_sig_to_der(sig) / sm2_sig_from_der(der)` | SM2 signature raw r\|\|s <-> DER SEQUENCE{r,s}; the decoder is strict DER (see below), `sm2_sig_to_der_or` / `sm2_sig_from_der_or` never trap |
| `hkdf_sm3(ikm, salt, info, out_len)` / `hkdf_sm3_extract` / `hkdf_sm3_expand` | HKDF-SM3 (RFC 5869) |
| `pbkdf2_sm3(password, salt, iterations, dk_len)` | PBKDF2-HMAC-SM3 (RFC 2898) |
| `sm2_sk_to_pem / sm2_sk_from_pem / sm2_pk_to_pem / sm2_pk_from_pem` | SM2 key PEM (PKCS#8 / SPKI, openssl-identical); `_or` twins for all four (`sm2_pk_to_pem_or`, `sm2_sk_from_pem_or`, `sm2_pk_from_pem_or`, …) when the input is peer-supplied |
| `sm2_sk_to_pkcs8_der / sm2_pkcs8_der_to_sk / sm2_pk_to_spki_der / sm2_spki_der_to_pk` | SM2 key DER forms; `_or` twins for all four, so a malformed peer encoding is an `Err` rather than a flag |
| `sm2_seal(pk, msg, rand) / sm2_open(sk, env)` | SM2 sealed envelope: enc_key(125)\|\|iv(12)\|\|SM4-GCM ct\|\|tag(16); `sm2_seal_or` never traps on a bad `pk`, `sm2_open_or` reports a rejected envelope as `Err` |
| `hmac_sha256 / hmac_sha512(key, msg : Bytes) -> Bytes` | HMAC (RFC 2104) |
| `hmac_sha3_256 / hmac_sha3_512(key, msg : Bytes) -> Bytes` | HMAC over SHA-3 (RFC 2104 + FIPS 202) |
| `hmac_sha3_224 / hmac_sha3_384(key, msg : Bytes) -> Bytes` | HMAC over SHA3-224/384 (RFC 2104 + FIPS 202) |
| `poly1305(key, msg : Bytes) -> Bytes` | Poly1305 MAC (RFC 8439), 16-byte tag |
| `cmac_aes(data, key : Bytes) -> Bytes` | AES-CMAC (NIST SP 800-38B), 16-byte tag |
| `aes_encrypt_cbc / aes_decrypt_cbc(data, key, iv) -> Bytes` | AES-CBC (IV prepended, PKCS#7) |
| `aes_gcm_encrypt(pt, key, iv, aad) -> (Bytes, Bytes)` | AES-GCM encrypt → (ct, 16-byte tag) |
| `aes_gcm_decrypt(ct, key, iv, aad, tag) -> (Bytes, Bool)` / `aes_gcm_decrypt_or(...)` | AES-GCM decrypt, constant-time tag verify; the `_or` form returns `Result` and never aborts |
| `aes_ccm_encrypt(pt, key, nonce, aad, mac_len) -> Bytes` | AES-CCM AEAD (SP 800-38C) → ct ‖ tag |
| `aes_ccm_decrypt(input, key, nonce, aad, mac_len) -> Bytes` | AES-CCM decrypt, aborts on tag mismatch |
| `gmac(key, iv, aad) -> Bytes` | GMAC (SP 800-38D), 16-byte tag |
| `gmac_verify(key, iv, aad, tag) -> Bool` | GMAC constant-time tag verify |
| `gmac_new(key, iv) -> GmacState` | Incremental GMAC (chunked AAD, 12-byte IV) |
| `gmac_new_iv(key, iv) -> GmacState` | Incremental GMAC, any IV length (SP 800-38D) |
| `gmac_update(st, aad_chunk)` | Feed an AAD chunk |
| `gmac_finalize(st) -> Bytes` | Incremental GMAC 16-byte tag |
| `gmac_iv(key, iv, aad) -> Bytes` | GMAC with any IV length (SP 800-38D) |
| `gmac_iv_verify(key, iv, aad, tag) -> Bool` | GMAC any-IV constant-time verify |
| `gmac_stream_verify(key, iv, aad, tag) -> Bool` | Constant-time check of a 16-byte tag produced by the incremental GMAC |
| `aes_ctr(data, key, iv) -> Bytes` | AES-CTR encrypt/decrypt (symmetric) |
| `aes_kw_wrap(kek, key_data) -> Bytes` / `aes_kw_unwrap(kek, wrapped) -> Result[Bytes, String]` | AES Key Wrap (RFC 3394): wrap returns the 8·(n+1)-byte `IV ‖ blocks`; unwrap is `Err` on an integrity failure |
| `aes_siv_encrypt(key, plaintext, ads : Array[Bytes]) -> Bytes` / `aes_siv_decrypt(envelope, key, ads) -> Result[Bytes, String]` | AES-SIV (RFC 5297), nonce-misuse-resistant; `key` 32/48/64 bytes, output is `IV(16) ‖ ct`, and `ads` is the vector of associated-data strings |
| `chacha20_xor(input, key, nonce, counter) -> Bytes` | ChaCha20 encrypt/decrypt (symmetric) |
| `salsa20_keystream_block(key, nonce, counter) -> Bytes` | Salsa20 keystream block (64 bytes) |
| `salsa20_xor(key, nonce, counter, data) -> Bytes` | Salsa20 stream cipher encrypt/decrypt (symmetric) |
| `chacha20_poly1305_encrypt(key, nonce, aad, pt) -> Bytes` | ChaCha20-Poly1305 AEAD → ct ‖ tag |
| `chacha20_poly1305_decrypt(key, nonce, aad, input) -> Bytes` | AEAD decrypt, aborts on tag mismatch |
| `hchacha20(key, in16 : Bytes) -> Bytes` | HChaCha20 subkey derivation (draft-irtf-cfrg-xchacha §2.2) |
| `xchacha20_xor(input, key, nonce24, counter) -> Bytes` | XChaCha20 stream cipher, 24-byte nonce (symmetric) |
| `xchacha20_poly1305_encrypt(key, nonce24, aad, pt) -> Bytes` | XChaCha20-Poly1305 AEAD → ct ‖ tag |
| `xchacha20_poly1305_decrypt(key, nonce24, aad, input) -> Bytes` | XChaCha20-Poly1305 AEAD decrypt, aborts on tag mismatch |
| `hotp(key, counter, digits)` / `hotp_sha256 / hotp_sha512(...) -> String` | HOTP (RFC 4226) with HMAC-SHA1/256/512; `digits` 1..=9 (the RFC recommends 6..=8) |
| `totp(key, unix_time, step, digits)` / `totp_sha256 / totp_sha512(...) -> String` | TOTP (RFC 6238); `step` in seconds ≥ 1, `digits` 1..=9 |
| `ed25519ctx_sign(seed, msg, ctx) / ed25519ctx_verify(pk, msg, sig, ctx)` | Ed25519ctx (RFC 8032), ctx 1..255 bytes |
| `ed25519ph_sign(seed, msg, ctx) / ed25519ph_verify(pk, msg, sig, ctx)` | Ed25519ph (RFC 8032), SHA-512 prehash |
| `ed25519ph_sign_hashed(seed, ph_hash, ctx) / ed25519ph_verify_hashed(pk, ph_hash, sig, ctx)` | the same, when the caller already holds the 64-byte SHA-512 prehash |
| `adler32(data : Bytes) -> Bytes` | Adler-32 (RFC 1950), 4-byte big-endian |
| `hkdf_sha256(salt, ikm, info, len) -> Bytes` | HKDF-SHA256 (RFC 5869) |
| `hkdf_sha512(salt, ikm, info, len) -> Bytes` | HKDF-SHA512 (RFC 5869) |
| `pbkdf2_hmac_sha256(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA256 (RFC 8018) |
| `pbkdf2_hmac_sha512(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA512 (RFC 8018) |
| `pbkdf2_hmac_sha1(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA1 (RFC 8018) |
| `hkdf_sha3_256(salt, ikm, info, len) -> Bytes` | HKDF-SHA3-256 (RFC 5869 over FIPS 202) |
| `pbkdf2_hmac_sha3_256(password, salt, iterations, len) -> Bytes` | PBKDF2-HMAC-SHA3-256 (RFC 8018 over FIPS 202) |
| `scrypt(password, salt, n, r, p, dklen) -> Bytes` | scrypt memory-hard KDF (RFC 7914), `n` power of two |
| `argon2id(password, salt, t_cost, m_cost, parallelism, hash_len) -> Bytes` | Argon2id (RFC 9106), the recommended variant |
| `argon2(…, type) / argon2i(…) / argon2d(…)` | the generic form with an explicit type (0 = d, 1 = i, 2 = id) and the two pure variants |
| `rsa_pkcs1_v15_encrypt(msg, n, e, rand_ps) -> Bytes` | RSAES-PKCS1-v1.5 encrypt (RFC 8017 §7.2); `rand_ps` must be k−msglen−3 **nonzero** bytes |
| `rsa_pkcs1_v15_encrypt_or(msg, n, e, rand_ps) -> Result[Bytes, String]` | same, reporting a degenerate peer modulus / a zero byte in `rand_ps` as `Err` |
| `rsa_pkcs1_v15_decrypt(ct, n, d) -> Bytes` | RSAES-PKCS1-v1.5 decrypt |
| `rsa_pkcs1_v15_sign(msg, n, d) -> Bytes` | RSASSA-PKCS1-v1.5 sign (SHA-256) |
| `rsa_pkcs1_v15_verify(msg, sig, n, e) -> Bool` | RSASSA-PKCS1-v1.5 verify |
| `rsa_oaep_encrypt(msg, n, e, seed, label) -> Bytes` | RSAES-OAEP encrypt (SHA-256) |
| `rsa_oaep_decrypt(ct, n, d, label) -> Bytes` | RSAES-OAEP decrypt |
| `rsa_oaep_encrypt_with(msg, n, e, seed, label, hash) -> Bytes` | OAEP encrypt, chosen hash + MGF1 |
| `rsa_oaep_encrypt_or / rsa_oaep_encrypt_with_or` | the two above as `Result`: a peer modulus < 2 or a message too long for it is an `Err`, not a trap |
| `rsa_oaep_decrypt_with(ct, n, d, label, hash) -> Bytes` | OAEP decrypt, chosen hash |
| `rsa_pss_sign(msg, n, d, salt) -> Bytes` | RSASSA-PSS sign (SHA-256) |
| `rsa_pss_verify(msg, sig, n, e, salt_len) -> Bool` | RSASSA-PSS verify |
| `rsa_pkcs1_v15_sign_crt(msg, p, q, dp, dq, qinv) -> Bytes` | PKCS1-v1.5 sign via CRT (~2.6x, byte-identical) |
| `rsa_pkcs1_v15_decrypt_crt(ct, p, q, dp, dq, qinv) -> Bytes` | PKCS1-v1.5 decrypt via CRT |
| `rsa_oaep_decrypt_crt(ct, p, q, dp, dq, qinv, label) -> Bytes` | OAEP decrypt via CRT |
| `rsa_pss_sign_crt(msg, p, q, dp, dq, qinv, salt) -> Bytes` | PSS sign via CRT |
| `rsa_pkcs1_v15_sign_with(msg, n, d, hash) -> Bytes` | PKCS1-v1.5 sign, hash = SHA-1/256/384/512 |
| `rsa_pkcs1_v15_verify_with(msg, sig, n, e, hash) -> Bool` | PKCS1-v1.5 verify, chosen hash |
| `rsa_pss_sign_with(msg, n, d, salt, hash) -> Bytes` | PSS sign, chosen hash + MGF1 |
| `rsa_pss_verify_with(msg, sig, n, e, salt_len, hash) -> Bool` | PSS verify, chosen hash |
| `rsa_pkcs1_v15_sign_with_crt(msg, p, q, dp, dq, qinv, hash) -> Bytes` | v1.5 sign, CRT + chosen hash |
| `rsa_pss_sign_with_crt(msg, p, q, dp, dq, qinv, salt, hash) -> Bytes` | PSS sign, CRT + chosen hash |
| `ed25519_public_key(seed) -> Bytes` | Derive 32-byte Ed25519 public key |
| `ed25519_sign(seed, message) -> Bytes` | Ed25519 sign (RFC 8032), 64-byte sig |
| `ed25519_verify(public_key, message, sig) -> Bool` | Ed25519 verify |
| `ecdsa_p256_public_key(sk) -> Bytes` | ECDSA P-256 public key (uncompressed) |
| `ecdsa_p256_sign(sk, message) -> Bytes` | ECDSA P-256 sign (RFC 6979, SHA-256) |
| `ecdsa_p256_sign_low_s(sk, message) -> Bytes` | P-256 sign, low-S canonical (WebCrypto) |
| `ecdsa_p256_verify(pk, message, sig) -> Bool` | ECDSA P-256 verify |
| `ecdsa_secp256k1_public_key(sk) -> Bytes` | ECDSA secp256k1 public key (uncompressed) |
| `ecdsa_secp256k1_sign(sk, message) -> Bytes` | ECDSA secp256k1 sign (RFC 6979, SHA-256) |
| `ecdsa_secp256k1_sign_low_s(sk, message) -> Bytes` | secp256k1 sign, BIP-62 low-S canonical |
| `ecdsa_secp256k1_verify(pk, message, sig) -> Bool` | ECDSA secp256k1 verify |
| `x25519(scalar, u) -> Bytes` | X25519 scalar mult (RFC 7748), DH shared secret |
| `x25519_or(scalar, u) -> Result[Bytes, String]` | X25519 without aborting on a wrong-length peer share |
| `dh_shared_is_zero(shared) -> Bool` | True for the all-zero X25519/X448 output a low-order peer point produces (RFC 7748 §6.1) — never use that as a key |
| `x25519_public_key(private_key) -> Bytes` | Derive X25519 public key (base u=9) |
| `ed448_public_key(seed) -> Bytes` | Derive 57-byte Ed448 public key |
| `ed448_sign(seed, message) -> Bytes` | Ed448 sign (RFC 8032), 114-byte sig |
| `ed448_sign_ctx(seed, message, ctx) -> Bytes` | Ed448 sign with context |
| `ed448_verify(pk, message, sig) -> Bool` | Ed448 verify (cofactor equation) |
| `ed448_verify_ctx(pk, message, sig, ctx) -> Bool` | Ed448 verify with context |
| `x448(scalar, u) -> Bytes` | X448 scalar mult (RFC 7748), DH shared secret |
| `x448_or(scalar, u) -> Result[Bytes, String]` | X448 without aborting on a wrong-length peer share |
| `x448_public_key(private_key) -> Bytes` | Derive X448 public key (base u=5) |
| `ml_kem_512_keygen(d, z) -> (ek, dk)` | ML-KEM-512 keygen (FIPS 203, deterministic in d,z) |
| `ml_kem_512_encaps(ek, m) -> (K, c)` | ML-KEM-512 encapsulation |
| `ml_kem_512_decaps(dk, c) -> Bytes` | ML-KEM-512 decapsulation (implicit rejection) |
| `ml_kem_768_keygen / encaps / decaps` | ML-KEM-768 (same shapes) |
| `ml_kem_1024_keygen / encaps / decaps` | ML-KEM-1024 (same shapes) |
| `ml_kem_768_hybrid_seal(ek, m, aad, msg)` | ML-KEM-768 hybrid encryption (HKDF + ChaCha20-Poly1305) |
| `ml_kem_768_hybrid_open(dk, blob, aad) -> Result[Bytes, String]` | hybrid decryption; one uniform `Err` for a malformed blob, a wrong-length `dk` or a failed tag |
| `ml_kem_768_hybrid_seal_init + ml_kem_hybrid_stream_update/final` | streaming hybrid seal |
| `ml_kem_{512,768,1024}_hybrid_seal_or / _hybrid_seal_init_or` | the seal path as `Result` — `ek` is the recipient's key, i.e. peer-supplied |
| `poly1305_new / poly1305_update / poly1305_finalize` | incremental Poly1305 |
| `aes_gcm_siv_encrypt(key, nonce, aad, pt)` | AES-GCM-SIV (RFC 8452, nonce-misuse-resistant) |
| `aes_gcm_siv_decrypt(key, nonce, aad, ct) -> Result[Bytes, String]` | AES-GCM-SIV decryption (returned `Option` before v0.91.0) |
| `xwing_keygen(seed) -> (pk, sk)` | X-Wing hybrid KEM keygen (ML-KEM-768 + X25519) |
| `xwing_encaps(pk, eseed) -> (ss, ct)` | X-Wing encapsulation (derandomized) |
| `xwing_decaps(ct, sk) -> Bytes` | X-Wing decapsulation |
| `turbo_shake_128(data, d, out_len)` | TurboSHAKE128 (RFC 9861, Keccak-p[1600,12]); domain byte `d` 1..=127 |
| `kangaroo_twelve_128(m, c, out_len)` | KangarooTwelve KT128 (tree hash + customization) |
| `turbo_shake_256 / kangaroo_twelve_256` | 256-bit capacity variants |
| `hpke_setup_s(suite, mode, pk_r, ikm_e, info, psk, psk_id, sk_s)` | HPKE sender setup (RFC 9180, all 4 modes) |
| `hpke_seal(ctx, aad, pt) / hpke_open(ctx, aad, ct) -> Result[Bytes, String]` | HPKE authenticated encryption (auto sequence numbers); Open advances the sequence exactly once per call and reports a failure as `Err` |
| `hpke_export(ctx, exporter_context, len)` | HPKE exporter |
| `hpke_x25519_* / hpke_p256_* / hpke_p521_* / hpke_x448_*` | HPKE cipher-suite selectors (all RFC-vectored suites) |
| `hpke_p384_hkdf_sha384_aes256gcm` | DHKEM(P-384) suite (differential vectors) |
| `hpke_derive_key_pair(suite, ikm) -> (pk, sk)` | DHKEM DeriveKeyPair (rejection-sampling for the NIST curves, up to 255 tries) |
| `hpke_encap / hpke_decap(suite, …)` | DHKEM base Encap/Decap; returns **(shared_secret, enc)** |
| `hpke_auth_encap(suite, pk_r, sk_s, ikm_e) / hpke_auth_decap(suite, enc, sk_r, pk_r, pk_s)` | DHKEM auth modes (RFC 9180 §5.1.3), `kem_context = enc ‖ pkRm ‖ pkSm`; same **(shared_secret, enc)** order |
| `hpke_setup_r(suite, mode, sk_r, pk_r, enc, info, psk, psk_id, pk_s)` | HPKE receiver setup (all 4 modes) |
| `hmac_sha384 / hkdf_sha384 / hkdf_sha384_extract` | SHA-384 MAC/KDF family |
| `ml_dsa_44_keygen(seed) -> (pk, sk)` | ML-DSA-44 keygen (FIPS 204, deterministic in seed) |
| `ml_dsa_44_sign(sk, msg, rnd, ctx) -> Bytes` | ML-DSA-44 sign (pure; rnd = 0^32 = deterministic) |
| `ml_dsa_44_verify(pk, msg, sig, ctx) -> Bool` | ML-DSA-44 verify |
| `ml_dsa_65_keygen / sign / verify` | ML-DSA-65 (same shapes) |
| `ml_dsa_87_keygen / sign / verify` | ML-DSA-87 (same shapes) |
| `ml_dsa_44_sign_prehash(sk, msg, rnd, ctx, ph)` | HashML-DSA-44 sign (FIPS 204 Alg 4, OID-tagged pre-hash); 65/87 have the same shape |
| `ml_dsa_44_verify_prehash(pk, msg, sig, ctx, ph)` | HashML-DSA-44 verify (FIPS 204 Alg 5); 65/87 have the same shape |
| `ml_dsa_44_sign_mu(sk, mu, rnd) / verify_mu(pk, mu, sig)` | ML-DSA external-mu interface (Alg 7/8); 65/87 have the same shape |
| `dsa_prehash_variants / dsa_prehash_sha2_256 / ...` | 12 pre-hash selectors (SHA2/SHA3 family + SHAKE-128/256) |
| `slh_keygen(slh_sha2_128s, sk_seed, sk_prf, pk_seed)` | SLH-DSA keygen (FIPS 205, deterministic in the three seeds) |
| `slh_sign(params, sk, msg, ctx) / slh_sign_hedged(...)` | SLH-DSA pure signing (deterministic / hedged) |
| `slh_verify(params, pk, msg, sig, ctx)` | SLH-DSA verification |
| `slh_sign_prehash / slh_verify_prehash` | HashSLH-DSA (OID-tagged pre-hash, 12 hash functions) |
| `slh_sign_raw / slh_verify_raw` | raw-M' internal interface |
| `slh_sha2_128s ... slh_shake_256f` | all 12 SLH-DSA parameter sets |
| `lms_keygen / lms_sign / lms_verify` | LMS (RFC 8554) stateful Merkle signatures; `lms_public_key` regenerates pk from SEED/I |
| `hss_keygen / hss_sign / hss_verify` | HSS multi-level LMS (L=1..8); `hss_keygen_with` for explicit parameter chains |
| `hss_public_key(sk) -> Bytes` | The HSS public key blob (typecode ‖ L ‖ root ‖ I) for a private key |
| `xmss_params(func, n, full_height, ...)` | XMSS/XMSS^MT parameter sets (RFC 8391): SHA2/SHAKE128/SHAKE256, n in {24,32,64}; d=1 is plain XMSS, d>1 multi-tree |
| `xmss_keygen_from_seed / xmss_sign / xmss_verify` | XMSS from 48-byte seed; `xmss_set_index` manages the leaf counter; `xmss_public_key` regenerates pk |
| `xmss_wots_pkgen / xmss_wots_sign / xmss_wots_pk_from_sig` | WOTS+ one-time primitives (exposed for verification tooling) |
| `falcon512_keypair_from_seed(seed) -> (pk, sk)` | Falcon-512 keygen (NTRU solve; deterministic in the 48-byte seed) |
| `falcon512_sign(sk, msg, rand) -> Bytes` | Falcon-512 signing (rand supplies nonce+seed like randombytes) |
| `falcon512_sign_padded(sk, msg, rand) -> Bytes` | Falcon-512 padded form (fixed 666 bytes) |
| `falcon512_verify(pk, msg, sig) -> Bool` | Falcon-512 verification (compact + padded forms) |
| `falcon1024_keypair_from_seed / sign / sign_padded / verify` | Falcon-1024 (same shapes; padded = 1280 bytes) |
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
| `chacha20_poly1305_decrypt_or(key, nonce, aad, input) -> Result[Bytes, String]` | ChaCha20-Poly1305 decrypt, `Err` instead of aborting on a bad tag |
| `xchacha20_poly1305_decrypt_or(key, nonce24, aad, input) -> Result[Bytes, String]` | XChaCha20-Poly1305 decrypt, graceful |
| `aes_ccm_decrypt_or(input, key, nonce, aad, mac_len) -> Result[Bytes, String]` | AES-CCM decrypt, graceful |
| `aes_decrypt_cbc_or(data, key, iv) -> Result[Bytes, String]` | AES-CBC decrypt with **strict** PKCS#7 (the lenient original cannot tell tampering from plaintext) |
| `sm4_cbc_decrypt_or(key, iv, data) -> Result[Bytes, String]` | SM4-CBC decrypt, graceful |
| `rsa_oaep_decrypt_or / _with_or / _crt_or -> Result[Bytes, String]` | RSA-OAEP decrypt, uniform `Err` for every failure cause |
| `rsa_pkcs1_v15_decrypt_or / _crt_or -> Result[Bytes, String]` | RSA PKCS#1 v1.5 decrypt, uniform `Err` |
| `ml_kem_512/768/1024_encaps_or(ek, m) -> Result[(Bytes, Bytes), String]` | ML-KEM encapsulation, `Err` on a wrong-length peer `ek` |
| `ml_kem_512/768/1024_decaps_or(dk, c) -> Result[Bytes, String]` | ML-KEM decapsulation, `Err` on wrong lengths (invalid `c` still gets the implicit-rejection key) |
| `xwing_encaps_or(pk, eseed) / xwing_decaps_or(ct, sk) -> Result[_, String]` | X-Wing, graceful on wrong-length peer material |
| `hpke_valid_pk(suite, pk) -> Bool` | Validate a peer HPKE public key / `enc` (length + on-curve for the NIST KEMs) |
| `hpke_encap_or / auth_encap_or / decap_or / auth_decap_or / setup_s_or / setup_r_or` | HPKE with peer keys validated up front, `Err` instead of aborting. The encap pair returns **(shared_secret, enc)** — the reverse of RFC 9180's pseudocode, and both halves are `Bytes`, so a swap compiles and fails silently |
| `bytes_equal(a, b : Bytes) -> Bool` | Constant-time comparison |

Streaming hashers (`<algo>_new` / `sha3_update` / `sha3_finalize` /
`shake_finalize`) are available for MD5, SHA-224/256/384/512, SHA3-224/256/384/512,
and SHAKE128/256, plus SHA-512/224 / SHA-512/256 (`sha512_224_new` /
`sha512_256_new` with `sha512_update`). For SHA-3/SHAKE, `sha3_update` is shared and the finalize
method depends on the variant (`sha3_finalize` for fixed-length, `shake_finalize(h, out_len)` for XOF).

**The SM2 DER decoders are strict DER, not BER.** `sm2_sig_from_der` and
`sm2_ct_from_der` reject anything that is not the one canonical encoding of a
value: non-minimal length forms (`81 06` where `06` is legal), indefinite
lengths, a leading zero on an INTEGER that does not need a sign pad, and
trailing bytes inside or after the SEQUENCE. That is what makes an accepted
blob re-encode byte-identically — without it a peer could offer several
distinct encodings of one signature or ciphertext (malleability, the bug class
behind Bitcoin's BIP-62). The key decoders (`sm2_pkcs8_der_to_sk`,
`sm2_spki_der_to_pk`, and both PEM parsers) apply the same length/INTEGER
rules; PKCS#8 keeps its OPTIONAL `publicKey` field optional, so decoding and
re-encoding a field-less key adds the field (decode/encode/decode is stable).
Every read in all four parsers is bounds-checked: a hostile blob that is a
valid DER *prefix* returns `(b"", false)` instead of trapping.

AES-CBC/GCM/CTR keys may be 128, 192, or 256 bits; the nonce for GCM and
ChaCha20 is 96 bits (12 bytes), the recommended length per spec. Wrong lengths
cause an `abort` with a descriptive message.

### Which channel reports a failure

Four shapes coexist — one of them empty as of v0.91.0. Which one a function
uses is frozen and machine-checked (`.github/scripts/api_contract_check.py`,
rule C4): a **new** entry point that reports failure must return
`Result[_, String]`.

| Channel | Count | Used by | On failure |
| --- | --- | --- | --- |
| `Bool` | 39 | every `*_verify` / `*_check`: signature, MAC and AEAD-tag verification, plus `bytes_equal`, `hpke_valid_pk`, `dh_shared_is_zero` | `false`. There is nothing to hand back, and a distinguishable error would be an authentication oracle |
| `(Bytes, Bool)` | 10 | `aes_gcm_decrypt`, `sm4_gcm_decrypt`, `sm2_decrypt`, `sm2_open`, and the six SM2 DER/PEM decoders | the `Bytes` are meaningless — read the flag. Each has a `Result` twin (`_or`) |
| `Option` (`Bytes?`) | **0** | — | **eliminated in v0.91.0**: `aes_gcm_siv_decrypt`, `hpke_open` and the three `ml_kem_*_hybrid_open` now return `Result` themselves. C4 keeps the list empty |
| `Result[_, String]` | 62 | the 54 `_or` twins, plus `aes_kw_unwrap`, `aes_siv_decrypt`, `sealed_box_open` and the five former `Option` functions | `Err(msg)`. Decryption and opening return **one uniform message** for every way peer input can fail, so the text is not a Bleichenbacher/Manger oracle |

Everything else either cannot fail on well-formed caller input (it `abort`s —
see the two-tier contract above) or just returns a value.

**Migration state.** All ten `(Bytes, Bool)` entry points have a `Result` twin
(`sm2_open_or`, `sm2_ct_from_der_or`, `sm2_sig_from_der_or`,
`sm2_pkcs8_der_to_sk_or`, `sm2_spki_der_to_pk_or`, `sm2_sk_from_pem_or`,
`sm2_pk_from_pem_or`, `aes_gcm_decrypt_or`, `sm4_gcm_decrypt_or`,
`sm2_decrypt_or`), added in v0.89.0–v0.90.0. The five `Option` ones went
further in v0.91.0: the `Option` form was **deleted** and the name now returns
`Result` directly, since an open that reports nothing is strictly less useful
than one that says why, and there was no aborting variant worth keeping (an
AEAD open that aborted on a forged tag would be a denial of service).

Prefer the `Result` forms in new code: the `(Bytes, Bool)` shapes are frozen
(rule C4) rather than maintained, and the twins are where they land. For
`hpke_open` the sequence number advances inside the function, so one call burns
exactly one nonce.

Two rules follow, and C4 enforces both:

- **new graceful entry points are `foo_or -> Result[_, String]`**, and they
  share one guard with their aborting twin rather than keeping a copy (rule C2);
- the three legacy shapes are **frozen by name**. Growing one is a deliberate
  act: the name has to be added to a list in the checker, which is where a
  reviewer will see it.

`Result` is the target shape because it can carry a reason; `(Bytes, Bool)` and
`Option` predate the `_or` family and stay for source compatibility.
Unifying them is a breaking change reserved for 1.0, together with the 19
same-type tuples — `(shared_secret, enc)`, `(pk, sk)`, `(ct, tag)` — whose
element order the compiler cannot check. The checker prints that list on every
run so it cannot quietly grow.

### Public but internal: what `pub` owes you here

MoonBit compiles `*_test.mbt` as a *blackbox* package, so a test can only reach
items marked `pub` — and a call across a package boundary needs `pub` too. That
forces some internals to be public so the layered and differential tests can
probe them. Since v0.88.0 they come in two tiers.

**Compiler-enforced: `cc06b/mooncry/internal`.** The Falcon low-level layer —
the FFT (`falcon_fft` / `falcon_ifft` / `falcon_poly_*_fft`), the modular NTT
and its `modp_*` field, the `zint_*` bignum helpers, `fp_of`, the constant
tables (`falcon_gauss_tab`, `falcon_primes_*`, the `falcon_max_*` bounds), the
Merkle tree, `falcon_mq_ntt` / `falcon_mq_intt`, `falcon_to_ntt_monty`,
`falcon_is_short`, `falcon_compute_public` and the NTRU solver — is its own
package: 81 names. MoonBit applies the Go-style rule to a path component named
`internal`, so a downstream consumer cannot import it at all:

```
Cannot import internal package cc06b/mooncry/internal ...
  due to internal visibility rules
```

Its layered tests stay in `lib/` and reach it through those `pub` items, which
is why they are `pub` at all. The package has no imports of its own and the
dependency runs one way (`lib` → `internal`), because MoonBit rejects import
cycles — that rule is also what keeps the second tier below in `lib`.

**Documented only: still `pub` in `lib`.** These could not move. The Falcon XOF
wraps this library's own public SHA-3 streaming state (`Sha3Hasher`,
`shake_finalize`), so `falcon_common.mbt` must stay in `lib`, and everything
that calls it stays with it.

| Group | Names | Why it is public |
| --- | --- | --- |
| Falcon XOF and codecs | `falcon_xof_*`, `falcon_hash_to_point`, `falcon_{modq,trim,comp}_{encode,decode}` | needs `lib`'s SHA-3 state, so it cannot live below `lib` |
| Falcon samplers | `falcon_mkgauss`, `falcon_prng_init`, `prng_get_u64` / `prng_get_u8`, `fp_floor` / `fp_trunc` / `fp_sqrt` / `fp_expm_p63` / `fp_invsqrt2` / `fp_invsqrt8`, `falcon_gaussian0_sampler`, `falcon_sampler*` | same reason; the port was verified layer by layer against the C reference and those tests need the boundaries visible |
| P-256 debug probes | `p256_dbg_mul` / `p256_dbg_ref_mul` / `p256_dbg_gmul` / `p256_dbg_ref_gmul` | the differential test of the native field against the reference one (`lib/p256_dbg_test.mbt`) |
| Test RNG | `falcon_test_rng_init` / `_bytes` / `_set_ctr` | a deterministic SHAKE256 stream so the Falcon KATs reproduce byte for byte |
| XMSS leaf helper | `xmss_gen_leaf_wots` | lets a test regenerate one leaf without building a whole tree |

⚠️ **`falcon_test_rng_*` is not a CSPRNG.** It is a counter-driven SHAKE256
stream that anyone can reproduce from nothing but the call order. Using it for
keys, nonces or `ikm` produces material an attacker can recompute. By design
this library contains no RNG at all: every real key and nonce comes from a
caller-supplied seed or `rand` callback.

If you consume this package, treat both tiers as private — the second one is a
documentation promise only, and it may change or vanish in any release.

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
- **ZUC is not constant-time.** The F function looks up S0/S1 with indices
  derived from the key and IV, so keystream generation leaks through the CPU
  cache exactly the way AES's tables do (since v0.79.0 the two tables are
  widened to `UInt64` at load — 4 KiB instead of 512 B — because the
  `Byte`→`Int`→`UInt64` conversion on every lookup cost more than the extra
  cache footprint: ~1.4x on the stream paths). What *is* constant-time: the MAC
  rounds do not branch on message bits (the conditional XOR is a masked AND),
  and the tag comparisons (`zuc_eia3_verify`, `zuc256_mac_verify`) use
  `bytes_equal` and return `false` — never a trap — on a wrong-length tag. The
  keystream and MAC computations themselves are **not side-channel-safe**
  against a local attacker.
- **Falcon keygen/sign are not constant-time.** The port favours clarity and
  cross-platform bit-exactness over the C reference's constant-time discipline:
  the NTRU solver's bignum comparisons, conditional reductions, and rejection
  loops branch on secret-dependent values. Falcon *verify* only branches on
  public data (pk, signature, message). Keygen/sign run on the key owner's
  machine with freshly generated secrets; treat them as **not side-channel-safe**
  against local timing/cache attackers.
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
  lengths `abort` immediately rather than producing wrong output. That covers
  the signature schemes' key material too: `slh_keygen` (three n-byte seeds,
  n = 16/24/32), the six SLH signers (sk = 4n), `ml_dsa_*_sign*` (sk = the
  expanded length for the parameter set, from one shared helper),
  `falcon512_keypair_from_seed` / `falcon1024_keypair_from_seed` (48 bytes) and
  `sm2_sign` / `sm2_sign_with_k` (32 bytes). Before v0.81.0 those either read
  out of bounds — an `unreachable` trap with no message — or silently accepted
  the short input: `slh_keygen` returned a 63-byte secret key that only trapped
  later, at signing time, and Falcon derived full-length but non-standard keys
  from a 47-byte seed, which no other implementation reproduces.
- **Numeric, enum and offset parameters are validated too** (v0.84.0–v0.85.0).
  A length, a digit count or a block offset is the caller's business, so each
  aborts with a message instead of trapping or answering a different question:
  HKDF's `length` (≤ 255·HashLen, RFC 5869), PBKDF2's `iterations` (≥ 1,
  RFC 8018) and `dklen`, the output lengths of SHAKE / cSHAKE / KMAC / BLAKE2 /
  BLAKE3 / TurboSHAKE / KangarooTwelve (≥ 0) and of `sha256_finalize_n` /
  `sha512_finalize_n` (0..=32 / 0..=64, the contract their doc comments always
  stated), `shake_finalize` — the streaming twin the v0.84.0 one-shot guard did
  not cover — TurboSHAKE's domain byte (1..=127, RFC 9861 §2),
  `sm4_encrypt_block` / `sm4_decrypt_block` (32 round-key words, and an offset
  that leaves a whole block inside `data`), HPKE's `mode` (0..=3; any other
  value used to mean base mode, i.e. silently no authentication), ML-DSA's `mu`
  (exactly 64 bytes, FIPS 204), and HOTP/TOTP's `digits` (1..=9) and `step`
  (≥ 1 second). Two of those were worse than a trap: `digits = 10` overflowed
  `pow10` on a 32-bit target — 10^10 wraps to 1410065408 on wasm but is exact
  on native64, so one call gave two different OTPs depending on the target —
  and a negative `step` became a huge `UInt64` (−30 → 18446744073709551586),
  quietly making every counter 0, i.e. the same OTP forever. Guards sit at the
  narrowest shared chokepoint (`shake_check_out_len`, `turbosha_x`,
  `sm4_check_block_args`, `otp_check_digits` / `otp_check_step`,
  `kdf_check_expand_len`, `kdf_check_pbkdf2`, `hpke_check_mode`, `dsa_sk_len`)
  so twins cannot drift, and each range's legal ends are pinned by a test — an
  over-tight guard turns it red.
- **Every buffer the library builds is capped at 1 GiB** (v0.87.0), and the
  cap is checked by *division*, never by computing the product — because the
  product is what overflows. `zuc_keystream(nwords = 2^30)` used to compute
  `nwords * 4`, which is 2^32 and wraps to 0 on a 32-bit target, so the
  keystream array came out empty and the first word written threw out of
  `Array::set` with nothing to explain why; scrypt's `p * 128 * r` is exactly
  2^32 at r = 2^20 and p = 32. Now argon2's `m_cost` (1-KiB blocks) and
  `hash_len`, scrypt's `r` / `p` / `N` / `dklen`, PBKDF2's `dklen`, and every
  XOF output length (SHAKE one-shot *and* streaming, cSHAKE/KMAC, BLAKE3,
  TurboSHAKE/KangarooTwelve, the Falcon XOF) refuse an out-of-range size with a
  message instead of dying in the allocator. `argon2`'s `variant` is validated
  as RFC 9106 §3 defines it (0 = Argon2d, 1 = Argon2i, 2 = Argon2id): any other
  value used to be hashed into H0 as-is, producing a key that differs from all
  three standard variants and that no other implementation reproduces.
- **A length expression can overflow before the call reaches the library.** On
  wasm32 `Int` is 32 bits, so `hkdf_sha256(salt, ikm, info, 1 << 40)` passes
  **256** — measured: the shift wraps in the caller's own expression, the
  RFC 5869 limit then sees a perfectly legal request, and the call returns 256
  bytes. The same source on native64 passes 2^40 and aborts on the RFC limit.
  No library-side check can see this. If a length comes from arithmetic rather
  than from a `Bytes.length()`, and the wasm target matters, compute it where
  the overflow is visible.
- **Untrusted input has a two-tier contract.** Parameter *shapes* (a key of the
  wrong length, a nonce of the wrong size) are caller errors and abort loudly.
  Values that arrive from a peer — ciphertexts, signatures, public keys,
  encoded blobs — are never allowed to trap: verifiers return `false`, the
  Option/Result APIs return `None`/`Err`, and KEM decapsulation falls back to
  the implicit-rejection key. Every such entry point is covered by the
  hostile-input fuzz suite (see [Testing](#testing)); where the historical API
  aborted on an authentication failure, a graceful `_or` twin was added and the
  original kept for compatibility. Since v0.86.0 a CI check
  (`.github/scripts/api_contract_check.py`) enforces the rest of that contract
  statically: every `_or` returns `Result`, each aborting twin shares **one**
  guard with its twin rather than keeping a copy, and every name in the Public
  API table below exists in the source.
- **Encrypting to a peer key crosses the same boundary as verifying one.**
  Sealing and encrypting consume a *recipient* public key that came off the
  wire, so those entry points have `_or` twins too:
  `ml_kem_*_hybrid_seal_or`, `rsa_oaep_encrypt_or` / `rsa_pkcs1_v15_encrypt_or`
  and `sm2_encrypt_or` / `sm2_seal_or` report a degenerate modulus, a
  wrong-length encapsulation key, or a malformed / off-curve SM2 point as `Err`
  instead of trapping (an off-curve point is the invalid-curve attack surface).
  So does *re-encoding* what a peer sent: `sm2_ct_to_der_or`,
  `sm2_sig_to_der_or`, `sm2_pk_to_spki_der_or` and `sm2_pk_to_pem_or` take a raw
  ciphertext / signature / public key that may well have been truncated in
  transit. Each pair shares one shape check, so the aborting encoder and its
  twin cannot disagree about what counts as well-formed.
  `rsa_pkcs1_v15_encrypt_or` also rejects a zero byte inside `rand_ps`: RFC 8017
  §7.2.1 requires nonzero octets, and accepting one would silently emit a
  ciphertext the recipient unpads to a truncated message.
- **Some *shape* parameters are peer-derived.** The tier above assumes a shape
  is the caller's business, which holds for a key or nonce length. It does not
  hold for a length field that a protocol puts on the wire: ZUC's LENGTH (the
  `nbits` argument of `zuc_eea3_*`, `zuc_eia3_*` and `zuc256_mac*`) comes from
  the PDCP/RRC header. A LENGTH that disagrees with the buffer it arrived in
  still aborts — silently MACing or encrypting a different message than the one
  received would be worse — so if your input can be truncated, check
  `data.length() == (nbits + 7) / 8` before calling. Otherwise a peer can
  trigger the abort, and an abort in a long-lived process is a denial of
  service.
- **Peer public keys are validated before ECDH.** HPKE's NIST-curve KEMs
  (P-256/P-384/P-521) check that the peer point is in range and on the curve
  before the scalar multiply (`hpke_valid_pk`, also enforced inside `hpke_dh`);
  without it an attacker could send a point on a different, small-order curve
  and recover the private scalar a few bits per query (invalid-curve attack,
  RFC 9180 §7.1.3). ECDSA, SM2 sign/verify and SM2 decryption perform the same
  check. X25519/X448 deliberately accept any input (RFC 7748).
- **RSA decryption errors are indistinguishable.** `rsa_oaep_decrypt_or` and
  `rsa_pkcs1_v15_decrypt_or` return one uniform message for a wrong-length
  ciphertext, a bad first byte, a missing separator and an lHash mismatch, so
  the error channel cannot be used as a Bleichenbacher/Manger oracle. This does
  not make the padding side-channel-free — timing still differs, and CBC/PKCS#1
  v1.5 remain unauthenticated: prefer an AEAD, and never expose the result to a
  peer without a MAC in front.
- **No RNG.** The library provides deterministic primitives; obtain keys, IVs,
  and nonces from a secure source.
- **No unbounded loops.** Every rejection-sampling loop that consumes
  caller-supplied randomness has an explicit attempt bound: Falcon signing
  (1000 attempts, then the empty-signature "cannot sign" signal), Falcon's
  discrete Gaussian sampler (10000, falling back to a sample the norm check
  rejects), and Falcon keygen's `(f,g)` / parity / range samplers (10000, then
  an abort, since the seed is local). ML-DSA signing (1000), ECDSA RFC 6979
  (100), SM2 nonce draws (100) and HPKE's DeriveKeyPair (255, the width RFC
  9180 gives the counter) were already bounded. With a working RNG none of
  these bounds is approached — Falcon signs in one or two attempts — but an
  unbounded loop over external input is a hang, and a hang is worse than an
  error: no message, no progress, and on wasm no way to interrupt it.

## Performance

Throughput is measured by the `lib` benchmark suite (`moon bench`) on 1 KiB
inputs. Figures below were re-measured for v0.85.0 (release mode, wasm,
Windows host, toolchain 0.1.20260904): the fastest of three consecutive full
runs over all 68 benches, of which the table lists 33. Per-row spread between
the runs was under 8% everywhere except AES-128-CMAC (62–81 µs).

Every figure this replaced was too high — by 4.5% (ZUC-128 stream) to 114%
(Argon2id, quoted at ~1.2 ms against a measured 561 µs), with AES-128-CMAC,
HMAC-SHA3-256 and ECDSA P-256 verify all quoted at ~1.9x their actual cost.
None of those code paths changed between the two measurements, and the rows
refreshed most recently drifted least, so the spread is host load at measurement
time rather than regressions. Read the table as one quiet host's numbers and run
`moon bench` yourself before comparing anything.

```bash
moon bench
```

| Algorithm | 1 KiB (approx.) |
| --- | --- |
| MD5 | ~6.5 µs |
| SHA-256 | ~10 µs |
| SHA-512 | ~10 µs |
| SHA3-256 | ~4.5 µs (unrolled Keccak) |
| SHA3-512 | ~6.9 µs |
| SHAKE128 1KiB (out=32) | ~6.1 µs |
| SHAKE256 1KiB (out=64) | ~6.4 µs |
| BLAKE2b | ~20 µs |
| BLAKE3 | ~31 µs (tree-Merkle) |
| HMAC-SHA256 | ~16 µs |
| HMAC-SHA3-256 | ~11 µs |
| HMAC-SHA3-512 | ~13 µs |
| AES-128-CMAC | ~62 µs |
| SipHash-2-4 | ~2.4 µs |
| CRC32 / CRC32C | ~2.3 / ~2.3 µs |
| sealed_box_seal | ~111 µs (HKDF + AES-256-GCM) |
| scrypt (N=1024,r=8,p=1,dk32) | ~21 ms (memory-hard KDF) |
| Argon2id (t=1,m=64,p=1,dk16) | ~561 µs (memory-hard KDF) |
| ECDSA P-256 sign | ~3.3 ms (native field) |
| ECDSA P-256 verify | ~4.1 ms (native field) |
| AES-256-SIV encrypt 1KiB | ~182 µs (S2V + AES-CTR) |
| AES-128-KW wrap 32B | ~35 µs |
| ChaCha20 | ~32 µs |
| ZUC-128 stream (raw XOR) | ~17 µs |
| ZUC-256 stream (raw XOR) | ~18 µs |
| 128-EEA3 encrypt | ~18 µs |
| 128-EIA3 MAC (32-bit tag) | ~24 µs |
| ZUC-256 MAC (128-bit tag) | ~34 µs |
| AES-256-CBC | ~78 µs (T-table) |
| AES-256-GCM | ~99 µs (T-table + GHASH 4-bit tables) |
| Base64 encode | ~7.8 µs |
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

**v0.21.0 perf pass.** Two fronts. (1) SHA-256 streaming: the hasher now
reuses one 64-word message schedule instead of allocating 16- and 64-word
arrays per block, reads buffer words without an intermediate `Bytes`, and
finalizes with in-place padding (no padded-array allocation); one-shot
SHA-256 1KiB drops ~26.9 → ~20.7 µs (**-23%**). New `sha256_update_byte` /
`sha224_update_byte` give byte-at-a-time streams a zero-allocation hot
path: ~26.3 µs/KiB, only ~1.3x one-shot (the old 1-byte `update` pattern
is ~3.7x). (2) RSA: all four private-key operations (PKCS1-v1.5
sign/decrypt, OAEP decrypt, PSS sign) gain `_crt` variants taking the CRT
key `(p, q, dP, dQ, qInv)` and doing two half-width exponentiations
instead of one full-width (RFC 8017 §5.1.2) — ~17.6-18.5 ms → ~6.8-7.0 ms
on RSA-1024 (**~2.5-2.6x**). CRT output is byte-identical to the
single-exponentiation path (deterministic padding), verified in-tree.
The PSS/OAEP `emBits` computation no longer allocates a ~k-char binary
string per call.

**v0.22.0 features.** Three additions. (1) **ECDSA secp256k1** (Bitcoin
curve, y² = x³ + 7): sign/verify/public-key with the same RFC 6979 +
SHA-256 deterministic construction as P-256. The point/RFC-6979 code is
now curve-parameterized (P-256 keeps its fast a = −3 doubling; secp256k1
uses the a = 0 specialization), and P-256 signatures stay byte-identical.
Verified against the Python `ecdsa` library
(`sign_digest_deterministic`) plus `cryptography` cross-verification;
signatures are not low-S-normalized (verify accepts any s in [1, n−1]);
use `ecdsa_secp256k1_sign_low_s` for BIP-62 canonical output (v0.23.0).
(2) **Multi-hash RSA signatures**: `rsa_pkcs1_v15_sign_with` /
`rsa_pkcs1_v15_verify_with` / `rsa_pss_sign_with` / `rsa_pss_verify_with`
take an `RsaHash` (SHA-1/256/384/512) for the message hash, DigestInfo
(v1.5) and MGF1 (PSS). The plain functions stay fixed to SHA-256. Verified
byte-for-byte against pycryptodome. (3) **Incremental GMAC**
(`gmac_new` / `gmac_update` / `gmac_finalize`): chunked AAD over the same
table-accelerated GHASH, equal to the one-shot `gmac` tag (verified
in-tree and against pycryptodome GCM-empty tags).

**v0.23.0 features.** Two additions. (1) **secp256k1 low-S signatures**
(`ecdsa_secp256k1_sign_low_s`): BIP-62 canonical form — if s > n/2 it is
replaced by n − s (r unchanged, still valid and deterministic). Verified
against the Python `ecdsa` library's `sigencode_string_canonize` plus
`cryptography`. (2) **Multi-hash RSA-OAEP**: `rsa_oaep_encrypt_with` /
`rsa_oaep_decrypt_with` take an `RsaHash` for lHash and MGF1 (the plain
functions stay fixed to SHA-256). Exact ciphertexts verified against
pycryptodome (fixed seed via its `randfunc` hook) plus random-seed interop;
SHA-512 vectors use a dedicated 2048-bit key since OAEP-SHA512 needs
k ≥ 2·hLen + 2 + |M| (impossible on 1024 bits).

**v0.24.0 features.** Two additions. (1) **P-256 low-S signatures**
(`ecdsa_p256_sign_low_s`): the WebCrypto / widely-mandated canonical form —
if s > n/2 it is replaced by n − s (r unchanged, still valid and
deterministic); `ecdsa_p256_verify` accepts both forms. Verified against
the Python `ecdsa` library's `sigencode_string_canonize` plus
`cryptography`, with a property test asserting s ≤ n/2 byte-wise. (2)
**GMAC with any IV length** (`gmac_iv` / `gmac_iv_verify` one-shot and
`gmac_new_iv` incremental): SP 800-38D §8.2.1 — 96-bit IVs keep the fast
J0 = IV || 0³¹ || 1 path; other lengths derive J0 via GHASH over
IV || 0^(s+64) || [len(IV)]₆₄. Verified against pycryptodome GCM-empty
tags for IV lengths 1/8/16/20/32 plus 12-byte fast-path equality and
streaming-vs-one-shot properties.

**v0.25.0 features.** **CRT × multi-hash combinations**: the CRT speed of
v0.21.0 and the hash choice of v0.22.0 are now combinable —
`rsa_pkcs1_v15_sign_with_crt` and `rsa_pss_sign_with_crt` take both the
CRT key (p, q, dP, dQ, qInv) and an `RsaHash`. Deterministic padding makes
them byte-identical to the pycryptodome-verified `_with` paths (transitive
verification across all four hashes, plus a salt_len=0 deterministic case).

**v0.26.0 features.** **The 448-bit suite**. (1) **Ed448** (RFC 8032 §5.2):
pure EdDSA over edwards448 (Goldilocks field p = 2⁴⁴⁸ − 2²²⁴ − 1), SHAKE256-based hashing with dom4 domain separation,
context support (`ed448_sign_ctx` / `ed448_verify_ctx`), cofactor
verification equation [4][S]B = [4]R + [4][k]A. Verified against all nine
official RFC 8032 §7.4 vectors incl. the 1023-octet message and the
context-carrying one, plus tamper/context-mismatch/S≥L negative tests.
(2) **X448** (RFC 7748): Montgomery-ladder Diffie-Hellman over curve448
with RFC §5 clamping. Verified against the official RFC 7748 §5.2 vectors,
the §6.1 DH triple, and the single-iteration K=u=5 vector, plus an ECDH
commutativity property.

**v0.27.0 features.** **Post-quantum: ML-KEM (FIPS 203)** — the NIST
standard module-lattice KEM, all three parameter sets (ML-KEM-512/768/1024).
Pure MoonBit on UInt (q = 3329), NTT-domain arithmetic with the standard
zeta/gamma tables, rejection sampling from a true incremental SHAKE128
stream, CBD noise sampling, Compress/ByteEncode for d = 1/4/5/10/11/12,
and the full K-PKE + ML-KEM algorithm set (KeyGen/Encaps/Decaps_internal,
implicit rejection included). The API is the deterministic internal form:
callers supply CSPRNG randomness (d, z for keygen; m for encaps).
**Lesson learned during this work**: the FIPS 203 *final* text instantiates
G = SHA3-512 and H = SHA3-256 (not SHAKE256 as in earlier drafts) — only
J and PRF remain SHAKE256. Verified against the official NIST ACVP vectors
(keyGen + encapsulation + decapsulation, incl. implicit-rejection cases)
for all three parameter sets, plus round-trip and tamper properties.

**v0.28.0 features.** **Post-quantum: ML-DSA (FIPS 204)** — the NIST
module-lattice signature standard, all three parameter sets
(ML-DSA-44/65/87). Pure-MoonBit port: NTT over q = 8380417 (Int64-widening
multiplies — Int is 32-bit on wasm-gc), rejection sampling
(SampleNTT/SamplePolyCBD/ExpandMask), Power2Round/Decompose/HighBits/
LowBits/MakeHint/UseHint, hint bit-pack/unpack, and the full
K-PKE + ML-DSA KeyGen/Sign/Verify internal algorithms (pure message
interface, hedged or deterministic via the `rnd` input). Verified against
the official NIST ACVP vectors: keyGen (all sets), sigGen pure
deterministic, and the full sigVer external-pure suite including every
rejection category. HashML-DSA and external-mu followed in v0.29.0/v0.30.0.

**v0.29.0 features.** **ML-DSA HashML-DSA + external-mu interfaces** —
completes the FIPS 204 algorithm surface. HashML-DSA (Algorithms 4/5):
M' = 0x01 || octet(|ctx|) || ctx || OID(PH) || PH(M) with the DER OID
tag of the pre-hash function (all 12 NIST digests/XOFs; SHAKE-128
pre-hash output 32 B, SHAKE-256 64 B). External-mu (Algorithms 7/8):
sign/verify with the 64-byte message digest mu supplied externally.
Verified against the official NIST ACVP vector sets (FIPS204-tr1 sigGen
pre-hash, deterministic, byte-exact; full sigVer pre-hash suite; all
rejection categories).

**v0.30.0 features.** **ML-DSA external-mu ACVP coverage** — the
external-mu entry points shipped in v0.29.0 (`*_sign_mu` /
`*_verify_mu`) are now pinned against the official NIST ACVP
external-mu vector groups: sigGen deterministic (byte-exact, mu
supplied) and the full sigVer external-mu suite including all rejection
categories. ML-DSA's complete FIPS 204 surface — pure, pre-hash and
external-mu interfaces — is now vector-verified (789 tests).

**v0.31.0 features.** **SLH-DSA (SPHINCS+, FIPS 205)** — the NIST
stateless hash-based signature standard, all 12 approved parameter sets
(SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}). Pure-MoonBit port: WOTS+
chains, XMSS Merkle trees, the hypertree, FORS few-time signatures,
the SHA2 instance (MGF1-SHA-256/512 based H_msg, compressed 22-byte
addresses, category-dependent hash selection) and the SHAKE instance
(SHAKE256 based). Verified against the official NIST ACVP vectors:
keyGen (all sets), sigGen deterministic (pure, pre-hash with OID
tagging, and internal/raw-M' semantics) and sigVer. Note: SLH-DSA is
deliberately expensive — signing runs thousands of hash calls; the full
849-test suite takes ~17 minutes.

**v0.32.0 features.** **SLH-DSA speed-up (~16%) + hasher cloning.**
SLH signing now runs through a per-key hash suite: the SHA2/SHAKE
`PK.seed` prefix is absorbed once and reused via zero-allocation
working hashers (state reset per call, prefix bytes restored). New
public utilities `sha256_clone` / `sha512_clone` / `sha3_clone`
deep-copy streaming hashers for hashing many messages that share a
prefix. Note a subtle trap now documented in the test history: when a
buffered prefix is shorter than one block, multi-block absorptions
overwrite the prefix region of the buffer, so a reused hasher must
restore it.

**v0.33.0 features.** **ML-KEM hybrid encryption (KEM + DEM)** —
`ml_kem_{512,768,1024}_hybrid_seal / hybrid_open` plus streaming
`hybrid_seal_init` + `ml_kem_hybrid_stream_update / stream_final`.
Composition: (K, c) = Encaps(ek, m); (key, nonce) = HKDF-SHA256(salt =
c, ikm = K, info = "mooncry/ml-kem-hybrid/v1", 44); blob = c ||
ChaCha20-Poly1305(key, nonce, aad, msg). `open` returns `None` on any
failure (KEM implicit rejection surfaces as a tag mismatch). New
incremental Poly1305 (`poly1305_new / update / finalize`; the one-shot
is now built on it). **Also fixes a latent HMAC bug**: keys longer than
one block were not zero-padded after hashing (ipad/opad truncated);
RFC 4231 TC6 regression vectors added. Verification: KEM I/O from the
official NIST ACVP vectors (FIPS 203); the composition layer is
cross-checked against pycryptodome.

**v0.34.0 features.** **SLH-DSA ~25% faster (suite 17 min → 13 min).**
Two allocation-removal passes on the per-node hash hot path:
`sha256_finalize_n` / `sha512_finalize_n` write truncated digests
directly (one allocation instead of finalize + slice), and `T_l` over
WOTS+/FORS public values now feeds the pre-split blocks into the hasher
without concatenating. Regression-tested against truncated one-shot
digests. (A moonc 0827 compiler ICE forced the finalize_n internals to
be factored into a shared padding helper — noted for future toolchains.)

**v0.35.0 features.** **X-Wing hybrid KEM**
(draft-connolly-cfrg-xwing-kem) — the ML-KEM-768 + X25519 composite
KEM: `xwing_keygen` (32-byte seed → 1216-byte pk), `xwing_encaps`
(derandomized in a 64-byte eseed) and `xwing_decaps` (implicit
rejection inherited from ML-KEM). Verified against the official draft
test vectors (keygen, encapsulation and decapsulation for all three
published vectors).

**v0.36.0 features.** **TurboSHAKE + KangarooTwelve (RFC 9861)** —
`turbo_shake_128 / turbo_shake_256` (Keccak-p[1600,12] sponge with a
domain byte; 12-round permutation factored out of the SHA-3 core) and
`kangaroo_twelve_128 / kangaroo_twelve_256` (Sakura tree hash over
8192-byte chunks with a customization string). Verified against every
applicable RFC 9861 test vector, including the 8191/8192-byte tree
boundary and customization-string cases.

**v0.37.0 features.** **HPKE — Hybrid Public Key Encryption (RFC
9180).** DHKEM(X25519, HKDF-SHA256) and DHKEM(X448, HKDF-SHA512);
KDFs HKDF-SHA256/SHA512; AEADs AES-128-GCM, AES-256-GCM and
ChaCha20Poly1305; all four modes (base / psk / auth / auth+psk).
`hpke_setup_s / hpke_setup_r` (derandomized via explicit ephemeral
IKM), `hpke_seal / hpke_open` with automatic sequence numbers
(`None` on authentication failure), and `hpke_export`. Verified
against the official RFC 9180 Appendix A vectors (every mode of the
X25519 suites, including the sequence-number carry at 255/256);
X448 covered by round-trip tests.

**v0.38.0 features.** **HPKE completes: DHKEM(P-256, HKDF-SHA256)**
with rejection-sampling key derivation and uncompressed-point
encoding, covering the remaining official RFC 9180 Appendix A suites
(A.3-A.5, all four modes each), including the mixed
DHKEM(P-256)+HKDF-SHA512 ciphersuite where the KEM-internal KDF
differs from the suite KDF. All three DHKEMs the RFC defines vectors
for are now vector-verified.

**v0.39.0 features.** **AES-GCM-SIV (RFC 8452)** — the
nonce-misuse-resistant AEAD: `aes_gcm_siv_encrypt /
aes_gcm_siv_decrypt` for AEAD_AES_128_GCM_SIV and
AEAD_AES_256_GCM_SIV. POLYVAL is implemented via the RFC Appendix A
equivalence with GHASH (ByteReverse + mulX), reusing the library's
table-accelerated GF(2^128) multiplier. Verified against all 48
official RFC 8452 Appendix C vectors (encrypt byte-exact + decrypt
round-trip).

**v0.40.0 features.** **HPKE completes: DHKEM(P-521, HKDF-SHA512)** —
rejection sampling with the 0x01 bitmask over 66-byte candidates,
133-byte uncompressed points, and the library's generic BigInt scalar
multiplication (P-521 also uses a = -3). The official RFC 9180
Appendix A.6 vectors (all four modes) now pass — every HPKE ciphersuite
the RFC publishes vectors for is vector-verified.

**v0.41.0 features.** **HPKE DHKEM(P-384, HKDF-SHA384) + HMAC/HKDF-SHA384**
— the HPKE KEM table is now complete (P-256/P-384/P-521/X25519/X448).
New public `hmac_sha384` (with the long-key zero-padding handled) and
`hkdf_sha384` / `hkdf_sha384_extract`, regression-tested against
pycryptodome (RFC 4231 TC6-style long key). P-384 HPKE is verified by
differential vectors from an independent Python oracle (the HPKE
composition machinery itself is RFC-vector-verified via P-256/P-521).

Falcon operation benchmarks (release, wasm, this host — `moon bench`):
**falcon512 keygen ~97 ms, sign ~4.4 ms, verify ~348 µs**.

**v0.55.0-v0.64.0 features.** **Falcon-512/1024 lattice signatures** —
a from-scratch pure-MoonBit port of the PQClean `clean` reference
(the official Falcon submission codebase): NTRU keygen via the
small-prime RNS + binary-GCD Bezout tree with f64 Babai reduction,
FFT-domain signing with on-the-fly LDL Gaussian sampling (Salsa20
prng + discrete Gaussian via the raykzhao exp polynomial), and
q = 12289 Montgomery-NTT verification. Every stage is byte-exact or
bit-exact against dumps from the C reference compiled locally: the
deterministic keypair (PK 897/1793 B, SK 1281/2305 B), all official
harness signatures (compact and padded forms), and rejection streams.
The single logn-parameterized tree covers both parameter sets (the
PQClean 512/1024 sources are functionally identical modulo prefixes).

**v0.53.0 features.** **Performance: Ed448 Shamir verification +
housekeeping.** Ed448 verify rewrites the cofactor equation
[4][S]B = [4]R + [4][k]A as [4](S*B - k*A - R) = O and evaluates it
with one interleaved-window double-scalar multiplication instead of
two independent ones (using L-k for -k is cofactor-safe: the
difference is [4](L*A) = O for ANY point since the group order is
4L). **Ed448 verify 15.2 → 12.0 ms**; the base point is hoisted to a
constant. ML-DSA's dq_mul keeps i64.rem after THREE measured-negative
alternatives (f64 reciprocal, folding with a subtraction loop, and
branch-free folding over q = 2^23-2^13+1) — all documented in-code so
nobody retries them. Also normalized 118 stray NUL bytes inside byte
literals across 22 files to `` escapes (semantics unchanged; the
files are text-clean for grep/diff again).

**v0.52.0 features.** **Performance: word-oriented scrypt.** The
Salsa20/8 core, scryptBlockMix and ROMix now operate on UInt word
arrays in place (V table = a single flat allocation; XORs and
interleaving at word granularity; no per-block Bytes conversions) —
~1.4x on the memory-hard loop. RFC 7914 vectors unchanged.

**v0.51.0 features.** **Performance: native P-256 field and curve
arithmetic.** New eight-32-bit-limb implementation of GF(p256):
schoolbook multiply with UInt64 accumulators (provably overflow-free)
and the NIST Solinas fast reduction — the fold table for
2^256 = 2^224 - 2^192 - 2^96 + 1 is DERIVED at init by a fixpoint
loop (cross-validated in Python against modular arithmetic on random
x < p^2) and the prime words come from the existing p256_curve
constant. Jacobian doubling/addition (a = -3), 4-bit windowed scalar
multiplication and Shamir double-scalar multiplication mirror the
vector-verified generic code; ec_scalar_mult and
ec_double_scalar_mult_jac dispatch to the native path whenever the
curve modulus is P-256's, so ECDSA, low-S signing, and HPKE P-256 DH
all benefit. **ECDSA P-256 sign 5.6 → 3.6 ms, verify 7.1 → 4.5 ms**
(3.5x / 5x versus the pre-optimization BigInt baseline). Differential
tests against the generic BigInt path (64 random field multiplies,
10 scalar multiples) run permanently in the suite.

**v0.50.0 features.** **Performance: matrix-expansion caching for the
lattice schemes.** ML-DSA re-expanded the full k x l A matrix (FIPS 204
ExpandA, k*l rejection-sampled polynomials) on every sign, verify and
keygen, and ML-KEM did the same with its k x k A-hat (FIPS 203 XOF
rejection sampling); both now live in single-slot caches keyed by
(rho, dimensions) — A depends only on the key's public seed, never on
the message. **ML-DSA-65 verify 1.78 ms → 0.61 ms (2.9x), sign 8.4 →
7.2 ms; ML-KEM-768 keygen 620 → 364 µs (1.7x), encaps 623 → 389 µs
(1.6x), decaps 583 µs.** New benchmarks: ml_dsa_65 sign/verify,
ml_kem_768 keygen/encaps/decaps. Cached matrices are contractually
read-only for all consumers.

**v0.49.0 features.** **Performance: native Curve448-Goldilocks field
arithmetic (radix 2^28, sixteen signed Int64 limbs).** p448 = 2^448 -
2^224 - 1 folds via 2^448 = 2^224 + 1; the fold coefficients are
derived per (i,j,k) by pure arithmetic in the multiply inner loop
(verified term-by-term against the recursive definition — no tables,
no hand-copied constants), the subtraction bias is the limb
decomposition of p448 computed at init. X448 runs a native Montgomery
ladder (a24 = 39081, RFC 7748 clamp); Ed448 point arithmetic (RFC
8032 A.4 projective formulas), encode/decode and the decoding square
root all move onto the new limbs, with 4-bit window scalar
multiplication. **Ed448 sign 27.2 → 13.2 ms (2.1x), verify 29.8 →
15.2 ms; X448 10.4 → 6.1 ms (1.7x).** Validated by a Python prototype
against the official RFC 7748 §6.2 X448 vectors (Alice/Bob/shared
secret) and the §7.1 iteration value before porting; all RFC 8032
§7.4 Ed448 vectors green.

**v0.48.0 features.** **Performance: division-free Ed448/X448 field
arithmetic** — the Barrett playbook from v0.46 applied to the 448-bit
Goldilocks prime: conditional add/sub, Barrett modular multiply, and
precomputed MSB-first bit chains for inversion (p-2) and the decoding
square root (exponent (p+1)/4). **Ed448 sign
27.2 → 21.3 ms, verify 29.8 → 23.5 ms; X448 10.4 → 7.9 ms.** New
benchmarks for Ed448/X448.

**v0.47.0 features.** **XMSS / XMSS^MT eXtended Merkle Signatures
(RFC 8391)** — the second major stateful hash-based family (with
LMS/HSS), ported 1:1 from the official reference implementation
(github.com/XMSS/xmss-reference, CC0, by the RFC authors). WOTS+
(w=16) with PRF_keygen-derived chain seeds, tweakable hashes thash_f/
thash_h with per-address PRF keys/masks, L-tree WOTS-pk compression,
stack-based treehash with auth-path extraction, and the XMSS^MT
layer machinery (d layers, per-layer subtree addresses). All five
domain-tagged hash instantiations: SHA2 with n=24/32/64 and SHAKE128/
SHAKE256 with n=32/64. Verified against the reference's deterministic
KATs (seed[i]=i, msg=0x25, index=2^(H-1)): WOTS+ pk/sign/pk-from-sig/
leaf byte-exact for all 7 parameter sets; XMSS^MT (H=20/2_256 family,
4 layers, all 7 sets) keygen+sign byte-exact; XMSS H10 verify for all
7 sets plus byte-exact keygen+sign for SHA2_10_256. Completes the
three-family post-quantum signature coverage: ML-DSA (lattice,
stateless), SLH-DSA (hash, stateless), LMS+XMSS (hash, stateful).

**v0.46.0 features.** **Performance: division-free EC arithmetic.**
Every modular multiply on the NIST curves (P-256, P-384, P-521) and
secp256k1 now reduces with a per-curve Barrett constant
(mu = floor(2^2k / p), derived once at init) instead of BigInt
division; field add/sub became conditional add/sub (no reduction op at
all); modular inversion (field and scalar order) runs a precomputed
MSB-first bit chain over the Barrett multiply instead of the generic
modular exponentiation. **ECDSA P-256 sign 8.2 → 5.6 ms (1.46x),
verify 9.5 → 7.1 ms (1.33x)**; secp256k1 and all HPKE NIST-curve DH
benefit identically.

**v0.45.0 features.** **Performance: native Curve25519 field
arithmetic (radix 2^25.5, ten signed Int64 limbs — donna/ref10 style).**
New `fe25519` core with multiplication coefficients DERIVED at init
from the shift table (never hand-copied), precomputed fixed-exponent
bit patterns (p-2 inversion, (p+3)/8 square root), and one raw
ladder pass. X25519 moves off the generic BigInt ladder:
**4.34 → 1.80 ms (2.4x)**. Ed25519 group arithmetic (extended
coordinates), point decoding (native sqrt instead of two BigInt
modular exponentiations) and encoding all run on the new limbs:
**sign 10.3 → 4.3 ms (2.4x), verify 9.9 → 3.7 ms (2.7x)**; Ed25519ctx/ph
ride the same path. Keccak gained flat lane-index tables (rho/pi/chi
without nested lookups or per-round mod-5) and copy-free SHA3 absorb.
New tests: RFC 7748 §6.1 vectors + iteration-1, ECDH commutativity
property, and public-key consistency (the BigInt ladder is retained
in the test tree as a differential reference).

**v0.44.0 features.** **Performance: T-table AES core + LMS fast
chains (benchmarked, wasm-gc).** The AES block core is rewritten in
the classic OpenSSL T-table style (four 256-entry UInt tables fusing
SubBytes+ShiftRows+MixColumns into one lookup per output word; the
decryption key schedule applies InvMixColumns to rounds 1..nr-1 per
the equivalent inverse cipher). Every AES mode benefits:
**AES-256-GCM 439 → 104 µs/KiB (4.2x)**, CTR 63.5, CBC 79.4, SIV 188,
CMAC 68.8 µs/KiB; GCM-SIV, CCM and KW ride the same core. LMS/HSS
chain hashing moved to a shared pre-padded SHA-256 block template
(one raw compression per Winternitz step, zero per-hash allocations):
LMS test workload ~1.9x, key generation several times faster.

**v0.43.0 features.** **LMS / HSS hash-based signatures (RFC 8554)**
— the Leighton-Micali Signature scheme and its Hierarchical variant,
SHA256 parameter sets (LMOTS_SHA256_N32_W1/W2/W4/W8 x
LMS_SHA256_M32_H5/H10/H15/H20/H25). Stateful: `lms_sign` consumes one
Merkle leaf per signature and aborts at exhaustion; HSS chains L
levels with fixed inter-level signatures (caller re-keys on bottom-level
exhaustion). Pseudorandom key generation follows RFC 8554 Appendix A
(SEED/I). Verified against the official RFC 8554 Appendix F test cases
(HSS L=2 verify + public-key regeneration from SEED/I) plus 12
oracle-generated vectors covering all four Winternitz widths, tree
heights 5/10/15, non-zero leaf counters, and HSS L=1/2/3, and
sign/verify round-trips. Completes the hash-based signature families
alongside SLH-DSA (stateless).

**v0.42.0 features.** **Performance polish (benchmarked, wasm-gc).**
Ed25519 rewritten on extended twisted Edwards coordinates (X:Y:Z:T,
Hisil et al. formulas) with 4-bit fixed-window scalar multiplication
and Shamir double-scalar verification: **sign 855 ms → 10.3 ms (83x),
verify 870 ms → 9.9 ms (88x)**. ECDSA P-256 (and secp256k1, and the
HPKE NIST-curve DH) switched from string double-and-add to 4-bit
windows + Shamir verify: **P-256 sign 12.4 → 10.2 ms, verify 22.7 →
12.3 ms**. BLAKE3 chunk compression made zero-allocation (ping-pong
message schedule): **64 → 20 µs/KiB (3.2x), now faster than BLAKE2b**.
New benchmarks for Ed25519/X25519.

**v0.79.0 perf pass (ZUC).** Every figure here is an *alternating same-session*
A/B against v0.78.0 (HEAD stashed, benched, restored, benched, twice). That
method was not optional: background load on the host swung absolute numbers by
3x while this work was running, and two conclusions drawn from cross-session
comparisons — "branchless is 2.3x slower", "the compact byte loop is 2x slower"
— both evaporated under a proper A/B and are not in the code.

* The ZUC-256 MAC held its accumulator and key register in `Array[UInt64]`,
  which costs a bounds-checked load *and* store per register word per **message
  bit**. Specialising the three tag sizes into local-variable registers: 1 KiB
  with a 128-bit tag **168 µs → 37.6 µs (4.5x)**, the same ratio in both rounds
  and under both load conditions.
* 128-EIA3's (K0, K1) pair packs into one `UInt64`, so sliding the register is a
  single 64-bit shift instead of two 32-bit shifts plus a merge (**~1.15x** on
  the MAC, and less code).
* S0/S1 widened from `Array[Byte]` to `Array[UInt64]` once at load, dropping a
  `Byte`→`Int`→`UInt64` conversion from each of the eight lookups per clock:
  **1.35-1.45x** on the stream paths for 4 KiB of table.
* The LFSR's 15-cell shift unrolled into constant-index copies: ~5% on an idle
  host, ~20% under load. Deleting the shift *entirely* measured no faster than
  the unrolled form, so the state stays a plain 16-cell array instead of
  becoming a ring buffer — which would have needed a new field in the public
  `ZucState` for nothing.
* Keystream XOR now runs word by word into the output buffer instead of
  materialising the whole keystream first: half the allocation, one pass.

Overall, against v0.78.0: stream paths **1.2-1.3x**, 128-EIA3 **1.3x**,
ZUC-256 MAC **4.5x**. Two candidates measured *within noise* and were not kept
as speed claims: unrolled constant shifts vs a compact loop with a computed
shift in the XOR path (the compact loop stayed), and a masked AND vs a branch
for the message-bit conditional (the mask stayed — same cost, and it removes
message-dependent branching).

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
vectors), **GMAC** (pycryptodome GCM) + incremental-vs-one-shot,
**keyed BLAKE2b/2s** (hashlib keyed),
**Adler-32** (zlib), **PBKDF2-HMAC-SHA1** (RFC 6070 official suite),
**ECDSA secp256k1** (Python `ecdsa` RFC 6979 + `cryptography` cross-verify,
sk = 1 ⇒ pubkey = G anchor; low-S BIP-62 via `sigencode_string_canonize`),
**multi-hash RSA** PKCS1-v1.5/PSS/OAEP
(pycryptodome, SHA-1/384/512 exact + random-salt/seed interop; OAEP-SHA512
on a 2048-bit key),
**sealed-box** round-trip + property-based round-trip checks
(deterministic PRNG) for every cipher + streaming-vs-one-shot consistency.

**Hostile-input robustness** (`lib/robust_test.mbt`, 17 tests) is the
reliability net for everything that parses bytes from a peer. A fixed
xorshift64* PRNG (same stream on every run and every target) generates
truncations, head drops, extensions, single-bit flips, byte replacements, byte
swaps and full wipes of an authentic value, plus random blobs of exactly the
right length so the parser runs *past* its first length gate. Each mutation is
fed to the corresponding entry point — ML-DSA / SLH-DSA / Falcon / Ed25519 /
Ed448 / ECDSA / SM2 / LMS / HSS / XMSS verification, ML-KEM / X-Wing / HPKE key
agreement, every AEAD and RSA decryption path, the SM2 DER/PEM codecs, the
Falcon public decoders, the hex/Base64 decoders, and X25519/X448 shares — and
must satisfy two properties: it never traps (reaching the end of the suite *is*
the assertion), and it never accepts (a mutated value is `false` / `None` /
`Err`, and an authentic one still round-trips afterwards). It also covers
degenerate Falcon secret keys (an all-zero body, a flipped coefficient byte) and
a broken caller-supplied RNG, which must terminate rather than hang.

The suite is written to have teeth: it catches a removed ML-DSA public-key
length check with an out-of-bounds trap, a removed HPKE on-curve check with an
accepted invalid-curve point, a removed X25519 length check with a trap
inside the ladder, a removed ML-KEM `ek` length check with a trap on the seal
path, a removed RSA modulus check with a trap inside the modexp, a removed
nonzero-`rand_ps` scan with an accepted zero byte, a removed SM2 on-curve
check with an accepted off-curve point (that one has a deterministic witness:
the real x with y zeroed), and a neutered SM2 encoder shape check with an
out-of-bounds trap. Two more, from the SLH-DSA coverage below: a
`slh_verify_prehash` that ignores its hash-algorithm argument, and a
`slh_sign_hedged` that ignores its randomness (the second one reddens as
"hedged(rnd) equalled the deterministic signature").

**SLH-DSA's four untested entry points** (`lib/slh_prehash_hedged_test.mbt`,
2 tests) — `slh_verify_prehash`, `slh_sign_hedged`, `slh_sign_prehash_hedged`
and `slh_sign_raw_hedged` had no coverage at all while their siblings were
pinned by ACVP known-answer vectors. That asymmetry mattered:
`slh_sign_prehash` was vector-checked 12 times, so a wrong
M' = 0x01‖octet(|ctx|)‖ctx‖OID‖PH(M) on the *verify* side would have shipped
silently — sign and verify would agree with each other and disagree with
everyone else. The tests now cover all twelve prehash algorithms' verify path
through three representatives (SHA2, SHA3, an XOF), every binding negative
(message, context, algorithm, flipped signature byte, wrong key, four malformed
lengths, an over-long context), both context boundaries (0 and 255 verify, 256
returns false rather than trapping), and domain separation in both directions
(a HashSLH-DSA signature verifies neither as a pure nor as a raw-M' signature).
The three hedged signers are anchored to external authority by a spec identity
rather than by new vectors: `slh_sign_internal` uses opt_rand = PK.seed when no
randomness is given, so `slh_sign_hedged(…, pk_seed)` must reproduce
`slh_sign(…)` byte for byte — and the deterministic signer is the one the ACVP
vectors pin. Fresh randomness must then differ from it and still verify, for
all three hedged entry points. These two tests cost ~88s of the release suite
(one SLH-DSA-128s signature is ~1.3s, verification about the same), which is
why the matrix is minimal and says so in its header.

**ZUC** (`lib/zuc_test.mbt`, 13 tests) is vector-verified twice over: the
official GM/T 0001.1-2012 keystream vectors, the 3GPP TS 35.222 EEA3 vectors
and the GM/T 0001.3-2012 / TS 35.223 EIA3 vectors, plus 107 differential
vectors (64-word streams for nine keys, one 1024-word run, a 16-point bit-length
sweep for EEA3 across COUNT/BEARER/DIRECTION, and a 13-point sweep for EIA3)
generated by the GmSSL reference compiled locally and re-verified against that
binary before being stored. ZUC-256 is covered the same way: the 2 official
20-word keystream vectors and the 12 official MAC vectors (4 keys x 32/64/128-bit
tags) from the ZUC-256 draft, plus 6 extended 64-word streams and a 36-case MAC
sweep over message lengths 0..200 bytes and all three tag sizes. On top of the
vectors: stream round-trips at 18 lengths, keystream determinism and prefix
consistency, one-bit key/IV separation, and the mode semantics that the vectors
alone do not pin — bits beyond LENGTH must not influence EEA3's output, EIA3's
MAC or the ZUC-256 MAC; a flipped in-range bit must break the MAC; COUNT,
BEARER, DIRECTION and the key must each be bound into it; and ZUC-256's three
tag sizes must be domain-separated. Both ports matched every vector on the
first run; perturbing one S-box entry fails 5 tests and one ZUC-256 key-schedule
field fails 2, so the vectors are genuinely exercised.

`lib/zuc_edge_test.mbt` (2 tests) closes the two gaps those sweeps leave. First,
every ZUC-256 MAC vector above is a whole number of bytes, because the reference
CLI feeds GmSSL's `zuc256_mac_update` by byte count — but `zuc256_mac_finish`
also takes a 1..7-bit tail, so a second oracle command (`mac256b`, added in
`Temp/zuc-oracle/oracle_bit.c`) yields 51 bit-granular tags: lengths 0, 1, 7, 9,
31, 33, 63, 65 and 508 bits across all three tag sizes, half of them with the
tail byte's unused low bits forced to 1. The reference gives the identical tag
for both forms, so "bits beyond LENGTH are not part of the message" is a
*differential* assertion against the compiled reference rather than a
self-referential one. Second, nbits=0 was covered for 128-EEA3 only; it is now
pinned for 128-EIA3 (3 parameter sets, with `zuc_eia3_verify` accepting its own
MAC) and for all three ZUC-256 tag sizes.

The hostile-input suite covers ZUC as well. `robust-zuc` drives forged
(message, tag) pairs through both verifiers at every buffer length the fuzzer
produces, plus mutated keys/IVs and involutive stream round-trips; the LENGTH
contract is respected by deriving nbits from each mutated buffer, so a wrong
shape never masks a wrong answer. `robust-zuc-state` interleaves two live
`ZucState`s word by word and requires each to reproduce its own one-shot
keystream — the aliasing bug class a caller-held mutable state invites (and
which the module-level widened S-box tables would make easy to reintroduce).
Both were teeth-checked: a `zuc_eia3_verify` that ignores the message turns
`robust-zuc` red, and making every state share one LFSR array turns
`robust-zuc-state` red.

**Structure-aware DER/PEM fuzzing** (`lib/robust_der_test.mbt`, 4 tests) targets
the hand-written ASN.1 parsers, where byte-flip fuzzing is nearly useless: a
mutated blob almost always dies at the first tag or length check, so the deep
paths never run. These build blobs that *look* like DER — every prefix of a
valid encoding, every single-byte substitution with a DER-meaningful value
(tags, both length forms, `0x80` indefinite, `0x81`/`0x82` long forms),
extra/inserted TLVs, non-minimal INTEGERs, trailing garbage — and hold each
codec to the identity strict DER implies: **an accepted blob must re-encode
byte-identically**. Two out-of-bounds traps were found this way, both of the
"valid prefix, nothing after it" shape that random mutation never produces.

**Streaming state** (`lib/robust_stream_test.mbt`, 3 tests) probes the two
failure modes one-shot KATs cannot see: a `clone` that shares its buffer with
the original, and a sub-block prefix overwritten when absorption crosses the
block boundary. Clones are forked at every block boundary (0/1/2/62..66/127..129
for the 64-byte-block hashes, the 128-byte range for SHA-512, and both SHA-3
rates 136/168), each fork fed a different suffix, and both results compared
against their one-shot digests. Plus streaming-vs-one-shot equality across 19
chunk sizes for MD5, SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256,
SHA3-224/512, SHAKE-256, SM3 and Poly1305; interleaved hashers; incremental
GMAC at four IV lengths; and the ML-KEM hybrid envelope streamed in 1..500-byte
chunks against its one-shot form.

**Boundary-length sweeps** (`lib/robust_boundary_test.mbt`, 5 tests) complement
the randomized property tests by pinning the sizes that block-oriented code
actually cares about: `0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
129, 255, 256, 257` for the plaintext and `0, 1, 15, 16, 17` for the AAD (both
have their own padding path in GHASH / Poly1305 / CCM / S2V). Each combination
asserts the exact output length the format specifies, an exact round trip, and
that a single flipped bit anywhere in the sealed blob is rejected. Coverage:
ChaCha20-Poly1305 and XChaCha20-Poly1305, AES-GCM at 128/192/256-bit keys,
SM4-GCM, AES-GCM-SIV at both key sizes, AES-CCM across nonce 7/11/13 (all three
`q = 15 - nonce_len` length-field widths) x mac 4/8/16, AES-SIV at 32/48/64-byte
keys with 0/1/2 AD entries, AES-KW, AES-CBC (including the PKCS#7 full extra
padding block on exact multiples of 16) and CTR, SM4-CBC/CTR, the sealed box,
the ML-KEM hybrid envelope and the SM2 GM/T 0009 envelope.

**1177 tests.**

## Development

The CI (`.github/workflows/moonbit-ci.yml`) installs the latest MoonBit
toolchain and runs five job groups: **check** (wasm32 — `moon check
--deny-warn`, `moon fmt --check`, `moon info`, `moon test --deny-warn
--release`, a guard that no build artifacts are tracked, and the static
[API contract check](#security--performance-boundaries)), **native64** (`moon
test --target native --release`, where `Int` is 64-bit instead of 32-bit),
**js** and **js-slh-shake** (`moon test --target js --release`, the
browser/node backend, sharded by file because the SLH-DSA suites dominate it)
and **fuzz-rotate** (the hostile-input suites re-run three times with freshly
randomized seeds, on a workspace that is discarded afterwards). Width-sensitive
masking and comparison code has to be correct on all of them. Run them locally:

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

**Layout.** Three packages, and the dependency may only point one way:

```
cmd/main    the NIST vector runner          -> lib
lib         the public API (490 pub names)  -> internal
internal    the Falcon low-level layer (81 names), not importable downstream
```

`internal/` is a package in the compiler-enforced sense (see
[Public but internal](#public-but-internal-what-pub-owes-you-here)). It has no
imports of its own; anything that needs the library's own primitives — the
Falcon XOF wrapping `Sha3Hasher`, say — has to stay in `lib`, because MoonBit
rejects import cycles (`Import loop detected`). A directory without a
`moon.pkg` is not a package at all and will not be found, which looks exactly
like a visibility error.

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
