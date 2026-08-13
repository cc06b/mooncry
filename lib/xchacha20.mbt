// ============================================================
// HChaCha20, XChaCha20 and XChaCha20-Poly1305
// (draft-irtf-cfrg-xchacha). XChaCha20 extends ChaCha20 to a
// 24-byte nonce: subkey = HChaCha20(key, nonce[0:16]), then plain
// ChaCha20 under (subkey, 0000 || nonce[16:24]). Reuses
// chacha_quarter_round / chacha20_xor / chacha20_poly1305_*.
// ============================================================

///|
/// Write a UInt as 4 little-endian bytes into `out` at `off`
fn xchacha_write_le(out : Array[Byte], off : Int, w : UInt) -> Unit {
  out[off] = (w & 0xFFU).to_byte()
  out[off + 1] = ((w >> 8) & 0xFFU).to_byte()
  out[off + 2] = ((w >> 16) & 0xFFU).to_byte()
  out[off + 3] = ((w >> 24) & 0xFFU).to_byte()
}

///|
/// HChaCha20 (draft §2.2): set up a ChaCha state with the constants,
/// the 32-byte key and the 16-byte input in words 12..15, run 20
/// rounds WITHOUT adding the original state back, and return words
/// 0..3 and 12..15 little-endian as a 32-byte subkey.
pub fn hchacha20(key : Bytes, in16 : Bytes) -> Bytes {
  if key.length() != 32 {
    abort("hchacha20: key must be 32 bytes (256 bits)")
  }
  if in16.length() != 16 {
    abort("hchacha20: input must be 16 bytes")
  }
  let state = Array::make(16, 0U)
  state[0] = 0x61707865U
  state[1] = 0x3320646eU
  state[2] = 0x79622d32U
  state[3] = 0x6b206574U
  for i in 0..<=7 {
    state[4 + i] = read_u32_le(key, i * 4)
  }
  for i in 0..<=3 {
    state[12 + i] = read_u32_le(in16, i * 4)
  }
  for _ in 0..<10 {
    chacha_quarter_round(state, 0, 4, 8, 12)
    chacha_quarter_round(state, 1, 5, 9, 13)
    chacha_quarter_round(state, 2, 6, 10, 14)
    chacha_quarter_round(state, 3, 7, 11, 15)
    chacha_quarter_round(state, 0, 5, 10, 15)
    chacha_quarter_round(state, 1, 6, 11, 12)
    chacha_quarter_round(state, 2, 7, 8, 13)
    chacha_quarter_round(state, 3, 4, 9, 14)
  }
  let out = Array::make(32, b'\x00')
  for i in 0..<=3 {
    xchacha_write_le(out, i * 4, state[i])
    xchacha_write_le(out, 16 + i * 4, state[12 + i])
  }
  Bytes::from_array(out[:])
}

///|
/// Build the 12-byte sub-nonce 00 00 00 00 || nonce24[16:24]
fn xchacha_sub_nonce(nonce24 : Bytes) -> Bytes {
  let out = Array::make(12, b'\x00')
  for i in 0..<8 {
    out[4 + i] = nonce24[16 + i]
  }
  Bytes::from_array(out[:])
}

///|
/// XChaCha20 stream cipher (draft §2.3): encrypt/decrypt `input` with
/// a 32-byte key, a 24-byte nonce and a 32-bit block counter
/// (symmetric, like `chacha20_xor`).
pub fn xchacha20_xor(
  input : Bytes,
  key : Bytes,
  nonce24 : Bytes,
  counter : UInt,
) -> Bytes {
  if key.length() != 32 {
    abort("xchacha20_xor: key must be 32 bytes (256 bits)")
  }
  if nonce24.length() != 24 {
    abort("xchacha20_xor: nonce must be 24 bytes (192 bits)")
  }
  let subkey = hchacha20(key, bytes_sub(nonce24, 0, 16))
  chacha20_xor(input, subkey, xchacha_sub_nonce(nonce24), counter)
}

///|
/// XChaCha20-Poly1305 AEAD encrypt (draft §2.3 / libsodium IETF
/// variant). 32-byte key, 24-byte nonce. Returns ciphertext || 16-byte
/// tag. Equivalent to ChaCha20-Poly1305 under the HChaCha20 subkey and
/// the 12-byte sub-nonce.
pub fn xchacha20_poly1305_encrypt(
  key : Bytes,
  nonce24 : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes {
  if key.length() != 32 {
    abort("xchacha20_poly1305_encrypt: key must be 32 bytes (256 bits)")
  }
  if nonce24.length() != 24 {
    abort("xchacha20_poly1305_encrypt: nonce must be 24 bytes (192 bits)")
  }
  let subkey = hchacha20(key, bytes_sub(nonce24, 0, 16))
  chacha20_poly1305_encrypt(subkey, xchacha_sub_nonce(nonce24), aad, plaintext)
}

///|
/// XChaCha20-Poly1305 AEAD decrypt. `input` = ciphertext || 16-byte
/// tag. Verifies the tag (constant-time) and returns the plaintext, or
/// aborts on mismatch.
pub fn xchacha20_poly1305_decrypt(
  key : Bytes,
  nonce24 : Bytes,
  aad : Bytes,
  input : Bytes,
) -> Bytes {
  if key.length() != 32 {
    abort("xchacha20_poly1305_decrypt: key must be 32 bytes (256 bits)")
  }
  if nonce24.length() != 24 {
    abort("xchacha20_poly1305_decrypt: nonce must be 24 bytes (192 bits)")
  }
  let subkey = hchacha20(key, bytes_sub(nonce24, 0, 16))
  chacha20_poly1305_decrypt(subkey, xchacha_sub_nonce(nonce24), aad, input)
}
