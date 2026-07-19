///|
/// ChaCha20-Poly1305 AEAD (RFC 8439 §2.6, §2.8). 256-bit key, 96-bit nonce.
/// Encrypt output = ciphertext || 16-byte tag. Reuses `chacha20_xor` + `poly1305`.

///|
fn le64(n : Int) -> Bytes {
  n.to_uint64().to_le_bytes()
}

///|
/// Pad `data` with zeros to the next 16-byte boundary (no-op if already aligned).
fn pad16(data : Bytes) -> Bytes {
  let r = data.length() % 16
  if r == 0 {
    Bytes::from_array(Array::make(0, b'\x00')[:])
  } else {
    Bytes::from_array(Array::make(16 - r, b'\x00')[:])
  }
}

///|
fn concat_all(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out = Array::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  Bytes::from_array(out[:])
}

///|
fn bytes_sub(data : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = data[start + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Build the Poly1305 MAC input: aad || pad(aad) || ct || pad(ct) || le64(aad_len) || le64(ct_len)
fn poly1305_mac_data(aad : Bytes, ct : Bytes) -> Bytes {
  let parts : Array[Bytes] = [
    aad,
    pad16(aad),
    ct,
    pad16(ct),
    le64(aad.length()),
    le64(ct.length()),
  ]
  concat_all(parts)
}

///|
/// One-time Poly1305 key = first 32 bytes of ChaCha20 block 0 (counter=0).
fn chacha20_poly1305_otk(key : Bytes, nonce : Bytes) -> Bytes {
  chacha20_xor(Bytes::make(32, b'\x00'), key, nonce, 0U)
}

///|
/// ChaCha20-Poly1305 encrypt. Returns ciphertext || 16-byte tag.
pub fn chacha20_poly1305_encrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes {
  if key.length() != 32 {
    abort("chacha20_poly1305_encrypt: key must be 32 bytes (256 bits)")
  }
  if nonce.length() != 12 {
    abort("chacha20_poly1305_encrypt: nonce must be 12 bytes (96 bits)")
  }
  let otk = chacha20_poly1305_otk(key, nonce)
  let ct = chacha20_xor(plaintext, key, nonce, 1U)
  let tag = poly1305(otk, poly1305_mac_data(aad, ct))
  let out_parts : Array[Bytes] = [ct, tag]
  concat_all(out_parts)
}

///|
/// ChaCha20-Poly1305 decrypt. `input` = ciphertext || 16-byte tag.
/// Verifies the tag (constant-time) and returns the plaintext, or aborts on mismatch.
pub fn chacha20_poly1305_decrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  input : Bytes,
) -> Bytes {
  if key.length() != 32 {
    abort("chacha20_poly1305_decrypt: key must be 32 bytes (256 bits)")
  }
  if nonce.length() != 12 {
    abort("chacha20_poly1305_decrypt: nonce must be 12 bytes (96 bits)")
  }
  let total = input.length()
  if total < 16 {
    abort("chacha20_poly1305_decrypt: input must be at least 16 bytes (tag)")
  }
  let ct_len = total - 16
  let ct = bytes_sub(input, 0, ct_len)
  let tag = bytes_sub(input, ct_len, 16)
  let otk = chacha20_poly1305_otk(key, nonce)
  let expected = poly1305(otk, poly1305_mac_data(aad, ct))
  if !bytes_equal(expected, tag) {
    abort("chacha20_poly1305_decrypt: tag verification failed")
  }
  chacha20_xor(ct, key, nonce, 1U)
}
