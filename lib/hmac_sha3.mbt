// ==================== HMAC-SHA3 (RFC 2104 + FIPS 202) ====================
// HMAC over the SHA-3 family. Block size = the Keccak *rate* (not 64):
//   SHA3-256 -> rate 136, SHA3-512 -> rate 72.
// Verified against RFC 2202 / known-good vectors.

///|
fn pad_key_to(key : Bytes, block_size : Int) -> Bytes {
  let padded = Array::make(block_size, b'\x00')
  for i in 0..<key.length() {
    padded[i] = key[i]
  }
  Bytes::from_array(padded[:])
}

///|
/// HMAC-SHA3-256 (RFC 2104 keyed hash over SHA3-256, block size 136).
/// Returns a 32-byte tag.
pub fn hmac_sha3_256(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 136
  let k_prime = if key.length() > block_size {
    pad_key_to(sha3_256(key), block_size)
  } else {
    pad_key_to(key, block_size)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  // inner = SHA3-256(ipad || message)
  let inner_h = sha3_256_new()
  sha3_update(inner_h, ipad)
  sha3_update(inner_h, message)
  let inner = sha3_finalize(inner_h)
  // outer = SHA3-256(opad || inner)
  let outer_h = sha3_256_new()
  sha3_update(outer_h, opad)
  sha3_update(outer_h, inner)
  sha3_finalize(outer_h)
}

///|
/// HMAC-SHA3-512 (RFC 2104 keyed hash over SHA3-512, block size 72).
/// Returns a 64-byte tag.
pub fn hmac_sha3_512(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 72
  let k_prime = if key.length() > block_size {
    pad_key_to(sha3_512(key), block_size)
  } else {
    pad_key_to(key, block_size)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  let inner_h = sha3_512_new()
  sha3_update(inner_h, ipad)
  sha3_update(inner_h, message)
  let inner = sha3_finalize(inner_h)
  let outer_h = sha3_512_new()
  sha3_update(outer_h, opad)
  sha3_update(outer_h, inner)
  sha3_finalize(outer_h)
}
