// ==================== HMAC-SHA3-224 / HMAC-SHA3-384 ====================
// Completes the HMAC-SHA3 family (RFC 2104 over FIPS 202).
// Block size = the Keccak rate: SHA3-224 -> 144, SHA3-384 -> 104.

///|
/// HMAC-SHA3-224 (RFC 2104 keyed hash over SHA3-224, block size 144).
/// Returns a 28-byte tag.
pub fn hmac_sha3_224(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 144
  let k_prime = if key.length() > block_size {
    pad_key_to(sha3_224(key), block_size)
  } else {
    pad_key_to(key, block_size)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  let inner_h = sha3_224_new()
  sha3_update(inner_h, ipad)
  sha3_update(inner_h, message)
  let inner = sha3_finalize(inner_h)
  let outer_h = sha3_224_new()
  sha3_update(outer_h, opad)
  sha3_update(outer_h, inner)
  sha3_finalize(outer_h)
}

///|
/// HMAC-SHA3-384 (RFC 2104 keyed hash over SHA3-384, block size 104).
/// Returns a 48-byte tag.
pub fn hmac_sha3_384(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 104
  let k_prime = if key.length() > block_size {
    pad_key_to(sha3_384(key), block_size)
  } else {
    pad_key_to(key, block_size)
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  let inner_h = sha3_384_new()
  sha3_update(inner_h, ipad)
  sha3_update(inner_h, message)
  let inner = sha3_finalize(inner_h)
  let outer_h = sha3_384_new()
  sha3_update(outer_h, opad)
  sha3_update(outer_h, inner)
  sha3_finalize(outer_h)
}
