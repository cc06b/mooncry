// ==================== SHA-512/t (FIPS 180-4 §5.3.6) ====================
// SHA-512/224 and SHA-512/256: the SHA-512 compression with distinct
// initial values and a truncated digest. Reuses the SHA-512 streaming
// hasher from hash_stream.mbt (same pattern as SHA-384).

///|
/// Create a new SHA-512/224 hasher (FIPS 180-4 §5.3.6.1)
pub fn sha512_224_new() -> Sha512Hasher {
  let state = Array::make(8, 0UL)
  state[0] = 0x8C3D37C819544DA2UL
  state[1] = 0x73E1996689DCD4D6UL
  state[2] = 0x1DFAB7AE32FF9C82UL
  state[3] = 0x679DD514582F9FCFUL
  state[4] = 0x0F6D2B697BD44DA8UL
  state[5] = 0x77E36F7304C48942UL
  state[6] = 0x3F9D85A86A1D36C8UL
  state[7] = 0x1112E6AD91D692A1UL
  Sha512Hasher::{
    state,
    buffer: Array::make(128, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-512/224 hasher (same compression as SHA-512)
pub fn sha512_224_update(hasher : Sha512Hasher, data : Bytes) -> Unit {
  sha512_update(hasher, data)
}

///|
/// Finalize and return the 28-byte SHA-512/224 digest
pub fn sha512_224_finalize(hasher : Sha512Hasher) -> Bytes {
  let full = sha512_finalize(hasher)
  let out = Array::make(28, b'\x00')
  for i in 0..<28 {
    out[i] = full[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHA-512/224 (FIPS 180-4), 28-byte digest
pub fn sha512_224(data : Bytes) -> Bytes {
  let hasher = sha512_224_new()
  sha512_224_update(hasher, data)
  sha512_224_finalize(hasher)
}

///|
/// Create a new SHA-512/256 hasher (FIPS 180-4 §5.3.6.2)
pub fn sha512_256_new() -> Sha512Hasher {
  let state = Array::make(8, 0UL)
  state[0] = 0x22312194FC2BF72CUL
  state[1] = 0x9F555FA3C84C64C2UL
  state[2] = 0x2393B86B6F53B151UL
  state[3] = 0x963877195940EABDUL
  state[4] = 0x96283EE2A88EFFE3UL
  state[5] = 0xBE5E1E2553863992UL
  state[6] = 0x2B0199FC2C85B8AAUL
  state[7] = 0x0EB72DDC81C52CA2UL
  Sha512Hasher::{
    state,
    buffer: Array::make(128, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-512/256 hasher (same compression as SHA-512)
pub fn sha512_256_update(hasher : Sha512Hasher, data : Bytes) -> Unit {
  sha512_update(hasher, data)
}

///|
/// Finalize and return the 32-byte SHA-512/256 digest
pub fn sha512_256_finalize(hasher : Sha512Hasher) -> Bytes {
  let full = sha512_finalize(hasher)
  let out = Array::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = full[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHA-512/256 (FIPS 180-4), 32-byte digest
pub fn sha512_256(data : Bytes) -> Bytes {
  let hasher = sha512_256_new()
  sha512_256_update(hasher, data)
  sha512_256_finalize(hasher)
}
