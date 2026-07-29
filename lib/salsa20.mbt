// ==================== Salsa20 (eSTREAM, 20-round stream cipher) ====================
// The Salsa20 stream cipher (Bernstein). 16/32-byte key, 8-byte nonce,
// 64-bit block counter. Reuses the Salsa20 quarter-round + rotation helpers
// from scrypt.mbt (the Salsa20/8 core). Verified against pycryptodome
// (Crypto.Cipher.Salsa20).
//
// sigma constants:
//   32-byte key -> "expand 32-byte k"
//   16-byte key -> "expand 16-byte k"

///|
let salsa20_sigma32 : Array[UInt] = [
  0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
]

///|
let salsa20_sigma16 : Array[UInt] = [
  0x61707865U, 0x3120646eU, 0x79622d36U, 0x6b206574U,
]

///|
/// Build the 16-word Salsa20 input block from key/nonce/counter (RFC 7539-era
/// Bernstein layout: sigma at corners, key split, nonce + counter in the
/// middle).
fn salsa20_input_block(
  key : Bytes,
  nonce : Bytes,
  counter : Int,
) -> Array[UInt] {
  let sigma = if key.length() == 32 { salsa20_sigma32 } else { salsa20_sigma16 }
  let b = Array::make(16, 0U)
  b[0] = sigma[0]
  b[5] = sigma[1]
  b[10] = sigma[2]
  b[15] = sigma[3]
  // key words
  b[1] = scrypt_read_u32_le(key, 0)
  b[2] = scrypt_read_u32_le(key, 4)
  b[3] = scrypt_read_u32_le(key, 8)
  b[4] = scrypt_read_u32_le(key, 12)
  if key.length() == 32 {
    b[11] = scrypt_read_u32_le(key, 16)
    b[12] = scrypt_read_u32_le(key, 20)
    b[13] = scrypt_read_u32_le(key, 24)
    b[14] = scrypt_read_u32_le(key, 28)
  } else {
    // 16-byte key is used twice
    b[11] = b[1]
    b[12] = b[2]
    b[13] = b[3]
    b[14] = b[4]
  }
  b[6] = scrypt_read_u32_le(nonce, 0)
  b[7] = scrypt_read_u32_le(nonce, 4)
  b[8] = counter.reinterpret_as_uint()
  b[9] = 0U
  b
}

///|
/// Compute one 64-byte Salsa20 keystream block for the given key, nonce, and
/// block counter.
pub fn salsa20_keystream_block(
  key : Bytes,
  nonce : Bytes,
  counter : Int,
) -> Bytes {
  if key.length() != 16 && key.length() != 32 {
    abort("salsa20: key length must be 16 or 32 bytes")
  }
  if nonce.length() != 8 {
    abort("salsa20: nonce length must be 8 bytes")
  }
  let block = salsa20_input_block(key, nonce, counter)
  let x = Array::make(16, 0U)
  for i in 0..<16 {
    x[i] = block[i]
  }
  // 10 doublerounds = 20 rounds
  for _ in 0..<10 {
    // columnround
    salsa20_qr(x, 0, 4, 8, 12)
    salsa20_qr(x, 5, 9, 13, 1)
    salsa20_qr(x, 10, 14, 2, 6)
    salsa20_qr(x, 15, 3, 7, 11)
    // rowround
    salsa20_qr(x, 0, 1, 2, 3)
    salsa20_qr(x, 5, 6, 7, 4)
    salsa20_qr(x, 10, 11, 8, 9)
    salsa20_qr(x, 15, 12, 13, 14)
  }
  let out = Array::make(64, b'\x00')
  for i in 0..<16 {
    scrypt_write_u32_le(out, i * 4, x[i] + block[i])
  }
  Bytes::from_array(out[:])
}

///|
/// Salsa20 stream-cipher encrypt/decrypt (symmetric). XORs `data` with the
/// Salsa20 keystream starting at block `counter`. `key` 16/32 bytes, `nonce`
/// 8 bytes.
pub fn salsa20_xor(
  key : Bytes,
  nonce : Bytes,
  counter : Int,
  data : Bytes,
) -> Bytes {
  let out = Array::make(data.length(), b'\x00')
  let mut off = 0
  let mut blk = counter
  while off < data.length() {
    let ks = salsa20_keystream_block(key, nonce, blk)
    let take = if data.length() - off < 64 { data.length() - off } else { 64 }
    for i in 0..<take {
      out[off + i] = (data[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    off = off + take
    blk = blk + 1
  }
  Bytes::from_array(out[:])
}
