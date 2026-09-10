// SM4 block cipher (GB/T 32907-2016): 128-bit block, 128-bit key, 32-round
// unbalanced Feistel structure. Tables are programmatically extracted from
// openssl and verified against the official example vector (sm4_tables.mbt).

///|
fn sm4_tau(a : UInt) -> UInt {
  let s0 = sm4_sbox[((a >> 24) & 0xFFU).reinterpret_as_int()].to_uint()
  let s1 = sm4_sbox[((a >> 16) & 0xFFU).reinterpret_as_int()].to_uint()
  let s2 = sm4_sbox[((a >> 8) & 0xFFU).reinterpret_as_int()].to_uint()
  let s3 = sm4_sbox[(a & 0xFFU).reinterpret_as_int()].to_uint()
  (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
}

///|
fn sm4_rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn sm4_l(b : UInt) -> UInt {
  b ^ sm4_rotl(b, 2) ^ sm4_rotl(b, 10) ^ sm4_rotl(b, 18) ^ sm4_rotl(b, 24)
}

///|
fn sm4_lk(b : UInt) -> UInt {
  b ^ sm4_rotl(b, 13) ^ sm4_rotl(b, 23)
}

///|
/// Expand a 16-byte SM4 key into the 32 round keys.
pub fn sm4_expand_key(key : Bytes) -> Array[UInt] {
  guard key.length() == 16 else {
    abort("sm4_expand_key: key must be 16 bytes")
  }
  let k = Array::make(36, 0U)
  for i in 0..<4 {
    k[i] = (
        (key[i * 4].to_uint() << 24) |
        (key[i * 4 + 1].to_uint() << 16) |
        (key[i * 4 + 2].to_uint() << 8) |
        key[i * 4 + 3].to_uint()
      ) ^
      sm4_fk[i]
  }
  let rk = Array::make(32, 0U)
  for i in 0..<32 {
    let x = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ sm4_ck[i]
    let k4 = k[i] ^ sm4_lk(sm4_tau(x))
    k[i + 4] = k4
    rk[i] = k4
  }
  rk
}

///|
fn sm4_read_block(data : Bytes, off : Int) -> (UInt, UInt, UInt, UInt) {
  (
    (data[off].to_uint() << 24) |
    (data[off + 1].to_uint() << 16) |
    (data[off + 2].to_uint() << 8) |
    data[off + 3].to_uint(),
    (data[off + 4].to_uint() << 24) |
    (data[off + 5].to_uint() << 16) |
    (data[off + 6].to_uint() << 8) |
    data[off + 7].to_uint(),
    (data[off + 8].to_uint() << 24) |
    (data[off + 9].to_uint() << 16) |
    (data[off + 10].to_uint() << 8) |
    data[off + 11].to_uint(),
    (data[off + 12].to_uint() << 24) |
    (data[off + 13].to_uint() << 16) |
    (data[off + 14].to_uint() << 8) |
    data[off + 15].to_uint(),
  )
}

///|
fn sm4_crypt_words(
  rk : Array[UInt],
  x0 : UInt,
  x1 : UInt,
  x2 : UInt,
  x3 : UInt,
) -> (UInt, UInt, UInt, UInt) {
  let x = Array::make(36, 0U)
  x[0] = x0
  x[1] = x1
  x[2] = x2
  x[3] = x3
  for i in 0..<32 {
    x[i + 4] = x[i] ^ sm4_l(sm4_tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
  }
  (x[35], x[34], x[33], x[32])
}

///|
fn sm4_write_words(
  out : Array[Byte],
  a : UInt,
  b : UInt,
  c : UInt,
  d : UInt,
) -> Unit {
  out[0] = ((a >> 24) & 0xFFU).to_byte()
  out[1] = ((a >> 16) & 0xFFU).to_byte()
  out[2] = ((a >> 8) & 0xFFU).to_byte()
  out[3] = (a & 0xFFU).to_byte()
  out[4] = ((b >> 24) & 0xFFU).to_byte()
  out[5] = ((b >> 16) & 0xFFU).to_byte()
  out[6] = ((b >> 8) & 0xFFU).to_byte()
  out[7] = (b & 0xFFU).to_byte()
  out[8] = ((c >> 24) & 0xFFU).to_byte()
  out[9] = ((c >> 16) & 0xFFU).to_byte()
  out[10] = ((c >> 8) & 0xFFU).to_byte()
  out[11] = (c & 0xFFU).to_byte()
  out[12] = ((d >> 24) & 0xFFU).to_byte()
  out[13] = ((d >> 16) & 0xFFU).to_byte()
  out[14] = ((d >> 8) & 0xFFU).to_byte()
  out[15] = (d & 0xFFU).to_byte()
}

///|
/// Encrypt one 16-byte block with pre-expanded round keys.
pub fn sm4_encrypt_block(rk : Array[UInt], data : Bytes, off : Int) -> Bytes {
  let (x0, x1, x2, x3) = sm4_read_block(data, off)
  let (a, b, c, d) = sm4_crypt_words(rk, x0, x1, x2, x3)
  let out = Array::make(16, (0).to_byte())
  sm4_write_words(out, a, b, c, d)
  Bytes::from_array(out[:])
}

///|
/// Decrypt one 16-byte block (same network, reversed round keys).
pub fn sm4_decrypt_block(rk : Array[UInt], data : Bytes, off : Int) -> Bytes {
  let rrk = Array::make(32, 0U)
  for i in 0..<32 {
    rrk[i] = rk[31 - i]
  }
  sm4_encrypt_block(rrk, data, off)
}

///|
/// One-shot single-block encryption with a 16-byte key.
pub fn sm4_encrypt(key : Bytes, block : Bytes) -> Bytes {
  sm4_encrypt_block(sm4_expand_key(key), block, 0)
}

///|
/// One-shot single-block decryption with a 16-byte key.
pub fn sm4_decrypt(key : Bytes, block : Bytes) -> Bytes {
  sm4_decrypt_block(sm4_expand_key(key), block, 0)
}
