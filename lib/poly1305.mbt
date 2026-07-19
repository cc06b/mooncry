///|
/// Poly1305 MAC (RFC 8439 §2.5). key: 32 bytes (r||s). Output: 16-byte tag.
/// Uses core bigint for the 130-bit modular arithmetic (mod 2^130 - 5).

///|
/// Read `len` bytes at `off` as a little-endian BigInt.
fn bigint_from_le(data : Bytes, off : Int, len : Int) -> BigInt {
  let mut result = @bigint.BigInt::from_int64(0L)
  let mut m = @bigint.BigInt::from_int64(1L)
  let b256 = @bigint.BigInt::from_int64(256L)
  for i in 0..<len {
    result = result +
      m * @bigint.BigInt::from_int64(data[off + i].to_int().to_int64())
    m = m * b256
  }
  result
}

///|
/// Write BigInt `n` as `len` little-endian bytes (mod 2^(8*len)).
fn bigint_to_le_bytes(n : BigInt, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  let mut x = n
  let b256 = @bigint.BigInt::from_int64(256L)
  for i in 0..<len {
    out[i] = (x % b256).to_int().to_byte()
    x = x / b256
  }
  Bytes::from_array(out[:])
}

///|
/// Poly1305 one-shot MAC. `key` must be 32 bytes; returns a 16-byte tag.
pub fn poly1305(key : Bytes, msg : Bytes) -> Bytes {
  if key.length() != 32 {
    abort("poly1305: key must be 32 bytes")
  }
  // Clamp r = key[0..16]: clear high 4 bits of bytes 3/7/11/15, low 2 bits of 4/8/12.
  let r_bytes = Array::make(16, b'\x00')
  for i in 0..<16 {
    r_bytes[i] = key[i]
  }
  r_bytes[3] = r_bytes[3] & 0x0f
  r_bytes[7] = r_bytes[7] & 0x0f
  r_bytes[11] = r_bytes[11] & 0x0f
  r_bytes[15] = r_bytes[15] & 0x0f
  r_bytes[4] = r_bytes[4] & 0xfc
  r_bytes[8] = r_bytes[8] & 0xfc
  r_bytes[12] = r_bytes[12] & 0xfc
  let r = bigint_from_le(Bytes::from_array(r_bytes[:]), 0, 16)
  let s = bigint_from_le(key, 16, 16)
  // p = 2^130 - 5
  let p = @bigint.BigInt::from_string(
    "1361129467683753853853498429727072845819",
  )
  let two128 = @bigint.BigInt::from_string(
    "340282366920938463463374607431768211456",
  )
  let mut acc = @bigint.BigInt::from_int64(0L)
  let b256 = @bigint.BigInt::from_int64(256L)
  let mut off = 0
  let len = msg.length()
  while off < len {
    let bl = if off + 16 <= len { 16 } else { len - off }
    let block_big = bigint_from_le(msg, off, bl)
    // high bit: 2^(8*bl) = 1 * 256^bl
    let mut h = @bigint.BigInt::from_int64(1L)
    for _ in 0..<bl {
      h = h * b256
    }
    let n = block_big + h
    acc = (acc + n) * r % p
    off = off + bl
  }
  let tag = (acc + s) % two128
  bigint_to_le_bytes(tag, 16)
}
