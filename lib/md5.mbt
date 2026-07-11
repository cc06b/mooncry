// ==================== MD5 (RFC 1321) ====================

///|
/// MD5 constants — 64 rounds of integer part of 2^32 * abs(sin(i+1))
let md5_t : Array[UInt] = [
  0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU, 0xa8304613U,
  0xfd469501U, 0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U,
  0xa679438eU, 0x49b40821U, 0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU,
  0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U, 0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
  0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU, 0xfffa3942U, 0x8771f681U, 0x6d9d6122U,
  0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U, 0x289b7ec6U, 0xeaa127faU,
  0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U, 0xf4292244U,
  0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
  0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U, 0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU,
  0xeb86d391U,
]

///|
/// MD5 per-round shift amounts
let md5_s : Array[Int] = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
  14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

///|
fn md5_f(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) | ((0xFFFFFFFFU ^ x) & z)
}

///|
fn md5_g(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & z) | (y & (0xFFFFFFFFU ^ z))
}

///|
fn md5_h(x : UInt, y : UInt, z : UInt) -> UInt {
  x ^ y ^ z
}

///|
fn md5_i(x : UInt, y : UInt, z : UInt) -> UInt {
  y ^ (x | (0xFFFFFFFFU ^ z))
}

///|
fn md5_left_rotate(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// Read 32-bit little-endian word from Bytes
fn read_u32_le(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
/// Write 32-bit little-endian word to array
fn write_u32_le(arr : Array[Byte], offset : Int, val : UInt) -> Unit {
  arr[offset] = (val & 0xFFU).to_byte()
  arr[offset + 1] = ((val >> 8) & 0xFFU).to_byte()
  arr[offset + 2] = ((val >> 16) & 0xFFU).to_byte()
  arr[offset + 3] = ((val >> 24) & 0xFFU).to_byte()
}

///|
fn md5_process_block(state : Array[UInt], block : Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  for i in 0..<=63 {
    let mut f : UInt = 0U
    let mut g = 0
    if i <= 15 {
      f = md5_f(b, c, d)
      g = i
    } else if i <= 31 {
      f = md5_g(b, c, d)
      g = (5 * i + 1) % 16
    } else if i <= 47 {
      f = md5_h(b, c, d)
      g = (3 * i + 5) % 16
    } else {
      f = md5_i(b, c, d)
      g = 7 * i % 16
    }
    let temp = d
    d = c
    c = b
    b = b + md5_left_rotate(a + f + md5_t[i] + block[g], md5_s[i])
    a = temp
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
}

///|
/// Compute MD5 (RFC 1321), 16-byte digest. Delegates to the streaming hasher.
pub fn md5(data : Bytes) -> Bytes {
  let hasher = md5_new()
  md5_update(hasher, data)
  md5_finalize(hasher)
}
