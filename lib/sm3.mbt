// SM3 cryptographic hash (GB/T 32905-2016), 256-bit digest, 512-bit blocks.
// Merkle-Damgard with SM3-specific message expansion (W/W') and compression
// (P0/P1 permutations, dual boolean function sets, rotating T constant).
// Validated against the standard's official Appendix A examples.

///|
/// Streaming SM3 hasher. Mirrors the Sha256Hasher layout so the one-shot
/// and incremental paths share a single source of truth.
pub struct Sm3Hasher {
  state : Array[UInt]
  buffer : Array[Byte]
  w : Array[UInt]
  mut buf_len : Int
  mut total_len : UInt64
}

///|
fn sm3_rotl(x : UInt, n : Int) -> UInt {
  if n == 0 {
    x
  } else {
    (x << n) | (x >> (32 - n))
  }
}

///|
fn sm3_p0(x : UInt) -> UInt {
  x ^ sm3_rotl(x, 9) ^ sm3_rotl(x, 17)
}

///|
fn sm3_p1(x : UInt) -> UInt {
  x ^ sm3_rotl(x, 15) ^ sm3_rotl(x, 23)
}

///|
fn sm3_process_block(h : Sm3Hasher, data : Array[Byte], off : Int) -> Unit {
  let w = h.w
  for j in 0..<=15 {
    w[j] = (data[off + j * 4].to_uint() << 24) |
      (data[off + j * 4 + 1].to_uint() << 16) |
      (data[off + j * 4 + 2].to_uint() << 8) |
      data[off + j * 4 + 3].to_uint()
  }
  for j in 16..<=67 {
    let x = w[j - 16] ^ w[j - 9] ^ sm3_rotl(w[j - 3], 15)
    w[j] = sm3_p1(x) ^ sm3_rotl(w[j - 13], 7) ^ w[j - 6]
  }
  let mut a = h.state[0]
  let mut b = h.state[1]
  let mut c = h.state[2]
  let mut d = h.state[3]
  let mut e = h.state[4]
  let mut f = h.state[5]
  let mut g = h.state[6]
  let mut hh = h.state[7]
  let all_ones = 0xFFFFFFFFU
  for j in 0..<=63 {
    let tj = if j < 16 { 0x79cc4519U } else { 0x7a879d8aU }
    let a12 = sm3_rotl(a, 12)
    let ss1 = sm3_rotl(a12 + e + sm3_rotl(tj, j % 32), 7)
    let ss2 = ss1 ^ a12
    let ff = if j < 16 { a ^ b ^ c } else { (a & b) | (a & c) | (b & c) }
    let gg = if j < 16 { e ^ f ^ g } else { (e & f) | ((all_ones ^ e) & g) }
    let tt1 = ff + d + ss2 + (w[j] ^ w[j + 4])
    let tt2 = gg + hh + ss1 + w[j]
    d = c
    c = sm3_rotl(b, 9)
    b = a
    a = tt1
    hh = g
    g = sm3_rotl(f, 19)
    f = e
    e = sm3_p0(tt2)
  }
  h.state[0] = h.state[0] ^ a
  h.state[1] = h.state[1] ^ b
  h.state[2] = h.state[2] ^ c
  h.state[3] = h.state[3] ^ d
  h.state[4] = h.state[4] ^ e
  h.state[5] = h.state[5] ^ f
  h.state[6] = h.state[6] ^ g
  h.state[7] = h.state[7] ^ hh
}

///|
/// Create a new SM3 hasher.
pub fn sm3_new() -> Sm3Hasher {
  let state = Array::make(8, 0U)
  state[0] = 0x7380166FU
  state[1] = 0x4914B2B9U
  state[2] = 0x172442D7U
  state[3] = 0xDA8A0600U
  state[4] = 0xA96F30BCU
  state[5] = 0x163138AAU
  state[6] = 0xE38DEE4DU
  state[7] = 0xB0FB0E4EU
  {
    state,
    buffer: Array::make(64, (0).to_byte()),
    w: Array::make(68, 0U),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the hasher.
pub fn sm3_update(h : Sm3Hasher, data : Bytes) -> Unit {
  h.total_len = h.total_len + data.length().to_uint64()
  let mut i = 0
  let n = data.length()
  if h.buf_len > 0 {
    while i < n && h.buf_len < 64 {
      h.buffer[h.buf_len] = data[i]
      h.buf_len = h.buf_len + 1
      i = i + 1
    }
    if h.buf_len == 64 {
      sm3_process_block(h, h.buffer, 0)
      h.buf_len = 0
    }
  }
  while i + 64 <= n {
    // copy the block into the scratch buffer (process_block reads Array[Byte])
    for j in 0..<64 {
      h.buffer[j] = data[i + j]
    }
    sm3_process_block(h, h.buffer, 0)
    i = i + 64
  }
  while i < n {
    h.buffer[h.buf_len] = data[i]
    h.buf_len = h.buf_len + 1
    i = i + 1
  }
}

///|
/// Finish and return the 32-byte digest. Padding is SHA-2-style: 0x80,
/// zeros, then the 64-bit big-endian bit length.
pub fn sm3_finalize(h : Sm3Hasher) -> Bytes {
  let bit_len = h.total_len * 8UL
  h.buffer[h.buf_len] = (0x80).to_byte()
  h.buf_len = h.buf_len + 1
  if h.buf_len > 56 {
    while h.buf_len < 64 {
      h.buffer[h.buf_len] = (0).to_byte()
      h.buf_len = h.buf_len + 1
    }
    sm3_process_block(h, h.buffer, 0)
    h.buf_len = 0
  }
  while h.buf_len < 56 {
    h.buffer[h.buf_len] = (0).to_byte()
    h.buf_len = h.buf_len + 1
  }
  for i in 0..<8 {
    let shift = (7 - i) * 8
    h.buffer[56 + i] = ((bit_len >> shift) & 0xFFUL).to_byte()
  }
  sm3_process_block(h, h.buffer, 0)
  let out = Array::make(32, (0).to_byte())
  for i in 0..<=7 {
    let v = h.state[i]
    out[i * 4] = ((v >> 24) & 0xFFU).to_byte()
    out[i * 4 + 1] = ((v >> 16) & 0xFFU).to_byte()
    out[i * 4 + 2] = ((v >> 8) & 0xFFU).to_byte()
    out[i * 4 + 3] = (v & 0xFFU).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// One-shot SM3 digest (32 bytes).
pub fn sm3(data : Bytes) -> Bytes {
  let h = sm3_new()
  sm3_update(h, data)
  sm3_finalize(h)
}
