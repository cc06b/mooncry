// ============================================================
// RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996).
// Two parallel MD4-style lines (80 steps each) over 64-byte blocks,
// 160-bit state. Widely used in Bitcoin address hashing.
// Verified against the official test vectors from the RIPEMD-160
// paper and differential-tested against hashlib.
// ============================================================

///|
/// RIPEMD-160 initial hash value (same as MD4/SHA-1)
let ripemd160_iv : Array[UInt] = [
  0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U,
]

///|
/// Message-word selection for the left line (80 steps)
let ripemd160_rl : Array[Int] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3,
  12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10,
  14, 1, 3, 8, 11, 6, 15, 13,
]

///|
/// Message-word selection for the right line (80 steps)
let ripemd160_rr : Array[Int] = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10,
  14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7,
  6, 2, 13, 14, 0, 3, 9, 11,
]

///|
/// Rotation amounts for the left line
let ripemd160_sl : Array[Int] = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7,
  15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5,
  12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11,
  6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

///|
/// Rotation amounts for the right line
let ripemd160_sr : Array[Int] = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9,
  11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13,
  7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12,
  5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

///|
/// Round constants for the left line
let ripemd160_kl : Array[UInt] = [
  0x00000000U, 0x5A827999U, 0x6ED9EBA1U, 0x8F1BBCDCU, 0xA953FD4EU,
]

///|
/// Round constants for the right line
let ripemd160_kr : Array[UInt] = [
  0x50A28BE6U, 0x5C4DD124U, 0x6D703EF3U, 0x7A6D76E9U, 0x00000000U,
]

///|
/// Boolean functions f1..f5 selected by the round index
fn ripemd160_f(round : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if round < 16 {
    x ^ y ^ z
  } else if round < 32 {
    (x & y) | ((0xFFFFFFFFU ^ x) & z)
  } else if round < 48 {
    (x | (0xFFFFFFFFU ^ y)) ^ z
  } else if round < 64 {
    (x & z) | (y & (0xFFFFFFFFU ^ z))
  } else {
    x ^ (y | (0xFFFFFFFFU ^ z))
  }
}

///|
/// Read 4 bytes at `offset` as a little-endian UInt
fn ripemd160_read_le(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
/// Compress one 64-byte block (16 little-endian words) into `h`
fn ripemd160_compress(h : Array[UInt], x : Array[UInt]) -> Unit {
  let mut al = h[0]
  let mut bl = h[1]
  let mut cl = h[2]
  let mut dl = h[3]
  let mut el = h[4]
  let mut ar = h[0]
  let mut br = h[1]
  let mut cr = h[2]
  let mut dr = h[3]
  let mut er = h[4]
  for j in 0..<80 {
    // left line: f_j, right line: f_{79-j} (f5..f1 in reverse order)
    let fl = ripemd160_f(j, bl, cl, dl)
    let fr = ripemd160_f(79 - j, br, cr, dr)
    let kl = ripemd160_kl[j / 16]
    let kr = ripemd160_kr[j / 16]
    let t = rotl32(al + fl + x[ripemd160_rl[j]] + kl, ripemd160_sl[j]) + el
    al = el
    el = dl
    dl = rotl32(cl, 10)
    cl = bl
    bl = t
    let t2 = rotl32(ar + fr + x[ripemd160_rr[j]] + kr, ripemd160_sr[j]) + er
    ar = er
    er = dr
    dr = rotl32(cr, 10)
    cr = br
    br = t2
  }
  let t = h[1] + cl + dr
  h[1] = h[2] + dl + er
  h[2] = h[3] + el + ar
  h[3] = h[4] + al + br
  h[4] = h[0] + bl + cr
  h[0] = t
}

///|
/// Compute RIPEMD-160, 20-byte digest
pub fn ripemd160(data : Bytes) -> Bytes {
  let h = Array::make(5, 0U)
  for i in 0..<=4 {
    h[i] = ripemd160_iv[i]
  }
  let len = data.length()
  let mut offset = 0
  // full 64-byte blocks
  while offset + 64 <= len {
    let x = Array::make(16, 0U)
    for i in 0..<=15 {
      x[i] = ripemd160_read_le(data, offset + i * 4)
    }
    ripemd160_compress(h, x)
    offset = offset + 64
  }
  // padding: 0x80, zeros, 64-bit little-endian bit length (MD4-style)
  let rem = len - offset
  let bit_len = len.to_uint64() * 8UL
  let pad_total = if rem < 56 { 64 } else { 128 }
  let padded = Array::make(pad_total, b'\x00')
  for i in 0..<rem {
    padded[i] = data[offset + i]
  }
  padded[rem] = b'\x80'
  let len_off = pad_total - 8
  let mut v = bit_len
  for i in 0..<8 {
    padded[len_off + i] = (v & 0xFFUL).to_byte()
    v = v >> 8
  }
  let padded_bytes = Bytes::from_array(padded[:])
  let num_blocks = pad_total / 64
  for b in 0..<num_blocks {
    let x = Array::make(16, 0U)
    for i in 0..<=15 {
      x[i] = ripemd160_read_le(padded_bytes, b * 64 + i * 4)
    }
    ripemd160_compress(h, x)
  }
  // output: 5 little-endian words
  let out = Array::make(20, b'\x00')
  for i in 0..<=4 {
    let w = h[i]
    out[i * 4] = (w & 0xFFU).to_byte()
    out[i * 4 + 1] = ((w >> 8) & 0xFFU).to_byte()
    out[i * 4 + 2] = ((w >> 16) & 0xFFU).to_byte()
    out[i * 4 + 3] = ((w >> 24) & 0xFFU).to_byte()
  }
  Bytes::from_array(out[:])
}
