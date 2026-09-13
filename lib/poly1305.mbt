// ============================================================
// Poly1305 one-time MAC (RFC 8439).
// v0.18.1 perf: rewritten from BigInt to 5-limb radix-2^26
// arithmetic ("donna" style) with UInt64 partial products. The
// BigInt version spent 128-bit mulmod per 16-byte block; the limb
// version does 25 small multiplies + shifts per block.
// ============================================================

///|
/// Read 8 bytes at `offset` as a little-endian UInt64
fn p1305_read_u64_le(data : Array[Byte], offset : Int) -> UInt64 {
  data[offset].to_uint64() |
  (data[offset + 1].to_uint64() << 8) |
  (data[offset + 2].to_uint64() << 16) |
  (data[offset + 3].to_uint64() << 24) |
  (data[offset + 4].to_uint64() << 32) |
  (data[offset + 5].to_uint64() << 40) |
  (data[offset + 6].to_uint64() << 48) |
  (data[offset + 7].to_uint64() << 56)
}

///|
/// Poly1305 one-shot MAC. `key` must be 32 bytes; returns a 16-byte
/// tag. Accumulator h is kept as 5 limbs of at most 26 bits each
/// (partially reduced); r is clamped per RFC 8439 §2.5.1.
pub struct Poly1305State {
  r0 : UInt64
  r1 : UInt64
  r2 : UInt64
  r3 : UInt64
  r4 : UInt64
  s1 : UInt64
  s2 : UInt64
  s3 : UInt64
  s4 : UInt64
  mut h0 : UInt64
  mut h1 : UInt64
  mut h2 : UInt64
  mut h3 : UInt64
  mut h4 : UInt64
  buffer : Array[Byte] // 17-byte scratch; index 16 carries the 2^128 pad bit
  key_tail : Bytes // key[16..32] (the "s" of the final addition)
  mut buf_len : Int
}

///|
/// Start an incremental Poly1305 computation (RFC 8439). `key` must be
/// 32 bytes. Feed data with `poly1305_update`, finish with
/// `poly1305_finalize`. v0.33.0.
pub fn poly1305_new(key : Bytes) -> Poly1305State {
  if key.length() != 32 {
    abort("poly1305_new: key must be 32 bytes")
  }
  let mask26 = 0x3ffffffUL
  let rb = Array::make(17, b'\x00')
  for i in 0..<16 {
    rb[i] = key[i]
  }
  rb[3] = rb[3] & 0x0f
  rb[7] = rb[7] & 0x0f
  rb[11] = rb[11] & 0x0f
  rb[15] = rb[15] & 0x0f
  rb[4] = rb[4] & 0xfc
  rb[8] = rb[8] & 0xfc
  rb[12] = rb[12] & 0xfc
  let rlo = p1305_read_u64_le(rb, 0)
  let rhi = p1305_read_u64_le(rb, 8)
  let r0 = rlo & mask26
  let r1 = (rlo >> 26) & mask26
  let r2 = (rlo >> 52) | ((rhi & 0x3fffUL) << 12)
  let r3 = (rhi >> 14) & mask26
  let r4 = (rhi >> 40) & mask26
  Poly1305State::{
    r0,
    r1,
    r2,
    r3,
    r4,
    s1: r1 * 5UL,
    s2: r2 * 5UL,
    s3: r3 * 5UL,
    s4: r4 * 5UL,
    h0: 0UL,
    h1: 0UL,
    h2: 0UL,
    h3: 0UL,
    h4: 0UL,
    buffer: Array::make(17, b'\x00'),
    key_tail: bytes_sub(key, 16, 16),
    buf_len: 0,
  }
}

///|
/// Absorb one 16-byte block from `st.buffer` (index 16 = pad bit).
fn poly1305_absorb(st : Poly1305State) -> Unit {
  let mask26 = 0x3ffffffUL
  let pb = st.buffer
  let lo = p1305_read_u64_le(pb, 0)
  let hi = p1305_read_u64_le(pb, 8)
  let mut h0 = st.h0 + (lo & mask26)
  let mut h1 = st.h1 + ((lo >> 26) & mask26)
  let mut h2 = st.h2 + ((lo >> 52) | ((hi & 0x3fffUL) << 12))
  let mut h3 = st.h3 + ((hi >> 14) & mask26)
  let mut h4 = st.h4 + ((hi >> 40) | (pb[16].to_uint64() << 24))
  let r0 = st.r0
  let r1 = st.r1
  let r2 = st.r2
  let r3 = st.r3
  let r4 = st.r4
  let d0 = h0 * r0 + h1 * st.s4 + h2 * st.s3 + h3 * st.s2 + h4 * st.s1
  let d1 = h0 * r1 + h1 * r0 + h2 * st.s4 + h3 * st.s3 + h4 * st.s2
  let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * st.s4 + h4 * st.s3
  let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * st.s4
  let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0
  let mut c = d0 >> 26
  h0 = d0 & mask26
  let d1c = d1 + c
  c = d1c >> 26
  h1 = d1c & mask26
  let d2c = d2 + c
  c = d2c >> 26
  h2 = d2c & mask26
  let d3c = d3 + c
  c = d3c >> 26
  h3 = d3c & mask26
  let d4c = d4 + c
  c = d4c >> 26
  h4 = d4c & mask26
  h0 = h0 + c * 5UL
  c = h0 >> 26
  h0 = h0 & mask26
  h1 = h1 + c
  st.h0 = h0
  st.h1 = h1
  st.h2 = h2
  st.h3 = h3
  st.h4 = h4
}

///|
/// Feed more bytes into an incremental Poly1305 state.
pub fn poly1305_update(st : Poly1305State, data : Bytes) -> Unit {
  let mut off = 0
  let len = data.length()
  while off < len {
    let take = if 16 - st.buf_len < len - off {
      16 - st.buf_len
    } else {
      len - off
    }
    for i in 0..<take {
      st.buffer[st.buf_len + i] = data[off + i]
    }
    st.buf_len = st.buf_len + take
    off = off + take
    if st.buf_len == 16 {
      st.buffer[16] = b'\x01'
      poly1305_absorb(st)
      st.buf_len = 0
    }
  }
}

///|
/// Finalize an incremental Poly1305 state and return the 16-byte tag.
pub fn poly1305_finalize(st : Poly1305State) -> Bytes {
  if st.buf_len > 0 {
    for i in (st.buf_len + 1)..<17 {
      st.buffer[i] = b'\x00'
    }
    st.buffer[st.buf_len] = b'\x01'
    poly1305_absorb(st)
    st.buf_len = 0
  }
  let mut h0 = st.h0
  let mut h1 = st.h1
  let mut h2 = st.h2
  let mut h3 = st.h3
  let mut h4 = st.h4
  // Final full carry chain
  let mut c = h1 >> 26
  h1 = h1 & 0x3ffffffUL
  h2 = h2 + c
  c = h2 >> 26
  h2 = h2 & 0x3ffffffUL
  h3 = h3 + c
  c = h3 >> 26
  h3 = h3 & 0x3ffffffUL
  h4 = h4 + c
  c = h4 >> 26
  h4 = h4 & 0x3ffffffUL
  h0 = h0 + c * 5UL
  c = h0 >> 26
  h0 = h0 & 0x3ffffffUL
  h1 = h1 + c
  // g = h + 5; if g >= 2^130 (i.e. h >= p) then use g - 2^130 (= h - p)
  let g0 = h0 + 5UL
  c = g0 >> 26
  let g0m = g0 & 0x3ffffffUL
  let g1 = h1 + c
  c = g1 >> 26
  let g1m = g1 & 0x3ffffffUL
  let g2 = h2 + c
  c = g2 >> 26
  let g2m = g2 & 0x3ffffffUL
  let g3 = h3 + c
  c = g3 >> 26
  let g3m = g3 & 0x3ffffffUL
  let g4c = h4 + c - 0x4000000UL // wraps huge when h < p
  let neg = g4c >> 63 // 1 when h < p
  let sel = neg - 1UL // all-ones when h >= p
  let inv = 0xFFFFFFFFFFFFFFFFUL ^ sel
  h0 = (h0 & inv) | (g0m & sel)
  h1 = (h1 & inv) | (g1m & sel)
  h2 = (h2 & inv) | (g2m & sel)
  h3 = (h3 & inv) | (g3m & sel)
  h4 = (h4 & inv) | (g4c & sel)
  // Reassemble into four 32-bit words (h is now < p < 2^130).
  let f0 = (h0 | (h1 << 26)) & 0xFFFFFFFFUL
  let f1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFFUL
  let f2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFFUL
  let f3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFFUL
  let key = st.key_tail
  let s0 = read_u32_le(key, 0).to_uint64()
  let s1w = read_u32_le(key, 4).to_uint64()
  let s2w = read_u32_le(key, 8).to_uint64()
  let s3w = read_u32_le(key, 12).to_uint64()
  let mut t = f0 + s0
  let w0 = t & 0xFFFFFFFFUL
  t = f1 + s1w + (t >> 32)
  let w1 = t & 0xFFFFFFFFUL
  t = f2 + s2w + (t >> 32)
  let w2 = t & 0xFFFFFFFFUL
  t = f3 + s3w + (t >> 32)
  let w3 = t & 0xFFFFFFFFUL
  let out = Array::make(16, b'\x00')
  let words = [w0, w1, w2, w3]
  for i in 0..<4 {
    let w = words[i]
    out[i * 4] = (w & 0xFFUL).to_byte()
    out[i * 4 + 1] = ((w >> 8) & 0xFFUL).to_byte()
    out[i * 4 + 2] = ((w >> 16) & 0xFFUL).to_byte()
    out[i * 4 + 3] = ((w >> 24) & 0xFFUL).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// Poly1305 one-shot MAC. `key` must be 32 bytes; returns a 16-byte
/// tag. Implemented over the incremental core (v0.33.0).
pub fn poly1305(key : Bytes, msg : Bytes) -> Bytes {
  let st = poly1305_new(key)
  poly1305_update(st, msg)
  poly1305_finalize(st)
}
