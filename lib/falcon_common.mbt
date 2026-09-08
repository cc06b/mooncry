// Falcon M1 foundation: inner SHAKE stream, hash_to_point, and the
// polynomial codecs. Faithful port of PQClean falcon-512/1024 `clean`
// (common.c hash_to_point + codec.c). Verified byte-exact against dumps
// from the official C implementation (see falcon_m1_test.mbt).

///|
/// Internal SHAKE256 stream: absorb once, then squeeze incrementally.
/// Mirrors inner_shake256_{init,inject,flip,extract}.
pub struct FalconXof {
  h : Sha3Hasher
  mut flipped : Bool
  mut lane : Int
  mut bi : Int
}

///|
/// Start a fresh XOF (nothing absorbed yet).
pub fn falcon_xof_init() -> FalconXof {
  { h: shake_256_new(), flipped: false, lane: 0, bi: 0, }
}

///|
/// Absorb `data` (inject). Only valid before the first extract.
pub fn falcon_xof_inject(x : FalconXof, data : Bytes) -> Unit {
  sha3_update(x.h, data)
}

///|
/// Finalize absorption (flip) and extract the next `len` stream bytes.
/// Subsequent extracts continue the same stream (lane cursor advances;
/// the shared sha3_squeeze restarts from lane 0 and cannot be reused).
pub fn falcon_xof_extract(x : FalconXof, len : Int) -> Bytes {
  if not_flipped(x) {
    ignore(shake_finalize(x.h, 0))
    x.flipped = true
  }
  let out = Array::make(len, (0).to_byte())
  let mut off = 0
  while off < len {
    if x.lane >= x.h.rate / 8 {
      keccak_f(x.h.state)
      x.lane = 0
      x.bi = 0
    }
    let lane = x.h.state[x.lane]
    out[off] = ((lane >> (x.bi * 8)) & 0xFFUL).to_byte()
    off = off + 1
    x.bi = x.bi + 1
    if x.bi == 8 {
      x.lane = x.lane + 1
      x.bi = 0
    }
  }
  Bytes::from_array(out)
}

///|
fn not_flipped(x : FalconXof) -> Bool {
  x.flipped == false
}

///|
/// hash_to_point: SHAKE256(nonce || msg) -> n field elements mod 12289.
/// Rejection sampling on 16-bit big-endian draws (< 61445 = 5*12289).
/// vartime logic; output identical to the ct variant (checked in tests).
pub fn falcon_hash_to_point(
  nonce : Bytes,
  msg : Bytes,
  logn : Int,
) -> Array[Int] {
  let x = falcon_xof_init()
  falcon_xof_inject(x, nonce)
  falcon_xof_inject(x, msg)
  let n = 1 << logn
  let out = Array::make(n, 0)
  let mut filled = 0
  while filled < n {
    let b = falcon_xof_extract(x, 2)
    let w = (b[0].to_int() << 8) | b[1].to_int()
    if w < 61445 {
      let mut v = w
      while v >= 12289 {
        v = v - 12289
      }
      out[filled] = v
      filled = filled + 1
    }
  }
  out
}

// ---------------------------------------------------------------------------
// Codecs (codec.c). Encode failures return empty Bytes; decode failures
// return an empty array (length mismatch signals invalid input).
// ---------------------------------------------------------------------------

///|
/// Pack n 14-bit values MSB-first (modq_encode). x[u] must be < 12289.
pub fn falcon_modq_encode(x : Array[Int], logn : Int) -> Bytes {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    if x[u] < 0 || x[u] >= 12289 {
      return b""
    }
  }
  let out_len = (n * 14 + 7) / 8
  let buf = Array::make(out_len, (0).to_byte())
  let mut acc = 0
  let mut acc_len = 0
  let mut v = 0
  for u = 0; u < n; u = u + 1 {
    acc = (acc << 14) | x[u]
    acc_len = acc_len + 14
    while acc_len >= 8 {
      acc_len = acc_len - 8
      buf[v] = ((acc >> acc_len) & 0xFF).to_byte()
      v = v + 1
    }
  }
  if acc_len > 0 {
    buf[v] = ((acc << (8 - acc_len)) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
/// Unpack modq_encode output. Invalid encoding -> empty array.
pub fn falcon_modq_decode(b : Bytes, logn : Int) -> Array[Int] {
  let n = 1 << logn
  let in_len = (n * 14 + 7) / 8
  if b.length() != in_len {
    return []
  }
  let x = Array::make(n, 0)
  let mut acc = 0
  let mut acc_len = 0
  let mut u = 0
  let mut v = 0
  while u < n {
    acc = ((acc << 8) | b[v].to_int()) & 0x3FFFFF
    v = v + 1
    acc_len = acc_len + 8
    while acc_len >= 14 && u < n {
      acc_len = acc_len - 14
      let w = (acc >> acc_len) & 0x3FFF
      if w >= 12289 {
        return []
      }
      x[u] = w
      u = u + 1
    }
  }
  if (acc & ((1 << acc_len) - 1)) != 0 {
    return []
  }
  x
}

///|
/// Pack n signed values in ±((1<<(bits-1))-1) MSB-first
/// (trim_i8_encode / trim_i16_encode share this logic).
pub fn falcon_trim_encode(x : Array[Int], logn : Int, bits : Int) -> Bytes {
  let n = 1 << logn
  let maxv = (1 << (bits - 1)) - 1
  let minv = 0 - maxv
  for u = 0; u < n; u = u + 1 {
    if x[u] < minv || x[u] > maxv {
      return b""
    }
  }
  let out_len = (n * bits + 7) / 8
  let buf = Array::make(out_len, (0).to_byte())
  let mask = (1 << bits) - 1
  let mut acc = 0
  let mut acc_len = 0
  let mut v = 0
  for u = 0; u < n; u = u + 1 {
    acc = (acc << bits) | (x[u] & mask)
    acc = acc & 0xFFFFFF
    acc_len = acc_len + bits
    while acc_len >= 8 {
      acc_len = acc_len - 8
      buf[v] = ((acc >> acc_len) & 0xFF).to_byte()
      v = v + 1
    }
  }
  if acc_len > 0 {
    buf[v] = ((acc << (8 - acc_len)) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
/// Unpack trim_encode output with sign extension. The -2^(bits-1)
/// pattern is forbidden; trailing extra bits must be zero.
pub fn falcon_trim_decode(b : Bytes, logn : Int, bits : Int) -> Array[Int] {
  let n = 1 << logn
  let in_len = (n * bits + 7) / 8
  if b.length() != in_len {
    return []
  }
  let x = Array::make(n, 0)
  let mask1 = (1 << bits) - 1
  let mask2 = 1 << (bits - 1)
  let mut acc = 0
  let mut acc_len = 0
  let mut u = 0
  let mut v = 0
  while u < n {
    acc = ((acc << 8) | b[v].to_int()) & 0xFFFFFF
    v = v + 1
    acc_len = acc_len + 8
    while acc_len >= bits && u < n {
      acc_len = acc_len - bits
      let mut w = (acc >> acc_len) & mask1
      if w == mask2 {
        return []
      }
      if (w & mask2) != 0 {
        w = w - (mask1 + 1)
      }
      x[u] = w
      u = u + 1
    }
  }
  if (acc & ((1 << acc_len) - 1)) != 0 {
    return []
  }
  x
}

///|
/// comp_encode: variable-length signed encoding of sig values in
/// ±2047. Per value: sign bit, low 7 bits of |x|, then w zero bits and
/// a terminating one, where w = |x| >> 7.
pub fn falcon_comp_encode(x : Array[Int], logn : Int) -> Bytes {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    if x[u] < -2047 || x[u] > 2047 {
      return b""
    }
  }
  let buf : Array[Byte] = []
  let mut acc = 0
  let mut acc_len = 0
  for u = 0; u < n; u = u + 1 {
    let mut t = x[u]
    acc = acc << 1
    if t < 0 {
      t = 0 - t
      acc = acc | 1
    }
    let mut w = t
    acc = (acc << 7) | (w & 127)
    w = w >> 7
    acc_len = acc_len + 8
    acc = (acc << (w + 1)) | 1
    acc = acc & 0x7FFFFFFF
    acc_len = acc_len + w + 1
    while acc_len >= 8 {
      acc_len = acc_len - 8
      buf.push(((acc >> acc_len) & 0xFF).to_byte())
    }
  }
  if acc_len > 0 {
    buf.push(((acc << (8 - acc_len)) & 0xFF).to_byte())
  }
  Bytes::from_array(buf)
}

///|
/// comp_decode: inverse of comp_encode. Rejects "-0", m > 2047 and
/// nonzero trailing bits; returns empty array on any malformed input.
pub fn falcon_comp_decode(b : Bytes, logn : Int) -> Array[Int] {
  let n = 1 << logn
  let len = b.length()
  let x = Array::make(n, 0)
  let mut acc = 0
  let mut acc_len = 0
  let mut v = 0
  for u = 0; u < n; u = u + 1 {
    if v >= len {
      return []
    }
    acc = ((acc << 8) | b[v].to_int()) & 0x7FFFFF
    v = v + 1
    let bb = (acc >> acc_len) & 0xFF
    let s = bb & 128
    let mut m = bb & 127
    let mut done = false
    while done == false {
      if acc_len == 0 {
        if v >= len {
          return []
        }
        acc = ((acc << 8) | b[v].to_int()) & 0x7FFFFF
        v = v + 1
        acc_len = 8
      }
      acc_len = acc_len - 1
      if ((acc >> acc_len) & 1) != 0 {
        done = true
      } else {
        m = m + 128
        if m > 2047 {
          return []
        }
      }
    }
    if s != 0 && m == 0 {
      return []
    }
    x[u] = if s != 0 { 0 - m } else { m }
  }
  if (acc & ((1 << acc_len) - 1)) != 0 {
    return []
  }
  x
}
