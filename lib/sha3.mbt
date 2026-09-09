// ============================================================
// SHA-3 / Keccak (FIPS 202). Keccak-f[1600] permutation + sponge.
// Implements SHA3-224/256/384/512. Explicit theta/rho/pi/chi/iota.
// State is a flat 25-lane Array[UInt64] (lane index = x + 5*y) —
// v0.18.0 perf: flattened from 5x5 nested arrays to avoid the inner
// array indirection in the hot permutation loop.
// ============================================================

///|
/// Round constants for the 24 rounds of Keccak-f[1600]
let keccak_rndc : Array[UInt64] = [
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
  0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
  0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
]

///|
/// Rotation offsets r[x][y] (FIPS 202 Table 2)
let keccak_rho : Array[Array[Int]] = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

///|
/// Rotate a 64-bit value left by n (1 <= n <= 63)
fn rotl64(x : UInt64, n : Int) -> UInt64 {
  (x << n) | (x >> (64 - n))
}

///|
/// Flat lane-index tables (idx = x + 5*y): precomputed rotation
/// amounts, pi destinations and chi neighbour indices — removes the
/// nested-array dereference and per-round mod-5 arithmetic from
/// keccak_f (v0.45.0 perf).
let keccak_rho_flat : Array[Int] = {
  let t = Array::make(25, 0)
  for x in 0..<5 {
    for y in 0..<5 {
      t[x + 5 * y] = keccak_rho[x][y]
    }
  }
  t
}

///|
let keccak_pi_dst : Array[Int] = {
  let t = Array::make(25, 0)
  for x in 0..<5 {
    for y in 0..<5 {
      t[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5)
    }
  }
  t
}

///|
let keccak_chi_l : Array[Int] = {
  let t = Array::make(25, 0)
  for x in 0..<5 {
    for y in 0..<5 {
      t[x + 5 * y] = (x + 1) % 5 + 5 * y
    }
  }
  t
}

///|
let keccak_chi_r : Array[Int] = {
  let t = Array::make(25, 0)
  for x in 0..<5 {
    for y in 0..<5 {
      t[x + 5 * y] = (x + 2) % 5 + 5 * y
    }
  }
  t
}

///|
fn read_lane_le_bytes(buf : Bytes, off : Int) -> UInt64 {
  buf[off].to_uint64() |
  (buf[off + 1].to_uint64() << 8) |
  (buf[off + 2].to_uint64() << 16) |
  (buf[off + 3].to_uint64() << 24) |
  (buf[off + 4].to_uint64() << 32) |
  (buf[off + 5].to_uint64() << 40) |
  (buf[off + 6].to_uint64() << 48) |
  (buf[off + 7].to_uint64() << 56)
}

///|
/// Read 8 bytes from an array at offset as a little-endian UInt64
fn read_lane_le(buf : Array[Byte], off : Int) -> UInt64 {
  buf[off].to_uint64() |
  (buf[off + 1].to_uint64() << 8) |
  (buf[off + 2].to_uint64() << 16) |
  (buf[off + 3].to_uint64() << 24) |
  (buf[off + 4].to_uint64() << 32) |
  (buf[off + 5].to_uint64() << 40) |
  (buf[off + 6].to_uint64() << 48) |
  (buf[off + 7].to_uint64() << 56)
}

///|
/// Build a fresh flat 25-lane Keccak state (lane index = x + 5*y)
fn new_state() -> Array[UInt64] {
  Array::make(25, 0UL)
}

///|
/// Keccak-f[1600] permutation on a flat 25-lane state in place
fn keccak_f(st : Array[UInt64]) -> Unit {
  keccak_f_fast(st)
}

///|
/// Keccak-p[1600]: rounds `start`..23 of Keccak-f. TurboSHAKE (RFC 9861)
/// uses start = 12 (the last 12 rounds). v0.36.0.
fn keccak_f_from(st : Array[UInt64], start : Int) -> Unit {
  if start == 0 {
    keccak_f_fast(st)
    return
  }
  let c = Array::make(5, 0UL)
  let d = Array::make(5, 0UL)
  let b = Array::make(25, 0UL)
  for round in start..<24 {
    // Theta
    for x in 0..<5 {
      c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
    }
    for x in 0..<5 {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1)
    }
    for x in 0..<5 {
      for y in 0..<5 {
        st[x + 5 * y] = st[x + 5 * y] ^ d[x]
      }
    }
    // Rho and Pi (flat tables, v0.45.0)
    for idx in 0..<25 {
      b[keccak_pi_dst[idx]] = rotl64(st[idx], keccak_rho_flat[idx])
    }
    // Chi (flat tables, v0.45.0)
    for idx in 0..<25 {
      st[idx] = b[idx] ^
        ((0xFFFFFFFFFFFFFFFFUL ^ b[keccak_chi_l[idx]]) & b[keccak_chi_r[idx]])
    }
    // Iota
    st[0] = st[0] ^ keccak_rndc[round]
  }
}

///|
/// SHA-3 sponge: absorb `data` (domain 0x06), squeeze `out_len` bytes.
fn sha3_sponge(rate_bytes : Int, data : Bytes, out_len : Int) -> Bytes {
  let st = new_state()
  let data_len = data.length()
  let lanes_per_block = rate_bytes / 8
  // absorb full blocks directly from the input (no full copy, v0.45.0)
  let full_blocks = data_len / rate_bytes
  for blk in 0..<full_blocks {
    let off = blk * rate_bytes
    for i in 0..<lanes_per_block {
      st[i] = st[i] ^ read_lane_le_bytes(data, off + i * 8)
    }
    keccak_f(st)
  }
  // final block: remaining bytes + pad10*1 (0x06 domain, 0x80 terminator)
  let rem = data_len - full_blocks * rate_bytes
  let tail = Array::make(rate_bytes, b'\x00')
  for i in 0..<rem {
    tail[i] = data[full_blocks * rate_bytes + i]
  }
  tail[rem] = (tail[rem].to_int() ^ 0x06).to_byte()
  tail[rate_bytes - 1] = (tail[rate_bytes - 1].to_int() ^ 0x80).to_byte()
  for i in 0..<lanes_per_block {
    st[i] = st[i] ^ read_lane_le(tail, i * 8)
  }
  keccak_f(st)
  // squeeze: output lanes 0,1,2,... little-endian, re-permuting after
  // every rate/8 lanes (only rate bytes may be read per round)
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < out_len {
    let lane = st[lane_idx]
    for bi in 0..<8 {
      if out_off >= out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= rate_bytes / 8 && out_off < out_len {
      keccak_f(st)
      lane_idx = 0
    }
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHA3-224 (FIPS 202), 28-byte digest
pub fn sha3_224(data : Bytes) -> Bytes {
  sha3_sponge(144, data, 28)
}

///|
/// Compute SHA3-256 (FIPS 202), 32-byte digest
pub fn sha3_256(data : Bytes) -> Bytes {
  sha3_sponge(136, data, 32)
}

///|
/// Compute SHA3-384 (FIPS 202), 48-byte digest
pub fn sha3_384(data : Bytes) -> Bytes {
  sha3_sponge(104, data, 48)
}

///|
/// Compute SHA3-512 (FIPS 202), 64-byte digest
pub fn sha3_512(data : Bytes) -> Bytes {
  sha3_sponge(72, data, 64)
}

// ==================== SHAKE (FIPS 202 XOF) ====================
// Like SHA-3 sponge but domain suffix 0x1F and variable output length.

///|
/// SHAKE sponge: domain 0x1F, squeeze `out_len` bytes.
fn shake_sponge(rate_bytes : Int, data : Bytes, out_len : Int) -> Bytes {
  let st = new_state()
  let data_len = data.length()
  let num_blocks = data_len / rate_bytes + 1
  let buf_len = num_blocks * rate_bytes
  let buf = Array::make(buf_len, b'\x00')
  for i in 0..<data_len {
    buf[i] = data[i]
  }
  buf[data_len] = (buf[data_len].to_int() ^ 0x1F).to_byte()
  buf[buf_len - 1] = (buf[buf_len - 1].to_int() ^ 0x80).to_byte()
  let lanes_per_block = rate_bytes / 8
  let mut off = 0
  while off < buf_len {
    for i in 0..<lanes_per_block {
      st[i] = st[i] ^ read_lane_le(buf, off + i * 8)
    }
    keccak_f(st)
    off = off + rate_bytes
  }
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < out_len {
    let lane = st[lane_idx]
    for bi in 0..<8 {
      if out_off >= out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= rate_bytes / 8 && out_off < out_len {
      keccak_f(st)
      lane_idx = 0
    }
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHAKE128 (FIPS 202), variable-length output
pub fn shake_128(data : Bytes, out_len : Int) -> Bytes {
  shake_sponge(168, data, out_len)
}

///|
/// Compute SHAKE256 (FIPS 202), variable-length output
pub fn shake_256(data : Bytes, out_len : Int) -> Bytes {
  shake_sponge(136, data, out_len)
}

///|
/// Fully unrolled Keccak-f[1600]: 25 local lanes, constant rotations,
/// no inner-loop array traffic / modulo / table reads. Generated from
/// the same repo formulas as the flat tables (never hand-typed).
fn keccak_f_fast(st : Array[UInt64]) -> Unit {
  let mut v00 = st[0]
  let mut v05 = st[5]
  let mut v10 = st[10]
  let mut v15 = st[15]
  let mut v20 = st[20]
  let mut v01 = st[1]
  let mut v06 = st[6]
  let mut v11 = st[11]
  let mut v16 = st[16]
  let mut v21 = st[21]
  let mut v02 = st[2]
  let mut v07 = st[7]
  let mut v12 = st[12]
  let mut v17 = st[17]
  let mut v22 = st[22]
  let mut v03 = st[3]
  let mut v08 = st[8]
  let mut v13 = st[13]
  let mut v18 = st[18]
  let mut v23 = st[23]
  let mut v04 = st[4]
  let mut v09 = st[9]
  let mut v14 = st[14]
  let mut v19 = st[19]
  let mut v24 = st[24]
  for round = 0; round < 24; round = round + 1 {
    let c0 = v00 ^ v05 ^ v10 ^ v15 ^ v20
    let c1 = v01 ^ v06 ^ v11 ^ v16 ^ v21
    let c2 = v02 ^ v07 ^ v12 ^ v17 ^ v22
    let c3 = v03 ^ v08 ^ v13 ^ v18 ^ v23
    let c4 = v04 ^ v09 ^ v14 ^ v19 ^ v24
    let d0 = c4 ^ ((c1 << 1) | (c1 >> 63))
    let d1 = c0 ^ ((c2 << 1) | (c2 >> 63))
    let d2 = c1 ^ ((c3 << 1) | (c3 >> 63))
    let d3 = c2 ^ ((c4 << 1) | (c4 >> 63))
    let d4 = c3 ^ ((c0 << 1) | (c0 >> 63))
    v00 = v00 ^ d0
    v05 = v05 ^ d0
    v10 = v10 ^ d0
    v15 = v15 ^ d0
    v20 = v20 ^ d0
    v01 = v01 ^ d1
    v06 = v06 ^ d1
    v11 = v11 ^ d1
    v16 = v16 ^ d1
    v21 = v21 ^ d1
    v02 = v02 ^ d2
    v07 = v07 ^ d2
    v12 = v12 ^ d2
    v17 = v17 ^ d2
    v22 = v22 ^ d2
    v03 = v03 ^ d3
    v08 = v08 ^ d3
    v13 = v13 ^ d3
    v18 = v18 ^ d3
    v23 = v23 ^ d3
    v04 = v04 ^ d4
    v09 = v09 ^ d4
    v14 = v14 ^ d4
    v19 = v19 ^ d4
    v24 = v24 ^ d4
    let b00 = v00
    let b01 = (v06 << 44) | (v06 >> 20)
    let b02 = (v12 << 43) | (v12 >> 21)
    let b03 = (v18 << 21) | (v18 >> 43)
    let b04 = (v24 << 14) | (v24 >> 50)
    let b05 = (v03 << 28) | (v03 >> 36)
    let b06 = (v09 << 20) | (v09 >> 44)
    let b07 = (v10 << 3) | (v10 >> 61)
    let b08 = (v16 << 45) | (v16 >> 19)
    let b09 = (v22 << 61) | (v22 >> 3)
    let b10 = (v01 << 1) | (v01 >> 63)
    let b11 = (v07 << 6) | (v07 >> 58)
    let b12 = (v13 << 25) | (v13 >> 39)
    let b13 = (v19 << 8) | (v19 >> 56)
    let b14 = (v20 << 18) | (v20 >> 46)
    let b15 = (v04 << 27) | (v04 >> 37)
    let b16 = (v05 << 36) | (v05 >> 28)
    let b17 = (v11 << 10) | (v11 >> 54)
    let b18 = (v17 << 15) | (v17 >> 49)
    let b19 = (v23 << 56) | (v23 >> 8)
    let b20 = (v02 << 62) | (v02 >> 2)
    let b21 = (v08 << 55) | (v08 >> 9)
    let b22 = (v14 << 39) | (v14 >> 25)
    let b23 = (v15 << 41) | (v15 >> 23)
    let b24 = (v21 << 2) | (v21 >> 62)
    v00 = b00 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b01) & b02)
    v05 = b05 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b06) & b07)
    v10 = b10 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b11) & b12)
    v15 = b15 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b16) & b17)
    v20 = b20 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b21) & b22)
    v01 = b01 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b02) & b03)
    v06 = b06 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b07) & b08)
    v11 = b11 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b12) & b13)
    v16 = b16 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b17) & b18)
    v21 = b21 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b22) & b23)
    v02 = b02 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b03) & b04)
    v07 = b07 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b08) & b09)
    v12 = b12 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b13) & b14)
    v17 = b17 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b18) & b19)
    v22 = b22 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b23) & b24)
    v03 = b03 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b04) & b00)
    v08 = b08 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b09) & b05)
    v13 = b13 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b14) & b10)
    v18 = b18 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b19) & b15)
    v23 = b23 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b24) & b20)
    v04 = b04 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b00) & b01)
    v09 = b09 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b05) & b06)
    v14 = b14 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b10) & b11)
    v19 = b19 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b15) & b16)
    v24 = b24 ^ ((0xFFFFFFFFFFFFFFFFUL ^ b20) & b21)
    v00 = v00 ^ keccak_rndc[round]
  }
  st[0] = v00
  st[5] = v05
  st[10] = v10
  st[15] = v15
  st[20] = v20
  st[1] = v01
  st[6] = v06
  st[11] = v11
  st[16] = v16
  st[21] = v21
  st[2] = v02
  st[7] = v07
  st[12] = v12
  st[17] = v17
  st[22] = v22
  st[3] = v03
  st[8] = v08
  st[13] = v13
  st[18] = v18
  st[23] = v23
  st[4] = v04
  st[9] = v09
  st[14] = v14
  st[19] = v19
  st[24] = v24
}
