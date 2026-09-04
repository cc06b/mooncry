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
  keccak_f_from(st, 0)
}

///|
/// Keccak-p[1600]: rounds `start`..23 of Keccak-f. TurboSHAKE (RFC 9861)
/// uses start = 12 (the last 12 rounds). v0.36.0.
fn keccak_f_from(st : Array[UInt64], start : Int) -> Unit {
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
    // Rho and Pi: b[y + 5*((2x+3y) mod 5)] = rot(st[x + 5y], r[x][y])
    for x in 0..<5 {
      for y in 0..<5 {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(
          st[x + 5 * y],
          keccak_rho[x][y],
        )
      }
    }
    // Chi: st[x+5y] = b[x+5y] ^ ((~b[(x+1)%5 + 5y]) & b[(x+2)%5 + 5y])
    for x in 0..<5 {
      for y in 0..<5 {
        st[x + 5 * y] = b[x + 5 * y] ^
          (
            (0xFFFFFFFFFFFFFFFFUL ^ b[(x + 1) % 5 + 5 * y]) &
            b[(x + 2) % 5 + 5 * y]
          )
      }
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
  // pad: data || 0x06 ... 0x80, block-aligned to rate_bytes
  let num_blocks = data_len / rate_bytes + 1
  let buf_len = num_blocks * rate_bytes
  let buf = Array::make(buf_len, b'\x00')
  for i in 0..<data_len {
    buf[i] = data[i]
  }
  buf[data_len] = (buf[data_len].to_int() ^ 0x06).to_byte()
  buf[buf_len - 1] = (buf[buf_len - 1].to_int() ^ 0x80).to_byte()
  // absorb: XOR each rate block into st (lane i = x + 5*y)
  let lanes_per_block = rate_bytes / 8
  let mut off = 0
  while off < buf_len {
    for i in 0..<lanes_per_block {
      st[i] = st[i] ^ read_lane_le(buf, off + i * 8)
    }
    keccak_f(st)
    off = off + rate_bytes
  }
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
