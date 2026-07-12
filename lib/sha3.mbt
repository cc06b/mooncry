// ============================================================
// SHA-3 / Keccak (FIPS 202). Keccak-f[1600] permutation + sponge.
// Implements SHA3-224/256/384/512. Explicit theta/rho/pi/chi/iota.
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
/// Build a fresh 5x5 state with distinct rows (Array::make would share one row)
fn new_state() -> Array[Array[UInt64]] {
  let s : Array[Array[UInt64]] = []
  for _ in 0..<5 {
    s.push(Array::make(5, 0UL))
  }
  s
}

///|
/// Keccak-f[1600] permutation on a 5x5 state st[x][y] in place
fn keccak_f(st : Array[Array[UInt64]]) -> Unit {
  let c = Array::make(5, 0UL)
  let d = Array::make(5, 0UL)
  let b = new_state()
  for round in 0..<24 {
    // Theta
    for x in 0..<5 {
      c[x] = st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4]
    }
    for x in 0..<5 {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1)
    }
    for x in 0..<5 {
      for y in 0..<5 {
        st[x][y] = st[x][y] ^ d[x]
      }
    }
    // Rho and Pi: b[y][(2x+3y) mod 5] = rot(st[x][y], r[x][y])
    for x in 0..<5 {
      for y in 0..<5 {
        b[y][(2 * x + 3 * y) % 5] = rotl64(st[x][y], keccak_rho[x][y])
      }
    }
    // Chi: st[x][y] = b[x][y] ^ ((~b[(x+1)%5][y]) & b[(x+2)%5][y])
    for x in 0..<5 {
      for y in 0..<5 {
        st[x][y] = b[x][y] ^
          ((0xFFFFFFFFFFFFFFFFUL ^ b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
      }
    }
    // Iota
    st[0][0] = st[0][0] ^ keccak_rndc[round]
  }
}

///|
/// SHA-3 sponge: absorb `data` (domain 0x06), squeeze `out_len` bytes.
fn sha3_sponge(rate_bytes : Int, data : Bytes, out_len : Int) -> Bytes {
  // state st[x][y], lane index = x + 5*y
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
      let x = i % 5
      let y = i / 5
      st[x][y] = st[x][y] ^ read_lane_le(buf, off + i * 8)
    }
    keccak_f(st)
    off = off + rate_bytes
  }
  // squeeze: output lanes 0,1,2,... (lane i = x + 5*y) little-endian
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < out_len {
    let x = lane_idx % 5
    let y = lane_idx / 5
    let lane = st[x][y]
    for bi in 0..<8 {
      if out_off >= out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= 25 && out_off < out_len {
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
