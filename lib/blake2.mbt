///|
/// BLAKE2b (RFC 7693) — unkeyed, variable-length hash (1..64 bytes).
/// Reuses `rotr64` from `sha512.mbt`. UInt64 `+` wraps mod 2^64 (same as SHA-512).

///|
let blake2b_iv : Array[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
/// Sigma: message-word permutation for round r (BLAKE2b uses 12 rounds).
let blake2b_sigma : Array[Array[Int]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 2, 6, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

///|
/// BLAKE2b G function (rotations 32, 24, 16, 63).
fn blake2b_g(
  v : Array[UInt64],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
/// Compress one 128-byte block into the chaining value `h`.
/// `t` is the total bytes processed so far (including this block);
/// `last` sets the last-block flag (inverts v[14]).
fn blake2b_compress(
  h : Array[UInt64],
  block : Array[UInt64],
  t : UInt64,
  last : Bool,
) -> Unit {
  let v = Array::make(16, 0UL)
  for i in 0..<=7 {
    v[i] = h[i]
    v[i + 8] = blake2b_iv[i]
  }
  v[12] = v[12] ^ t
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  for r in 0..<=11 {
    let s = blake2b_sigma[r]
    blake2b_g(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
    blake2b_g(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
    blake2b_g(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
    blake2b_g(v, 3, 7, 11, 15, block[s[6]], block[s[7]])
    blake2b_g(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
    blake2b_g(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
    blake2b_g(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
    blake2b_g(v, 3, 4, 9, 14, block[s[14]], block[s[15]])
  }
  for i in 0..<=7 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Read 8 bytes at `offset` as a little-endian UInt64.
fn blake2b_read_lane(data : Bytes, offset : Int) -> UInt64 {
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
/// BLAKE2b hash (RFC 7693), unkeyed, `out_len` in 1..64 bytes.
pub fn blake2b(data : Bytes, out_len : Int) -> Bytes {
  if out_len < 1 || out_len > 64 {
    abort("blake2b: out_len must be in 1..64")
  }
  let h = Array::make(8, 0UL)
  for i in 0..<=7 {
    h[i] = blake2b_iv[i]
  }
  // parameter block (unkeyed, fanout=1, depth=1): h[0] ^= 0x01010000 | nn
  h[0] = h[0] ^ (0x01010000UL + out_len.to_uint64())
  let len = data.length()
  let mut offset = 0
  let mut t = 0UL
  // full 128-byte blocks
  while offset + 128 <= len {
    let block = Array::make(16, 0UL)
    for i in 0..<=15 {
      block[i] = blake2b_read_lane(data, offset + i * 8)
    }
    t = t + 128UL
    blake2b_compress(h, block, t, false)
    offset = offset + 128
  }
  // last block: copy remaining bytes into a zero-padded 128-byte buffer
  let rem = len - offset
  let padded = Array::make(128, b'\x00')
  for i in 0..<rem {
    padded[i] = data[offset + i]
  }
  let last_bytes = Bytes::from_array(padded[:])
  let block2 = Array::make(16, 0UL)
  for i in 0..<=15 {
    block2[i] = blake2b_read_lane(last_bytes, i * 8)
  }
  t = t + rem.to_uint64()
  blake2b_compress(h, block2, t, true)
  // output: first out_len bytes of h, little-endian per word
  let out = Array::make(out_len, b'\x00')
  for i in 0..<=7 {
    let wb = h[i].to_le_bytes()
    for j in 0..<8 {
      let idx = i * 8 + j
      if idx < out_len {
        out[idx] = wb[j]
      }
    }
  }
  Bytes::from_array(out[:])
}
