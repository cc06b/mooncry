///|
/// BLAKE2s (RFC 7693) — 32-bit sibling of BLAKE2b, unkeyed, variable-length
/// hash (1..32 bytes). Same structure as blake2.mbt with 32-bit words,
/// 64-byte blocks, 10 rounds and rotations 16/12/8/7.

///|
let blake2s_iv : Array[UInt] = [
  0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
  0x5BE0CD19U,
]

///|
/// Sigma: message-word permutation (first 10 rows, reused each round)
let blake2s_sigma : Array[Array[Int]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

///|
/// Rotate a 32-bit value right by n (1 <= n <= 31)
fn blake2s_rotr(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// BLAKE2s G function (rotations 16, 12, 8, 7)
fn blake2s_g(
  v : Array[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : UInt,
  y : UInt,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = blake2s_rotr(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = blake2s_rotr(v[b] ^ v[c], 12)
  v[a] = v[a] + v[b] + y
  v[d] = blake2s_rotr(v[d] ^ v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = blake2s_rotr(v[b] ^ v[c], 7)
}

///|
/// Compress one 64-byte block into the chaining value `h`.
/// `t` is the total bytes processed so far (including this block);
/// `last` sets the last-block flag (inverts v[14]).
fn blake2s_compress(
  h : Array[UInt],
  block : Array[UInt],
  t : UInt64,
  last : Bool,
) -> Unit {
  let v = Array::make(16, 0U)
  for i in 0..<=7 {
    v[i] = h[i]
    v[i + 8] = blake2s_iv[i]
  }
  v[12] = v[12] ^ (t & 0xFFFFFFFFUL).to_uint()
  v[13] = v[13] ^ ((t >> 32) & 0xFFFFFFFFUL).to_uint()
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFU
  }
  for r in 0..<=9 {
    let s = blake2s_sigma[r]
    blake2s_g(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
    blake2s_g(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
    blake2s_g(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
    blake2s_g(v, 3, 7, 11, 15, block[s[6]], block[s[7]])
    blake2s_g(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
    blake2s_g(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
    blake2s_g(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
    blake2s_g(v, 3, 4, 9, 14, block[s[14]], block[s[15]])
  }
  for i in 0..<=7 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Read 4 bytes at `offset` as a little-endian UInt
fn blake2s_read_word(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
/// BLAKE2s hash (RFC 7693), unkeyed, `out_len` in 1..32 bytes.
pub fn blake2s(data : Bytes, out_len : Int) -> Bytes {
  if out_len < 1 || out_len > 32 {
    abort("blake2s: out_len must be in 1..32")
  }
  let h = Array::make(8, 0U)
  for i in 0..<=7 {
    h[i] = blake2s_iv[i]
  }
  // parameter block (unkeyed, fanout=1, depth=1): h[0] ^= 0x01010000 | nn
  h[0] = h[0] ^ (0x01010000U + out_len.reinterpret_as_uint())
  let len = data.length()
  let mut offset = 0
  let mut t = 0UL
  // full 64-byte blocks
  while offset + 64 <= len {
    let block = Array::make(16, 0U)
    for i in 0..<=15 {
      block[i] = blake2s_read_word(data, offset + i * 4)
    }
    t = t + 64UL
    blake2s_compress(h, block, t, false)
    offset = offset + 64
  }
  // last block: copy remaining bytes into a zero-padded 64-byte buffer
  let rem = len - offset
  let padded = Array::make(64, b'\x00')
  for i in 0..<rem {
    padded[i] = data[offset + i]
  }
  let last_bytes = Bytes::from_array(padded[:])
  let block2 = Array::make(16, 0U)
  for i in 0..<=15 {
    block2[i] = blake2s_read_word(last_bytes, i * 4)
  }
  t = t + rem.to_uint64()
  blake2s_compress(h, block2, t, true)
  // output: first out_len bytes of h, little-endian per word
  let out = Array::make(out_len, b'\x00')
  for i in 0..<=7 {
    let w = h[i]
    for j in 0..<4 {
      let idx = i * 4 + j
      if idx < out_len {
        out[idx] = ((w >> (j * 8)) & 0xFFU).to_byte()
      }
    }
  }
  Bytes::from_array(out[:])
}
