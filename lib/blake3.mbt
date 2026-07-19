///|
/// BLAKE3 (BLAKE3-team/BLAKE3 spec). 32-bit words, 7 rounds.
/// Handles inputs up to 1024 bytes (one chunk). Longer inputs need tree mode (TODO).
/// Output is an XOF (variable length). Uses UInt64 masked to 32 bits.

///|
let blake3_iv : Array[UInt64] = [
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
  0x1F83D9ABUL, 0x5BE0CD19UL,
]

///|
let blake3_msg_perm : Array[Int] = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
]

///|
fn rotr32(x : UInt64, n : Int) -> UInt64 {
  ((x >> n) | (x << (32 - n))) & 0xFFFFFFFFUL
}

///|
fn blake3_g(
  v : Array[UInt64],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  mx : UInt64,
  my : UInt64,
) -> Unit {
  v[a] = (v[a] + v[b] + mx) & 0xFFFFFFFFUL
  v[d] = rotr32(v[d] ^ v[a], 16)
  v[c] = (v[c] + v[d]) & 0xFFFFFFFFUL
  v[b] = rotr32(v[b] ^ v[c], 12)
  v[a] = (v[a] + v[b] + my) & 0xFFFFFFFFUL
  v[d] = rotr32(v[d] ^ v[a], 8)
  v[c] = (v[c] + v[d]) & 0xFFFFFFFFUL
  v[b] = rotr32(v[b] ^ v[c], 7)
}

///|
fn blake3_round(v : Array[UInt64], m : Array[UInt64]) -> Unit {
  blake3_g(v, 0, 4, 8, 12, m[0], m[1])
  blake3_g(v, 1, 5, 9, 13, m[2], m[3])
  blake3_g(v, 2, 6, 10, 14, m[4], m[5])
  blake3_g(v, 3, 7, 11, 15, m[6], m[7])
  blake3_g(v, 0, 5, 10, 15, m[8], m[9])
  blake3_g(v, 1, 6, 11, 12, m[10], m[11])
  blake3_g(v, 2, 7, 8, 13, m[12], m[13])
  blake3_g(v, 3, 4, 9, 14, m[14], m[15])
}

///|
fn blake3_permute(m : Array[UInt64]) -> Array[UInt64] {
  let p = Array::make(16, 0UL)
  for i in 0..<16 {
    p[i] = m[blake3_msg_perm[i]]
  }
  p
}

///|
fn blake3_compress(
  cv : Array[UInt64],
  block_words : Array[UInt64],
  counter : UInt64,
  block_len : UInt64,
  flags : UInt64,
) -> Array[UInt64] {
  let v = Array::make(16, 0UL)
  for i in 0..<8 {
    v[i] = cv[i]
  }
  v[8] = blake3_iv[0]
  v[9] = blake3_iv[1]
  v[10] = blake3_iv[2]
  v[11] = blake3_iv[3]
  v[12] = counter
  v[13] = 0UL
  v[14] = block_len
  v[15] = flags
  let mut block = Array::make(16, 0UL)
  for i in 0..<16 {
    block[i] = block_words[i]
  }
  for _ in 0..<6 {
    blake3_round(v, block)
    block = blake3_permute(block)
  }
  blake3_round(v, block)
  // output: state[i] ^= state[i+8]; state[i+8] ^= cv[i]
  for i in 0..<8 {
    let t = v[i] ^ v[i + 8]
    v[i + 8] = v[i + 8] ^ cv[i]
    v[i] = t
  }
  v
}

///|
fn blake3_words_from_le(block : Array[Byte]) -> Array[UInt64] {
  let w = Array::make(16, 0UL)
  for i in 0..<16 {
    w[i] = block[i * 4].to_uint64() |
      (block[i * 4 + 1].to_uint64() << 8) |
      (block[i * 4 + 2].to_uint64() << 16) |
      (block[i * 4 + 3].to_uint64() << 24)
  }
  w
}

///|
/// BLAKE3 XOF, `out_len` bytes. Supports inputs up to 1024 bytes (one chunk).
/// Longer inputs require the tree-Merkle mode (TODO).
pub fn blake3_xof(data : Bytes, out_len : Int) -> Bytes {
  if out_len < 0 {
    abort("blake3_xof: out_len must be non-negative")
  }
  let len = data.length()
  if len > 1024 {
    abort("blake3_xof: inputs > 1024 bytes (tree mode) not yet supported")
  }
  let cv = Array::make(8, 0UL)
  for i in 0..<8 {
    cv[i] = blake3_iv[i]
  }
  let mut blocks_compressed = 0
  let mut off = 0
  // full 64-byte blocks (not CHUNK_END; more may come)
  while off + 64 < len {
    let block = Array::make(64, b'\x00')
    for i in 0..<64 {
      block[i] = data[off + i]
    }
    let words = blake3_words_from_le(block)
    let flags = if blocks_compressed == 0 { 1UL } else { 0UL }
    let st = blake3_compress(cv, words, 0UL, 64UL, flags)
    for i in 0..<8 {
      cv[i] = st[i]
    }
    blocks_compressed = blocks_compressed + 1
    off = off + 64
  }
  // last (partial or empty) block: CHUNK_END (and CHUNK_START if no full block)
  let rem = len - off
  let last_block = Array::make(64, b'\x00')
  for i in 0..<rem {
    last_block[i] = data[off + i]
  }
  let last_words = blake3_words_from_le(last_block)
  let last_flags = (if blocks_compressed == 0 { 1UL } else { 0UL }) | 2UL
  // root output: re-compress the last block with ROOT + output counter
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut out_counter = 0UL
  while out_off < out_len {
    let st = blake3_compress(
      cv,
      last_words,
      out_counter,
      rem.to_uint64(),
      last_flags | 8UL,
    )
    for i in 0..<16 {
      if out_off >= out_len {
        break
      }
      let word = st[i]
      for bi in 0..<4 {
        if out_off >= out_len {
          break
        }
        out[out_off] = ((word >> (bi * 8)) & 0xFFUL).to_byte()
        out_off = out_off + 1
      }
    }
    out_counter = out_counter + 1UL
  }
  Bytes::from_array(out[:])
}

///|
/// BLAKE3 hash, 32-byte (256-bit) digest.
pub fn blake3(data : Bytes) -> Bytes {
  blake3_xof(data, 32)
}
