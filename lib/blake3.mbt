///|
/// BLAKE3 (BLAKE3-team/BLAKE3 spec). 32-bit words, 7 rounds, tree-Merkle.
/// Arbitrary-length input via chunk tree. UInt64 masked to 32 bits.

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
fn b3_copy8(a : Array[UInt64]) -> Array[UInt64] {
  let r = Array::make(8, 0UL)
  for i in 0..<8 {
    r[i] = a[i]
  }
  r
}

///|
fn b3_first8(st : Array[UInt64]) -> Array[UInt64] {
  b3_copy8(st)
}

// ==================== Chunk state ====================

///|
priv struct B3ChunkState {
  mut cv : Array[UInt64]
  chunk_counter : UInt64
  block : Array[Byte]
  mut block_len : Int
  mut blocks_compressed : Int
  flags : UInt64
}

///|
fn b3_chunk_new(
  key : Array[UInt64],
  chunk_counter : UInt64,
  flags : UInt64,
) -> B3ChunkState {
  B3ChunkState::{
    cv: b3_copy8(key),
    chunk_counter,
    block: Array::make(64, b'\x00'),
    block_len: 0,
    blocks_compressed: 0,
    flags,
  }
}

///|
fn b3_chunk_len(cs : B3ChunkState) -> Int {
  64 * cs.blocks_compressed + cs.block_len
}

///|
fn b3_start_flag(cs : B3ChunkState) -> UInt64 {
  if cs.blocks_compressed == 0 {
    1UL
  } else {
    0UL
  }
}

///|
fn b3_chunk_update(cs : B3ChunkState, input : Bytes) -> Unit {
  let mut off = 0
  let len = input.length()
  while off < len {
    if cs.block_len == 64 {
      let words = blake3_words_from_le(cs.block)
      let st = blake3_compress(
        cs.cv,
        words,
        cs.chunk_counter,
        64UL,
        cs.flags | b3_start_flag(cs),
      )
      cs.cv = b3_first8(st)
      cs.blocks_compressed = cs.blocks_compressed + 1
      cs.block_len = 0
    }
    let take = if 64 - cs.block_len < len - off {
      64 - cs.block_len
    } else {
      len - off
    }
    for i in 0..<take {
      cs.block[cs.block_len + i] = input[off + i]
    }
    cs.block_len = cs.block_len + take
    off = off + take
  }
}

// ==================== Output / parent ====================

///|
priv struct B3Output {
  input_cv : Array[UInt64]
  block_words : Array[UInt64]
  counter : UInt64
  block_len : UInt64
  flags : UInt64
}

///|
fn b3_chaining_value(o : B3Output) -> Array[UInt64] {
  b3_first8(
    blake3_compress(o.input_cv, o.block_words, o.counter, o.block_len, o.flags),
  )
}

///|
fn b3_parent_output(
  left : Array[UInt64],
  right : Array[UInt64],
  key : Array[UInt64],
  flags : UInt64,
) -> B3Output {
  let bw = Array::make(16, 0UL)
  for i in 0..<8 {
    bw[i] = left[i]
    bw[8 + i] = right[i]
  }
  B3Output::{
    input_cv: key,
    block_words: bw,
    counter: 0UL,
    block_len: 64UL,
    flags: 4UL | flags,
  } // PARENT=4
}

///|
fn b3_chunk_output(cs : B3ChunkState) -> B3Output {
  B3Output::{
    input_cv: cs.cv,
    block_words: blake3_words_from_le(cs.block),
    counter: cs.chunk_counter,
    block_len: cs.block_len.to_uint64(),
    flags: cs.flags | b3_start_flag(cs) | 2UL, // CHUNK_END=2
  }
}

// ==================== Hasher (tree) ====================

///|
priv struct B3Hasher {
  mut chunk_state : B3ChunkState
  key : Array[UInt64]
  cv_stack : Array[Array[UInt64]]
  mut cv_stack_len : Int
  flags : UInt64
}

///|
fn b3_new_stack() -> Array[Array[UInt64]] {
  let s : Array[Array[UInt64]] = []
  for _ in 0..<54 {
    s.push(Array::make(8, 0UL))
  }
  s
}

///|
fn b3_hasher_new() -> B3Hasher {
  B3Hasher::{
    chunk_state: b3_chunk_new(blake3_iv, 0UL, 0UL),
    key: blake3_iv,
    cv_stack: b3_new_stack(),
    cv_stack_len: 0,
    flags: 0UL,
  }
}

///|
/// Push a completed chunk's cv, merging completed subtrees (trailing-zero rule).
fn b3_add_cv(
  h : B3Hasher,
  new_cv : Array[UInt64],
  total_chunks : UInt64,
) -> Unit {
  let mut tc = total_chunks
  let mut cv = b3_copy8(new_cv)
  while (tc & 1UL) == 0UL {
    h.cv_stack_len = h.cv_stack_len - 1
    let left = h.cv_stack[h.cv_stack_len]
    cv = b3_first8(
      // parent: input_cv=key, block=[left||cv], counter=0, block_len=64, flags=PARENT|h.flags
      blake3_compress(
        h.key,
        {
          let bw = Array::make(16, 0UL)
          for i in 0..<8 {
            bw[i] = left[i]
            bw[8 + i] = cv[i]
          }
          bw
        },
        0UL,
        64UL,
        4UL | h.flags,
      ),
    )
    tc = tc >> 1
  }
  h.cv_stack[h.cv_stack_len] = cv
  h.cv_stack_len = h.cv_stack_len + 1
}

///|
fn b3_hasher_update(h : B3Hasher, input : Bytes) -> Unit {
  let mut off = 0
  let len = input.length()
  while off < len {
    if b3_chunk_len(h.chunk_state) == 1024 {
      let cs = h.chunk_state
      let chunk_cv = b3_chaining_value(b3_chunk_output(cs))
      b3_add_cv(h, chunk_cv, cs.chunk_counter + 1UL)
      h.chunk_state = b3_chunk_new(h.key, cs.chunk_counter + 1UL, h.flags)
    }
    let want = 1024 - b3_chunk_len(h.chunk_state)
    let take = if want < len - off { want } else { len - off }
    let b = Array::make(take, b'\x00')
    for i in 0..<take {
      b[i] = input[off + i]
    }
    b3_chunk_update(h.chunk_state, Bytes::from_array(b[:]))
    off = off + take
  }
}

///|
fn b3_hasher_finalize(h : B3Hasher, out_len : Int) -> Bytes {
  let mut output = b3_chunk_output(h.chunk_state)
  let mut i = h.cv_stack_len - 1
  while i >= 0 {
    output = b3_parent_output(
      h.cv_stack[i],
      b3_chaining_value(output),
      h.key,
      h.flags,
    )
    i = i - 1
  }
  // root output: re-compress with ROOT + output block counter
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut out_counter = 0UL
  while out_off < out_len {
    let st = blake3_compress(
      output.input_cv,
      output.block_words,
      out_counter,
      output.block_len,
      output.flags | 8UL, // ROOT=8
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
/// BLAKE3 XOF, `out_len` bytes. Arbitrary-length input (tree-Merkle).
pub fn blake3_xof(data : Bytes, out_len : Int) -> Bytes {
  if out_len < 0 {
    abort("blake3_xof: out_len must be non-negative")
  }
  let h = b3_hasher_new()
  b3_hasher_update(h, data)
  b3_hasher_finalize(h, out_len)
}

///|
/// BLAKE3 hash, 32-byte (256-bit) digest.
pub fn blake3(data : Bytes) -> Bytes {
  blake3_xof(data, 32)
}
