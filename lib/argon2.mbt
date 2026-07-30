// ==================== Argon2 (RFC 9106: 2d / 2i / 2id) ====================
// Memory-hard password-based KDF. Ported verbatim from the reference C
// implementation (extras/libargon2): fBlaMka/G/BLAKE2_ROUND_NOMSG,
// fill_block (row-then-column P over 1024-byte blocks), index_alpha,
// fill_segment (data-independent addressing for 2i / first-half-pass-0 of
// 2id), blake2b_long (H'), initial_hash (H0), fill_first_blocks, finalize.
// UInt64 arithmetic wraps mod 2^64 (verified), matching C uint64_t.
// Verified against argon2-cffi (the reference C lib via cffi).

///|
let a2_sync_points : Int = 4

///|
let a2_addresses_in_block : Int = 128

///|
let a2_version_13 : Int = 0x13

///|
fn a2_le_u64(data : Bytes, offset : Int) -> UInt64 {
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
fn a2_store_u64_le(out : Array[Byte], offset : Int, v : UInt64) -> Unit {
  out[offset] = (v & 0xFFUL).to_byte()
  out[offset + 1] = ((v >> 8) & 0xFFUL).to_byte()
  out[offset + 2] = ((v >> 16) & 0xFFUL).to_byte()
  out[offset + 3] = ((v >> 24) & 0xFFUL).to_byte()
  out[offset + 4] = ((v >> 32) & 0xFFUL).to_byte()
  out[offset + 5] = ((v >> 40) & 0xFFUL).to_byte()
  out[offset + 6] = ((v >> 48) & 0xFFUL).to_byte()
  out[offset + 7] = ((v >> 56) & 0xFFUL).to_byte()
}

///|
fn a2_le32(out : Array[Byte], offset : Int, v : Int) -> Unit {
  out[offset] = (v & 0xFF).to_byte()
  out[offset + 1] = ((v >> 8) & 0xFF).to_byte()
  out[offset + 2] = ((v >> 16) & 0xFF).to_byte()
  out[offset + 3] = ((v >> 24) & 0xFF).to_byte()
}

///|
fn a2_rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// Convert a UInt64 known to be < 2^31 to a non-negative Int (UInt64 has no
/// reinterpret_as_int; extract low 32 bits via bytes).
fn a2_u64_to_int(v : UInt64) -> Int {
  let b0 = (v & 0xFFUL).to_byte().to_int()
  let b1 = ((v >> 8) & 0xFFUL).to_byte().to_int()
  let b2 = ((v >> 16) & 0xFFUL).to_byte().to_int()
  let b3 = ((v >> 24) & 0xFFUL).to_byte().to_int()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///|
fn a2_load_block(data : Bytes) -> Array[UInt64] {
  let v = Array::make(128, 0UL)
  for i in 0..<128 {
    v[i] = a2_le_u64(data, i * 8)
  }
  v
}

///|
fn a2_store_block(v : Array[UInt64]) -> Bytes {
  let out = Array::make(1024, b'\x00')
  for i in 0..<128 {
    a2_store_u64_le(out, i * 8, v[i])
  }
  Bytes::from_array(out[:])
}

///|
fn a2_copy_block(src : Array[UInt64]) -> Array[UInt64] {
  let v = Array::make(128, 0UL)
  for i in 0..<128 {
    v[i] = src[i]
  }
  v
}

///|
fn a2_zero_block() -> Array[UInt64] {
  Array::make(128, 0UL)
}

///|
fn a2_xor_into(dst : Array[UInt64], src : Array[UInt64]) -> Unit {
  for i in 0..<128 {
    dst[i] = dst[i] ^ src[i]
  }
}

///|
fn a2_fblamka(x : UInt64, y : UInt64) -> UInt64 {
  let m = 0xFFFFFFFFUL
  let xy = (x & m) * (y & m)
  x + y + xy + xy
}

///|
fn a2_g(v : Array[UInt64], a : Int, b : Int, c : Int, d : Int) -> Unit {
  v[a] = a2_fblamka(v[a], v[b])
  v[d] = a2_rotr64(v[d] ^ v[a], 32)
  v[c] = a2_fblamka(v[c], v[d])
  v[b] = a2_rotr64(v[b] ^ v[c], 24)
  v[a] = a2_fblamka(v[a], v[b])
  v[d] = a2_rotr64(v[d] ^ v[a], 16)
  v[c] = a2_fblamka(v[c], v[d])
  v[b] = a2_rotr64(v[b] ^ v[c], 63)
}

///|
fn a2_round_nomsg(v : Array[UInt64], idx : Array[Int]) -> Unit {
  a2_g(v, idx[0], idx[4], idx[8], idx[12])
  a2_g(v, idx[1], idx[5], idx[9], idx[13])
  a2_g(v, idx[2], idx[6], idx[10], idx[14])
  a2_g(v, idx[3], idx[7], idx[11], idx[15])
  a2_g(v, idx[0], idx[5], idx[10], idx[15])
  a2_g(v, idx[1], idx[6], idx[11], idx[12])
  a2_g(v, idx[2], idx[7], idx[8], idx[13])
  a2_g(v, idx[3], idx[4], idx[9], idx[14])
}

///|
fn a2_row_idx(i : Int) -> Array[Int] {
  let idx = Array::make(16, 0)
  for k in 0..<16 {
    idx[k] = 16 * i + k
  }
  idx
}

///|
fn a2_col_idx(i : Int) -> Array[Int] {
  let idx = Array::make(16, 0)
  for k in 0..<8 {
    idx[2 * k] = 2 * i + 16 * k
    idx[2 * k + 1] = 2 * i + 16 * k + 1
  }
  idx
}

///|
fn a2_fill_block(
  prev : Array[UInt64],
  ref_ : Array[UInt64],
  next : Array[UInt64],
  with_xor : Bool,
) -> Unit {
  let block_r = a2_copy_block(ref_)
  a2_xor_into(block_r, prev)
  let block_tmp = a2_copy_block(block_r)
  if with_xor {
    a2_xor_into(block_tmp, next)
  }
  for i in 0..<8 {
    a2_round_nomsg(block_r, a2_row_idx(i))
  }
  for i in 0..<8 {
    a2_round_nomsg(block_r, a2_col_idx(i))
  }
  for i in 0..<128 {
    next[i] = block_tmp[i] ^ block_r[i]
  }
}

///|
fn a2_next_addresses(
  address_block : Array[UInt64],
  input_block : Array[UInt64],
  zero_block : Array[UInt64],
) -> Unit {
  input_block[6] = input_block[6] + 1UL
  a2_fill_block(zero_block, input_block, address_block, false)
  a2_fill_block(zero_block, address_block, address_block, false)
}

///|
fn a2_index_alpha(
  pass : Int,
  slice : Int,
  index : Int,
  same_lane : Bool,
  segment_length : Int,
  lane_length : Int,
  pseudo_rand : UInt64,
) -> Int {
  let mut reference_area_size = 0
  if pass == 0 {
    if slice == 0 {
      reference_area_size = index - 1
    } else if same_lane {
      reference_area_size = slice * segment_length + index - 1
    } else {
      reference_area_size = slice * segment_length +
        (if index == 0 { -1 } else { 0 })
    }
  } else if same_lane {
    reference_area_size = lane_length - segment_length + index - 1
  } else {
    reference_area_size = lane_length -
      segment_length +
      (if index == 0 { -1 } else { 0 })
  }
  if reference_area_size < 0 {
    reference_area_size = 0
  }
  let ras = reference_area_size.to_uint64()
  let mut rp = pseudo_rand
  rp = (rp * rp) >> 32
  let rp2 = (ras * rp) >> 32
  let rel = a2_u64_to_int(ras - 1UL - rp2)
  let mut start_position = 0
  if pass != 0 {
    start_position = if slice == a2_sync_points - 1 {
      0
    } else {
      (slice + 1) * segment_length
    }
  }
  let abs = start_position + rel
  let r = abs % lane_length
  if r < 0 {
    r + lane_length
  } else {
    r
  }
}

///|
fn a2_h_prime(input : Bytes, out_len : Int) -> Bytes {
  if out_len <= 64 {
    let prefix = Array::make(4, b'\x00')
    a2_le32(prefix, 0, out_len)
    return blake2b(concat_bytes(Bytes::from_array(prefix[:]), input), out_len)
  }
  let prefix = Array::make(4, b'\x00')
  a2_le32(prefix, 0, out_len)
  let mut out_buffer = blake2b(
    concat_bytes(Bytes::from_array(prefix[:]), input),
    64,
  )
  let out = Array::make(out_len, b'\x00')
  let mut out_pos = 0
  for i in 0..<32 {
    out[out_pos] = out_buffer[i]
    out_pos = out_pos + 1
  }
  let mut toproduce = out_len - 32
  let in_buffer = Array::make(64, b'\x00')
  while toproduce > 64 {
    for i in 0..<64 {
      in_buffer[i] = out_buffer[i]
    }
    out_buffer = blake2b(Bytes::from_array(in_buffer[:]), 64)
    for i in 0..<32 {
      out[out_pos] = out_buffer[i]
      out_pos = out_pos + 1
    }
    toproduce = toproduce - 32
  }
  for i in 0..<64 {
    in_buffer[i] = out_buffer[i]
  }
  out_buffer = blake2b(Bytes::from_array(in_buffer[:]), toproduce)
  for i in 0..<toproduce {
    out[out_pos] = out_buffer[i]
    out_pos = out_pos + 1
  }
  Bytes::from_array(out[:])
}

///|
fn a2_le32_bytes(v : Int) -> Bytes {
  let b = Array::make(4, b'\x00')
  a2_le32(b, 0, v)
  Bytes::from_array(b[:])
}

///|
fn a2_initial_hash(
  lanes : Int,
  outlen : Int,
  m_cost : Int,
  t_cost : Int,
  version : Int,
  type_ : Int,
  pwd : Bytes,
  salt : Bytes,
) -> Bytes {
  let parts : Array[Bytes] = [
    a2_le32_bytes(lanes),
    a2_le32_bytes(outlen),
    a2_le32_bytes(m_cost),
    a2_le32_bytes(t_cost),
    a2_le32_bytes(version),
    a2_le32_bytes(type_),
    a2_le32_bytes(pwd.length()),
    pwd,
    a2_le32_bytes(salt.length()),
    salt,
    a2_le32_bytes(0),
    a2_le32_bytes(0),
  ]
  blake2b(concat_all(parts), 64)
}

///|
fn a2_fill_first_blocks(
  mem : Array[Array[UInt64]],
  h0 : Bytes,
  lanes : Int,
  lane_length : Int,
) -> Unit {
  let seed = Array::make(72, b'\x00')
  for i in 0..<64 {
    seed[i] = h0[i]
  }
  for l in 0..<lanes {
    a2_le32(seed, 64, 0)
    a2_le32(seed, 68, l)
    mem[l * lane_length + 0] = a2_load_block(
      a2_h_prime(Bytes::from_array(seed[:]), 1024),
    )
    a2_le32(seed, 64, 1)
    a2_le32(seed, 68, l)
    mem[l * lane_length + 1] = a2_load_block(
      a2_h_prime(Bytes::from_array(seed[:]), 1024),
    )
  }
}

///|
fn a2_finalize(
  mem : Array[Array[UInt64]],
  lanes : Int,
  lane_length : Int,
  outlen : Int,
) -> Bytes {
  let blockhash = a2_copy_block(mem[lane_length - 1])
  for l in 1..<lanes {
    a2_xor_into(blockhash, mem[l * lane_length + (lane_length - 1)])
  }
  a2_h_prime(a2_store_block(blockhash), outlen)
}

///|
fn a2_fill_segment(
  mem : Array[Array[UInt64]],
  pass : Int,
  lane : Int,
  slice : Int,
  lanes : Int,
  segment_length : Int,
  lane_length : Int,
  memory_blocks : Int,
  passes : Int,
  type_ : Int,
  version : Int,
) -> Unit {
  let data_independent = type_ == 1 ||
    (type_ == 2 && pass == 0 && slice < a2_sync_points / 2)
  let address_block = a2_zero_block()
  let input_block = a2_zero_block()
  let zero_block = a2_zero_block()
  if data_independent {
    input_block[0] = pass.to_uint64()
    input_block[1] = lane.to_uint64()
    input_block[2] = slice.to_uint64()
    input_block[3] = memory_blocks.to_uint64()
    input_block[4] = passes.to_uint64()
    input_block[5] = type_.to_uint64()
  }
  let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 }
  if pass == 0 && slice == 0 && data_independent {
    a2_next_addresses(address_block, input_block, zero_block)
  }
  let mut curr_offset = lane * lane_length +
    slice * segment_length +
    starting_index
  let mut prev_offset = if curr_offset % lane_length == 0 {
    curr_offset + lane_length - 1
  } else {
    curr_offset - 1
  }
  for i in starting_index..<segment_length {
    if curr_offset % lane_length == 1 {
      prev_offset = curr_offset - 1
    }
    let pseudo_rand = if data_independent {
      if i % a2_addresses_in_block == 0 {
        a2_next_addresses(address_block, input_block, zero_block)
      }
      address_block[i % a2_addresses_in_block]
    } else {
      mem[prev_offset][0]
    }
    let mut ref_lane = a2_u64_to_int((pseudo_rand >> 32) % lanes.to_uint64())
    if pass == 0 && slice == 0 {
      ref_lane = lane
    }
    let ref_index = a2_index_alpha(
      pass,
      slice,
      i,
      ref_lane == lane,
      segment_length,
      lane_length,
      pseudo_rand & 0xFFFFFFFFUL,
    )
    let ref_block = mem[lane_length * ref_lane + ref_index]
    let with_xor = if version == 0x10 { false } else { pass != 0 }
    a2_fill_block(mem[prev_offset], ref_block, mem[curr_offset], with_xor)
    curr_offset = curr_offset + 1
    prev_offset = prev_offset + 1
  }
}

///|
fn a2_fill_memory_blocks(
  mem : Array[Array[UInt64]],
  passes : Int,
  lanes : Int,
  segment_length : Int,
  lane_length : Int,
  memory_blocks : Int,
  type_ : Int,
  version : Int,
) -> Unit {
  for pass in 0..<passes {
    for slice in 0..<a2_sync_points {
      for lane in 0..<lanes {
        a2_fill_segment(
          mem, pass, lane, slice, lanes, segment_length, lane_length, memory_blocks,
          passes, type_, version,
        )
      }
    }
  }
}

///|
/// Argon2 (RFC 9106) memory-hard KDF. `variant`: 0 = Argon2d, 1 = Argon2i,
/// 2 = Argon2id. `t_cost` = passes, `m_cost` = memory in 1-KiB blocks,
/// `parallelism` = lanes, `hash_len` = output length (>= 4).
pub fn argon2(
  password : Bytes,
  salt : Bytes,
  t_cost : Int,
  m_cost : Int,
  parallelism : Int,
  hash_len : Int,
  variant : Int,
) -> Bytes {
  if t_cost < 1 || m_cost < 8 * parallelism || parallelism < 1 || hash_len < 4 {
    abort("argon2: invalid parameters (t>=1, m>=8*p, p>=1, hashlen>=4)")
  }
  if salt.length() < 8 {
    abort("argon2: salt must be at least 8 bytes")
  }
  let version = a2_version_13
  let lanes = parallelism
  // align memory
  let mut memory_blocks = m_cost
  if memory_blocks < 2 * a2_sync_points * lanes {
    memory_blocks = 2 * a2_sync_points * lanes
  }
  let segment_length = memory_blocks / (lanes * a2_sync_points)
  memory_blocks = segment_length * (lanes * a2_sync_points)
  let lane_length = segment_length * a2_sync_points
  // allocate memory (distinct blocks; Array::make(n, block) would share the reference)
  let mem : Array[Array[UInt64]] = []
  for _ in 0..<memory_blocks {
    mem.push(a2_zero_block())
  }
  // H0 + first blocks
  let h0 = a2_initial_hash(
    lanes, hash_len, m_cost, t_cost, version, variant, password, salt,
  )
  a2_fill_first_blocks(mem, h0, lanes, lane_length)
  // fill
  a2_fill_memory_blocks(
    mem, t_cost, lanes, segment_length, lane_length, memory_blocks, variant, version,
  )
  // finalize
  a2_finalize(mem, lanes, lane_length, hash_len)
}

///|
/// Argon2id (the recommended variant): data-independent addressing for the
/// first half of the first pass, data-dependent thereafter.
pub fn argon2id(
  password : Bytes,
  salt : Bytes,
  t_cost : Int,
  m_cost : Int,
  parallelism : Int,
  hash_len : Int,
) -> Bytes {
  argon2(password, salt, t_cost, m_cost, parallelism, hash_len, 2)
}

///|
/// Argon2d: data-dependent addressing (maximize resistance to GPU cracking).
pub fn argon2d(
  password : Bytes,
  salt : Bytes,
  t_cost : Int,
  m_cost : Int,
  parallelism : Int,
  hash_len : Int,
) -> Bytes {
  argon2(password, salt, t_cost, m_cost, parallelism, hash_len, 0)
}

///|
/// Argon2i: data-independent addressing (side-channel resistant).
pub fn argon2i(
  password : Bytes,
  salt : Bytes,
  t_cost : Int,
  m_cost : Int,
  parallelism : Int,
  hash_len : Int,
) -> Bytes {
  argon2(password, salt, t_cost, m_cost, parallelism, hash_len, 1)
}
