// ==================== Streaming Hash APIs ====================
// Incremental hashing with update/finalize pattern for large or streaming data.

// ==================== MD5 Streaming ====================

///|
/// Incremental MD5 hasher
pub struct Md5Hasher {
  state : Array[UInt]
  buffer : Array[Byte]
  mut buf_len : Int
  mut total_len : UInt64
}

///|
/// Create a new MD5 hasher
pub fn md5_new() -> Md5Hasher {
  let state = Array::make(4, 0U)
  state[0] = 0x67452301U
  state[1] = 0xefcdab89U
  state[2] = 0x98badcfeU
  state[3] = 0x10325476U
  Md5Hasher::{
    state,
    buffer: Array::make(64, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the MD5 hasher
pub fn md5_update(hasher : Md5Hasher, data : Bytes) -> Unit {
  hasher.total_len = hasher.total_len + data.length().to_uint64()
  let data_len = data.length()
  let mut data_offset = 0
  // Fill buffer first
  if hasher.buf_len > 0 {
    let space = 64 - hasher.buf_len
    let to_copy = if data_len < space { data_len } else { space }
    for i in 0..<to_copy {
      hasher.buffer[hasher.buf_len + i] = data[data_offset + i]
    }
    hasher.buf_len = hasher.buf_len + to_copy
    data_offset = data_offset + to_copy
    if hasher.buf_len == 64 {
      // Process full buffer
      let block = Array::make(16, 0U)
      let buf_bytes = Bytes::from_array(hasher.buffer[:])
      for j in 0..<=15 {
        block[j] = read_u32_le(buf_bytes, j * 4)
      }
      md5_process_block(hasher.state, block)
      hasher.buf_len = 0
    }
  }
  // Process full blocks directly from input
  let remaining = data_len - data_offset
  let num_full_blocks = remaining / 64
  for b in 0..<num_full_blocks {
    let block = Array::make(16, 0U)
    let offset = data_offset + b * 64
    for j in 0..<=15 {
      block[j] = read_u32_le(data, offset + j * 4)
    }
    md5_process_block(hasher.state, block)
  }
  // Store remainder in buffer
  let rem_start = data_offset + num_full_blocks * 64
  let rem_count = remaining - num_full_blocks * 64
  if rem_count > 0 {
    for i in 0..<rem_count {
      hasher.buffer[i] = data[rem_start + i]
    }
    hasher.buf_len = rem_count
  }
}

///|
/// Finalize and return the 16-byte MD5 digest
pub fn md5_finalize(hasher : Md5Hasher) -> Bytes {
  // Pad the remaining buffer
  let bit_len = hasher.total_len * 8UL
  let pad_len = 56 - hasher.buf_len % 64
  let pad_len_final = if pad_len <= 0 { pad_len + 64 } else { pad_len }
  // Create padded data from buffer + padding + length
  let final_block_len = hasher.buf_len + pad_len_final + 8
  let padded = Array::make(final_block_len, b'\x00')
  for i in 0..<hasher.buf_len {
    padded[i] = hasher.buffer[i]
  }
  padded[hasher.buf_len] = b'\x80'
  let lo = (bit_len & 0xFFFFFFFFUL).to_uint()
  let hi = ((bit_len >> 32) & 0xFFFFFFFFUL).to_uint()
  write_u32_le(padded, hasher.buf_len + pad_len_final, lo)
  write_u32_le(padded, hasher.buf_len + pad_len_final + 4, hi)
  // Process all final blocks
  let padded_bytes = Bytes::from_array(padded[:])
  let num_blocks = final_block_len / 64
  for i in 0..<num_blocks {
    let block = Array::make(16, 0U)
    let offset = i * 64
    for j in 0..<=15 {
      block[j] = read_u32_le(padded_bytes, offset + j * 4)
    }
    md5_process_block(hasher.state, block)
  }
  // Output digest
  let result_arr = Array::make(16, b'\x00')
  write_u32_le(result_arr, 0, hasher.state[0])
  write_u32_le(result_arr, 4, hasher.state[1])
  write_u32_le(result_arr, 8, hasher.state[2])
  write_u32_le(result_arr, 12, hasher.state[3])
  Bytes::from_array(result_arr[:])
}

// ==================== SHA-256 Streaming ====================

///|
/// Incremental SHA-256 hasher. `w` is a reusable 64-word message-schedule
/// scratch shared by update/finalize (perf v0.21.0: zero per-block
/// allocation).
pub struct Sha256Hasher {
  state : Array[UInt]
  buffer : Array[Byte]
  w : Array[UInt]
  mut buf_len : Int
  mut total_len : UInt64
}

///|
/// Create a new SHA-256 hasher
pub fn sha256_new() -> Sha256Hasher {
  let state = Array::make(8, 0U)
  state[0] = 0x6a09e667U
  state[1] = 0xbb67ae85U
  state[2] = 0x3c6ef372U
  state[3] = 0xa54ff53aU
  state[4] = 0x510e527fU
  state[5] = 0x9b05688cU
  state[6] = 0x1f83d9abU
  state[7] = 0x5be0cd19U
  Sha256Hasher::{
    state,
    buffer: Array::make(64, b'\x00'),
    w: Array::make(64, 0U),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Fill `hasher.w[0..15]` from the internal byte buffer (no intermediate
/// Bytes allocation).
fn sha256_words_from_buffer(hasher : Sha256Hasher) -> Unit {
  let w = hasher.w
  let buf = hasher.buffer
  for j in 0..<=15 {
    w[j] = read_u32_be_arr(buf, j * 4)
  }
}

///|
/// Write the big-endian 64-bit bit count at `offset` in the internal buffer.
fn sha256_write_len(
  hasher : Sha256Hasher,
  offset : Int,
  bit_len : UInt64,
) -> Unit {
  let hi = ((bit_len >> 32) & 0xFFFFFFFFUL).to_uint()
  let lo = (bit_len & 0xFFFFFFFFUL).to_uint()
  hasher.buffer[offset] = ((hi >> 24) & 0xFFU).to_byte()
  hasher.buffer[offset + 1] = ((hi >> 16) & 0xFFU).to_byte()
  hasher.buffer[offset + 2] = ((hi >> 8) & 0xFFU).to_byte()
  hasher.buffer[offset + 3] = (hi & 0xFFU).to_byte()
  hasher.buffer[offset + 4] = ((lo >> 24) & 0xFFU).to_byte()
  hasher.buffer[offset + 5] = ((lo >> 16) & 0xFFU).to_byte()
  hasher.buffer[offset + 6] = ((lo >> 8) & 0xFFU).to_byte()
  hasher.buffer[offset + 7] = (lo & 0xFFU).to_byte()
}

///|
/// Feed data into the SHA-256 hasher
pub fn sha256_update(hasher : Sha256Hasher, data : Bytes) -> Unit {
  let data_len = data.length()
  if data_len == 0 {
    return
  }
  hasher.total_len = hasher.total_len + data_len.to_uint64()
  let mut data_offset = 0
  if hasher.buf_len > 0 {
    let space = 64 - hasher.buf_len
    let to_copy = if data_len < space { data_len } else { space }
    for i in 0..<to_copy {
      hasher.buffer[hasher.buf_len + i] = data[data_offset + i]
    }
    hasher.buf_len = hasher.buf_len + to_copy
    data_offset = data_offset + to_copy
    if hasher.buf_len == 64 {
      sha256_words_from_buffer(hasher)
      process_block(hasher.state, hasher.w)
      hasher.buf_len = 0
    }
  }
  let remaining = data_len - data_offset
  let num_full_blocks = remaining / 64
  let w = hasher.w
  for b in 0..<num_full_blocks {
    let offset = data_offset + b * 64
    for j in 0..<=15 {
      w[j] = read_u32_be(data, offset + j * 4)
    }
    process_block(hasher.state, w)
  }
  let rem_count = remaining - num_full_blocks * 64
  if rem_count > 0 {
    let rem_start = data_offset + num_full_blocks * 64
    for i in 0..<rem_count {
      hasher.buffer[i] = data[rem_start + i]
    }
    hasher.buf_len = rem_count
  }
}

///|
/// Feed a single byte into the SHA-256 hasher. For byte-at-a-time streams
/// this is much cheaper than `sha256_update(hasher, Bytes::make(1, byte))`:
/// no Bytes allocation and a minimal hot path (perf v0.21.0).
pub fn sha256_update_byte(hasher : Sha256Hasher, byte : Byte) -> Unit {
  hasher.total_len = hasher.total_len + 1UL
  let buf_len = hasher.buf_len
  hasher.buffer[buf_len] = byte
  if buf_len == 63 {
    hasher.buf_len = 64
    sha256_words_from_buffer(hasher)
    process_block(hasher.state, hasher.w)
    hasher.buf_len = 0
  } else {
    hasher.buf_len = buf_len + 1
  }
}

///|
/// Finalize and return the 32-byte SHA-256 digest. Pads in place inside the
/// hasher buffer (perf v0.21.0: no padded-array allocation).
fn sha256_finish_blocks(hasher : Sha256Hasher) -> Unit {
  let bit_len = hasher.total_len * 8UL
  let buf_len = hasher.buf_len
  if buf_len < 56 {
    // 0x80 + zeros + length all fit in the current block.
    hasher.buffer[buf_len] = b'\x80'
    for i in (buf_len + 1)..<56 {
      hasher.buffer[i] = b'\x00'
    }
    sha256_write_len(hasher, 56, bit_len)
    sha256_words_from_buffer(hasher)
    process_block(hasher.state, hasher.w)
  } else {
    // Need a second block for the length.
    hasher.buffer[buf_len] = b'\x80'
    for i in (buf_len + 1)..<64 {
      hasher.buffer[i] = b'\x00'
    }
    sha256_words_from_buffer(hasher)
    process_block(hasher.state, hasher.w)
    for i in 0..<56 {
      hasher.buffer[i] = b'\x00'
    }
    sha256_write_len(hasher, 56, bit_len)
    sha256_words_from_buffer(hasher)
    process_block(hasher.state, hasher.w)
  }
}

///|
pub fn sha256_finalize(hasher : Sha256Hasher) -> Bytes {
  sha256_finish_blocks(hasher)
  let result_arr = Array::make(32, b'\x00')
  for i in 0..<=7 {
    let val = hasher.state[i]
    result_arr[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result_arr[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result_arr[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result_arr[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  Bytes::from_array(result_arr[:])
}

///|
/// Finalize and return only the first `n` bytes of the digest (n <= 32).
/// Cheaper than `sha256_finalize` + truncation (one allocation). v0.34.0.
pub fn sha256_finalize_n(hasher : Sha256Hasher, n : Int) -> Bytes {
  sha256_finish_blocks(hasher)
  let result_arr = Array::make(n, b'\x00')
  for idx in 0..<n {
    let val = hasher.state[idx / 4]
    let shift = (3 - idx % 4) * 8
    result_arr[idx] = ((val >> shift) & 0xFFU).to_byte()
  }
  Bytes::from_array(result_arr[:])
}

// ==================== SHA-512 Streaming ====================

///|
/// Incremental SHA-512 hasher
pub struct Sha512Hasher {
  state : Array[UInt64]
  buffer : Array[Byte]
  mut buf_len : Int
  mut total_len : UInt64
}

///|
/// Create a new SHA-512 hasher
pub fn sha512_new() -> Sha512Hasher {
  let state = Array::make(8, 0UL)
  state[0] = 0x6a09e667f3bcc908UL
  state[1] = 0xbb67ae8584caa73bUL
  state[2] = 0x3c6ef372fe94f82bUL
  state[3] = 0xa54ff53a5f1d36f1UL
  state[4] = 0x510e527fade682d1UL
  state[5] = 0x9b05688c2b3e6c1fUL
  state[6] = 0x1f83d9abfb41bd6bUL
  state[7] = 0x5be0cd19137e2179UL
  Sha512Hasher::{
    state,
    buffer: Array::make(128, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-512 hasher
pub fn sha512_update(hasher : Sha512Hasher, data : Bytes) -> Unit {
  hasher.total_len = hasher.total_len + data.length().to_uint64()
  let data_len = data.length()
  let mut data_offset = 0
  if hasher.buf_len > 0 {
    let space = 128 - hasher.buf_len
    let to_copy = if data_len < space { data_len } else { space }
    for i in 0..<to_copy {
      hasher.buffer[hasher.buf_len + i] = data[data_offset + i]
    }
    hasher.buf_len = hasher.buf_len + to_copy
    data_offset = data_offset + to_copy
    if hasher.buf_len == 128 {
      let block = Array::make(16, 0UL)
      let buf_bytes = Bytes::from_array(hasher.buffer[:])
      for j in 0..<=15 {
        block[j] = read_u64_be(buf_bytes, j * 8)
      }
      sha512_process_block(hasher.state, block)
      hasher.buf_len = 0
    }
  }
  let remaining = data_len - data_offset
  let num_full_blocks = remaining / 128
  for b in 0..<num_full_blocks {
    let block = Array::make(16, 0UL)
    let offset = data_offset + b * 128
    for j in 0..<=15 {
      block[j] = read_u64_be(data, offset + j * 8)
    }
    sha512_process_block(hasher.state, block)
  }
  let rem_start = data_offset + num_full_blocks * 128
  let rem_count = remaining - num_full_blocks * 128
  if rem_count > 0 {
    for i in 0..<rem_count {
      hasher.buffer[i] = data[rem_start + i]
    }
    hasher.buf_len = rem_count
  }
}

///|
/// Finalize and return the 64-byte SHA-512 digest
fn sha512_finish_blocks(hasher : Sha512Hasher) -> Unit {
  let bit_len = hasher.total_len * 8UL
  let pad_len = 112 - hasher.buf_len % 128
  let pad_len_final = if pad_len <= 0 { pad_len + 128 } else { pad_len }
  let final_block_len = hasher.buf_len + pad_len_final + 16
  let padded = Array::make(final_block_len, b'\x00')
  for i in 0..<hasher.buf_len {
    padded[i] = hasher.buffer[i]
  }
  padded[hasher.buf_len] = b'\x80'
  // 128-bit length: high 64 bits = 0, low 64 bits = bit_len
  write_u64_be(padded, hasher.buf_len + pad_len_final, 0UL)
  write_u64_be(padded, hasher.buf_len + pad_len_final + 8, bit_len)
  let padded_bytes = Bytes::from_array(padded[:])
  let num_blocks = final_block_len / 128
  for i in 0..<num_blocks {
    let block = Array::make(16, 0UL)
    let offset = i * 128
    for j in 0..<=15 {
      block[j] = read_u64_be(padded_bytes, offset + j * 8)
    }
    sha512_process_block(hasher.state, block)
  }
}

///|
pub fn sha512_finalize(hasher : Sha512Hasher) -> Bytes {
  sha512_finish_blocks(hasher)
  let result_arr = Array::make(64, b'\x00')
  for i in 0..<=7 {
    write_u64_be(result_arr, i * 8, hasher.state[i])
  }
  Bytes::from_array(result_arr[:])
}

///|
/// Finalize and return only the first `n` bytes of the digest (n <= 64).
/// Cheaper than `sha512_finalize` + truncation (one allocation). v0.34.0.
pub fn sha512_finalize_n(hasher : Sha512Hasher, n : Int) -> Bytes {
  sha512_finish_blocks(hasher)
  let result_arr = Array::make(n, b'\x00')
  for idx in 0..<n {
    let word = hasher.state[idx / 8]
    let shift = (7 - idx % 8) * 8
    result_arr[idx] = ((word >> shift) & 0xFFUL).to_byte()
  }
  Bytes::from_array(result_arr[:])
}

// ==================== SHA-224 Streaming (FIPS 180-4) ====================
// SHA-224 = SHA-256 with a different IV, truncated to 28 bytes.

///|
/// Create a new SHA-224 hasher
pub fn sha224_new() -> Sha256Hasher {
  let state = Array::make(8, 0U)
  state[0] = 0xc1059ed8U
  state[1] = 0x367cd507U
  state[2] = 0x3070dd17U
  state[3] = 0xf70e5939U
  state[4] = 0xffc00b31U
  state[5] = 0x68581511U
  state[6] = 0x64f98fa7U
  state[7] = 0xbefa4fa4U
  Sha256Hasher::{
    state,
    buffer: Array::make(64, b'\x00'),
    w: Array::make(64, 0U),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-224 hasher (same compression as SHA-256)
pub fn sha224_update(hasher : Sha256Hasher, data : Bytes) -> Unit {
  sha256_update(hasher, data)
}

///|
/// Feed a single byte into the SHA-224 hasher (see `sha256_update_byte`)
pub fn sha224_update_byte(hasher : Sha256Hasher, byte : Byte) -> Unit {
  sha256_update_byte(hasher, byte)
}

///|
/// Finalize and return the 28-byte SHA-224 digest
pub fn sha224_finalize(hasher : Sha256Hasher) -> Bytes {
  // SHA-224 is SHA-256 with a different IV, truncated to 28 bytes (first 7 words)
  let full = sha256_finalize(hasher)
  let out = Array::make(28, b'\x00')
  for i in 0..<28 {
    out[i] = full[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHA-224 (FIPS 180-4), 28-byte digest
pub fn sha224(data : Bytes) -> Bytes {
  let hasher = sha224_new()
  sha224_update(hasher, data)
  sha224_finalize(hasher)
}

// ==================== SHA-384 Streaming (FIPS 180-4) ====================
// SHA-384 = SHA-512 with a different IV, truncated to 48 bytes.

///|
/// Create a new SHA-384 hasher
pub fn sha384_new() -> Sha512Hasher {
  let state = Array::make(8, 0UL)
  state[0] = 0xcbbb9d5dc1059ed8UL
  state[1] = 0x629a292a367cd507UL
  state[2] = 0x9159015a3070dd17UL
  state[3] = 0x152fecd8f70e5939UL
  state[4] = 0x67332667ffc00b31UL
  state[5] = 0x8eb44a8768581511UL
  state[6] = 0xdb0c2e0d64f98fa7UL
  state[7] = 0x47b5481dbefa4fa4UL
  Sha512Hasher::{
    state,
    buffer: Array::make(128, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-384 hasher (same compression as SHA-512)
pub fn sha384_update(hasher : Sha512Hasher, data : Bytes) -> Unit {
  sha512_update(hasher, data)
}

///|
/// Finalize and return the 48-byte SHA-384 digest
pub fn sha384_finalize(hasher : Sha512Hasher) -> Bytes {
  let full = sha512_finalize(hasher)
  let out = Array::make(48, b'\x00')
  for i in 0..<48 {
    out[i] = full[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Compute SHA-384 (FIPS 180-4), 48-byte digest
pub fn sha384(data : Bytes) -> Bytes {
  let hasher = sha384_new()
  sha384_update(hasher, data)
  sha384_finalize(hasher)
}

///|
/// Deep-copy a SHA-256 hasher so the copy can be finalized without
/// disturbing the original (useful for hashing many messages that share
/// a common prefix). v0.32.0.
pub fn sha256_clone(hasher : Sha256Hasher) -> Sha256Hasher {
  let state = Array::make(8, 0U)
  for i in 0..<8 {
    state[i] = hasher.state[i]
  }
  let buffer = Array::make(64, b'\x00')
  for i in 0..<64 {
    buffer[i] = hasher.buffer[i]
  }
  let w = Array::make(64, 0U)
  for i in 0..<64 {
    w[i] = hasher.w[i]
  }
  Sha256Hasher::{
    state,
    buffer,
    w,
    buf_len: hasher.buf_len,
    total_len: hasher.total_len,
  }
}

///|
/// Deep-copy a SHA-512 hasher (see `sha256_clone`). v0.32.0.
pub fn sha512_clone(hasher : Sha512Hasher) -> Sha512Hasher {
  let state = Array::make(8, 0UL)
  for i in 0..<8 {
    state[i] = hasher.state[i]
  }
  let buffer = Array::make(128, b'\x00')
  for i in 0..<128 {
    buffer[i] = hasher.buffer[i]
  }
  Sha512Hasher::{
    state,
    buffer,
    buf_len: hasher.buf_len,
    total_len: hasher.total_len,
  }
}
