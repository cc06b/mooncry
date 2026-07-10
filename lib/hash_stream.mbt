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
/// Incremental SHA-256 hasher
pub struct Sha256Hasher {
  state : Array[UInt]
  buffer : Array[Byte]
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
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Feed data into the SHA-256 hasher
pub fn sha256_update(hasher : Sha256Hasher, data : Bytes) -> Unit {
  hasher.total_len = hasher.total_len + data.length().to_uint64()
  let data_len = data.length()
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
      let block = Array::make(16, 0U)
      let buf_bytes = Bytes::from_array(hasher.buffer[:])
      for j in 0..<=15 {
        block[j] = read_u32_be(buf_bytes, j * 4)
      }
      process_block(hasher.state, block)
      hasher.buf_len = 0
    }
  }
  let remaining = data_len - data_offset
  let num_full_blocks = remaining / 64
  for b in 0..<num_full_blocks {
    let block = Array::make(16, 0U)
    let offset = data_offset + b * 64
    for j in 0..<=15 {
      block[j] = read_u32_be(data, offset + j * 4)
    }
    process_block(hasher.state, block)
  }
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
/// Finalize and return the 32-byte SHA-256 digest
pub fn sha256_finalize(hasher : Sha256Hasher) -> Bytes {
  let bit_len = hasher.total_len * 8UL
  let pad_len = 56 - hasher.buf_len % 64
  let pad_len_final = if pad_len <= 0 { pad_len + 64 } else { pad_len }
  let final_block_len = hasher.buf_len + pad_len_final + 8
  let padded = Array::make(final_block_len, b'\x00')
  for i in 0..<hasher.buf_len {
    padded[i] = hasher.buffer[i]
  }
  padded[hasher.buf_len] = b'\x80'
  // Big-endian 64-bit length
  let hi = ((bit_len >> 32) & 0xFFFFFFFFUL).to_uint()
  let lo = (bit_len & 0xFFFFFFFFUL).to_uint()
  let len_offset = hasher.buf_len + pad_len_final
  padded[len_offset] = ((hi >> 24) & 0xFFU).to_byte()
  padded[len_offset + 1] = ((hi >> 16) & 0xFFU).to_byte()
  padded[len_offset + 2] = ((hi >> 8) & 0xFFU).to_byte()
  padded[len_offset + 3] = (hi & 0xFFU).to_byte()
  padded[len_offset + 4] = ((lo >> 24) & 0xFFU).to_byte()
  padded[len_offset + 5] = ((lo >> 16) & 0xFFU).to_byte()
  padded[len_offset + 6] = ((lo >> 8) & 0xFFU).to_byte()
  padded[len_offset + 7] = (lo & 0xFFU).to_byte()
  let padded_bytes = Bytes::from_array(padded[:])
  let num_blocks = final_block_len / 64
  for i in 0..<num_blocks {
    let block = Array::make(16, 0U)
    let offset = i * 64
    for j in 0..<=15 {
      block[j] = read_u32_be(padded_bytes, offset + j * 4)
    }
    process_block(hasher.state, block)
  }
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
pub fn sha512_finalize(hasher : Sha512Hasher) -> Bytes {
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
  let result_arr = Array::make(64, b'\x00')
  for i in 0..<=7 {
    write_u64_be(result_arr, i * 8, hasher.state[i])
  }
  Bytes::from_array(result_arr[:])
}
