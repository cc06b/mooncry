// ==================== SHA-1 (FIPS 180-4) ====================
// 160-bit hash. Mirrors the SHA-256 streaming structure; uses left rotation
// (ROTL) and 80 rounds. Verified against Python `hashlib.sha1` + RFC 1321.

///|
pub struct Sha1Hasher {
  state : Array[UInt]
  buffer : Array[Byte]
  mut buf_len : Int
  mut total_len : UInt64
}

///|
/// Create a new SHA-1 hasher with the standard IV.
pub fn sha1_new() -> Sha1Hasher {
  let state = Array::make(5, 0U)
  state[0] = 0x67452301U
  state[1] = 0xefcdab89U
  state[2] = 0x98badcfeU
  state[3] = 0x10325476U
  state[4] = 0xc3d2e1f0U
  Sha1Hasher::{
    state,
    buffer: Array::make(64, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
fn sha1_write_u32_be(out : Array[Byte], offset : Int, v : UInt) -> Unit {
  out[offset] = ((v >> 24) & 0xFFU).to_byte()
  out[offset + 1] = ((v >> 16) & 0xFFU).to_byte()
  out[offset + 2] = ((v >> 8) & 0xFFU).to_byte()
  out[offset + 3] = (v & 0xFFU).to_byte()
}

///|
/// SHA-1 compression: process one 64-byte block.
fn sha1_process_block(state : Array[UInt], block : Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  // message schedule
  let w = Array::make(80, 0U)
  for i in 0..<16 {
    w[i] = block[i]
  }
  for t in 16..<80 {
    w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
  }
  for t in 0..<80 {
    let (f, k) = if t < 20 {
      ((b & c) | ((b ^ 0xFFFFFFFFU) & d), 0x5A827999U)
    } else if t < 40 {
      (b ^ c ^ d, 0x6ED9EBA1U)
    } else if t < 60 {
      ((b & c) | (b & d) | (c & d), 0x8F1BBCDCU)
    } else {
      (b ^ c ^ d, 0xCA62C1D6U)
    }
    let temp = (rotl32(a, 5) + f + e + k + w[t]) & 0xFFFFFFFFU
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = temp
  }
  state[0] = (state[0] + a) & 0xFFFFFFFFU
  state[1] = (state[1] + b) & 0xFFFFFFFFU
  state[2] = (state[2] + c) & 0xFFFFFFFFU
  state[3] = (state[3] + d) & 0xFFFFFFFFU
  state[4] = (state[4] + e) & 0xFFFFFFFFU
}

///|
/// Feed data into the SHA-1 hasher.
pub fn sha1_update(hasher : Sha1Hasher, data : Bytes) -> Unit {
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
      for j in 0..<16 {
        block[j] = read_u32_be(Bytes::from_array(hasher.buffer[:]), j * 4)
      }
      sha1_process_block(hasher.state, block)
      hasher.buf_len = 0
    }
  }
  let remaining = data_len - data_offset
  let num_full_blocks = remaining / 64
  for b in 0..<num_full_blocks {
    let block = Array::make(16, 0U)
    let offset = data_offset + b * 64
    for j in 0..<16 {
      block[j] = read_u32_be(data, offset + j * 4)
    }
    sha1_process_block(hasher.state, block)
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
/// Finalize and return the 20-byte SHA-1 digest.
pub fn sha1_finalize(hasher : Sha1Hasher) -> Bytes {
  let bit_len = hasher.total_len * 8UL
  let pad_len = 56 - hasher.buf_len % 64
  let pad_len_final = if pad_len <= 0 { pad_len + 64 } else { pad_len }
  let final_block_len = hasher.buf_len + pad_len_final + 8
  let padded = Array::make(final_block_len, b'\x00')
  for i in 0..<hasher.buf_len {
    padded[i] = hasher.buffer[i]
  }
  padded[hasher.buf_len] = b'\x80'
  // length as 64-bit big-endian
  let hi = (bit_len >> 32) & 0xFFFFFFFFUL
  let lo = bit_len & 0xFFFFFFFFUL
  sha1_write_u32_be(padded, final_block_len - 8, hi.to_uint())
  sha1_write_u32_be(padded, final_block_len - 4, lo.to_uint())
  let mut off = 0
  while off < final_block_len {
    let block = Array::make(16, 0U)
    for j in 0..<16 {
      block[j] = read_u32_be(Bytes::from_array(padded[:]), off + j * 4)
    }
    sha1_process_block(hasher.state, block)
    off = off + 64
  }
  let out = Array::make(20, b'\x00')
  for i in 0..<5 {
    sha1_write_u32_be(out, i * 4, hasher.state[i])
  }
  Bytes::from_array(out[:])
}

///|
/// SHA-1 one-shot (FIPS 180-4), 20-byte digest.
pub fn sha1(data : Bytes) -> Bytes {
  let h = sha1_new()
  sha1_update(h, data)
  sha1_finalize(h)
}

///|
/// HMAC-SHA1 (RFC 2104), 20-byte tag. Block size 64.
pub fn hmac_sha1(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 64
  let k_prime = if key.length() > block_size {
    let padded = Array::make(block_size, b'\x00')
    let h = sha1_new()
    sha1_update(h, key)
    let digest = sha1_finalize(h)
    for i in 0..<20 {
      padded[i] = digest[i]
    }
    Bytes::from_array(padded[:])
  } else {
    let padded = Array::make(block_size, b'\x00')
    for i in 0..<key.length() {
      padded[i] = key[i]
    }
    Bytes::from_array(padded[:])
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  let inner_h = sha1_new()
  sha1_update(inner_h, ipad)
  sha1_update(inner_h, message)
  let inner = sha1_finalize(inner_h)
  let outer_h = sha1_new()
  sha1_update(outer_h, opad)
  sha1_update(outer_h, inner)
  sha1_finalize(outer_h)
}
