// ============================================================
// Keyed BLAKE2b / BLAKE2s (RFC 7693 §2.6). The key (padded to one
// block) is processed as the first data block and the key length is
// encoded in the parameter word. Reuses the compression functions
// from blake2.mbt / blake2s.mbt.
// ============================================================

///|
/// Keyed BLAKE2b (RFC 7693): MAC / keyed hash with a 1..64-byte key
/// and `out_len` 1..64 bytes.
pub fn blake2b_keyed(data : Bytes, key : Bytes, out_len : Int) -> Bytes {
  if key.length() < 1 || key.length() > 64 {
    abort("blake2b_keyed: key must be 1..64 bytes")
  }
  if out_len < 1 || out_len > 64 {
    abort("blake2b_keyed: out_len must be in 1..64")
  }
  let h = Array::make(8, 0UL)
  for i in 0..<=7 {
    h[i] = blake2b_iv[i]
  }
  // parameter block: fanout=1, depth=1, key length kk, digest size nn
  h[0] = h[0] ^
    (0x01010000UL + (key.length().to_uint64() << 8) + out_len.to_uint64())
  // first block: key zero-padded to 128 bytes
  let key_padded = Array::make(128, b'\x00')
  for i in 0..<key.length() {
    key_padded[i] = key[i]
  }
  let key_bytes = Bytes::from_array(key_padded[:])
  let key_block = Array::make(16, 0UL)
  for i in 0..<=15 {
    key_block[i] = blake2b_read_lane(key_bytes, i * 8)
  }
  let len = data.length()
  if len == 0 {
    blake2b_compress(h, key_block, 128UL, true)
  } else {
    blake2b_compress(h, key_block, 128UL, false)
    let mut t = 128UL
    let mut offset = 0
    while offset + 128 <= len {
      let block = Array::make(16, 0UL)
      for i in 0..<=15 {
        block[i] = blake2b_read_lane(data, offset + i * 8)
      }
      t = t + 128UL
      blake2b_compress(h, block, t, false)
      offset = offset + 128
    }
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
  }
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

///|
/// Keyed BLAKE2s (RFC 7693): MAC / keyed hash with a 1..32-byte key
/// and `out_len` 1..32 bytes.
pub fn blake2s_keyed(data : Bytes, key : Bytes, out_len : Int) -> Bytes {
  if key.length() < 1 || key.length() > 32 {
    abort("blake2s_keyed: key must be 1..32 bytes")
  }
  if out_len < 1 || out_len > 32 {
    abort("blake2s_keyed: out_len must be in 1..32")
  }
  let h = Array::make(8, 0U)
  for i in 0..<=7 {
    h[i] = blake2s_iv[i]
  }
  h[0] = h[0] ^
    (
      0x01010000U +
      (key.length().reinterpret_as_uint() << 8) +
      out_len.reinterpret_as_uint()
    )
  // first block: key zero-padded to 64 bytes
  let key_padded = Array::make(64, b'\x00')
  for i in 0..<key.length() {
    key_padded[i] = key[i]
  }
  let key_bytes = Bytes::from_array(key_padded[:])
  let key_block = Array::make(16, 0U)
  for i in 0..<=15 {
    key_block[i] = blake2s_read_word(key_bytes, i * 4)
  }
  let len = data.length()
  if len == 0 {
    blake2s_compress(h, key_block, 64UL, true)
  } else {
    blake2s_compress(h, key_block, 64UL, false)
    let mut t = 64UL
    let mut offset = 0
    while offset + 64 <= len {
      let block = Array::make(16, 0U)
      for i in 0..<=15 {
        block[i] = blake2s_read_word(data, offset + i * 4)
      }
      t = t + 64UL
      blake2s_compress(h, block, t, false)
      offset = offset + 64
    }
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
  }
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
