// ==================== SHA-3 Streaming (FIPS 202) ====================
// Incremental update/finalize for SHA3-224/256/384/512. Reuses the
// Keccak-f permutation + state layout from sha3.mbt.

///|
/// Streaming SHA-3 hasher. `rate`/`out_len`/`domain` are fixed per variant.
pub struct Sha3Hasher {
  state : Array[UInt64]
  buffer : Array[Byte]
  mut buf_len : Int
  rate : Int
  domain : Int
  out_len : Int
}

///|
fn sha3_new(rate : Int, out_len : Int, domain : Int) -> Sha3Hasher {
  Sha3Hasher::{
    state: new_state(),
    buffer: Array::make(rate, b'\x00'),
    buf_len: 0,
    rate,
    domain,
    out_len,
  }
}

///|
/// Absorb one full rate-block from `buffer` into `state`, then permute.
fn sha3_absorb_block(h : Sha3Hasher) -> Unit {
  let lanes = h.rate / 8
  for i in 0..<lanes {
    h.state[i] = h.state[i] ^ read_lane_le(h.buffer, i * 8)
  }
  keccak_f(h.state)
}

///|
/// Feed more input bytes into the hasher. Blocks are absorbed as soon as the
/// internal buffer fills to `rate` bytes.
pub fn sha3_update(h : Sha3Hasher, data : Bytes) -> Unit {
  let mut off = 0
  let len = data.length()
  while off < len {
    let space = h.rate - h.buf_len
    let take = if space < len - off { space } else { len - off }
    for i in 0..<take {
      h.buffer[h.buf_len + i] = data[off + i]
    }
    h.buf_len = h.buf_len + take
    off = off + take
    if h.buf_len == h.rate {
      sha3_absorb_block(h)
      h.buf_len = 0
    }
  }
}

///|
/// Finalize: apply the domain-separation/padding, absorb the last block,
/// and squeeze `out_len` bytes. This *consumes* the hasher — the padding is
/// XORed into its buffer in place — so a second call, or a `sha3_update`
/// after it, produces an unrelated digest with no error. Fork with
/// `sha3_clone` before finalizing.
pub fn sha3_finalize(h : Sha3Hasher) -> Bytes {
  // Clear the unused tail (leftover from a previous absorbed block).
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  // pad10*1: domain suffix at buf_len, 0x80 at the last byte of the rate.
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  // squeeze: read rate/8 lanes per permutation round
  let out = Array::make(h.out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < h.out_len {
    let lane = h.state[lane_idx]
    for bi in 0..<8 {
      if out_off >= h.out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= h.rate / 8 && out_off < h.out_len {
      keccak_f(h.state)
      lane_idx = 0
    }
  }
  Bytes::from_array(out[:])
}

///|
/// Streaming SHA3-224: rate 144 bytes, 28-byte output, domain suffix 0x06.
/// Feed with `sha3_update`, finish with `sha3_finalize`.
pub fn sha3_224_new() -> Sha3Hasher {
  sha3_new(144, 28, 0x06)
}

///|
/// Streaming SHA3-256: rate 136, 32-byte output, domain 0x06.
pub fn sha3_256_new() -> Sha3Hasher {
  sha3_new(136, 32, 0x06)
}

///|
/// Streaming SHA3-384: rate 104, 48-byte output, domain 0x06.
pub fn sha3_384_new() -> Sha3Hasher {
  sha3_new(104, 48, 0x06)
}

///|
/// Streaming SHA3-512: rate 72, 64-byte output, domain 0x06.
pub fn sha3_512_new() -> Sha3Hasher {
  sha3_new(72, 64, 0x06)
}

// ==================== SHAKE Streaming (FIPS 202 XOF) ====================

///|
/// Squeeze `out_len` bytes from the sponge (variable-length output).
fn sha3_squeeze(h : Sha3Hasher, out_len : Int) -> Bytes {
  shake_check_out_len(out_len)
  let out = Array::make(out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < out_len {
    let lane = h.state[lane_idx]
    for bi in 0..<8 {
      if out_off >= out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= h.rate / 8 && out_off < out_len {
      keccak_f(h.state)
      lane_idx = 0
    }
  }
  Bytes::from_array(out[:])
}

///|
/// Streaming SHAKE128: rate 168, domain 0x1F, and no fixed output length --
/// `shake_finalize(h, out_len)` squeezes as much as you ask for.
pub fn shake_128_new() -> Sha3Hasher {
  sha3_new(168, 0, 0x1F)
}

///|
/// Streaming SHAKE256: rate 136, domain 0x1F, output length chosen at
/// `shake_finalize`.
pub fn shake_256_new() -> Sha3Hasher {
  sha3_new(136, 0, 0x1F)
}

///|
/// Finalize a SHAKE hasher and squeeze `out_len` bytes (domain 0x1F, XOF).
/// `out_len` must be non-negative. Like every finalize here, this consumes the
/// hasher: see the single-use note in the README.
pub fn shake_finalize(h : Sha3Hasher, out_len : Int) -> Bytes {
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  sha3_squeeze(h, out_len)
}

///|
/// Deep-copy a SHA-3/SHAKE hasher so the copy can be finalized without
/// disturbing the original (useful for hashing many messages that share
/// a common prefix). v0.32.0.
pub fn sha3_clone(h : Sha3Hasher) -> Sha3Hasher {
  let state = Array::make(25, 0UL)
  for i in 0..<25 {
    state[i] = h.state[i]
  }
  let buffer = Array::make(h.rate, b'\x00')
  for i in 0..<h.rate {
    buffer[i] = h.buffer[i]
  }
  Sha3Hasher::{
    state,
    buffer,
    buf_len: h.buf_len,
    rate: h.rate,
    domain: h.domain,
    out_len: h.out_len,
  }
}
