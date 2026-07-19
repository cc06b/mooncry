// ==================== SHA-3 Streaming (FIPS 202) ====================
// Incremental update/finalize for SHA3-224/256/384/512. Reuses the
// Keccak-f permutation + state layout from sha3.mbt.

///|
/// Streaming SHA-3 hasher. `rate`/`out_len`/`domain` are fixed per variant.
pub struct Sha3Hasher {
  state : Array[Array[UInt64]]
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
    let x = i % 5
    let y = i / 5
    h.state[x][y] = h.state[x][y] ^ read_lane_le(h.buffer, i * 8)
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
/// and squeeze `out_len` bytes.
pub fn sha3_finalize(h : Sha3Hasher) -> Bytes {
  // Clear the unused tail (leftover from a previous absorbed block).
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  // pad10*1: domain suffix at buf_len, 0x80 at the last byte of the rate.
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  // squeeze
  let out = Array::make(h.out_len, b'\x00')
  let mut out_off = 0
  let mut lane_idx = 0
  while out_off < h.out_len {
    let x = lane_idx % 5
    let y = lane_idx / 5
    let lane = h.state[x][y]
    for bi in 0..<8 {
      if out_off >= h.out_len {
        break
      }
      out[out_off] = ((lane >> (bi * 8)) & 0xFFUL).to_byte()
      out_off = out_off + 1
    }
    lane_idx = lane_idx + 1
    if lane_idx >= 25 && out_off < h.out_len {
      keccak_f(h.state)
      lane_idx = 0
    }
  }
  Bytes::from_array(out[:])
}

///|
pub fn sha3_224_new() -> Sha3Hasher {
  sha3_new(144, 28, 0x06)
}

///|
pub fn sha3_256_new() -> Sha3Hasher {
  sha3_new(136, 32, 0x06)
}

///|
pub fn sha3_384_new() -> Sha3Hasher {
  sha3_new(104, 48, 0x06)
}

///|
pub fn sha3_512_new() -> Sha3Hasher {
  sha3_new(72, 64, 0x06)
}
