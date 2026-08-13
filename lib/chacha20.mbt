// ==================== ChaCha20 (RFC 8439) ====================

///|
/// ChaCha20 quarter round — operates on 4 words in place
fn chacha_quarter_round(
  state : Array[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
) -> Unit {
  state[a] = state[a] + state[b]
  state[d] = state[d] ^ state[a]
  state[d] = (state[d] << 16) | (state[d] >> 16)
  state[c] = state[c] + state[d]
  state[b] = state[b] ^ state[c]
  state[b] = (state[b] << 12) | (state[b] >> 20)
  state[a] = state[a] + state[b]
  state[d] = state[d] ^ state[a]
  state[d] = (state[d] << 8) | (state[d] >> 24)
  state[c] = state[c] + state[d]
  state[b] = state[b] ^ state[c]
  state[b] = (state[b] << 7) | (state[b] >> 25)
}

///|
/// ChaCha20 encrypt/decrypt (RFC 8439). XOR is symmetric — same function for both directions.
/// key: 32 bytes, nonce: 12 bytes, counter: initial block counter (usually 0).
/// v0.18.0 perf: the base state (constants + key + nonce words) is built
/// once per call and the 16-word working array is reused across blocks,
/// instead of re-parsing the key/nonce and allocating two arrays per block.
pub fn chacha20_xor(
  input : Bytes,
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
) -> Bytes {
  if key.length() != 32 {
    abort("chacha20_xor: key length must be 32 bytes (256 bits)")
  }
  if nonce.length() != 12 {
    abort("chacha20_xor: nonce length must be 12 bytes (96 bits)")
  }
  // Base state: constants + key (8 words) + nonce (3 words), built once
  let base = Array::make(16, 0U)
  base[0] = 0x61707865U
  base[1] = 0x3320646eU
  base[2] = 0x79622d32U
  base[3] = 0x6b206574U
  for i in 0..<=7 {
    base[4 + i] = read_u32_le(key, i * 4)
  }
  base[13] = read_u32_le(nonce, 0)
  base[14] = read_u32_le(nonce, 4)
  base[15] = read_u32_le(nonce, 8)
  let working = Array::make(16, 0U)
  let len = input.length()
  let output = Array::make(len, b'\x00')
  let num_blocks = (len + 63) / 64
  for block_idx in 0..<num_blocks {
    // keystream block = chacha(base with counter)
    base[12] = counter + block_idx.reinterpret_as_uint()
    for i in 0..<=15 {
      working[i] = base[i]
    }
    for _ in 0..<10 {
      chacha_quarter_round(working, 0, 4, 8, 12)
      chacha_quarter_round(working, 1, 5, 9, 13)
      chacha_quarter_round(working, 2, 6, 10, 14)
      chacha_quarter_round(working, 3, 7, 11, 15)
      chacha_quarter_round(working, 0, 5, 10, 15)
      chacha_quarter_round(working, 1, 6, 11, 12)
      chacha_quarter_round(working, 2, 7, 8, 13)
      chacha_quarter_round(working, 3, 4, 9, 14)
    }
    // XOR keystream words into input (final block may be partial)
    let input_offset = block_idx * 64
    let avail = len - input_offset
    for i in 0..<=15 {
      let word_start = i * 4
      if word_start >= avail {
        break
      }
      let ks_word = working[i] + base[i]
      let take = if avail - word_start < 4 { avail - word_start } else { 4 }
      if take >= 1 {
        output[input_offset + word_start] = (input[input_offset + word_start].to_uint() ^
        (ks_word & 0xFFU)).to_byte()
      }
      if take >= 2 {
        output[input_offset + word_start + 1] = (input[input_offset +
        word_start +
        1].to_uint() ^
        ((ks_word >> 8) & 0xFFU)).to_byte()
      }
      if take >= 3 {
        output[input_offset + word_start + 2] = (input[input_offset +
        word_start +
        2].to_uint() ^
        ((ks_word >> 16) & 0xFFU)).to_byte()
      }
      if take >= 4 {
        output[input_offset + word_start + 3] = (input[input_offset +
        word_start +
        3].to_uint() ^
        ((ks_word >> 24) & 0xFFU)).to_byte()
      }
    }
  }
  Bytes::from_array(output[:])
}
