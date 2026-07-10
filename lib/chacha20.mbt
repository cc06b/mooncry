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
/// ChaCha20 block function — produces 64 bytes of keystream
fn chacha20_block(key : Bytes, counter : UInt, nonce : Bytes) -> Array[UInt] {
  // Initialize state: "expand 32-byte k" + key(8) + counter + nonce(3)
  let state = Array::make(16, 0U)
  // Constants
  state[0] = 0x61707865U // "expa"
  state[1] = 0x3320646eU // "nd 3"
  state[2] = 0x79622d32U // "2-by"
  state[3] = 0x6b206574U // "te k"
  // Key (8 words, little-endian)
  for i in 0..<=7 {
    state[4 + i] = read_u32_le(key, i * 4)
  }
  // Counter
  state[12] = counter
  // Nonce (3 words, little-endian)
  state[13] = read_u32_le(nonce, 0)
  state[14] = read_u32_le(nonce, 4)
  state[15] = read_u32_le(nonce, 8)
  // Working copy
  let working = Array::make(16, 0U)
  for i in 0..<=15 {
    working[i] = state[i]
  }
  // 20 rounds = 10 * (column round + diagonal round)
  for _ in 0..<10 {
    // Column rounds
    chacha_quarter_round(working, 0, 4, 8, 12)
    chacha_quarter_round(working, 1, 5, 9, 13)
    chacha_quarter_round(working, 2, 6, 10, 14)
    chacha_quarter_round(working, 3, 7, 11, 15)
    // Diagonal rounds
    chacha_quarter_round(working, 0, 5, 10, 15)
    chacha_quarter_round(working, 1, 6, 11, 12)
    chacha_quarter_round(working, 2, 7, 8, 13)
    chacha_quarter_round(working, 3, 4, 9, 14)
  }
  // Add original state to working state
  for i in 0..<=15 {
    working[i] = working[i] + state[i]
  }
  working
}

///|
/// ChaCha20 encrypt/decrypt (RFC 8439). XOR is symmetric — same function for both directions.
/// key: 32 bytes, nonce: 12 bytes, counter: initial block counter (usually 0)
pub fn chacha20_xor(
  input : Bytes,
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
) -> Bytes {
  let len = input.length()
  let output = Array::make(len, b'\x00')
  let num_full_blocks = len / 64
  let remainder = len % 64
  // Process full 64-byte blocks
  for block_idx in 0..<num_full_blocks {
    let keystream_words = chacha20_block(
      key,
      counter + block_idx.reinterpret_as_uint(),
      nonce,
    )
    let input_offset = block_idx * 64
    for i in 0..<=15 {
      let ks_word = keystream_words[i]
      let word_offset = input_offset + i * 4
      output[word_offset] = (input[word_offset].to_uint() ^ (ks_word & 0xFFU)).to_byte()
      output[word_offset + 1] = (input[word_offset + 1].to_uint() ^
      ((ks_word >> 8) & 0xFFU)).to_byte()
      output[word_offset + 2] = (input[word_offset + 2].to_uint() ^
      ((ks_word >> 16) & 0xFFU)).to_byte()
      output[word_offset + 3] = (input[word_offset + 3].to_uint() ^
      ((ks_word >> 24) & 0xFFU)).to_byte()
    }
  }
  // Process remaining bytes
  if remainder > 0 {
    let keystream_words = chacha20_block(
      key,
      counter + num_full_blocks.reinterpret_as_uint(),
      nonce,
    )
    let input_offset = num_full_blocks * 64
    let mut byte_idx = 0
    for i in 0..<=15 {
      if byte_idx >= remainder {
        break
      }
      let ks_word = keystream_words[i]
      let shift = [0, 8, 16, 24]
      for j in 0..<=3 {
        if byte_idx >= remainder {
          break
        }
        let ks_byte = ((ks_word >> shift[j]) & 0xFFU).to_byte()
        output[input_offset + byte_idx] = (input[input_offset + byte_idx].to_uint() ^
        ks_byte.to_uint()).to_byte()
        byte_idx = byte_idx + 1
      }
    }
  }
  Bytes::from_array(output[:])
}
