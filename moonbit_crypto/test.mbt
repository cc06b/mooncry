// MoonBit Crypto Library
// SHA-256 and HMAC-SHA256 Implementation with test vectors

/// Right rotate for 32-bit unsigned integers
fn rotr(x: UInt, n: Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

/// Lower sigma 0
fn sig0(x: UInt) -> UInt {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Lower sigma 1
fn sig1(x: UInt) -> UInt {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// Upper sigma 0
fn cap_sig0(x: UInt) -> UInt {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Upper sigma 1
fn cap_sig1(x: UInt) -> UInt {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Choice function
fn ch(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ ((0xFFFFFFFFU ^ x) & z)
}

/// Majority function
fn maj(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 constants
fn get_k() -> Array[UInt] {
  [
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
  ]
}

/// Process one 512-bit block
fn process_block(state: Array[UInt], block: Array[UInt]) -> Unit {
  let k = get_k()
  
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  
  let w = Array::make(64, 0U)
  
  for i in 0..<=15 {
    w[i] = block[i]
  }
  
  for i in 16..<=63 {
    w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16]
  }
  
  for i in 0..<=63 {
    let t1 = h + cap_sig1(e) + ch(e, f, g) + k[i] + w[i]
    let t2 = cap_sig0(a) + maj(a, b, c)
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

/// Read 4 bytes as big-endian UInt
fn read_u32_be(data: Bytes, offset: Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

/// Pad the input message for SHA-256
fn pad_message(data: Bytes) -> Array[Byte] {
  let original_len = data.length()
  let bit_len = original_len * 8
  let pad_len = 64 - ((original_len + 9) % 64)
  let final_len = original_len + 9 + pad_len
  
  let padded = Array::make(final_len, b'\x00')
  
  for i in 0..<original_len {
    padded[i] = data[i]
  }
  
  padded[original_len] = b'\x80'
  
  let bit_len_u64 = bit_len.to_uint64()
  padded[original_len + 1 + pad_len] = ((bit_len_u64 >> 56) & 0xFFUL).to_byte()
  padded[original_len + 2 + pad_len] = ((bit_len_u64 >> 48) & 0xFFUL).to_byte()
  padded[original_len + 3 + pad_len] = ((bit_len_u64 >> 40) & 0xFFUL).to_byte()
  padded[original_len + 4 + pad_len] = ((bit_len_u64 >> 32) & 0xFFUL).to_byte()
  padded[original_len + 5 + pad_len] = ((bit_len_u64 >> 24) & 0xFFUL).to_byte()
  padded[original_len + 6 + pad_len] = ((bit_len_u64 >> 16) & 0xFFUL).to_byte()
  padded[original_len + 7 + pad_len] = ((bit_len_u64 >> 8) & 0xFFUL).to_byte()
  padded[original_len + 8 + pad_len] = (bit_len_u64 & 0xFFUL).to_byte()
  
  padded
}

/// Compute SHA-256 hash
pub fn sha256(data: Bytes) -> Bytes {
  let state = Array::make(8, 0U)
  state[0] = 0x6a09e667U
  state[1] = 0xbb67ae85U
  state[2] = 0x3c6ef372U
  state[3] = 0xa54ff53aU
  state[4] = 0x510e527fU
  state[5] = 0x9b05688cU
  state[6] = 0x1f83d9abU
  state[7] = 0x5be0cd19U
  
  let padded_arr = pad_message(data)
  let padded = Bytes::from_array(padded_arr[:])
  let num_blocks = padded.length() / 64
  
  for i in 0..<num_blocks {
    let block = Array::make(16, 0U)
    let offset = i * 64
    for j in 0..<=15 {
      block[j] = read_u32_be(padded, offset + j * 4)
    }
    process_block(state, block)
  }
  
  let result_arr = Array::make(32, b'\x00')
  for i in 0..<=7 {
    let val = state[i]
    result_arr[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result_arr[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result_arr[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result_arr[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  
  Bytes::from_array(result_arr[:])
}

/// Create a byte array with same value repeated
fn repeat_byte(byte: Byte, count: Int) -> Array[Byte] {
  let result = Array::make(count, b'\x00')
  for i in 0..<count {
    result[i] = byte
  }
  result
}

/// XOR two Bytes arrays
fn xor_bytes(a: Bytes, b: Bytes) -> Array[Byte] {
  let len = a.length()
  let result = Array::make(len, b'\x00')
  for i in 0..<len {
    let val_a = a[i].to_int()
    let val_b = b[i].to_int()
    result[i] = (val_a ^ val_b).to_byte()
  }
  result
}

/// Concatenate two Bytes
fn concat_bytes(a: Bytes, b: Bytes) -> Bytes {
  let len_a = a.length()
  let len_b = b.length()
  let result = Array::make(len_a + len_b, b'\x00')
  for i in 0..<len_a {
    result[i] = a[i]
  }
  for i in 0..<len_b {
    result[len_a + i] = b[i]
  }
  Bytes::from_array(result[:])
}

/// HMAC-SHA256 implementation
pub fn hmac_sha256(key: Bytes, message: Bytes) -> Bytes {
  let block_size = 64 // SHA-256 block size is 512 bits = 64 bytes
  
  // Prepare the key
  let k_prime = if key.length() > block_size {
    sha256(key)
  } else {
    let padded = Array::make(block_size, b'\x00')
    for i in 0..<key.length() {
      padded[i] = key[i]
    }
    Bytes::from_array(padded[:])
  }
  
  // Create ipad and opad
  let ipad_arr = repeat_byte(b'\x36', block_size)
  let opad_arr = repeat_byte(b'\x5c', block_size)
  let ipad = Bytes::from_array(ipad_arr[:])
  let opad = Bytes::from_array(opad_arr[:])
  
  // Compute inner hash: H((K' ^ ipad) || message)
  let inner_key_xor = xor_bytes(k_prime, ipad)
  let inner_key_bytes = Bytes::from_array(inner_key_xor[:])
  let inner_input = concat_bytes(inner_key_bytes, message)
  let inner_hash = sha256(inner_input)
  
  // Compute outer hash: H((K' ^ opad) || inner_hash)
  let outer_key_xor = xor_bytes(k_prime, opad)
  let outer_key_bytes = Bytes::from_array(outer_key_xor[:])
  let outer_input = concat_bytes(outer_key_bytes, inner_hash)
  
  sha256(outer_input)
}

/// Convert Bytes to hex string
pub fn bytes_to_hex(data: Bytes) -> String {
  let hex_chars = "0123456789abcdef"
  let mut result = ""
  for i in 0..<data.length() {
    let byte = data[i].to_int()
    let high = (byte >> 4) & 0xF
    let low = byte & 0xF
    let high_char = ((hex_chars[high].to_int()).to_char()).unwrap()
    let low_char = ((hex_chars[low].to_int()).to_char()).unwrap()
    result = result + high_char.to_string() + low_char.to_string()
  }
  result
}
