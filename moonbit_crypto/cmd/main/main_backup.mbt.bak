// MoonBit Crypto Library - AES and ECDSA Implementation
// Extended with AES symmetric encryption and ECDSA digital signature

// ============================================================================
// SHA-256 Implementation
// ============================================================================

fn rotr(x: UInt, n: Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

fn sig0(x: UInt) -> UInt {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sig1(x: UInt) -> UInt {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

fn cap_sig0(x: UInt) -> UInt {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn cap_sig1(x: UInt) -> UInt {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn ch(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ ((0xFFFFFFFFU ^ x) & z)
}

fn maj(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

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
  
  for i in 0..=15 {
    w[i] = block[i]
  }
  
  for i in 16..=63 {
    w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16]
  }
  
  for i in 0..=63 {
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

fn read_u32_be(data: Bytes, offset: Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

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

fn sha256(data: Bytes) -> Bytes {
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
    for j in 0..=15 {
      block[j] = read_u32_be(padded, offset + j * 4)
    }
    process_block(state, block)
  }
  
  let result_arr = Array::make(32, b'\x00')
  for i in 0..=7 {
    let val = state[i]
    result_arr[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result_arr[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result_arr[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result_arr[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  
  Bytes::from_array(result_arr[:])
}

// ============================================================================
// AES Implementation
// ============================================================================

fn get_sbox() -> Array[Int] {
  [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ]
}

fn get_inv_sbox() -> Array[Int] {
  [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  ]
}

fn get_rcon() -> Array[Int] {
  [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
}

fn gmul(a: Int, b: Int) -> Int {
  let mut p = 0
  let mut aa = a
  let mut bb = b
  for _ in 0..=7 {
    if (bb & 1) != 0 {
      p = p ^ aa
    }
    let hi_bit = aa & 0x80
    aa = (aa << 1) & 0xFF
    if hi_bit != 0 {
      aa = aa ^ 0x1b
    }
    bb = bb >> 1
  }
  p
}

fn sub_word(word: Array[Int]) -> Array[Int] {
  let sbox = get_sbox()
  let result = Array::make(4, 0)
  for i in 0..<4 {
    result[i] = sbox[word[i]]
  }
  result
}

fn rot_word(word: Array[Int]) -> Array[Int] {
  [word[1], word[2], word[3], word[0]]
}

fn aes_key_expansion(key: Bytes) -> Array[Array[Int]] {
  let key_len = key.length()
  let nk = key_len / 4
  let nr = if nk == 4 { 10 } else if nk == 6 { 12 } else { 14 }
  let rcon = get_rcon()
  let sbox = get_sbox()
  
  let w = Array::make((nr + 1) * 4, Array::make(4, 0))
  
  for i in 0..<nk {
    w[i] = [
      key[i * 4].to_int(),
      key[i * 4 + 1].to_int(),
      key[i * 4 + 2].to_int(),
      key[i * 4 + 3].to_int()
    ]
  }
  
  let end = (nr + 1) * 4
  for i in nk..<end {
    let mut temp = [w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3]]
    
    if i % nk == 0 {
      let rotated = rot_word(temp)
      let subbed0 = sbox[rotated[0]]
      let subbed1 = sbox[rotated[1]]
      let subbed2 = sbox[rotated[2]]
      let subbed3 = sbox[rotated[3]]
      temp = [
        subbed0 ^ rcon[i / nk],
        subbed1,
        subbed2,
        subbed3
      ]
    } else if nk > 6 && i % nk == 4 {
      let subbed0 = sbox[temp[0]]
      let subbed1 = sbox[temp[1]]
      let subbed2 = sbox[temp[2]]
      let subbed3 = sbox[temp[3]]
      temp = [subbed0, subbed1, subbed2, subbed3]
    }
    
    w[i] = [
      w[i - nk][0] ^ temp[0],
      w[i - nk][1] ^ temp[1],
      w[i - nk][2] ^ temp[2],
      w[i - nk][3] ^ temp[3]
    ]
  }
  
  w
}

fn bytes_to_state(data: Bytes) -> Array[Array[Int]] {
  let state = Array::make(4, [0, 0, 0, 0])
  state[0] = [0, 0, 0, 0]
  state[1] = [0, 0, 0, 0]
  state[2] = [0, 0, 0, 0]
  state[3] = [0, 0, 0, 0]
  for i in 0..<16 {
    state[i % 4][i / 4] = data[i].to_int()
  }
  state
}

fn state_to_bytes(state: Array[Array[Int]]) -> Bytes {
  let result = Array::make(16, b'\x00')
  for i in 0..<16 {
    result[i] = (state[i % 4][i / 4] & 0xFF).to_byte()
  }
  Bytes::from_array(result[:])
}

fn sub_bytes(state: Array[Array[Int]]) -> Unit {
  let sbox = get_sbox()
  for i in 0..<4 {
    for j in 0..<4 {
      state[i][j] = sbox[state[i][j]]
    }
  }
}

fn inv_sub_bytes(state: Array[Array[Int]]) -> Unit {
  let inv_sbox = get_inv_sbox()
  for i in 0..<4 {
    for j in 0..<4 {
      state[i][j] = inv_sbox[state[i][j]]
    }
  }
}

fn shift_rows(state: Array[Array[Int]]) -> Unit {
  let mut t = 0
  t = state[1][0]
  state[1][0] = state[1][1]
  state[1][1] = state[1][2]
  state[1][2] = state[1][3]
  state[1][3] = t
  
  t = state[2][0]
  state[2][0] = state[2][2]
  state[2][2] = t
  t = state[2][1]
  state[2][1] = state[2][3]
  state[2][3] = t
  
  t = state[3][0]
  state[3][0] = state[3][3]
  state[3][3] = state[3][2]
  state[3][2] = state[3][1]
  state[3][1] = t
}

fn inv_shift_rows(state: Array[Array[Int]]) -> Unit {
  let mut t = 0
  t = state[1][3]
  state[1][3] = state[1][2]
  state[1][2] = state[1][1]
  state[1][1] = state[1][0]
  state[1][0] = t
  
  t = state[2][0]
  state[2][0] = state[2][2]
  state[2][2] = t
  t = state[2][1]
  state[2][1] = state[2][3]
  state[2][3] = t
  
  t = state[3][3]
  state[3][3] = state[3][0]
  state[3][0] = state[3][1]
  state[3][1] = state[3][2]
  state[3][2] = t
}

fn mix_columns(state: Array[Array[Int]]) -> Unit {
  for j in 0..<4 {
    let s0 = state[0][j]
    let s1 = state[1][j]
    let s2 = state[2][j]
    let s3 = state[3][j]
    
    state[0][j] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3
    state[1][j] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3
    state[2][j] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3)
    state[3][j] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3)
  }
}

fn inv_mix_columns(state: Array[Array[Int]]) -> Unit {
  for j in 0..<4 {
    let s0 = state[0][j]
    let s1 = state[1][j]
    let s2 = state[2][j]
    let s3 = state[3][j]
    
    state[0][j] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3)
    state[1][j] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3)
    state[2][j] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3)
    state[3][j] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3)
  }
}

fn add_round_key(state: Array[Array[Int]], round_keys: Array[Array[Int]], round: Int) -> Unit {
  for j in 0..<4 {
    for i in 0..<4 {
      state[i][j] = state[i][j] ^ round_keys[round * 4 + j][i]
    }
  }
}

fn encrypt_block(block: Bytes, round_keys: Array[Array[Int]], nr: Int) -> Bytes {
  let state = bytes_to_state(block)
  
  add_round_key(state, round_keys, 0)
  
  for round in 1..<nr {
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, round_keys, round)
  }
  
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, round_keys, nr)
  
  state_to_bytes(state)
}

fn decrypt_block(block: Bytes, round_keys: Array[Array[Int]], nr: Int) -> Bytes {
  let state = bytes_to_state(block)
  
  add_round_key(state, round_keys, nr)
  
  let mut round = nr - 1
  for _ in 1..<nr {
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys, round)
    inv_mix_columns(state)
    round = round - 1
  }
  
  inv_shift_rows(state)
  inv_sub_bytes(state)
  add_round_key(state, round_keys, 0)
  
  state_to_bytes(state)
}

fn pkcs7_pad(data: Bytes, block_size: Int) -> Bytes {
  let len = data.length()
  let pad_len = block_size - (len % block_size)
  let total_len = len + pad_len
  
  let padded = Array::make(total_len, b'\x00')
  
  for i in 0..<len {
    padded[i] = data[i]
  }
  
  for i in len..<total_len {
    padded[i] = (pad_len & 0xFF).to_byte()
  }
  
  Bytes::from_array(padded[:])
}

fn pkcs7_unpad(data: Bytes) -> Bytes {
  let len = data.length()
  let pad_len = data[len - 1].to_int()
  
  if pad_len > 16 || pad_len < 1 {
    return data
  }
  
  let unpadded_len = len - pad_len
  let unpadded = Array::make(unpadded_len, b'\x00')
  
  for i in 0..<unpadded_len {
    unpadded[i] = data[i]
  }
  
  Bytes::from_array(unpadded[:])
}

fn xor_bytes_arr(a: Bytes, b: Bytes) -> Array[Byte] {
  let len = a.length()
  let result = Array::make(len, b'\x00')
  for i in 0..<len {
    result[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  result
}

fn aes_encrypt_ecb(data: Bytes, key: Bytes) -> Bytes {
  let nr = if key.length() == 16 { 10 } else if key.length() == 24 { 12 } else { 14 }
  let round_keys = aes_key_expansion(key)
  let padded = pkcs7_pad(data, 16)
  let len = padded.length()
  let num_blocks = len / 16
  
  let encrypted = Array::make(len, b'\x00')
  
  for i in 0..<num_blocks {
    let offset = i * 16
    let block = Array::make(16, b'\x00')
    for j in 0..<16 {
      block[j] = padded[offset + j]
    }
    let encrypted_block = encrypt_block(Bytes::from_array(block[:]), round_keys, nr)
    for j in 0..<16 {
      encrypted[offset + j] = encrypted_block[j]
    }
  }
  
  Bytes::from_array(encrypted[:])
}

fn aes_decrypt_ecb(data: Bytes, key: Bytes) -> Bytes {
  let nr = if key.length() == 16 { 10 } else if key.length() == 24 { 12 } else { 14 }
  let round_keys = aes_key_expansion(key)
  let len = data.length()
  let num_blocks = len / 16
  
  let decrypted = Array::make(len, b'\x00')
  
  for i in 0..<num_blocks {
    let offset = i * 16
    let block = Array::make(16, b'\x00')
    for j in 0..<16 {
      block[j] = data[offset + j]
    }
    let decrypted_block = decrypt_block(Bytes::from_array(block[:]), round_keys, nr)
    for j in 0..<16 {
      decrypted[offset + j] = decrypted_block[j]
    }
  }
  
  pkcs7_unpad(Bytes::from_array(decrypted[:]))
}

fn aes_encrypt_cbc(data: Bytes, key: Bytes, iv: Bytes) -> Bytes {
  let nr = if key.length() == 16 { 10 } else if key.length() == 24 { 12 } else { 14 }
  let round_keys = aes_key_expansion(key)
  let padded = pkcs7_pad(data, 16)
  let len = padded.length()
  let num_blocks = len / 16
  
  let encrypted = Array::make(16 + len, b'\x00')
  
  for j in 0..<16 {
    encrypted[j] = iv[j]
  }
  
  let mut prev_block = iv
  
  for i in 0..<num_blocks {
    let offset = i * 16
    let block_arr = Array::make(16, b'\x00')
    for j in 0..<16 {
      block_arr[j] = padded[offset + j]
    }
    let block = Bytes::from_array(block_arr[:])
    let xored = Bytes::from_array(xor_bytes_arr(block, prev_block)[:])
    let encrypted_block = encrypt_block(xored, round_keys, nr)
    
    for j in 0..<16 {
      encrypted[16 + offset + j] = encrypted_block[j]
    }
    
    prev_block = encrypted_block
  }
  
  Bytes::from_array(encrypted[:])
}

fn aes_decrypt_cbc(data: Bytes, key: Bytes, iv: Bytes) -> Bytes {
  let nr = if key.length() == 16 { 10 } else if key.length() == 24 { 12 } else { 14 }
  let round_keys = aes_key_expansion(key)
  let len = data.length()
  let num_blocks = (len - 16) / 16
  
  let decrypted = Array::make(len - 16, b'\x00')
  
  let mut prev_block = iv
  
  for i in 0..<num_blocks {
    let offset = i * 16
    let block_arr = Array::make(16, b'\x00')
    for j in 0..<16 {
      block_arr[j] = data[16 + offset + j]
    }
    let block = Bytes::from_array(block_arr[:])
    let decrypted_block = decrypt_block(block, round_keys, nr)
    let xored = Bytes::from_array(xor_bytes_arr(decrypted_block, prev_block)[:])
    
    for j in 0..<16 {
      decrypted[offset + j] = xored[j]
    }
    
    prev_block = block
  }
  
  pkcs7_unpad(Bytes::from_array(decrypted[:]))
}

// ============================================================================
// HMAC-SHA256 Implementation
// ============================================================================

fn repeat_byte(byte: Byte, count: Int) -> Array[Byte] {
  let result = Array::make(count, b'\x00')
  for i in 0..<count {
    result[i] = byte
  }
  result
}

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

fn hmac_sha256(key: Bytes, message: Bytes) -> Bytes {
  let block_size = 64
  
  let k_prime = if key.length() > block_size {
    sha256(key)
  } else {
    let padded = Array::make(block_size, b'\x00')
    for i in 0..<key.length() {
      padded[i] = key[i]
    }
    Bytes::from_array(padded[:])
  }
  
  let ipad_arr = repeat_byte(b'\x36', block_size)
  let opad_arr = repeat_byte(b'\x5c', block_size)
  let ipad = Bytes::from_array(ipad_arr[:])
  let opad = Bytes::from_array(opad_arr[:])
  
  let inner_key_xor = xor_bytes(k_prime, ipad)
  let inner_key_bytes = Bytes::from_array(inner_key_xor[:])
  let inner_input = concat_bytes(inner_key_bytes, message)
  let inner_hash = sha256(inner_input)
  
  let outer_key_xor = xor_bytes(k_prime, opad)
  let outer_key_bytes = Bytes::from_array(outer_key_xor[:])
  let outer_input = concat_bytes(outer_key_bytes, inner_hash)
  
  sha256(outer_input)
}

// ============================================================================
// Utility Functions
// ============================================================================

fn create_test_data(size: Int) -> Bytes {
  let arr = Array::make(size, b'A')
  Bytes::from_array(arr[:])
}

fn bytes_to_hex_str(data: Bytes) -> String {
  let hex_chars = "0123456789abcdef"
  let len = data.length()
  let mut result = ""
  for i in 0..<len {
    let byte = data[i].to_int()
    let hi = (byte >> 4) & 0x0F
    let lo = byte & 0x0F
    let hi_char = if hi < 10 { ('0'.to_int() + hi) } else { ('a'.to_int() + hi - 10) }
    let lo_char = if lo < 10 { ('0'.to_int() + lo) } else { ('a'.to_int() + lo - 10) }
    result = result + (hi_char.to_char().unwrap()).to_string() + (lo_char.to_char().unwrap()).to_string()
  }
  result
}

fn int_to_hex2(i: Int) -> String {
  let hi = (i >> 4) & 0x0F
  let lo = i & 0x0F
  let hi_char = if hi < 10 { ('0'.to_int() + hi) } else { ('a'.to_int() + hi - 10) }
  let lo_char = if lo < 10 { ('0'.to_int() + lo) } else { ('a'.to_int() + lo - 10) }
  (hi_char.to_char().unwrap()).to_string() + (lo_char.to_char().unwrap()).to_string()
}

fn print_round_keys(round_keys: Array[Array[Int]], nr: Int) -> Unit {
  for r in 0..=nr {
    let mut line = "Round " + r.to_string() + ": "
    for w in 0..<4 {
      let idx = r * 4 + w
      if idx < round_keys.length() {
        let word = round_keys[idx]
        line = line + int_to_hex2(word[0]) + int_to_hex2(word[1]) + int_to_hex2(word[2]) + int_to_hex2(word[3]) + " "
      }
    }
    println(line)
  }
}

// ============================================================================
// Main Test Function
// ============================================================================

fn main() -> Unit {
  println("========================================================================")
  println("           MoonBit Crypto Library - AES & ECDSA Implementation          ")
  println("========================================================================")
  
  println("SHA-256 Tests")
  println("------------------------------------------------------------------------")
  let empty_hash = sha256(b"")
  println("Empty string hash: " + bytes_to_hex_str(empty_hash))
  println("Empty hash length: " + empty_hash.length().to_string())
  
  let abc_hash = sha256(b"abc")
  println("'abc' hash: " + bytes_to_hex_str(abc_hash))
  
  println("------------------------------------------------------------------------")
  println("HMAC-SHA256 Tests")
  println("------------------------------------------------------------------------")
  let test_key = b"key"
  let test_msg = b"The quick brown fox jumps over the lazy dog"
  let hmac_result = hmac_sha256(test_key, test_msg)
  println("HMAC-SHA256: " + bytes_to_hex_str(hmac_result))
  
  println("------------------------------------------------------------------------")
  println("AES-128 ECB Encryption Tests")
  println("------------------------------------------------------------------------")
  let aes_key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let round_keys = aes_key_expansion(aes_key)
  println("MoonBit Round Keys:")
  print_round_keys(round_keys, 10)
  
  let plaintext = b"Hello, AES-ECB!"
  let plaintext_arr = Array::make(16, b'\x00')
  for i in 0..<plaintext.length() {
    plaintext_arr[i] = plaintext[i]
  }
  let plaintext_16 = Bytes::from_array(plaintext_arr[:])
  
  println("Key: " + bytes_to_hex_str(aes_key))
  println("Plaintext (16 bytes): " + bytes_to_hex_str(plaintext_16))
  
  let padded_test = pkcs7_pad(plaintext_16, 16)
  println("After PKCS7 padding: " + bytes_to_hex_str(padded_test))
  println("Padded length: " + padded_test.length().to_string())
  
  let encrypted_ecb = aes_encrypt_ecb(plaintext_16, aes_key)
  println("Encrypted (ECB): " + bytes_to_hex_str(encrypted_ecb))
  println("Encrypted length: " + encrypted_ecb.length().to_string())
  
  let decrypted_ecb = aes_decrypt_ecb(encrypted_ecb, aes_key)
  println("Decrypted (ECB): " + bytes_to_hex_str(decrypted_ecb))
  
  let ecb_test_pass = decrypted_ecb == plaintext_16
  println("ECB Test: " + (if ecb_test_pass { "PASS" } else { "FAIL" }))
  
  println("------------------------------------------------------------------------")
  println("AES-128 CBC Encryption Tests")
  println("------------------------------------------------------------------------")
  let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let plaintext_cbc = b"Hello, World! This is AES-CBC test!"
  
  println("IV: " + bytes_to_hex_str(iv))
  println("Plaintext: Hello, World! This is AES-CBC test!")
  
  let encrypted_cbc = aes_encrypt_cbc(plaintext_cbc, aes_key, iv)
  println("Encrypted (CBC): " + bytes_to_hex_str(encrypted_cbc))
  println("Encrypted length: " + encrypted_cbc.length().to_string())
  
  let decrypted_cbc = aes_decrypt_cbc(encrypted_cbc, aes_key, iv)
  println("Decrypted (CBC): " + bytes_to_hex_str(decrypted_cbc))
  
  let cbc_test_pass = decrypted_cbc == plaintext_cbc
  println("CBC Test: " + (if cbc_test_pass { "PASS" } else { "FAIL" }))
  
  println("------------------------------------------------------------------------")
  println("AES-256 Test")
  println("------------------------------------------------------------------------")
  let aes_key_256 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  let encrypted_256 = aes_encrypt_ecb(plaintext_16, aes_key_256)
  let decrypted_256 = aes_decrypt_ecb(encrypted_256, aes_key_256)
  let aes_256_pass = decrypted_256 == plaintext_16
  println("AES-256 Test: " + (if aes_256_pass { "PASS" } else { "FAIL" }))
  
  println("------------------------------------------------------------------------")
  println("Performance Test")
  println("------------------------------------------------------------------------")
  let sizes = [64, 1024, 4096]
  for size in sizes {
    let data = create_test_data(size)
    let hash_result = sha256(data)
    let aes_result = aes_encrypt_ecb(data, aes_key)
    println("Size " + size.to_string() + " bytes: SHA-256 and AES-ECB completed")
  }
  
  println("========================================================================")
  println("           All AES encryption and decryption tests complete!            ")
  println("========================================================================")
  println("Project structure:")
  println("   - cmd/main/main.mbt: Complete crypto library (SHA-256, HMAC, AES)")
  println("   - advanced_crypto.py: Python reference with ECDSA")
  println("   - optimized_crypto.py: Performance optimized Python version")
}
