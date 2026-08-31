// ============================================================
// MoonBit Crypto Library
// Single source of truth: SHA-256, HMAC-SHA256, AES-CBC, AES-GCM
// ============================================================

// ==================== Shared Utilities ====================

///|
/// Concatenate two Bytes
fn concat_bytes(a : Bytes, b : Bytes) -> Bytes {
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

///|
/// XOR two equal-length Bytes
fn xor_bytes(a : Bytes, b : Bytes) -> Bytes {
  let len = a.length()
  let result = Array::make(len, b'\x00')
  for i in 0..<len {
    result[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(result[:])
}

///|
/// Constant-time comparison — does not short-circuit on first difference
pub fn bytes_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
/// Convert Bytes to lowercase hex string (O(n) via StringBuilder)
pub fn bytes_to_hex(data : Bytes) -> String {
  let hex_chars = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let buf = StringBuilder(size_hint=data.length() * 2)
  for i in 0..<data.length() {
    let b = data[i].to_int() & 0xFF
    buf.write_char(hex_chars[(b >> 4) & 0xF])
    buf.write_char(hex_chars[b & 0xF])
  }
  buf.to_string()
}

///|
/// Decode a hex string to `Bytes`. Rejects odd-length or non-hex input by
/// aborting. Inverse of `bytes_to_hex`.
fn hex_char_to_int(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    -1
  }
}

///|
pub fn hex_to_bytes(hex : String) -> Bytes {
  let len = hex.length()
  if len % 2 != 0 {
    abort("hex_to_bytes: hex string length must be even")
  }
  let n = len / 2
  let out = Array::make(n, b'\x00')
  for i in 0..<n {
    let hi = hex_char_to_int(hex[i * 2].to_int())
    let lo = hex_char_to_int(hex[i * 2 + 1].to_int())
    if hi < 0 || lo < 0 {
      abort("hex_to_bytes: invalid hex character")
    }
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out[:])
}

// ==================== SHA-256 (FIPS 180-4) ====================

///|
let sha256_k : Array[UInt] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
fn sig0(x : UInt) -> UInt {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

///|
fn sig1(x : UInt) -> UInt {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

///|
fn cap_sig0(x : UInt) -> UInt {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

///|
fn cap_sig1(x : UInt) -> UInt {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

///|
fn ch(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ ((0xFFFFFFFFU ^ x) & z)
}

///|
fn maj(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
/// SHA-256 compression. The caller must have filled `w[0..15]` with the
/// block's big-endian message words; `w` doubles as the 64-entry message
/// schedule. (Perf v0.21.0: callers reuse one scratch array instead of
/// allocating a 16-word block array plus a 64-word schedule per block.)
fn process_block(state : Array[UInt], w : Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  for i in 16..<=63 {
    w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16]
  }
  for i in 0..<=63 {
    let t1 = h + cap_sig1(e) + ch(e, f, g) + sha256_k[i] + w[i]
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

///|
fn read_u32_be(data : Bytes, offset : Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn read_u32_be_arr(data : Array[Byte], offset : Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
/// Compute SHA-256 (FIPS 180-4), 32-byte digest. Delegates to the streaming
/// hasher so the one-shot and incremental paths share a single source of truth.
pub fn sha256(data : Bytes) -> Bytes {
  let hasher = sha256_new()
  sha256_update(hasher, data)
  sha256_finalize(hasher)
}

// ==================== HMAC-SHA256 (RFC 2104) ====================

///|
fn repeat_byte(byte : Byte, count : Int) -> Bytes {
  let result = Array::make(count, byte)
  Bytes::from_array(result[:])
}

///|
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
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

  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))

  let inner = sha256(concat_bytes(ipad, message))
  sha256(concat_bytes(opad, inner))
}

// ==================== AES (FIPS 197) ====================

///|
let sbox : Array[Int] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
  0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
  0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
  0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
  0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
  0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
  0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
  0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
  0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
  0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
  0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]

///|
let inv_sbox : Array[Int] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
  0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
  0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
  0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
  0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
  0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
  0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
  0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
  0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
  0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
  0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
  0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  0x55, 0x21, 0x0c, 0x7d,
]

///|
let rcon : Array[Int] = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

///|
/// GF(2^8) multiplication — constant-time bit-by-bit (no lookup table, no cache side-channel)
fn gmul(a : Int, b : Int) -> Int {
  let mut p = 0
  let mut aa = a
  let mut bb = b
  for _ in 0..<8 {
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

///|
/// Precomputed GF(2^8) product tables for the fixed AES coefficients.
/// mix_columns uses mul2/mul3; inv_mix_columns uses mul9/mul11/mul13/mul14.
/// Replacing the per-byte gmul loop with a single lookup is a large speedup,
/// but like any table indexed by state bytes it is NOT constant-time (cache
/// side channel on the AES state). Constant-time verification is retained
/// for tag comparison (bytes_equal) and PKCS#7 padding. This is the standard
/// software-AES tradeoff when AES-NI is unavailable.
fn build_mul_table(m : Int) -> Array[Int] {
  let t = Array::make(256, 0)
  for i in 0..<256 {
    t[i] = gmul(m, i)
  }
  t
}

///|
let mul2 : Array[Int] = build_mul_table(0x02)

///|
let mul3 : Array[Int] = build_mul_table(0x03)

///|
let mul9 : Array[Int] = build_mul_table(0x09)

///|
let mul11 : Array[Int] = build_mul_table(0x0b)

///|
let mul13 : Array[Int] = build_mul_table(0x0d)

///|
let mul14 : Array[Int] = build_mul_table(0x0e)

///|
fn rot_word(word : Array[Int]) -> Array[Int] {
  [word[1], word[2], word[3], word[0]]
}

///|
fn aes_key_expansion(key : Bytes) -> Array[Array[Int]] {
  let key_len = key.length()
  let nk = key_len / 4
  let nr = if nk == 4 { 10 } else if nk == 6 { 12 } else { 14 }

  let w = Array::make((nr + 1) * 4, Array::make(4, 0))

  for i in 0..<nk {
    w[i] = [
      key[i * 4].to_int(),
      key[i * 4 + 1].to_int(),
      key[i * 4 + 2].to_int(),
      key[i * 4 + 3].to_int(),
    ]
  }

  let end = (nr + 1) * 4
  for i in nk..<end {
    let mut temp = [w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3]]

    if i % nk == 0 {
      let rotated = rot_word(temp)
      temp = [
        sbox[rotated[0]] ^ rcon[i / nk],
        sbox[rotated[1]],
        sbox[rotated[2]],
        sbox[rotated[3]],
      ]
    } else if nk > 6 && i % nk == 4 {
      temp = [sbox[temp[0]], sbox[temp[1]], sbox[temp[2]], sbox[temp[3]]]
    }

    w[i] = [
      w[i - nk][0] ^ temp[0],
      w[i - nk][1] ^ temp[1],
      w[i - nk][2] ^ temp[2],
      w[i - nk][3] ^ temp[3],
    ]
  }

  w
}

///|
fn bytes_to_state(data : Bytes) -> Array[Array[Int]] {
  let state = [
    Array::make(4, 0),
    Array::make(4, 0),
    Array::make(4, 0),
    Array::make(4, 0),
  ]
  for i in 0..<16 {
    state[i % 4][i / 4] = data[i].to_int()
  }
  state
}

///|
fn state_to_bytes(state : Array[Array[Int]]) -> Bytes {
  let result = Array::make(16, b'\x00')
  for i in 0..<16 {
    result[i] = (state[i % 4][i / 4] & 0xFF).to_byte()
  }
  Bytes::from_array(result[:])
}

///|
fn sub_bytes(state : Array[Array[Int]]) -> Unit {
  for i in 0..<4 {
    for j in 0..<4 {
      state[i][j] = sbox[state[i][j]]
    }
  }
}

///|
fn inv_sub_bytes(state : Array[Array[Int]]) -> Unit {
  for i in 0..<4 {
    for j in 0..<4 {
      state[i][j] = inv_sbox[state[i][j]]
    }
  }
}

///|
fn shift_rows(state : Array[Array[Int]]) -> Unit {
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

///|
fn inv_shift_rows(state : Array[Array[Int]]) -> Unit {
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

///|
fn mix_columns(state : Array[Array[Int]]) -> Unit {
  for j in 0..<4 {
    let s0 = state[0][j]
    let s1 = state[1][j]
    let s2 = state[2][j]
    let s3 = state[3][j]
    state[0][j] = mul2[s0] ^ mul3[s1] ^ s2 ^ s3
    state[1][j] = s0 ^ mul2[s1] ^ mul3[s2] ^ s3
    state[2][j] = s0 ^ s1 ^ mul2[s2] ^ mul3[s3]
    state[3][j] = mul3[s0] ^ s1 ^ s2 ^ mul2[s3]
  }
}

///|
fn inv_mix_columns(state : Array[Array[Int]]) -> Unit {
  for j in 0..<4 {
    let s0 = state[0][j]
    let s1 = state[1][j]
    let s2 = state[2][j]
    let s3 = state[3][j]
    state[0][j] = mul14[s0] ^ mul11[s1] ^ mul13[s2] ^ mul9[s3]
    state[1][j] = mul9[s0] ^ mul14[s1] ^ mul11[s2] ^ mul13[s3]
    state[2][j] = mul13[s0] ^ mul9[s1] ^ mul14[s2] ^ mul11[s3]
    state[3][j] = mul11[s0] ^ mul13[s1] ^ mul9[s2] ^ mul14[s3]
  }
}

///|
fn add_round_key(
  state : Array[Array[Int]],
  round_keys : Array[Array[Int]],
  round : Int,
) -> Unit {
  for j in 0..<4 {
    for i in 0..<4 {
      state[i][j] = state[i][j] ^ round_keys[round * 4 + j][i]
    }
  }
}

///|
fn encrypt_block(
  block : Bytes,
  round_keys : Array[Array[Int]],
  nr : Int,
) -> Bytes {
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

///|
fn decrypt_block(
  block : Bytes,
  round_keys : Array[Array[Int]],
  nr : Int,
) -> Bytes {
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

// ==================== PKCS7 Padding (RFC 5652) ====================

///|
fn pkcs7_pad(data : Bytes, block_size : Int) -> Bytes {
  let len = data.length()
  let pad_len = block_size - len % block_size
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

///|
/// Remove PKCS7 padding — verifies ALL padding bytes in constant time
fn pkcs7_unpad(data : Bytes) -> Bytes {
  let len = data.length()
  if len == 0 {
    return data
  }
  let pad_len = data[len - 1].to_int()
  if pad_len > 16 || pad_len < 1 {
    return data
  }
  // Constant-time verification: accumulate XOR of every padding byte vs expected value
  let mut diff = 0
  for i in 0..<pad_len {
    diff = diff | (data[len - 1 - i].to_int() ^ pad_len)
  }
  if diff != 0 {
    return data
  }
  let unpadded_len = len - pad_len
  let unpadded = Array::make(unpadded_len, b'\x00')
  for i in 0..<unpadded_len {
    unpadded[i] = data[i]
  }
  Bytes::from_array(unpadded[:])
}

// ==================== AES-CBC (NIST SP 800-38A) ====================

///|
pub fn aes_encrypt_cbc(data : Bytes, key : Bytes, iv : Bytes) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_encrypt_cbc: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 16 {
    abort("aes_encrypt_cbc: iv length must be 16 bytes")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
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
    let xored = xor_bytes(block, prev_block)
    let encrypted_block = encrypt_block(xored, round_keys, nr)
    for j in 0..<16 {
      encrypted[16 + offset + j] = encrypted_block[j]
    }
    prev_block = encrypted_block
  }

  Bytes::from_array(encrypted[:])
}

///|
pub fn aes_decrypt_cbc(data : Bytes, key : Bytes, iv : Bytes) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_decrypt_cbc: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 16 {
    abort("aes_decrypt_cbc: iv length must be 16 bytes")
  }
  if data.length() < 16 || (data.length() - 16) % 16 != 0 {
    abort("aes_decrypt_cbc: ciphertext must be 16 (IV prefix) + N*16 bytes")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
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
    let xored = xor_bytes(decrypted_block, prev_block)
    for j in 0..<16 {
      decrypted[offset + j] = xored[j]
    }
    prev_block = block
  }

  pkcs7_unpad(Bytes::from_array(decrypted[:]))
}

// ==================== AES-GCM (NIST SP 800-38D) ====================
// Only supports 96-bit (12-byte) IV — the recommended length per spec.

///|
/// Read 16 bytes at offset as 4 big-endian UInt words
fn bytes_to_block(data : Bytes, offset : Int) -> Array[UInt] {
  [
    (data[offset].to_uint() << 24) |
    (data[offset + 1].to_uint() << 16) |
    (data[offset + 2].to_uint() << 8) |
    data[offset + 3].to_uint(),
    (data[offset + 4].to_uint() << 24) |
    (data[offset + 5].to_uint() << 16) |
    (data[offset + 6].to_uint() << 8) |
    data[offset + 7].to_uint(),
    (data[offset + 8].to_uint() << 24) |
    (data[offset + 9].to_uint() << 16) |
    (data[offset + 10].to_uint() << 8) |
    data[offset + 11].to_uint(),
    (data[offset + 12].to_uint() << 24) |
    (data[offset + 13].to_uint() << 16) |
    (data[offset + 14].to_uint() << 8) |
    data[offset + 15].to_uint(),
  ]
}

///|
/// Convert 4 UInt words to 16 bytes (big-endian)
fn block_to_bytes(block : Array[UInt]) -> Bytes {
  let result = Array::make(16, b'\x00')
  for i in 0..<4 {
    let val = block[i]
    result[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  Bytes::from_array(result[:])
}

///|
/// Read a 16-byte block from data at offset into `out` (big-endian
/// words), zero-padding if fewer than 16 bytes remain. Reuses the
/// caller's scratch array instead of allocating per block.
fn ghash_read_block_into(data : Bytes, offset : Int, out : Array[UInt]) -> Unit {
  let len = data.length()
  for j in 0..<4 {
    let mut val = 0U
    for k in 0..<4 {
      let idx = offset + j * 4 + k
      if idx < len {
        val = val | (data[idx].to_uint() << ((3 - k) * 8))
      }
    }
    out[j] = val
  }
}

///|
/// In-place GF(2^128) doubling (right shift by 1 with conditional
/// reduction), MSB-first GCM convention: v <- v·α
fn ghash_double(v : Array[UInt]) -> Unit {
  let lsb = v[3] & 1U
  v[3] = (v[3] >> 1) | (v[2] << 31)
  v[2] = (v[2] >> 1) | (v[1] << 31)
  v[1] = (v[1] >> 1) | (v[0] << 31)
  v[0] = v[0] >> 1
  if lsb != 0U {
    v[0] = v[0] ^ 0xE1000000U
  }
}

///|
/// Precompute the 4-bit GHASH table for the hash subkey H:
/// tab[(p*16 + n)*4 .. +4] = g(n)·H·α^(4p), where p = 0 is the most
/// significant nibble of X and g(n) = n3·α^0 + n2·α^1 + n1·α^2 + n0·α^3
/// for nibble bits n3..n0 (n3 = MSB). One GHASH multiply then costs 32
/// table lookups + XORs instead of 128 bit-serial iterations.
fn ghash_make_table(h : Array[UInt]) -> Array[UInt] {
  let tab = Array::make(32 * 16 * 4, 0U)
  let v = Array::make(4, 0U)
  let z = Array::make(4, 0U)
  // p = 0: M0[n] = g(n)·H via a 4-bit serial multiply
  for n in 1..<16 {
    for i in 0..<4 {
      v[i] = h[i]
    }
    z[0] = 0U
    z[1] = 0U
    z[2] = 0U
    z[3] = 0U
    for k in 0..<4 {
      if (n & (8 >> k)) != 0 {
        z[0] = z[0] ^ v[0]
        z[1] = z[1] ^ v[1]
        z[2] = z[2] ^ v[2]
        z[3] = z[3] ^ v[3]
      }
      ghash_double(v)
    }
    let base = n * 4
    tab[base] = z[0]
    tab[base + 1] = z[1]
    tab[base + 2] = z[2]
    tab[base + 3] = z[3]
  }
  // p = 1..31: Mp[n] = double^4(M(p-1)[n])
  for p in 1..<32 {
    for n in 0..<16 {
      let prev = ((p - 1) * 16 + n) * 4
      v[0] = tab[prev]
      v[1] = tab[prev + 1]
      v[2] = tab[prev + 2]
      v[3] = tab[prev + 3]
      ghash_double(v)
      ghash_double(v)
      ghash_double(v)
      ghash_double(v)
      let cur = (p * 16 + n) * 4
      tab[cur] = v[0]
      tab[cur + 1] = v[1]
      tab[cur + 2] = v[2]
      tab[cur + 3] = v[3]
    }
  }
  tab
}

///|
/// GF(2^128) multiplication for GHASH via the precomputed 4-bit table:
/// out = x·H = XOR over the 32 nibble positions of X.
fn ghash_mul_into(
  tab : Array[UInt],
  x : Array[UInt],
  out : Array[UInt],
) -> Unit {
  out[0] = 0U
  out[1] = 0U
  out[2] = 0U
  out[3] = 0U
  for p in 0..<32 {
    let nibble = ((x[p / 8] >> (28 - p % 8 * 4)) & 0xFU).reinterpret_as_int()
    let base = (p * 16 + nibble) * 4
    out[0] = out[0] ^ tab[base]
    out[1] = out[1] ^ tab[base + 1]
    out[2] = out[2] ^ tab[base + 2]
    out[3] = out[3] ^ tab[base + 3]
  }
}

///|
/// Compute GHASH over AAD and ciphertext (table-accelerated)
fn gcm_ghash(h : Array[UInt], aad : Bytes, ciphertext : Bytes) -> Array[UInt] {
  let tab = ghash_make_table(h)
  let y = Array::make(4, 0U)
  let blk = Array::make(4, 0U)
  let prod = Array::make(4, 0U)

  // Process AAD blocks (zero-padded)
  let aad_len = aad.length()
  let mut off = 0
  while off < aad_len {
    ghash_read_block_into(aad, off, blk)
    y[0] = y[0] ^ blk[0]
    y[1] = y[1] ^ blk[1]
    y[2] = y[2] ^ blk[2]
    y[3] = y[3] ^ blk[3]
    ghash_mul_into(tab, y, prod)
    y[0] = prod[0]
    y[1] = prod[1]
    y[2] = prod[2]
    y[3] = prod[3]
    off = off + 16
  }

  // Process ciphertext blocks (zero-padded)
  let ct_len = ciphertext.length()
  off = 0
  while off < ct_len {
    ghash_read_block_into(ciphertext, off, blk)
    y[0] = y[0] ^ blk[0]
    y[1] = y[1] ^ blk[1]
    y[2] = y[2] ^ blk[2]
    y[3] = y[3] ^ blk[3]
    ghash_mul_into(tab, y, prod)
    y[0] = prod[0]
    y[1] = prod[1]
    y[2] = prod[2]
    y[3] = prod[3]
    off = off + 16
  }

  // Process length block: [len(AAD) in bits]_64 || [len(C) in bits]_64
  let aad_bits = (aad_len * 8).to_uint64()
  let ct_bits = (ct_len * 8).to_uint64()
  y[0] = y[0] ^ ((aad_bits >> 32) & 0xFFFFFFFFUL).to_uint()
  y[1] = y[1] ^ (aad_bits & 0xFFFFFFFFUL).to_uint()
  y[2] = y[2] ^ ((ct_bits >> 32) & 0xFFFFFFFFUL).to_uint()
  y[3] = y[3] ^ (ct_bits & 0xFFFFFFFFUL).to_uint()
  ghash_mul_into(tab, y, prod)
  y[0] = prod[0]
  y[1] = prod[1]
  y[2] = prod[2]
  y[3] = prod[3]

  y
}

///|
/// Increment the rightmost 32 bits of a 128-bit counter
fn inc32(counter : Array[UInt]) -> Unit {
  counter[3] = counter[3] + 1U
}

///|
/// Galois Counter Mode — counter-mode keystream XOR
fn gctr(
  round_keys : Array[Array[Int]],
  nr : Int,
  icb : Array[UInt],
  data : Bytes,
) -> Bytes {
  let len = data.length()
  if len == 0 {
    return b""
  }

  let result = Array::make(len, b'\x00')
  let counter = [icb[0], icb[1], icb[2], icb[3]]
  let num_blocks = (len + 15) / 16

  for b in 0..<num_blocks {
    let counter_bytes = block_to_bytes(counter)
    let keystream = encrypt_block(counter_bytes, round_keys, nr)

    let offset = b * 16
    let block_len = if offset + 16 <= len { 16 } else { len - offset }
    for j in 0..<block_len {
      result[offset + j] = (data[offset + j].to_int() ^ keystream[j].to_int()).to_byte()
    }
    inc32(counter)
  }

  Bytes::from_array(result[:])
}

///|
/// AES-GCM encrypt — returns (ciphertext, 16-byte tag)
pub fn aes_gcm_encrypt(
  plaintext : Bytes,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_gcm_encrypt: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 12 {
    abort("aes_gcm_encrypt: iv/nonce length must be 12 bytes (96 bits)")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)

  // H = AES_K(0^128) — hash subkey
  let h_bytes = encrypt_block(
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", round_keys,
    nr,
  )
  let h = bytes_to_block(h_bytes, 0)

  // J0 = IV || 0^31 || 1 (96-bit IV)
  let j0 = Array::make(4, 0U)
  j0[0] = (iv[0].to_uint() << 24) |
    (iv[1].to_uint() << 16) |
    (iv[2].to_uint() << 8) |
    iv[3].to_uint()
  j0[1] = (iv[4].to_uint() << 24) |
    (iv[5].to_uint() << 16) |
    (iv[6].to_uint() << 8) |
    iv[7].to_uint()
  j0[2] = (iv[8].to_uint() << 24) |
    (iv[9].to_uint() << 16) |
    (iv[10].to_uint() << 8) |
    iv[11].to_uint()
  j0[3] = 0x00000001U

  // C = GCTR(K, inc32(J0), P)
  let inc_j0 = [j0[0], j0[1], j0[2], j0[3]]
  inc32(inc_j0)
  let ciphertext = gctr(round_keys, nr, inc_j0, plaintext)

  // S = GHASH(H, AAD, C)
  let s = gcm_ghash(h, aad, ciphertext)

  // T = GCTR(K, J0, S) = S XOR AES_K(J0)
  let j0_bytes = block_to_bytes(j0)
  let e_j0 = encrypt_block(j0_bytes, round_keys, nr)
  let e_j0_block = bytes_to_block(e_j0, 0)

  let tag_block = Array::make(4, 0U)
  tag_block[0] = s[0] ^ e_j0_block[0]
  tag_block[1] = s[1] ^ e_j0_block[1]
  tag_block[2] = s[2] ^ e_j0_block[2]
  tag_block[3] = s[3] ^ e_j0_block[3]
  let tag = block_to_bytes(tag_block)

  (ciphertext, tag)
}

///|
/// AES-GCM decrypt — verifies tag, returns (plaintext, true) or (b"", false)
pub fn aes_gcm_decrypt(
  ciphertext : Bytes,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  tag : Bytes,
) -> (Bytes, Bool) {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_gcm_decrypt: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 12 {
    abort("aes_gcm_decrypt: iv/nonce length must be 12 bytes (96 bits)")
  }
  if tag.length() != 16 {
    abort("aes_gcm_decrypt: tag length must be 16 bytes (128 bits)")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)

  // H = AES_K(0^128)
  let h_bytes = encrypt_block(
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", round_keys,
    nr,
  )
  let h = bytes_to_block(h_bytes, 0)

  // J0 = IV || 0^31 || 1
  let j0 = Array::make(4, 0U)
  j0[0] = (iv[0].to_uint() << 24) |
    (iv[1].to_uint() << 16) |
    (iv[2].to_uint() << 8) |
    iv[3].to_uint()
  j0[1] = (iv[4].to_uint() << 24) |
    (iv[5].to_uint() << 16) |
    (iv[6].to_uint() << 8) |
    iv[7].to_uint()
  j0[2] = (iv[8].to_uint() << 24) |
    (iv[9].to_uint() << 16) |
    (iv[10].to_uint() << 8) |
    iv[11].to_uint()
  j0[3] = 0x00000001U

  // Compute expected tag
  let s = gcm_ghash(h, aad, ciphertext)
  let j0_bytes = block_to_bytes(j0)
  let e_j0 = encrypt_block(j0_bytes, round_keys, nr)
  let e_j0_block = bytes_to_block(e_j0, 0)

  let expected_tag_block = Array::make(4, 0U)
  expected_tag_block[0] = s[0] ^ e_j0_block[0]
  expected_tag_block[1] = s[1] ^ e_j0_block[1]
  expected_tag_block[2] = s[2] ^ e_j0_block[2]
  expected_tag_block[3] = s[3] ^ e_j0_block[3]
  let expected_tag = block_to_bytes(expected_tag_block)

  // Verify tag in constant time
  if !bytes_equal(expected_tag, tag) {
    return (b"", false)
  }

  // Decrypt: P = GCTR(K, inc32(J0), C)
  let inc_j0 = [j0[0], j0[1], j0[2], j0[3]]
  inc32(inc_j0)
  let plaintext = gctr(round_keys, nr, inc_j0, ciphertext)

  (plaintext, true)
}

// ==================== HMAC-SHA512 (RFC 2104) ====================

///|
/// Compute HMAC-SHA512. Block size for SHA-512 is 128 bytes.
pub fn hmac_sha512(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 128
  let k_prime = if key.length() > block_size {
    sha512(key)
  } else {
    let padded = Array::make(block_size, b'\x00')
    for i in 0..<key.length() {
      padded[i] = key[i]
    }
    Bytes::from_array(padded[:])
  }
  let ipad = xor_bytes(k_prime, repeat_byte(b'\x36', block_size))
  let opad = xor_bytes(k_prime, repeat_byte(b'\x5c', block_size))
  let inner = sha512(concat_bytes(ipad, message))
  sha512(concat_bytes(opad, inner))
}

// ==================== AES-CTR (NIST SP 800-38A) ====================

///|
/// AES-CTR encrypt/decrypt (symmetric — XOR keystream). key: 16/24/32 bytes,
/// iv: 16-byte initial counter. Counter increments as 128-bit big-endian.
pub fn aes_ctr(data : Bytes, key : Bytes, iv : Bytes) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_ctr: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 16 {
    abort("aes_ctr: iv length must be 16 bytes")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)
  let len = data.length()
  let output = Array::make(len, b'\x00')
  let counter = Array::make(16, b'\x00')
  for i in 0..<16 {
    counter[i] = iv[i]
  }
  let num_blocks = (len + 15) / 16
  for blk in 0..<num_blocks {
    let keystream = encrypt_block(Bytes::from_array(counter[:]), round_keys, nr)
    let offset = blk * 16
    let block_len = if offset + 16 <= len { 16 } else { len - offset }
    for j in 0..<block_len {
      output[offset + j] = (data[offset + j].to_int() ^ keystream[j].to_int()).to_byte()
    }
    let mut k = 15
    while k >= 0 {
      counter[k] = ((counter[k].to_int() + 1) & 0xFF).to_byte()
      if counter[k] != 0 {
        break
      }
      k = k - 1
    }
  }
  Bytes::from_array(output[:])
}
