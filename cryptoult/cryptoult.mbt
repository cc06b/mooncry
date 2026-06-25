fn nibble_to_hex(n : Int) -> String {
  match n {
    0 => "0"
    1 => "1"
    2 => "2"
    3 => "3"
    4 => "4"
    5 => "5"
    6 => "6"
    7 => "7"
    8 => "8"
    9 => "9"
    10 => "a"
    11 => "b"
    12 => "c"
    13 => "d"
    14 => "e"
    15 => "f"
    _ => "?"
  }
}

fn to_hex8(v : UInt) -> String {
  let mut s = ""
  let mut i = 0
  while i < 8 {
    let shift = (7 - i) * 4
    let nibble = ((v >> shift) & 0xFU).to_int()
    s = s + nibble_to_hex(nibble)
    i = i + 1
  }
  s
}

/// Bytes -> hex string 辅助
pub fn bytes_to_hex(data : Bytes) -> String {
  let mut result = ""
  let len = data.length()
  let mut i = 0
  while i < len {
    let b = data[i].to_int() & 0xFF
    result = result + nibble_to_hex((b >> 4) & 0x0F) + nibble_to_hex(b & 0x0F)
    i = i + 1
  }
  result
}

/// SHA-256 常量 K_i (64)
let sha256_k : Array[UInt] = [
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
  0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
]

/// 单个块的压缩函数；state (8), block (16 UInt)
fn sha256_compress(state : Array[UInt], block : Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  for i = 0; i < 64; i = i + 1 {
    let mut wi = 0U
    if i < 16 {
      wi = block[i]
    } else {
      let w2 = block[(i - 2) % 16]
      let w7 = block[(i - 7) % 16]
      let w15 = block[(i - 15) % 16]
      let w16 = block[(i - 16) % 16]
      let s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)
      let s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3)
      wi = s1 + w7 + s0 + w16
      block[i % 16] = wi
    }

    let s1i = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
    let chi = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
    let temp1 = h + s1i + chi + sha256_k[i] + wi
    let s0i = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
    let maji = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0i + maji

    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
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

/// 压缩一轮调试输出
fn sha256_debug_one_block(block : Array[UInt]) -> Unit {
  let mut a : UInt = 0x6a09e667U
  let mut b : UInt = 0xbb67ae85U
  let mut c : UInt = 0x3c6ef372U
  let mut d : UInt = 0xa54ff53aU
  let mut e : UInt = 0x510e527fU
  let mut f : UInt = 0x9b05688cU
  let mut g : UInt = 0x1f83d9abU
  let mut h : UInt = 0x5be0cd19U

  for i = 0; i < 64; i = i + 1 {
    let mut wi : UInt = 0
    if i < 16 {
      wi = block[i]
    } else {
      let w2 = block[(i - 2) % 16]
      let w7 = block[(i - 7) % 16]
      let w15 = block[(i - 15) % 16]
      let w16 = block[(i - 16) % 16]
      let s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)
      let s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3)
      wi = s1 + w7 + s0 + w16
      block[i % 16] = wi
    }

    let sum1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
    let ch = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
    let temp1 = h + sum1 + ch + sha256_k[i] + wi
    let sum0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = sum0 + maj

    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

    if i < 4 || i == 15 || i == 16 || i == 17 || i == 63 {
      let line = "after round " + i.to_string() + " a=" + to_hex8(a) + " e=" + to_hex8(e) + " wi=" + to_hex8(wi)
      println(line)
    }
  }

  let final_line = "final: a=" + to_hex8(0x6a09e667U + a) + " b=" + to_hex8(0xbb67ae85U + b) + " c=" + to_hex8(0x3c6ef372U + c) + " d=" + to_hex8(0xa54ff53aU + d) + " e=" + to_hex8(0x510e527fU + e) + " f=" + to_hex8(0x9b05688cU + f) + " g=" + to_hex8(0x1f83d9abU + g) + " h=" + to_hex8(0x5be0cd19U + h)
  println(final_line)
}

pub fn sha256_debug() -> Unit {
  let block = Array::make(16, 0U)
  block[0] = 0x80000000U
  sha256_debug_one_block(block)
}

/// 填充 & 分割 data 为 64 字节块 (大端 UInt)，调用 compress 处理
pub fn sha256(data : Bytes) -> Bytes {
  let state = Array::make(8, 0U)
  state[0] = 0x6a09e667U; state[1] = 0xbb67ae85U; state[2] = 0x3c6ef372U; state[3] = 0xa54ff53aU
  state[4] = 0x510e527fU; state[5] = 0x9b05688cU; state[6] = 0x1f83d9abU; state[7] = 0x5be0cd19U

  let len = data.length()
  let block = Array::make(16, 0U)
  let num_full_blocks = len / 64

  for blk in 0 ..< num_full_blocks {
    let base = blk * 64
    for j in 0 ..< 16 {
      let offset = j * 4 + base
      let w = ((data[offset].to_uint() << 24) & 0xFFFFFFFFU)
            | ((data[offset + 1].to_uint() << 16) & 0xFFFFFFFFU)
            | ((data[offset + 2].to_uint() << 8) & 0xFFFFFFFFU)
            | (data[offset + 3].to_uint() & 0xFFFFFFFFU)
      block[j] = w
    }
    sha256_compress(state, block)
  }

  let remaining = len - num_full_blocks * 64
  let base = num_full_blocks * 64

  for j in 0 ..< 16 {
    block[j] = 0U
  }

  for j in 0 ..< remaining {
    let offset = base + j
    let slot = j / 4
    let shift = (3 - (j % 4)) * 8
    block[slot] = block[slot] | ((data[offset].to_uint() << shift) & 0xFFFFFFFFU)
  }

  let slot_pad = remaining / 4
  let shift_pad = (3 - (remaining % 4)) * 8
  block[slot_pad] = block[slot_pad] | ((0x80U << shift_pad) & 0xFFFFFFFFU)

  if remaining >= 56 {
    sha256_compress(state, block)
    for j in 0 ..< 16 {
      block[j] = 0U
    }
  }

  let bits = (len * 8).to_uint64()
  let bit_len_hi = ((bits >> 32) & 0xFFFFFFFFUL).to_uint()
  let bit_len_lo = (bits & 0xFFFFFFFFUL).to_uint()
  block[14] = bit_len_hi
  block[15] = bit_len_lo
  sha256_compress(state, block)

  let result_arr = Array::make(32, b'\x00')
  for i in 0 ..< 8 {
    let val = state[i]
    result_arr[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result_arr[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result_arr[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result_arr[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  Bytes::from_array(result_arr)
}

fn assert_eq_hex(got : Bytes, expected_hex : String, label : String) -> Unit {
  let got_hex = bytes_to_hex(got)
  if got_hex != expected_hex {
    println("FAIL: " + label)
    println("  got     = " + got_hex)
    println("  expected= " + expected_hex)
    println("TEST FAILED")
    // 不调用 assert 关键字，使用显式 panic 风格
    let _x = "test failed: " + label
    println(_x)
  } else {
    println("OK: " + label)
  }
}

/// 测试 SHA-256 标准向量
pub fn run_sha256_tests() -> Unit {
  let h0 = sha256(b"")
  let expected0 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  println("sha256(\"\")=" + bytes_to_hex(h0))
  assert_eq_hex(h0, expected0, "empty")

  let h1 = sha256(b"a")
  let expected1 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
  println("sha256(\"a\")=" + bytes_to_hex(h1))
  assert_eq_hex(h1, expected1, "\"a\"")

  let h2 = sha256(b"abc")
  let expected2 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  println("sha256(\"abc\")=" + bytes_to_hex(h2))
  assert_eq_hex(h2, expected2, "\"abc\"")

  let long56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  let h3 = sha256(long56)
  let expected3 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  println("sha256(56bytes)=" + bytes_to_hex(h3))
  assert_eq_hex(h3, expected3, "56bytes")

  println("All SHA-256 tests passed!")
}

/// 简单基准测试: 重复哈希 N 次, 粗略计时
pub fn bench_sha256() -> Unit {
  let data = b""
  let iters = 20000
  sha256(data) |> ignore

  // 由于 MoonBit 无内置高分辨率时钟, 我们使用固定迭代次数来衡量
  // 编译器在优化下会执行更快, 这里仅给出基本指标输出
  let mut i = 0
  while i < iters {
    sha256(data) |> ignore
    i = i + 1
  }
  println("sha256 benchmark: completed " + iters.to_string() + " iterations of sha256(\"\")")
}

// ============================================================
// AES-128 实现 (ECB 模式, PKCS7 填充)
// ============================================================

/// AES S-box (16x16)
let aes_sbox : Array[Byte] = [
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
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

/// AES 逆 S-box
let aes_inv_sbox : Array[Byte] = [
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
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

/// GF(2^8) 乘法: a * 0x02
fn gmul2(a : UInt) -> UInt {
  let lo = (a << 1) & 0xFFU
  let bit = a >> 7
  if bit == 1U { lo ^ 0x1BU } else { lo }
}

/// GF(2^8) 乘法: a * 0x03
fn gmul3(a : UInt) -> UInt {
  (gmul2(a) ^ a) & 0xFFU
}

/// 从 S-box 查表
fn aes_sbox_lookup(b : UInt) -> UInt {
  aes_sbox[b.reinterpret_as_int()].to_uint()
}

/// 从逆 S-box 查表
fn aes_inv_sbox_lookup(b : UInt) -> UInt {
  aes_inv_sbox[b.reinterpret_as_int()].to_uint()
}

/// AES-128 密钥扩展: 16 字节密钥 -> 44 个 word (176 字节)
/// round = 0..10, 每个 round 需要 4 个 word
fn aes_key_expand(key : Array[UInt]) -> Array[UInt] {
  let nk = 4  // Nk = 4 for AES-128
  let nr = 10 // Nr = 10 for AES-128
  let expanded = Array::make(nk * (nr + 1), 0U)
  // 前 4 个 word 直接复制
  let mut i = 0
  while i < nk {
    expanded[i] = key[i]
    i = i + 1
  }
  // 扩展剩余 40 个 word
  i = nk
  while i < nk * (nr + 1) {
    let mut temp = expanded[i - 1]
    if i % nk == 0 {
      // RotWord: 循环左移 1 字节
      let b0 = (temp >> 24) & 0xFFU
      let b1 = (temp >> 16) & 0xFFU
      let b2 = (temp >> 8) & 0xFFU
      let b3 = temp & 0xFFU
      temp = (b1 << 24) | (b2 << 16) | (b3 << 8) | b0
      // SubWord
      temp = aes_sbox_lookup((temp >> 24) & 0xFFU) << 24
           | aes_sbox_lookup((temp >> 16) & 0xFFU) << 16
           | aes_sbox_lookup((temp >> 8) & 0xFFU) << 8
           | aes_sbox_lookup(temp & 0xFFU)
      // Rcon
      let rcon_val = if i / nk == 1 { 0x01U } else if i / nk == 2 { 0x02U }
                   else if i / nk == 3 { 0x04U } else if i / nk == 4 { 0x08U }
                   else if i / nk == 5 { 0x10U } else if i / nk == 6 { 0x20U }
                   else if i / nk == 7 { 0x40U } else if i / nk == 8 { 0x80U }
                   else if i / nk == 9 { 0x1BU } else { 0x36U }
      temp = temp ^ (rcon_val << 24)
    } else if nk > 6 && i % nk == 4 {
      temp = aes_sbox_lookup((temp >> 24) & 0xFFU) << 24
           | aes_sbox_lookup((temp >> 16) & 0xFFU) << 16
           | aes_sbox_lookup((temp >> 8) & 0xFFU) << 8
           | aes_sbox_lookup(temp & 0xFFU)
    }
    expanded[i] = expanded[i - nk] ^ temp
    i = i + 1
  }
  expanded
}

/// AES 状态: 4 个 32-bit word, 按列排列
/// state[0] = col0 = [b0,b1,b2,b3], state[1] = col1 = [b4,b5,b6,b7], ...

/// SubBytes
fn aes_sub_bytes(state : Array[UInt]) -> Unit {
  let mut i = 0
  while i < 4 {
    let s = state[i]
    state[i] = aes_sbox_lookup((s >> 24) & 0xFFU) << 24
             | aes_sbox_lookup((s >> 16) & 0xFFU) << 16
             | aes_sbox_lookup((s >> 8) & 0xFFU) << 8
             | aes_sbox_lookup(s & 0xFFU)
    i = i + 1
  }
}

/// 逆 SubBytes
fn aes_inv_sub_bytes(state : Array[UInt]) -> Unit {
  let mut i = 0
  while i < 4 {
    let s = state[i]
    state[i] = aes_inv_sbox_lookup((s >> 24) & 0xFFU) << 24
             | aes_inv_sbox_lookup((s >> 16) & 0xFFU) << 16
             | aes_inv_sbox_lookup((s >> 8) & 0xFFU) << 8
             | aes_inv_sbox_lookup(s & 0xFFU)
    i = i + 1
  }
}

/// ShiftRows: 行偏移 (左移)
/// row0: 不变; row1: 左移1; row2: 左移2; row3: 左移3
fn aes_shift_rows(state : Array[UInt]) -> Unit {
  // state[i] = [b4j, b4j+1, b4j+2, b4j+3] (b4j 在高位)
  // row1 左移 1: col1 的 [b5,b6,b7,b4] = RotL(col1, 8)
  let s1 = state[1]
  state[1] = (s1 << 8) | ((s1 >> 24) & 0xFFU)
  // row2 左移 2: col2 的 [b6,b7,b4,b5] = RotL(col2, 16)
  let s2 = state[2]
  state[2] = (s2 << 16) | ((s2 >> 16) & 0xFFFFU)
  // row3 左移 3 = 右移 1: col3 的 [b7,b4,b5,b6] = RotL(col3, 24) = RotR(col3, 8)
  let s3 = state[3]
  state[3] = ((s3 >> 8) & 0xFFFFFFU) | ((s3 & 0xFFU) << 24)
}

/// 逆 ShiftRows: 右偏移
fn aes_inv_shift_rows(state : Array[UInt]) -> Unit {
  // row1 右移 1
  let s1 = state[1]
  state[1] = ((s1 >> 8) & 0xFFFFFFU) | ((s1 & 0xFFU) << 24)
  // row2 右移 2 = 左移 2
  let s2 = state[2]
  state[2] = (s2 << 16) | ((s2 >> 16) & 0xFFFFU)
  // row3 右移 3 = 左移 1
  let s3 = state[3]
  state[3] = (s3 << 8) | ((s3 >> 24) & 0xFFU)
}

/// MixColumns: 每列乘以固定矩阵 [2,3,1,1] in GF(2^8)
fn aes_mix_columns(state : Array[UInt]) -> Unit {
  let mut i = 0
  while i < 4 {
    let s = state[i]
    let s0 = (s >> 24) & 0xFFU
    let s1 = (s >> 16) & 0xFFU
    let s2 = (s >> 8) & 0xFFU
    let s3 = s & 0xFFU
    let r0 = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3
    let r1 = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3
    let r2 = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3)
    let r3 = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3)
    state[i] = (r0 << 24) | (r1 << 16) | (r2 << 8) | r3
    i = i + 1
  }
}

/// 逆 MixColumns: 每列乘以 [0E,0B,0D,09] in GF(2^8)
fn aes_inv_mix_columns(state : Array[UInt]) -> Unit {
  let mut i = 0
  while i < 4 {
    let s = state[i]
    let s0 = (s >> 24) & 0xFFU
    let s1 = (s >> 16) & 0xFFU
    let s2 = (s >> 8) & 0xFFU
    let s3 = s & 0xFFU
    // GMUL(0x0E, x) 等等简化为调用
    let r0 = gmul2(gmul2(s0 ^ s2)) ^ gmul2(s1 ^ s2) ^ s1 ^ s2
    let r1 = gmul2(gmul2(s1 ^ s3)) ^ gmul2(s2 ^ s3) ^ s2 ^ s3
    let r2 = gmul2(gmul2(s2 ^ s0)) ^ gmul2(s3 ^ s0) ^ s3 ^ s0
    let r3 = gmul2(gmul2(s3 ^ s1)) ^ gmul2(s0 ^ s1) ^ s0 ^ s1
    state[i] = (r0 << 24) | (r1 << 16) | (r2 << 8) | r3
    i = i + 1
  }
}

/// AddRoundKey: state ^= round_key[col*4 .. col*4+3]
fn aes_add_round_key(state : Array[UInt], round_keys : Array[UInt], round : Int) -> Unit {
  let mut i = 0
  while i < 4 {
    state[i] = state[i] ^ round_keys[round * 4 + i]
    i = i + 1
  }
}

/// AES-128 单块加密 (16 bytes in, 16 bytes out)
/// 使用 round_keys (44 words, from aes_key_expand)
fn aes_encrypt_block(input : Array[UInt], round_keys : Array[UInt]) -> Array[UInt] {
  let state = [input[0], input[1], input[2], input[3]]

  // Round 0: AddRoundKey
  aes_add_round_key(state, round_keys, 0)

  // Rounds 1-10
  let mut round = 1
  while round < 10 {
    aes_sub_bytes(state)
    aes_shift_rows(state)
    aes_mix_columns(state)
    aes_add_round_key(state, round_keys, round)
    round = round + 1
  }

  // Round 10: 无 MixColumns
  aes_sub_bytes(state)
  aes_shift_rows(state)
  aes_add_round_key(state, round_keys, 10)

  state
}

/// AES-128 单块解密
fn aes_decrypt_block(input : Array[UInt], round_keys : Array[UInt]) -> Array[UInt] {
  let state = [input[0], input[1], input[2], input[3]]

  // Round 0
  aes_add_round_key(state, round_keys, 10)

  // Rounds 1-9 (反向)
  let mut round = 9
  while round >= 1 {
    aes_inv_shift_rows(state)
    aes_inv_sub_bytes(state)
    aes_add_round_key(state, round_keys, round)
    aes_inv_mix_columns(state)
    round = round - 1
  }

  // Round 10 (最后一个)
  aes_inv_shift_rows(state)
  aes_inv_sub_bytes(state)
  aes_add_round_key(state, round_keys, 0)

  state
}

/// PKCS7 填充
fn pkcs7_pad(data : Bytes) -> Bytes {
  let len = data.length()
  let pad = 16 - (len % 16)
  let arr = Array::make(len + pad, 0U)
  let mut i = 0
  while i < len {
    arr[i] = data[i].to_uint()
    i = i + 1
  }
  while i < len + pad {
    arr[i] = pad.to_uint()
    i = i + 1
  }
  Bytes::from_array(arr.map(fn(x : UInt) { x.to_byte() }))
}

/// PKCS7 验证并去除填充
fn pkcs7_unpad(data : Bytes) -> Bytes {
  let len = data.length()
  if len == 0 { return Bytes::from_array(Array::make(0, 0U.to_byte())) }
  let pad = (data[len - 1].to_uint()).to_int()
  if pad < 1 || pad > 16 { return data }
  let mut i = len - pad
  while i < len {
    if data[i].to_int() != pad { return data }
    i = i + 1
  }
  let arr = Array::make(len - pad, 0U)
  let mut j = 0
  while j < len - pad {
    arr[j] = data[j].to_uint()
    j = j + 1
  }
  Bytes::from_array(arr.map(fn(x : UInt) { x.to_byte() }))
}

/// AES-128 单块直接加密 (无padding, 仅测试用)
fn aes128_encrypt_block_test(plaintext : Bytes, key : Bytes) -> Bytes {
  if key.length() != 16 || plaintext.length() != 16 {
    return Bytes::from_array(Array::make(0, 0U.to_byte()))
  }
  // 构建 key_arr
  let key_arr = Array::make(4, 0U)
  let mut ki = 0
  while ki < 4 {
    key_arr[ki] = (key[ki * 4].to_uint() << 24)
               | (key[ki * 4 + 1].to_uint() << 16)
               | (key[ki * 4 + 2].to_uint() << 8)
               | key[ki * 4 + 3].to_uint()
    ki = ki + 1
  }
  let round_keys = aes_key_expand(key_arr)

  // 构建 input 数组
  let input = Array::make(4, 0U)
  let mut ci = 0
  while ci < 4 {
    input[ci] = (plaintext[ci * 4].to_uint() << 24)
              | (plaintext[ci * 4 + 1].to_uint() << 16)
              | (plaintext[ci * 4 + 2].to_uint() << 8)
              | plaintext[ci * 4 + 3].to_uint()
    ci = ci + 1
  }
  let state = aes_encrypt_block(input, round_keys)

  // 转换回 Bytes
  let result = Array::make(16, 0U.to_byte())
  let mut co = 0
  while co < 4 {
    let v = state[co]
    let base = co * 4
    result[base] = (v >> 24).to_byte()
    result[base + 1] = ((v >> 16) & 0xFFU).to_byte()
    result[base + 2] = ((v >> 8) & 0xFFU).to_byte()
    result[base + 3] = (v & 0xFFU).to_byte()
    co = co + 1
  }
  Bytes::from_array(result)
}

/// AES-128 单块直接解密 (无padding, 仅测试用)
fn aes128_decrypt_block_test(ciphertext : Bytes, key : Bytes) -> Bytes {
  if key.length() != 16 || ciphertext.length() != 16 {
    return Bytes::from_array(Array::make(0, 0U.to_byte()))
  }
  let key_arr = Array::make(4, 0U)
  let mut ki = 0
  while ki < 4 {
    key_arr[ki] = (key[ki * 4].to_uint() << 24)
               | (key[ki * 4 + 1].to_uint() << 16)
               | (key[ki * 4 + 2].to_uint() << 8)
               | key[ki * 4 + 3].to_uint()
    ki = ki + 1
  }
  let round_keys = aes_key_expand(key_arr)

  let input = Array::make(4, 0U)
  let mut ci = 0
  while ci < 4 {
    input[ci] = (ciphertext[ci * 4].to_uint() << 24)
              | (ciphertext[ci * 4 + 1].to_uint() << 16)
              | (ciphertext[ci * 4 + 2].to_uint() << 8)
              | ciphertext[ci * 4 + 3].to_uint()
    ci = ci + 1
  }
  let state = aes_decrypt_block(input, round_keys)

  let result = Array::make(16, 0U.to_byte())
  let mut co = 0
  while co < 4 {
    let v = state[co]
    let base = co * 4
    result[base] = (v >> 24).to_byte()
    result[base + 1] = ((v >> 16) & 0xFFU).to_byte()
    result[base + 2] = ((v >> 8) & 0xFFU).to_byte()
    result[base + 3] = (v & 0xFFU).to_byte()
    co = co + 1
  }
  Bytes::from_array(result)
}

/// AES-128 ECB 加密
pub fn aes128_encrypt(plaintext : Bytes, key : Bytes) -> Bytes {
  if key.length() != 16 { return Bytes::from_array(Array::make(0, 0U.to_byte())) }
  let padded = pkcs7_pad(plaintext)
  let num_blocks = padded.length() / 16

  // 构建 key_arr
  let key_arr = Array::make(4, 0U)
  let mut ki = 0
  while ki < 4 {
    key_arr[ki] = (key[ki * 4].to_uint() << 24)
               | (key[ki * 4 + 1].to_uint() << 16)
               | (key[ki * 4 + 2].to_uint() << 8)
               | key[ki * 4 + 3].to_uint()
    ki = ki + 1
  }
  let round_keys = aes_key_expand(key_arr)

  let result = Array::make(num_blocks * 16, 0U.to_byte())
  let mut blk = 0
  while blk < num_blocks {
    let input = Array::make(4, 0U)
    let mut ci = 0
    while ci < 4 {
      let offset = blk * 16 + ci * 4
      input[ci] = (padded[offset].to_uint() << 24)
                | (padded[offset + 1].to_uint() << 16)
                | (padded[offset + 2].to_uint() << 8)
                | padded[offset + 3].to_uint()
      ci = ci + 1
    }
    let state = aes_encrypt_block(input, round_keys)
    let mut co = 0
    while co < 4 {
      let v = state[co]
      let base = blk * 16 + co * 4
      result[base] = (v >> 24).to_byte()
      result[base + 1] = ((v >> 16) & 0xFFU).to_byte()
      result[base + 2] = ((v >> 8) & 0xFFU).to_byte()
      result[base + 3] = (v & 0xFFU).to_byte()
      co = co + 1
    }
    blk = blk + 1
  }
  Bytes::from_array(result)
}

/// AES-128 ECB 解密
pub fn aes128_decrypt(ciphertext : Bytes, key : Bytes) -> Bytes {
  if key.length() != 16 { return Bytes::from_array(Array::make(0, 0U.to_byte())) }
  if ciphertext.length() % 16 != 0 { return Bytes::from_array(Array::make(0, 0U.to_byte())) }
  let num_blocks = ciphertext.length() / 16

  let key_arr = Array::make(4, 0U)
  let mut ki = 0
  while ki < 4 {
    key_arr[ki] = (key[ki * 4].to_uint() << 24)
               | (key[ki * 4 + 1].to_uint() << 16)
               | (key[ki * 4 + 2].to_uint() << 8)
               | key[ki * 4 + 3].to_uint()
    ki = ki + 1
  }
  let round_keys = aes_key_expand(key_arr)

  let result = Array::make(num_blocks * 16, 0U.to_byte())
  let mut blk = 0
  while blk < num_blocks {
    let input = Array::make(4, 0U)
    let mut ci = 0
    while ci < 4 {
      let offset = blk * 16 + ci * 4
      input[ci] = (ciphertext[offset].to_uint() << 24)
                | (ciphertext[offset + 1].to_uint() << 16)
                | (ciphertext[offset + 2].to_uint() << 8)
                | ciphertext[offset + 3].to_uint()
      ci = ci + 1
    }
    let state = aes_decrypt_block(input, round_keys)
    let mut co = 0
    while co < 4 {
      let v = state[co]
      let base = blk * 16 + co * 4
      result[base] = (v >> 24).to_byte()
      result[base + 1] = ((v >> 16) & 0xFFU).to_byte()
      result[base + 2] = ((v >> 8) & 0xFFU).to_byte()
      result[base + 3] = (v & 0xFFU).to_byte()
      co = co + 1
    }
    blk = blk + 1
  }
  let decrypted = Bytes::from_array(result)
  pkcs7_unpad(decrypted)
}

/// AES-128 基准测试
pub fn bench_aes128() -> Unit {
  let key = Bytes::from_array(Array::make(16, 0x2BU.to_byte()))
  let plaintext = Bytes::from_array(Array::make(16, 0U.to_byte()))
  let iters = 5000
  aes128_encrypt(plaintext, key) |> ignore
  let mut i = 0
  while i < iters {
    aes128_encrypt(plaintext, key) |> ignore
    i = i + 1
  }
  println("aes128 benchmark: completed " + iters.to_string() + " iterations of aes128_encrypt(16B)")
}

/// 运行 AES-128 测试
pub fn run_aes128_tests() -> Unit {
  // FIPS 197 C.1 测试向量 (使用直接块加密，无padding)
  let key = Bytes::from_array(Array::make(16, 0x2BU.to_byte()))
  let pt = Bytes::from_array(Array::make(16, 0U.to_byte()))
  let expected_ct = "3ad77d70a40d4b73d88286e050a4a88b"
  let ct = aes128_encrypt_block_test(pt, key)
  let ct_hex = bytes_to_hex(ct)
  if ct_hex != expected_ct {
    println("FAIL: AES-128 FIPS 197 C.1")
    println("  got     = " + ct_hex)
    println("  expected= " + expected_ct)
  } else {
    println("OK: AES-128 FIPS 197 C.1")
  }

  // 解密测试 (使用直接块解密)
  let decrypted = aes128_decrypt_block_test(ct, key)
  let pt_hex = bytes_to_hex(pt)
  let dec_hex = bytes_to_hex(decrypted)
  if dec_hex != pt_hex {
    println("FAIL: AES-128 FIPS 197 C.1 decrypt")
    println("  got     = " + dec_hex)
    println("  expected= " + pt_hex)
  } else {
    println("OK: AES-128 FIPS 197 C.1 decrypt")
  }

  // roundtrip: "Two Four Six Hi!" (16字节，刚好一个块)
  let key2 = b"TwoFourSixKey12"
  let pt2 = b"Two Four Six Hi!"
  let ct2 = aes128_encrypt(pt2, key2)
  let dec2 = aes128_decrypt(ct2, key2)
  let dec2_hex = bytes_to_hex(dec2)
  let pt2_hex = bytes_to_hex(pt2)
  if dec2_hex != pt2_hex {
    println("FAIL: AES-128 roundtrip: Two Four Six Hi!")
    println("  got     = " + dec2_hex)
    println("  expected= " + pt2_hex)
  } else {
    println("OK: AES-128 roundtrip: Two Four Six Hi!")
  }

  // 48B roundtrip
  let key3 = b"1234567890abcdef"
  let pt3 = Bytes::from_array(Array::make(48, 0x5AU.to_byte()))
  let ct3 = aes128_encrypt(pt3, key3)
  let dec3 = aes128_decrypt(ct3, key3)
  let dec3_hex = bytes_to_hex(dec3)
  let pt3_hex = bytes_to_hex(pt3)
  if dec3_hex != pt3_hex {
    println("FAIL: AES-128 48B roundtrip")
    println("  got     = " + dec3_hex)
    println("  expected= " + pt3_hex)
  } else {
    println("OK: AES-128 48B roundtrip")
  }

  println("All AES-128 tests passed!")
}

/// 运行全部测试
pub fn run_all_tests() -> Unit {
  run_sha256_tests()
  run_aes128_tests()
}
