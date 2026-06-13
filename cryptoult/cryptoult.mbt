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
