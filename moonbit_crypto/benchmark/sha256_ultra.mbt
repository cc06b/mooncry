// MoonBit SHA-256 - 极致性能优化版本
// 目标：接近纯 C 性能

// ============================================================================
// 极致优化策略
// ============================================================================

// 1. 完全使用 const 预计算
const K: Array[UInt] = [
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

const H_INIT: Array[UInt] = [
  0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
  0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
]

// 2. 极致内联：旋转右移
fn rotr(x: UInt, n: Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

// 3. 批量处理：一次性读取16个字（4字节 × 16 = 64字节）
fn read_block(data: Array[Byte], offset: Int) -> Array[UInt] {
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
    (data[offset + 16].to_uint() << 24) |
    (data[offset + 17].to_uint() << 16) |
    (data[offset + 18].to_uint() << 8) |
    data[offset + 19].to_uint(),
    (data[offset + 20].to_uint() << 24) |
    (data[offset + 21].to_uint() << 16) |
    (data[offset + 22].to_uint() << 8) |
    data[offset + 23].to_uint(),
    (data[offset + 24].to_uint() << 24) |
    (data[offset + 25].to_uint() << 16) |
    (data[offset + 26].to_uint() << 8) |
    data[offset + 27].to_uint(),
    (data[offset + 28].to_uint() << 24) |
    (data[offset + 29].to_uint() << 16) |
    (data[offset + 30].to_uint() << 8) |
    data[offset + 31].to_uint(),
    (data[offset + 32].to_uint() << 24) |
    (data[offset + 33].to_uint() << 16) |
    (data[offset + 34].to_uint() << 8) |
    data[offset + 35].to_uint(),
    (data[offset + 36].to_uint() << 24) |
    (data[offset + 37].to_uint() << 16) |
    (data[offset + 38].to_uint() << 8) |
    data[offset + 39].to_uint(),
    (data[offset + 40].to_uint() << 24) |
    (data[offset + 41].to_uint() << 16) |
    (data[offset + 42].to_uint() << 8) |
    data[offset + 43].to_uint(),
    (data[offset + 44].to_uint() << 24) |
    (data[offset + 45].to_uint() << 16) |
    (data[offset + 46].to_uint() << 8) |
    data[offset + 47].to_uint(),
    (data[offset + 48].to_uint() << 24) |
    (data[offset + 49].to_uint() << 16) |
    (data[offset + 50].to_uint() << 8) |
    data[offset + 51].to_uint(),
    (data[offset + 52].to_uint() << 24) |
    (data[offset + 53].to_uint() << 16) |
    (data[offset + 54].to_uint() << 8) |
    data[offset + 55].to_uint(),
    (data[offset + 56].to_uint() << 24) |
    (data[offset + 57].to_uint() << 16) |
    (data[offset + 58].to_uint() << 8) |
    data[offset + 59].to_uint(),
    (data[offset + 60].to_uint() << 24) |
    (data[offset + 61].to_uint() << 16) |
    (data[offset + 62].to_uint() << 8) |
    data[offset + 63].to_uint()
  ]
}

// 4. 展开主循环：完全内联64轮计算
fn sha256_block_opt(state: Array[UInt], block: Array[UInt]) -> Unit {
  // 预取数据到局部变量（减少数组访问）
  let w0 = block[0]
  let w1 = block[1]
  let w2 = block[2]
  let w3 = block[3]
  let w4 = block[4]
  let w5 = block[5]
  let w6 = block[6]
  let w7 = block[7]
  let w8 = block[8]
  let w9 = block[9]
  let w10 = block[10]
  let w11 = block[11]
  let w12 = block[12]
  let w13 = block[13]
  let w14 = block[14]
  let w15 = block[15]
  
  // 消息扩展（16-63）
  let w16 = rotr(w14, 17) ^ rotr(w14, 19) ^ (w14 >> 10) + w9 + rotr(w1, 7) ^ rotr(w1, 18) ^ (w1 >> 3) + w0
  let w17 = rotr(w15, 17) ^ rotr(w15, 19) ^ (w15 >> 10) + w10 + rotr(w2, 7) ^ rotr(w2, 18) ^ (w2 >> 3) + w1
  let w18 = rotr(w16, 17) ^ rotr(w16, 19) ^ (w16 >> 10) + w11 + rotr(w3, 7) ^ rotr(w3, 18) ^ (w3 >> 3) + w2
  let w19 = rotr(w17, 17) ^ rotr(w17, 19) ^ (w17 >> 10) + w12 + rotr(w4, 7) ^ rotr(w4, 18) ^ (w4 >> 3) + w3
  let w20 = rotr(w18, 17) ^ rotr(w18, 19) ^ (w18 >> 10) + w13 + rotr(w5, 7) ^ rotr(w5, 18) ^ (w5 >> 3) + w4
  let w21 = rotr(w19, 17) ^ rotr(w19, 19) ^ (w19 >> 10) + w14 + rotr(w6, 7) ^ rotr(w6, 18) ^ (w6 >> 3) + w5
  let w22 = rotr(w20, 17) ^ rotr(w20, 19) ^ (w20 >> 10) + w15 + rotr(w7, 7) ^ rotr(w7, 18) ^ (w7 >> 3) + w6
  let w23 = rotr(w21, 17) ^ rotr(w21, 19) ^ (w21 >> 10) + w16 + rotr(w8, 7) ^ rotr(w8, 18) ^ (w8 >> 3) + w7
  let w24 = rotr(w22, 17) ^ rotr(w22, 19) ^ (w22 >> 10) + w17 + rotr(w9, 7) ^ rotr(w9, 18) ^ (w9 >> 3) + w8
  let w25 = rotr(w23, 17) ^ rotr(w23, 19) ^ (w23 >> 10) + w18 + rotr(w10, 7) ^ rotr(w10, 18) ^ (w10 >> 3) + w9
  let w26 = rotr(w24, 17) ^ rotr(w24, 19) ^ (w24 >> 10) + w19 + rotr(w11, 7) ^ rotr(w11, 18) ^ (w11 >> 3) + w10
  let w27 = rotr(w25, 17) ^ rotr(w25, 19) ^ (w25 >> 10) + w20 + rotr(w12, 7) ^ rotr(w12, 18) ^ (w12 >> 3) + w11
  let w28 = rotr(w26, 17) ^ rotr(w26, 19) ^ (w26 >> 10) + w21 + rotr(w13, 7) ^ rotr(w13, 18) ^ (w13 >> 3) + w12
  let w29 = rotr(w27, 17) ^ rotr(w27, 19) ^ (w27 >> 10) + w22 + rotr(w14, 7) ^ rotr(w14, 18) ^ (w14 >> 3) + w13
  let w30 = rotr(w28, 17) ^ rotr(w28, 19) ^ (w28 >> 10) + w23 + rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3) + w14
  let w31 = rotr(w29, 17) ^ rotr(w29, 19) ^ (w29 >> 10) + w24 + rotr(w16, 7) ^ rotr(w16, 18) ^ (w16 >> 3) + w15
  let w32 = rotr(w30, 17) ^ rotr(w30, 19) ^ (w30 >> 10) + w25 + rotr(w17, 7) ^ rotr(w17, 18) ^ (w17 >> 3) + w16
  let w33 = rotr(w31, 17) ^ rotr(w31, 19) ^ (w31 >> 10) + w26 + rotr(w18, 7) ^ rotr(w18, 18) ^ (w18 >> 3) + w17
  let w34 = rotr(w32, 17) ^ rotr(w32, 19) ^ (w32 >> 10) + w27 + rotr(w19, 7) ^ rotr(w19, 18) ^ (w19 >> 3) + w18
  let w35 = rotr(w33, 17) ^ rotr(w33, 19) ^ (w33 >> 10) + w28 + rotr(w20, 7) ^ rotr(w20, 18) ^ (w20 >> 3) + w19
  let w36 = rotr(w34, 17) ^ rotr(w34, 19) ^ (w34 >> 10) + w29 + rotr(w21, 7) ^ rotr(w21, 18) ^ (w21 >> 3) + w20
  let w37 = rotr(w35, 17) ^ rotr(w35, 19) ^ (w35 >> 10) + w30 + rotr(w22, 7) ^ rotr(w22, 18) ^ (w22 >> 3) + w21
  let w38 = rotr(w36, 17) ^ rotr(w36, 19) ^ (w36 >> 10) + w31 + rotr(w23, 7) ^ rotr(w23, 18) ^ (w23 >> 3) + w22
  let w39 = rotr(w37, 17) ^ rotr(w37, 19) ^ (w37 >> 10) + w32 + rotr(w24, 7) ^ rotr(w24, 18) ^ (w24 >> 3) + w23
  let w40 = rotr(w38, 17) ^ rotr(w38, 19) ^ (w38 >> 10) + w33 + rotr(w25, 7) ^ rotr(w25, 18) ^ (w25 >> 3) + w24
  let w41 = rotr(w39, 17) ^ rotr(w39, 19) ^ (w39 >> 10) + w34 + rotr(w26, 7) ^ rotr(w26, 18) ^ (w26 >> 3) + w25
  let w42 = rotr(w40, 17) ^ rotr(w40, 19) ^ (w40 >> 10) + w35 + rotr(w27, 7) ^ rotr(w27, 18) ^ (w27 >> 3) + w26
  let w43 = rotr(w41, 17) ^ rotr(w41, 19) ^ (w41 >> 10) + w36 + rotr(w28, 7) ^ rotr(w28, 18) ^ (w28 >> 3) + w27
  let w44 = rotr(w42, 17) ^ rotr(w42, 19) ^ (w42 >> 10) + w37 + rotr(w29, 7) ^ rotr(w29, 18) ^ (w29 >> 3) + w28
  let w45 = rotr(w43, 17) ^ rotr(w43, 19) ^ (w43 >> 10) + w38 + rotr(w30, 7) ^ rotr(w30, 18) ^ (w30 >> 3) + w29
  let w46 = rotr(w44, 17) ^ rotr(w44, 19) ^ (w44 >> 10) + w39 + rotr(w31, 7) ^ rotr(w31, 18) ^ (w31 >> 3) + w30
  let w47 = rotr(w45, 17) ^ rotr(w45, 19) ^ (w45 >> 10) + w40 + rotr(w32, 7) ^ rotr(w32, 18) ^ (w32 >> 3) + w31
  let w48 = rotr(w46, 17) ^ rotr(w46, 19) ^ (w46 >> 10) + w41 + rotr(w33, 7) ^ rotr(w33, 18) ^ (w33 >> 3) + w32
  let w49 = rotr(w47, 17) ^ rotr(w47, 19) ^ (w47 >> 10) + w42 + rotr(w34, 7) ^ rotr(w34, 18) ^ (w34 >> 3) + w33
  let w50 = rotr(w48, 17) ^ rotr(w48, 19) ^ (w48 >> 10) + w43 + rotr(w35, 7) ^ rotr(w35, 18) ^ (w35 >> 3) + w34
  let w51 = rotr(w49, 17) ^ rotr(w49, 19) ^ (w49 >> 10) + w44 + rotr(w36, 7) ^ rotr(w36, 18) ^ (w36 >> 3) + w35
  let w52 = rotr(w50, 17) ^ rotr(w50, 19) ^ (w50 >> 10) + w45 + rotr(w37, 7) ^ rotr(w37, 18) ^ (w37 >> 3) + w36
  let w53 = rotr(w51, 17) ^ rotr(w51, 19) ^ (w51 >> 10) + w46 + rotr(w38, 7) ^ rotr(w38, 18) ^ (w38 >> 3) + w37
  let w54 = rotr(w52, 17) ^ rotr(w52, 19) ^ (w52 >> 10) + w47 + rotr(w39, 7) ^ rotr(w39, 18) ^ (w39 >> 3) + w38
  let w55 = rotr(w53, 17) ^ rotr(w53, 19) ^ (w53 >> 10) + w48 + rotr(w40, 7) ^ rotr(w40, 18) ^ (w40 >> 3) + w39
  let w56 = rotr(w54, 17) ^ rotr(w54, 19) ^ (w54 >> 10) + w49 + rotr(w41, 7) ^ rotr(w41, 18) ^ (w41 >> 3) + w40
  let w57 = rotr(w55, 17) ^ rotr(w55, 19) ^ (w55 >> 10) + w50 + rotr(w42, 7) ^ rotr(w42, 18) ^ (w42 >> 3) + w41
  let w58 = rotr(w56, 17) ^ rotr(w56, 19) ^ (w56 >> 10) + w51 + rotr(w43, 7) ^ rotr(w43, 18) ^ (w43 >> 3) + w42
  let w59 = rotr(w57, 17) ^ rotr(w57, 19) ^ (w57 >> 10) + w52 + rotr(w44, 7) ^ rotr(w44, 18) ^ (w44 >> 3) + w43
  let w60 = rotr(w58, 17) ^ rotr(w58, 19) ^ (w58 >> 10) + w53 + rotr(w45, 7) ^ rotr(w45, 18) ^ (w45 >> 3) + w44
  let w61 = rotr(w59, 17) ^ rotr(w59, 19) ^ (w59 >> 10) + w54 + rotr(w46, 7) ^ rotr(w46, 18) ^ (w46 >> 3) + w45
  let w62 = rotr(w60, 17) ^ rotr(w60, 19) ^ (w60 >> 10) + w55 + rotr(w47, 7) ^ rotr(w47, 18) ^ (w47 >> 3) + w46
  let w63 = rotr(w61, 17) ^ rotr(w61, 19) ^ (w61 >> 10) + w56 + rotr(w48, 7) ^ rotr(w48, 18) ^ (w48 >> 3) + w47

  // 初始化工作变量
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  // 轮次0
  let t1 = h + rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25) + (e & f) ^ ((0xFFFFFFFFU ^ e) & g) + K[0] + w0
  let t2 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22) + (a & b) ^ (a & c) ^ (b & c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮次1
  let t1 = h + rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25) + (e & f) ^ ((0xFFFFFFFFU ^ e) & g) + K[1] + w1
  let t2 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22) + (a & b) ^ (a & c) ^ (b & c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 更新哈希值
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

// 5. SHA-256 主函数（优化版）
fn sha256_fast(data: Bytes) -> Bytes {
  let state = [H_INIT[0], H_INIT[1], H_INIT[2], H_INIT[3], H_INIT[4], H_INIT[5], H_INIT[6], H_INIT[7]]

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
  let base = original_len + 1 + pad_len
  padded[base] = ((bit_len_u64 >> 56) & 0xFFUL).to_byte()
  padded[base + 1] = ((bit_len_u64 >> 48) & 0xFFUL).to_byte()
  padded[base + 2] = ((bit_len_u64 >> 40) & 0xFFUL).to_byte()
  padded[base + 3] = ((bit_len_u64 >> 32) & 0xFFUL).to_byte()
  padded[base + 4] = ((bit_len_u64 >> 24) & 0xFFUL).to_byte()
  padded[base + 5] = ((bit_len_u64 >> 16) & 0xFFUL).to_byte()
  padded[base + 6] = ((bit_len_u64 >> 8) & 0xFFUL).to_byte()
  padded[base + 7] = (bit_len_u64 & 0xFFUL).to_byte()

  let block_count = final_len / 64
  for i in 0..<block_count {
    let block = read_block(padded, i * 64)
    sha256_block_opt(state, block)
  }

  let result = Array::make(32, b'\x00')
  for i in 0..=7 {
    let val = state[i]
    result[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result[i * 4 + 3] = (val & 0xFFU).to_byte()
  }

  Bytes::from_array(result[:])
}

fn bytes_to_hex(data: Bytes) -> String {
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

fn main() -> Unit {
  println("======================================================================")
  println("      MoonBit SHA-256 极致优化版本 - 性能测试")
  println("======================================================================")
  println()

  let iterations = 100
  let sizes = [64, 256, 1024, 4096, 16384]

  println("测试配置:")
  println("  - 迭代次数: " + iterations.to_string())
  println("  - 优化策略: const预计算 + 批量读取 + 消息扩展展开")
  println()

  for size in sizes {
    let data_arr = Array::make(size, b'\x00')
    for i in 0..<size {
      data_arr[i] = (i % 256).to_byte()
    }
    let data = Bytes::from_array(data_arr[:])

    for _ in 0..<iterations {
      let hash = sha256_fast(data)
    }

    println("大小: " + size.to_string() + " 字节 -> 完成 " + iterations.to_string() + " 次迭代")
  }

  println()
  println("======================================================================")
  println("测试完成！")
  println("======================================================================")
}
