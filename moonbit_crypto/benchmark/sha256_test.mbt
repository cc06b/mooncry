// MoonBit SHA-256 性能测试 - 带内部分时计数
// 使用迭代计数来测量相对性能

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

fn rotr(x: UInt, n: Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

fn sha256(data: Bytes) -> Bytes {
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
    let offset = i * 64
    let block = [
      (padded[offset].to_uint() << 24) | (padded[offset + 1].to_uint() << 16) | (padded[offset + 2].to_uint() << 8) | padded[offset + 3].to_uint(),
      (padded[offset + 4].to_uint() << 24) | (padded[offset + 5].to_uint() << 16) | (padded[offset + 6].to_uint() << 8) | padded[offset + 7].to_uint(),
      (padded[offset + 8].to_uint() << 24) | (padded[offset + 9].to_uint() << 16) | (padded[offset + 10].to_uint() << 8) | padded[offset + 11].to_uint(),
      (padded[offset + 12].to_uint() << 24) | (padded[offset + 13].to_uint() << 16) | (padded[offset + 14].to_uint() << 8) | padded[offset + 15].to_uint(),
      (padded[offset + 16].to_uint() << 24) | (padded[offset + 17].to_uint() << 16) | (padded[offset + 18].to_uint() << 8) | padded[offset + 19].to_uint(),
      (padded[offset + 20].to_uint() << 24) | (padded[offset + 21].to_uint() << 16) | (padded[offset + 22].to_uint() << 8) | padded[offset + 23].to_uint(),
      (padded[offset + 24].to_uint() << 24) | (padded[offset + 25].to_uint() << 16) | (padded[offset + 26].to_uint() << 8) | padded[offset + 27].to_uint(),
      (padded[offset + 28].to_uint() << 24) | (padded[offset + 29].to_uint() << 16) | (padded[offset + 30].to_uint() << 8) | padded[offset + 31].to_uint(),
      (padded[offset + 32].to_uint() << 24) | (padded[offset + 33].to_uint() << 16) | (padded[offset + 34].to_uint() << 8) | padded[offset + 35].to_uint(),
      (padded[offset + 36].to_uint() << 24) | (padded[offset + 37].to_uint() << 16) | (padded[offset + 38].to_uint() << 8) | padded[offset + 39].to_uint(),
      (padded[offset + 40].to_uint() << 24) | (padded[offset + 41].to_uint() << 16) | (padded[offset + 42].to_uint() << 8) | padded[offset + 43].to_uint(),
      (padded[offset + 44].to_uint() << 24) | (padded[offset + 45].to_uint() << 16) | (padded[offset + 46].to_uint() << 8) | padded[offset + 47].to_uint(),
      (padded[offset + 48].to_uint() << 24) | (padded[offset + 49].to_uint() << 16) | (padded[offset + 50].to_uint() << 8) | padded[offset + 51].to_uint(),
      (padded[offset + 52].to_uint() << 24) | (padded[offset + 53].to_uint() << 16) | (padded[offset + 54].to_uint() << 8) | padded[offset + 55].to_uint(),
      (padded[offset + 56].to_uint() << 24) | (padded[offset + 57].to_uint() << 16) | (padded[offset + 58].to_uint() << 8) | padded[offset + 59].to_uint(),
      (padded[offset + 60].to_uint() << 24) | (padded[offset + 61].to_uint() << 16) | (padded[offset + 62].to_uint() << 8) | padded[offset + 63].to_uint()
    ]

    let w = Array::make(64, 0U)
    for i in 0..=15 {
      w[i] = block[i]
    }
    for i in 16..=63 {
      let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w[i] = s0 + w[i - 7] + s1 + w[i - 16]
    }

    let mut a = state[0]
    let mut b = state[1]
    let mut c = state[2]
    let mut d = state[3]
    let mut e = state[4]
    let mut f = state[5]
    let mut g = state[6]
    let mut h = state[7]

    for j in 0..=63 {
      let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      let ch = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
      let temp1 = h + s1 + ch + K[j] + w[j]
      let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 + maj

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

fn main() -> Unit {
  println("======================================================================")
  println("            MoonBit SHA-256 性能测试")
  println("======================================================================")
  println()

  let iterations = 500
  let sizes = [64, 256, 1024, 4096, 16384]

  println("配置:")
  println("  - 迭代次数: " + iterations.to_string())
  println("  - 数据大小: " + sizes.to_string())
  println()

  println("-" * 70)
  println("开始测试...")
  println("-" * 70)
  println()

  for size in sizes {
    let data_arr = Array::make(size, b'\x00')
    for i in 0..<size {
      data_arr[i] = (i % 256).to_byte()
    }
    let data = Bytes::from_array(data_arr[:])

    println("数据大小: " + size.to_string() + " 字节")

    for i in 0..<iterations {
      let hash = sha256(data)
    }

    println("  完成: " + iterations.to_string() + " 次迭代")
    println()
  }

  println("-" * 70)
  println("测试完成!")
  println("-" * 70)
  println()
  println("注意: MoonBit 当前版本未提供精确计时 API")
  println("请使用外部时间测量工具（如 PowerShell Measure-Command）")
  println("来获得精确的性能数据。")
  println()
  println("======================================================================")
}
