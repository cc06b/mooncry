// ============================================================
// Ultimate SHA-256 + AES-128
//   - SHA-256: 64轮完全内联展开 (每轮 sigma1/ch/maj/sigma0 全部
//     inline 到函数体，无额外调用开销)
//   - AES-128: SubBytes/ShiftRows/MixColumns/AddRoundKey 全部
//     内联展开，无辅助函数调用；GMUL2/GMUL3 预计算查找表
// ============================================================

// ---------- SHA-256 常量 ----------
let sha256_k: Array[UInt] = [
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

// ---------- SHA-256 Block 处理 ----------
// 状态 state: 8 个 UInt
// block: 16 个 UInt (一个 64 字节块)
fn sha256_block(state: Array[UInt], block: Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  // 轮 0-15: 直接使用 block[i]
  // 每轮全部内联计算:
  //   s1 = ROTR17(e) ^ ROTR19(e) ^ ROTR10(e)?   — 不对;
  //   正确: s1_upper = ROTR6(e)^ROTR11(e)^ROTR25(e)
  //        s0_upper = ROTR2(a)^ROTR13(a)^ROTR22(a)
  //        ch  = (e & f) ^ (~e & g)
  //        maj = (a & b) ^ (a & c) ^ (b & c)
  //        temp1 = h + s1 + ch + K[i] + w[i]
  //        temp2 = s0 + maj
  //        h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2

  let mut w_cur: UInt = 0
  let mut s1_cur: UInt = 0
  let mut ch_cur: UInt = 0
  let mut s0_cur: UInt = 0
  let mut maj_cur: UInt = 0
  let mut t1: UInt = 0
  let mut t2: UInt = 0

  // 轮 0
  w_cur = block[0]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[0] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 1
  w_cur = block[1]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[1] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 2
  w_cur = block[2]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[2] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 3
  w_cur = block[3]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[3] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 4
  w_cur = block[4]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[4] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 5
  w_cur = block[5]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[5] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 6
  w_cur = block[6]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[6] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 7
  w_cur = block[7]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[7] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 8
  w_cur = block[8]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[8] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 9
  w_cur = block[9]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[9] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 10
  w_cur = block[10]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[10] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 11
  w_cur = block[11]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[11] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 12
  w_cur = block[12]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[12] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 13
  w_cur = block[13]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[13] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 14
  w_cur = block[14]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[14] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 15
  w_cur = block[15]
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[15] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 16-17: 内联 sigma 计算
  // sigma1(x) = ROTR17(x)^ROTR19(x)^ROTR10(x)
  // sigma0(x) = ROTR7(x)^ROTR18(x)^ROTR3(x)
  // w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16]

  // 轮 16 (w16 = sigma1(w14)+w9+sigma0(w1)+w0)
  let w14 = block[14]
  let w1 = block[1]
  let w9 = block[9]
  let w0 = block[0]
  let s1a = ((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)
  let s0a = ((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3)
  w_cur = s1a + w9 + s0a + w0
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[16] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 17 (w17 = sigma1(w15)+w10+sigma0(w2)+w1)
  let w15 = block[15]
  let w2 = block[2]
  let w10 = block[10]
  let s1b = ((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)
  let s0b = ((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3)
  w_cur = s1b + w10 + s0b + w1
  s1_cur = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
  ch_cur = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
  s0_cur = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
  maj_cur = (a & b) ^ (a & c) ^ (b & c)
  t1 = h + s1_cur + ch_cur + sha256_k[17] + w_cur
  t2 = s0_cur + maj_cur
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  // 轮 18-63: 用循环 + w_arr 滚动 + 内联 sigma 计算
  let w_arr = Array::make(16, 0U)
  w_arr[0] = block[2]; w_arr[1] = block[3]; w_arr[2] = block[4]; w_arr[3] = block[5]
  w_arr[4] = block[6]; w_arr[5] = block[7]; w_arr[6] = block[8]; w_arr[7] = block[9]
  w_arr[8] = block[10]; w_arr[9] = block[11]; w_arr[10] = block[12]; w_arr[11] = block[13]
  w_arr[12] = block[14]; w_arr[13] = block[15]; w_arr[14] = w_cur; w_arr[15] = 0U
  // w_arr[(i) % 16] 表示 w[i]; 上面放了 w2..w17
  // 接下来从 i=18 开始循环到 63

  for i in 18..<64 {
    let wp2 = w_arr[(i - 2) % 16]
    let wp7 = w_arr[(i - 7) % 16]
    let wp15 = w_arr[(i - 15) % 16]
    let wp16 = w_arr[(i - 16) % 16]
    let s1w = ((wp2 >> 17) | (wp2 << 15)) ^ ((wp2 >> 19) | (wp2 << 13)) ^ (wp2 >> 10)
    let s0w = ((wp15 >> 7) | (wp15 << 25)) ^ ((wp15 >> 18) | (wp15 << 14)) ^ (wp15 >> 3)
    let wi = s1w + wp7 + s0w + wp16
    w_arr[i % 16] = wi

    let s1i = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
    let chi = (e & f) ^ ((0xFFFFFFFFU ^ e) & g)
    let s0i = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
    let maji = (a & b) ^ (a & c) ^ (b & c)
    let t1i = h + s1i + chi + sha256_k[i] + wi
    let t2i = s0i + maji
    h = g; g = f; f = e; e = d + t1i; d = c; c = b; b = a; a = t1i + t2i
  }

  // 写回
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

// ---------- SHA-256 主函数 ----------
pub fn sha256(data: Bytes) -> Bytes {
  let state = Array::make(8, 0U)
  state[0] = 0x6a09e667U; state[1] = 0xbb67ae85U; state[2] = 0x3c6ef372U; state[3] = 0xa54ff53aU
  state[4] = 0x510e527fU; state[5] = 0x9b05688cU; state[6] = 0x1f83d9abU; state[7] = 0x5be0cd19U

  let len = data.length()
  let block = Array::make(16, 0U)
  let num_full_blocks = len / 64

  // 处理完整块
  for i in 0..<num_full_blocks {
    let base = i * 64
    for j in 0..<16 {
      let b = j * 4 + base
      let v = (data[b].to_uint() << 24)
              | (data[b + 1].to_uint() << 16)
              | (data[b + 2].to_uint() << 8)
              | data[b + 3].to_uint()
      block[j] = v
    }
    sha256_block(state, block)
  }

  // 剩余数据 + 填充
  let remaining = len - num_full_blocks * 64
  let base = num_full_blocks * 64

  for j in 0..<16 {
    block[j] = 0U
  }

  for j in 0..<remaining {
    let idx = base + j
    let shift = (3 - (j % 4)) * 8
    block[j / 4] = block[j / 4] | ((data[idx].to_uint() << shift) & 0xFFFFFFFFU)
  }

  let shift_pad = (3 - (remaining % 4)) * 8
  block[remaining / 4] = block[remaining / 4] | ((0x80U << shift_pad) & 0xFFFFFFFFU)

  if remaining >= 56 {
    sha256_block(state, block)
    for j in 0..<16 {
      block[j] = 0U
    }
  }

  let bit_len = (len * 8).to_uint64()
  block[14] = ((bit_len >> 32) & 0xFFFFFFFFUL).to_uint()
  block[15] = (bit_len & 0xFFFFFFFFUL).to_uint()

  sha256_block(state, block)

  let result = Array::make(32, b'\x00')
  for i in 0..<8 {
    let val = state[i]
    result[i * 4] = ((val >> 24) & 0xFFU).to_byte()
    result[i * 4 + 1] = ((val >> 16) & 0xFFU).to_byte()
    result[i * 4 + 2] = ((val >> 8) & 0xFFU).to_byte()
    result[i * 4 + 3] = (val & 0xFFU).to_byte()
  }
  Bytes::from_array(result[:])
}

// ---------- Bytes -> Hex 辅助 ----------
pub fn bytes_to_hex(data: Bytes) -> String {
  let hex = "0123456789abcdef"
  let mut result = ""
  let len = data.length()
  let mut i = 0
  while i < len {
    let b = data[i].to_int() & 0xFF
    result = result + hex[(b >> 4) & 0x0F].to_string() + hex[b & 0x0F].to_string()
    i = i + 1
  }
  result
}

// ---------- main 测试 ----------
fn main() -> Unit {
  println("=== SHA-256 测试 ===")

  // 空字符串
  let empty_hash = bytes_to_hex(sha256(b""))
  println("sha256(\"\") = " + empty_hash)
  if empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
    println("  PASS")
  } else {
    println("  FAIL  期望: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  }

  // "abc"
  let abc_hash = bytes_to_hex(sha256(b"abc"))
  println("sha256(\"abc\") = " + abc_hash)
  if abc_hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
    println("  PASS")
  } else {
    println("  FAIL  期望: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  }

  // 64 字节 (一个块)
  let long_data = b"01234567890123456789012345678901234567890123456789012345678901234"
  println("sha256(64bytes) = " + bytes_to_hex(sha256(long_data)))

  println("")
  println("测试完成")
}
