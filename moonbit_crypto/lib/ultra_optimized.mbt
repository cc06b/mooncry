// MoonBit Ultra-Optimized Crypto Library
// 极致性能优化：循环展开 + 完整查表 + 批量处理
//
// 本模块提供高度优化的SHA-256哈希算法实现：
// - 完全展开64轮压缩函数循环，消除循环控制开销
// - 预计算常量数组，避免运行时计算
// - 优化的填充和分块处理，减少内存分配
// - 寄存器变量重用，提高缓存利用率
//
// 作者：MoonBit Crypto Team
// 版本：1.0.0

// ============================================================================
// SHA-256 完全循环展开优化
// ============================================================================

const SHA256_K: Array[UInt] = [
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

fn sha256_rotr(x: UInt, n: Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

fn sha256_sigma0(x: UInt) -> UInt {
  sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3)
}

fn sha256_sigma1(x: UInt) -> UInt {
  sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10)
}

fn sha256_sigma0_upper(x: UInt) -> UInt {
  sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22)
}

fn sha256_sigma1_upper(x: UInt) -> UInt {
  sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25)
}

fn sha256_ch(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ ((0xFFFFFFFFU ^ x) & z)
}

fn sha256_maj(x: UInt, y: UInt, z: UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

fn sha256_block_unrolled(state: Array[UInt], block: Array[UInt]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  let w0 = block[0]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[0] + w0
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w1 = block[1]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[1] + w1
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w2 = block[2]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[2] + w2
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w3 = block[3]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[3] + w3
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w4 = block[4]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[4] + w4
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w5 = block[5]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[5] + w5
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w6 = block[6]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[6] + w6
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w7 = block[7]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[7] + w7
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w8 = block[8]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[8] + w8
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w9 = block[9]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[9] + w9
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w10 = block[10]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[10] + w10
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w11 = block[11]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[11] + w11
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w12 = block[12]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[12] + w12
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w13 = block[13]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[13] + w13
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w14 = block[14]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[14] + w14
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w15 = block[15]
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[15] + w15
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w16 = sha256_sigma1(w14) + w9 + sha256_sigma0(w1) + w0
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[16] + w16
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w17 = sha256_sigma1(w15) + w10 + sha256_sigma0(w2) + w1
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[17] + w17
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w18 = sha256_sigma1(w16) + w11 + sha256_sigma0(w3) + w2
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[18] + w18
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w19 = sha256_sigma1(w17) + w12 + sha256_sigma0(w4) + w3
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[19] + w19
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w20 = sha256_sigma1(w18) + w13 + sha256_sigma0(w5) + w4
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[20] + w20
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w21 = sha256_sigma1(w19) + w14 + sha256_sigma0(w6) + w5
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[21] + w21
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w22 = sha256_sigma1(w20) + w15 + sha256_sigma0(w7) + w6
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[22] + w22
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w23 = sha256_sigma1(w21) + w16 + sha256_sigma0(w8) + w7
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[23] + w23
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w24 = sha256_sigma1(w22) + w17 + sha256_sigma0(w9) + w8
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[24] + w24
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w25 = sha256_sigma1(w23) + w18 + sha256_sigma0(w10) + w9
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[25] + w25
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w26 = sha256_sigma1(w24) + w19 + sha256_sigma0(w11) + w10
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[26] + w26
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w27 = sha256_sigma1(w25) + w20 + sha256_sigma0(w12) + w11
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[27] + w27
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w28 = sha256_sigma1(w26) + w21 + sha256_sigma0(w13) + w12
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[28] + w28
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w29 = sha256_sigma1(w27) + w22 + sha256_sigma0(w14) + w13
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[29] + w29
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w30 = sha256_sigma1(w28) + w23 + sha256_sigma0(w15) + w14
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[30] + w30
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w31 = sha256_sigma1(w29) + w24 + sha256_sigma0(w16) + w15
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[31] + w31
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w32 = sha256_sigma1(w30) + w25 + sha256_sigma0(w17) + w16
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[32] + w32
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w33 = sha256_sigma1(w31) + w26 + sha256_sigma0(w18) + w17
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[33] + w33
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w34 = sha256_sigma1(w32) + w27 + sha256_sigma0(w19) + w18
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[34] + w34
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w35 = sha256_sigma1(w33) + w28 + sha256_sigma0(w20) + w19
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[35] + w35
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w36 = sha256_sigma1(w34) + w29 + sha256_sigma0(w21) + w20
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[36] + w36
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w37 = sha256_sigma1(w35) + w30 + sha256_sigma0(w22) + w21
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[37] + w37
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w38 = sha256_sigma1(w36) + w31 + sha256_sigma0(w23) + w22
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[38] + w38
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w39 = sha256_sigma1(w37) + w32 + sha256_sigma0(w24) + w23
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[39] + w39
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w40 = sha256_sigma1(w38) + w33 + sha256_sigma0(w25) + w24
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[40] + w40
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w41 = sha256_sigma1(w39) + w34 + sha256_sigma0(w26) + w25
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[41] + w41
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w42 = sha256_sigma1(w40) + w35 + sha256_sigma0(w27) + w26
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[42] + w42
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w43 = sha256_sigma1(w41) + w36 + sha256_sigma0(w28) + w27
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[43] + w43
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w44 = sha256_sigma1(w42) + w37 + sha256_sigma0(w29) + w28
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[44] + w44
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w45 = sha256_sigma1(w43) + w38 + sha256_sigma0(w30) + w29
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[45] + w45
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w46 = sha256_sigma1(w44) + w39 + sha256_sigma0(w31) + w30
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[46] + w46
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w47 = sha256_sigma1(w45) + w40 + sha256_sigma0(w32) + w31
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[47] + w47
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w48 = sha256_sigma1(w46) + w41 + sha256_sigma0(w33) + w32
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[48] + w48
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w49 = sha256_sigma1(w47) + w42 + sha256_sigma0(w34) + w33
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[49] + w49
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w50 = sha256_sigma1(w48) + w43 + sha256_sigma0(w35) + w34
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[50] + w50
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w51 = sha256_sigma1(w49) + w44 + sha256_sigma0(w36) + w35
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[51] + w51
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w52 = sha256_sigma1(w50) + w45 + sha256_sigma0(w37) + w36
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[52] + w52
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w53 = sha256_sigma1(w51) + w46 + sha256_sigma0(w38) + w37
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[53] + w53
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w54 = sha256_sigma1(w52) + w47 + sha256_sigma0(w39) + w38
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[54] + w54
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w55 = sha256_sigma1(w53) + w48 + sha256_sigma0(w40) + w39
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[55] + w55
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w56 = sha256_sigma1(w54) + w49 + sha256_sigma0(w41) + w40
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[56] + w56
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w57 = sha256_sigma1(w55) + w50 + sha256_sigma0(w42) + w41
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[57] + w57
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w58 = sha256_sigma1(w56) + w51 + sha256_sigma0(w43) + w42
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[58] + w58
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w59 = sha256_sigma1(w57) + w52 + sha256_sigma0(w44) + w43
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[59] + w59
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w60 = sha256_sigma1(w58) + w53 + sha256_sigma0(w45) + w44
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[60] + w60
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w61 = sha256_sigma1(w59) + w54 + sha256_sigma0(w46) + w45
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[61] + w61
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w62 = sha256_sigma1(w60) + w55 + sha256_sigma0(w47) + w46
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[62] + w62
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  let w63 = sha256_sigma1(w61) + w56 + sha256_sigma0(w48) + w47
  let t1 = h + sha256_sigma1_upper(e) + sha256_ch(e, f, g) + SHA256_K[63] + w63
  let t2 = sha256_sigma0_upper(a) + sha256_maj(a, b, c)
  h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

pub fn sha256_ultra(data: Bytes) -> Bytes {
  let state = Array::make(8, 0x6a09e667U)
  state[1] = 0xbb67ae85U
  state[2] = 0x3c6ef372U
  state[3] = 0xa54ff53aU
  state[4] = 0x510e527fU
  state[5] = 0x9b05688cU
  state[6] = 0x1f83d9abU
  state[7] = 0x5be0cd19U

  let len = data.length()
  let block = Array::make(16, 0U)
  let num_full_blocks = len / 64

  for i in 0..<num_full_blocks {
    let base = i * 64
    block[0] = (data[base].to_uint() << 24) | (data[base + 1].to_uint() << 16) | (data[base + 2].to_uint() << 8) | data[base + 3].to_uint()
    block[1] = (data[base + 4].to_uint() << 24) | (data[base + 5].to_uint() << 16) | (data[base + 6].to_uint() << 8) | data[base + 7].to_uint()
    block[2] = (data[base + 8].to_uint() << 24) | (data[base + 9].to_uint() << 16) | (data[base + 10].to_uint() << 8) | data[base + 11].to_uint()
    block[3] = (data[base + 12].to_uint() << 24) | (data[base + 13].to_uint() << 16) | (data[base + 14].to_uint() << 8) | data[base + 15].to_uint()
    block[4] = (data[base + 16].to_uint() << 24) | (data[base + 17].to_uint() << 16) | (data[base + 18].to_uint() << 8) | data[base + 19].to_uint()
    block[5] = (data[base + 20].to_uint() << 24) | (data[base + 21].to_uint() << 16) | (data[base + 22].to_uint() << 8) | data[base + 23].to_uint()
    block[6] = (data[base + 24].to_uint() << 24) | (data[base + 25].to_uint() << 16) | (data[base + 26].to_uint() << 8) | data[base + 27].to_uint()
    block[7] = (data[base + 28].to_uint() << 24) | (data[base + 29].to_uint() << 16) | (data[base + 30].to_uint() << 8) | data[base + 31].to_uint()
    block[8] = (data[base + 32].to_uint() << 24) | (data[base + 33].to_uint() << 16) | (data[base + 34].to_uint() << 8) | data[base + 35].to_uint()
    block[9] = (data[base + 36].to_uint() << 24) | (data[base + 37].to_uint() << 16) | (data[base + 38].to_uint() << 8) | data[base + 39].to_uint()
    block[10] = (data[base + 40].to_uint() << 24) | (data[base + 41].to_uint() << 16) | (data[base + 42].to_uint() << 8) | data[base + 43].to_uint()
    block[11] = (data[base + 44].to_uint() << 24) | (data[base + 45].to_uint() << 16) | (data[base + 46].to_uint() << 8) | data[base + 47].to_uint()
    block[12] = (data[base + 48].to_uint() << 24) | (data[base + 49].to_uint() << 16) | (data[base + 50].to_uint() << 8) | data[base + 51].to_uint()
    block[13] = (data[base + 52].to_uint() << 24) | (data[base + 53].to_uint() << 16) | (data[base + 54].to_uint() << 8) | data[base + 55].to_uint()
    block[14] = (data[base + 56].to_uint() << 24) | (data[base + 57].to_uint() << 16) | (data[base + 58].to_uint() << 8) | data[base + 59].to_uint()
    block[15] = (data[base + 60].to_uint() << 24) | (data[base + 61].to_uint() << 16) | (data[base + 62].to_uint() << 8) | data[base + 63].to_uint()
    
    sha256_block_unrolled(state, block)
  }

  let remaining = len - num_full_blocks * 64
  let base = num_full_blocks * 64
  
  for j in 0..<16 {
    block[j] = 0U
  }
  
  for j in 0..<remaining {
    let idx = base + j
    let shift = (3 - (j % 4)) * 8
    block[j / 4] = block[j / 4] | (data[idx].to_uint() << shift)
  }
  
  let shift = (3 - (remaining % 4)) * 8
  block[remaining / 4] = block[remaining / 4] | (0x80U << shift)

  if remaining >= 56 {
    sha256_block_unrolled(state, block)
    for j in 0..<16 {
      block[j] = 0U
    }
  }

  let bit_len = (len * 8).to_uint64()
  block[14] = ((bit_len >> 32) & 0xFFFFFFFFUL).to_uint()
  block[15] = (bit_len & 0xFFFFFFFFUL).to_uint()

  sha256_block_unrolled(state, block)

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
