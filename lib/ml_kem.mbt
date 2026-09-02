// ==================== ML-KEM (FIPS 203) ====================
// Module-lattice Key Encapsulation Mechanism: ML-KEM-512/768/1024.
// Pure MoonBit, no FFI. Coefficient arithmetic is mod q = 3329 in UInt
// (products fit in 32 bits). Implements Algorithms 1-18 of FIPS 203:
// Compress/Decompress, ByteEncode/ByteDecode, NTT / NTT^-1 (scale 3303 =
// 128^-1 mod q, per Algorithm 10 step 14), MultiplyNTTs, SampleNTT
// (rejection from SHAKE128), SamplePolyCBD, K-PKE.KeyGen/Encrypt/Decrypt
// and ML-KEM.KeyGen/Encaps/Decaps_internal.
// Verified against the official NIST ACVP vectors (keyGen + encapsulation
// + decapsulation, incl. implicit-rejection cases) for all three
// parameter sets.
//
// The API is the deterministic "_internal" form: callers supply the
// randomness (d, z for keygen; m for encapsulation) from a CSPRNG.
// Decapsulation returns the shared key directly (implicit rejection is
// handled internally per Algorithm 18).

// ---------- parameter sets ----------

///|
priv struct MlKemParams {
  k : Int
  eta1 : Int
  eta2 : Int
  du : Int
  dv : Int
}

///|
let mlkem_512 : MlKemParams = { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, }

///|
let mlkem_768 : MlKemParams = { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, }

///|
let mlkem_1024 : MlKemParams = { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, }

// ---------- arithmetic mod q ----------

///|
let kem_q : UInt = 3329U

///|
let kem_zeta_brv : Array[UInt] = [
  1U, 1729U, 2580U, 3289U, 2642U, 630U, 1897U, 848U, 1062U, 1919U, 193U, 797U, 2786U,
  3260U, 569U, 1746U, 296U, 2447U, 1339U, 1476U, 3046U, 56U, 2240U, 1333U, 1426U,
  2094U, 535U, 2882U, 2393U, 2879U, 1974U, 821U, 289U, 331U, 3253U, 1756U, 1197U,
  2304U, 2277U, 2055U, 650U, 1977U, 2513U, 632U, 2865U, 33U, 1320U, 1915U, 2319U,
  1435U, 807U, 452U, 1438U, 2868U, 1534U, 2402U, 2647U, 2617U, 1481U, 648U, 2474U,
  3110U, 1227U, 910U, 17U, 2761U, 583U, 2649U, 1637U, 723U, 2288U, 1100U, 1409U,
  2662U, 3281U, 233U, 756U, 2156U, 3015U, 3050U, 1703U, 1651U, 2789U, 1789U, 1847U,
  952U, 1461U, 2687U, 939U, 2308U, 2437U, 2388U, 733U, 2337U, 268U, 641U, 1584U,
  2298U, 2037U, 3220U, 375U, 2549U, 2090U, 1645U, 1063U, 319U, 2773U, 757U, 2099U,
  561U, 2466U, 2594U, 2804U, 1092U, 403U, 1026U, 1143U, 2150U, 2775U, 886U, 1722U,
  1212U, 1874U, 1029U, 2110U, 2935U, 885U, 2154U, 17U, 3312U, 2761U, 568U, 583U,
  2746U, 2649U, 680U, 1637U, 1692U, 723U, 2606U, 2288U, 1041U, 1100U, 2229U, 1409U,
  1920U, 2662U, 667U, 3281U, 48U, 233U, 3096U, 756U, 2573U, 2156U, 1173U, 3015U,
  314U, 3050U, 279U, 1703U, 1626U, 1651U, 1678U, 2789U, 540U, 1789U, 1540U, 1847U,
  1482U, 952U, 2377U, 1461U, 1868U, 2687U, 642U, 939U, 2390U, 2308U, 1021U, 2437U,
  892U, 2388U, 941U, 733U, 2596U, 2337U, 992U, 268U, 3061U, 641U, 2688U, 1584U, 1745U,
  2298U, 1031U, 2037U, 1292U, 3220U, 109U, 375U, 2954U, 2549U, 780U, 2090U, 1239U,
  1645U, 1684U, 1063U, 2266U, 319U, 3010U, 2773U, 556U, 757U, 2572U, 2099U, 1230U,
  561U, 2768U, 2466U, 863U, 2594U, 735U, 2804U, 525U, 1092U, 2237U, 403U, 2926U,
  1026U, 2303U, 1143U, 2186U, 2150U, 1179U, 2775U, 554U, 886U, 2443U, 1722U, 1607U,
  1212U, 2117U, 1874U, 1455U, 1029U, 2300U, 2110U, 1219U, 2935U, 394U, 885U, 2444U,
  2154U, 1175U,
]

///|
// gamma_i = zeta^(2*BitRev7(i)+1) mod q (Appendix A), for MultiplyNTTs.
let kem_gamma : Array[UInt] = [
  17U, 3312U, 2761U, 568U, 583U, 2746U, 2649U, 680U, 1637U, 1692U, 723U, 2606U, 2288U,
  1041U, 1100U, 2229U, 1409U, 1920U, 2662U, 667U, 3281U, 48U, 233U, 3096U, 756U,
  2573U, 2156U, 1173U, 3015U, 314U, 3050U, 279U, 1703U, 1626U, 1651U, 1678U, 2789U,
  540U, 1789U, 1540U, 1847U, 1482U, 952U, 2377U, 1461U, 1868U, 2687U, 642U, 939U,
  2390U, 2308U, 1021U, 2437U, 892U, 2388U, 941U, 733U, 2596U, 2337U, 992U, 268U,
  3061U, 641U, 2688U, 1584U, 1745U, 2298U, 1031U, 2037U, 1292U, 3220U, 109U, 375U,
  2954U, 2549U, 780U, 2090U, 1239U, 1645U, 1684U, 1063U, 2266U, 319U, 3010U, 2773U,
  556U, 757U, 2572U, 2099U, 1230U, 561U, 2768U, 2466U, 863U, 2594U, 735U, 2804U,
  525U, 1092U, 2237U, 403U, 2926U, 1026U, 2303U, 1143U, 2186U, 2150U, 1179U, 2775U,
  554U, 886U, 2443U, 1722U, 1607U, 1212U, 2117U, 1874U, 1455U, 1029U, 2300U, 2110U,
  1219U, 2935U, 394U, 885U, 2444U, 2154U, 1175U,
]

///|
fn kq_add(a : UInt, b : UInt) -> UInt {
  let s = a + b
  if s >= kem_q {
    s - kem_q
  } else {
    s
  }
}

///|
fn kq_sub(a : UInt, b : UInt) -> UInt {
  if a >= b {
    a - b
  } else {
    a + kem_q - b
  }
}

///|
fn kq_mul(a : UInt, b : UInt) -> UInt {
  a * b % kem_q
}

// ---------- NTT (FIPS 203 Algorithms 9/10) ----------

///|
fn kem_ntt(f : Array[UInt]) -> Unit {
  let mut i = 1
  let mut len = 128
  while len >= 2 {
    let mut start = 0
    while start < 256 {
      let zeta = kem_zeta_brv[i]
      i = i + 1
      for j in start..<(start + len) {
        let t = kq_mul(zeta, f[j + len])
        f[j + len] = kq_sub(f[j], t)
        f[j] = kq_add(f[j], t)
      }
      start = start + 2 * len
    }
    len = len / 2
  }
}

///|
fn kem_ntt_inv(f : Array[UInt]) -> Unit {
  let mut i = 127
  let mut len = 2
  while len <= 128 {
    let mut start = 0
    while start < 256 {
      let zeta = kem_zeta_brv[i]
      i = i - 1
      for j in start..<(start + len) {
        let t = f[j]
        f[j] = kq_add(t, f[j + len])
        f[j + len] = kq_mul(zeta, kq_sub(f[j + len], t))
      }
      start = start + 2 * len
    }
    len = len * 2
  }
  // FIPS 203 Algorithm 10 step 14: multiply by 3303 (= 128^-1 mod q)
  for j in 0..<256 {
    f[j] = kq_mul(f[j], 3303U)
  }
}

///|
// MultiplyNTTs (Algorithm 11): product in the NTT domain.
fn kem_mul_ntt(f : Array[UInt], g : Array[UInt]) -> Array[UInt] {
  let out = Array::make(256, 0U)
  for i in 0..<128 {
    let gmi = kem_gamma[i]
    let a0 = f[2 * i]
    let a1 = f[2 * i + 1]
    let b0 = g[2 * i]
    let b1 = g[2 * i + 1]
    out[2 * i] = kq_add(kq_mul(a0, b0), kq_mul(kq_mul(a1, b1), gmi))
    out[2 * i + 1] = kq_add(kq_mul(a0, b1), kq_mul(a1, b0))
  }
  out
}

// ---------- Compress / Decompress (FIPS 203) ----------

///|
fn kem_compress(x : UInt, d : Int) -> UInt {
  // round(2^d / q * x) mod 2^d = floor((2^d * x + q/2) / q)
  let num = (x << d) + 1664U
  num / kem_q
}

///|
fn kem_decompress(y : UInt, d : Int) -> UInt {
  // round(q / 2^d * y) = floor((q * y + 2^(d-1)) / 2^d)
  (kem_q * y + (1U << (d - 1))) >> d
}

// ---------- ByteEncode / ByteDecode (bit packing, d = 1..12) ----------

///|
fn kem_byte_encode(f : Array[UInt], d : Int) -> Bytes {
  let nbytes = 32 * d
  let out = Array::make(nbytes, b'\x00')
  let mut bit = 0
  for i in 0..<256 {
    let mut v = f[i]
    for _ in 0..<d {
      if (v & 1U) == 1U {
        out[bit / 8] = (out[bit / 8].to_int() | (1 << (bit % 8))).to_byte()
      }
      v = v >> 1
      bit = bit + 1
    }
  }
  Bytes::from_array(out[:])
}

///|
fn kem_byte_decode(b : Bytes, d : Int) -> Array[UInt] {
  let f = Array::make(256, 0U)
  let mut bit = 0
  for i in 0..<256 {
    let mut v = 0U
    for j in 0..<d {
      let byte = b[(bit + j) / 8].to_uint()
      if ((byte >> ((bit + j) % 8)) & 1U) == 1U {
        v = v | (1U << j)
      }
    }
    f[i] = v
    bit = bit + d
  }
  f
}

// ---------- hashes: G, H, J, PRF ----------

///|
// G(X) = SHA3-512(X) (FIPS 203 §4.1, Eq. 4.5) — NOT SHAKE256.
fn kem_g(x : Bytes) -> Bytes {
  sha3_512(x)
}

///|
// H(X) = SHA3-256(X) (FIPS 203 §4.1, Eq. 4.4) — NOT SHAKE256.
fn kem_h(x : Bytes) -> Bytes {
  sha3_256(x)
}

///|
// J(X) = SHAKE256(X, 32)
fn kem_j(x : Bytes) -> Bytes {
  shake_256(x, 32)
}

///|
fn kem_prf(eta : Int, s : Bytes, n : Int) -> Bytes {
  shake_256(concat_bytes(s, Bytes::make(1, n.to_byte())), 64 * eta)
}

// ---------- sampling ----------

///|
// Incremental XOF reader over a finalized SHAKE state: squeezes bytes
// across keccak_f permutations, exactly matching FIPS 203 XOF.Squeeze.
priv struct KemXofStream {
  state : Array[UInt64]
  rate_lanes : Int
  mut lane_idx : Int
  mut byte_idx : Int
}

///|
fn kem_xof_next(x : KemXofStream) -> Byte {
  if x.byte_idx >= 8 {
    x.byte_idx = 0
    x.lane_idx = x.lane_idx + 1
  }
  if x.lane_idx >= x.rate_lanes {
    keccak_f(x.state)
    x.lane_idx = 0
  }
  let v = x.state[x.lane_idx]
  let b = ((v >> (x.byte_idx * 8)) & 0xFFUL).to_byte()
  x.byte_idx = x.byte_idx + 1
  b
}

///|
// SampleNTT (Algorithm 7): B = rho || j_byte || i_byte; rejection sampling
// from a SHAKE128 stream.
fn kem_sample_ntt(b34 : Bytes) -> Array[UInt] {
  let h = shake_128_new()
  sha3_update(h, b34)
  // apply SHAKE padding once, absorb the final block (permutes the state)
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  let x = KemXofStream::{
    state: h.state,
    rate_lanes: h.rate / 8,
    lane_idx: 0,
    byte_idx: 0,
  }
  let out = Array::make(256, 0U)
  let mut j = 0
  while j < 256 {
    let c0 = kem_xof_next(x)
    let c1 = kem_xof_next(x)
    let c2 = kem_xof_next(x)
    let d1 = c0.to_uint() | ((c1.to_uint() & 0xFU) << 8)
    let d2 = (c1.to_uint() >> 4) | (c2.to_uint() << 4)
    if d1 < kem_q {
      out[j] = d1
      j = j + 1
    }
    if d2 < kem_q && j < 256 {
      out[j] = d2
      j = j + 1
    }
  }
  out
}

///|
// SamplePolyCBD_eta (Algorithm 8): B has 64*eta bytes.
fn kem_sample_cbd(eta : Int, b : Bytes) -> Array[UInt] {
  let f = Array::make(256, 0U)
  for i in 0..<256 {
    let mut x = 0
    let mut y = 0
    for jj in 0..<eta {
      let bit_x = (
          b[(2 * i * eta + jj) / 8].to_int() >> ((2 * i * eta + jj) % 8)
        ) &
        1
      let bit_y = (
          b[(2 * i * eta + eta + jj) / 8].to_int() >>
          ((2 * i * eta + eta + jj) % 8)
        ) &
        1
      x = x + bit_x
      y = y + bit_y
    }
    f[i] = if x >= y {
      (x - y).reinterpret_as_uint()
    } else {
      kem_q - (y - x).reinterpret_as_uint()
    }
  }
  f
}

// ---------- vector helpers ----------

///|
fn kem_vec_ntt(vec : Array[Array[UInt]]) -> Unit {
  for i in 0..<vec.length() {
    kem_ntt(vec[i])
  }
}

///|
fn kem_vec_encode(vec : Array[Array[UInt]], d : Int) -> Bytes {
  let mut acc = b""
  for i in 0..<vec.length() {
    acc = concat_bytes(acc, kem_byte_encode(vec[i], d))
  }
  acc
}

///|
fn kem_vec_decode(b : Bytes, d : Int, count : Int) -> Array[Array[UInt]] {
  let vec = Array::make(count, Array::make(256, 0U))
  let per = 32 * d
  for i in 0..<count {
    let chunk = Array::make(per, b'\x00')
    for j in 0..<per {
      chunk[j] = b[i * per + j]
    }
    vec[i] = kem_byte_decode(Bytes::from_array(chunk[:]), d)
  }
  vec
}

///|
fn kem_vec_compress(vec : Array[Array[UInt]], d : Int) -> Unit {
  for i in 0..<vec.length() {
    for j in 0..<256 {
      vec[i][j] = kem_compress(vec[i][j], d)
    }
  }
}

///|
fn kem_vec_decompress(vec : Array[Array[UInt]], d : Int) -> Unit {
  for i in 0..<vec.length() {
    for j in 0..<256 {
      vec[i][j] = kem_decompress(vec[i][j], d)
    }
  }
}

///|
fn kem_poly_compress(v : Array[UInt], d : Int) -> Unit {
  for j in 0..<256 {
    v[j] = kem_compress(v[j], d)
  }
}

// ---------- K-PKE (Algorithms 13-15) ----------

///|
// Generate matrix A-hat[i][j] = SampleNTT(rho || j || i), flat k*k array.
fn kem_expand_matrix(rho : Bytes, k : Int) -> Array[Array[UInt]] {
  let mat = Array::make(k * k, Array::make(256, 0U))
  let buf = Array::make(34, b'\x00')
  for i in 0..<32 {
    buf[i] = rho[i]
  }
  for i in 0..<k {
    for j in 0..<k {
      buf[32] = j.to_byte()
      buf[33] = i.to_byte()
      mat[i * k + j] = kem_sample_ntt(Bytes::from_array(buf[:]))
    }
  }
  mat
}

///|
fn kem_kpke_keygen(params : MlKemParams, d : Bytes) -> (Bytes, Bytes) {
  let k = params.k
  let g = kem_g(concat_bytes(d, Bytes::make(1, k.to_byte())))
  let rho = Array::make(32, b'\x00')
  let sigma = Array::make(32, b'\x00')
  for i in 0..<32 {
    rho[i] = g[i]
    sigma[i] = g[32 + i]
  }
  let rho_b = Bytes::from_array(rho[:])
  let sigma_b = Bytes::from_array(sigma[:])
  let amat = kem_expand_matrix(rho_b, k)
  let mut n = 0
  let s_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    s_vec[i] = kem_sample_cbd(params.eta1, kem_prf(params.eta1, sigma_b, n))
    n = n + 1
  }
  let e_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    e_vec[i] = kem_sample_cbd(params.eta1, kem_prf(params.eta1, sigma_b, n))
    n = n + 1
  }
  kem_vec_ntt(s_vec)
  kem_vec_ntt(e_vec)
  // t_hat = A o s_hat + e_hat
  let t_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    let acc = Array::make(256, 0U)
    for j in 0..<k {
      let prod = kem_mul_ntt(amat[i * k + j], s_vec[j])
      for c in 0..<256 {
        acc[c] = kq_add(acc[c], prod[c])
      }
    }
    for c in 0..<256 {
      acc[c] = kq_add(acc[c], e_vec[i][c])
    }
    t_vec[i] = acc
  }
  let ek = concat_bytes(kem_vec_encode(t_vec, 12), rho_b)
  let dk_pke = kem_vec_encode(s_vec, 12)
  (ek, dk_pke)
}

///|
fn kem_kpke_encrypt(
  params : MlKemParams,
  ek : Bytes,
  m : Bytes,
  r : Bytes,
) -> Bytes {
  let k = params.k
  let t_vec = kem_vec_decode(ek, 12, k)
  let rho_b = Array::make(32, b'\x00')
  for i in 0..<32 {
    rho_b[i] = ek[384 * k + i]
  }
  let rho = Bytes::from_array(rho_b[:])
  let amat = kem_expand_matrix(rho, k)
  let mut n = 0
  let y_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    y_vec[i] = kem_sample_cbd(params.eta1, kem_prf(params.eta1, r, n))
    n = n + 1
  }
  let e1_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    e1_vec[i] = kem_sample_cbd(params.eta2, kem_prf(params.eta2, r, n))
    n = n + 1
  }
  let e2 = kem_sample_cbd(params.eta2, kem_prf(params.eta2, r, n))
  kem_vec_ntt(y_vec)
  // u = NTT^-1(A^T o y_hat) + e1   (A^T[i][j] = A[j][i])
  let u_vec = Array::make(k, Array::make(256, 0U))
  for i in 0..<k {
    let acc = Array::make(256, 0U)
    for j in 0..<k {
      let prod = kem_mul_ntt(amat[j * k + i], y_vec[j])
      for c in 0..<256 {
        acc[c] = kq_add(acc[c], prod[c])
      }
    }
    kem_ntt_inv(acc)
    for c in 0..<256 {
      acc[c] = kq_add(acc[c], e1_vec[i][c])
    }
    u_vec[i] = acc
  }
  // mu = Decompress_1(ByteDecode_1(m))
  let m_bits = kem_byte_decode(m, 1)
  let mu = Array::make(256, 0U)
  for i in 0..<256 {
    mu[i] = kem_decompress(m_bits[i], 1)
  }
  // v = NTT^-1(t_hat^T o y_hat) + e2 + mu
  let v = Array::make(256, 0U)
  for j in 0..<k {
    let prod = kem_mul_ntt(t_vec[j], y_vec[j])
    for c in 0..<256 {
      v[c] = kq_add(v[c], prod[c])
    }
  }
  kem_ntt_inv(v)
  for c in 0..<256 {
    v[c] = kq_add(kq_add(v[c], e2[c]), mu[c])
  }
  kem_vec_compress(u_vec, params.du)
  kem_poly_compress(v, params.dv)
  concat_bytes(kem_vec_encode(u_vec, params.du), kem_byte_encode(v, params.dv))
}

///|
fn kem_kpke_decrypt(params : MlKemParams, dk_pke : Bytes, c : Bytes) -> Bytes {
  let k = params.k
  let c1_len = 32 * params.du * k
  let c1 = Array::make(c1_len, b'\x00')
  for i in 0..<c1_len {
    c1[i] = c[i]
  }
  let c2_len = 32 * params.dv
  let c2 = Array::make(c2_len, b'\x00')
  for i in 0..<c2_len {
    c2[i] = c[c1_len + i]
  }
  let u_vec = kem_vec_decode(Bytes::from_array(c1[:]), params.du, k)
  kem_vec_decompress(u_vec, params.du)
  let v_enc = kem_byte_decode(Bytes::from_array(c2[:]), params.dv)
  let v_dec = Array::make(256, 0U)
  for i in 0..<256 {
    v_dec[i] = kem_decompress(v_enc[i], params.dv)
  }
  let s_vec = kem_vec_decode(dk_pke, 12, k)
  // w = v' - NTT^-1(s_hat^T o NTT(u'))
  kem_vec_ntt(u_vec)
  let w = Array::make(256, 0U)
  for j in 0..<k {
    let prod = kem_mul_ntt(s_vec[j], u_vec[j])
    for c in 0..<256 {
      w[c] = kq_add(w[c], prod[c])
    }
  }
  kem_ntt_inv(w)
  for c in 0..<256 {
    w[c] = kq_sub(v_dec[c], w[c])
  }
  kem_poly_compress(w, 1)
  kem_byte_encode(w, 1)
}

// ---------- ML-KEM (Algorithms 16-18) ----------

///|
fn kem_keygen_internal(
  params : MlKemParams,
  d : Bytes,
  z : Bytes,
) -> (Bytes, Bytes) {
  if d.length() != 32 || z.length() != 32 {
    abort("ml_kem keygen: d and z must be 32 bytes")
  }
  let (ek, dk_pke) = kem_kpke_keygen(params, d)
  let dk = concat_bytes(concat_bytes(concat_bytes(dk_pke, ek), kem_h(ek)), z)
  (ek, dk)
}

///|
fn kem_encaps_internal(
  params : MlKemParams,
  ek : Bytes,
  m : Bytes,
) -> (Bytes, Bytes) {
  if m.length() != 32 {
    abort("ml_kem encaps: m must be 32 bytes")
  }
  let gm = kem_g(concat_bytes(m, kem_h(ek)))
  let k_shared = Array::make(32, b'\x00')
  let r = Array::make(32, b'\x00')
  for i in 0..<32 {
    k_shared[i] = gm[i]
    r[i] = gm[32 + i]
  }
  let c = kem_kpke_encrypt(params, ek, m, Bytes::from_array(r[:]))
  (Bytes::from_array(k_shared[:]), c)
}

///|
fn kem_decaps_internal(params : MlKemParams, dk : Bytes, c : Bytes) -> Bytes {
  let k = params.k
  let dk_pke_len = 384 * k
  let ek_len = 384 * k + 32
  let dk_pke = Array::make(dk_pke_len, b'\x00')
  for i in 0..<dk_pke_len {
    dk_pke[i] = dk[i]
  }
  let ek_pke = Array::make(ek_len, b'\x00')
  for i in 0..<ek_len {
    ek_pke[i] = dk[dk_pke_len + i]
  }
  let hsh = Array::make(32, b'\x00')
  for i in 0..<32 {
    hsh[i] = dk[768 * k + 32 + i]
  }
  let z = Array::make(32, b'\x00')
  for i in 0..<32 {
    z[i] = dk[768 * k + 64 + i]
  }
  let m_prime = kem_kpke_decrypt(params, Bytes::from_array(dk_pke[:]), c)
  let gm = kem_g(concat_bytes(m_prime, Bytes::from_array(hsh[:])))
  let k_prime = Array::make(32, b'\x00')
  let r_prime = Array::make(32, b'\x00')
  for i in 0..<32 {
    k_prime[i] = gm[i]
    r_prime[i] = gm[32 + i]
  }
  let k_bar = kem_j(concat_bytes(Bytes::from_array(z[:]), c))
  let c_prime = kem_kpke_encrypt(
    params,
    Bytes::from_array(ek_pke[:]),
    m_prime,
    Bytes::from_array(r_prime[:]),
  )
  if bytes_equal(c, c_prime) {
    Bytes::from_array(k_prime[:])
  } else {
    k_bar
  }
}

// ---------- public API ----------

///|
/// ML-KEM-512 key generation (FIPS 203): deterministic from the caller's
/// 32-byte randomness pair (d, z) — supply CSPRNG output. Returns (ek, dk).
pub fn ml_kem_512_keygen(d : Bytes, z : Bytes) -> (Bytes, Bytes) {
  kem_keygen_internal(mlkem_512, d, z)
}

///|
/// ML-KEM-512 encapsulation: deterministic from the caller's 32-byte m
/// (CSPRNG output). Returns the (shared key K, ciphertext c) pair.
pub fn ml_kem_512_encaps(ek : Bytes, m : Bytes) -> (Bytes, Bytes) {
  kem_encaps_internal(mlkem_512, ek, m)
}

///|
/// ML-KEM-512 decapsulation: returns the 32-byte shared key. Implicit
/// rejection (Algorithm 18) is handled internally.
pub fn ml_kem_512_decaps(dk : Bytes, c : Bytes) -> Bytes {
  kem_decaps_internal(mlkem_512, dk, c)
}

///|
/// ML-KEM-768 key generation. See `ml_kem_512_keygen`.
pub fn ml_kem_768_keygen(d : Bytes, z : Bytes) -> (Bytes, Bytes) {
  kem_keygen_internal(mlkem_768, d, z)
}

///|
/// ML-KEM-768 encapsulation. See `ml_kem_512_encaps`.
pub fn ml_kem_768_encaps(ek : Bytes, m : Bytes) -> (Bytes, Bytes) {
  kem_encaps_internal(mlkem_768, ek, m)
}

///|
/// ML-KEM-768 decapsulation. See `ml_kem_512_decaps`.
pub fn ml_kem_768_decaps(dk : Bytes, c : Bytes) -> Bytes {
  kem_decaps_internal(mlkem_768, dk, c)
}

///|
/// ML-KEM-1024 key generation. See `ml_kem_512_keygen`.
pub fn ml_kem_1024_keygen(d : Bytes, z : Bytes) -> (Bytes, Bytes) {
  kem_keygen_internal(mlkem_1024, d, z)
}

///|
/// ML-KEM-1024 encapsulation. See `ml_kem_512_encaps`.
pub fn ml_kem_1024_encaps(ek : Bytes, m : Bytes) -> (Bytes, Bytes) {
  kem_encaps_internal(mlkem_1024, ek, m)
}

///|
/// ML-KEM-1024 decapsulation. See `ml_kem_512_decaps`.
pub fn ml_kem_1024_decaps(dk : Bytes, c : Bytes) -> Bytes {
  kem_decaps_internal(mlkem_1024, dk, c)
}
