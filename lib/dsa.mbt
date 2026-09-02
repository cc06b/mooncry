// ==================== ML-DSA (FIPS 204) ====================
// Module-Lattice Digital Signature: ML-DSA-44/65/87, pure variant
// (Sign_internal / Verify_internal / KeyGen_internal). Deterministic
// signing with caller-supplied per-message randomness `rnd` (use the
// all-zero constant for the FIPS "deterministic" variant, fresh CSPRNG
// output for the hedged variant). Verified against the official NIST ACVP
// vectors (keyGen, pure sigGen deterministic, sigVer) for all three
// parameter sets. Ported from the FIPS-204 pq-crystals reference with
// plain mod-q arithmetic (no Montgomery).

// ---------- parameter sets ----------

///|
priv struct DsaParams {
  k : Int
  l : Int
  eta : Int
  tau : Int
  gamma1 : Int
  gamma2 : Int
  omega : Int
  ctilde : Int
  beta : Int
}

///|
let dsa_q : Int = 8380417

///|
// 2^32 mod q (unused in plain-arithmetic port; kept for reference)
let dsa_44 : DsaParams = {
  k: 4,
  l: 4,
  eta: 2,
  tau: 39,
  gamma1: 1 << 17,
  gamma2: (dsa_q - 1) / 88,
  omega: 80,
  ctilde: 32,
  beta: 78,
}

///|
let dsa_65 : DsaParams = {
  k: 6,
  l: 5,
  eta: 4,
  tau: 49,
  gamma1: 1 << 19,
  gamma2: (dsa_q - 1) / 32,
  omega: 55,
  ctilde: 48,
  beta: 196,
}

///|
let dsa_87 : DsaParams = {
  k: 8,
  l: 7,
  eta: 2,
  tau: 60,
  gamma1: 1 << 19,
  gamma2: (dsa_q - 1) / 32,
  omega: 75,
  ctilde: 64,
  beta: 120,
}

// ---------- mod-q arithmetic (coefficients kept in [0, q)) ----------

///|
fn dq_add(a : Int, b : Int) -> Int {
  let s = a + b
  if s >= dsa_q {
    s - dsa_q
  } else {
    s
  }
}

///|
fn dq_sub(a : Int, b : Int) -> Int {
  if a >= b {
    a - b
  } else {
    a + dsa_q - b
  }
}

///|
fn dq_mul(a : Int, b : Int) -> Int {
  // NOTE: MoonBit Int is 32-bit on wasm-gc; (q-1)^2 overflows. Widen.
  (a.to_int64() * b.to_int64() % 8380417L).to_int()
}

///|
// centered representative in (-q/2, q/2]
fn dq_centered(a : Int) -> Int {
  if a > dsa_q / 2 {
    a - dsa_q
  } else {
    a
  }
}

// ---------- NTT (FIPS 204 Algorithm 41/42; zetas[m] = 1753^BitRev8(m)) ----------

///|
let dsa_zetas : Array[UInt] = [
  1U, 4808194U, 3765607U, 3761513U, 5178923U, 5496691U, 5234739U, 5178987U, 7778734U,
  3542485U, 2682288U, 2129892U, 3764867U, 7375178U, 557458U, 7159240U, 5010068U,
  4317364U, 2663378U, 6705802U, 4855975U, 7946292U, 676590U, 7044481U, 5152541U,
  1714295U, 2453983U, 1460718U, 7737789U, 4795319U, 2815639U, 2283733U, 3602218U,
  3182878U, 2740543U, 4793971U, 5269599U, 2101410U, 3704823U, 1159875U, 394148U,
  928749U, 1095468U, 4874037U, 2071829U, 4361428U, 3241972U, 2156050U, 3415069U,
  1759347U, 7562881U, 4805951U, 3756790U, 6444618U, 6663429U, 4430364U, 5483103U,
  3192354U, 556856U, 3870317U, 2917338U, 1853806U, 3345963U, 1858416U, 3073009U,
  1277625U, 5744944U, 3852015U, 4183372U, 5157610U, 5258977U, 8106357U, 2508980U,
  2028118U, 1937570U, 4564692U, 2811291U, 5396636U, 7270901U, 4158088U, 1528066U,
  482649U, 1148858U, 5418153U, 7814814U, 169688U, 2462444U, 5046034U, 4213992U, 4892034U,
  1987814U, 5183169U, 1736313U, 235407U, 5130263U, 3258457U, 5801164U, 1787943U,
  5989328U, 6125690U, 3482206U, 4197502U, 7080401U, 6018354U, 7062739U, 2461387U,
  3035980U, 621164U, 3901472U, 7153756U, 2925816U, 3374250U, 1356448U, 5604662U,
  2683270U, 5601629U, 4912752U, 2312838U, 7727142U, 7921254U, 348812U, 8052569U,
  1011223U, 6026202U, 4561790U, 6458164U, 6143691U, 1744507U, 1753U, 6444997U, 5720892U,
  6924527U, 2660408U, 6600190U, 8321269U, 2772600U, 1182243U, 87208U, 636927U, 4415111U,
  4423672U, 6084020U, 5095502U, 4663471U, 8352605U, 822541U, 1009365U, 5926272U,
  6400920U, 1596822U, 4423473U, 4620952U, 6695264U, 4969849U, 2678278U, 4611469U,
  4829411U, 635956U, 8129971U, 5925040U, 4234153U, 6607829U, 2192938U, 6653329U,
  2387513U, 4768667U, 8111961U, 5199961U, 3747250U, 2296099U, 1239911U, 4541938U,
  3195676U, 2642980U, 1254190U, 8368000U, 2998219U, 141835U, 8291116U, 2513018U,
  7025525U, 613238U, 7070156U, 6161950U, 7921677U, 6458423U, 4040196U, 4908348U,
  2039144U, 6500539U, 7561656U, 6201452U, 6757063U, 2105286U, 6006015U, 6346610U,
  586241U, 7200804U, 527981U, 5637006U, 6903432U, 1994046U, 2491325U, 6987258U, 507927U,
  7192532U, 7655613U, 6545891U, 5346675U, 8041997U, 2647994U, 3009748U, 5767564U,
  4148469U, 749577U, 4357667U, 3980599U, 2569011U, 6764887U, 1723229U, 1665318U,
  2028038U, 1163598U, 5011144U, 3994671U, 8368538U, 7009900U, 3020393U, 3363542U,
  214880U, 545376U, 7609976U, 3105558U, 7277073U, 508145U, 7826699U, 860144U, 3430436U,
  140244U, 6866265U, 6195333U, 3123762U, 2358373U, 6187330U, 5365997U, 6663603U,
  2926054U, 7987710U, 8077412U, 3531229U, 4405932U, 4606686U, 1900052U, 7598542U,
  1054478U, 7648983U,
]

///|
fn dsa_ntt(w : Array[Int]) -> Unit {
  let mut m = 0
  let mut len = 128
  while len >= 1 {
    let mut start = 0
    while start < 256 {
      m = m + 1
      let z = dsa_zetas[m].reinterpret_as_int()
      for j in start..<(start + len) {
        let t = dq_mul(z, w[j + len])
        w[j + len] = dq_sub(w[j], t)
        w[j] = dq_add(w[j], t)
      }
      start = start + 2 * len
    }
    len = len / 2
  }
}

///|
fn dsa_ntt_inv(w : Array[Int]) -> Unit {
  let mut m = 256
  let mut len = 1
  while len < 256 {
    let mut start = 0
    while start < 256 {
      m = m - 1
      let z = dsa_q - dsa_zetas[m].reinterpret_as_int() // -zetas[m]
      for j in start..<(start + len) {
        let t = w[j]
        w[j] = dq_add(t, w[j + len])
        w[j + len] = dq_mul(z, dq_sub(t, w[j + len]))
      }
      start = start + 2 * len
    }
    len = len * 2
  }
  let f = 8347681 // 256^-1 mod q
  for j in 0..<256 {
    w[j] = dq_mul(f, w[j])
  }
}

///|
// pointwise product in NTT domain (FIPS 204 Algorithm 45)
fn dsa_mul_ntt(a : Array[Int], b : Array[Int]) -> Array[Int] {
  let out = Array::make(256, 0)
  for i in 0..<256 {
    out[i] = dq_mul(a[i], b[i])
  }
  out
}
// ---------- incremental SHAKE streams (package-private Keccak access) ----------

///|
priv struct DsaStream {
  state : Array[UInt64]
  rate_lanes : Int
  mut lane_idx : Int
  mut byte_idx : Int
}

///|
// Finalize a SHAKE hasher and wrap its state in an incremental reader.
fn dsa_stream_new_128(seed : Bytes) -> DsaStream {
  let h = shake_128_new()
  sha3_update(h, seed)
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  DsaStream::{
    state: h.state,
    rate_lanes: h.rate / 8,
    lane_idx: 0,
    byte_idx: 0,
  }
}

///|
fn dsa_stream_new_256(seed : Bytes) -> DsaStream {
  let h = shake_256_new()
  sha3_update(h, seed)
  for i in h.buf_len..<h.rate {
    h.buffer[i] = b'\x00'
  }
  h.buffer[h.buf_len] = (h.buffer[h.buf_len].to_int() ^ h.domain).to_byte()
  h.buffer[h.rate - 1] = (h.buffer[h.rate - 1].to_int() ^ 0x80).to_byte()
  sha3_absorb_block(h)
  DsaStream::{
    state: h.state,
    rate_lanes: h.rate / 8,
    lane_idx: 0,
    byte_idx: 0,
  }
}

///|
fn dsa_stream_next(x : DsaStream) -> Byte {
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

// ---------- sampling ----------

///|
// ExpandA: A[i][j] sampled from SHAKE128(rho || LE16(j + 256*i)); rejection
// on 23-bit values (FIPS 204 CoeffFromThreeBytes).
fn dsa_sample_uniform(rho : Bytes, nonce : Int) -> Array[Int] {
  let nbuf = Array::make(34, b'\x00')
  for i in 0..<32 {
    nbuf[i] = rho[i]
  }
  nbuf[32] = (nonce & 0xFF).to_byte()
  nbuf[33] = ((nonce >> 8) & 0xFF).to_byte()
  let st = dsa_stream_new_128(Bytes::from_array(nbuf[:]))
  let out = Array::make(256, 0)
  let mut ctr = 0
  while ctr < 256 {
    let b0 = dsa_stream_next(st).to_int()
    let b1 = dsa_stream_next(st).to_int()
    let b2 = dsa_stream_next(st).to_int()
    let t = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF
    if t < dsa_q {
      out[ctr] = t
      ctr = ctr + 1
    }
  }
  out
}

///|
// ExpandS: coefficients in [-eta, eta] from SHAKE256(rho' || LE16(nonce)),
// rejection on half-bytes (rej_eta).
fn dsa_sample_eta(
  params : DsaParams,
  rho_prime : Bytes,
  nonce : Int,
) -> Array[Int] {
  let nbuf = Array::make(66, b'\x00')
  for i in 0..<64 {
    nbuf[i] = rho_prime[i]
  }
  nbuf[64] = (nonce & 0xFF).to_byte()
  nbuf[65] = ((nonce >> 8) & 0xFF).to_byte()
  let st = dsa_stream_new_256(Bytes::from_array(nbuf[:]))
  let out = Array::make(256, 0)
  let mut ctr = 0
  while ctr < 256 {
    let b = dsa_stream_next(st).to_int()
    let t0 = b & 0x0F
    let t1 = b >> 4
    if params.eta == 2 {
      if t0 < 15 {
        out[ctr] = 2 - t0 % 5
        ctr = ctr + 1
      }
      if t1 < 15 && ctr < 256 {
        out[ctr] = 2 - t1 % 5
        ctr = ctr + 1
      }
    } else {
      if t0 < 9 {
        out[ctr] = 4 - t0
        ctr = ctr + 1
      }
      if t1 < 9 && ctr < 256 {
        out[ctr] = 4 - t1
        ctr = ctr + 1
      }
    }
  }
  out
}

///|
// ExpandMask: z coefficients from gamma1-packed SHAKE256 output.
// Normalized into [0, q): value gamma1 - v, +q if negative.
fn dsa_sample_gamma1(
  params : DsaParams,
  rho_prime : Bytes,
  kappa : Int,
) -> Array[Int] {
  let nbuf = Array::make(66, b'\x00')
  for i in 0..<64 {
    nbuf[i] = rho_prime[i]
  }
  nbuf[64] = (kappa & 0xFF).to_byte()
  nbuf[65] = ((kappa >> 8) & 0xFF).to_byte()
  let st = dsa_stream_new_256(Bytes::from_array(nbuf[:]))
  let out = Array::make(256, 0)
  if params.gamma1 == 1 << 17 {
    // 9 bytes per 4 coefficients (18-bit packed)
    for i in 0..<64 {
      let buf = Array::make(9, 0)
      for j in 0..<9 {
        buf[j] = dsa_stream_next(st).to_int()
      }
      let v0 = (buf[0] | (buf[1] << 8) | (buf[2] << 16)) & 0x3FFFF
      let v1 = ((buf[2] >> 2) | (buf[3] << 6) | (buf[4] << 14)) & 0x3FFFF
      let v2 = ((buf[4] >> 4) | (buf[5] << 4) | (buf[6] << 12)) & 0x3FFFF
      let v3 = ((buf[6] >> 6) | (buf[7] << 2) | (buf[8] << 10)) & 0x3FFFF
      out[4 * i] = dsa_mod_norm(params.gamma1 - v0)
      out[4 * i + 1] = dsa_mod_norm(params.gamma1 - v1)
      out[4 * i + 2] = dsa_mod_norm(params.gamma1 - v2)
      out[4 * i + 3] = dsa_mod_norm(params.gamma1 - v3)
    }
  } else {
    // 5 bytes per 2 coefficients (20-bit packed)
    for i in 0..<128 {
      let buf = Array::make(5, 0)
      for j in 0..<5 {
        buf[j] = dsa_stream_next(st).to_int()
      }
      let v0 = (buf[0] | (buf[1] << 8) | (buf[2] << 16)) & 0xFFFFF
      let v1 = ((buf[2] >> 4) | (buf[3] << 4) | (buf[4] << 12)) & 0xFFFFF
      out[2 * i] = dsa_mod_norm(params.gamma1 - v0)
      out[2 * i + 1] = dsa_mod_norm(params.gamma1 - v1)
    }
  }
  out
}

///|
fn dsa_mod_norm(a : Int) -> Int {
  if a < 0 {
    a + dsa_q
  } else {
    a
  }
}

///|
// SampleInBall (FIPS 204 Algorithm 29): c has tau nonzero coefficients
// in {-1, 1} at positions chosen by rejection.
fn dsa_sample_in_ball(params : DsaParams, c_tilde : Bytes) -> Array[Int] {
  let st = dsa_stream_new_256(c_tilde)
  let mut signs = 0UL
  for i in 0..<8 {
    signs = signs | (dsa_stream_next(st).to_uint64() << (8 * i))
  }
  let c = Array::make(256, 0)
  for i in (256 - params.tau)..<256 {
    let mut b = 0
    while ({
            b = dsa_stream_next(st).to_int()
            b > i
          }) {
      ()
    }
    c[i] = c[b]
    c[b] = if (signs & 1UL) == 1UL { dsa_q - 1 } else { 1 }
    signs = signs >> 1
  }
  c
}
// ---------- rounding (FIPS 204 Algorithms 35-40) ----------

///|
// Power2Round: a in [0,q) -> (a1, a0) with a = a1*2^13 + a0,
// -2^12 < a0 <= 2^12. Returns a1; a0 via centered output.
fn dsa_power2round(a : Int) -> (Int, Int) {
  let a1 = (a + (1 << 12) - 1) >> 13
  let a0 = a - (a1 << 13)
  (a1, a0)
}

///|
// Decompose: a in [0,q) -> (a1, a0) per FIPS 204 Algorithm 36.
fn dsa_decompose(params : DsaParams, a : Int) -> (Int, Int) {
  let mut a1 = (a + 127) >> 7
  if params.gamma2 == (dsa_q - 1) / 32 {
    a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15
  } else {
    a1 = (a1 * 11275 + (1 << 23)) >> 24
    if a1 > 43 {
      a1 = 0
    }
  }
  let mut a0 = a - a1 * 2 * params.gamma2
  if a0 > (dsa_q - 1) / 2 {
    a0 = a0 - dsa_q
  }
  (a1, a0)
}

///|
fn dsa_lowbits(params : DsaParams, a : Int) -> Int {
  let (_, a0) = dsa_decompose(params, a)
  a0
}

///|
fn dsa_make_hint(params : DsaParams, a0 : Int, a1 : Int) -> Int {
  if a0 > params.gamma2 ||
    a0 < -params.gamma2 ||
    (a0 == -params.gamma2 && a1 != 0) {
    1
  } else {
    0
  }
}

///|
fn dsa_use_hint(params : DsaParams, a : Int, hint : Int) -> Int {
  let (a1, a0) = dsa_decompose(params, a)
  if hint == 0 {
    return a1
  }
  let m = if params.gamma2 == (dsa_q - 1) / 32 { 16 } else { 44 }
  if a0 > 0 {
    (a1 + 1) % m
  } else {
    (a1 - 1 + m) % m
  }
}

// ---------- bit packing ----------

///|
// t1: 10 bits per coefficient (values in [0, 1024))
fn dsa_pack_t1_poly(r : Array[Byte], off : Int, a : Array[Int]) -> Unit {
  for i in 0..<64 {
    let c0 = a[4 * i]
    let c1 = a[4 * i + 1]
    let c2 = a[4 * i + 2]
    let c3 = a[4 * i + 3]
    r[off + 5 * i] = (c0 & 0xFF).to_byte()
    r[off + 5 * i + 1] = (((c0 >> 8) | (c1 << 2)) & 0xFF).to_byte()
    r[off + 5 * i + 2] = (((c1 >> 6) | (c2 << 4)) & 0xFF).to_byte()
    r[off + 5 * i + 3] = (((c2 >> 4) | (c3 << 6)) & 0xFF).to_byte()
    r[off + 5 * i + 4] = ((c3 >> 2) & 0xFF).to_byte()
  }
}

///|
fn dsa_unpack_t1_poly(a : Bytes, off : Int) -> Array[Int] {
  let r = Array::make(256, 0)
  for i in 0..<64 {
    let b0 = a[off + 5 * i].to_int()
    let b1 = a[off + 5 * i + 1].to_int()
    let b2 = a[off + 5 * i + 2].to_int()
    let b3 = a[off + 5 * i + 3].to_int()
    let b4 = a[off + 5 * i + 4].to_int()
    r[4 * i] = (b0 | (b1 << 8)) & 0x3FF
    r[4 * i + 1] = ((b1 >> 2) | (b2 << 6)) & 0x3FF
    r[4 * i + 2] = ((b2 >> 4) | (b3 << 4)) & 0x3FF
    r[4 * i + 3] = ((b3 >> 6) | (b4 << 2)) & 0x3FF
  }
  r
}

///|
// t0: centered a0 in (-2^12, 2^12], stored as 2^12 - a0 (13 bits)
fn dsa_pack_t0_poly(r : Array[Byte], off : Int, a : Array[Int]) -> Unit {
  for i in 0..<32 {
    let t = Array::make(8, 0)
    for j in 0..<8 {
      t[j] = (1 << 12) - a[8 * i + j]
    }
    let o = off + 13 * i
    r[o] = (t[0] & 0xFF).to_byte()
    r[o + 1] = (((t[0] >> 8) | (t[1] << 5)) & 0xFF).to_byte()
    r[o + 2] = ((t[1] >> 3) & 0xFF).to_byte()
    r[o + 3] = (((t[1] >> 11) | (t[2] << 2)) & 0xFF).to_byte()
    r[o + 4] = (((t[2] >> 6) | (t[3] << 7)) & 0xFF).to_byte()
    r[o + 5] = ((t[3] >> 1) & 0xFF).to_byte()
    r[o + 6] = (((t[3] >> 9) | (t[4] << 4)) & 0xFF).to_byte()
    r[o + 7] = ((t[4] >> 4) & 0xFF).to_byte()
    r[o + 8] = (((t[4] >> 12) | (t[5] << 1)) & 0xFF).to_byte()
    r[o + 9] = (((t[5] >> 7) | (t[6] << 6)) & 0xFF).to_byte()
    r[o + 10] = ((t[6] >> 2) & 0xFF).to_byte()
    r[o + 11] = (((t[6] >> 10) | (t[7] << 3)) & 0xFF).to_byte()
    r[o + 12] = ((t[7] >> 5) & 0xFF).to_byte()
  }
}

///|
fn dsa_unpack_t0_poly(a : Bytes, off : Int) -> Array[Int] {
  let r = Array::make(256, 0)
  for i in 0..<32 {
    let o = off + 13 * i
    let b = Array::make(13, 0)
    for j in 0..<13 {
      b[j] = a[o + j].to_int()
    }
    r[8 * i] = (1 << 12) - ((b[0] | (b[1] << 8)) & 0x1FFF)
    r[8 * i + 1] = (1 << 12) -
      (((b[1] >> 5) | (b[2] << 3) | (b[3] << 11)) & 0x1FFF)
    r[8 * i + 2] = (1 << 12) - (((b[3] >> 2) | (b[4] << 6)) & 0x1FFF)
    r[8 * i + 3] = (1 << 12) -
      (((b[4] >> 7) | (b[5] << 1) | (b[6] << 9)) & 0x1FFF)
    r[8 * i + 4] = (1 << 12) -
      (((b[6] >> 4) | (b[7] << 4) | (b[8] << 12)) & 0x1FFF)
    r[8 * i + 5] = (1 << 12) - (((b[8] >> 1) | (b[9] << 7)) & 0x1FFF)
    r[8 * i + 6] = (1 << 12) -
      (((b[9] >> 6) | (b[10] << 2) | (b[11] << 10)) & 0x1FFF)
    r[8 * i + 7] = (1 << 12) - (((b[11] >> 3) | (b[12] << 5)) & 0x1FFF)
  }
  r
}

///|
// eta packing: coefficients as eta - c (bitlen(2*eta) bits)
fn dsa_pack_eta_poly(
  r : Array[Byte],
  off : Int,
  a : Array[Int],
  eta : Int,
) -> Unit {
  if eta == 2 {
    for i in 0..<32 {
      let t = Array::make(8, 0)
      for j in 0..<8 {
        t[j] = eta - a[8 * i + j]
      }
      let o = off + 3 * i
      r[o] = ((t[0] | (t[1] << 3) | (t[2] << 6)) & 0xFF).to_byte()
      r[o + 1] = (((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF).to_byte()
      r[o + 2] = (((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF).to_byte()
    }
  } else {
    for i in 0..<128 {
      let t0 = eta - a[2 * i]
      let t1 = eta - a[2 * i + 1]
      r[off + i] = ((t0 | (t1 << 4)) & 0xFF).to_byte()
    }
  }
}

///|
fn dsa_unpack_eta_poly(a : Bytes, off : Int, eta : Int) -> Array[Int] {
  let r = Array::make(256, 0)
  if eta == 2 {
    for i in 0..<32 {
      let o = off + 3 * i
      let b0 = a[o].to_int()
      let b1 = a[o + 1].to_int()
      let b2 = a[o + 2].to_int()
      r[8 * i] = eta - (b0 & 7)
      r[8 * i + 1] = eta - ((b0 >> 3) & 7)
      r[8 * i + 2] = eta - (((b0 >> 6) | (b1 << 2)) & 7)
      r[8 * i + 3] = eta - ((b1 >> 1) & 7)
      r[8 * i + 4] = eta - ((b1 >> 4) & 7)
      r[8 * i + 5] = eta - (((b1 >> 7) | (b2 << 1)) & 7)
      r[8 * i + 6] = eta - ((b2 >> 2) & 7)
      r[8 * i + 7] = eta - ((b2 >> 5) & 7)
    }
  } else {
    for i in 0..<128 {
      let b = a[off + i].to_int()
      r[2 * i] = eta - (b & 0x0F)
      r[2 * i + 1] = eta - (b >> 4)
    }
  }
  r
}

///|
// z packing: gamma1 - c (18 or 20 bits)
fn dsa_pack_z_poly(
  r : Array[Byte],
  off : Int,
  a : Array[Int],
  gamma1 : Int,
) -> Unit {
  if gamma1 == 1 << 17 {
    for i in 0..<64 {
      let t = Array::make(4, 0)
      for j in 0..<4 {
        t[j] = gamma1 - dq_centered(a[4 * i + j])
      }
      let o = off + 9 * i
      r[o] = (t[0] & 0xFF).to_byte()
      r[o + 1] = ((t[0] >> 8) & 0xFF).to_byte()
      r[o + 2] = (((t[0] >> 16) | (t[1] << 2)) & 0xFF).to_byte()
      r[o + 3] = ((t[1] >> 6) & 0xFF).to_byte()
      r[o + 4] = (((t[1] >> 14) | (t[2] << 4)) & 0xFF).to_byte()
      r[o + 5] = ((t[2] >> 4) & 0xFF).to_byte()
      r[o + 6] = (((t[2] >> 12) | (t[3] << 6)) & 0xFF).to_byte()
      r[o + 7] = ((t[3] >> 2) & 0xFF).to_byte()
      r[o + 8] = ((t[3] >> 10) & 0xFF).to_byte()
    }
  } else {
    for i in 0..<128 {
      let t0 = gamma1 - dq_centered(a[2 * i])
      let t1 = gamma1 - dq_centered(a[2 * i + 1])
      let o = off + 5 * i
      r[o] = (t0 & 0xFF).to_byte()
      r[o + 1] = ((t0 >> 8) & 0xFF).to_byte()
      r[o + 2] = (((t0 >> 16) | (t1 << 4)) & 0xFF).to_byte()
      r[o + 3] = ((t1 >> 4) & 0xFF).to_byte()
      r[o + 4] = ((t1 >> 12) & 0xFF).to_byte()
    }
  }
}

///|
fn dsa_unpack_z_poly(a : Bytes, off : Int, gamma1 : Int) -> Array[Int] {
  let r = Array::make(256, 0)
  if gamma1 == 1 << 17 {
    for i in 0..<64 {
      let o = off + 9 * i
      let b = Array::make(9, 0)
      for j in 0..<9 {
        b[j] = a[o + j].to_int()
      }
      r[4 * i] = dsa_mod_norm(
        gamma1 - ((b[0] | (b[1] << 8) | (b[2] << 16)) & 0x3FFFF),
      )
      r[4 * i + 1] = dsa_mod_norm(
        gamma1 - (((b[2] >> 2) | (b[3] << 6) | (b[4] << 14)) & 0x3FFFF),
      )
      r[4 * i + 2] = dsa_mod_norm(
        gamma1 - (((b[4] >> 4) | (b[5] << 4) | (b[6] << 12)) & 0x3FFFF),
      )
      r[4 * i + 3] = dsa_mod_norm(
        gamma1 - (((b[6] >> 6) | (b[7] << 2) | (b[8] << 10)) & 0x3FFFF),
      )
    }
  } else {
    for i in 0..<128 {
      let o = off + 5 * i
      let b = Array::make(5, 0)
      for j in 0..<5 {
        b[j] = a[o + j].to_int()
      }
      r[2 * i] = dsa_mod_norm(
        gamma1 - ((b[0] | (b[1] << 8) | (b[2] << 16)) & 0xFFFFF),
      )
      r[2 * i + 1] = dsa_mod_norm(
        gamma1 - (((b[2] >> 4) | (b[3] << 4) | (b[4] << 12)) & 0xFFFFF),
      )
    }
  }
  r
}

///|
// w1 packing: 6 bits (gamma2 = (q-1)/88) or 4 bits (gamma2 = (q-1)/32)
fn dsa_pack_w1_poly(
  r : Array[Byte],
  off : Int,
  a : Array[Int],
  gamma2 : Int,
) -> Unit {
  if gamma2 == (dsa_q - 1) / 88 {
    for i in 0..<64 {
      let c0 = a[4 * i]
      let c1 = a[4 * i + 1]
      let c2 = a[4 * i + 2]
      let c3 = a[4 * i + 3]
      let o = off + 3 * i
      r[o] = ((c0 | (c1 << 6)) & 0xFF).to_byte()
      r[o + 1] = (((c1 >> 2) | (c2 << 4)) & 0xFF).to_byte()
      r[o + 2] = (((c2 >> 4) | (c3 << 2)) & 0xFF).to_byte()
    }
  } else {
    for i in 0..<128 {
      r[off + i] = ((a[2 * i] | (a[2 * i + 1] << 4)) & 0xFF).to_byte()
    }
  }
}
// ---------- matrix/vector NTT-domain helpers ----------

///|
fn dsa_vec_ntt_inv(v : Array[Array[Int]]) -> Unit {
  for i in 0..<v.length() {
    dsa_ntt_inv(v[i])
  }
}

///|
fn dsa_mat_vec_mul(
  mat : Array[Array[Int]],
  v : Array[Array[Int]],
  k : Int,
  l : Int,
) -> Array[Array[Int]] {
  let out = Array::make(k, Array::make(256, 0))
  for i in 0..<k {
    let acc = Array::make(256, 0)
    for j in 0..<l {
      let prod = dsa_mul_ntt(mat[i * l + j], v[j])
      for c in 0..<256 {
        acc[c] = dq_add(acc[c], prod[c])
      }
    }
    out[i] = acc
  }
  out
}

// ---------- key / signature encode & decode ----------

///|
fn dsa_keygen_internal(params : DsaParams, seed : Bytes) -> (Bytes, Bytes) {
  if seed.length() != 32 {
    abort("ml_dsa keygen: seed must be 32 bytes")
  }
  let h = shake_256(
    concat_all([
      seed,
      Bytes::make(1, params.k.to_byte()),
      Bytes::make(1, params.l.to_byte()),
    ]),
    128,
  )
  let rho = Array::make(32, b'\x00')
  let rho_prime = Array::make(64, b'\x00')
  let key = Array::make(32, b'\x00')
  for i in 0..<32 {
    rho[i] = h[i]
    key[i] = h[96 + i]
  }
  for i in 0..<64 {
    rho_prime[i] = h[32 + i]
  }
  let rho_b = Bytes::from_array(rho[:])
  let rho_prime_b = Bytes::from_array(rho_prime[:])
  // A matrix (k x l) in NTT domain
  let mat = Array::make(params.k * params.l, Array::make(256, 0))
  for i in 0..<params.k {
    for j in 0..<params.l {
      mat[i * params.l + j] = dsa_sample_uniform(rho_b, j + 256 * i)
    }
  }
  // s1 (l polys), s2 (k polys)
  let s1 = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    s1[i] = dsa_sample_eta(params, rho_prime_b, i)
  }
  let s2 = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    s2[i] = dsa_sample_eta(params, rho_prime_b, params.l + i)
  }
  // t = INTT(A o NTT(s1)) + s2
  let s1_hat = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    let p = Array::make(256, 0)
    for c in 0..<256 {
      p[c] = dsa_mod_norm(s1[i][c])
    }
    dsa_ntt(p)
    s1_hat[i] = p
  }
  let t = dsa_mat_vec_mul(mat, s1_hat, params.k, params.l)
  dsa_vec_ntt_inv(t)
  for i in 0..<params.k {
    for c in 0..<256 {
      t[i][c] = dq_add(t[i][c], dsa_mod_norm(s2[i][c]))
    }
  }
  // power2round
  let t1 = Array::make(params.k, Array::make(256, 0))
  let t0 = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    let r1 = Array::make(256, 0)
    let r0 = Array::make(256, 0)
    for c in 0..<256 {
      let (a1, a0) = dsa_power2round(t[i][c])
      r1[c] = a1
      r0[c] = a0
    }
    t1[i] = r1
    t0[i] = r0
  }
  // pk = rho || t1
  let pk_len = 32 + 320 * params.k
  let pk = Array::make(pk_len, b'\x00')
  for i in 0..<32 {
    pk[i] = rho[i]
  }
  for i in 0..<params.k {
    dsa_pack_t1_poly(pk, 32 + 320 * i, t1[i])
  }
  let pk_b = Bytes::from_array(pk[:])
  let tr = shake_256(pk_b, 64)
  // sk = rho || key || tr || s1 || s2 || t0
  let eta_bytes = if params.eta == 2 { 96 } else { 128 }
  let sk_len = 128 + eta_bytes * (params.l + params.k) + 416 * params.k
  let sk = Array::make(sk_len, b'\x00')
  for i in 0..<32 {
    sk[i] = rho[i]
    sk[32 + i] = key[i]
  }
  for i in 0..<64 {
    sk[64 + i] = tr[i]
  }
  let mut off = 128
  for i in 0..<params.l {
    dsa_pack_eta_poly(sk, off, s1[i], params.eta)
    off = off + eta_bytes
  }
  for i in 0..<params.k {
    dsa_pack_eta_poly(sk, off, s2[i], params.eta)
    off = off + eta_bytes
  }
  for i in 0..<params.k {
    dsa_pack_t0_poly(sk, off, t0[i])
    off = off + 416
  }
  (pk_b, Bytes::from_array(sk[:]))
}

///|
fn dsa_unpack_sk(
  params : DsaParams,
  sk : Bytes,
) -> (
  Bytes,
  Bytes,
  Bytes,
  Array[Array[Int]],
  Array[Array[Int]],
  Array[Array[Int]],
) {
  let rho = Array::make(32, b'\x00')
  let key = Array::make(32, b'\x00')
  let tr = Array::make(64, b'\x00')
  for i in 0..<32 {
    rho[i] = sk[i]
    key[i] = sk[32 + i]
  }
  for i in 0..<64 {
    tr[i] = sk[64 + i]
  }
  let eta_bytes = if params.eta == 2 { 96 } else { 128 }
  let mut off = 128
  let s1 = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    s1[i] = dsa_unpack_eta_poly(sk, off, params.eta)
    off = off + eta_bytes
  }
  let s2 = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    s2[i] = dsa_unpack_eta_poly(sk, off, params.eta)
    off = off + eta_bytes
  }
  let t0 = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    t0[i] = dsa_unpack_t0_poly(sk, off)
    off = off + 416
  }
  (
    Bytes::from_array(rho[:]),
    Bytes::from_array(key[:]),
    Bytes::from_array(tr[:]),
    s1,
    s2,
    t0,
  )
}

///|
fn dsa_pack_w1_vec(params : DsaParams, w1 : Array[Array[Int]]) -> Bytes {
  let per = if params.gamma2 == (dsa_q - 1) / 88 { 192 } else { 128 }
  let out = Array::make(per * params.k, b'\x00')
  for i in 0..<params.k {
    dsa_pack_w1_poly(out, per * i, w1[i], params.gamma2)
  }
  Bytes::from_array(out[:])
}

///|
fn dsa_pack_hint(params : DsaParams, h : Array[Array[Int]]) -> Bytes {
  let out = Array::make(params.omega + params.k, b'\x00')
  let mut idx = 0
  for i in 0..<params.k {
    for j in 0..<256 {
      if h[i][j] != 0 {
        out[idx] = j.to_byte()
        idx = idx + 1
      }
    }
    out[params.omega + i] = idx.to_byte()
  }
  Bytes::from_array(out[:])
}

///|
// Returns None on malformed hint encoding.
fn dsa_unpack_hint(params : DsaParams, buf : Bytes) -> Array[Array[Int]]? {
  let h = Array::make(params.k, Array::make(256, 0))
  let mut k_idx = 0
  for i in 0..<params.k {
    let endi = buf[params.omega + i].to_int()
    if endi < k_idx || endi > params.omega {
      return None
    }
    let hr = Array::make(256, 0)
    for j in k_idx..<endi {
      if j > k_idx && buf[j].to_int() <= buf[j - 1].to_int() {
        return None
      }
      hr[buf[j].to_int()] = 1
    }
    h[i] = hr
    k_idx = endi
  }
  for j in k_idx..<params.omega {
    if buf[j].to_int() != 0 {
      return None
    }
  }
  Some(h)
}

///|
fn dsa_format_msg(msg : Bytes, ctx : Bytes) -> Bytes {
  concat_all([
    Bytes::make(1, b'\x00'),
    Bytes::make(1, ctx.length().to_byte()),
    ctx,
    msg,
  ])
}

///|
fn dsa_sign_internal(
  params : DsaParams,
  sk : Bytes,
  msg : Bytes,
  ctx : Bytes,
  rnd : Bytes,
) -> Bytes {
  if ctx.length() > 255 {
    abort("ml_dsa sign: context too long")
  }
  let (rho, key, tr, s1, s2, t0) = dsa_unpack_sk(params, sk)
  // NTT of secret vectors
  let s1_hat = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    let p = Array::make(256, 0)
    for c in 0..<256 {
      p[c] = dsa_mod_norm(s1[i][c])
    }
    dsa_ntt(p)
    s1_hat[i] = p
  }
  let s2_hat = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    let p = Array::make(256, 0)
    for c in 0..<256 {
      p[c] = dsa_mod_norm(s2[i][c])
    }
    dsa_ntt(p)
    s2_hat[i] = p
  }
  let t0_hat = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    let p = Array::make(256, 0)
    for c in 0..<256 {
      p[c] = dsa_mod_norm(t0[i][c])
    }
    dsa_ntt(p)
    t0_hat[i] = p
  }
  let mat = Array::make(params.k * params.l, Array::make(256, 0))
  for i in 0..<params.k {
    for j in 0..<params.l {
      mat[i * params.l + j] = dsa_sample_uniform(rho, j + 256 * i)
    }
  }
  let mu = shake_256(concat_bytes(tr, dsa_format_msg(msg, ctx)), 64)
  let rho_pp = shake_256(concat_all([key, rnd, mu]), 64)
  let mut kappa = 0
  let mut attempts = 0
  while true {
    attempts = attempts + 1
    if attempts > 1000 {
      abort("ml_dsa sign: too many rejections")
    }
    // y
    let y = Array::make(params.l, Array::make(256, 0))
    for i in 0..<params.l {
      y[i] = dsa_sample_gamma1(params, rho_pp, kappa + i)
    }
    // w = INTT(A o NTT(y))
    let y_hat = Array::make(params.l, Array::make(256, 0))
    for i in 0..<params.l {
      let p = Array::make(256, 0)
      for c in 0..<256 {
        p[c] = y[i][c]
      }
      dsa_ntt(p)
      y_hat[i] = p
    }
    let w = dsa_mat_vec_mul(mat, y_hat, params.k, params.l)
    dsa_vec_ntt_inv(w)
    // decompose
    let w1 = Array::make(params.k, Array::make(256, 0))
    let w0 = Array::make(params.k, Array::make(256, 0))
    for i in 0..<params.k {
      let wr = Array::make(256, 0)
      let wr0 = Array::make(256, 0)
      for c in 0..<256 {
        let (hi, lo) = dsa_decompose(params, w[i][c])
        wr[c] = hi
        wr0[c] = lo
      }
      w1[i] = wr
      w0[i] = wr0
    }
    let c_tilde = shake_256(
      concat_bytes(mu, dsa_pack_w1_vec(params, w1)),
      params.ctilde,
    )
    let cp = dsa_sample_in_ball(params, c_tilde)
    let cp_hat = Array::make(256, 0)
    for c in 0..<256 {
      cp_hat[c] = cp[c]
    }
    dsa_ntt(cp_hat)
    // z = y + INTT(cp o s1)
    let mut z_ok = true
    let z_vec = Array::make(params.l, Array::make(256, 0))
    for i in 0..<params.l {
      let prod = dsa_mul_ntt(cp_hat, s1_hat[i])
      dsa_ntt_inv(prod)
      let z = Array::make(256, 0)
      for c in 0..<256 {
        z[c] = dq_add(y[i][c], prod[c])
        let cen = dq_centered(z[c])
        if cen >= params.gamma1 - params.beta ||
          cen <= -(params.gamma1 - params.beta) {
          z_ok = false
        }
      }
      z_vec[i] = z
    }
    if z_ok {
      // r0 = LowBits(w - INTT(cp o s2))
      let mut r0_ok = true
      let r0_vec = Array::make(params.k, Array::make(256, 0))
      for i in 0..<params.k {
        let prod = dsa_mul_ntt(cp_hat, s2_hat[i])
        dsa_ntt_inv(prod)
        let r0 = Array::make(256, 0)
        for c in 0..<256 {
          let r = dq_sub(w[i][c], prod[c])
          r0[c] = dsa_lowbits(params, r)
          if r0[c] >= params.gamma2 - params.beta ||
            r0[c] <= -(params.gamma2 - params.beta) {
            r0_ok = false
          }
        }
        r0_vec[i] = r0
      }
      if r0_ok {
        // ct0 = INTT(cp o t0)
        let mut ct0_ok = true
        let ct0_vec = Array::make(params.k, Array::make(256, 0))
        for i in 0..<params.k {
          let prod = dsa_mul_ntt(cp_hat, t0_hat[i])
          dsa_ntt_inv(prod)
          for c in 0..<256 {
            prod[c] = dq_centered(prod[c])
            if prod[c] >= params.gamma2 || prod[c] <= -params.gamma2 {
              ct0_ok = false
            }
          }
          ct0_vec[i] = prod
        }
        if ct0_ok {
          // hints
          let h_vec = Array::make(params.k, Array::make(256, 0))
          let mut weight = 0
          for i in 0..<params.k {
            let hr = Array::make(256, 0)
            for c in 0..<256 {
              let hint = dsa_make_hint(
                params,
                r0_vec[i][c] + ct0_vec[i][c],
                w1[i][c],
              )
              hr[c] = hint
              weight = weight + hint
            }
            h_vec[i] = hr
          }
          if weight <= params.omega {
            // encode signature
            let z_bytes = if params.gamma1 == 1 << 17 {
              576 * params.l
            } else {
              640 * params.l
            }
            let sig = Array::make(
              params.ctilde + z_bytes + params.omega + params.k,
              b'\x00',
            )
            for i in 0..<params.ctilde {
              sig[i] = c_tilde[i]
            }
            let per_z = if params.gamma1 == 1 << 17 { 576 } else { 640 }
            for i in 0..<params.l {
              dsa_pack_z_poly(
                sig,
                params.ctilde + per_z * i,
                z_vec[i],
                params.gamma1,
              )
            }
            let hint_b = dsa_pack_hint(params, h_vec)
            let hoff = params.ctilde + z_bytes
            for i in 0..<(params.omega + params.k) {
              sig[hoff + i] = hint_b[i]
            }
            return Bytes::from_array(sig[:])
          }
        }
      }
    }
    kappa = kappa + params.l
  }
  Bytes::make(0, b'\x00') // unreachable
}

///|
fn dsa_verify_internal(
  params : DsaParams,
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if ctx.length() > 255 {
    return false
  }
  let z_bytes = if params.gamma1 == 1 << 17 {
    576 * params.l
  } else {
    640 * params.l
  }
  if sig.length() != params.ctilde + z_bytes + params.omega + params.k {
    return false
  }
  // unpack pk
  let rho = Array::make(32, b'\x00')
  for i in 0..<32 {
    rho[i] = pk[i]
  }
  let t1 = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    t1[i] = dsa_unpack_t1_poly(pk, 32 + 320 * i)
  }
  // unpack sig
  let c_tilde = Array::make(params.ctilde, b'\x00')
  for i in 0..<params.ctilde {
    c_tilde[i] = sig[i]
  }
  let per_z = if params.gamma1 == 1 << 17 { 576 } else { 640 }
  let z = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    z[i] = dsa_unpack_z_poly(sig, params.ctilde + per_z * i, params.gamma1)
  }
  let h = match
    dsa_unpack_hint(
      params,
      e4_slice_sig(sig, params.ctilde + z_bytes, params.omega + params.k),
    ) {
    Some(hv) => hv
    None => return false
  }
  // z norm check
  for i in 0..<params.l {
    for c in 0..<256 {
      let cen = dq_centered(z[i][c])
      if cen >= params.gamma1 - params.beta ||
        cen <= -(params.gamma1 - params.beta) {
        return false
      }
    }
  }
  let mu = shake_256(
    concat_bytes(shake_256(pk, 64), dsa_format_msg(msg, ctx)),
    64,
  )
  let cp = dsa_sample_in_ball(params, Bytes::from_array(c_tilde[:]))
  let mat = Array::make(params.k * params.l, Array::make(256, 0))
  for i in 0..<params.k {
    for j in 0..<params.l {
      mat[i * params.l + j] = dsa_sample_uniform(
        Bytes::from_array(rho[:]),
        j + 256 * i,
      )
    }
  }
  let z_hat = Array::make(params.l, Array::make(256, 0))
  for i in 0..<params.l {
    let p = Array::make(256, 0)
    for c in 0..<256 {
      p[c] = z[i][c]
    }
    dsa_ntt(p)
    z_hat[i] = p
  }
  let w1p = dsa_mat_vec_mul(mat, z_hat, params.k, params.l)
  let cp_hat = Array::make(256, 0)
  for c in 0..<256 {
    cp_hat[c] = cp[c]
  }
  dsa_ntt(cp_hat)
  // t1 * 2^d, NTT, multiply by cp, subtract
  for i in 0..<params.k {
    let t1s = Array::make(256, 0)
    for c in 0..<256 {
      t1s[c] = (t1[i][c] << 13) % dsa_q
    }
    dsa_ntt(t1s)
    let prod = dsa_mul_ntt(cp_hat, t1s)
    for c in 0..<256 {
      w1p[i][c] = dq_sub(w1p[i][c], prod[c])
    }
  }
  dsa_vec_ntt_inv(w1p)
  // use hint, repack w1
  let w1_rec = Array::make(params.k, Array::make(256, 0))
  for i in 0..<params.k {
    let wr = Array::make(256, 0)
    for c in 0..<256 {
      wr[c] = dsa_use_hint(params, w1p[i][c], h[i][c])
    }
    w1_rec[i] = wr
  }
  let c2 = shake_256(
    concat_bytes(mu, dsa_pack_w1_vec(params, w1_rec)),
    params.ctilde,
  )
  bytes_equal(c2, Bytes::from_array(c_tilde[:]))
}

///|
fn e4_slice_sig(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}

// ---------- public API ----------

///|
/// ML-DSA-44 key generation (FIPS 204): deterministic from a 32-byte seed.
/// Returns (pk, sk).
pub fn ml_dsa_44_keygen(seed : Bytes) -> (Bytes, Bytes) {
  dsa_keygen_internal(dsa_44, seed)
}

///|
/// ML-DSA-44 signing of the pure message `msg` (optional context `ctx`).
/// `rnd` is the per-message randomness: 32 zero bytes for the deterministic
/// variant, fresh CSPRNG output for the hedged variant.
pub fn ml_dsa_44_sign(
  sk : Bytes,
  msg : Bytes,
  rnd : Bytes,
  ctx : Bytes,
) -> Bytes {
  dsa_sign_internal(dsa_44, sk, msg, ctx, rnd)
}

///|
/// ML-DSA-44 signature verification (pure message variant).
pub fn ml_dsa_44_verify(
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  dsa_verify_internal(dsa_44, pk, msg, sig, ctx)
}

///|
/// ML-DSA-65 key generation. See `ml_dsa_44_keygen`.
pub fn ml_dsa_65_keygen(seed : Bytes) -> (Bytes, Bytes) {
  dsa_keygen_internal(dsa_65, seed)
}

///|
/// ML-DSA-65 signing. See `ml_dsa_44_sign`.
pub fn ml_dsa_65_sign(
  sk : Bytes,
  msg : Bytes,
  rnd : Bytes,
  ctx : Bytes,
) -> Bytes {
  dsa_sign_internal(dsa_65, sk, msg, ctx, rnd)
}

///|
/// ML-DSA-65 verification. See `ml_dsa_44_verify`.
pub fn ml_dsa_65_verify(
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  dsa_verify_internal(dsa_65, pk, msg, sig, ctx)
}

///|
/// ML-DSA-87 key generation. See `ml_dsa_44_keygen`.
pub fn ml_dsa_87_keygen(seed : Bytes) -> (Bytes, Bytes) {
  dsa_keygen_internal(dsa_87, seed)
}

///|
/// ML-DSA-87 signing. See `ml_dsa_44_sign`.
pub fn ml_dsa_87_sign(
  sk : Bytes,
  msg : Bytes,
  rnd : Bytes,
  ctx : Bytes,
) -> Bytes {
  dsa_sign_internal(dsa_87, sk, msg, ctx, rnd)
}

///|
/// ML-DSA-87 verification. See `ml_dsa_44_verify`.
pub fn ml_dsa_87_verify(
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  dsa_verify_internal(dsa_87, pk, msg, sig, ctx)
}
