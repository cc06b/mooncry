/// Native P-256 (secp256r1) field and curve arithmetic — eight 32-bit
/// limbs (UInt) with UInt64/Int64 intermediates and the NIST Solinas
/// fast reduction. Replaces the generic BigInt path for P-256 scalar
/// multiplications (ECDSA sign/verify, public-key derivation, HPKE
/// P-256 DH) — measured ~3x on wasm-gc (v0.51.0).
///
/// The reduction constants are DERIVED, never hand-copied:
/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1  =>  2^256 = 2^224 - 2^192 -
/// 2^96 + 1 (mod p), so each high word r[i] (i >= 8) folds onto words
/// {i-8:+1, i-1:+1, i-2:-1, i-5:-1}, applied to a fixpoint. The table
/// was cross-validated in Python against modular arithmetic on random
/// x < p^2 (max |coef| = 3, max column sum 8 -> Int64 headroom).
///
/// The curve formulas mirror the vector-verified generic Jacobian code
/// in ecdsa.mbt (a = -3 doubling, general addition with the u1==u2
/// degeneracies) limb-for-limb.

///|
let p256_mask32 : UInt64 = 0xFFFFFFFFUL

///|
/// The prime as eight little-endian 32-bit words, derived from the
/// existing p256_curve constant (single source of truth).
let p256_prime_words : Array[UInt] = {
  let be = p256_curve.p.to_octets(length=32)
  let w = Array::make(8, 0U)
  for i in 0..<8 {
    w[i] = ((be[28 - 4 * i].to_int() << 24) |
    (be[29 - 4 * i].to_int() << 16) |
    (be[30 - 4 * i].to_int() << 8) |
    be[31 - 4 * i].to_int()).reinterpret_as_uint()
  }
  w
}

///|
/// Solinas fold coefficients: p256_foldc[(i-8)*8 + k] for high word i.
let p256_foldc : Array[Int] = {
  let t = Array::make(64, 0)
  for i in 8..<16 {
    let w = Array::make(16, 0)
    w[i - 8] = w[i - 8] + 1
    w[i - 1] = w[i - 1] + 1
    w[i - 2] = w[i - 2] - 1
    w[i - 5] = w[i - 5] - 1
    let mut progress = true
    while progress {
      progress = false
      for k in 8..<16 {
        if w[k] != 0 {
          let cf = w[k]
          w[k] = 0
          w[k - 8] = w[k - 8] + cf
          w[k - 1] = w[k - 1] + cf
          w[k - 2] = w[k - 2] - cf
          w[k - 5] = w[k - 5] - cf
          progress = true
        }
      }
    }
    for k in 0..<8 {
      t[(i - 8) * 8 + k] = w[k]
    }
  }
  t
}

///|
/// Bits of p-2 (MSB-first) for the native Fermat inversion.
let p256_pm2_bits : Array[Bool] = {
  let e = p256_curve.p - @bigint.BigInt::from_int(2)
  let str = e.to_string(radix=2)
  let t = Array::make(str.length(), false)
  for i in 0..<str.length() {
    t[i] = str[i] == '1'
  }
  t
}

// ==================== field ====================

///|
/// Int64 -> UInt32 for values known to be in [0, 2^32): Int64.to_int()
/// SATURATES above 2^31 on wasm-gc, so split into halves (each < 2^16
/// post-shift) and reassemble with wrapping Int arithmetic.
fn f256_i64_to_u32(v : Int64) -> UInt {
  let hi = (v >> 16).to_int()
  let lo = (v & 0xFFFFL).to_int()
  ((hi << 16) | lo).reinterpret_as_uint()
}

///|
fn f256_zero() -> Array[UInt] {
  Array::make(8, 0U)
}

///|
fn f256_one() -> Array[UInt] {
  let f = Array::make(8, 0U)
  f[0] = 1U
  f
}

///|
fn f256_is_zero(a : Array[UInt]) -> Bool {
  for i in 0..<8 {
    if a[i] != 0U {
      return false
    }
  }
  true
}

///|
fn f256_equal(a : Array[UInt], b : Array[UInt]) -> Bool {
  for i in 0..<8 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// Big-endian 32 bytes -> limbs.
fn f256_from_bytes(be : Bytes) -> Array[UInt] {
  let w = Array::make(8, 0U)
  for i in 0..<8 {
    w[i] = ((be[28 - 4 * i].to_int() << 24) |
    (be[29 - 4 * i].to_int() << 16) |
    (be[30 - 4 * i].to_int() << 8) |
    be[31 - 4 * i].to_int()).reinterpret_as_uint()
  }
  w
}

///|
/// Limbs -> big-endian 32 bytes.
fn f256_to_bytes(a : Array[UInt]) -> Bytes {
  let out = Array::make(32, b'\x00')
  for i in 0..<8 {
    let v = a[i]
    out[28 - 4 * i] = ((v >> 24) & 0xFFU).to_byte()
    out[29 - 4 * i] = ((v >> 16) & 0xFFU).to_byte()
    out[30 - 4 * i] = ((v >> 8) & 0xFFU).to_byte()
    out[31 - 4 * i] = (v & 0xFFU).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn f256_from_big(x : @bigint.BigInt) -> Array[UInt] {
  let p = p256_curve.p
  let m = (x % p + p) % p
  f256_from_bytes(m.to_octets(length=32))
}

///|
fn f256_to_big(a : Array[UInt]) -> @bigint.BigInt {
  @bigint.BigInt::from_octets(f256_to_bytes(a))
}

///|
/// Compare limbs as 256-bit integers: -1 / 0 / 1.
fn f256_cmp(a : Array[UInt], b : Array[UInt]) -> Int {
  for i = 7; i >= 0; i = i - 1 {
    if a[i] < b[i] {
      return -1
    }
    if a[i] > b[i] {
      return 1
    }
  }
  0
}

///|
/// a -= b assuming a >= b (no borrow out).
fn f256_sub_raw(a : Array[UInt], b : Array[UInt]) -> Array[UInt] {
  let r = Array::make(8, 0U)
  let mut borrow = 0L
  for i in 0..<8 {
    let d = a[i].to_int64() - b[i].to_int64() - borrow
    if d < 0L {
      r[i] = f256_i64_to_u32(d + 4294967296L)
      borrow = 1L
    } else {
      r[i] = f256_i64_to_u32(d)
      borrow = 0L
    }
  }
  r
}

///|
fn f256_add(a : Array[UInt], b : Array[UInt]) -> Array[UInt] {
  let r = Array::make(8, 0U)
  let mut carry = 0UL
  for i in 0..<8 {
    let s = a[i].to_uint64() + b[i].to_uint64() + carry
    r[i] = (s & p256_mask32).to_uint()
    carry = s >> 32
  }
  // sum < 2p: one conditional subtraction (carry out implies >= p)
  if carry > 0UL || f256_cmp(r, p256_prime_words) >= 0 {
    return f256_sub_raw(r, p256_prime_words)
  }
  r
}

///|
fn f256_sub(a : Array[UInt], b : Array[UInt]) -> Array[UInt] {
  let r = Array::make(8, 0U)
  let mut borrow = 0L
  for i in 0..<8 {
    let d = a[i].to_int64() - b[i].to_int64() - borrow
    if d < 0L {
      r[i] = f256_i64_to_u32(d + 4294967296L)
      borrow = 1L
    } else {
      r[i] = f256_i64_to_u32(d)
      borrow = 0L
    }
  }
  if borrow > 0L {
    // add p back (result was negative): r += p, carry out discarded (= mod p)
    let mut carry = 0UL
    for i in 0..<8 {
      let s = r[i].to_uint64() + p256_prime_words[i].to_uint64() + carry
      r[i] = (s & p256_mask32).to_uint()
      carry = s >> 32
    }
  }
  r
}

///|
fn f256_mul(a : Array[UInt], b : Array[UInt]) -> Array[UInt] {
  // 1) schoolbook: 16 words, each step r[i+j] + a[i]*b[j] + carry
  //    is provably < 2^64 (r < 2^32, prod <= 2^64-2^33+1, carry < 2^32).
  let r = Array::make(16, 0U)
  for i in 0..<8 {
    let mut carry = 0UL
    let ai = a[i].to_uint64()
    for j in 0..<8 {
      let t = r[i + j].to_uint64() + ai * b[j].to_uint64() + carry
      r[i + j] = (t & p256_mask32).to_uint()
      carry = t >> 32
    }
    r[i + 8] = carry.to_uint()
  }
  // 2) Solinas fold into signed Int64 accumulators
  let acc = Array::make(8, 0L)
  for k in 0..<8 {
    acc[k] = r[k].to_int64()
  }
  for i in 8..<16 {
    let ri = r[i].to_int64()
    if ri == 0L {
      continue
    }
    let base = (i - 8) * 8
    for k in 0..<8 {
      let cf = p256_foldc[base + k]
      if cf != 0 {
        acc[k] = acc[k] + cf.to_int64() * ri
      }
    }
  }
  // 3) carry-normalize, folding any overflow past word 7 with
  //    2^256 = 2^224 - 2^192 - 2^96 + 1. Iterate until the fold carry
  //    vanishes (each pass shrinks it by ~2^28, so <= 3 passes).
  let mut done = false
  while done == false {
    let mut c = 0L
    for k in 0..<8 {
      let t = acc[k] + c
      c = t >> 32
      acc[k] = t - (c << 32)
    }
    if c == 0L {
      done = true
    } else {
      acc[7] = acc[7] + c // +2^224
      acc[6] = acc[6] - c // -2^192
      acc[3] = acc[3] - c // -2^96
      acc[0] = acc[0] + c // +1
    }
  }
  // 4) extract words; value now in [0, 2^256); one conditional subtract
  let out = Array::make(8, 0U)
  for k in 0..<8 {
    out[k] = f256_i64_to_u32(acc[k])
  }
  if f256_cmp(out, p256_prime_words) >= 0 {
    return f256_sub_raw(out, p256_prime_words)
  }
  out
}

///|
fn f256_sqr(a : Array[UInt]) -> Array[UInt] {
  f256_mul(a, a)
}

///|
fn f256_inv(a : Array[UInt]) -> Array[UInt] {
  let mut r = f256_one()
  for b in p256_pm2_bits {
    r = f256_sqr(r)
    if b {
      r = f256_mul(r, a)
    }
  }
  r
}

// ==================== curve (Jacobian, a = -3) ====================

///|
priv struct P256Jac {
  x : Array[UInt]
  y : Array[UInt]
  z : Array[UInt]
}

///|
fn p256_identity() -> P256Jac {
  P256Jac::{ x: f256_zero(), y: f256_one(), z: f256_zero(), }
}

///|
fn p256_double(pt : P256Jac) -> P256Jac {
  if f256_is_zero(pt.z) || f256_is_zero(pt.y) {
    return p256_identity()
  }
  let delta = f256_sqr(pt.z)
  let gamma = f256_sqr(pt.y)
  let beta = f256_mul(pt.x, gamma)
  // alpha = 3*(X - delta)*(X + delta)   (a = -3)
  let t = f256_sub(pt.x, delta)
  let u = f256_add(pt.x, delta)
  let alpha = f256_mul(f256_add(f256_add(t, t), t), u)
  // X3 = alpha^2 - 8*beta
  let alpha_sq = f256_sqr(alpha)
  let beta2 = f256_add(beta, beta)
  let beta4 = f256_add(beta2, beta2)
  let beta8 = f256_add(beta4, beta4)
  let x3 = f256_sub(alpha_sq, beta8)
  // Z3 = (Y + Z)^2 - gamma - delta
  let yz = f256_add(pt.y, pt.z)
  let yz_sq = f256_sqr(yz)
  let z3 = f256_sub(f256_sub(yz_sq, gamma), delta)
  // Y3 = alpha*(4*beta - X3) - 8*gamma^2
  let inner = f256_sub(beta4, x3)
  let gamma_sq = f256_sqr(gamma)
  let gamma_sq2 = f256_add(gamma_sq, gamma_sq)
  let gamma_sq4 = f256_add(gamma_sq2, gamma_sq2)
  let gamma_sq8 = f256_add(gamma_sq4, gamma_sq4)
  let y3 = f256_sub(f256_mul(alpha, inner), gamma_sq8)
  P256Jac::{ x: x3, y: y3, z: z3, }
}

///|
fn p256_add(p1 : P256Jac, p2 : P256Jac) -> P256Jac {
  if f256_is_zero(p1.z) {
    return p2
  }
  if f256_is_zero(p2.z) {
    return p1
  }
  let z1z1 = f256_sqr(p1.z)
  let z2z2 = f256_sqr(p2.z)
  let u1 = f256_mul(p1.x, z2z2)
  let u2 = f256_mul(p2.x, z1z1)
  let s1 = f256_mul(f256_mul(p1.y, p2.z), z2z2)
  let s2 = f256_mul(f256_mul(p2.y, p1.z), z1z1)
  if f256_equal(u1, u2) {
    if f256_equal(s1, s2) == false {
      return p256_identity()
    }
    return p256_double(p1)
  }
  let h = f256_sub(u2, u1)
  let h2 = f256_add(h, h)
  let i = f256_sqr(h2)
  let j = f256_mul(h, i)
  let s2_minus_s1 = f256_sub(s2, s1)
  let rr = f256_add(s2_minus_s1, s2_minus_s1)
  let v = f256_mul(u1, i)
  let rr_sq = f256_sqr(rr)
  let v2 = f256_add(v, v)
  let x3 = f256_sub(f256_sub(rr_sq, j), v2)
  let t1 = f256_sub(v, x3)
  let t2 = f256_mul(rr, t1)
  let s12 = f256_add(s1, s1)
  let t3 = f256_mul(s12, j)
  let y3 = f256_sub(t2, t3)
  let z12 = f256_add(p1.z, p2.z)
  let z12_sq = f256_sqr(z12)
  let t4 = f256_sub(f256_sub(z12_sq, z1z1), z2z2)
  let z3 = f256_mul(t4, h)
  P256Jac::{ x: x3, y: y3, z: z3, }
}

///|
fn p256_to_affine(pt : P256Jac) -> EcPoint {
  if f256_is_zero(pt.z) {
    return ec_identity()
  }
  let zi = f256_inv(pt.z)
  let zi2 = f256_sqr(zi)
  let zi3 = f256_mul(zi2, zi)
  EcPoint::{
    x: f256_to_big(f256_mul(pt.x, zi2)),
    y: f256_to_big(f256_mul(pt.y, zi3)),
    inf: false,
  }
}

///|
fn p256_from_affine(pt : EcPoint) -> P256Jac {
  if pt.inf {
    return p256_identity()
  }
  P256Jac::{ x: f256_from_big(pt.x), y: f256_from_big(pt.y), z: f256_one(), }
}

///|
/// 4-bit fixed-window scalar multiplication (mirrors ec_scalar_mult_jac).
fn p256_scalar_mult_jac(k : @bigint.BigInt, jp : P256Jac) -> P256Jac {
  let tab = Array::make(16, p256_identity())
  tab[1] = jp
  for i in 2..<16 {
    tab[i] = p256_add(tab[i - 1], jp)
  }
  let hex = k.to_string(radix=16)
  let mut r = p256_identity()
  for ch in hex {
    r = p256_double(r)
    r = p256_double(r)
    r = p256_double(r)
    r = p256_double(r)
    let d = ec_hex_nibble(ch.to_int())
    if d > 0 {
      r = p256_add(r, tab[d])
    }
  }
  r
}

///|
/// Shamir double scalar multiplication (mirrors ec_double_scalar_mult_jac).
fn p256_double_scalar_mult_jac(
  k1 : @bigint.BigInt,
  p1 : P256Jac,
  k2 : @bigint.BigInt,
  p2 : P256Jac,
) -> P256Jac {
  let t1 = Array::make(16, p256_identity())
  t1[1] = p1
  for i in 2..<16 {
    t1[i] = p256_add(t1[i - 1], p1)
  }
  let t2 = Array::make(16, p256_identity())
  t2[1] = p2
  for i in 2..<16 {
    t2[i] = p256_add(t2[i - 1], p2)
  }
  let h1 = k1.to_string(radix=16)
  let h2 = k2.to_string(radix=16)
  let n = if h1.length() > h2.length() { h1.length() } else { h2.length() }
  let mut r = p256_identity()
  for i in 0..<n {
    r = p256_double(r)
    r = p256_double(r)
    r = p256_double(r)
    r = p256_double(r)
    let o1 = n - h1.length()
    let d1 = if i < o1 { 0 } else { ec_hex_nibble(h1[i - o1].to_int()) }
    let o2 = n - h2.length()
    let d2 = if i < o2 { 0 } else { ec_hex_nibble(h2[i - o2].to_int()) }
    if d1 > 0 {
      r = p256_add(r, t1[d1])
    }
    if d2 > 0 {
      r = p256_add(r, t2[d2])
    }
  }
  r
}

// ==================== glue for ecdsa.mbt ====================

///|
fn p256_scalar_mult_native(k : @bigint.BigInt, p : EcPoint) -> EcPoint {
  p256_to_affine(p256_scalar_mult_jac(k, p256_from_affine(p)))
}

///|
fn p256_double_scalar_mult_native(
  k1 : @bigint.BigInt,
  p1 : EcPoint,
  k2 : @bigint.BigInt,
  p2 : EcPoint,
) -> EcPoint {
  p256_to_affine(
    p256_double_scalar_mult_jac(
      k1,
      p256_from_affine(p1),
      k2,
      p256_from_affine(p2),
    ),
  )
}

///|
/// Debug probes (differential testing during the native-port bringup).
pub fn p256_dbg_mul(a : Bytes, b : Bytes) -> Bytes {
  f256_to_bytes(f256_mul(f256_from_bytes(a), f256_from_bytes(b)))
}

///|
pub fn p256_dbg_ref_mul(a : Bytes, b : Bytes) -> Bytes {
  let x = @bigint.BigInt::from_octets(a) % p256_curve.p
  let y = @bigint.BigInt::from_octets(b) % p256_curve.p
  ec_mul(p256_curve, x, y).to_octets(length=32)
}

///|
pub fn p256_dbg_gmul(k : Int) -> Bytes {
  let g = ec_g_point(p256_curve)
  let pt = p256_scalar_mult_native(@bigint.BigInt::from_int(k), g)
  concat_all([pt.x.to_octets(length=32), pt.y.to_octets(length=32)])
}

///|
pub fn p256_dbg_ref_gmul(k : Int) -> Bytes {
  let g = ec_g_point(p256_curve)
  let pt = jac_to_affine(
    p256_curve,
    ec_scalar_mult_jac(p256_curve, @bigint.BigInt::from_int(k), ec_to_jac(g)),
  )
  concat_all([pt.x.to_octets(length=32), pt.y.to_octets(length=32)])
}

///|
pub fn bytes_slice_dbg(b : Bytes, off : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[off + i]
  }
  Bytes::from_array(out)
}
