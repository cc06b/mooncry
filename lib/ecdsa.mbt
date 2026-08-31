// ==================== ECDSA (RFC 6979 deterministic) ====================
// Sign/verify over 256-bit prime curves, currently:
//   - P-256 (secp256r1): y^2 = x^3 - 3x + b mod p
//   - secp256k1 (Bitcoin): y^2 = x^3 + 7 mod p  (a = 0)
// RFC 6979 deterministic k generation with HMAC-SHA-256. Field arithmetic
// uses @bigint. Verified against the `cryptography` library (P-256) and
// the `ecdsa` library + `cryptography` cross-verification (secp256k1).
//
// v0.20.0 perf: point arithmetic moved from affine to Jacobian projective
// coordinates. Affine double/add each need one Fermat-exponentiation modular
// inverse (~256 field muls); a 256-bit scalar multiplication therefore cost
// ~384 inverses. Jacobian double/add need no inverses at all — only the
// final conversion back to affine inverts once. Measured on one host:
// sign 58.6 -> 2.66 ms and verify 117.4 -> 5.19 ms (~22x both).
//
// v0.22.0: curve parameters moved into an EcCurve record so the same
// Jacobian/RFC 6979 code serves both curves. P-256 behavior is unchanged
// (byte-identical signatures).

///|
priv struct EcCurve {
  p : @bigint.BigInt
  n : @bigint.BigInt
  b : @bigint.BigInt
  // true: a = -3 (P-256 fast doubling); false: a = 0 (secp256k1)
  a_minus3 : Bool
  gx : @bigint.BigInt
  gy : @bigint.BigInt
}

///|
let p256_curve : EcCurve = {
  p: @bigint.BigInt::from_string(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    radix=16,
  ),
  n: @bigint.BigInt::from_string(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    radix=16,
  ),
  b: @bigint.BigInt::from_string(
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    radix=16,
  ),
  a_minus3: true,
  gx: @bigint.BigInt::from_string(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    radix=16,
  ),
  gy: @bigint.BigInt::from_string(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    radix=16,
  ),
}

///|
let secp256k1_curve : EcCurve = {
  p: @bigint.BigInt::from_string(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    radix=16,
  ),
  n: @bigint.BigInt::from_string(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    radix=16,
  ),
  b: @bigint.BigInt::from_uint64(7UL),
  a_minus3: false,
  gx: @bigint.BigInt::from_string(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    radix=16,
  ),
  gy: @bigint.BigInt::from_string(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    radix=16,
  ),
}

///|
let ec_one : @bigint.BigInt = @bigint.BigInt::from_uint64(1UL)

///|
let ec_two : @bigint.BigInt = @bigint.BigInt::from_uint64(2UL)

///|
let ec_zero : @bigint.BigInt = @bigint.BigInt::from_uint64(0UL)

///|
fn ec_mod(p : @bigint.BigInt, x : @bigint.BigInt) -> @bigint.BigInt {
  (x % p + p) % p
}

///|
fn ec_mul(
  p : @bigint.BigInt,
  a : @bigint.BigInt,
  b : @bigint.BigInt,
) -> @bigint.BigInt {
  a * b % p
}

///|
fn ec_add(
  p : @bigint.BigInt,
  a : @bigint.BigInt,
  b : @bigint.BigInt,
) -> @bigint.BigInt {
  ec_mod(p, a + b)
}

///|
// Non-negative subtraction (avoids negative BigInt intermediates — see X25519
// lesson): (a + p) - b is always >= 0 since a in [0,p) and b in [0,p).
fn ec_sub(
  p : @bigint.BigInt,
  a : @bigint.BigInt,
  b : @bigint.BigInt,
) -> @bigint.BigInt {
  (a + p - b) % p
}

///|
fn ec_inv(p : @bigint.BigInt, a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(p - ec_two, modulus=p)
}

///|
fn ec_inv_n(n : @bigint.BigInt, a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(n - ec_two, modulus=n)
}

///|
priv struct EcPoint {
  x : @bigint.BigInt
  y : @bigint.BigInt
  inf : Bool
}

///|
fn ec_identity() -> EcPoint {
  EcPoint::{ x: ec_zero, y: ec_zero, inf: true, }
}

// ==================== Jacobian projective points ====================
// (X, Y, Z) represents affine (X/Z^2, Y/Z^3); Z = 0 is the point at
// infinity. Doubling specializes on the curve's `a` (-3 for P-256, 0 for
// secp256k1). All subtractions go through ec_sub so no negative BigInt
// intermediates are produced.

///|
priv struct JacPoint {
  x : @bigint.BigInt
  y : @bigint.BigInt
  z : @bigint.BigInt
}

///|
fn jac_identity() -> JacPoint {
  JacPoint::{ x: ec_zero, y: ec_one, z: ec_zero, }
}

///|
fn ec_to_jac(p : EcPoint) -> JacPoint {
  if p.inf {
    jac_identity()
  } else {
    JacPoint::{ x: p.x, y: p.y, z: ec_one, }
  }
}

///|
/// Convert back to affine with a single modular inverse
fn jac_to_affine(c : EcCurve, jp : JacPoint) -> EcPoint {
  if jp.z == ec_zero {
    return ec_identity()
  }
  let zi = ec_inv(c.p, jp.z)
  let zi2 = ec_mul(c.p, zi, zi)
  let zi3 = ec_mul(c.p, zi2, zi)
  EcPoint::{ x: ec_mul(c.p, jp.x, zi2), y: ec_mul(c.p, jp.y, zi3), inf: false, }
}

///|
/// Jacobian doubling.
/// a = -3 (P-256): alpha = 3*(X - delta)*(X + delta) (= 3X^2 + a*Z^4)
/// a = 0 (secp256k1): alpha = 3*X^2
/// With delta = Z^2, gamma = Y^2, beta = X*gamma:
/// X' = alpha^2 - 8*beta
/// Z' = (Y + Z)^2 - gamma - delta
/// Y' = alpha*(4*beta - X') - 8*gamma^2
fn jac_double_pt(c : EcCurve, p : JacPoint) -> JacPoint {
  if p.z == ec_zero || p.y == ec_zero {
    return jac_identity()
  }
  let delta = ec_mul(c.p, p.z, p.z)
  let gamma = ec_mul(c.p, p.y, p.y)
  let beta = ec_mul(c.p, p.x, gamma)
  let alpha = if c.a_minus3 {
    // alpha = 3 * (x - delta) * (x + delta)
    let t = ec_sub(c.p, p.x, delta)
    let u = ec_add(c.p, p.x, delta)
    ec_mul(c.p, ec_add(c.p, ec_add(c.p, t, t), t), u)
  } else {
    // alpha = 3 * x^2 (a = 0)
    let xx = ec_mul(c.p, p.x, p.x)
    ec_add(c.p, ec_add(c.p, xx, xx), xx)
  }
  // X3 = alpha^2 - 8*beta
  let alpha_sq = ec_mul(c.p, alpha, alpha)
  let beta2 = ec_add(c.p, beta, beta)
  let beta4 = ec_add(c.p, beta2, beta2)
  let beta8 = ec_add(c.p, beta4, beta4)
  let x3 = ec_sub(c.p, alpha_sq, beta8)
  // Z3 = (y + z)^2 - gamma - delta
  let yz = ec_add(c.p, p.y, p.z)
  let yz_sq = ec_mul(c.p, yz, yz)
  let z3 = ec_sub(c.p, ec_sub(c.p, yz_sq, gamma), delta)
  // Y3 = alpha*(4*beta - X3) - 8*gamma^2
  let beta4b = ec_add(c.p, beta2, beta2)
  let inner = ec_sub(c.p, beta4b, x3)
  let gamma_sq = ec_mul(c.p, gamma, gamma)
  let gamma_sq2 = ec_add(c.p, gamma_sq, gamma_sq)
  let gamma_sq4 = ec_add(c.p, gamma_sq2, gamma_sq2)
  let gamma_sq8 = ec_add(c.p, gamma_sq4, gamma_sq4)
  let y3 = ec_sub(c.p, ec_mul(c.p, alpha, inner), gamma_sq8)
  JacPoint::{ x: x3, y: y3, z: z3, }
}

///|
/// General Jacobian addition P1 + P2 (handles arbitrary Z; correctly
/// degenerates to doubling when U1 == U2 and S1 == S2, and to infinity
/// when U1 == U2 and S1 != S2).
fn jac_add_pt(c : EcCurve, p1 : JacPoint, p2 : JacPoint) -> JacPoint {
  if p1.z == ec_zero {
    return p2
  }
  if p2.z == ec_zero {
    return p1
  }
  let z1z1 = ec_mul(c.p, p1.z, p1.z)
  let z2z2 = ec_mul(c.p, p2.z, p2.z)
  let u1 = ec_mul(c.p, p1.x, z2z2)
  let u2 = ec_mul(c.p, p2.x, z1z1)
  let s1 = ec_mul(c.p, ec_mul(c.p, p1.y, p2.z), z2z2)
  let s2 = ec_mul(c.p, ec_mul(c.p, p2.y, p1.z), z1z1)
  if u1 == u2 {
    if s1 != s2 {
      return jac_identity()
    }
    return jac_double_pt(c, p1)
  }
  let h = ec_sub(c.p, u2, u1)
  let h2 = ec_add(c.p, h, h)
  let i = ec_mul(c.p, h2, h2)
  let j = ec_mul(c.p, h, i)
  let s2_minus_s1 = ec_sub(c.p, s2, s1)
  let rr = ec_add(c.p, s2_minus_s1, s2_minus_s1)
  let v = ec_mul(c.p, u1, i)
  // X3 = rr^2 - J - 2V
  let rr_sq = ec_mul(c.p, rr, rr)
  let v2 = ec_add(c.p, v, v)
  let x3 = ec_sub(c.p, ec_sub(c.p, rr_sq, j), v2)
  // Y3 = rr*(V - X3) - 2*S1*J
  let t1 = ec_sub(c.p, v, x3)
  let t2 = ec_mul(c.p, rr, t1)
  let s12 = ec_add(c.p, s1, s1)
  let t3 = ec_mul(c.p, s12, j)
  let y3 = ec_sub(c.p, t2, t3)
  // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
  let z12 = ec_add(c.p, p1.z, p2.z)
  let z12_sq = ec_mul(c.p, z12, z12)
  let t4 = ec_sub(c.p, ec_sub(c.p, z12_sq, z1z1), z2z2)
  let z3 = ec_mul(c.p, t4, h)
  JacPoint::{ x: x3, y: y3, z: z3, }
}

///|
/// Scalar multiplication: double-and-add over Jacobian points, converting
/// back to affine with one modular inverse at the end.
fn ec_scalar_mult(c : EcCurve, k : @bigint.BigInt, p : EcPoint) -> EcPoint {
  let jp = ec_to_jac(p)
  let bits = k.to_string(radix=2)
  let mut r = jac_identity()
  for ch in bits {
    r = jac_double_pt(c, r)
    if ch == '1' {
      r = jac_add_pt(c, r, jp)
    }
  }
  jac_to_affine(c, r)
}

///|
/// Add two affine points via Jacobian coordinates (single inverse at the
/// end instead of one per affine operation)
fn ec_add_points(c : EcCurve, p1 : EcPoint, p2 : EcPoint) -> EcPoint {
  jac_to_affine(c, jac_add_pt(c, ec_to_jac(p1), ec_to_jac(p2)))
}

///|
fn ec_g_point(c : EcCurve) -> EcPoint {
  EcPoint::{ x: c.gx, y: c.gy, inf: false, }
}

// ==================== RFC 6979 deterministic k ====================

///|
/// Big-endian bytes -> BigInt.
fn ec_be_to_int(b : Bytes) -> @bigint.BigInt {
  @bigint.BigInt::from_octets(b)
}

///|
/// BigInt -> `len` big-endian bytes.
fn ec_int_to_be(x : @bigint.BigInt, len : Int) -> Bytes {
  x.to_octets(length=len)
}

///|
/// bits2int (RFC 6979): interpret the hash bytes as a big-endian integer.
/// For 256-bit curves (hlen == qlen == 32) no right-shift is applied.
fn ec_bits2int(b : Bytes) -> @bigint.BigInt {
  ec_be_to_int(b)
}

///|
/// int2octets (RFC 6979): x as qlen/8 = 32 bytes (x < n).
fn ec_int2octets(x : @bigint.BigInt) -> Bytes {
  ec_int_to_be(x, 32)
}

///|
/// bits2octets (RFC 6979): bits2int(h) mod n, as 32 bytes.
fn ec_bits2octets(n : @bigint.BigInt, h : Bytes) -> Bytes {
  let z = ec_bits2int(h) % n
  ec_int_to_be(z, 32)
}

///|
/// HMAC-SHA-256 producing a 32-byte tag.
fn ec_hmac_sha256(key : Bytes, msg : Bytes) -> Bytes {
  hmac_sha256(key, msg)
}

///|
/// RFC 6979 deterministic k generator state.
priv struct Rfc6979 {
  mut v : Bytes
  mut k : Bytes
}

///|
fn rfc6979_new(n : @bigint.BigInt, x : @bigint.BigInt, h1 : Bytes) -> Rfc6979 {
  let x_bytes = ec_int2octets(x)
  let h1_bytes = ec_bits2octets(n, h1)
  let v0 = Array::make(32, b'\x01')
  let k0 = Array::make(32, b'\x00')
  let k1 = ec_hmac_sha256(
    Bytes::from_array(k0[:]),
    concat_all([
      Bytes::from_array(v0[:]),
      Bytes::make(1, b'\x00'),
      x_bytes,
      h1_bytes,
    ]),
  )
  let v1 = ec_hmac_sha256(k1, Bytes::from_array(v0[:]))
  // Step F: K = HMAC(K1, V1 || 0x01 || x || h1)  (matches the ecdsa-lib / pycryptodome variant)
  let k2 = ec_hmac_sha256(
    k1,
    concat_all([v1, Bytes::make(1, b'\x01'), x_bytes, h1_bytes]),
  )
  // Step G: V = HMAC(K2, V1)
  let v2 = ec_hmac_sha256(k2, v1)
  Rfc6979::{ v: v2, k: k2, }
}

///|
/// Produce the next candidate k (RFC 6979). May return a value outside
/// [1, n-1]; the caller must reject and call again.
fn rfc6979_next(g : Rfc6979) -> @bigint.BigInt {
  // Step H2: T = V = HMAC(K, V); for 256-bit curves (qlen=32) one V block
  // suffices.
  g.v = ec_hmac_sha256(g.k, g.v)
  let k_candidate = ec_bits2int(g.v)
  // Rejection advance: K = HMAC(K, V || 0x00) [no x/h1]; V = HMAC(K, V)
  g.k = ec_hmac_sha256(g.k, concat_bytes(g.v, Bytes::make(1, b'\x00')))
  g.v = ec_hmac_sha256(g.k, g.v)
  k_candidate
}

// ==================== generic sign / verify ====================

///|
/// Derive the uncompressed public key (0x04 || X(32) || Y(32)) from a
/// 32-byte big-endian private scalar.
fn ec_public_key(c : EcCurve, private_key : Bytes) -> Bytes {
  if private_key.length() != 32 {
    abort("ecdsa: private key must be 32 bytes")
  }
  let d = ec_be_to_int(private_key)
  let q = ec_scalar_mult(c, d, ec_g_point(c))
  let out = Array::make(65, b'\x00')
  out[0] = b'\x04'
  let qx = ec_int_to_be(q.x, 32)
  let qy = ec_int_to_be(q.y, 32)
  for i in 0..<32 {
    out[1 + i] = qx[i]
    out[33 + i] = qy[i]
  }
  Bytes::from_array(out[:])
}

///|
/// ECDSA sign (RFC 6979 deterministic, SHA-256). Returns the 64-byte
/// signature (r || s, each 32 bytes big-endian).
fn ec_sign(c : EcCurve, private_key : Bytes, message : Bytes) -> Bytes {
  if private_key.length() != 32 {
    abort("ecdsa_sign: private key must be 32 bytes")
  }
  let d = ec_be_to_int(private_key)
  let h = sha256(message)
  let e = ec_bits2int(h)
  let gen = rfc6979_new(c.n, d, h)
  let mut r = ec_zero
  let mut s = ec_zero
  let mut ok = false
  let mut attempts = 0
  while !ok {
    attempts = attempts + 1
    if attempts > 100 {
      abort("ecdsa_sign: too many RFC 6979 attempts")
    }
    let k = rfc6979_next(gen)
    if k < ec_one || k >= c.n {
      continue
    }
    let point = ec_scalar_mult(c, k, ec_g_point(c))
    if point.inf {
      continue
    }
    r = point.x % c.n
    if r == ec_zero {
      continue
    }
    // s = k^-1 * (e + r*d) mod n
    let rd = r * d % c.n
    let e_rd = (e + rd) % c.n
    s = ec_mul(c.n, ec_inv_n(c.n, k), e_rd) % c.n
    if s == ec_zero {
      continue
    }
    ok = true
  }
  let r_bytes = ec_int_to_be(r, 32)
  let s_bytes = ec_int_to_be(s, 32)
  let out = Array::make(64, b'\x00')
  for i in 0..<32 {
    out[i] = r_bytes[i]
    out[32 + i] = s_bytes[i]
  }
  Bytes::from_array(out[:])
}

///|
/// ECDSA verify. `public_key` is the uncompressed 65-byte form
/// (0x04 || X || Y). Returns true iff the signature is valid.
fn ec_verify(
  c : EcCurve,
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
) -> Bool {
  if public_key.length() != 65 || public_key[0] != b'\x04' || sig.length() != 64 {
    return false
  }
  let qx = ec_be_to_int(ec_slice(public_key, 1, 32))
  let qy = ec_be_to_int(ec_slice(public_key, 33, 32))
  let q = EcPoint::{ x: qx, y: qy, inf: false, }
  // check Q is on the curve: y^2 = x^3 + a*x + b mod p
  let lhs = ec_mul(c.p, qy, qy)
  let x3 = ec_mul(c.p, ec_mul(c.p, qx, qx), qx)
  let rhs = if c.a_minus3 {
    // a = -3: x^3 - 3x + b
    ec_add(c.p, ec_sub(c.p, x3, ec_add(c.p, ec_add(c.p, qx, qx), qx)), c.b)
  } else {
    // a = 0: x^3 + b
    ec_add(c.p, x3, c.b)
  }
  if !(lhs == rhs) {
    return false
  }
  let r_sig = ec_be_to_int(ec_slice(sig, 0, 32))
  let s_sig = ec_be_to_int(ec_slice(sig, 32, 32))
  if r_sig < ec_one || r_sig >= c.n || s_sig < ec_one || s_sig >= c.n {
    return false
  }
  let h = sha256(message)
  let e = ec_bits2int(h)
  let w = ec_inv_n(c.n, s_sig)
  let u1 = ec_mul(c.n, e, w) % c.n
  let u2 = ec_mul(c.n, r_sig, w) % c.n
  let pt = ec_add_points(
    c,
    ec_scalar_mult(c, u1, ec_g_point(c)),
    ec_scalar_mult(c, u2, q),
  )
  if pt.inf {
    return false
  }
  pt.x % c.n == r_sig
}

///|
fn ec_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}

// ==================== public API: P-256 ====================

///|
/// Derive the P-256 public key (uncompressed: 0x04 || X(32) || Y(32)) from a
/// 32-byte big-endian private scalar.
pub fn ecdsa_p256_public_key(private_key : Bytes) -> Bytes {
  ec_public_key(p256_curve, private_key)
}

///|
/// ECDSA P-256 sign (RFC 6979 deterministic). Returns the 64-byte signature
/// (r || s, each 32 bytes big-endian).
pub fn ecdsa_p256_sign(private_key : Bytes, message : Bytes) -> Bytes {
  ec_sign(p256_curve, private_key, message)
}

///|
/// ECDSA P-256 verify. `public_key` is the uncompressed 65-byte form
/// (0x04 || X || Y). Returns true iff the signature is valid.
pub fn ecdsa_p256_verify(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
) -> Bool {
  ec_verify(p256_curve, public_key, message, sig)
}

// ==================== public API: secp256k1 ====================

///|
/// Derive the secp256k1 public key (uncompressed: 0x04 || X(32) || Y(32))
/// from a 32-byte big-endian private scalar.
pub fn ecdsa_secp256k1_public_key(private_key : Bytes) -> Bytes {
  ec_public_key(secp256k1_curve, private_key)
}

///|
/// ECDSA secp256k1 sign (RFC 6979 deterministic with SHA-256, the standard
/// Bitcoin curve construction). Returns the 64-byte signature (r || s, each
/// 32 bytes big-endian). Note: `s` is not normalized to the low-S form;
/// normalize if you need BIP-62 canonical signatures.
pub fn ecdsa_secp256k1_sign(private_key : Bytes, message : Bytes) -> Bytes {
  ec_sign(secp256k1_curve, private_key, message)
}

///|
/// ECDSA secp256k1 verify. `public_key` is the uncompressed 65-byte form
/// (0x04 || X || Y). Returns true iff the signature is valid. Accepts any
/// valid s in [1, n-1] (both high- and low-S forms).
pub fn ecdsa_secp256k1_verify(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
) -> Bool {
  ec_verify(secp256k1_curve, public_key, message, sig)
}
