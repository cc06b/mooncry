// ==================== ECDSA P-256 (secp256r1, RFC 6979 deterministic) ====================
// Sign/verify over the NIST P-256 curve y^2 = x^3 - 3x + b mod p, using
// RFC 6979 deterministic k generation (HMAC-SHA-256). Field arithmetic uses
// @bigint. Verified against the `cryptography` library (ECDSA P-256).
//
// v0.20.0 perf: point arithmetic moved from affine to Jacobian projective
// coordinates. Affine double/add each need one Fermat-exponentiation modular
// inverse (~256 field muls); a 256-bit scalar multiplication therefore cost
// ~384 inverses. Jacobian double/add need no inverses at all — only the
// final conversion back to affine inverts once. Measured on one host:
// sign 58.6 -> 2.66 ms and verify 117.4 -> 5.19 ms (~22x both).

///|
let ec_p : @bigint.BigInt = @bigint.BigInt::from_string(
  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
  radix=16,
)

///|
let ec_n : @bigint.BigInt = @bigint.BigInt::from_string(
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
  radix=16,
)

///|
let ec_b : @bigint.BigInt = @bigint.BigInt::from_string(
  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
  radix=16,
)

///|
// a = -3 mod p
let ec_a : @bigint.BigInt = ec_p - @bigint.BigInt::from_uint64(3UL)

///|
let ec_gx : @bigint.BigInt = @bigint.BigInt::from_string(
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  radix=16,
)

///|
let ec_gy : @bigint.BigInt = @bigint.BigInt::from_string(
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  radix=16,
)

///|
let ec_one : @bigint.BigInt = @bigint.BigInt::from_uint64(1UL)

///|
let ec_two : @bigint.BigInt = @bigint.BigInt::from_uint64(2UL)

///|
let ec_zero : @bigint.BigInt = @bigint.BigInt::from_uint64(0UL)

///|
fn ec_mod(x : @bigint.BigInt) -> @bigint.BigInt {
  (x % ec_p + ec_p) % ec_p
}

///|
fn ec_mul(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  a * b % ec_p
}

///|
fn ec_add(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  ec_mod(a + b)
}

///|
// Non-negative subtraction (avoids negative BigInt intermediates — see X25519
// lesson): (a + p) - b is always >= 0 since a in [0,p) and b in [0,p).
fn ec_sub(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + ec_p - b) % ec_p
}

///|
fn ec_inv(a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(ec_p - ec_two, modulus=ec_p)
}

///|
fn ec_inv_n(a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(ec_n - ec_two, modulus=ec_n)
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
// infinity. Doubling uses the a = -3 fast formulas. All subtractions go
// through ec_sub so no negative BigInt intermediates are produced.

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
fn jac_to_affine(jp : JacPoint) -> EcPoint {
  if jp.z == ec_zero {
    return ec_identity()
  }
  let zi = ec_inv(jp.z)
  let zi2 = ec_mul(zi, zi)
  let zi3 = ec_mul(zi2, zi)
  EcPoint::{ x: ec_mul(jp.x, zi2), y: ec_mul(jp.y, zi3), inf: false, }
}

///|
/// Jacobian doubling with the a = -3 optimization:
/// delta = Z^2, gamma = Y^2, beta = X*gamma,
/// alpha = 3*(X - delta)*(X + delta)  (= 3X^2 + a*Z^4 since a = -3)
/// X' = alpha^2 - 8*beta
/// Z' = (Y + Z)^2 - gamma - delta
/// Y' = alpha*(4*beta - X') - 8*gamma^2
fn jac_double_pt(p : JacPoint) -> JacPoint {
  if p.z == ec_zero || p.y == ec_zero {
    return jac_identity()
  }
  let delta = ec_mul(p.z, p.z)
  let gamma = ec_mul(p.y, p.y)
  let beta = ec_mul(p.x, gamma)
  // alpha = 3 * (x - delta) * (x + delta)
  let t = ec_sub(p.x, delta)
  let u = ec_add(p.x, delta)
  let alpha = ec_mul(ec_add(ec_add(t, t), t), u)
  // X3 = alpha^2 - 8*beta
  let alpha_sq = ec_mul(alpha, alpha)
  let beta2 = ec_add(beta, beta)
  let beta4 = ec_add(beta2, beta2)
  let beta8 = ec_add(beta4, beta4)
  let x3 = ec_sub(alpha_sq, beta8)
  // Z3 = (y + z)^2 - gamma - delta
  let yz = ec_add(p.y, p.z)
  let yz_sq = ec_mul(yz, yz)
  let z3 = ec_sub(ec_sub(yz_sq, gamma), delta)
  // Y3 = alpha*(4*beta - X3) - 8*gamma^2
  let beta4b = ec_add(beta2, beta2)
  let inner = ec_sub(beta4b, x3)
  let gamma_sq = ec_mul(gamma, gamma)
  let gamma_sq2 = ec_add(gamma_sq, gamma_sq)
  let gamma_sq4 = ec_add(gamma_sq2, gamma_sq2)
  let gamma_sq8 = ec_add(gamma_sq4, gamma_sq4)
  let y3 = ec_sub(ec_mul(alpha, inner), gamma_sq8)
  JacPoint::{ x: x3, y: y3, z: z3, }
}

///|
/// General Jacobian addition P1 + P2 (handles arbitrary Z; correctly
/// degenerates to doubling when U1 == U2 and S1 == S2, and to infinity
/// when U1 == U2 and S1 != S2).
fn jac_add_pt(p1 : JacPoint, p2 : JacPoint) -> JacPoint {
  if p1.z == ec_zero {
    return p2
  }
  if p2.z == ec_zero {
    return p1
  }
  let z1z1 = ec_mul(p1.z, p1.z)
  let z2z2 = ec_mul(p2.z, p2.z)
  let u1 = ec_mul(p1.x, z2z2)
  let u2 = ec_mul(p2.x, z1z1)
  let s1 = ec_mul(ec_mul(p1.y, p2.z), z2z2)
  let s2 = ec_mul(ec_mul(p2.y, p1.z), z1z1)
  if u1 == u2 {
    if s1 != s2 {
      return jac_identity()
    }
    return jac_double_pt(p1)
  }
  let h = ec_sub(u2, u1)
  let h2 = ec_add(h, h)
  let i = ec_mul(h2, h2)
  let j = ec_mul(h, i)
  let s2_minus_s1 = ec_sub(s2, s1)
  let rr = ec_add(s2_minus_s1, s2_minus_s1)
  let v = ec_mul(u1, i)
  // X3 = rr^2 - J - 2V
  let rr_sq = ec_mul(rr, rr)
  let v2 = ec_add(v, v)
  let x3 = ec_sub(ec_sub(rr_sq, j), v2)
  // Y3 = rr*(V - X3) - 2*S1*J
  let t1 = ec_sub(v, x3)
  let t2 = ec_mul(rr, t1)
  let s12 = ec_add(s1, s1)
  let t3 = ec_mul(s12, j)
  let y3 = ec_sub(t2, t3)
  // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
  let z12 = ec_add(p1.z, p2.z)
  let z12_sq = ec_mul(z12, z12)
  let t4 = ec_sub(ec_sub(z12_sq, z1z1), z2z2)
  let z3 = ec_mul(t4, h)
  JacPoint::{ x: x3, y: y3, z: z3, }
}

///|
/// Scalar multiplication: double-and-add over Jacobian points, converting
/// back to affine with one modular inverse at the end.
fn ec_scalar_mult(k : @bigint.BigInt, p : EcPoint) -> EcPoint {
  let jp = ec_to_jac(p)
  let bits = k.to_string(radix=2)
  let mut r = jac_identity()
  for c in bits {
    r = jac_double_pt(r)
    if c == '1' {
      r = jac_add_pt(r, jp)
    }
  }
  jac_to_affine(r)
}

///|
/// Add two affine points via Jacobian coordinates (single inverse at the
/// end instead of one per affine operation)
fn ec_add_points(p1 : EcPoint, p2 : EcPoint) -> EcPoint {
  jac_to_affine(jac_add_pt(ec_to_jac(p1), ec_to_jac(p2)))
}

///|
let ec_g : EcPoint = EcPoint::{ x: ec_gx, y: ec_gy, inf: false, }

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
/// For P-256 (hlen == qlen == 32) no right-shift is applied.
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
fn ec_bits2octets(h : Bytes) -> Bytes {
  let z = ec_bits2int(h) % ec_n
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
fn rfc6979_new(x : @bigint.BigInt, h1 : Bytes) -> Rfc6979 {
  let x_bytes = ec_int2octets(x)
  let h1_bytes = ec_bits2octets(h1)
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
  // Step H2: T = V = HMAC(K, V); for P-256 (qlen=32) one V block suffices.
  g.v = ec_hmac_sha256(g.k, g.v)
  let k_candidate = ec_bits2int(g.v)
  // Rejection advance: K = HMAC(K, V || 0x00) [no x/h1]; V = HMAC(K, V)
  g.k = ec_hmac_sha256(g.k, concat_bytes(g.v, Bytes::make(1, b'\x00')))
  g.v = ec_hmac_sha256(g.k, g.v)
  k_candidate
}

// ==================== public API ====================

///|
/// Derive the P-256 public key (uncompressed: 0x04 || X(32) || Y(32)) from a
/// 32-byte big-endian private scalar.
pub fn ecdsa_p256_public_key(private_key : Bytes) -> Bytes {
  if private_key.length() != 32 {
    abort("ecdsa_p256_public_key: private key must be 32 bytes")
  }
  let d = ec_be_to_int(private_key)
  let q = ec_scalar_mult(d, ec_g)
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
/// ECDSA P-256 sign (RFC 6979 deterministic). Returns the 64-byte signature
/// (r || s, each 32 bytes big-endian).
pub fn ecdsa_p256_sign(private_key : Bytes, message : Bytes) -> Bytes {
  if private_key.length() != 32 {
    abort("ecdsa_p256_sign: private key must be 32 bytes")
  }
  let d = ec_be_to_int(private_key)
  let h = sha256(message)
  let e = ec_bits2int(h)
  let gen = rfc6979_new(d, h)
  let mut r = ec_zero
  let mut s = ec_zero
  let mut ok = false
  let mut attempts = 0
  while !ok {
    attempts = attempts + 1
    if attempts > 100 {
      abort("ecdsa_p256_sign: too many RFC 6979 attempts")
    }
    let k = rfc6979_next(gen)
    if k < ec_one || k >= ec_n {
      continue
    }
    let point = ec_scalar_mult(k, ec_g)
    if point.inf {
      continue
    }
    r = point.x % ec_n
    if r == ec_zero {
      continue
    }
    // s = k^-1 * (e + r*d) mod n
    let rd = r * d % ec_n
    let e_rd = (e + rd) % ec_n
    s = ec_mul_n(ec_inv_n(k), e_rd) % ec_n
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
// (n-arithmetic for the scalar ring)
fn ec_mul_n(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  a * b % ec_n
}

///|
/// ECDSA P-256 verify. `public_key` is the uncompressed 65-byte form
/// (0x04 || X || Y). Returns true iff the signature is valid.
pub fn ecdsa_p256_verify(
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
  let lhs = ec_mul(qy, qy)
  let rhs = ec_add(ec_add(ec_mul(ec_mul(qx, qx), qx), ec_mul(ec_a, qx)), ec_b)
  if !(lhs == rhs) {
    return false
  }
  let r_sig = ec_be_to_int(ec_slice(sig, 0, 32))
  let s_sig = ec_be_to_int(ec_slice(sig, 32, 32))
  if r_sig < ec_one || r_sig >= ec_n || s_sig < ec_one || s_sig >= ec_n {
    return false
  }
  let h = sha256(message)
  let e = ec_bits2int(h)
  let w = ec_inv_n(s_sig)
  let u1 = ec_mul_n(e, w) % ec_n
  let u2 = ec_mul_n(r_sig, w) % ec_n
  let pt = ec_add_points(ec_scalar_mult(u1, ec_g), ec_scalar_mult(u2, q))
  if pt.inf {
    return false
  }
  pt.x % ec_n == r_sig
}

///|
fn ec_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}
