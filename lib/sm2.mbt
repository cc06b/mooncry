// SM2 digital signature algorithm (GB/T 32918.2-2017) over the sm2p256v1
// curve (GB/T 32918.5). Reuses the generic EcCurve machinery from ecdsa.mbt
// (Barrett reduction, Jacobian double-and-add, double scalar mult) — SM2's
// curve parameter a equals p-3, the same fast-doubling case as P-256.
// Hash is SM3; the Z value binds signer ID + curve + public key.
// Signatures are raw r||s (64 bytes); public keys uncompressed 04||x||y.

///|
let sm2_curve : EcCurve = ec_make_curve(
  @bigint.BigInt::from_string(sm2_p_hex, radix=16),
  @bigint.BigInt::from_string(sm2_n_hex, radix=16),
  @bigint.BigInt::from_string(sm2_b_hex, radix=16),
  true, // a = p - 3
  @bigint.BigInt::from_string(sm2_gx_hex, radix=16),
  @bigint.BigInt::from_string(sm2_gy_hex, radix=16),
)

///|
fn sm2_a_bytes() -> Bytes {
  // a = p - 3 (verified at extraction time)
  ec_int_to_be(sm2_curve.p - @bigint.BigInt::from_int(3), 32)
}

///|
/// Compute the Z value: SM3(ENTL || ID || a || b || xG || yG || xA || yA),
/// where ENTL is the bit length of ID in two big-endian bytes.
fn sm2_za(qx : @bigint.BigInt, qy : @bigint.BigInt, id : Bytes) -> Bytes {
  let id_bits = id.length() * 8
  guard id_bits > 0 && id_bits < 65536 else {
    abort("sm2: ID bit length must fit in two bytes and be nonzero")
  }
  let entl = Array::make(2, (0).to_byte())
  entl[0] = ((id_bits >> 8) & 0xFF).to_byte()
  entl[1] = (id_bits & 0xFF).to_byte()
  let mut acc = Bytes::from_array(entl[:])
  acc = concat_bytes(acc, id)
  acc = concat_bytes(acc, sm2_a_bytes())
  acc = concat_bytes(acc, ec_int_to_be(sm2_curve.b, 32))
  acc = concat_bytes(acc, ec_int_to_be(sm2_curve.gx, 32))
  acc = concat_bytes(acc, ec_int_to_be(sm2_curve.gy, 32))
  acc = concat_bytes(acc, ec_int_to_be(qx, 32))
  acc = concat_bytes(acc, ec_int_to_be(qy, 32))
  sm3(acc)
}

///|
/// Derive the SM2 public key (uncompressed, 65 bytes: 0x04 || x || y) from
/// a 32-byte big-endian secret key d, with 1 <= d <= n-2.
pub fn sm2_public_key(sk : Bytes) -> Bytes {
  guard sk.length() == 32 else { abort("sm2_public_key: sk must be 32 bytes") }
  let d = ec_be_to_int(sk)
  let one = @bigint.BigInt::from_int(1)
  guard d >= one && d <= sm2_curve.n - 2 else {
    abort("sm2_public_key: secret key out of range [1, n-2]")
  }
  let q = ec_scalar_mult(sm2_curve, d, ec_g_point(sm2_curve))
  let out = Array::make(65, (0).to_byte())
  out[0] = (4).to_byte()
  let xb = ec_int_to_be(q.x, 32)
  let yb = ec_int_to_be(q.y, 32)
  for i in 0..<32 {
    out[1 + i] = xb[i]
    out[33 + i] = yb[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Check a purported public key point lies on sm2p256v1: y^2 = x^3 + a x + b.
fn sm2_on_curve(qx : @bigint.BigInt, qy : @bigint.BigInt) -> Bool {
  let lhs = ec_mul(sm2_curve, qy, qy)
  let x3 = ec_mul(sm2_curve, ec_mul(sm2_curve, qx, qx), qx)
  let ax = ec_red(sm2_curve, (sm2_curve.p - @bigint.BigInt::from_int(3)) * qx)
  let rhs = ec_add(sm2_curve, ec_add(sm2_curve, x3, ax), sm2_curve.b)
  lhs == rhs
}

///|
/// Sign with an explicit nonce k (32-byte big-endian, 1 <= k <= n-1).
/// Returns r||s (64 bytes). Aborts if k is degenerate (r == 0 or r+k == n) —
/// callers using random k should retry with a fresh k via sm2_sign.
pub fn sm2_sign_with_k(sk : Bytes, msg : Bytes, id : Bytes, k : Bytes) -> Bytes {
  guard k.length() == 32 else { abort("sm2_sign_with_k: k must be 32 bytes") }
  let d = ec_be_to_int(sk)
  let kx = ec_be_to_int(k)
  let one = @bigint.BigInt::from_int(1)
  guard d >= one && d <= sm2_curve.n - 2 else {
    abort("sm2_sign_with_k: secret key out of range")
  }
  guard kx >= one && kx <= sm2_curve.n - one else {
    abort("sm2_sign_with_k: k out of range [1, n-1]")
  }
  let q = ec_scalar_mult(sm2_curve, d, ec_g_point(sm2_curve))
  let za = sm2_za(q.x, q.y, id)
  let e = ec_be_to_int(sm3(concat_bytes(za, msg)))
  let pt = ec_scalar_mult(sm2_curve, kx, ec_g_point(sm2_curve))
  let r = ec_red_n(sm2_curve, e + pt.x)
  guard r != ec_zero && r + kx != sm2_curve.n else {
    abort("sm2_sign_with_k: degenerate k (r==0 or r+k==n); pick another k")
  }
  // s = (1+d)^-1 * (k - r*d) mod n
  let s = ec_mul_n(
    sm2_curve,
    ec_inv_n(sm2_curve, one + d),
    ec_red_n(sm2_curve, kx - r * d),
  )
  let out = Array::make(64, (0).to_byte())
  let rb = ec_int_to_be(r, 32)
  let sb = ec_int_to_be(s, 32)
  for i in 0..<32 {
    out[i] = rb[i]
    out[32 + i] = sb[i]
  }
  Bytes::from_array(out[:])
}

///|
/// Sign with fresh randomness: `rand(32)` must return a uniform 32-byte
/// string per call (used as the nonce k). SECURITY: k must be unique per
/// signature under the same key — reuse leaks the secret key (as in ECDSA).
/// Degenerate draws are retried automatically.
pub fn sm2_sign(
  sk : Bytes,
  msg : Bytes,
  id : Bytes,
  rand : (Int) -> Bytes,
) -> Bytes {
  let d = ec_be_to_int(sk)
  let q = ec_scalar_mult(sm2_curve, d, ec_g_point(sm2_curve))
  let za = sm2_za(q.x, q.y, id)
  let e = ec_be_to_int(sm3(concat_bytes(za, msg)))
  let one = @bigint.BigInt::from_int(1)
  let mut done = false
  let out = Array::make(64, (0).to_byte())
  let mut tries = 0
  while !done {
    guard tries < 100 else { abort("sm2_sign: too many degenerate k draws") }
    tries = tries + 1
    let kx = ec_be_to_int(rand(32))
    if kx >= one && kx <= sm2_curve.n - one {
      let pt = ec_scalar_mult(sm2_curve, kx, ec_g_point(sm2_curve))
      let r = ec_red_n(sm2_curve, e + pt.x)
      if r != ec_zero && r + kx != sm2_curve.n {
        let s = ec_mul_n(
          sm2_curve,
          ec_inv_n(sm2_curve, one + d),
          ec_red_n(sm2_curve, kx - r * d),
        )
        let rb = ec_int_to_be(r, 32)
        let sb = ec_int_to_be(s, 32)
        for i in 0..<32 {
          out[i] = rb[i]
          out[32 + i] = sb[i]
        }
        done = true
      }
    }
  }
  Bytes::from_array(out[:])
}

///|
/// Verify an SM2 signature (r||s, 64 bytes) against the uncompressed public
/// key (65 bytes) and signer ID. Rejects points off the curve and malformed
/// encodings.
pub fn sm2_verify(pk : Bytes, msg : Bytes, id : Bytes, sig : Bytes) -> Bool {
  if pk.length() != 65 || pk[0] != (4).to_byte() || sig.length() != 64 {
    return false
  }
  let px = ec_be_to_int(ec_slice(pk, 1, 32))
  let py = ec_be_to_int(ec_slice(pk, 33, 32))
  if px <= ec_zero || px >= sm2_curve.p || py <= ec_zero || py >= sm2_curve.p {
    return false
  }
  if !sm2_on_curve(px, py) {
    return false
  }
  let r = ec_be_to_int(ec_slice(sig, 0, 32))
  let s = ec_be_to_int(ec_slice(sig, 32, 32))
  let one = @bigint.BigInt::from_int(1)
  if r < one || r >= sm2_curve.n || s < one || s >= sm2_curve.n {
    return false
  }
  let t = ec_red_n(sm2_curve, r + s)
  if t == ec_zero {
    return false
  }
  let q = EcPoint::{ x: px, y: py, inf: false, }
  let jp = ec_double_scalar_mult_jac(sm2_curve, s, ec_g_point(sm2_curve), t, q)
  let pt = jac_to_affine(sm2_curve, jp)
  if pt.inf {
    return false
  }
  let za = sm2_za(px, py, id)
  let e = ec_be_to_int(sm3(concat_bytes(za, msg)))
  ec_red_n(sm2_curve, e + pt.x) == r
}
