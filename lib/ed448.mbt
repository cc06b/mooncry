// ==================== Ed448 (RFC 8032, pure EdDSA) ====================
// Ed448-Goldilocks signatures over edwards448 (x^2 + y^2 = 1 + d x^2 y^2,
// d = -39081, p = 2^448 - 2^224 - 1) with SHAKE256-based hashing and the
// dom4 domain separation. Follows the RFC 8032 §5.2 algorithm and the
// Appendix A reference formulas (projective X,Y,Z coordinates, no T).
// Verified against the official RFC 8032 §7.4 test vectors (incl. the
// 1023-octet message and the context-carrying vector).
//
// Verification uses the cofactor equation [4][S]B = [4]R + [4][k]A.
// No RNG: key generation and signing are deterministic (caller supplies
// the 57-byte private key seed).

///|
let ed448_p : @bigint.BigInt = @bigint.BigInt::from_string(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  radix=16,
)

///|
let ed448_d : @bigint.BigInt = ed448_p - @bigint.BigInt::from_uint64(39081UL)

///|
let ed448_l : @bigint.BigInt = @bigint.BigInt::from_string(
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
  radix=16,
)

///|
let ed448_bx : @bigint.BigInt = @bigint.BigInt::from_string(
  "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
  radix=16,
)

///|
let ed448_by : @bigint.BigInt = @bigint.BigInt::from_string(
  "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
  radix=16,
)

///|
let ed448_zero : @bigint.BigInt = @bigint.BigInt::from_uint64(0UL)

///|
let ed448_one : @bigint.BigInt = @bigint.BigInt::from_uint64(1UL)

// ---------- field helpers (always non-negative intermediates) ----------

///|
fn e4_add(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + b) % ed448_p
}

///|
fn e4_sub(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + ed448_p - b) % ed448_p
}

///|
fn e4_mul(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  a * b % ed448_p
}

///|
fn e4_sqr(a : @bigint.BigInt) -> @bigint.BigInt {
  a * a % ed448_p
}

///|
fn e4_inv(a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(ed448_p - ed448_one - ed448_one, modulus=ed448_p)
}

///|
// p ≡ 3 (mod 4): sqrt(x) = x^((p+1)/4), when it exists.
let ed448_sqrt_exp : @bigint.BigInt = (ed448_p + ed448_one) /
  @bigint.BigInt::from_uint64(4UL)

// ---------- little-endian byte <-> BigInt ----------

///|
fn e4_le_to_int(b : Bytes) -> @bigint.BigInt {
  let n = b.length()
  let rev = Array::make(n, b'\x00')
  for i in 0..<n {
    rev[i] = b[n - 1 - i]
  }
  @bigint.BigInt::from_octets(Bytes::from_array(rev[:]))
}

///|
fn e4_int_to_le(x : @bigint.BigInt, len : Int) -> Bytes {
  let be = x.to_octets(length=len)
  let rev = Array::make(len, b'\x00')
  for i in 0..<len {
    rev[i] = be[len - 1 - i]
  }
  Bytes::from_array(rev[:])
}

// ---------- points (projective X,Y,Z; x = X/Z, y = Y/Z) ----------

///|
priv struct E448Point {
  x : @bigint.BigInt
  y : @bigint.BigInt
  z : @bigint.BigInt
}

///|
fn e448_identity() -> E448Point {
  E448Point::{ x: ed448_zero, y: ed448_one, z: ed448_one, }
}

///|
/// RFC 8032 Appendix A.4 addition (edwards448, a = 1).
fn e448_add(pt : E448Point, q : E448Point) -> E448Point {
  let xcp = e4_mul(pt.x, q.x)
  let ycp = e4_mul(pt.y, q.y)
  let zcp = e4_mul(pt.z, q.z)
  let bb = e4_sqr(zcp)
  let ee = e4_mul(e4_mul(ed448_d, xcp), ycp)
  let ff = e4_sub(bb, ee)
  let gg = e4_add(bb, ee)
  let x3 = e4_mul(
    e4_mul(zcp, ff),
    e4_sub(e4_mul(e4_add(pt.x, pt.y), e4_add(q.x, q.y)), e4_add(xcp, ycp)),
  )
  let y3 = e4_mul(e4_mul(zcp, gg), e4_sub(ycp, xcp))
  let z3 = e4_mul(ff, gg)
  E448Point::{ x: x3, y: y3, z: z3, }
}

///|
/// RFC 8032 Appendix A.4 doubling (edwards448, a = 1).
fn e448_double(pt : E448Point) -> E448Point {
  let x1s = e4_sqr(pt.x)
  let y1s = e4_sqr(pt.y)
  let z1s = e4_sqr(pt.z)
  let xys = e4_add(pt.x, pt.y)
  let ff = e4_add(x1s, y1s)
  let jj = e4_sub(ff, e4_add(z1s, z1s))
  let x3 = e4_mul(e4_sub(e4_sub(e4_sqr(xys), x1s), y1s), jj)
  let y3 = e4_mul(ff, e4_sub(x1s, y1s))
  let z3 = e4_mul(ff, jj)
  E448Point::{ x: x3, y: y3, z: z3, }
}

///|
/// Double-and-add scalar multiplication (LSB-first, RFC reference style).
fn e448_mul(s : @bigint.BigInt, pt : E448Point) -> E448Point {
  let mut r = e448_identity()
  let mut base = pt
  let mut k = s
  while k > ed448_zero {
    // k is odd: add
    if k % @bigint.BigInt::from_uint64(2UL) != ed448_zero {
      r = e448_add(r, base)
    }
    base = e448_double(base)
    k = k / @bigint.BigInt::from_uint64(2UL)
  }
  r
}

///|
fn e448_equal(pt : E448Point, q : E448Point) -> Bool {
  e4_mul(pt.x, q.z) == e4_mul(q.x, pt.z) &&
  e4_mul(pt.y, q.z) == e4_mul(q.y, pt.z)
}

// ---------- encoding / decoding ----------

///|
/// Encode y (57 bytes little-endian) with the sign bit of x in the most
/// significant bit of the final octet (RFC 8032 §5.2.5 step 4).
fn e448_encode(pt : E448Point) -> Bytes {
  let zinv = e4_inv(pt.z)
  let x = e4_mul(pt.x, zinv)
  let y = e4_mul(pt.y, zinv)
  let out = e4_int_to_le(y, 57)
  let arr = Array::make(57, b'\x00')
  for i in 0..<57 {
    arr[i] = out[i]
  }
  if x % @bigint.BigInt::from_uint64(2UL) != ed448_zero {
    arr[56] = (arr[56].to_int() | 0x80).to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
/// Solve x^2 = (y^2 - 1) / (d y^2 - 1) (RFC Appendix A.4 solve_x2), then
/// take the square root; returns None if no valid x with the given sign.
fn e448_recover_x(y : @bigint.BigInt, sign : Int) -> E448Point? {
  if y >= ed448_p {
    return None
  }
  let y2 = e4_sqr(y)
  let num = e4_sub(y2, ed448_one)
  let den = e4_inv(e4_sub(e4_mul(ed448_d, y2), ed448_one))
  let x2 = e4_mul(num, den)
  if x2 == ed448_zero {
    if sign == 1 {
      return None
    }
    return Some(E448Point::{ x: ed448_zero, y, z: ed448_one, })
  }
  let x = x2.pow(ed448_sqrt_exp, modulus=ed448_p)
  if e4_sqr(x) != x2 {
    return None
  }
  let x_odd = x % @bigint.BigInt::from_uint64(2UL) != ed448_zero
  let x_sign = if x_odd { 1 } else { 0 }
  let xf = if x_sign == sign { x } else { ed448_p - x }
  Some(E448Point::{ x: xf, y, z: ed448_one, })
}

///|
fn e448_decode(s : Bytes) -> E448Point? {
  if s.length() != 57 {
    return None
  }
  let sign = (s[56].to_int() >> 7) & 1
  let arr = Array::make(57, b'\x00')
  for i in 0..<57 {
    arr[i] = s[i]
  }
  arr[56] = (arr[56].to_int() & 0x7F).to_byte()
  let y = e4_le_to_int(Bytes::from_array(arr[:]))
  match e448_recover_x(y, sign) {
    Some(pt) => Some(pt)
    None => None
  }
}

// ---------- dom4 and secret expansion ----------

///|
/// dom4(F, C) = "SigEd448" || octet(F) || octet(len(C)) || C
fn e448_dom4(flag : Int, ctx : Bytes) -> Bytes {
  let head = Array::make(9, b'\x00')
  let tag = b"SigEd448"
  for i in 0..<8 {
    head[i] = tag[i]
  }
  head[8] = flag.to_byte()
  concat_all([
    Bytes::from_array(head[:]),
    Bytes::make(1, ctx.length().to_byte()),
    ctx,
  ])
}

///|
/// RFC 8032 §5.2.5: SHAKE256(seed, 114); prune: clear the two least
/// significant bits of the first octet, clear the last octet, set the
/// highest bit of the second-to-last octet; s = little-endian of the
/// first 57 octets. Returns (s, prefix) with prefix = h[57..114].
fn e448_secret_expand(seed : Bytes) -> (@bigint.BigInt, Bytes) {
  if seed.length() != 57 {
    abort("ed448: private key must be 57 bytes")
  }
  let h = shake_256(seed, 114)
  let arr = Array::make(57, b'\x00')
  for i in 0..<57 {
    arr[i] = h[i]
  }
  arr[0] = (arr[0].to_int() & 0xFC).to_byte()
  arr[55] = (arr[55].to_int() | 0x80).to_byte()
  arr[56] = b'\x00'
  let s = e4_le_to_int(Bytes::from_array(arr[:]))
  let prefix = Array::make(57, b'\x00')
  for i in 0..<57 {
    prefix[i] = h[57 + i]
  }
  (s, Bytes::from_array(prefix[:]))
}

///|
fn e448_base() -> E448Point {
  E448Point::{ x: ed448_bx, y: ed448_by, z: ed448_one, }
}

// ---------- public API ----------

///|
/// Derive the 57-byte Ed448 public key (encoded point) from a 57-byte
/// private key seed.
pub fn ed448_public_key(seed : Bytes) -> Bytes {
  let (s, _) = e448_secret_expand(seed)
  e448_encode(e448_mul(s, e448_base()))
}

///|
/// Ed448 sign (RFC 8032 §5.2.6, pure Ed448, context C). Returns the
/// 114-byte signature R (57) || S (57). Deterministic.
pub fn ed448_sign_ctx(seed : Bytes, message : Bytes, ctx : Bytes) -> Bytes {
  if ctx.length() > 255 {
    abort("ed448_sign_ctx: context must be at most 255 bytes")
  }
  let (s, prefix) = e448_secret_expand(seed)
  let a_enc = e448_encode(e448_mul(s, e448_base()))
  let dom = e448_dom4(0, ctx)
  let r = e4_le_to_int(shake_256(concat_all([dom, prefix, message]), 114)) %
    ed448_l
  let r_enc = e448_encode(e448_mul(r, e448_base()))
  let k = e4_le_to_int(shake_256(concat_all([dom, r_enc, a_enc, message]), 114)) %
    ed448_l
  let ss = (r + k * s) % ed448_l
  concat_bytes(r_enc, e4_int_to_le(ss, 57))
}

///|
/// Ed448 sign with an empty context (the common case).
pub fn ed448_sign(seed : Bytes, message : Bytes) -> Bytes {
  ed448_sign_ctx(seed, message, b"")
}

///|
/// Ed448 verify (RFC 8032 §5.2.7, cofactor equation
/// [4][S]B = [4]R + [4][k]A). `ctx` must match the signer's context.
pub fn ed448_verify_ctx(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if public_key.length() != 57 || sig.length() != 114 {
    return false
  }
  let r_enc = e4_slice(sig, 0, 57)
  let ss = e4_le_to_int(e4_slice(sig, 57, 57))
  if ss >= ed448_l {
    return false
  }
  let a_pt = match e448_decode(public_key) {
    Some(pt) => pt
    None => return false
  }
  let r_pt = match e448_decode(r_enc) {
    Some(pt) => pt
    None => return false
  }
  let dom = e448_dom4(0, ctx)
  let k = e4_le_to_int(
      shake_256(concat_all([dom, r_enc, public_key, message]), 114),
    ) %
    ed448_l
  // [4][S]B
  let lhs = e448_double(e448_double(e448_mul(ss, e448_base())))
  // [4]R + [4][k]A
  let r4 = e448_double(e448_double(r_pt))
  let ka4 = e448_double(e448_double(e448_mul(k, a_pt)))
  let rhs = e448_add(r4, ka4)
  e448_equal(lhs, rhs)
}

///|
/// Ed448 verify with an empty context.
pub fn ed448_verify(public_key : Bytes, message : Bytes, sig : Bytes) -> Bool {
  ed448_verify_ctx(public_key, message, sig, b"")
}

///|
fn e4_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}
