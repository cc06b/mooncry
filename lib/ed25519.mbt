// ==================== Ed25519 (RFC 8032, ed25519-sha-512) ====================
// Twisted Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2 over GF(p), p = 2^255-19.
// Field arithmetic uses MoonBit core `@bigint` (mod p). Point addition is
// the unified affine formula (a = -1); scalar multiplication is
// double-and-add. Verified against the `cryptography` library (Ed25519).
//
// No RNG: signing is deterministic (RFC 8032), so no randomness is needed.

///|
let ed_p : @bigint.BigInt = @bigint.BigInt::from_string(
  "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
  radix=16,
)

///|
let ed_l : @bigint.BigInt = @bigint.BigInt::from_string(
  "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
  radix=16,
)

///|
let ed_one : @bigint.BigInt = @bigint.BigInt::from_uint64(1UL)

///|
let ed_two : @bigint.BigInt = @bigint.BigInt::from_uint64(2UL)

///|
let ed_zero : @bigint.BigInt = @bigint.BigInt::from_uint64(0UL)

///|
// d = -121665 / 121666 mod p
let ed_d : @bigint.BigInt = {
  let num = ed_p - @bigint.BigInt::from_uint64(121665UL)
  let den = @bigint.BigInt::from_uint64(121666UL)
  let den_inv = den.pow(ed_p - ed_two, modulus=ed_p)
  num * den_inv % ed_p
}

///|
fn ed_mod(x : @bigint.BigInt) -> @bigint.BigInt {
  (x % ed_p + ed_p) % ed_p
}

///|
fn ed_mul(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  a * b % ed_p
}

///|
fn ed_add(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  ed_mod(a + b)
}

///|
fn ed_sub(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  ed_mod(a - b)
}

///|
fn ed_inv(a : @bigint.BigInt) -> @bigint.BigInt {
  a.pow(ed_p - ed_two, modulus=ed_p)
}

///|
/// Little-endian bytes -> BigInt (RFC 8032 encodes scalars/coords LE).
fn ed_le_to_int(bytes : Bytes) -> @bigint.BigInt {
  let n = bytes.length()
  let rev = Array::make(n, b'\x00')
  for i in 0..<n {
    rev[i] = bytes[n - 1 - i]
  }
  @bigint.BigInt::from_octets(Bytes::from_array(rev[:]))
}

///|
/// BigInt -> `len` little-endian bytes.
fn ed_int_to_le(x : @bigint.BigInt, len : Int) -> Bytes {
  let be = x.to_octets(length=len)
  let n = be.length()
  let rev = Array::make(n, b'\x00')
  for i in 0..<n {
    rev[i] = be[n - 1 - i]
  }
  Bytes::from_array(rev[:])
}

///|
/// Square root mod p (p = 2^255-19, p = 5 mod 8). Returns an even root or
/// aborts if `v` is not a quadratic residue.
fn ed_sqrt(v : @bigint.BigInt) -> @bigint.BigInt {
  // candidate = v^((p+3)/8) mod p
  let exp = (ed_p + @bigint.BigInt::from_uint64(3UL)) /
    @bigint.BigInt::from_uint64(8UL)
  let cand = v.pow(exp, modulus=ed_p)
  let sq = ed_mul(cand, cand)
  if sq == v {
    return cand
  }
  let neg_v = ed_p - v
  if sq == neg_v {
    // sqrt(-1) = 2^((p-1)/4) mod p
    let i_exp = (ed_p - ed_one) / @bigint.BigInt::from_uint64(4UL)
    let sqrt_m1 = ed_two.pow(i_exp, modulus=ed_p)
    return ed_mul(cand, sqrt_m1)
  }
  abort("ed_sqrt: not a quadratic residue")
}

///|
priv struct EdPoint {
  x : @bigint.BigInt
  y : @bigint.BigInt
}

///|
/// Unified point addition for a = -1 (handles doubling and identity).
fn ed_point_add(p1 : EdPoint, p2 : EdPoint) -> EdPoint {
  let x1 = p1.x
  let y1 = p1.y
  let x2 = p2.x
  let y2 = p2.y
  let x1x2 = ed_mul(x1, x2)
  let y1y2 = ed_mul(y1, y2)
  let xy = ed_mul(x1x2, y1y2) // x1*x2*y1*y2
  let dxy = ed_mul(ed_d, xy)
  let denom_x = ed_add(ed_one, dxy)
  let denom_y = ed_sub(ed_one, dxy)
  let x3_num = ed_add(ed_mul(x1, y2), ed_mul(y1, x2))
  // a = -1 -> y3_num = y1*y2 - a*x1*x2 = y1*y2 + x1*x2
  let y3_num = ed_add(y1y2, x1x2)
  EdPoint::{
    x: ed_mul(x3_num, ed_inv(denom_x)),
    y: ed_mul(y3_num, ed_inv(denom_y)),
  }
}

///|
/// The identity point (0, 1).
fn ed_identity() -> EdPoint {
  EdPoint::{ x: ed_zero, y: ed_one, }
}

///|
/// Scalar multiplication k*P via MSB-first double-and-add.
fn ed_scalar_mult(k : @bigint.BigInt, p : EdPoint) -> EdPoint {
  let bits = k.to_string(radix=2)
  let mut r = ed_identity()
  for c in bits {
    r = ed_point_add(r, r)
    if c == '1' {
      r = ed_point_add(r, p)
    }
  }
  r
}

///|
/// The base point B: y = 4/5 mod p, x = the even square root of
/// x^2 = (y^2 - 1) / (1 + d*y^2).
let ed_base : EdPoint = {
  let y = ed_mul(
    @bigint.BigInt::from_uint64(4UL),
    ed_inv(@bigint.BigInt::from_uint64(5UL)),
  )
  let y2 = ed_mul(y, y)
  let num = ed_sub(y2, ed_one) // y^2 - 1
  let den = ed_add(ed_one, ed_mul(ed_d, y2)) // 1 + d*y^2
  let x2 = ed_mul(num, ed_inv(den))
  let x = ed_sqrt(x2)
  // pick the even root (x is even for the standard base point)
  let x_even = if x % @bigint.BigInt::from_uint64(2UL) == ed_zero {
    x
  } else {
    ed_p - x
  }
  EdPoint::{ x: x_even, y, }
}

///|
/// Encode a point: y little-endian 32 bytes, top bit = x's least-significant bit.
fn ed_encode(p : EdPoint) -> Bytes {
  let y_bytes = ed_int_to_le(p.y, 32)
  let out = Array::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = y_bytes[i]
  }
  // x parity into the top bit of the last byte (byte 31).
  let x_lsb = p.x % ed_two
  if x_lsb == ed_one {
    out[31] = (out[31].to_int() | 0x80).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// Decode a 32-byte encoding into a point, recovering x. Returns `None`
/// if the encoding is malformed or y/x^2 is not a quadratic residue (a
/// verification path never aborts on bad input).
fn ed_decode(enc : Bytes) -> EdPoint? {
  if enc.length() != 32 {
    return None
  }
  let y_arr = Array::make(32, b'\x00')
  for i in 0..<32 {
    y_arr[i] = enc[i]
  }
  let x_sign = (y_arr[31].to_int() & 0x80) != 0
  y_arr[31] = (y_arr[31].to_int() & 0x7F).to_byte()
  let y = ed_le_to_int(Bytes::from_array(y_arr[:]))
  if y >= ed_p {
    return None
  }
  let y2 = ed_mul(y, y)
  let num = ed_sub(y2, ed_one)
  let den = ed_add(ed_one, ed_mul(ed_d, y2))
  let x2 = ed_mul(num, ed_inv(den))
  // sqrt mod p (p = 5 mod 8); None if x2 is not a QR.
  let exp = (ed_p + @bigint.BigInt::from_uint64(3UL)) /
    @bigint.BigInt::from_uint64(8UL)
  let cand = x2.pow(exp, modulus=ed_p)
  let sq = ed_mul(cand, cand)
  let x = if sq == x2 {
    cand
  } else if sq == ed_p - x2 {
    let i_exp = (ed_p - ed_one) / @bigint.BigInt::from_uint64(4UL)
    let sqrt_m1 = ed_two.pow(i_exp, modulus=ed_p)
    ed_mul(cand, sqrt_m1)
  } else {
    return None
  }
  let x_chosen = if (x % ed_two == ed_one) == x_sign { x } else { ed_p - x }
  Some(EdPoint::{ x: x_chosen, y, })
}

///|
/// Copy a sub-slice as a fresh `Bytes` (since `Bytes` slicing yields a view).
fn ed_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Clamp a 32-byte scalar per RFC 8032: clear the 3 low bits of byte 0,
/// clear bit 255 (top bit of byte 31), set bit 254.
fn ed_clamp(s : Bytes) -> Bytes {
  let out = Array::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = s[i]
  }
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = (out[31].to_int() & 63).to_byte()
  out[31] = (out[31].to_int() | 64).to_byte()
  Bytes::from_array(out[:])
}

// ==================== public API ====================

///|
/// Derive the 32-byte Ed25519 public key from a 32-byte secret seed.
pub fn ed25519_public_key(seed : Bytes) -> Bytes {
  if seed.length() != 32 {
    abort("ed25519_public_key: seed must be 32 bytes")
  }
  let h = sha512(seed)
  let a_bytes = ed_clamp(ed_slice(h, 0, 32))
  let a = ed_le_to_int(a_bytes)
  let a_point = ed_scalar_mult(a, ed_base)
  ed_encode(a_point)
}

///|
/// Sign `message` with the 32-byte secret seed. Deterministic (RFC 8032).
/// Returns the 64-byte signature (R || S).
pub fn ed25519_sign(seed : Bytes, message : Bytes) -> Bytes {
  if seed.length() != 32 {
    abort("ed25519_sign: seed must be 32 bytes")
  }
  let h = sha512(seed)
  let a_bytes = ed_clamp(ed_slice(h, 0, 32))
  let a = ed_le_to_int(a_bytes)
  let prefix = ed_slice(h, 32, 32)
  let pk = ed_encode(ed_scalar_mult(a, ed_base))
  // r = SHA-512(prefix || M) mod L
  let r_hash = sha512(concat_bytes(prefix, message))
  let r = ed_le_to_int(r_hash) % ed_l
  let r_point = ed_scalar_mult(r, ed_base)
  let r_enc = ed_encode(r_point)
  // k = SHA-512(R || A || M) mod L
  let k_input = concat_all([r_enc, pk, message])
  let k = ed_le_to_int(sha512(k_input)) % ed_l
  let s = (r + k * a % ed_l) % ed_l
  let s_enc = ed_int_to_le(s, 32)
  concat_bytes(r_enc, s_enc)
}

///|

///|
/// Verify an Ed25519 signature. Returns true iff valid; returns false on any
/// malformed input (bad R encoding, S out of range, etc.) — never aborts.
pub fn ed25519_verify(public_key : Bytes, message : Bytes, sig : Bytes) -> Bool {
  if public_key.length() != 32 || sig.length() != 64 {
    return false
  }
  let r_enc = ed_slice(sig, 0, 32)
  let s_enc = ed_slice(sig, 32, 32)
  let s = ed_le_to_int(s_enc)
  if s >= ed_l {
    return false
  }
  let a = match ed_decode(public_key) {
    Some(p) => p
    None => return false
  }
  let r = match ed_decode(r_enc) {
    Some(p) => p
    None => return false
  }
  let k = ed_le_to_int(sha512(concat_all([r_enc, public_key, message]))) % ed_l
  // S * B == R + k * A
  let lhs = ed_scalar_mult(s, ed_base)
  let rhs = ed_point_add(r, ed_scalar_mult(k, a))
  bytes_equal(ed_encode(lhs), ed_encode(rhs))
}
