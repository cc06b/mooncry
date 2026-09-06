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
// Extended twisted Edwards coordinates (X:Y:Z:T) with a = -1, per
// Hisil-Wong-Carter-Dawson "Twisted Edwards Curves Revisited"
// (EFD extended-1). One inversion per scalar multiplication instead
// of two per affine addition (v0.42.0 perf: ~85x fewer field ops).

///|
priv struct EdExt {
  x : @bigint.BigInt
  y : @bigint.BigInt
  z : @bigint.BigInt
  t : @bigint.BigInt
}

///|
let ed_2d : @bigint.BigInt = ed_add(ed_d, ed_d)

///|
fn ed_to_ext(p : EdPoint) -> EdExt {
  EdExt::{ x: p.x, y: p.y, z: ed_one, t: ed_mul(p.x, p.y), }
}

///|
fn ed_from_ext(q : EdExt) -> EdPoint {
  let zi = ed_inv(q.z)
  EdPoint::{ x: ed_mul(q.x, zi), y: ed_mul(q.y, zi), }
}

///|
fn ed_ext_identity() -> EdExt {
  EdExt::{ x: ed_zero, y: ed_one, z: ed_one, t: ed_zero, }
}

///|
/// Doubling: dbl-2008-hwcd (4M + 4S + 1*a).
fn ed_ext_double(p : EdExt) -> EdExt {
  let a = ed_mul(p.x, p.x)
  let b = ed_mul(p.y, p.y)
  let zz = ed_mul(p.z, p.z)
  let c = ed_add(zz, zz)
  let d = ed_sub(ed_zero, a) // a-curve = -1: D = -A
  let xy = ed_add(p.x, p.y)
  let e = ed_sub(ed_sub(ed_mul(xy, xy), a), b)
  let g = ed_add(d, b)
  let f = ed_sub(g, c)
  let h = ed_sub(d, b)
  EdExt::{ x: ed_mul(e, f), y: ed_mul(g, h), t: ed_mul(e, h), z: ed_mul(f, g), }
}

///|
/// Addition: add-2008-hwcd-3 (8M).
fn ed_ext_add(p1 : EdExt, p2 : EdExt) -> EdExt {
  let a = ed_mul(ed_sub(p1.y, p1.x), ed_sub(p2.y, p2.x))
  let b = ed_mul(ed_add(p1.y, p1.x), ed_add(p2.y, p2.x))
  let c = ed_mul(ed_mul(p1.t, ed_2d), p2.t)
  let z1z2 = ed_mul(p1.z, p2.z)
  let dd = ed_add(z1z2, z1z2)
  let e = ed_sub(b, a)
  let f = ed_sub(dd, c)
  let g = ed_add(dd, c)
  let h = ed_add(b, a)
  EdExt::{ x: ed_mul(e, f), y: ed_mul(g, h), t: ed_mul(e, h), z: ed_mul(f, g), }
}

///|
/// Fixed 4-bit-window scalar multiplication in extended coordinates.
fn ed_ext_scalar_mult(k : @bigint.BigInt, p : EdExt) -> EdExt {
  let tab = Array::make(16, ed_ext_identity())
  tab[1] = p
  for i in 2..<16 {
    tab[i] = ed_ext_add(tab[i - 1], p)
  }
  let hex = k.to_string(radix=16)
  let mut r = ed_ext_identity()
  for ch in hex {
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    let d = ec_hex_nibble(ch.to_int())
    if d > 0 {
      r = ed_ext_add(r, tab[d])
    }
  }
  r
}

///|
/// Shamir's trick: k1*P1 + k2*P2 with one shared doubling chain.
fn ed_ext_double_scalar_mult(
  k1 : @bigint.BigInt,
  p1 : EdExt,
  k2 : @bigint.BigInt,
  p2 : EdExt,
) -> EdExt {
  let t1 = Array::make(16, ed_ext_identity())
  t1[1] = p1
  for i in 2..<16 {
    t1[i] = ed_ext_add(t1[i - 1], p1)
  }
  let t2 = Array::make(16, ed_ext_identity())
  t2[1] = p2
  for i in 2..<16 {
    t2[i] = ed_ext_add(t2[i - 1], p2)
  }
  let h1 = k1.to_string(radix=16)
  let h2 = k2.to_string(radix=16)
  let n = if h1.length() > h2.length() { h1.length() } else { h2.length() }
  let mut r = ed_ext_identity()
  for i in 0..<n {
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    r = ed_ext_double(r)
    let o1 = n - h1.length()
    let d1 = if i < o1 { 0 } else { ec_hex_nibble(h1[i - o1].to_int()) }
    let o2 = n - h2.length()
    let d2 = if i < o2 { 0 } else { ec_hex_nibble(h2[i - o2].to_int()) }
    if d1 > 0 {
      r = ed_ext_add(r, t1[d1])
    }
    if d2 > 0 {
      r = ed_ext_add(r, t2[d2])
    }
  }
  r
}

///|
/// Scalar multiplication k*P (extended coordinates, 4-bit window).
fn ed_scalar_mult(k : @bigint.BigInt, p : EdPoint) -> EdPoint {
  ed_from_ext(ed_ext_scalar_mult(k, ed_to_ext(p)))
}

///|
/// Double scalar multiplication k1*P1 + k2*P2 (Shamir's trick).
fn ed_double_scalar_mult(
  k1 : @bigint.BigInt,
  p1 : EdPoint,
  k2 : @bigint.BigInt,
  p2 : EdPoint,
) -> EdPoint {
  ed_from_ext(ed_ext_double_scalar_mult(k1, ed_to_ext(p1), k2, ed_to_ext(p2)))
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
  // S * B == R + k * A  <=>  S*B + (L - k)*A == R (one Shamir mult)
  let lhs = ed_double_scalar_mult(s, ed_base, ed_sub(ed_l, k), a)
  bytes_equal(ed_encode(lhs), ed_encode(r))
}
