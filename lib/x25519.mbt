// ==================== X25519 (RFC 7748) ====================
// Elliptic-curve Diffie-Hellman over Curve25519 (Montgomery curve
// y^2 = x^3 + 486662*x^2 + x) using the x-coordinate-only Montgomery
// ladder. Field arithmetic reuses the GF(2^255-19) primitives from
// ed25519.mbt. Verified against the `cryptography` library (X25519).

///|
let x25519_a24 : @bigint.BigInt = @bigint.BigInt::from_uint64(121665UL)

///|
let x25519_base : Bytes = Bytes::from_array([
  b'\x09', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
])

///|
/// Clamp a 32-byte X25519 scalar: clear the 3 low bits of byte 0, clear the
/// top bit of byte 31, set bit 254 (byte 31 |= 0x40).
fn x25519_clamp(s : Bytes) -> Bytes {
  let out = Array::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = s[i]
  }
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = (out[31].to_int() & 127).to_byte()
  out[31] = (out[31].to_int() | 64).to_byte()
  Bytes::from_array(out[:])
}

///|
/// Montgomery ladder step subtraction that never produces a negative
/// intermediate (avoids BigInt state issues under heavy iteration):
/// (a + p) - b is always >= 0 since a in [0,p) and b in [0,p).
fn x_sub(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + ed_p - b) % ed_p
}

///|
/// One Montgomery ladder step. Kept as a separate function so BigInt
/// temporaries are dropped per call rather than accumulating in the caller.
fn x25519_step(
  x1 : @bigint.BigInt,
  x2 : @bigint.BigInt,
  z2 : @bigint.BigInt,
  x3 : @bigint.BigInt,
  z3 : @bigint.BigInt,
) -> (@bigint.BigInt, @bigint.BigInt, @bigint.BigInt, @bigint.BigInt) {
  let a = ed_add(x2, z2)
  let aa = ed_mul(a, a)
  let b = x_sub(x2, z2)
  let bb = ed_mul(b, b)
  let e = x_sub(aa, bb)
  let c = ed_add(x3, z3)
  let d = x_sub(x3, z3)
  let da = ed_mul(d, a)
  let cb = ed_mul(c, b)
  let da_pb = ed_add(da, cb)
  let da_mb = x_sub(da, cb)
  let da_mb_sq = ed_mul(da_mb, da_mb)
  let new_x3 = ed_mul(da_pb, da_pb)
  let new_z3 = ed_mul(x1, da_mb_sq)
  let new_x2 = ed_mul(aa, bb)
  let a24_e = ed_mul(x25519_a24, e)
  let aa_p_a24e = ed_add(aa, a24_e)
  let new_z2 = ed_mul(e, aa_p_a24e)
  (new_x2, new_z2, new_x3, new_z3)
}

///|
/// X25519 scalar multiplication (RFC 7748): compute the shared secret from a
/// 32-byte clamped `scalar` and a 32-byte `u` coordinate (the peer's public
/// key, or 9 for base-point key generation). Returns the 32-byte result.
pub fn x25519(scalar : Bytes, u : Bytes) -> Bytes {
  if scalar.length() != 32 || u.length() != 32 {
    abort("x25519: scalar and u must be 32 bytes")
  }
  let k_bytes = x25519_clamp(scalar)
  let k = ed_le_to_int(k_bytes)
  // u: mask the top bit of byte 31 (RFC 7748 ignores it).
  let u_bytes = Array::make(32, b'\x00')
  for i in 0..<32 {
    u_bytes[i] = u[i]
  }
  u_bytes[31] = (u_bytes[31].to_int() & 127).to_byte()
  let x1 = ed_le_to_int(Bytes::from_array(u_bytes[:]))
  // Montgomery ladder
  let mut x2 = ed_one
  let mut z2 = ed_zero
  let mut x3 = x1
  let mut z3 = ed_one
  let mut swap = 0
  let bits = k.to_string(radix=2)
  for idx in 0..<bits.length() {
    let k_t = if bits[idx] == '1' { 1 } else { 0 }
    swap = swap ^ k_t
    if swap == 1 {
      let t = x2
      x2 = x3
      x3 = t
      let t2 = z2
      z2 = z3
      z3 = t2
    }
    swap = k_t
    let r = x25519_step(x1, x2, z2, x3, z3)
    x2 = r.0
    z2 = r.1
    x3 = r.2
    z3 = r.3
  }
  if swap == 1 {
    let t = x2
    x2 = x3
    x3 = t
    let t2 = z2
    z2 = z3
    z3 = t2
  }
  let z_inv = ed_inv(z2)
  let result = ed_mul(x2, z_inv)
  ed_int_to_le(result, 32)
}

///|
/// Convenience: derive an X25519 public key from a 32-byte private scalar
/// (base point u = 9).
pub fn x25519_public_key(private_key : Bytes) -> Bytes {
  x25519(private_key, x25519_base)
}
