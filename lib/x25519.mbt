// ==================== X25519 (RFC 7748) ====================
// Elliptic-curve Diffie-Hellman over Curve25519 (Montgomery curve
// y^2 = x^3 + 486662*x^2 + x) using the x-coordinate-only Montgomery
// ladder. Field arithmetic reuses the GF(2^255-19) primitives from
// ed25519.mbt. Verified against the `cryptography` library (X25519).

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
/// X25519 scalar multiplication (RFC 7748): compute the shared secret from a
/// 32-byte clamped `scalar` and a 32-byte `u` coordinate (the peer's public
/// key, or 9 for base-point key generation). Returns the 32-byte result.
pub fn x25519(scalar : Bytes, u : Bytes) -> Bytes {
  if scalar.length() != 32 || u.length() != 32 {
    abort("x25519: scalar and u must be 32 bytes")
  }
  x25519_ladder(x25519_clamp(scalar), u)
}

///|
/// Convenience: derive an X25519 public key from a 32-byte private scalar
/// (base point u = 9).
pub fn x25519_public_key(private_key : Bytes) -> Bytes {
  x25519(private_key, x25519_base)
}
