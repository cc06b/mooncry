// ==================== X448 (RFC 7748) ====================
// X448 Diffie-Hellman over curve448 (Montgomery form), 448-bit security.
// Montgomery ladder on the u-coordinate per RFC 7748 §5. Verified against
// the official RFC 7748 §5.2/§6.1 test vectors (incl. the single-iteration
// K=u=5 vector).
//
// Note: the ladder here uses a plain (non-constant-time) conditional swap;
// the library's asymmetric operations are not side-channel hardened (see
// the README security notes).

///|
// Barrett reduction constants (v0.48.0, same playbook as ed448.mbt).

///|
/// X448 scalar multiplication (RFC 7748): 56-byte scalar and 56-byte
/// u-coordinate in, 56-byte u-coordinate out (little-endian). The u
/// coordinate is decoded as a little-endian integer mod p (any high bits
/// beyond 448 are impossible for a 56-byte input).
pub fn x448(scalar : Bytes, u : Bytes) -> Bytes {
  if scalar.length() != 56 || u.length() != 56 {
    abort("x448: scalar and u must be 56 bytes")
  }
  x448_ladder_native(scalar, u)
}

///|
/// Derive the X448 public key (u = scalar * base point u=5).
pub fn x448_public_key(private_key : Bytes) -> Bytes {
  let base = Array::make(56, b'\x00')
  base[0] = b'\x05'
  x448(private_key, Bytes::from_array(base[:]))
}
