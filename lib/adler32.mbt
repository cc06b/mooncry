///|
/// Adler-32 checksum (RFC 1950 / zlib): rolling sums A = 1 + sum(bytes)
/// mod 65521 and B = sum of A values mod 65521, combined as
/// (B << 16) | A. Returned as 4 bytes big-endian.

///|
/// Largest prime smaller than 2^16, the Adler-32 modulus
let adler32_mod : UInt = 65521U

///|
/// Compute Adler-32 (RFC 1950). Returns the 32-bit value as a 4-byte
/// Bytes (big-endian), identical to Python `zlib.adler32`.
pub fn adler32(data : Bytes) -> Bytes {
  let mut a = 1U
  let mut b = 0U
  for i in 0..<data.length() {
    a = (a + data[i].to_uint()) % adler32_mod
    b = (b + a) % adler32_mod
  }
  let v = (b << 16) | a
  let out = Array::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFFU).to_byte()
  out[1] = ((v >> 16) & 0xFFU).to_byte()
  out[2] = ((v >> 8) & 0xFFU).to_byte()
  out[3] = (v & 0xFFU).to_byte()
  Bytes::from_array(out[:])
}
