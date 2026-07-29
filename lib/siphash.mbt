// ==================== SipHash-2-4 (64-bit) ====================
// Aumasson & Bernstein, "SipHash: a fast short-input PRF" (2012).
// 64-bit keyed PRF. Verified against a Python reference implementation
// (cross-checked in-sandbox) for many message lengths.
//
// Output is returned little-endian, matching the reference vectors.

///|
fn siphash_read_u64_le(data : Bytes, offset : Int) -> UInt64 {
  data[offset].to_uint64() |
  (data[offset + 1].to_uint64() << 8) |
  (data[offset + 2].to_uint64() << 16) |
  (data[offset + 3].to_uint64() << 24) |
  (data[offset + 4].to_uint64() << 32) |
  (data[offset + 5].to_uint64() << 40) |
  (data[offset + 6].to_uint64() << 48) |
  (data[offset + 7].to_uint64() << 56)
}

///|
priv struct SipState {
  // using a flat array of 4 UInt64 for easy in-place rotation
  mut v0 : UInt64
  mut v1 : UInt64
  mut v2 : UInt64
  mut v3 : UInt64
}

///|
fn sipround(s : SipState) -> Unit {
  s.v0 = (s.v0 + s.v1) & 0xFFFFFFFFFFFFFFFFUL
  s.v1 = rotl64(s.v1, 13)
  s.v1 = (s.v1 ^ s.v0) & 0xFFFFFFFFFFFFFFFFUL
  s.v0 = rotl64(s.v0, 32)
  s.v2 = (s.v2 + s.v3) & 0xFFFFFFFFFFFFFFFFUL
  s.v3 = rotl64(s.v3, 16)
  s.v3 = (s.v3 ^ s.v2) & 0xFFFFFFFFFFFFFFFFUL
  s.v0 = (s.v0 + s.v3) & 0xFFFFFFFFFFFFFFFFUL
  s.v3 = rotl64(s.v3, 21)
  s.v3 = (s.v3 ^ s.v0) & 0xFFFFFFFFFFFFFFFFUL
  s.v2 = (s.v2 + s.v1) & 0xFFFFFFFFFFFFFFFFUL
  s.v1 = rotl64(s.v1, 17)
  s.v1 = (s.v1 ^ s.v2) & 0xFFFFFFFFFFFFFFFFUL
  s.v2 = rotl64(s.v2, 32)
}

///|
/// SipHash-2-4 (64-bit). `key` must be 16 bytes; returns 8 bytes
/// (little-endian). Wrong key length aborts.
pub fn siphash_2_4(key : Bytes, data : Bytes) -> Bytes {
  if key.length() != 16 {
    abort("siphash_2_4: key length must be 16 bytes")
  }
  let k0 = siphash_read_u64_le(key, 0)
  let k1 = siphash_read_u64_le(key, 8)
  let s = SipState::{
    v0: k0 ^ 0x736f6d6570736575UL,
    v1: k1 ^ 0x646f72616e646f6dUL,
    v2: k0 ^ 0x6c7967656e657261UL,
    v3: k1 ^ 0x7465646279746573UL,
  }
  let len = data.length()
  let num_full = len / 8
  let mut i = 0
  for _ in 0..<num_full {
    let m = siphash_read_u64_le(data, i)
    i = i + 8
    s.v3 = (s.v3 ^ m) & 0xFFFFFFFFFFFFFFFFUL
    sipround(s)
    sipround(s)
    s.v0 = (s.v0 ^ m) & 0xFFFFFFFFFFFFFFFFUL
  }
  // final block: leftover bytes (0..7) then the length byte.
  let rem = len - i
  let mut b = (len & 0xFF).to_uint64() << 56
  for j in 0..<rem {
    b = b | (data[i + j].to_uint64() << (j * 8))
  }
  s.v3 = (s.v3 ^ b) & 0xFFFFFFFFFFFFFFFFUL
  sipround(s)
  sipround(s)
  s.v0 = (s.v0 ^ b) & 0xFFFFFFFFFFFFFFFFUL
  // finalization
  s.v2 = (s.v2 ^ 0xFFUL) & 0xFFFFFFFFFFFFFFFFUL
  for _ in 0..<4 {
    sipround(s)
  }
  let out_val = (s.v0 ^ s.v1 ^ s.v2 ^ s.v3) & 0xFFFFFFFFFFFFFFFFUL
  let out = Array::make(8, b'\x00')
  for j in 0..<8 {
    out[j] = ((out_val >> (j * 8)) & 0xFFUL).to_byte()
  }
  Bytes::from_array(out[:])
}
