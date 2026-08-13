// ==================== CRC-64 (reflected, all-ones init/xorout) ====================
// Follows the same structure as crc32.mbt. Verified against the public
// check values of the CRC RevEng catalogue ("123456789" input).

///|
/// CRC-64/XZ reflected table (poly 0x42F0E1EBA9EA3693, reflected)
let crc64_xz_table : Array[UInt64] = (fn() {
  let t = Array::make(256, 0UL)
  for i in 0..<256 {
    let mut c = i.to_uint64()
    for _ in 0..<8 {
      c = if (c & 1UL) != 0UL {
        (c >> 1) ^ 0xC96C5795D7870F42UL
      } else {
        c >> 1
      }
    }
    t[i] = c
  }
  t
})()

///|
/// CRC-64/GO-ISO reflected table (poly 0x000000000000001B, reflected)
let crc64_go_iso_table : Array[UInt64] = (fn() {
  let t = Array::make(256, 0UL)
  for i in 0..<256 {
    let mut c = i.to_uint64()
    for _ in 0..<8 {
      c = if (c & 1UL) != 0UL {
        (c >> 1) ^ 0xD800000000000000UL
      } else {
        c >> 1
      }
    }
    t[i] = c
  }
  t
})()

///|
/// Reflected CRC-64 with init/xorout all ones, driven by `table`
fn crc64_with(data : Bytes, table : Array[UInt64]) -> UInt64 {
  let mut crc = 0xFFFFFFFFFFFFFFFFUL
  for i in 0..<data.length() {
    let idx = ((crc ^ data[i].to_uint64()) & 0xFFUL).to_int()
    crc = (crc >> 8) ^ table[idx]
  }
  crc ^ 0xFFFFFFFFFFFFFFFFUL
}

///|
/// Write a UInt64 into `out` starting at `off` as 8 big-endian bytes
fn crc64_write_be(out : Array[Byte], v : UInt64) -> Unit {
  let mut i = 0
  while i < 8 {
    out[i] = ((v >> (56 - i * 8)) & 0xFFUL).to_byte()
    i = i + 1
  }
}

///|
/// CRC-64/XZ (poly 0x42F0E1EBA9EA3693 reflected, init/xorout all
/// ones), used by xz / lzma. Returns the 64-bit value as an 8-byte
/// Bytes (big-endian).
pub fn crc64_xz(data : Bytes) -> Bytes {
  let out = Array::make(8, b'\x00')
  crc64_write_be(out, crc64_with(data, crc64_xz_table))
  Bytes::from_array(out[:])
}

///|
/// CRC-64/GO-ISO (poly 0x000000000000001B reflected, init/xorout all
/// ones), the 64-bit CRC used by Go's hash/crc64 ISO table. Returns
/// the 64-bit value as an 8-byte Bytes (big-endian).
pub fn crc64_go_iso(data : Bytes) -> Bytes {
  let out = Array::make(8, b'\x00')
  crc64_write_be(out, crc64_with(data, crc64_go_iso_table))
  Bytes::from_array(out[:])
}
