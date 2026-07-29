// ==================== CRC32 (IEEE 802.3) + CRC32C (Castagnoli) ====================
// Reflected (LSB-first) CRC, init 0xFFFFFFFF, final XOR 0xFFFFFFFF.
// Verified against Python zlib.crc32 (IEEE) and zlib.crc32 with crc32c.

// Precomputed reflected tables (built once at startup).

///|
let crc32_table : Array[UInt] = (fn() {
  let t = Array::make(256, 0U)
  for i in 0..<256 {
    let mut c = i.reinterpret_as_uint()
    for _ in 0..<8 {
      c = if (c & 1U) != 0U { (c >> 1) ^ 0xEDB88320U } else { c >> 1 }
    }
    t[i] = c
  }
  t
})()

///|
let crc32c_table : Array[UInt] = (fn() {
  let t = Array::make(256, 0U)
  for i in 0..<256 {
    let mut c = i.reinterpret_as_uint()
    for _ in 0..<8 {
      c = if (c & 1U) != 0U { (c >> 1) ^ 0x82F63B78U } else { c >> 1 }
    }
    t[i] = c
  }
  t
})()

///|
fn crc32_with(data : Bytes, table : Array[UInt]) -> UInt {
  let mut crc = 0xFFFFFFFFU
  for i in 0..<data.length() {
    let idx = ((crc ^ data[i].to_uint()) & 0xFFU).reinterpret_as_int()
    crc = (crc >> 8) ^ table[idx]
  }
  crc ^ 0xFFFFFFFFU
}

///|
/// CRC-32 (IEEE 802.3, poly 0xEDB88320 reflected). 4-byte big-endian-ish
/// checksum identical to Python `zlib.crc32`. Returns the 32-bit value as
/// a 4-byte Bytes (big-endian).
pub fn crc32(data : Bytes) -> Bytes {
  let v = crc32_with(data, crc32_table)
  let out = Array::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFFU).to_byte()
  out[1] = ((v >> 16) & 0xFFU).to_byte()
  out[2] = ((v >> 8) & 0xFFU).to_byte()
  out[3] = (v & 0xFFU).to_byte()
  Bytes::from_array(out[:])
}

///|
/// CRC-32C (Castagnoli, poly 0x82F63B78 reflected), used by iSCSI / ext4.
/// Returns the 32-bit value as a 4-byte Bytes (big-endian).
pub fn crc32c(data : Bytes) -> Bytes {
  let v = crc32_with(data, crc32c_table)
  let out = Array::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFFU).to_byte()
  out[1] = ((v >> 16) & 0xFFU).to_byte()
  out[2] = ((v >> 8) & 0xFFU).to_byte()
  out[3] = (v & 0xFFU).to_byte()
  Bytes::from_array(out[:])
}
