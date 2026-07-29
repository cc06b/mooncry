// ==================== Graceful (Result-returning) API variants ====================
// The default one-shot decoders abort on malformed input (fail-fast). These
// `_or` variants return `Result` so callers that prefer graceful handling can
// branch on `Ok`/`Err` without a process abort.

///|
/// Decode a hex string to `Bytes` without aborting. Returns `Err(msg)` on
/// odd length or any non-hex character; `Ok(bytes)` otherwise.
pub fn hex_to_bytes_or(hex : String) -> Result[Bytes, String] {
  let n = hex.length()
  if n % 2 != 0 {
    return Err("hex_to_bytes: odd length")
  }
  let out = Array::make(n / 2, b'\x00')
  let mut idx = 0
  for c in hex.iter() {
    let v = hex_char_to_int(c.to_int())
    if v < 0 {
      return Err("hex_to_bytes: non-hex character")
    }
    let oi = idx / 2
    if idx % 2 == 0 {
      out[oi] = (v << 4).to_byte()
    } else {
      out[oi] = (out[oi].to_int() | v).to_byte()
    }
    idx = idx + 1
  }
  Ok(Bytes::from_array(out[:]))
}

///|
/// Decode base64 without aborting. `base64_decode` returns an empty `Bytes`
/// for malformed input; this distinguishes that from a legitimately empty
/// input and surfaces it as `Err`.
pub fn base64_decode_or(encoded : String) -> Result[Bytes, String] {
  let out = base64_decode(encoded)
  if encoded.length() == 0 {
    return Ok(out)
  }
  if out.length() == 0 {
    return Err("base64_decode: malformed input")
  }
  Ok(out)
}
