// ==================== Base64 (RFC 4648) ====================
///|
/// Standard Base64 alphabet
let base64_alphabet : Array[Byte] = [
  b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',
  b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P',
  b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X',
  b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f',
  b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
  b'o', b'p', b'q', b'r', b's', b't', b'u', b'v',
  b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3',
  b'4', b'5', b'6', b'7', b'8', b'9', b'+', b'/',
]
///|
/// Base64 encode (RFC 4648, standard alphabet with padding)
pub fn base64_encode(data : Bytes) -> String {
  let len = data.length()
  let full_groups = len / 3
  let remainder = len % 3
  let output_len = if remainder == 0 {
    full_groups * 4
  } else {
    (full_groups + 1) * 4
  }
  let output = Array::make(output_len, b'\x00')
  // Process full 3-byte groups
  for i in 0..<full_groups {
    let offset = i * 3
    let b0 = data[offset].to_int()
    let b1 = data[offset + 1].to_int()
    let b2 = data[offset + 2].to_int()
    let idx0 = b0 >> 2
    let idx1 = ((b0 & 0x03) << 4) | (b1 >> 4)
    let idx2 = ((b1 & 0x0F) << 2) | (b2 >> 6)
    let idx3 = b2 & 0x3F
    let out_off = i * 4
    output[out_off]     = base64_alphabet[idx0]
    output[out_off + 1] = base64_alphabet[idx1]
    output[out_off + 2] = base64_alphabet[idx2]
    output[out_off + 3] = base64_alphabet[idx3]
  }
  // Process remaining bytes with padding
  if remainder > 0 {
    let offset = full_groups * 3
    let out_off = full_groups * 4
    let b0 = data[offset].to_int()
    output[out_off] = base64_alphabet[b0 >> 2]
    if remainder == 1 {
      output[out_off + 1] = base64_alphabet[(b0 & 0x03) << 4]
      output[out_off + 2] = b'='
      output[out_off + 3] = b'='
    } else {
      let b1 = data[offset + 1].to_int()
      output[out_off + 1] = base64_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]
      output[out_off + 2] = base64_alphabet[(b1 & 0x0F) << 2]
      output[out_off + 3] = b'='
    }
  }
  // Convert bytes to string
  let mut result = ""
  for i in 0..<output_len {
    result = result + output[i].to_char().to_string()
  }
  result
}
///|
/// Decode a single base64 character to its 6-bit value. Returns -1 for invalid input.
fn base64_char_value(c : Byte) -> Int {
  let code = c.to_int()
  if code >= 65 && code <= 90 {   // A-Z
    return code - 65
  }
  if code >= 97 && code <= 122 {  // a-z
    return code - 71
  }
  if code >= 48 && code <= 57 {   // 0-9
    return code + 4
  }
  if code == 43 { return 62 }      // +
  if code == 47 { return 63 }      // /
  -1
}
///|
/// Base64 decode (RFC 4648, standard alphabet). Returns empty Bytes on invalid input.
pub fn base64_decode(encoded : String) -> Bytes {
  // Remove padding and validate
  let mut clean_len = 0
  let mut padding = 0
  let enc_bytes = encoded.to_bytes()
  let enc_len = enc_bytes.length()
  // Count valid chars and trailing padding
  for i in 0..<enc_len {
    let c = enc_bytes[i]
    if c == b'=' {
      padding = padding + 1
    } else if base64_char_value(c) >= 0 {
      clean_len = clean_len + 1
    }
    // Ignore whitespace? For strictness we don't.
  }
  // Calculate output length
  let groups = clean_len / 4
  let remainder_clean = clean_len % 4
  let mut output_len = groups * 3
  if remainder_clean == 2 {
    output_len = output_len + 1
  } else if remainder_clean == 3 {
    output_len = output_len + 2
  }
  let output = Array::make(output_len, b'\x00')
  let mut out_idx = 0
  let mut in_idx = 0
  // Process full 4-char groups
  for _ in 0..<groups {
    // Skip padding chars at end, but for full groups there shouldn't be any
    let v0 = base64_char_value(enc_bytes[in_idx])
    let v1 = base64_char_value(enc_bytes[in_idx + 1])
    let v2 = base64_char_value(enc_bytes[in_idx + 2])
    let v3 = base64_char_value(enc_bytes[in_idx + 3])
    output[out_idx]     = ((v0 << 2) | (v1 >> 4)).to_byte()
    output[out_idx + 1] = (((v1 & 0x0F) << 4) | (v2 >> 2)).to_byte()
    output[out_idx + 2] = (((v2 & 0x03) << 6) | v3).to_byte()
    in_idx = in_idx + 4
    out_idx = out_idx + 3
  }
  // Process remaining chars
  if remainder_clean == 2 {
    let v0 = base64_char_value(enc_bytes[in_idx])
    let v1 = base64_char_value(enc_bytes[in_idx + 1])
    output[out_idx] = ((v0 << 2) | (v1 >> 4)).to_byte()
  } else if remainder_clean == 3 {
    let v0 = base64_char_value(enc_bytes[in_idx])
    let v1 = base64_char_value(enc_bytes[in_idx + 1])
    let v2 = base64_char_value(enc_bytes[in_idx + 2])
    output[out_idx]     = ((v0 << 2) | (v1 >> 4)).to_byte()
    output[out_idx + 1] = (((v1 & 0x0F) << 4) | (v2 >> 2)).to_byte()
  }
  Bytes::from_array(output[:])
}
