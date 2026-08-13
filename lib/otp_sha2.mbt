// ==================== HOTP/TOTP with SHA-256 / SHA-512 ====================
// RFC 6238 (Appendix B) defines TOTP with SHA-256 and SHA-512 in
// addition to SHA-1. These variants reuse the RFC 4226 dynamic
// truncation from hotp.mbt with the stronger HMACs.

///|
/// RFC 4226 dynamic truncation of a MAC (any length) to an OTP of
/// `digits` decimal characters.
fn otp_truncate(mac : Bytes, digits : Int) -> String {
  let offset = mac[mac.length() - 1].to_int() & 0x0f
  let binary = ((mac[offset].to_int() & 0x7f) << 24) |
    (mac[offset + 1].to_int() << 16) |
    (mac[offset + 2].to_int() << 8) |
    mac[offset + 3].to_int()
  let otp = binary % pow10(digits)
  pad_otp(otp, digits)
}

///|
/// HOTP (RFC 4226) with HMAC-SHA256. Returns a zero-padded
/// `digits`-char OTP string.
pub fn hotp_sha256(key : Bytes, counter : UInt64, digits : Int) -> String {
  let mac = hmac_sha256(key, u64_be_bytes(counter))
  otp_truncate(mac, digits)
}

///|
/// HOTP (RFC 4226) with HMAC-SHA512. Returns a zero-padded
/// `digits`-char OTP string.
pub fn hotp_sha512(key : Bytes, counter : UInt64, digits : Int) -> String {
  let mac = hmac_sha512(key, u64_be_bytes(counter))
  otp_truncate(mac, digits)
}

///|
/// TOTP (RFC 6238) with HMAC-SHA256: HOTP-SHA256 over
/// counter = unix_time / step.
pub fn totp_sha256(
  key : Bytes,
  unix_time : UInt64,
  step : Int,
  digits : Int,
) -> String {
  let counter = unix_time / step.to_uint64()
  hotp_sha256(key, counter, digits)
}

///|
/// TOTP (RFC 6238) with HMAC-SHA512: HOTP-SHA512 over
/// counter = unix_time / step.
pub fn totp_sha512(
  key : Bytes,
  unix_time : UInt64,
  step : Int,
  digits : Int,
) -> String {
  let counter = unix_time / step.to_uint64()
  hotp_sha512(key, counter, digits)
}
