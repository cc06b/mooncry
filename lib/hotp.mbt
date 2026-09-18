// ==================== HOTP / TOTP (RFC 4226 / RFC 6238) ====================
// HMAC-SHA1 based one-time passwords. HOTP is event-based (counter); TOTP is
// time-based (unix time / step). Verified against RFC 4226 Appendix D and
// RFC 6238 Appendix B test vectors.

///|
fn u64_be_bytes(v : UInt64) -> Bytes {
  let out = Array::make(8, b'\x00')
  for i in 0..<8 {
    out[i] = ((v >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// 10^n via repeated multiplication.
fn pow10(n : Int) -> Int {
  let mut r = 1
  for _ in 0..<n {
    r = r * 10
  }
  r
}

///|
/// Zero-pad a non-negative integer to `digits` characters (leading zeros).
fn pad_otp(otp : Int, digits : Int) -> String {
  let s = otp.to_string()
  let buf = StringBuilder(size_hint=digits)
  for _ in 0..<(digits - s.length()) {
    buf.write_char('0')
  }
  buf.write_string(s)
  buf.to_string()
}

///|
/// One source of truth for the OTP parameter checks, shared by all six public
/// entries (`hotp`, `hotp_sha256`, `hotp_sha512` and the three `totp`s).
///
/// RFC 4226 §4 requires 6 <= digits <= 8; 1..=9 is accepted because a few
/// deployments use longer OTPs. 9 is the ceiling because `binary` is a 31-bit
/// dynamic and 10^9 is the largest power of ten that still fits an `Int` on a
/// 32-bit target. At digits = 10 `pow10` overflowed instead of failing: 10^10
/// wraps to 1410065408 on wasm — measured, in debug as well as release — while
/// native64 computes the true 10000000000, so one call gave two different OTPs
/// depending on the target.
///
/// `step` is the TOTP time step in seconds and must be positive. Zero raised a
/// bare `divide by zero` with nothing to point at `step`, and a negative step
/// converted to a huge `UInt64` (-30 becomes 18446744073709551586), which
/// quietly made every counter 0 — the same OTP forever, and it verified. v0.85.0.
fn otp_check_digits(digits : Int) -> Unit {
  if digits < 1 || digits > 9 {
    abort("hotp/totp: digits must be in 1..=9 (RFC 4226 recommends 6..=8)")
  }
}

///|
fn otp_check_step(step : Int) -> Unit {
  if step < 1 {
    abort("totp: step must be a positive number of seconds")
  }
}

///|
/// HOTP (RFC 4226): HMAC-SHA1(key, counter as 8-byte BE), dynamic
/// truncation, mod 10^digits. Returns the OTP as a zero-padded `digits`-char
/// string (default 6). `digits` must be in 1..=9.
pub fn hotp(key : Bytes, counter : UInt64, digits : Int) -> String {
  otp_check_digits(digits)
  let mac = hmac_sha1(key, u64_be_bytes(counter))
  let offset = mac[19].to_int() & 0x0f
  let binary = ((mac[offset].to_int() & 0x7f) << 24) |
    (mac[offset + 1].to_int() << 16) |
    (mac[offset + 2].to_int() << 8) |
    mac[offset + 3].to_int()
  let otp = binary % pow10(digits)
  pad_otp(otp, digits)
}

///|
/// TOTP (RFC 6238): HOTP over counter = unix_time / step. `step` default 30s,
/// `digits` default 6 (RFC 6238 test vectors use 8). `step` must be positive
/// and `digits` in 1..=9.
pub fn totp(
  key : Bytes,
  unix_time : UInt64,
  step : Int,
  digits : Int,
) -> String {
  otp_check_step(step)
  let counter = unix_time / step.to_uint64()
  hotp(key, counter, digits)
}
