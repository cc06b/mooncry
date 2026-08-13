// TOTP/HOTP SHA-256 and SHA-512 vectors from RFC 6238 Appendix B
// (Table 1). Keys: SHA-256 = ASCII "12345678901234567890" repeated to
// 32 bytes, SHA-512 repeated to 64 bytes (per the RFC test setup).

///|
fn otp_sha2_key256() -> Bytes {
  b"12345678901234567890123456789012"
}

///|
fn otp_sha2_key512() -> Bytes {
  b"1234567890123456789012345678901234567890123456789012345678901234"
}

///|
test "TOTP-SHA256: RFC 6238 Table 1" {
  let times : Array[UInt64] = [
    59UL, 1111111109UL, 1111111111UL, 1234567890UL, 2000000000UL, 20000000000UL,
  ]
  let expect = [
    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
  ]
  for i in 0..<6 {
    assert_true(totp_sha256(otp_sha2_key256(), times[i], 30, 8) == expect[i])
  }
}

///|
test "TOTP-SHA512: RFC 6238 Table 1" {
  let times : Array[UInt64] = [
    59UL, 1111111109UL, 1111111111UL, 1234567890UL, 2000000000UL, 20000000000UL,
  ]
  let expect = [
    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
  ]
  for i in 0..<6 {
    assert_true(totp_sha512(otp_sha2_key512(), times[i], 30, 8) == expect[i])
  }
}

///|
test "HOTP-SHA256/512: TOTP is HOTP over time/step" {
  // t=59, step=30 -> counter=1
  assert_true(hotp_sha256(otp_sha2_key256(), 1UL, 8) == "46119246")
  assert_true(hotp_sha512(otp_sha2_key512(), 1UL, 8) == "90693936")
}

///|
test "TOTP variants: different hashes give different OTPs" {
  assert_true(
    totp_sha256(otp_sha2_key256(), 59UL, 30, 8) !=
    totp_sha512(otp_sha2_key512(), 59UL, 30, 8),
  )
  assert_true(
    totp(otp_sha2_key256(), 59UL, 30, 8) !=
    totp_sha256(otp_sha2_key256(), 59UL, 30, 8),
  )
}
