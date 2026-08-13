// PBKDF2-HMAC-SHA1 vectors: the official RFC 6070 test suite.

///|
test "PBKDF2-HMAC-SHA1: RFC 6070, 1 iteration" {
  let expected = hex_to_bytes("0c60c80f961f0e71f3a9b524af6012062fe037a6")
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha1(b"password", b"salt", 1, 20)),
  )
}

///|
test "PBKDF2-HMAC-SHA1: RFC 6070, 2 iterations" {
  let expected = hex_to_bytes("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha1(b"password", b"salt", 2, 20)),
  )
}

///|
test "PBKDF2-HMAC-SHA1: RFC 6070, 4096 iterations" {
  let expected = hex_to_bytes("4b007901b765489abead49d926f721d065a429c1")
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20)),
  )
}

///|
test "PBKDF2-HMAC-SHA1: RFC 6070, long password/salt, dklen 25" {
  let expected = hex_to_bytes(
    "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
  )
  assert_true(
    bytes_equal(
      expected,
      pbkdf2_hmac_sha1(
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
        25,
      ),
    ),
  )
}

///|
test "PBKDF2-HMAC-SHA1: RFC 6070, embedded NUL bytes" {
  let expected = hex_to_bytes("56fa6aa75548099dcc37d7f03425e0c3")
  assert_true(
    bytes_equal(
      expected,
      pbkdf2_hmac_sha1(
        hex_to_bytes("7061737300776f7264"),
        hex_to_bytes("7361006c74"),
        4096,
        16,
      ),
    ),
  )
}

///|
test "PBKDF2-HMAC-SHA1: dklen across block boundary (40 > 20)" {
  let full = pbkdf2_hmac_sha1(b"password", b"salt", 4096, 40)
  let short = pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20)
  // first 20 bytes of the longer derivation equal the shorter one
  let mut same = true
  for i in 0..<20 {
    if full[i] != short[i] {
      same = false
    }
  }
  assert_true(same)
  assert_true(full.length() == 40)
}
