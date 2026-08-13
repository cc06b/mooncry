// HMAC-SHA3-224 / HMAC-SHA3-384 vectors. Generated with Python stdlib
// hmac + hashlib.sha3_224/sha3_384 (RFC 2104 over FIPS 202).

///|
fn hmac_sha3_ext_key() -> Bytes {
  b"keykeykey"
}

///|
test "HMAC-SHA3-224: empty message" {
  let expected = hex_to_bytes(
    "ac9b408001014fa534482ca69a311486a204bd78667bc87d3a01c55f",
  )
  assert_true(bytes_equal(expected, hmac_sha3_224(hmac_sha3_ext_key(), b"")))
}

///|
test "HMAC-SHA3-224: abc" {
  let expected = hex_to_bytes(
    "c531a5b2d60924e7ceb2db0c37cbfe6851a5d04251179db237a12e2f",
  )
  assert_true(bytes_equal(expected, hmac_sha3_224(hmac_sha3_ext_key(), b"abc")))
}

///|
test "HMAC-SHA3-224: fox" {
  let expected = hex_to_bytes(
    "82e8d325327efad5ba810f5e8e897227a13b9e14257fc9e5ce95e508",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_224(
        hmac_sha3_ext_key(),
        b"The quick brown fox jumps over the lazy dog",
      ),
    ),
  )
}

///|
test "HMAC-SHA3-224: 200-byte key hashes down (rate 144)" {
  let key = Array::make(200, b'\x00')
  for i in 0..<200 {
    key[i] = i.to_byte()
  }
  let expected = hex_to_bytes(
    "357b4157b1aeecd86e4de2e59e29ccaa4e1d79e8da32e11b57b54e72",
  )
  assert_true(
    bytes_equal(expected, hmac_sha3_224(Bytes::from_array(key[:]), b"abc")),
  )
}

///|
test "HMAC-SHA3-384: empty message" {
  let expected = hex_to_bytes(
    "819279ae0d363f95d86ffbe35dcb86aac70f92517d08dd06d218fcbdefd21534c9f832233ff48dfae8702052f9c6d84a",
  )
  assert_true(bytes_equal(expected, hmac_sha3_384(hmac_sha3_ext_key(), b"")))
}

///|
test "HMAC-SHA3-384: abc" {
  let expected = hex_to_bytes(
    "1fc98e2269f97da8f81389eeaccd0204d5282db3712e2b0d8e2eff813fa936e1a14850b38b301f89bd68da7a7319b7d0",
  )
  assert_true(bytes_equal(expected, hmac_sha3_384(hmac_sha3_ext_key(), b"abc")))
}

///|
test "HMAC-SHA3-384: fox" {
  let expected = hex_to_bytes(
    "49b0da1fd0c664cbc87c22c5c0b97dfdaa06a3c6bfc1f8f6d7e65146e7596cff1507cc29f352108e68eaa92ea68b32a0",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_384(
        hmac_sha3_ext_key(),
        b"The quick brown fox jumps over the lazy dog",
      ),
    ),
  )
}

///|
test "HMAC-SHA3-384: 200-byte key hashes down (rate 104)" {
  let key = Array::make(200, b'\x00')
  for i in 0..<200 {
    key[i] = i.to_byte()
  }
  let expected = hex_to_bytes(
    "f08b650f04b576b3f2749f1a7ea2e2fe603365d435d9e0f3f04d5b4fcb81996cee1fa0225c53c63a01d6003cd939f2a9",
  )
  assert_true(
    bytes_equal(expected, hmac_sha3_384(Bytes::from_array(key[:]), b"abc")),
  )
}

///|
test "HMAC-SHA3: variants differ on the same input" {
  assert_true(
    !bytes_equal(
      hmac_sha3_256(hmac_sha3_ext_key(), b"abc"),
      hmac_sha3_512(hmac_sha3_ext_key(), b"abc"),
    ),
  )
  // same-length members of the family must also disagree
  assert_true(
    !bytes_equal(
      hmac_sha3_224(hmac_sha3_ext_key(), b"abc"),
      hmac_sha3_224(hmac_sha3_ext_key(), b"abd"),
    ),
  )
}
