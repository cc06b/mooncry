// ==================== SHA-3 tests (FIPS 202 vectors, cross-checked via Python hashlib) ====================

///|
test "SHA3-256: empty" {
  let expected = hex_to_bytes(
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  )
  assert_true(bytes_equal(expected, sha3_256(b"")))
}

///|
test "SHA3-256: abc" {
  let expected = hex_to_bytes(
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  )
  assert_true(bytes_equal(expected, sha3_256(b"abc")))
}

///|
test "SHA3-256: fox" {
  let expected = hex_to_bytes(
    "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
  )
  assert_true(
    bytes_equal(
      expected,
      sha3_256(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "SHA3-512: empty" {
  let expected = hex_to_bytes(
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
  )
  assert_true(bytes_equal(expected, sha3_512(b"")))
}

///|
test "SHA3-512: abc" {
  let expected = hex_to_bytes(
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
  )
  assert_true(bytes_equal(expected, sha3_512(b"abc")))
}

///|
test "SHA3-512: fox" {
  let expected = hex_to_bytes(
    "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
  )
  assert_true(
    bytes_equal(
      expected,
      sha3_512(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "SHA3-224: abc" {
  let expected = hex_to_bytes(
    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
  )
  assert_true(bytes_equal(expected, sha3_224(b"abc")))
}

///|
test "SHA3-384: abc" {
  let expected = hex_to_bytes(
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
  )
  assert_true(bytes_equal(expected, sha3_384(b"abc")))
}
