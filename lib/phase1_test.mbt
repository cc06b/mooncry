// ==================== Phase 1 tests: SHA-224, SHA-384, HMAC-SHA512, HKDF, PBKDF2 ====================
// Vectors cross-checked against Python hashlib/hmac (known-correct reference).

///|
test "SHA-224: empty" {
  let expected = hex_to_bytes(
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
  )
  assert_true(bytes_equal(expected, sha224(b"")))
}

///|
test "SHA-224: abc" {
  let expected = hex_to_bytes(
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
  )
  assert_true(bytes_equal(expected, sha224(b"abc")))
}

///|
test "SHA-224: fox" {
  let expected = hex_to_bytes(
    "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
  )
  assert_true(
    bytes_equal(
      expected,
      sha224(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "SHA-384: empty" {
  let expected = hex_to_bytes(
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
  )
  assert_true(bytes_equal(expected, sha384(b"")))
}

///|
test "SHA-384: abc" {
  let expected = hex_to_bytes(
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
  )
  assert_true(bytes_equal(expected, sha384(b"abc")))
}

///|
test "SHA-384: fox" {
  let expected = hex_to_bytes(
    "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
  )
  assert_true(
    bytes_equal(
      expected,
      sha384(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "HMAC-SHA512: empty msg" {
  let expected = hex_to_bytes(
    "84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e",
  )
  assert_true(bytes_equal(expected, hmac_sha512(b"key", b"")))
}

///|
test "HMAC-SHA512: abc" {
  let expected = hex_to_bytes(
    "3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a",
  )
  assert_true(bytes_equal(expected, hmac_sha512(b"key", b"abc")))
}

///|
test "HMAC-SHA512: fox" {
  let expected = hex_to_bytes(
    "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha512(b"key", b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "PBKDF2-SHA256: iter=1" {
  let expected = hex_to_bytes(
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
  )
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)),
  )
}

///|
test "PBKDF2-SHA256: iter=4096" {
  let expected = hex_to_bytes(
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  )
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32)),
  )
}

///|
test "HKDF-SHA256: case1" {
  let expected = hex_to_bytes(
    "f1840c1f388c8fc7a9137c561360962da050de51672f0d7c9fee3ff15c251fec952b1167ce74a43929bf",
  )
  assert_true(
    bytes_equal(
      expected,
      hkdf_sha256(b"salt", b"input key material", b"info", 42),
    ),
  )
}

///|
test "HKDF-SHA256: case2 (empty salt)" {
  let expected = hex_to_bytes(
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
  )
  let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  assert_true(bytes_equal(expected, hkdf_sha256(b"", ikm, b"", 32)))
}

///|
test "HKDF-SHA256: case3" {
  let expected = hex_to_bytes(
    "5e6df5c1b2f6e869243f96db2cbe0dc0a29b4eb7d47e622e55b5ae3ee4bcced67d5a7cb2606f05ed160d32f2c63a52fcf87a357bf771de92a1226bec858cd049042b3863027e33a19dc274b2478fbe53",
  )
  assert_true(bytes_equal(expected, hkdf_sha256(b"a", b"b", b"c", 80)))
}
