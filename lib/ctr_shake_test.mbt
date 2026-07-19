// ==================== AES-CTR + SHAKE tests ====================

///|
test "AES-128-CTR: NIST SP 800-38A F.5.1 block 1" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
  let expected = hex_to_bytes("874d6191b620e3261bef6864990db6ce")
  assert_true(bytes_equal(expected, aes_ctr(pt, key, iv)))
}

///|
test "AES-128-CTR: round-trip" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  let pt = Bytes::make(200, b'')
  let ct = aes_ctr(pt, key, iv)
  assert_true(bytes_equal(pt, aes_ctr(ct, key, iv)))
}

///|
test "AES-256-CTR: round-trip" {
  let key = hex_to_bytes(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  )
  let iv = hex_to_bytes("00112233445566778899aabbccddeeff")
  let pt = bench_input(100)
  let ct = aes_ctr(pt, key, iv)
  assert_true(bytes_equal(pt, aes_ctr(ct, key, iv)))
}

///|
test "SHAKE128: empty, 32 bytes" {
  let expected = hex_to_bytes(
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  )
  assert_true(bytes_equal(expected, shake_128(b"", 32)))
}

///|
test "SHAKE128: abc, 32 bytes" {
  let expected = hex_to_bytes(
    "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
  )
  assert_true(bytes_equal(expected, shake_128(b"abc", 32)))
}

///|
test "SHAKE128: fox, 32 bytes" {
  let expected = hex_to_bytes(
    "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
  )
  assert_true(
    bytes_equal(
      expected,
      shake_128(b"The quick brown fox jumps over the lazy dog", 32),
    ),
  )
}

///|
test "SHAKE256: empty, 64 bytes" {
  let expected = hex_to_bytes(
    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
  )
  assert_true(bytes_equal(expected, shake_256(b"", 64)))
}

///|
test "SHAKE256: abc, 64 bytes" {
  let expected = hex_to_bytes(
    "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
  )
  assert_true(bytes_equal(expected, shake_256(b"abc", 64)))
}

///|
test "SHAKE256: fox, 64 bytes" {
  let expected = hex_to_bytes(
    "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442",
  )
  assert_true(
    bytes_equal(
      expected,
      shake_256(b"The quick brown fox jumps over the lazy dog", 64),
    ),
  )
}
