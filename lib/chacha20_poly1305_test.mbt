///|
test "ChaCha20-Poly1305: round-trip" {
  let key = Bytes::make(32, b'')
  let nonce = Bytes::make(12, b'	')
  let aad = b"associated data"
  let pt = b"secret message for aead round-trip test"
  let ct = chacha20_poly1305_encrypt(key, nonce, aad, pt)
  let recovered = chacha20_poly1305_decrypt(key, nonce, aad, ct)
  assert_true(bytes_equal(pt, recovered))
}

///|
test "ChaCha20-Poly1305: pycryptodome vector 1 (with AAD)" {
  let key = hex_to_bytes(
    "425df73d57fb957221b3601cdfae3ea4ce0d249d7ae97b8b7f27348b0dcb6afe",
  )
  let nonce = hex_to_bytes("5f60f5a838797373aca32603")
  let aad = hex_to_bytes("50515253c0c0c0c0")
  let pt = b"Ladies and Gentlemen of the class of 99"
  let expected = hex_to_bytes(
    "91db14665ba957d3ddc18dd09c9119e1aabdad8a1617b14f10b2e026d8c0678ff1302c0fab6e65f4d6e51d8ac64d3c4b6aec89064b05e9",
  )
  assert_true(
    bytes_equal(expected, chacha20_poly1305_encrypt(key, nonce, aad, pt)),
  )
}

///|
test "ChaCha20-Poly1305: pycryptodome vector 2 (empty pt+aad)" {
  let key = hex_to_bytes(
    "696171c9a9110a09a2a3eedd4e21090aae74bbfad5960be28b5d4720b6c9b567",
  )
  let nonce = hex_to_bytes("af7f35592a4d8953a9299d5c")
  let expected = hex_to_bytes("5ae8a08da99650a1d81e75f6558b191d")
  assert_true(
    bytes_equal(expected, chacha20_poly1305_encrypt(key, nonce, b"", b"")),
  )
}

///|
test "ChaCha20-Poly1305: pycryptodome vector 3 (abc+aad)" {
  let key = hex_to_bytes(
    "edaf65c2403986b225fd21a69b0f84dffc79e38059ac18a0186052916000f79a",
  )
  let nonce = hex_to_bytes("1498b4fcd00ae54ef5deba6c")
  let expected = hex_to_bytes("8b39380326995a663bcacbf065aa6bf9e5bfe7")
  assert_true(
    bytes_equal(expected, chacha20_poly1305_encrypt(key, nonce, b"aad", b"abc")),
  )
}
