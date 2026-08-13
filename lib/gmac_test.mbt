// GMAC vectors generated with pycryptodome AES-GCM (empty plaintext),
// the authentication-only specialization defined by NIST SP 800-38D.

///|
fn gmac_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "GMAC: AES-128, empty AAD" {
  let expected = hex_to_bytes("435b9ba12d75a4be8a977ea3cd011890")
  let tag = gmac(gmac_range_bytes(16), gmac_range_bytes(12), b"")
  assert_true(bytes_equal(expected, tag))
  assert_true(gmac_verify(gmac_range_bytes(16), gmac_range_bytes(12), b"", tag))
}

///|
test "GMAC: AES-128, short AAD" {
  let expected = hex_to_bytes("77eb66dfa91031e3e771c841faf50fd1")
  let tag = gmac(gmac_range_bytes(16), gmac_range_bytes(12), b"header data")
  assert_true(bytes_equal(expected, tag))
  assert_true(
    gmac_verify(gmac_range_bytes(16), gmac_range_bytes(12), b"header data", tag),
  )
}

///|
test "GMAC: AES-256, RFC 8452-style nonce, 64B AAD" {
  let key = gmac_range_bytes(32)
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let aad = gmac_range_bytes(64)
  let expected = hex_to_bytes("e69ce78b231750563d30b1b7fa6f207b")
  assert_true(bytes_equal(expected, gmac(key, iv, aad)))
}

///|
test "GMAC: equals the AES-GCM tag of an empty plaintext" {
  let key = gmac_range_bytes(16)
  let iv = gmac_range_bytes(12)
  let aad = b"authenticated but not encrypted"
  let (_, gcm_tag) = aes_gcm_encrypt(b"", key, iv, aad)
  assert_true(bytes_equal(gcm_tag, gmac(key, iv, aad)))
}

///|
test "GMAC: tag is AAD-sensitive" {
  let key = gmac_range_bytes(16)
  let iv = gmac_range_bytes(12)
  assert_true(!bytes_equal(gmac(key, iv, b"one"), gmac(key, iv, b"two")))
  assert_true(!gmac_verify(key, iv, b"two", gmac(key, iv, b"one")))
}
