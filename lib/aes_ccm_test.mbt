// AES-CCM (NIST SP 800-38C / RFC 3610) vectors. Anchored on RFC 3610
// Packet Vector #1; the remaining vectors were generated with
// pycryptodome AES-CCM and round-trip verified.

///|
fn ccm_range_bytes(start : Int, n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = ((start + i) % 256).to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "AES-CCM: RFC 3610 Packet Vector #1" {
  let key = hex_to_bytes("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
  let nonce = hex_to_bytes("00000003020100A0A1A2A3A4A5")
  let aad = hex_to_bytes("0001020304050607")
  let pt = hex_to_bytes("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
  let expected = hex_to_bytes(
    "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384" + "17e8d12cfdf926e0",
  )
  let out = aes_ccm_encrypt(pt, key, nonce, aad, 8)
  assert_true(bytes_equal(expected, out))
  assert_true(bytes_equal(pt, aes_ccm_decrypt(out, key, nonce, aad, 8)))
}

///|
test "AES-CCM: empty plaintext (tag-only output)" {
  let key = ccm_range_bytes(0, 16)
  let nonce = ccm_range_bytes(0, 13)
  let expected = hex_to_bytes("cb1f0dec81b63a4b")
  let out = aes_ccm_encrypt(b"", key, nonce, b"aad", 8)
  assert_true(bytes_equal(expected, out))
  assert_true(bytes_equal(b"", aes_ccm_decrypt(out, key, nonce, b"aad", 8)))
}

///|
test "AES-CCM: empty AAD, 12-byte nonce, 12-byte tag" {
  let key = ccm_range_bytes(0, 16)
  let nonce = ccm_range_bytes(0, 12)
  let expected = hex_to_bytes("5b709f0bb3a0a7d21c" + "f33ebefaca8bdebdf3f443eb")
  let out = aes_ccm_encrypt(b"hello ccm", key, nonce, b"", 12)
  assert_true(bytes_equal(expected, out))
  assert_true(
    bytes_equal(b"hello ccm", aes_ccm_decrypt(out, key, nonce, b"", 12)),
  )
}

///|
test "AES-CCM: 7-byte nonce, 4-byte tag (q=8)" {
  let key = ccm_range_bytes(0, 16)
  let nonce = ccm_range_bytes(0, 7)
  let expected = hex_to_bytes(
    "5715b1ef39830708a405a5ee98eb09b0cf21098c7b865325998ba6e70eb59e95c620e8716d942355" +
    "5ffbc9b4",
  )
  let out = aes_ccm_encrypt(ccm_range_bytes(0, 40), key, nonce, b"hdr", 4)
  assert_true(bytes_equal(expected, out))
  assert_true(
    bytes_equal(
      ccm_range_bytes(0, 40),
      aes_ccm_decrypt(out, key, nonce, b"hdr", 4),
    ),
  )
}

///|
test "AES-CCM: AES-256 key, 16-byte tag, 200B payload" {
  let key = ccm_range_bytes(0, 24)
  let nonce = ccm_range_bytes(0, 13)
  let aad = ccm_range_bytes(0, 8)
  let expected = hex_to_bytes(
    "9b931c7ba3644bca4f27ee4098401211751cdfa708f2ebad52e09e7650497876025f1a8d2c4fe55db5f62be769fa352bcfae0abe0a1334a09c2020d3235e8439ef202a782d304f7afa6c2a9c2e1b3c2a959e71c4e57392788098f9447192db1156aeca61a8d74a1009066e9907827070468253b990841a22b71508b252e9b7f5bed13f58097e482a5e22f7f3f5a8ce9a2c80588847d574b253092010d40ff330a052a9986765a307531405a0c22cf1bd230073de65486f0351c7219cb28ab8053a51d0c54f223061" +
    "9d01f89ee8f11866f61587e63f21cf59",
  )
  let out = aes_ccm_encrypt(ccm_range_bytes(0, 200), key, nonce, aad, 16)
  assert_true(bytes_equal(expected, out))
  assert_true(
    bytes_equal(
      ccm_range_bytes(0, 200),
      aes_ccm_decrypt(out, key, nonce, aad, 16),
    ),
  )
}

///|
test "AES-CCM: AES-256 with 11-byte nonce, 10-byte tag" {
  let key = ccm_range_bytes(0, 32)
  let nonce = ccm_range_bytes(0, 11)
  let aad_arr = Array::make(20, b'\x00')
  for i in 0..<20 {
    aad_arr[i] = b'x'
  }
  let aad = Bytes::from_array(aad_arr[:])
  let expected = hex_to_bytes(
    "73c113655e45b593b7fd1cbe14cad2d44cf59209b34ebc3232ef2369c9f9e27604466b5ca043e6e6d8a5cd2b60c44758e4565b6bfe0aa17744ed163dcea8a6176c764814cd597ecf0527eb12f8546984296d63b063ff24259605873f0848ab4efc0b6ca9" +
    "572554b3c4047b20d513",
  )
  let out = aes_ccm_encrypt(ccm_range_bytes(0, 100), key, nonce, aad, 10)
  assert_true(bytes_equal(expected, out))
  assert_true(
    bytes_equal(
      ccm_range_bytes(0, 100),
      aes_ccm_decrypt(out, key, nonce, aad, 10),
    ),
  )
}

///|
test "AES-CCM: AAD is authenticated (tag changes, CTR layer does not)" {
  let key = hex_to_bytes("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
  let nonce = hex_to_bytes("00000003020100A0A1A2A3A4A5")
  let pt = hex_to_bytes("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
  let out1 = aes_ccm_encrypt(
    pt,
    key,
    nonce,
    hex_to_bytes("0001020304050607"),
    8,
  )
  let out2 = aes_ccm_encrypt(
    pt,
    key,
    nonce,
    hex_to_bytes("0001020304050608"),
    8,
  )
  // same keystream: ciphertext parts identical
  let mut ct_same = true
  for i in 0..<pt.length() {
    if out1[i] != out2[i] {
      ct_same = false
    }
  }
  assert_true(ct_same)
  // ...but the tags must differ
  assert_true(!bytes_equal(out1, out2))
}
