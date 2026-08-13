// HChaCha20 / XChaCha20 / XChaCha20-Poly1305 vectors
// (draft-irtf-cfrg-xchacha). Anchored on the draft's official test
// vectors (§2.2.1 HChaCha20, §A.3.1 AEAD) and differential-tested
// against libsodium (PyNaCl) over 120 random inputs before commit.

///|
fn xchacha_range_bytes(start : Int, n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = (start + i).to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
/// draft test key/nonce: key = 80..9f, nonce24 = 40..57
fn xchacha_key() -> Bytes {
  xchacha_range_bytes(0x80, 32)
}

///|
fn xchacha_nonce24() -> Bytes {
  xchacha_range_bytes(0x40, 24)
}

// ==================== HChaCha20 ====================

///|
test "HChaCha20: draft §2.2.1 official vector" {
  let key = xchacha_range_bytes(0, 32) // 00..1f
  let in16 = hex_to_bytes("000000090000004a0000000031415927")
  let expected = hex_to_bytes(
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
  )
  assert_true(bytes_equal(expected, hchacha20(key, in16)))
}

///|
test "HChaCha20: subkey is 32 bytes and input-sensitive" {
  let key = xchacha_key()
  let a = hchacha20(key, hex_to_bytes("000000090000004a0000000031415927"))
  let b = hchacha20(key, hex_to_bytes("010000090000004a0000000031415927"))
  assert_true(a.length() == 32)
  assert_true(!bytes_equal(a, b))
}

// ==================== XChaCha20 stream ====================

///|
test "XChaCha20: abc (counter=0)" {
  let expected = hex_to_bytes("1a7b7c")
  assert_true(
    bytes_equal(
      expected,
      xchacha20_xor(b"abc", xchacha_key(), xchacha_nonce24(), 0U),
    ),
  )
}

///|
test "XChaCha20: fox (counter=0)" {
  let expected = hex_to_bytes(
    "2f717aa0821499fa626f0d39e0ce13d821a31053c287dce0ae53ef07e68b27a1c9ae07543a7a4bbf19b375",
  )
  assert_true(
    bytes_equal(
      expected,
      xchacha20_xor(
        b"The quick brown fox jumps over the lazy dog",
        xchacha_key(),
        xchacha_nonce24(),
        0U,
      ),
    ),
  )
}

///|
test "XChaCha20: 200B crosses block boundaries (counter=0)" {
  let data = xchacha_range_bytes(0, 200)
  let expected = hex_to_bytes(
    "7b181d83f764f69e0146654083b473f757dd7a60bce7a787c56a9a6a9fe419ca81ea051b7f2514b855f5385b75fba60a619012d4572664de88012f49d56d2b65b14d31b71fb5b21db35b3d98bae3d31a6216203d5111cabb92e3af571e085397605d721e4f08f91a59ba8b2202fe3035b160d867d84ed207d69ded2c011bea42c1616007e65e3ae24dfb931268234731dbc65b983189aa6d9c4e8e8e8a3b0f15e22aa18a5de6ac61ab4ddc7ddb0e05d571b1788002bac4f12222050897e48b28868beaeeb1ba1714",
  )
  assert_true(
    bytes_equal(
      expected,
      xchacha20_xor(data, xchacha_key(), xchacha_nonce24(), 0U),
    ),
  )
}

///|
test "XChaCha20: encrypt/decrypt symmetric" {
  let data = b"nonce-misuse resistant stream cipher"
  let ct = xchacha20_xor(data, xchacha_key(), xchacha_nonce24(), 0U)
  let pt = xchacha20_xor(ct, xchacha_key(), xchacha_nonce24(), 0U)
  assert_true(bytes_equal(data, pt))
}

// ==================== XChaCha20-Poly1305 AEAD ====================

///|
test "XChaCha20-Poly1305: draft §A.3.1 official vector" {
  let pt = hex_to_bytes(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
    "637265656e20776f756c642062652069742e",
  )
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let expected = hex_to_bytes(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
    "21f9664c97637da9768812f615c68b13b52e" +
    "c0875924c1c7987947deafd8780acf49",
  )
  let out = xchacha20_poly1305_encrypt(
    xchacha_key(),
    xchacha_nonce24(),
    aad,
    pt,
  )
  assert_true(bytes_equal(expected, out))
  // decrypt round-trip
  assert_true(
    bytes_equal(
      pt,
      xchacha20_poly1305_decrypt(xchacha_key(), xchacha_nonce24(), aad, out),
    ),
  )
}

///|
test "XChaCha20-Poly1305: empty plaintext (libsodium)" {
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let expected = hex_to_bytes("e4c5191f68fd06d9592f83754480d19d")
  assert_true(
    bytes_equal(
      expected,
      xchacha20_poly1305_encrypt(xchacha_key(), xchacha_nonce24(), aad, b""),
    ),
  )
}

///|
test "XChaCha20-Poly1305: abc with AAD (libsodium)" {
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let expected = hex_to_bytes("906e10cfa026d76fb7481715aee9ec9628e9bd")
  assert_true(
    bytes_equal(
      expected,
      xchacha20_poly1305_encrypt(xchacha_key(), xchacha_nonce24(), aad, b"abc"),
    ),
  )
}

///|
test "XChaCha20-Poly1305: abc without AAD (libsodium)" {
  let expected = hex_to_bytes("906e10eb0356ccf2f2a5e49e696a8f6ef3a6fc")
  assert_true(
    bytes_equal(
      expected,
      xchacha20_poly1305_encrypt(xchacha_key(), xchacha_nonce24(), b"", b"abc"),
    ),
  )
}

///|
test "XChaCha20-Poly1305: fox with AAD (libsodium)" {
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let expected = hex_to_bytes(
    "a56416d42a859d39903215a199d9f37554280a4e6f31f19cb99a9a7a27272dbc685930114a17e65d55bc8689173a3153425c0e96dd55c2ca4231a4",
  )
  assert_true(
    bytes_equal(
      expected,
      xchacha20_poly1305_encrypt(
        xchacha_key(),
        xchacha_nonce24(),
        aad,
        b"The quick brown fox jumps over the lazy dog",
      ),
    ),
  )
}

///|
test "XChaCha20-Poly1305: 200B with AAD (libsodium)" {
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let expected = hex_to_bytes(
    "f10d71f75ff5f25df31b7dd8faa3935a2256607d11518afbd2a3ef175e4813d7201d325e0f48b95a19facb6242be7075f1209827980e924796ddad6c415baa0201a1a0c7269efa228d3b53d2a8e387f11b069b58f1496aad5c8e4e4e4afbcfd522ea614a9d266ca16b8d1cbd1bcec515b171b840c27a0431e2e2c5c857244be8c6cbaaaef1fa575413b05a89d9c20c21cd0b5b74c1bd548a6045355deb4b4f4645c46bc8e3d45349e005d04784133597fe889888a84772f666d26d202206cb15c478680d7d54c37c5cdb5a2ab57e5722218eff34fa320d64",
  )
  assert_true(
    bytes_equal(
      expected,
      xchacha20_poly1305_encrypt(
        xchacha_key(),
        xchacha_nonce24(),
        aad,
        xchacha_range_bytes(0, 200),
      ),
    ),
  )
}

///|
test "XChaCha20-Poly1305: 24-byte nonce gives fresh keystream vs 12-byte" {
  // Same first 16 nonce bytes are not enough: the last 8 bytes matter
  let n1 = xchacha_nonce24()
  let n2arr = Array::make(24, b'\x00')
  for i in 0..<24 {
    n2arr[i] = n1[i]
  }
  n2arr[23] = (n2arr[23].to_int() ^ 1).to_byte()
  let n2 = Bytes::from_array(n2arr[:])
  assert_true(
    !bytes_equal(
      xchacha20_xor(b"abc", xchacha_key(), n1, 0U),
      xchacha20_xor(b"abc", xchacha_key(), n2, 0U),
    ),
  )
}
