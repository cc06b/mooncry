// ==================== Test Helpers ====================

// ==================== MD5 Tests (RFC 1321 test vectors) ====================

///|
test "MD5: empty string" {
  let expected = hex_to_bytes("d41d8cd98f00b204e9800998ecf8427e")
  let actual = md5(b"")
  assert_true(bytes_equal(expected, actual))
}

///|
test "MD5: 'a'" {
  let expected = hex_to_bytes("0cc175b9c0f1b6a831c399e269772661")
  let actual = md5(b"a")
  assert_true(bytes_equal(expected, actual))
}

///|
test "MD5: 'abc'" {
  let expected = hex_to_bytes("900150983cd24fb0d6963f7d28e17f72")
  let actual = md5(b"abc")
  assert_true(bytes_equal(expected, actual))
}

///|
test "MD5: 'message digest'" {
  let expected = hex_to_bytes("f96b697d7cb7938d525a2f31aaf161d0")
  let actual = md5(b"message digest")
  assert_true(bytes_equal(expected, actual))
}

///|
test "MD5: alphabet string" {
  let expected = hex_to_bytes("c3fcd3d76192e4007dfb496cca67e13b")
  let actual = md5(b"abcdefghijklmnopqrstuvwxyz")
  assert_true(bytes_equal(expected, actual))
}

// ==================== SHA-256 Tests (FIPS 180-4) ====================

///|
test "SHA-256: empty string" {
  let expected = hex_to_bytes(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  let actual = sha256(b"")
  assert_true(bytes_equal(expected, actual))
}

///|
test "SHA-256: 'abc'" {
  let expected = hex_to_bytes(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  let actual = sha256(b"abc")
  assert_true(bytes_equal(expected, actual))
}

///|
test "SHA-256: 56-byte block boundary" {
  let expected = hex_to_bytes(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  let actual = sha256(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  assert_true(bytes_equal(expected, actual))
}

// ==================== SHA-512 Tests (FIPS 180-4) ====================

///|
test "SHA-512: empty string" {
  let expected = hex_to_bytes(
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  let actual = sha512(b"")
  assert_true(bytes_equal(expected, actual))
}

///|
test "SHA-512: 'abc'" {
  let expected = hex_to_bytes(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  let actual = sha512(b"abc")
  assert_true(bytes_equal(expected, actual))
}

///|
test "SHA-512: FIPS 180-4 §B.3 — 112-byte message (block boundary)" {
  // 112-byte message: exactly fills one 1024-bit block with the 1-bit + length.
  let msg = hex_to_bytes(
    "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475",
  )
  let expected = hex_to_bytes(
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
  let actual = sha512(msg)
  assert_true(bytes_equal(expected, actual))
}

// ==================== HMAC-SHA256 Tests (RFC 4231) ====================

///|
test "HMAC-SHA256: RFC 4231 Case 1" {
  let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let expected = hex_to_bytes(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  let actual = hmac_sha256(key, b"Hi There")
  assert_true(bytes_equal(expected, actual))
}

///|
test "HMAC-SHA256: RFC 4231 Case 2" {
  let expected = hex_to_bytes(
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  let actual = hmac_sha256(b"Jefe", b"what do ya want for nothing?")
  assert_true(bytes_equal(expected, actual))
}

// ==================== AES-CBC Tests (NIST SP 800-38A) ====================

///|
test "AES-128-CBC: NIST F.2.1 first block" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
  let ct = aes_encrypt_cbc(pt, key, iv)
  // First ciphertext block starts at offset 16 (after IV)
  let c1_arr = Array::make(16, b'\x00')
  for j in 0..<16 {
    c1_arr[j] = ct[16 + j]
  }
  let c1 = Bytes::from_array(c1_arr[:])
  let expected = hex_to_bytes("7649abac8119b246cee98e9b12e9197d")
  assert_true(bytes_equal(expected, c1))
}

///|
test "AES-128-CBC: round-trip decrypt" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = b"Hello, AES-CBC! This is a test message."
  let ct = aes_encrypt_cbc(pt, key, iv)
  let dec = aes_decrypt_cbc(ct, key, iv)
  assert_true(bytes_equal(pt, dec))
}

///|
test "AES-256-CBC: round-trip" {
  let key = hex_to_bytes(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  )
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = b"AES-256 CBC round trip test message!"
  let ct = aes_encrypt_cbc(pt, key, iv)
  let dec = aes_decrypt_cbc(ct, key, iv)
  assert_true(bytes_equal(pt, dec))
}

///|
test "AES-256-CBC: NIST SP 800-38A F.2.5 first block" {
  let key = hex_to_bytes(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  )
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
  let ct = aes_encrypt_cbc(pt, key, iv)
  // First ciphertext block (after the prepended IV) must match NIST F.2.5.
  let c1_arr = Array::make(16, b'\x00')
  for j in 0..<16 {
    c1_arr[j] = ct[16 + j]
  }
  let c1 = Bytes::from_array(c1_arr[:])
  let expected = hex_to_bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
  assert_true(bytes_equal(expected, c1))
}

// ==================== AES-GCM Tests (NIST SP 800-38D) ====================

///|
test "AES-128-GCM: empty plaintext" {
  let key = hex_to_bytes("00000000000000000000000000000000")
  let iv = hex_to_bytes("000000000000000000000000")
  let (ct, tag) = aes_gcm_encrypt(b"", key, iv, b"")
  assert_true(ct.length() == 0)
  let expected_tag = hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a")
  assert_true(bytes_equal(expected_tag, tag))
}

///|
test "AES-128-GCM: 64-byte plaintext, no AAD" {
  let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let pt = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  )
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, b"")
  let expected_ct = hex_to_bytes(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
  )
  let expected_tag = hex_to_bytes("4d5c2af327cd64a62cf35abd2ba6fab4")
  assert_true(bytes_equal(expected_ct, ct))
  assert_true(bytes_equal(expected_tag, tag))
}

///|
test "AES-128-GCM: decrypt round-trip with AAD" {
  let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let pt = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  )
  let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, aad)
  let (dec, ok) = aes_gcm_decrypt(ct, key, iv, aad, tag)
  assert_true(ok)
  assert_true(bytes_equal(pt, dec))
}

///|
test "AES-128-GCM: tag tamper detection" {
  let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let pt = b"test message"
  let aad = b"additional data"
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, aad)
  let bad_tag_arr = Array::make(tag.length(), b'\x00')
  for i in 0..<tag.length() {
    bad_tag_arr[i] = tag[i]
  }
  bad_tag_arr[0] = (bad_tag_arr[0].to_int() ^ 0x01).to_byte()
  let bad_tag = Bytes::from_array(bad_tag_arr[:])
  let (_, ok) = aes_gcm_decrypt(ct, key, iv, aad, bad_tag)
  assert_true(!ok)
}

///|
test "AES-256-GCM: NIST TC13 (empty plaintext, no AAD)" {
  let key = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let iv = hex_to_bytes("000000000000000000000000")
  let (ct, tag) = aes_gcm_encrypt(b"", key, iv, b"")
  assert_true(ct.length() == 0)
  let expected_tag = hex_to_bytes("530f8afbc74536b9a963b4f1c4cb738b")
  assert_true(bytes_equal(expected_tag, tag))
}

///|
test "AES-256-GCM: NIST TC14 (single zero block, no AAD)" {
  let key = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let iv = hex_to_bytes("000000000000000000000000")
  let pt = hex_to_bytes("00000000000000000000000000000000")
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, b"")
  let expected_ct = hex_to_bytes("cea7403d4d606b6e074ec5d3baf39d18")
  let expected_tag = hex_to_bytes("d0d1c8a799996bf0265b98b5d48ab919")
  assert_true(bytes_equal(expected_ct, ct))
  assert_true(bytes_equal(expected_tag, tag))
}

// ==================== ChaCha20 Tests (RFC 8439) ====================

///|
test "ChaCha20: RFC 8439 Section 2.3.2 block function" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  // RFC 8439 §2.3.2 nonce: 00:00:00:09:00:00:00:4a:00:00:00:00, counter = 1.
  let nonce = hex_to_bytes("000000090000004a00000000")
  // Encrypting 64 zero bytes with counter=1 yields the ChaCha20 block keystream.
  let zero_block = Bytes::from_array(Array::make(64, b'\x00')[:])
  let result = chacha20_xor(zero_block, key, nonce, 1U)
  // Canonical RFC 8439 §2.3.2 keystream block (64 bytes).
  let expected = hex_to_bytes(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
  )
  assert_true(bytes_equal(expected, result))
}

///|
test "ChaCha20: multi-block keystream (RFC 8439 §2.3.2 nonce, counters 1..2)" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_bytes("000000090000004a00000000")
  // 128 zero bytes = 2 blocks; counter starts at 1 (block 1 = §2.3.2 vector).
  let zero = Bytes::from_array(Array::make(128, b'\x00')[:])
  let result = chacha20_xor(zero, key, nonce, 1U)
  // Block 1 (counter 1) is the canonical RFC 8439 §2.3.2 vector; block 2
  // (counter 2) cross-checked against PyCryptodome and OpenSSL.
  let expected = hex_to_bytes(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8e721f89255f9c486bf21679c683d4f9c5cf2fa27865526005b06ca374c86af3b",
  )
  assert_true(bytes_equal(expected, result))
}

///|
test "ChaCha20: encrypt round-trip" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_to_bytes("000000000000000000000001")
  let pt = b"Hello, ChaCha20! This is a test message for encryption."
  let ct = chacha20_xor(pt, key, nonce, 0U)
  let dec = chacha20_xor(ct, key, nonce, 0U)
  assert_true(bytes_equal(pt, dec))
}

// ==================== Base64 Tests (RFC 4648) ====================

///|
test "Base64: empty string" {
  assert_true(base64_encode(b"") == "")
  assert_true(base64_decode("").length() == 0)
}

///|
test "Base64: 'f'" {
  assert_true(base64_encode(b"f") == "Zg==")
  assert_true(bytes_equal(b"f", base64_decode("Zg==")))
}

///|
test "Base64: 'fo'" {
  assert_true(base64_encode(b"fo") == "Zm8=")
  assert_true(bytes_equal(b"fo", base64_decode("Zm8=")))
}

///|
test "Base64: 'foo'" {
  assert_true(base64_encode(b"foo") == "Zm9v")
  assert_true(bytes_equal(b"foo", base64_decode("Zm9v")))
}

///|
test "Base64: 'foob'" {
  assert_true(base64_encode(b"foob") == "Zm9vYg==")
  assert_true(bytes_equal(b"foob", base64_decode("Zm9vYg==")))
}

///|
test "Base64: 'fooba'" {
  assert_true(base64_encode(b"fooba") == "Zm9vYmE=")
  assert_true(bytes_equal(b"fooba", base64_decode("Zm9vYmE=")))
}

///|
test "Base64: 'foobar'" {
  assert_true(base64_encode(b"foobar") == "Zm9vYmFy")
  assert_true(bytes_equal(b"foobar", base64_decode("Zm9vYmFy")))
}

// ==================== Streaming Hash Tests ====================

///|
test "Streaming MD5: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = md5(data)
  let hasher = md5_new()
  md5_update(hasher, b"The quick brown fox ")
  md5_update(hasher, b"jumps over the lazy dog")
  let streamed = md5_finalize(hasher)
  assert_true(bytes_equal(one_shot, streamed))
}

///|
test "Streaming SHA-256: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = sha256(data)
  let hasher = sha256_new()
  sha256_update(hasher, b"The quick brown fox ")
  sha256_update(hasher, b"jumps over the lazy dog")
  let streamed = sha256_finalize(hasher)
  assert_true(bytes_equal(one_shot, streamed))
}

///|
test "Streaming SHA-512: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = sha512(data)
  let hasher = sha512_new()
  sha512_update(hasher, b"The quick brown fox ")
  sha512_update(hasher, b"jumps over the lazy dog")
  let streamed = sha512_finalize(hasher)
  assert_true(bytes_equal(one_shot, streamed))
}

///|
test "Streaming SHA-256: multi-block boundary" {
  // Feed data in 1-byte chunks to exercise buffer logic
  let data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
  let one_shot = sha256(data)
  let hasher = sha256_new()
  for i in 0..<data.length() {
    let byte_arr = Array::make(1, b'\x00')
    byte_arr[0] = data[i]
    sha256_update(hasher, Bytes::from_array(byte_arr[:]))
  }
  let streamed = sha256_finalize(hasher)
  assert_true(bytes_equal(one_shot, streamed))
}

// ==================== Large-Data Standard Vectors ====================

///|
/// Build `count` copies of a single byte (used for the million-"a" vectors).
fn repeat_bytes(byte : Byte, count : Int) -> Bytes {
  Bytes::from_array(Array::make(count, byte)[:])
}

///|
test "MD5: RFC 1321 — one million 'a' characters" {
  let msg = repeat_bytes(b'a', 1000000)
  let expected = hex_to_bytes("7707d6ae4e027c70eea2a935c2296f21")
  assert_true(bytes_equal(expected, md5(msg)))
}

///|
test "SHA-256: FIPS 180-4 §B.1 — one million 'a' characters" {
  let msg = repeat_bytes(b'a', 1000000)
  let expected = hex_to_bytes(
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  )
  assert_true(bytes_equal(expected, sha256(msg)))
}

///|
test "SHA-512: FIPS 180-4 §B.3 — one million 'a' characters" {
  let msg = repeat_bytes(b'a', 1000000)
  let expected = hex_to_bytes(
    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
  )
  assert_true(bytes_equal(expected, sha512(msg)))
}
