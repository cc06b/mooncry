// ==================== Test Helpers ====================
fn hex_char_to_int(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

fn hex_to_bytes(hex : String) -> Bytes {
  let len = hex.length() / 2
  let result = Array::make(len, b'\x00')
  for i in 0..<len {
    let hi = hex_char_to_int(hex[i * 2].to_int())
    let lo = hex_char_to_int(hex[i * 2 + 1].to_int())
    result[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(result[:])
}

// ==================== MD5 Tests (RFC 1321 test vectors) ====================
test "MD5: empty string" {
  let expected = hex_to_bytes("d41d8cd98f00b204e9800998ecf8427e")
  let actual = md5(b"")
  assert(bytes_equal(expected, actual))
}

test "MD5: 'a'" {
  let expected = hex_to_bytes("0cc175b9c0f1b6a831c399e269772661")
  let actual = md5(b"a")
  assert(bytes_equal(expected, actual))
}

test "MD5: 'abc'" {
  let expected = hex_to_bytes("900150983cd24fb0d6963f7d28e17f72")
  let actual = md5(b"abc")
  assert(bytes_equal(expected, actual))
}

test "MD5: 'message digest'" {
  let expected = hex_to_bytes("f96b697d7cb7938d525a2f31aaf161d0")
  let actual = md5(b"message digest")
  assert(bytes_equal(expected, actual))
}

test "MD5: alphabet string" {
  let expected = hex_to_bytes("c3fcd3d76192e4007dfb496cca67e13b")
  let actual = md5(b"abcdefghijklmnopqrstuvwxyz")
  assert(bytes_equal(expected, actual))
}

// ==================== SHA-256 Tests (FIPS 180-4) ====================
test "SHA-256: empty string" {
  let expected = hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  let actual = sha256(b"")
  assert(bytes_equal(expected, actual))
}

test "SHA-256: 'abc'" {
  let expected = hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  let actual = sha256(b"abc")
  assert(bytes_equal(expected, actual))
}

test "SHA-256: 56-byte block boundary" {
  let expected = hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
  let actual = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
  assert(bytes_equal(expected, actual))
}

// ==================== SHA-512 Tests (FIPS 180-4) ====================
test "SHA-512: empty string" {
  let expected = hex_to_bytes(
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
  let actual = sha512(b"")
  assert(bytes_equal(expected, actual))
}

test "SHA-512: 'abc'" {
  let expected = hex_to_bytes(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  let actual = sha512(b"abc")
  assert(bytes_equal(expected, actual))
}

// ==================== HMAC-SHA256 Tests (RFC 4231) ====================
test "HMAC-SHA256: RFC 4231 Case 1" {
  let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  let actual = hmac_sha256(key, b"Hi There")
  assert(bytes_equal(expected, actual))
}

test "HMAC-SHA256: RFC 4231 Case 2" {
  let expected = hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  let actual = hmac_sha256(b"Jefe", b"what do ya want for nothing?")
  assert(bytes_equal(expected, actual))
}

// ==================== AES-CBC Tests (NIST SP 800-38A) ====================
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
  assert(bytes_equal(expected, c1))
}

test "AES-128-CBC: round-trip decrypt" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = b"Hello, AES-CBC! This is a test message."
  let ct = aes_encrypt_cbc(pt, key, iv)
  let dec = aes_decrypt_cbc(ct, key, iv)
  assert(bytes_equal(pt, dec))
}

test "AES-256-CBC: round-trip" {
  let key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
  let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let pt = b"AES-256 CBC round trip test message!"
  let ct = aes_encrypt_cbc(pt, key, iv)
  let dec = aes_decrypt_cbc(ct, key, iv)
  assert(bytes_equal(pt, dec))
}

// ==================== AES-GCM Tests (NIST SP 800-38D) ====================
test "AES-128-GCM: empty plaintext" {
  let key = hex_to_bytes("00000000000000000000000000000000")
  let iv = hex_to_bytes("000000000000000000000000")
  let (ct, tag) = aes_gcm_encrypt(b"", key, iv, b"")
  assert(ct.length() == 0)
  let expected_tag = hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a")
  assert(bytes_equal(expected_tag, tag))
}

test "AES-128-GCM: 64-byte plaintext, no AAD" {
  let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let pt = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, b"")
  let expected_ct = hex_to_bytes(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
  let expected_tag = hex_to_bytes("4d5c2af327cd64a62cf35abd2ba6fab4")
  assert(bytes_equal(expected_ct, ct))
  assert(bytes_equal(expected_tag, tag))
}

test "AES-128-GCM: decrypt round-trip with AAD" {
  let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let iv = hex_to_bytes("cafebabefacedbaddecaf888")
  let pt = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
  let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let (ct, tag) = aes_gcm_encrypt(pt, key, iv, aad)
  let (dec, ok) = aes_gcm_decrypt(ct, key, iv, aad, tag)
  assert(ok)
  assert(bytes_equal(pt, dec))
}

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
  assert(!ok)
}

// ==================== ChaCha20 Tests (RFC 8439) ====================
test "ChaCha20: RFC 8439 Section 2.3.2 block function" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let nonce = hex_to_bytes("000000000000004a00000000")
  let counter = 1U
  // We can verify by encrypting a zero block and checking keystream
  let zero_block = Bytes::from_array(Array::make(64, b'\x00')[:])
  let result = chacha20_xor(zero_block, key, nonce, counter)
  let expected = hex_to_bytes(
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed310a5160807d7e731e72fce33f088b749e4414881985c58857a8c79a9719d520c49e84700c5df043e34875a524c41a329541609f0f0e4fbe653deb9377e69a318b73c1aaa8")
  assert(bytes_equal(expected, result))
}

test "ChaCha20: encrypt round-trip" {
  let key = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  let nonce = hex_to_bytes("000000000000000000000001")
  let pt = b"Hello, ChaCha20! This is a test message for encryption."
  let ct = chacha20_xor(pt, key, nonce, 0U)
  let dec = chacha20_xor(ct, key, nonce, 0U)
  assert(bytes_equal(pt, dec))
}

// ==================== Base64 Tests (RFC 4648) ====================
test "Base64: empty string" {
  assert(base64_encode(b"") == "")
  assert(base64_decode("").length() == 0)
}

test "Base64: 'f'" {
  assert(base64_encode(b"f") == "Zg==")
  assert(bytes_equal(b"f", base64_decode("Zg==")))
}

test "Base64: 'fo'" {
  assert(base64_encode(b"fo") == "Zm8=")
  assert(bytes_equal(b"fo", base64_decode("Zm8=")))
}

test "Base64: 'foo'" {
  assert(base64_encode(b"foo") == "Zm9v")
  assert(bytes_equal(b"foo", base64_decode("Zm9v")))
}

test "Base64: 'foob'" {
  assert(base64_encode(b"foob") == "Zm9vYg==")
  assert(bytes_equal(b"foob", base64_decode("Zm9vYg==")))
}

test "Base64: 'fooba'" {
  assert(base64_encode(b"fooba") == "Zm9vYmE=")
  assert(bytes_equal(b"fooba", base64_decode("Zm9vYmE=")))
}

test "Base64: 'foobar'" {
  assert(base64_encode(b"foobar") == "Zm9vYmFy")
  assert(bytes_equal(b"foobar", base64_decode("Zm9vYmFy")))
}

// ==================== Streaming Hash Tests ====================
test "Streaming MD5: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = md5(data)
  let hasher = md5_new()
  md5_update(hasher, b"The quick brown fox ")
  md5_update(hasher, b"jumps over the lazy dog")
  let streamed = md5_finalize(hasher)
  assert(bytes_equal(one_shot, streamed))
}

test "Streaming SHA-256: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = sha256(data)
  let hasher = sha256_new()
  sha256_update(hasher, b"The quick brown fox ")
  sha256_update(hasher, b"jumps over the lazy dog")
  let streamed = sha256_finalize(hasher)
  assert(bytes_equal(one_shot, streamed))
}

test "Streaming SHA-512: matches one-shot" {
  let data = b"The quick brown fox jumps over the lazy dog"
  let one_shot = sha512(data)
  let hasher = sha512_new()
  sha512_update(hasher, b"The quick brown fox ")
  sha512_update(hasher, b"jumps over the lazy dog")
  let streamed = sha512_finalize(hasher)
  assert(bytes_equal(one_shot, streamed))
}

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
  assert(bytes_equal(one_shot, streamed))
}
