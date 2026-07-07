// ============================================================================
// MoonBit Crypto — NIST Test Vector Validation
// Validates SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231),
// AES-CBC (NIST SP 800-38A), AES-GCM (NIST SP 800-38D / McGrew-Viega)
// ============================================================================

///|
/// Convert a hex code-unit value (0-9, a-f, A-F) to its 0-15 integer value.
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

///|
/// Convert a hex string to Bytes. Length must be even.
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

///|
/// Print PASS/FAIL for a single named check. Returns true if passed.
fn check(name : String, ok : Bool, expected : String, actual : String) -> Bool {
  if ok {
    println("  [PASS] " + name)
  } else {
    println("  [FAIL] " + name)
    println("    expected: " + expected)
    println("    actual:   " + actual)
  }
  ok
}

///|
fn main {
  println(
    "========================================================================",
  )
  println("  MoonBit Crypto — NIST Test Vector Validation")
  println(
    "========================================================================",
  )

  // ===================== SHA-256 (FIPS 180-4 §B.1) =====================
  println("[SHA-256]")

  let h1 = @lib.sha256(b"")
  let e1 = hex_to_bytes(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  if !check(
      "SHA-256('')  — empty string",
      @lib.bytes_equal(h1, e1),
      @lib.bytes_to_hex(e1),
      @lib.bytes_to_hex(h1),
    ) {
    return
  }

  let h2 = @lib.sha256(b"abc")
  let e2 = hex_to_bytes(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  if !check(
      "SHA-256('abc')",
      @lib.bytes_equal(h2, e2),
      @lib.bytes_to_hex(e2),
      @lib.bytes_to_hex(h2),
    ) {
    return
  }

  let h3 = @lib.sha256(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  let e3 = hex_to_bytes(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  if !check(
      "SHA-256('abcdbcde...nopq')  — 56 bytes",
      @lib.bytes_equal(h3, e3),
      @lib.bytes_to_hex(e3),
      @lib.bytes_to_hex(h3),
    ) {
    return
  }

  // ===================== HMAC-SHA256 (RFC 4231) =====================
  println("[HMAC-SHA256]")

  let k1 = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let hm1 = @lib.hmac_sha256(k1, b"Hi There")
  let hme1 = hex_to_bytes(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  if !check(
      "HMAC-SHA256 RFC 4231 Case 1",
      @lib.bytes_equal(hm1, hme1),
      @lib.bytes_to_hex(hme1),
      @lib.bytes_to_hex(hm1),
    ) {
    return
  }

  let hm2 = @lib.hmac_sha256(b"Jefe", b"what do ya want for nothing?")
  let hme2 = hex_to_bytes(
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  if !check(
      "HMAC-SHA256 RFC 4231 Case 2",
      @lib.bytes_equal(hm2, hme2),
      @lib.bytes_to_hex(hme2),
      @lib.bytes_to_hex(hm2),
    ) {
    return
  }

  // ===================== AES-128-CBC (NIST SP 800-38A F.2.1) =====================
  println("[AES-128-CBC]")

  // NIST F.2.1 vectors (no padding in the spec; our impl uses PKCS7 + IV prepend).
  // Encrypting exactly 16 bytes of plaintext yields IV || c1 || c2 (48 bytes).
  // c1 must equal the NIST first ciphertext block.
  let cbc_key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let cbc_iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let cbc_pt = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
  let cbc_ct = @lib.aes_encrypt_cbc(cbc_pt, cbc_key, cbc_iv)

  let c1_arr = Array::make(16, b'\x00')
  for j in 0..<16 {
    c1_arr[j] = cbc_ct[16 + j]
  }
  let c1 = Bytes::from_array(c1_arr[:])
  let c1_expected = hex_to_bytes("7649abac8119b246cee98e9b12e9197d")
  if !check(
      "AES-128-CBC NIST F.2.1 first ciphertext block",
      @lib.bytes_equal(c1, c1_expected),
      @lib.bytes_to_hex(c1_expected),
      @lib.bytes_to_hex(c1),
    ) {
    return
  }

  let cbc_dec = @lib.aes_decrypt_cbc(cbc_ct, cbc_key, cbc_iv)
  if !check(
      "AES-128-CBC round-trip decrypt",
      @lib.bytes_equal(cbc_dec, cbc_pt),
      @lib.bytes_to_hex(cbc_pt),
      @lib.bytes_to_hex(cbc_dec),
    ) {
    return
  }

  // Multi-block round-trip with non-block-aligned length
  let cbc_pt2 = b"Hello, AES-CBC! This is a 37-byte message."
  let cbc_ct2 = @lib.aes_encrypt_cbc(cbc_pt2, cbc_key, cbc_iv)
  let cbc_dec2 = @lib.aes_decrypt_cbc(cbc_ct2, cbc_key, cbc_iv)
  if !check(
      "AES-128-CBC round-trip (non-aligned length)",
      @lib.bytes_equal(cbc_dec2, cbc_pt2),
      @lib.bytes_to_hex(cbc_pt2),
      @lib.bytes_to_hex(cbc_dec2),
    ) {
    return
  }

  // ===================== AES-128-GCM (NIST SP 800-38D / McGrew-Viega) =====================
  println("[AES-128-GCM]")

  // Test Case 1: empty plaintext, empty AAD
  let gcm_k = hex_to_bytes("00000000000000000000000000000000")
  let gcm_iv = hex_to_bytes("000000000000000000000000")
  let (gcm_c1, gcm_t1) = @lib.aes_gcm_encrypt(b"", gcm_k, gcm_iv, b"")
  let tc1_tag_expected = hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a")
  if !check(
      "AES-GCM Test Case 1 (empty) — ciphertext empty",
      gcm_c1.length() == 0,
      "0 bytes",
      gcm_c1.length().to_string() + " bytes",
    ) {
    return
  }
  if !check(
      "AES-GCM Test Case 1 (empty) — tag",
      @lib.bytes_equal(gcm_t1, tc1_tag_expected),
      @lib.bytes_to_hex(tc1_tag_expected),
      @lib.bytes_to_hex(gcm_t1),
    ) {
    return
  }

  // Test Case 2: single zero block, empty AAD
  let zero_block = hex_to_bytes("00000000000000000000000000000000")
  let (gcm_c2, gcm_t2) = @lib.aes_gcm_encrypt(zero_block, gcm_k, gcm_iv, b"")
  let tc2_c_expected = hex_to_bytes("0388dace60b6a392f328c2b971b2fe78")
  let tc2_t_expected = hex_to_bytes("ab6e47d42cec13bdf53a67b21257bddf")
  if !check(
      "AES-GCM Test Case 2 (zero block) — ciphertext",
      @lib.bytes_equal(gcm_c2, tc2_c_expected),
      @lib.bytes_to_hex(tc2_c_expected),
      @lib.bytes_to_hex(gcm_c2),
    ) {
    return
  }
  if !check(
      "AES-GCM Test Case 2 (zero block) — tag",
      @lib.bytes_equal(gcm_t2, tc2_t_expected),
      @lib.bytes_to_hex(tc2_t_expected),
      @lib.bytes_to_hex(gcm_t2),
    ) {
    return
  }

  // Test Case 3: 64-byte plaintext, empty AAD
  let gcm_k3 = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
  let gcm_iv3 = hex_to_bytes("cafebabefacedbaddecaf888")
  let gcm_p3 = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  )
  let (gcm_c3, gcm_t3) = @lib.aes_gcm_encrypt(gcm_p3, gcm_k3, gcm_iv3, b"")
  let tc3_c_expected = hex_to_bytes(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
  )
  let tc3_t_expected = hex_to_bytes("4d5c2af327cd64a62cf35abd2ba6fab4")
  if !check(
      "AES-GCM Test Case 3 (64B, no AAD) — ciphertext",
      @lib.bytes_equal(gcm_c3, tc3_c_expected),
      @lib.bytes_to_hex(tc3_c_expected),
      @lib.bytes_to_hex(gcm_c3),
    ) {
    return
  }
  if !check(
      "AES-GCM Test Case 3 (64B, no AAD) — tag",
      @lib.bytes_equal(gcm_t3, tc3_t_expected),
      @lib.bytes_to_hex(tc3_t_expected),
      @lib.bytes_to_hex(gcm_t3),
    ) {
    return
  }

  // Test Case 4: 60-byte plaintext, 20-byte AAD (uses truncated plaintext per spec)
  let gcm_p4 = hex_to_bytes(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  )
  let gcm_a4 = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let (gcm_c4, gcm_t4) = @lib.aes_gcm_encrypt(gcm_p4, gcm_k3, gcm_iv3, gcm_a4)
  let tc4_c_expected = hex_to_bytes(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  )
  let tc4_t_expected = hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a47")
  if !check(
      "AES-GCM Test Case 4 (60B + 20B AAD) — ciphertext",
      @lib.bytes_equal(gcm_c4, tc4_c_expected),
      @lib.bytes_to_hex(tc4_c_expected),
      @lib.bytes_to_hex(gcm_c4),
    ) {
    return
  }
  if !check(
      "AES-GCM Test Case 4 (60B + 20B AAD) — tag",
      @lib.bytes_equal(gcm_t4, tc4_t_expected),
      @lib.bytes_to_hex(tc4_t_expected),
      @lib.bytes_to_hex(gcm_t4),
    ) {
    return
  }

  // GCM decrypt round-trip
  let (gcm_dec, gcm_ok) = @lib.aes_gcm_decrypt(
    gcm_c4, gcm_k3, gcm_iv3, gcm_a4, gcm_t4,
  )
  if !check(
      "AES-GCM decrypt round-trip — tag verified", gcm_ok, "true", "false",
    ) {
    return
  }
  if !check(
      "AES-GCM decrypt round-trip — plaintext",
      @lib.bytes_equal(gcm_dec, gcm_p4),
      @lib.bytes_to_hex(gcm_p4),
      @lib.bytes_to_hex(gcm_dec),
    ) {
    return
  }

  // GCM tag tamper detection
  let bad_tag = hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a48")
  let (_, gcm_bad) = @lib.aes_gcm_decrypt(
    gcm_c4, gcm_k3, gcm_iv3, gcm_a4, bad_tag,
  )
  if !check("AES-GCM tag tamper detection", !gcm_bad, "false", "true") {
    return
  }

  // GCM ciphertext tamper detection
  let bad_ct_arr = Array::make(gcm_c4.length(), b'\x00')
  for i in 0..<gcm_c4.length() {
    bad_ct_arr[i] = gcm_c4[i]
  }
  bad_ct_arr[0] = (bad_ct_arr[0].to_int() ^ 0x01).to_byte()
  let bad_ct = Bytes::from_array(bad_ct_arr[:])
  let (_, gcm_bad_ct) = @lib.aes_gcm_decrypt(
    bad_ct, gcm_k3, gcm_iv3, gcm_a4, gcm_t4,
  )
  if !check("AES-GCM ciphertext tamper detection", !gcm_bad_ct, "false", "true") {
    return
  }

  println(
    "========================================================================",
  )
  println("  All NIST test vectors PASSED")
  println(
    "========================================================================",
  )
}
