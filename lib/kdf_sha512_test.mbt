// HKDF-SHA512 vectors generated with Python stdlib hmac (the HKDF
// construction itself is anchored on RFC 5869 Test Case 1 via the
// SHA-256 variant). PBKDF2-HMAC-SHA512 vectors from
// hashlib.pbkdf2_hmac.

///|
fn kdf512_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "HKDF-SHA512: RFC 5869 TC1-shaped inputs" {
  let salt = hex_to_bytes("000102030405060708090a0b0c")
  let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")
  let expected = hex_to_bytes(
    "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
  )
  assert_true(bytes_equal(expected, hkdf_sha512(salt, ikm, info, 42)))
}

///|
test "HKDF-SHA512: empty salt defaults to 64 zero bytes" {
  let expected = hex_to_bytes(
    "3d63e6f6213d80921f5da3907f95e1f71cc15e173d0164efc8c6e0fc0deba4348a1ae77e5877ff18576197937c43faaae9a269aac4ffb4fc7e47d3ef3e6f0ac9",
  )
  assert_true(
    bytes_equal(expected, hkdf_sha512(b"", b"input key material", b"info", 64)),
  )
}

///|
test "HKDF-SHA512: longer inputs, 80-byte output (two blocks)" {
  let expected = hex_to_bytes(
    "4efc7470f65e9c4709809613326922262f678ad0501fa2b950cb9ad2083e84f31bee47739bcf16e548d4e901a5b468889db14a20db292a616580f5e4b895636e53224cfc1a8d78d480eee7784991384e",
  )
  assert_true(
    bytes_equal(
      expected,
      hkdf_sha512(
        kdf512_range_bytes(40),
        kdf512_range_bytes(50),
        kdf512_range_bytes(20),
        80,
      ),
    ),
  )
}

///|
test "HKDF-SHA512 vs HKDF-SHA256: different PRFs differ" {
  let a = hkdf_sha512(b"salt", b"ikm", b"info", 32)
  let b = hkdf_sha256(b"salt", b"ikm", b"info", 32)
  assert_true(!bytes_equal(a, b))
}

///|
test "PBKDF2-HMAC-SHA512: password/salt, 1 iteration" {
  let expected = hex_to_bytes(
    "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
  )
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha512(b"password", b"salt", 1, 64)),
  )
}

///|
test "PBKDF2-HMAC-SHA512: 2 iterations" {
  let expected = hex_to_bytes(
    "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
  )
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha512(b"password", b"salt", 2, 64)),
  )
}

///|
test "PBKDF2-HMAC-SHA512: 4096 iterations" {
  let expected = hex_to_bytes(
    "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
  )
  assert_true(
    bytes_equal(expected, pbkdf2_hmac_sha512(b"password", b"salt", 4096, 64)),
  )
}

///|
test "PBKDF2-HMAC-SHA512: dklen across block boundary (100 > 64)" {
  let expected = hex_to_bytes(
    "a8dd6d37d051e8eb7575fdae3e36466a71768cdd400e7c5eb4ba1dd707d7dc277b44c87d80224714a5fbbe9368e4943f4dac76ca0560dffd0d4ac4473dbd9b7d7785cec0cf0a66713097f48681f2885d1888af0dd946ff52d48f24a57c7c095f65115813",
  )
  assert_true(
    bytes_equal(
      expected,
      pbkdf2_hmac_sha512(
        b"passwdpasswdpasswdpasswdpasswd",
        kdf512_range_bytes(16),
        100,
        100,
      ),
    ),
  )
}

///|
/// HMAC-SHA384 / HKDF-SHA384 regression vectors (pycryptodome oracle,
/// RFC 4231 TC6 style long key). v0.41.0.
test "HMAC-SHA384 RFC4231 TC6 + HKDF-SHA384" {
  let key = Bytes::make(131, b'\xaa')
  let msg = b"Test Using Larger Than Block-Size Key - Hash Key First"
  assert_true(
    bytes_equal(
      hmac_sha384(key, msg),
      hex_to_bytes(
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hkdf_sha384(b"salt-value", b"ikm-material", b"info-x", 48),
      hex_to_bytes(
        "835154f13d355160da59a2fa018bbb7c14a73fcb2accb53ecb7dc6c2b9860c983af980c90de215081d2044e5733ac230",
      ),
    ),
  )
}
