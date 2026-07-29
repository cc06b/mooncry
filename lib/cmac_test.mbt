// ==================== AES-CMAC (NIST SP 800-38B) ====================
// Vectors cross-checked against pycryptodome CMAC.

///|
test "AES-128-CMAC: 0B input" {
  let expected = hex_to_bytes("bb1d6929e95937287fa37d129b756746")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        b"", b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
      ),
    ),
  )
}

///|
test "AES-128-CMAC: 16B input" {
  let expected = hex_to_bytes("bfce096180d5daa0396bf08cd06f07a9")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7c\x1f\x7e\x7e\x7e\x7e", b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
      ),
    ),
  )
}

///|
test "AES-128-CMAC: 40B input" {
  let expected = hex_to_bytes("9f7276f728bb4c918a95d7f33d479945")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        hex_to_bytes(
          "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
      ),
    ),
  )
}

///|
test "AES-128-CMAC: 64B input" {
  let expected = hex_to_bytes("95e64c86f13f39a1e8015c2e920159ea")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        hex_to_bytes(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ),
        b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
      ),
    ),
  )
}

///|
test "AES-256-CMAC: 0B input" {
  let expected = hex_to_bytes("028962f61b7bf89efc6b551f4667d983")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        b"", b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
      ),
    ),
  )
}

///|
test "AES-256-CMAC: 16B input" {
  let expected = hex_to_bytes("6e51314f3527c2e1cc8c6aded5dcde3f")
  assert_true(
    bytes_equal(
      expected,
      cmac_aes(
        b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7c\x1f\x7e\x7e\x7e\x7e", b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
      ),
    ),
  )
}
