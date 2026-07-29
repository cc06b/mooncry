// ==================== SipHash-2-4 (64-bit) ====================
// Vectors cross-checked against a Python reference implementation.

///|
test "SipHash-2-4: 0B input" {
  let expected = hex_to_bytes("310e0edd47db6f72")
  assert_true(
    bytes_equal(
      expected,
      siphash_2_4(
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", b"",
      ),
    ),
  )
}

///|
test "SipHash-2-4: 1B input" {
  let expected = hex_to_bytes("fd67dc93c539f874")
  assert_true(
    bytes_equal(
      expected,
      siphash_2_4(
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", b"\x00",
      ),
    ),
  )
}

///|
test "SipHash-2-4: 8B input" {
  let expected = hex_to_bytes("6224939a79f5f593")
  assert_true(
    bytes_equal(
      expected,
      siphash_2_4(
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", b"\x00\x01\x02\x03\x04\x05\x06\x07",
      ),
    ),
  )
}

///|
test "SipHash-2-4: 15B input" {
  let expected = hex_to_bytes("e545be4961ca29a1")
  assert_true(
    bytes_equal(
      expected,
      siphash_2_4(
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
      ),
    ),
  )
}

///|
test "SipHash-2-4: 63B input" {
  let expected = hex_to_bytes("724506eb4c328a95")
  assert_true(
    bytes_equal(
      expected,
      siphash_2_4(
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        hex_to_bytes(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e",
        ),
      ),
    ),
  )
}
