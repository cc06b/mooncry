// BLAKE2s (RFC 7693) vectors. Generated with Python hashlib.blake2s,
// anchored on the RFC 7693 sample value for "abc".

///|
fn blake2s_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "BLAKE2s-256: empty" {
  let expected = hex_to_bytes(
    "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
  )
  assert_true(bytes_equal(expected, blake2s(b"", 32)))
}

///|
test "BLAKE2s-256: abc (RFC 7693 sample)" {
  let expected = hex_to_bytes(
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
  )
  assert_true(bytes_equal(expected, blake2s(b"abc", 32)))
}

///|
test "BLAKE2s-256: fox" {
  let expected = hex_to_bytes(
    "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
  )
  assert_true(
    bytes_equal(
      expected,
      blake2s(b"The quick brown fox jumps over the lazy dog", 32),
    ),
  )
}

///|
test "BLAKE2s-256: 896-bit multi-block message" {
  let expected = hex_to_bytes(
    "358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7",
  )
  assert_true(
    bytes_equal(
      expected,
      blake2s(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        32,
      ),
    ),
  )
}

///|
test "BLAKE2s-256: 32B sequence" {
  let expected = hex_to_bytes(
    "05825607d7fdf2d82ef4c3c8c2aea961ad98d60edff7d018983e21204c0d93d1",
  )
  assert_true(bytes_equal(expected, blake2s(blake2s_range_bytes(32), 32)))
}

///|
test "BLAKE2s-256: 200B sequence spans four blocks" {
  let expected = hex_to_bytes(
    "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741",
  )
  assert_true(bytes_equal(expected, blake2s(blake2s_range_bytes(200), 32)))
}

///|
test "BLAKE2s: variable digest sizes (16 / 20 / 1)" {
  assert_true(
    bytes_equal(
      hex_to_bytes("aa4938119b1dc7b87cbad0ffd200d0ae"),
      blake2s(b"abc", 16),
    ),
  )
  assert_true(
    bytes_equal(
      hex_to_bytes("5ae3b99be29b01834c3b508521ede60438f8de17"),
      blake2s(b"abc", 20),
    ),
  )
  assert_true(bytes_equal(hex_to_bytes("0d"), blake2s(b"abc", 1)))
}

///|
test "BLAKE2s: digest size changes the parameter block (not a prefix)" {
  // Unlike truncation, shorter digests use a different IV XOR, so the
  // 16-byte digest must not equal the first 16 bytes of the 32-byte one
  let full = blake2s(b"abc", 32)
  let short = blake2s(b"abc", 16)
  let mut same = true
  for i in 0..<16 {
    if full[i] != short[i] {
      same = false
    }
  }
  assert_true(!same)
}
