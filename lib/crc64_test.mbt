// CRC-64 vectors. The "check" values (input "123456789") are the
// public catalogue values from CRC RevEng / crccalc; the remaining
// vectors were generated with a reflected-table Python reference
// anchored on those check values.

///|
test "CRC-64/XZ: empty" {
  assert_true(bytes_equal(hex_to_bytes("0000000000000000"), crc64_xz(b"")))
}

///|
test "CRC-64/XZ: 1B input" {
  assert_true(bytes_equal(hex_to_bytes("330284772e652b05"), crc64_xz(b"a")))
}

///|
test "CRC-64/XZ: 3B input" {
  assert_true(bytes_equal(hex_to_bytes("2cd8094a1a277627"), crc64_xz(b"abc")))
}

///|
test "CRC-64/XZ: check value (123456789)" {
  assert_true(
    bytes_equal(hex_to_bytes("995dc9bbdf1939fa"), crc64_xz(b"123456789")),
  )
}

///|
test "CRC-64/XZ: fox" {
  assert_true(
    bytes_equal(
      hex_to_bytes("5b5eb8c2e54aa1c4"),
      crc64_xz(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "CRC-64/GO-ISO: empty" {
  assert_true(bytes_equal(hex_to_bytes("0000000000000000"), crc64_go_iso(b"")))
}

///|
test "CRC-64/GO-ISO: 1B input" {
  assert_true(bytes_equal(hex_to_bytes("3420000000000000"), crc64_go_iso(b"a")))
}

///|
test "CRC-64/GO-ISO: 3B input" {
  assert_true(
    bytes_equal(hex_to_bytes("3776c42000000000"), crc64_go_iso(b"abc")),
  )
}

///|
test "CRC-64/GO-ISO: check value (123456789)" {
  assert_true(
    bytes_equal(hex_to_bytes("b90956c775a41001"), crc64_go_iso(b"123456789")),
  )
}

///|
test "CRC-64/GO-ISO: fox" {
  assert_true(
    bytes_equal(
      hex_to_bytes("4ef14e19f4c6e28e"),
      crc64_go_iso(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "CRC-64: XZ and GO-ISO disagree on non-trivial input" {
  assert_true(!bytes_equal(crc64_xz(b"abc"), crc64_go_iso(b"abc")))
}
