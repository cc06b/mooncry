// Adler-32 vectors cross-checked against Python zlib.adler32 and the
// well-known "Wikipedia" check value (0x11E60398).

///|
fn adler32_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "Adler-32: empty input is 1" {
  assert_true(bytes_equal(hex_to_bytes("00000001"), adler32(b"")))
}

///|
test "Adler-32: 1B input" {
  assert_true(bytes_equal(hex_to_bytes("00620062"), adler32(b"a")))
}

///|
test "Adler-32: abc" {
  assert_true(bytes_equal(hex_to_bytes("024d0127"), adler32(b"abc")))
}

///|
test "Adler-32: fox" {
  assert_true(
    bytes_equal(
      hex_to_bytes("5bdc0fda"),
      adler32(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "Adler-32: 200B sequence (exercises the mod-65521 wrap)" {
  assert_true(
    bytes_equal(hex_to_bytes("5a284dbd"), adler32(adler32_range_bytes(200))),
  )
}

///|
test "Adler-32: Wikipedia check value" {
  assert_true(bytes_equal(hex_to_bytes("11e60398"), adler32(b"Wikipedia")))
}
