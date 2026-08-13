// RIPEMD-160 vectors: the official test suite from the RIPEMD-160
// paper (all cross-checked against Python hashlib) plus differential
// inputs.

///|
fn ripemd160_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "RIPEMD-160: empty" {
  let expected = hex_to_bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31")
  assert_true(bytes_equal(expected, ripemd160(b"")))
}

///|
test "RIPEMD-160: a" {
  let expected = hex_to_bytes("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")
  assert_true(bytes_equal(expected, ripemd160(b"a")))
}

///|
test "RIPEMD-160: abc" {
  let expected = hex_to_bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
  assert_true(bytes_equal(expected, ripemd160(b"abc")))
}

///|
test "RIPEMD-160: message digest" {
  let expected = hex_to_bytes("5d0689ef49d2fae572b881b123a85ffa21595f36")
  assert_true(bytes_equal(expected, ripemd160(b"message digest")))
}

///|
test "RIPEMD-160: alphabet" {
  let expected = hex_to_bytes("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
  assert_true(bytes_equal(expected, ripemd160(b"abcdefghijklmnopqrstuvwxyz")))
}

///|
test "RIPEMD-160: 56-char two-block message" {
  let expected = hex_to_bytes("12a053384a9c0c88e405a06c27dcf49ada62eb2b")
  assert_true(
    bytes_equal(
      expected,
      ripemd160(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
  )
}

///|
test "RIPEMD-160: fox" {
  let expected = hex_to_bytes("37f332f68db77bd9d7edd4969571ad671cf9dd3b")
  assert_true(
    bytes_equal(
      expected,
      ripemd160(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "RIPEMD-160: 32B sequence" {
  let expected = hex_to_bytes("e6babb9619d7a81272711fc546a16b211dd93957")
  assert_true(bytes_equal(expected, ripemd160(ripemd160_range_bytes(32))))
}

///|
test "RIPEMD-160: 200B sequence spans four blocks" {
  let expected = hex_to_bytes("c315823ea8fe07a2dd18de4e545255afe3af0738")
  assert_true(bytes_equal(expected, ripemd160(ripemd160_range_bytes(200))))
}

///|
test "RIPEMD-160: one million 'a'" {
  let mut data = b""
  let chunk = Array::make(1000, b'a')
  let chunk_bytes = Bytes::from_array(chunk[:])
  let mut i = 0
  while i < 1000 {
    data = concat_bytes2(data, chunk_bytes)
    i = i + 1
  }
  let expected = hex_to_bytes("52783243c1697bdbe16d37f97f68f08325dc1528")
  assert_true(bytes_equal(expected, ripemd160(data)))
}

///|
/// Local concat helper (1000-byte chunks)
fn concat_bytes2(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(a.length() + b.length(), b'\x00')
  for i in 0..<a.length() {
    out[i] = a[i]
  }
  for i in 0..<b.length() {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out[:])
}
