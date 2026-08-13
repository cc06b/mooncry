// Keccak-256 vectors cross-checked against pycryptodome
// (Crypto.Hash.keccak, digest_bits=256), the reference used by
// Ethereum tooling.

///|
test "Keccak-256: empty" {
  let expected = hex_to_bytes(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  )
  assert_true(bytes_equal(expected, keccak_256(b"")))
}

///|
test "Keccak-256: abc" {
  let expected = hex_to_bytes(
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
  )
  assert_true(bytes_equal(expected, keccak_256(b"abc")))
}

///|
test "Keccak-256: fox" {
  let expected = hex_to_bytes(
    "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
  )
  assert_true(
    bytes_equal(
      expected,
      keccak_256(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "Keccak-256: 32B sequence" {
  let data = Array::make(32, b'\x00')
  for i in 0..<32 {
    data[i] = i.to_byte()
  }
  let expected = hex_to_bytes(
    "8ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd2d",
  )
  assert_true(bytes_equal(expected, keccak_256(Bytes::from_array(data[:]))))
}

///|
test "Keccak-256: differs from SHA3-256 (domain 0x01 vs 0x06)" {
  // Same input must give different digests under the two paddings
  assert_true(!bytes_equal(keccak_256(b"abc"), sha3_256(b"abc")))
}
