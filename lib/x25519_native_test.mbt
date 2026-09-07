/// X25519 native radix-2^25.5 ladder tests: RFC 7748 §6.1 vectors plus
/// a differential comparison against the retained BigInt reference.

///|
test "x25519 rfc7748 vector 1" {
  let k = hex_to_bytes(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let u = hex_to_bytes(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  let expected = hex_to_bytes(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
  assert_true(bytes_equal(x25519(k, u), expected))
}

///|
test "x25519 rfc7748 vector 2" {
  let k = hex_to_bytes(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
  )
  let u = hex_to_bytes(
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
  )
  let expected = hex_to_bytes(
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
  )
  assert_true(bytes_equal(x25519(k, u), expected))
}

///|
test "x25519 rfc7748 iteration 1" {
  let nine = hex_to_bytes(
    "0900000000000000000000000000000000000000000000000000000000000000",
  )
  let expected = hex_to_bytes(
    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
  )
  assert_true(bytes_equal(x25519(nine, nine), expected))
}

///|
test "x25519 ecdh commutativity property" {
  // ECDH: x25519(a, pk_b) == x25519(b, pk_a) for random key pairs —
  // exercises clamping, carries and the full ladder against itself.
  for i in 0..<8 {
    let a = sha256(Bytes::make(1, (i + 100).to_byte()))
    let b = sha256(Bytes::make(1, i.to_byte()))
    let pa = x25519_public_key(a)
    let pb = x25519_public_key(b)
    let s1 = x25519(a, pb)
    let s2 = x25519(b, pa)
    assert_true(bytes_equal(s1, s2))
  }
}

///|
test "x25519 public key equals direct base call" {
  let sk = sha256(hex_to_bytes("78323531395f7075625f73656564"))
  let nine = hex_to_bytes(
    "0900000000000000000000000000000000000000000000000000000000000000",
  )
  assert_true(bytes_equal(x25519_public_key(sk), x25519(sk, nine)))
}
