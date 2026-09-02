// ==================== X448 tests (RFC 7748 §5.2/§6.1 official vectors) ============

///|
test "X448 RFC 7748 vector 1" {
  let scalar = hex_to_bytes(
    "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
  )
  let u = hex_to_bytes(
    "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
  )
  assert_true(
    bytes_equal(
      x448(scalar, u),
      hex_to_bytes(
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
      ),
    ),
  )
}

///|
test "X448 RFC 7748 vector 2" {
  let scalar = hex_to_bytes(
    "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
  )
  let u = hex_to_bytes(
    "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
  )
  assert_true(
    bytes_equal(
      x448(scalar, u),
      hex_to_bytes(
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
      ),
    ),
  )
}

///|
test "X448 one iteration (K = u = 5)" {
  let k = Array::make(56, b'\x00')
  k[0] = b'\x05'
  let kb = Bytes::from_array(k[:])
  assert_true(
    bytes_equal(
      x448(kb, kb),
      hex_to_bytes(
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
      ),
    ),
  )
}

///|
test "X448 RFC 7748 §6.1 Diffie-Hellman" {
  let alice_priv = hex_to_bytes(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
  )
  let alice_pub_expected = hex_to_bytes(
    "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
  )
  let bob_priv = hex_to_bytes(
    "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
  )
  let bob_pub_expected = hex_to_bytes(
    "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
  )
  let shared_expected = hex_to_bytes(
    "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
  )
  let alice_pub = x448_public_key(alice_priv)
  let bob_pub = x448_public_key(bob_priv)
  assert_true(bytes_equal(alice_pub, alice_pub_expected))
  assert_true(bytes_equal(bob_pub, bob_pub_expected))
  assert_true(bytes_equal(x448(alice_priv, bob_pub), shared_expected))
  assert_true(bytes_equal(x448(bob_priv, alice_pub), shared_expected))
}

///|
test "property: X448 ECDH commutativity" {
  let r = Rng::{ state: 0x448AB001U, }
  for _ in 0..<3 {
    let a = rng_bytes(r, 56)
    let b = rng_bytes(r, 56)
    let pa = x448_public_key(a)
    let pb = x448_public_key(b)
    assert_true(bytes_equal(x448(a, pb), x448(b, pa)))
  }
}
