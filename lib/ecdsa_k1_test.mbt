// ==================== ECDSA secp256k1 (v0.22.0) ====================
// Vectors generated with the Python `ecdsa` library
// (`sign_digest_deterministic`, RFC 6979 + SHA-256; note: the library's
// plain `sign()` adds randomized entropy since 0.19, so it must NOT be
// used for exact vectors) and independently cross-verified with
// `cryptography` (EllipticCurvePublicKey.verify). sk1 = 1 makes the
// public key equal to the generator G, a useful sanity anchor.

///|
let k1_sk1 : Bytes = hex_to_bytes(
  "0000000000000000000000000000000000000000000000000000000000000001",
)

///|
let k1_sk2 : Bytes = hex_to_bytes(
  "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
)

///|
test "secp256k1 public key (sk=1 gives generator G)" {
  let pubk = ecdsa_secp256k1_public_key(k1_sk1)
  assert_true(
    bytes_equal(
      pubk,
      hex_to_bytes(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      ),
    ),
  )
}

///|
test "secp256k1 public key (random sk)" {
  let pubk = ecdsa_secp256k1_public_key(k1_sk2)
  assert_true(
    bytes_equal(
      pubk,
      hex_to_bytes(
        "042c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae64564b95e4fdb6948c0386e189b006a29f686769b011704275e4459822dc3328085",
      ),
    ),
  )
}

///|
test "secp256k1 sign (exact, RFC 6979 SHA-256)" {
  let sig = ecdsa_secp256k1_sign(k1_sk1, b"hello secp256k1")
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "eb5e0535f13f5973a263266ec570795cafe37abb2deed0720fb7f2a9dce1b29cf724b9bc8db02ace4e349e01d45033c0ddb3df645152139f016d8d470bf0942d",
      ),
    ),
  )
  let sig_empty = ecdsa_secp256k1_sign(k1_sk1, b"")
  assert_true(
    bytes_equal(
      sig_empty,
      hex_to_bytes(
        "77c8d336572f6f466055b5f70f433851f8f535f6c4fc71133a6cfd71079d03b70ed9f5eb8aa5b266abac35d416c3207e7a538bf5f37649727d7a9823b1069577",
      ),
    ),
  )
  let sig2 = ecdsa_secp256k1_sign(k1_sk2, b"hello secp256k1")
  assert_true(
    bytes_equal(
      sig2,
      hex_to_bytes(
        "43194ec942732d8eb9e5496935e84863265f2eadb19e26904e8ba6440cb839ac7aabb47d94601b3af6836f9b1d60588fcd70c5c24a91db0ee8c7ce04ad0f6c53",
      ),
    ),
  )
  let sig2_empty = ecdsa_secp256k1_sign(k1_sk2, b"")
  assert_true(
    bytes_equal(
      sig2_empty,
      hex_to_bytes(
        "725f4086bb24a2617205d2594c7dd8644b1e3329b90144ba65cea39cc9bff45dd4aba825b1bebb7fba2b7b03a10bfe1d7bf04a023fcb1a1ad77cb72a70777d27",
      ),
    ),
  )
}

///|
test "secp256k1 verify" {
  let pubk = ecdsa_secp256k1_public_key(k1_sk2)
  let sig = ecdsa_secp256k1_sign(k1_sk2, b"hello secp256k1")
  assert_true(ecdsa_secp256k1_verify(pubk, b"hello secp256k1", sig))
}

///|
test "secp256k1 verify rejects tampered message" {
  let pubk = ecdsa_secp256k1_public_key(k1_sk2)
  let sig = ecdsa_secp256k1_sign(k1_sk2, b"hello secp256k1")
  assert_false(ecdsa_secp256k1_verify(pubk, b"hello secp256k2", sig))
}

///|
test "secp256k1 verify rejects P-256 key (off-curve)" {
  // A P-256 public key is (with overwhelming probability) not on
  // secp256k1; the on-curve check must reject it.
  let p256_pub = ecdsa_p256_public_key(k1_sk2)
  let sig = Bytes::make(64, b'\x01')
  assert_false(ecdsa_secp256k1_verify(p256_pub, b"x", sig))
}

///|
test "secp256k1 verify rejects r/s out of range" {
  let pubk = ecdsa_secp256k1_public_key(k1_sk1)
  let sig = ecdsa_secp256k1_sign(k1_sk1, b"range")
  // r = 0
  let bad_r = Array::make(64, b'\x00')
  for i in 32..<64 {
    bad_r[i] = sig[i]
  }
  assert_false(
    ecdsa_secp256k1_verify(pubk, b"range", Bytes::from_array(bad_r[:])),
  )
  // s = n (invalid: must be < n); n in big-endian
  let n_bytes = hex_to_bytes(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  )
  let bad_s = Array::make(64, b'\x00')
  for i in 0..<32 {
    bad_s[i] = sig[i]
    bad_s[32 + i] = n_bytes[i]
  }
  assert_false(
    ecdsa_secp256k1_verify(pubk, b"range", Bytes::from_array(bad_s[:])),
  )
}
