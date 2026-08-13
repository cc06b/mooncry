// Ed25519ctx / Ed25519ph vectors from RFC 8032 §7.2 / §7.3 (official
// test vectors).

///|
fn ed_ext_seed1() -> Bytes {
  hex_to_bytes(
    "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6",
  )
}

///|
fn ed_ext_pk1() -> Bytes {
  hex_to_bytes(
    "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292",
  )
}

///|
test "Ed25519ctx: public key derivation matches RFC 8032" {
  assert_true(bytes_equal(ed_ext_pk1(), ed25519_public_key(ed_ext_seed1())))
}

///|
test "Ed25519ctx: 'foo' vector (RFC 8032 §7.2)" {
  let msg = hex_to_bytes("f726936d19c800494e3fdaff20b276a8")
  let ctx = hex_to_bytes("666f6f")
  let expected = hex_to_bytes(
    "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
  )
  let sig = ed25519ctx_sign(ed_ext_seed1(), msg, ctx)
  assert_true(bytes_equal(expected, sig))
  assert_true(ed25519ctx_verify(ed_ext_pk1(), msg, sig, ctx))
}

///|
test "Ed25519ctx: 'bar' vector — same message, different context" {
  let msg = hex_to_bytes("f726936d19c800494e3fdaff20b276a8")
  let ctx = hex_to_bytes("626172")
  let expected = hex_to_bytes(
    "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d",
  )
  let sig = ed25519ctx_sign(ed_ext_seed1(), msg, ctx)
  assert_true(bytes_equal(expected, sig))
  assert_true(ed25519ctx_verify(ed_ext_pk1(), msg, sig, ctx))
}

///|
test "Ed25519ctx: 'foo2' vector — different message" {
  let msg = hex_to_bytes("508e9e6882b979fea900f62adceaca35")
  let ctx = hex_to_bytes("666f6f")
  let expected = hex_to_bytes(
    "8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b",
  )
  let sig = ed25519ctx_sign(ed_ext_seed1(), msg, ctx)
  assert_true(bytes_equal(expected, sig))
  assert_true(ed25519ctx_verify(ed_ext_pk1(), msg, sig, ctx))
}

///|
test "Ed25519ctx: 'foo3' vector — second key pair" {
  let seed = hex_to_bytes(
    "ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560",
  )
  let pk = hex_to_bytes(
    "0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772",
  )
  let msg = hex_to_bytes("f726936d19c800494e3fdaff20b276a8")
  let ctx = hex_to_bytes("666f6f")
  let expected = hex_to_bytes(
    "21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f",
  )
  assert_true(bytes_equal(pk, ed25519_public_key(seed)))
  let sig = ed25519ctx_sign(seed, msg, ctx)
  assert_true(bytes_equal(expected, sig))
  assert_true(ed25519ctx_verify(pk, msg, sig, ctx))
}

///|
test "Ed25519ctx: wrong context fails verification" {
  let msg = hex_to_bytes("f726936d19c800494e3fdaff20b276a8")
  let sig = ed25519ctx_sign(ed_ext_seed1(), msg, hex_to_bytes("666f6f"))
  assert_true(
    !ed25519ctx_verify(ed_ext_pk1(), msg, sig, hex_to_bytes("626172")),
  )
}

///|
test "Ed25519ctx: domain separation from plain Ed25519" {
  let msg = hex_to_bytes("f726936d19c800494e3fdaff20b276a8")
  let plain = ed25519_sign(ed_ext_seed1(), msg)
  let ctxed = ed25519ctx_sign(ed_ext_seed1(), msg, hex_to_bytes("666f6f"))
  assert_true(!bytes_equal(plain, ctxed))
  // plain verify must reject the ctx signature
  assert_true(!ed25519_verify(ed_ext_pk1(), msg, ctxed))
}

///|
test "Ed25519ph: 'TEST abc' vector (RFC 8032 §7.3)" {
  let seed = hex_to_bytes(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
  )
  let pk = hex_to_bytes(
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
  )
  let msg = hex_to_bytes("616263")
  let expected = hex_to_bytes(
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
  )
  assert_true(bytes_equal(pk, ed25519_public_key(seed)))
  let sig = ed25519ph_sign(seed, msg, b"")
  assert_true(bytes_equal(expected, sig))
  assert_true(ed25519ph_verify(pk, msg, sig, b""))
}

///|
test "Ed25519ph: hashed-entry API round-trip" {
  let seed = hex_to_bytes(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
  )
  let pk = hex_to_bytes(
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
  )
  let digest = sha512(b"abc")
  let sig = ed25519ph_sign_hashed(seed, digest, b"")
  assert_true(ed25519ph_verify_hashed(pk, digest, sig, b""))
  // must agree with the message-based API
  assert_true(bytes_equal(sig, ed25519ph_sign(seed, b"abc", b"")))
}

///|
test "Ed25519ph: domain separation from plain Ed25519 and ctx" {
  let msg = b"abc"
  let ph = ed25519ph_sign(ed_ext_seed1(), msg, b"")
  let plain = ed25519_sign(ed_ext_seed1(), msg)
  assert_true(!bytes_equal(ph, plain))
  assert_true(!ed25519_verify(ed_ext_pk1(), msg, ph))
}
