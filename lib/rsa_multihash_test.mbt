// ==================== RSA multi-hash signature API (v0.22.0) ====================
// Vectors cross-checked against pycryptodome (pkcs1_15 + pss) on the same
// 1024-bit test key as rsa_test.mbt. Notes:
// - pycryptodome pss.verify must be given an explicit salt_bytes when the
//   salt length differs from hLen (its auto-detect rejects longer salts);
// - exact PSS vectors use the fixed salt 000102...1f injected via the
//   library's rand_func hook;
// - the plain (non-`_with`) functions stay fixed to SHA-256 (covered by
//   rsa_test.mbt).

///|
let mh_msg : Bytes = b"rsa multi-hash test message"

///|
let mh_salt32 : Bytes = hex_to_bytes(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)

///|
test "RSA PKCS1-v1.5 sign_with (SHA-1, exact)" {
  let sig = rsa_pkcs1_v15_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, rsa_hash_sha1,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "2214fc0edde816d69807f3358e63ed60cbb42fa8fa7590aa38964167b22135c2d7b7e12c664db401e000c2d2c34c68ee8d02359661b87544f398d5c22d9cdb21528d3e2d41937211e40171ce06d7121f83ebf007d7974e1339894b0fabc331840e55632b62926786e805cf6cbc5e48654aa045c88f34c3d4d5301489df01889b",
      ),
    ),
  )
  assert_true(
    rsa_pkcs1_v15_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, rsa_hash_sha1,
    ),
  )
}

///|
test "RSA PKCS1-v1.5 sign_with (SHA-384, exact)" {
  let sig = rsa_pkcs1_v15_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, rsa_hash_sha384,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "af69806258c24a50eae0156c8880167e674fcfa5ff4412f5558725968638fbb1e30e5abd7f80747d0d4de7379c63fb5dd5fad995cc5422e24df0ffb93a0e61e5587caa6d07999b855071c073308c65628c642016557942094422c557bc2e67264d611c8320326f358db4402f073362b540570cc1014141c1e7ffcc6cb8803a47",
      ),
    ),
  )
  assert_true(
    rsa_pkcs1_v15_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, rsa_hash_sha384,
    ),
  )
}

///|
test "RSA PKCS1-v1.5 sign_with (SHA-512, exact)" {
  let sig = rsa_pkcs1_v15_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, rsa_hash_sha512,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "39a44eb0c0b3775f723d147283852808718c137040b346d0d3fc754e0638d81de37fb4f021498a979581ba369e91caf546e61e40b53029f30aaf36a856edeec9e2a90fd4923887d1f7555850e291b701abcc2cc4ed8521fc8edf70c9c92227903554ae3502c639ce33f6c745c3bef9aa2957222c7f4c93b08e98e4ed26d70cf9",
      ),
    ),
  )
  assert_true(
    rsa_pkcs1_v15_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, rsa_hash_sha512,
    ),
  )
}

///|
test "RSA PKCS1-v1.5 verify_with rejects wrong-hash verification" {
  let sig = rsa_pkcs1_v15_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, rsa_hash_sha1,
  )
  assert_false(
    rsa_pkcs1_v15_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, rsa_hash_sha256,
    ),
  )
}

///|
test "RSA PSS sign_with (SHA-1, exact, salt 32)" {
  let sig = rsa_pss_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, mh_salt32, rsa_hash_sha1,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "5b841196324461b0af9404b285e17842ff9b598fb4905d8a6e46318cb273fae03f5bdcb6028e9146496284039b0b94cb579e296b0387f8d2f2d6a2ca10205b352354778118084026e73abc71929118691b8a54c1b94e36ebfcb55040ec59f210c65610f0c28499e727b6413829a97630481add4b388ce706662cce3c812d2afa",
      ),
    ),
  )
  assert_true(
    rsa_pss_verify_with(mh_msg, sig, rsa_test_n, rsa_test_e, 32, rsa_hash_sha1),
  )
}

///|
test "RSA PSS sign_with (SHA-384, exact, salt 32)" {
  let sig = rsa_pss_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, mh_salt32, rsa_hash_sha384,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "3f8ee89477a39ec05fd96d7b76dc500036e613fb6a81e2911801cd00ee36a8272632eb972443ed7db36a447c032a84669737fa37830558da403d8f8bd246d666e86daa7406d07dae83518b32d9b7bb0b78717635482cb4f4a6b1b11a1f78ed4d5764ec9464645f704ad67eaf615c3f740a3b17becf77535290b3b59b205a5b6c",
      ),
    ),
  )
  assert_true(
    rsa_pss_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, 32, rsa_hash_sha384,
    ),
  )
}

///|
test "RSA PSS sign_with (SHA-512, exact, salt 32)" {
  let sig = rsa_pss_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, mh_salt32, rsa_hash_sha512,
  )
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "592ad5d1c5315c18720f9e57262fadf545d10b4c4e4e435a4596a6f9befadce6df03d1754ff17e6a182e707e6cb17e475b1f0a69fa2dff93d1b71a6a7aa52f694f232c8e40fa1a7e63f95712e3195b294fec358799d4ddebb998c5d0fcfa62feb5a6f53b0b56632f347737f30974dd75257ed99ee19f49fe0ea2b61b015e120b",
      ),
    ),
  )
  assert_true(
    rsa_pss_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, 32, rsa_hash_sha512,
    ),
  )
}

///|
test "RSA PSS verify_with (pycryptodome sig, random salt)" {
  // SHA-1, salt 20
  let sig1 = hex_to_bytes(
    "572a0268bed31d6f4dbb17884446496d20638eb7d3efdd8e01914d4affa91a731be780a301b82d11deb4a530c740af10bf38c23244d8b373ef9022c67137adf23f7a85c539f72d8197c9327f98e0f7507bfeb8d87efe55a75dfcc6b88a4ac93d8b8db63c5c1ee5cfd75f21135f2edff2147699700ba65f572a06e472d3694aa3",
  )
  assert_true(
    rsa_pss_verify_with(mh_msg, sig1, rsa_test_n, rsa_test_e, 20, rsa_hash_sha1),
  )
  // SHA-384, salt 48
  let sig384 = hex_to_bytes(
    "0ca8279220a27d9741d5adbabb642af4c2880941ea607c270d7d3613fd42ee5f7fb3be6cec64744436f15e52a616b92ce6df9d976d2c56e019c134b1ca673c325bf0aa97befd6b65652d62a32c1c2687689804f325d627bab572b87f40f0d37d1126c7d256b3ff56c984259326eb6e8760c986fb93b96ecdaf5f3cad44697ad4",
  )
  assert_true(
    rsa_pss_verify_with(
      mh_msg, sig384, rsa_test_n, rsa_test_e, 48, rsa_hash_sha384,
    ),
  )
  // SHA-512, salt 20
  let sig512 = hex_to_bytes(
    "5f239530c0798aa1aed19edf347fd803cf7542bdccd0b23a0317f500b2010e5fb585cd4c846644e9cbba9306baf05fe3c79e87be6632b679eeb6e8f67b90de0edff18ee8388bec6d41611d7fcc55641eee73005869806c2645297833ec1d214d76c4db2e67f8a535ecafda905ce58a95640380d212a42d90d7dcd27470d9ae6a",
  )
  assert_true(
    rsa_pss_verify_with(
      mh_msg, sig512, rsa_test_n, rsa_test_e, 20, rsa_hash_sha512,
    ),
  )
}

///|
test "RSA PSS verify_with (salt_len = 0, deterministic)" {
  let sig1 = hex_to_bytes(
    "605524fb2fe809cb1e9e6d7636dd8bd402c5313ef49c4d5460f1f1ce4280f24850db0ccacf7c6ab6d536214410d5ab14f3c2b6c6a3e8714ba07ec08e87e3a8b4cf7aaf648437267c80b92508b1825e4499a82ea0cd3826f0df91321d32131fa02b3e418e894ee2108b2cb0fcbc13b510841e82c6fbe7b22ddba1a3c1daab566b",
  )
  assert_true(
    rsa_pss_verify_with(mh_msg, sig1, rsa_test_n, rsa_test_e, 0, rsa_hash_sha1),
  )
  // salt_len 0 is deterministic: signing with an empty salt must reproduce
  assert_true(
    bytes_equal(
      rsa_pss_sign_with(mh_msg, rsa_test_n, rsa_test_d, b"", rsa_hash_sha1),
      sig1,
    ),
  )
  let sig512 = hex_to_bytes(
    "8c26a3d6044ce506f8076edfd0e16e0fb0e77ff55445dbef1dbff66ff031e7f091c0802854c5628faf8553d046735fb0c8a9a92abebe6694eb9fa13432385d505b5843ac1055bf8e381fd1cb4037611d4885f94432487a9425d97e17594ba622c8ee00f3c97a27298d71f5da1b19ba2356bf61eba7116f465af02a0396cff981",
  )
  assert_true(
    rsa_pss_verify_with(
      mh_msg, sig512, rsa_test_n, rsa_test_e, 0, rsa_hash_sha512,
    ),
  )
  assert_true(
    bytes_equal(
      rsa_pss_sign_with(mh_msg, rsa_test_n, rsa_test_d, b"", rsa_hash_sha512),
      sig512,
    ),
  )
}

///|
test "RSA PSS verify_with rejects wrong salt_len / wrong hash" {
  let sig = rsa_pss_sign_with(
    mh_msg, rsa_test_n, rsa_test_d, mh_salt32, rsa_hash_sha384,
  )
  assert_false(
    rsa_pss_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, 20, rsa_hash_sha384,
    ),
  )
  assert_false(
    rsa_pss_verify_with(
      mh_msg, sig, rsa_test_n, rsa_test_e, 32, rsa_hash_sha512,
    ),
  )
}

///|
test "RSA SHA-256 _with == plain fixed functions (compat)" {
  let salt = Bytes::make(32, b'\x2a')
  assert_true(
    bytes_equal(
      rsa_pss_sign_with(mh_msg, rsa_test_n, rsa_test_d, salt, rsa_hash_sha256),
      rsa_pss_sign(mh_msg, rsa_test_n, rsa_test_d, salt),
    ),
  )
  assert_true(
    bytes_equal(
      rsa_pkcs1_v15_sign_with(mh_msg, rsa_test_n, rsa_test_d, rsa_hash_sha256),
      rsa_pkcs1_v15_sign(mh_msg, rsa_test_n, rsa_test_d),
    ),
  )
}
