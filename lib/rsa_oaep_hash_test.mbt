// ==================== RSA-OAEP multi-hash tests (v0.23.0) =================
// Vectors cross-checked against pycryptodome (PKCS1_OAEP) on the 1024-bit
// test key from rsa_test.mbt (SHA-1/SHA-384; SHA-256 covered by the fixed
// functions) plus a dedicated 2048-bit key for SHA-512 (OAEP-SHA512 needs
// k >= 2*hLen + 2 + |M|, impossible on 1024 bits). Exact ciphertexts use a
// fixed seed injected via pycryptodome's randfunc hook; interop vectors use
// random seeds. Message: b"oaep multi-hash message".

///|
let om_msg : Bytes = b"oaep multi-hash message"

///|
let om_label : Bytes = b""

///|
test "RSA OAEP encrypt_with (SHA-1, exact ct)" {
  let seed = hex_to_bytes("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb")
  let ct = rsa_oaep_encrypt_with(
    om_msg, rsa_test_n, rsa_test_e, seed, om_label, rsa_hash_sha1,
  )
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "94d42f6eaea8f1dae0411453ce53c5b5b5a25605cdbad4ae75d4c360bcbb00e86b00f2e570816665afcb5c6465f215c7d5bcd3ec6a2aca49b8fd176fcf8b775465a9634ab51a78efc4b42a8de2fb56c0d47aa5f1e19f432c16f010aba4d9721a7554adfd81d9d4ff20dce8b6775cec6de43e871b7f55182689aa37ba6dc08215",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(ct, rsa_test_n, rsa_test_d, om_label, rsa_hash_sha1),
      om_msg,
    ),
  )
}

///|
test "RSA OAEP encrypt_with (SHA-384, exact ct)" {
  let seed = hex_to_bytes(
    "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7",
  )
  let ct = rsa_oaep_encrypt_with(
    om_msg, rsa_test_n, rsa_test_e, seed, om_label, rsa_hash_sha384,
  )
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "4643a4760ac49c9f412ffa2547f0d3bc04d8e6c74a9a92e33b6490b639fdb081e27e1f8aacf65bd0b1c28f7179a0def089610d01b54a781994e7ca335e6ac237af88e2fc44301056c9edc2e3482bf97d6f02c099618b957312eb3078bd7316b25bc3a52371b0d96fc85405f5c73bd0e6814e830c52325cd5d8c036a2228e358a",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(
        ct, rsa_test_n, rsa_test_d, om_label, rsa_hash_sha384,
      ),
      om_msg,
    ),
  )
}

///|
test "RSA OAEP decrypt_with (pycryptodome ct, random seed)" {
  let ct1 = hex_to_bytes(
    "9284096690cac62089f59e80ec66c3e331fb15594a60f8cab246086d410ca46c64116af4dad4d17ad542c42aff6215f22a46c86f0e0770ce5de82f1e4e2005e6bfb454b3a2c445cabc8ce83721edce37979275514a615b7b065c21bf20e4af55f7bab988ccb28b8c2155ceb015922796438f2e0109b5aa268e292a53d3099b63",
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(
        ct1, rsa_test_n, rsa_test_d, om_label, rsa_hash_sha1,
      ),
      om_msg,
    ),
  )
  let ct384 = hex_to_bytes(
    "021c3c1e3e7f771e0570b7363e9bfb3455819f9e3732b7e0c41113e1675300fbf5cffd0c270a9c9c0bada61b85739b78ac4d742349ece21e98bb7d6b053472143c2d802820a3e0470f8266f229b184fe947efd52fb2ac16848ddd52d486bae8f570e5b4572f8fefb6ff6d531a7f21bca2615b0db47461cfba88b951a473acc91",
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(
        ct384, rsa_test_n, rsa_test_d, om_label, rsa_hash_sha384,
      ),
      om_msg,
    ),
  )
}

///|
// 2048-bit key (fixed, generated with a seeded RNG in Python) — SHA-512
// OAEP needs a modulus of at least 2048 bits.
let om_n2048 : Bytes = hex_to_bytes(
  "c6fb08629ec47bdef8efb5e6ddaae63f6d87dbd5b33250fc15b64bf8bf50c760dc7a6925b7b13c6d960b756b2c0e8a0d4a9318b8ca3ae4de6ab3311286c99370ef13739671962a5c78bc470e9e27d6d8e319d06cece27cf08b1cd27af796923279133daf337b1757f9d849a0403600547bb8e0e3c54ef8e952bed5254cf36ceae173393c116c02f4ace0696b8e82c39daf9e2cac8951efd8b66a5802224498ebc1c715861df58eca94b724d6ea69ad9f5bd5124fa49f35bd82c9547db10c1c7165ad9cee98ebd885b6885219c884f7f6d10ef1d8c10485242bef0e2f4a95b638f67a92c7477e034ce5a51477ca92f7dc76fdddcbc5bfd581dc53c84e745aa57f",
)

///|
let om_d2048 : Bytes = hex_to_bytes(
  "1db1f407e7c2d1ebae41f3e71ed8b4e0ed63339b1a519d85696619c36725d2837193f122385e4272e64c127b6a8946f001db9efa60efd61d1d565db1f29c9d9ce289081c811a147b55675fc15e37fad7c658a162c81d6ae0e919e58d856a9aa9dea8d0f15720fd145b8c7c3c66a8c876d339fd91f06dbf36eeeadcdb62b7075f68da8de84c9623fabe67d2b69e0e80c6658efc6a7eddafceca493dd540780a194048ec3cf5b3f7ec85490df7f5e402189250f6b6d66bc147814af19274638944d1a0b16a9efb082db207a01ce9d75ff32d2ec4c0ac93fb224980af74b93adad39d3e6131917facc8a1253d4c0d2979d3146e58948ae90b304c75fb72d009d819",
)

///|
test "RSA OAEP SHA-512 (2048-bit key, exact ct)" {
  let seed = hex_to_bytes(
    "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001020304050607",
  )
  let ct = rsa_oaep_encrypt_with(
    om_msg, om_n2048, rsa_test_e, seed, om_label, rsa_hash_sha512,
  )
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "aa882b9ca7e0cd8482437c0dc3cf7ff5b21cd2952bc5175407a6986be4449db5f814a7aa9352b51be72ed03c322bb8d2ccf6f885a7fa84f57dc60f86ac4c8ba393700bad116fb6747b48e8dc35d1a63cab1c1ddc2642671cf5d7f5865d406e4b203ea3fbb694f140a1c0270f1863ad896b357d99c92ae95fb6f37a75ff95695c3f07465856b247c5653fcbff127421cac16f4df32493262ff1477c2eaf23c773660f5be4b5b86b4c6f4d58377b6fef4ffbb2a51bc236658c1fc3b5957c403236c155e37d68e851c5001d789fa68ee674f0b22683b7550c0535967238d8f3dab668c1306ebc6644f2f2bd1c2dc2828342341fceed2d09f6730a9054da7d69c1ad",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(ct, om_n2048, om_d2048, om_label, rsa_hash_sha512),
      om_msg,
    ),
  )
  // interop: pycryptodome random-seed ciphertext
  let ct_rand = hex_to_bytes(
    "652896f9ccf4bcd40756f001433641caac1a39c6a7e08e049ac13ac1722852a461abe3c6863435ab0481b5526e6d99a77a52031111fa53fd160e3f2749fcdb79e7f367c330b8df486a195cf1fbf60b3a5bbe38603ee6ebb47f193b251c68e0b325143e08c34a43c1dd44232ff7e2ade13deecb61887cea6d681e5f0b35138794357f73b111eda5fd0289762d82b59740cc44898cfa11dec3449695e2bebcdaaff61df593a7a2f644580521cd5c093d17f7ddf3c5a788f427b63b254c22cd7ba3610663f06a13f0c5e1f17904d8c8e00498721026c1e5e8d4cedb23e6c2fd51945b42bb7a9ef9690a8c94a35020a615af2492a9ce1129415b496c354e31768d20",
  )
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(
        ct_rand, om_n2048, om_d2048, om_label, rsa_hash_sha512,
      ),
      om_msg,
    ),
  )
}

///|
test "RSA OAEP _with (SHA-256) == plain fixed functions (compat)" {
  let seed = Bytes::make(32, b'\x11')
  assert_true(
    bytes_equal(
      rsa_oaep_encrypt_with(
        om_msg, rsa_test_n, rsa_test_e, seed, om_label, rsa_hash_sha256,
      ),
      rsa_oaep_encrypt(om_msg, rsa_test_n, rsa_test_e, seed, om_label),
    ),
  )
  let ct = rsa_oaep_encrypt(om_msg, rsa_test_n, rsa_test_e, seed, om_label)
  assert_true(
    bytes_equal(
      rsa_oaep_decrypt_with(
        ct, rsa_test_n, rsa_test_d, om_label, rsa_hash_sha256,
      ),
      rsa_oaep_decrypt(ct, rsa_test_n, rsa_test_d, om_label),
    ),
  )
}

///|
test "RSA OAEP _with round-trips for all hashes" {
  let r = Rng::{ state: 0x0AE9C001U, }
  for trial in 0..<4 {
    let hash = rsa_hash_variants[trial]
    let h_len = if trial == 0 {
      20
    } else if trial == 1 {
      32
    } else if trial == 2 {
      48
    } else {
      64
    }
    let seed = rng_bytes(r, h_len)
    let msg = rng_bytes(r, 5 + trial * 3)
    // SHA-512 needs the 2048-bit key
    let (nn, dd) = if h_len == 64 {
      (om_n2048, om_d2048)
    } else {
      (rsa_test_n, rsa_test_d)
    }
    let ct = rsa_oaep_encrypt_with(msg, nn, rsa_test_e, seed, om_label, hash)
    assert_true(
      bytes_equal(rsa_oaep_decrypt_with(ct, nn, dd, om_label, hash), msg),
    )
  }
}
