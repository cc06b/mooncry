// AES-GCM-SIV official vectors (RFC 8452 Appendix C.1/C.2). v0.39.0.

///|
test "AES-128-GCM-SIV RFC8452 vector 1 (pt 0B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = b""
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(bytes_equal(ct, hex_to_bytes("dc20e2d83f25705bb49e439eca56de25")))
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 2 (pt 8B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("0100000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("b5d839330ac7b786578782fff6013b815b287c22493a364c"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 3 (pt 12B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("010000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 4 (pt 16B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("01000000000000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 5 (pt 32B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "0100000000000000000000000000000002000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c66" +
        "7cd86847bf6155ff",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 6 (pt 48B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "01000000000000000000000000000000020000000000000000000000000000000300000000000000" +
    "0000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64df42bf7226122fa92" +
        "e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 7 (pt 64B, aad 0B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "01000000000000000000000000000000020000000000000000000000000000000300000000000000" +
    "000000000000000004000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af02516a2bdcbc08d52" +
        "1be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f8a263dd317aa88d56bdf3936dba75bb8",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 8 (pt 8B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("0200000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("1e6daba35669f4273b0a1a2560969cdf790d99759abd1508"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 9 (pt 12B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("020000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 10 (pt 16B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("02000000000000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 11 (pt 32B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "0200000000000000000000000000000003000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71e6af6a7f87287da0" +
        "59a71684ed3498e1",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 12 (pt 48B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "02000000000000000000000000000000030000000000000000000000000000000400000000000000" +
    "0000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b0053201d723120a8562" +
        "b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 13 (pt 64B, aad 1B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "02000000000000000000000000000000030000000000000000000000000000000400000000000000" +
    "000000000000000005000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42feec601910d3467bb8" +
        "b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80cdc46ae475563de037001ef84ae21744",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 14 (pt 4B, aad 12B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("010000000000000000000000")
  let pt = hex_to_bytes("02000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(ct, hex_to_bytes("a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14")),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 15 (pt 20B, aad 18B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("010000000000000000000000000000000200")
  let pt = hex_to_bytes("0300000000000000000000000000000004000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6fe106514",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 16 (pt 18B, aad 20B)" {
  let key = hex_to_bytes("01000000000000000000000000000000")
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("0100000000000000000000000000000002000000")
  let pt = hex_to_bytes("030000000000000000000000000000000400")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 17 (pt 0B, aad 0B)" {
  let key = hex_to_bytes("e66021d5eb8e4f4066d4adb9c33560e4")
  let nonce = hex_to_bytes("f46e44bb3da0015c94f70887")
  let aad = b""
  let pt = b""
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(bytes_equal(ct, hex_to_bytes("a4194b79071b01a87d65f706e3949578")))
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 18 (pt 3B, aad 5B)" {
  let key = hex_to_bytes("36864200e0eaf5284d884a0e77d31646")
  let nonce = hex_to_bytes("bae8e37fc83441b16034566b")
  let aad = hex_to_bytes("46bb91c3c5")
  let pt = hex_to_bytes("7a806c")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(ct, hex_to_bytes("af60eb711bd85bc1e4d3e0a462e074eea428a8")),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 19 (pt 6B, aad 10B)" {
  let key = hex_to_bytes("aedb64a6c590bc84d1a5e269e4b47801")
  let nonce = hex_to_bytes("afc0577e34699b9e671fdd4f")
  let aad = hex_to_bytes("fc880c94a95198874296")
  let pt = hex_to_bytes("bdc66f146545")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 20 (pt 9B, aad 15B)" {
  let key = hex_to_bytes("d5cc1fd161320b6920ce07787f86743b")
  let nonce = hex_to_bytes("275d1ab32f6d1f0434d8848c")
  let aad = hex_to_bytes("046787f3ea22c127aaf195d1894728")
  let pt = hex_to_bytes("1177441f195495860f")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 21 (pt 12B, aad 20B)" {
  let key = hex_to_bytes("b3fed1473c528b8426a582995929a149")
  let nonce = hex_to_bytes("9e9ad8780c8d63d0ab4149c0")
  let aad = hex_to_bytes("c9882e5386fd9f92ec489c8fde2be2cf97e74e93")
  let pt = hex_to_bytes("9f572c614b4745914474e7c7")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 22 (pt 15B, aad 25B)" {
  let key = hex_to_bytes("2d4ed87da44102952ef94b02b805249b")
  let nonce = hex_to_bytes("ac80e6f61455bfac8308a2d4")
  let aad = hex_to_bytes("2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a")
  let pt = hex_to_bytes("0d8c8451178082355c9e940fea2f58")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 23 (pt 18B, aad 30B)" {
  let key = hex_to_bytes("bde3b2f204d1e9f8b06bc47f9745b3d1")
  let nonce = hex_to_bytes("ae06556fb6aa7890bebc18fe")
  let aad = hex_to_bytes(
    "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f",
  )
  let pt = hex_to_bytes("6b3db4da3d57aa94842b9803a96e07fb6de7")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4db84",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-128-GCM-SIV RFC8452 vector 24 (pt 21B, aad 35B)" {
  let key = hex_to_bytes("f901cfe8a69615a93fdf7a98cad48179")
  let nonce = hex_to_bytes("6245709fb18853f68d833640")
  let aad = hex_to_bytes(
    "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21",
  )
  let pt = hex_to_bytes("e42a3c02c25b64869e146d7b233987bddfc240871d")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 25 (pt 0B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = b""
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(bytes_equal(ct, hex_to_bytes("07f5f4169bbf55a8400cd47ea6fd400f")))
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 26 (pt 8B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("0100000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 27 (pt 12B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("010000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 28 (pt 16B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes("01000000000000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 29 (pt 32B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "0100000000000000000000000000000002000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b0" +
        "06a976397632eb5d",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 30 (pt 48B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "01000000000000000000000000000000020000000000000000000000000000000300000000000000" +
    "0000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6" +
        "ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 31 (pt 64B, aad 0B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = b""
  let pt = hex_to_bytes(
    "01000000000000000000000000000000020000000000000000000000000000000300000000000000" +
    "000000000000000004000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891" +
        "a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 32 (pt 8B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("0200000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 33 (pt 12B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("020000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 34 (pt 16B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes("02000000000000000000000000000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 35 (pt 32B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "0200000000000000000000000000000003000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e196" +
        "5604374aab96dbbc",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 36 (pt 48B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "02000000000000000000000000000000030000000000000000000000000000000400000000000000" +
    "0000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf56" +
        "4527f2314f42fe2503332742b228c647173616cfd44c54eb",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 37 (pt 64B, aad 1B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("01")
  let pt = hex_to_bytes(
    "02000000000000000000000000000000030000000000000000000000000000000400000000000000" +
    "000000000000000005000000000000000000000000000000",
  )
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de88" +
        "7b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 38 (pt 4B, aad 12B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("010000000000000000000000")
  let pt = hex_to_bytes("02000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(ct, hex_to_bytes("22b3f4cd1835e517741dfddccfa07fa4661b74cf")),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 39 (pt 20B, aad 18B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("010000000000000000000000000000000200")
  let pt = hex_to_bytes("0300000000000000000000000000000004000000")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 40 (pt 18B, aad 20B)" {
  let key = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex_to_bytes("030000000000000000000000")
  let aad = hex_to_bytes("0100000000000000000000000000000002000000")
  let pt = hex_to_bytes("030000000000000000000000000000000400")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 41 (pt 0B, aad 0B)" {
  let key = hex_to_bytes(
    "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200",
  )
  let nonce = hex_to_bytes("e0eaf5284d884a0e77d31646")
  let aad = b""
  let pt = b""
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(bytes_equal(ct, hex_to_bytes("169fbb2fbf389a995f6390af22228a62")))
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 42 (pt 3B, aad 5B)" {
  let key = hex_to_bytes(
    "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269",
  )
  let nonce = hex_to_bytes("e4b47801afc0577e34699b9e")
  let aad = hex_to_bytes("4fbdc66f14")
  let pt = hex_to_bytes("671fdd")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(ct, hex_to_bytes("0eaccb93da9bb81333aee0c785b240d319719d")),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 43 (pt 6B, aad 10B)" {
  let key = hex_to_bytes(
    "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3",
  )
  let nonce = hex_to_bytes("2f6d1f0434d8848c1177441f")
  let aad = hex_to_bytes("6787f3ea22c127aaf195")
  let pt = hex_to_bytes("195495860f04")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 44 (pt 9B, aad 15B)" {
  let key = hex_to_bytes(
    "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0",
  )
  let nonce = hex_to_bytes("9f572c614b4745914474e7c7")
  let aad = hex_to_bytes("489c8fde2be2cf97e74e932d4ed87d")
  let pt = hex_to_bytes("c9882e5386fd9f92ec")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 45 (pt 12B, aad 20B)" {
  let key = hex_to_bytes(
    "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235",
  )
  let nonce = hex_to_bytes("5c9e940fea2f582950a70d5a")
  let aad = hex_to_bytes("0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f")
  let pt = hex_to_bytes("1db2316fd568378da107b52b")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes("8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5"),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 46 (pt 15B, aad 25B)" {
  let key = hex_to_bytes(
    "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb",
  )
  let nonce = hex_to_bytes("6de71860f762ebfbd08284e4")
  let aad = hex_to_bytes("f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f")
  let pt = hex_to_bytes("21702de0de18baa9c9596291b08466")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 47 (pt 18B, aad 30B)" {
  let key = hex_to_bytes(
    "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7",
  )
  let nonce = hex_to_bytes("028ec6eb5ea7e298342a94d4")
  let aad = hex_to_bytes(
    "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
  )
  let pt = hex_to_bytes("b202b370ef9768ec6561c4fe6b7e7296fa85")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}

///|
test "AES-256-GCM-SIV RFC8452 vector 48 (pt 21B, aad 35B)" {
  let key = hex_to_bytes(
    "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23",
  )
  let nonce = hex_to_bytes("688089e55540db1872504e1c")
  let aad = hex_to_bytes(
    "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541",
  )
  let pt = hex_to_bytes("ced532ce4159b035277d4dfbb7db62968b13cd4eec")
  let ct = aes_gcm_siv_encrypt(key, nonce, aad, pt)
  assert_true(
    bytes_equal(
      ct,
      hex_to_bytes(
        "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594",
      ),
    ),
  )
  match aes_gcm_siv_decrypt(key, nonce, aad, ct) {
    Some(rec) => assert_true(bytes_equal(rec, pt))
    None => assert_true(false)
  }
}
