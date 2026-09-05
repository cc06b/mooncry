// HPKE DHKEM(P-521) official vectors (RFC 9180 Appendix A.6). v0.40.0.

///|
test "HPKE RFC9180 p521_hkdf_sha512_aes256gcm Base mode" {
  let suite = hpke_p521_hkdf_sha512_aes256gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5" +
    "ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904",
  )
  let pk_r = hex_to_bytes(
    "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738" +
    "bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c" +
    "7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed8" +
    "16e523b6b6a418f66d2451ec64",
  )
  let sk_r = hex_to_bytes(
    "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523" +
    "a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = b""
  let pk_s = b""
  let (enc, ctx_s) = hpke_setup_s(
    suite, 0, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a490" +
        "55758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463" +
        "962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a9" +
        "96ee522aef863dd5739d2f29b0",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 0, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c79" +
          "5a7c5b841a",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c79" +
        "5a7c5b841a",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a" +
          "05fd352256",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a" +
        "05fd352256",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b" +
          "61d24e1c7a",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b" +
        "61d24e1c7a",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, b"", 32),
      hex_to_bytes(
        "05e2e5bd9f0c30832b80a279ff211cc65eceb0d97001524085d609ead60d0412",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "fca69744bb537f5b7a1596dbf34eaa8d84bf2e3ee7f1a155d41bd3624aa92b63",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "f389beaac6fcf6c0d9376e20f97e364f0609a88f1bc76d7328e9104df8477013",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p521_hkdf_sha512_aes256gcm PSK mode" {
  let suite = hpke_p521_hkdf_sha512_aes256gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "f3ebfa9a69a924e672114fcd9e06fa9559e937f7eccce4181a2b506df53dbe514be12f094bb28e01" +
    "de19dd345b4f7ede5ad7eaa6b9c3019592ec68eaae9a14732ce0",
  )
  let pk_r = hex_to_bytes(
    "04006917e049a2be7e1482759fb067ddb94e9c4f7f5976f655088dec45246614ff924ed3b385fc29" +
    "86c0ecc39d14f907bf837d7306aada59dd5889086125ecd038ead400603394b5d81f89ebfd556a89" +
    "8cc1d6a027e143d199d3db845cb91c5289fb26c5ff80832935b0e8dd08d37c6185a6f77683347e47" +
    "2d1edb6daa6bd7652fea628fae",
  )
  let sk_r = hex_to_bytes(
    "011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bde264428de03379863b" +
    "4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753eb72",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = b""
  let pk_s = b""
  let (enc, ctx_s) = hpke_setup_s(
    suite, 1, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d48d0768b368110fab2" +
        "1407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bff793b30036d2c614d55730bd2a40c718" +
        "f9466faf4d5f8170d22b6df98dfe0c067d02b349ae4a142e0c03418f0a1479ff78a3db07ae2c2e89" +
        "e5840f712c174ba2118e90fdcb",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 1, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be5" +
          "31aa7843a1",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be5" +
        "31aa7843a1",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "77a16162831f90de350fea9152cfc685ecfa10acb4f7994f41aed43fa5431f2382d078ec88baec53" +
          "943984553e",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "77a16162831f90de350fea9152cfc685ecfa10acb4f7994f41aed43fa5431f2382d078ec88baec53" +
        "943984553e",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "f1d48d09f126b9003b4c7d3fe6779c7c92173188a2bb7465ba43d899a6398a333914d2bb19fd769d" +
          "53f3ec7336",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "f1d48d09f126b9003b4c7d3fe6779c7c92173188a2bb7465ba43d899a6398a333914d2bb19fd769d" +
        "53f3ec7336",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, b"", 32),
      hex_to_bytes(
        "62691f0f971e34de38370bff24deb5a7d40ab628093d304be60946afcdb3a936",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "76083c6d1b6809da088584674327b39488eaf665f0731151128452e04ce81bff",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "0c7cfc0976e25ae7680cf909ae2de1859cd9b679610a14bec40d69b91785b2f6",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p521_hkdf_sha512_aes256gcm Auth mode" {
  let suite = hpke_p521_hkdf_sha512_aes256gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "fe1c589c2a05893895a537f38c7cb4300b5a7e8fef3d6ccb8f07a498029c61e90262e009dc254c7f" +
    "6235f9c6b2fd6aeff0a714db131b09258c16e217b7bd2aa619b0",
  )
  let pk_r = hex_to_bytes(
    "04007d419b8834e7513d0e7cc66424a136ec5e11395ab353da324e3586673ee73d53ab34f30a0b42" +
    "a92d054d0db321b80f6217e655e304f72793767c4231785c4a4a6e008f31b93b7a4f2b8cd12e5fe5" +
    "a0523dc71353c66cbdad51c86b9e0bdfcd9a45698f2dab1809ab1b0f88f54227232c858accc44d9a" +
    "8d41775ac026341564a2d749f4",
  )
  let sk_r = hex_to_bytes(
    "013ef326940998544a899e15e1726548ff43bbdb23a8587aa3bef9d1b857338d87287df5667037b5" +
    "19d6a14661e9503cfc95a154d93566d8c84e95ce93ad05293a0b",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "001018584599625ff9953b9305849850d5e34bd789d4b81101139662fbea8b6508ddb9d019b0d692" +
    "e737f66beae3f1f783e744202aaf6fea01506c27287e359fe776",
  )
  let pk_s = hex_to_bytes(
    "04015cc3636632ea9a3879e43240beae5d15a44fba819282fac26a19c989fafdd0f330b8521dff7d" +
    "c393101b018c1e65b07be9f5fc9a28a1f450d6a541ee0d76221133001e8f0f6a05ab79f9b9bb9ccc" +
    "e142a453d59c5abebb5674839d935a3ca1a3fbc328539a60b3bc3c05fed22838584a726b9c176796" +
    "cad0169ba4093332cbd2dc3a9f",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d111fe759497f8aefdc5d" +
        "bb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b117e9cf01e29320b799bbc86afdc5ea97" +
        "d941ea1c5bd5ebeeac7a784b3bab524746f3e640ec26ee1bd91255f9330d974f845084637ee0e6fe" +
        "9f505c5b87c86a4e1a6c3096dd",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 2, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "0116aeb3a1c405c61b1ce47600b7ecd11d89b9c08c408b7e2d1e00a4d64696d12e6881dc61688209" +
          "a8207427f9",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "0116aeb3a1c405c61b1ce47600b7ecd11d89b9c08c408b7e2d1e00a4d64696d12e6881dc61688209" +
        "a8207427f9",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "37ece0cf6741f443e9d73b9966dc0b228499bb21fbf313948327231e70a18380e080529c0267f399" +
          "ba7c539cc6",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "37ece0cf6741f443e9d73b9966dc0b228499bb21fbf313948327231e70a18380e080529c0267f399" +
        "ba7c539cc6",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "d17b045cac963e45d55fd3692ec17f100df66ac06d91f3b6af8efa7ed3c8895550eb753bc801fe4b" +
          "d27005b4bd",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "d17b045cac963e45d55fd3692ec17f100df66ac06d91f3b6af8efa7ed3c8895550eb753bc801fe4b" +
        "d27005b4bd",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, b"", 32),
      hex_to_bytes(
        "8d78748d632f95b8ce0c67d70f4ad1757e61e872b5941e146986804b3990154b",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "80a4753230900ea785b6c80775092801fe91183746479f9b04c305e1db9d1f4d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "620b176d737cf366bcc20d96adb54ec156978220879b67923689e6dca36210ed",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p521_hkdf_sha512_aes256gcm AuthPSK mode" {
  let suite = hpke_p521_hkdf_sha512_aes256gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "54272797b1fbc128a6967ff1fd606e0c67868f7762ce1421439cbc9e90ce1b28d566e6c2acbce712" +
    "e48eebf236696eb680849d6873e9959395b2931975d61d38bd6c",
  )
  let pk_r = hex_to_bytes(
    "0401655b5d3b7cfafaba30851d25edc44c6dd17d99410efbed8591303b4dbeea8cb1045d5255f9a6" +
    "0384c3bbd4a3386ae6e6fab341dc1f8db0eed5f0ab1aaac6d7838e00dadf8a1c2c64b48f89c63372" +
    "1e88369e54104b31368f26e35d04a442b0b428510fb23caada686add16492f333b0f7ba74c391d77" +
    "9b788df2c38d7a7f4778009d91",
  )
  let sk_r = hex_to_bytes(
    "0053c0bc8c1db4e9e5c3e3158bfdd7fc716aef12db13c8515adf821dd692ba3ca53041029128ee19" +
    "c8556e345c4bcb840bb7fd789f97fe10f17f0e2c6c2528072843",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "003f64675fc8914ec9e2b3ecf13585b26dbaf3d5d805042ba487a5070b8c5ac1d39b17e2161771cc" +
    "1b4d0a3ba6e866f4ea4808684b56af2a49b5e5111146d45d9326",
  )
  let pk_s = hex_to_bytes(
    "040013761e97007293d57de70962876b4926f69a52680b4714bee1d4236aa96c19b840c57e80b14e" +
    "91258f0a350e3f7ba59f3f091633aede4c7ec4fa8918323aa45d5901076dec8eeb22899fda9ab9e1" +
    "960003ff0535f53c02c40f2ae4cdc6070a3870b85b4bdd0bb77f1f889e7ee51f465a308f08c666ad" +
    "3407f75dc046b2ff5a24dbe2ed",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff71e560b15aff96741e" +
        "cffb63d8ac3090c3769679009ac59a99a1feb4713c5f090fc0dbed01ad73c45d29d369e36744e9ed" +
        "37d12f80700c16d816485655169a5dd66e4ddf27f2acffe0f56f7f77ea2b473b4bf0518b975d9527" +
        "009a3d14e5a4957e3e8a9074f8",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 3, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "942a2a92e0817cf032ce61abccf4f3a7c5d21b794ed943227e07b7df2d6dd92c9b8a9371949e65cc" +
          "a262448ab7",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "942a2a92e0817cf032ce61abccf4f3a7c5d21b794ed943227e07b7df2d6dd92c9b8a9371949e65cc" +
        "a262448ab7",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "c0a83b5ec3d7933a090f681717290337b4fede5bfaa0a40ec29f93acad742888a1513c649104c391" +
          "c78d1d7f29",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "c0a83b5ec3d7933a090f681717290337b4fede5bfaa0a40ec29f93acad742888a1513c649104c391" +
        "c78d1d7f29",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  {
    let ct = hpke_seal(
      ctx_s,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
    )
    assert_true(
      bytes_equal(
        ct,
        hex_to_bytes(
          "2847b2e0ce0b9da8fca7b0e81ff389d1682ee1b388ed09579b145058b5af6a93a85dd50d9f417dc8" +
          "8f2c785312",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "2847b2e0ce0b9da8fca7b0e81ff389d1682ee1b388ed09579b145058b5af6a93a85dd50d9f417dc8" +
        "8f2c785312",
      ),
    ) {
    Some(pt) =>
      assert_true(
        bytes_equal(
          pt,
          hex_to_bytes(
            "4265617574792069732074727574682c20747275746820626561757479",
          ),
        ),
      )
    None => assert_true(false)
  }
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, b"", 32),
      hex_to_bytes(
        "a39502ef5ca116aa1317bd9583dd52f15b0502b71d900fc8a622d19623d0cb5d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "749eda112c4cfdd6671d84595f12cd13198fc3ef93ed72369178f344fe6e09c3",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "f8b4e72cefbff4ca6c4eabb8c0383287082cfcbb953d900aed4959afd0017095",
      ),
    ),
  )
}
