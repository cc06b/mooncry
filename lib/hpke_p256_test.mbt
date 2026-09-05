// HPKE DHKEM(P-256) official vectors (RFC 9180 Appendix A.3-A.5). v0.38.0.

///|
test "HPKE RFC9180 p256_hkdf_sha256_aes128gcm Base mode" {
  let suite = hpke_p256_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
  )
  let pk_r = hex_to_bytes(
    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8" +
    "a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
  )
  let sk_r = hex_to_bytes(
    "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
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
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4" +
        "b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
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
          "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab252" +
          "3f39513434",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab252" +
        "3f39513434",
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
          "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3c" +
          "d655b28e82",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3c" +
        "d655b28e82",
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
          "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb5" +
          "5fed7a7fec",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb5" +
        "5fed7a7fec",
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
        "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_aes128gcm PSK mode" {
  let suite = hpke_p256_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "2afa611d8b1a7b321c761b483b6a053579afa4f767450d3ad0f84a39fda587a6",
  )
  let pk_r = hex_to_bytes(
    "040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b766" +
    "39eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1",
  )
  let sk_r = hex_to_bytes(
    "438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661",
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
        "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d14" +
        "85137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f",
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
          "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2" +
          "126b75d0eb",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2" +
        "126b75d0eb",
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
          "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a10" +
          "73a7102c27",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a10" +
        "73a7102c27",
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
          "adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0" +
          "c7781465b2",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0" +
        "c7781465b2",
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
        "a115a59bf4dd8dc49332d6a0093af8efca1bcbfd3627d850173f5c4a55d0c185",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "4517eaede0669b16aac7c92d5762dd459c301fa10e02237cd5aeb9be969430c4",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "164e02144d44b607a7722e58b0f4156e67c0c2874d74cf71da6ca48a4cbdc5e0",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_aes128gcm Auth mode" {
  let suite = hpke_p256_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "798d82a8d9ea19dbc7f2c6dfa54e8a6706f7cdc119db0813dacf8440ab37c857",
  )
  let pk_r = hex_to_bytes(
    "04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28" +
    "fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d",
  )
  let sk_r = hex_to_bytes(
    "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9",
  )
  let pk_s = hex_to_bytes(
    "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd" +
    "9086c80b309df22cf37609f58c1127f7607e85f210b2804f73",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c53" +
        "5ef06745f3d308624414153b22c7332bc1e691cb4af4d53454",
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
          "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099e" +
          "d3289ffe19",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099e" +
        "d3289ffe19",
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
          "b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e" +
          "3966aa1250",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e" +
        "3966aa1250",
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
          "8dc805680e3271a801790833ed74473710157645584f06d1b53ad439078d880b23e2525666317827" +
          "1c80ee8b7c",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "8dc805680e3271a801790833ed74473710157645584f06d1b53ad439078d880b23e2525666317827" +
        "1c80ee8b7c",
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
        "837e49c3ff629250c8d80d3c3fb957725ed481e59e2feb57afd9fe9a8c7c4497",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "594213f9018d614b82007a7021c3135bda7b380da4acd9ab27165c508640dbda",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "14fe634f95ca0d86e15247cca7de7ba9b73c9b9deb6437e1c832daf7291b79d5",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_aes128gcm AuthPSK mode" {
  let suite = hpke_p256_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "3c1fceb477ec954c8d58ef3249e4bb4c38241b5925b95f7486e4d9f1d0d35fbb",
  )
  let pk_r = hex_to_bytes(
    "04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462a" +
    "b7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3",
  )
  let sk_r = hex_to_bytes(
    "bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240",
  )
  let pk_s = hex_to_bytes(
    "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73" +
    "863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317d" +
        "c22509c7b00991ae990bf65f8b236700c82ab7c11a84511401",
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
          "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f" +
          "4ff81b9246",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f" +
        "4ff81b9246",
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
          "51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579" +
          "c10fc09736",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579" +
        "c10fc09736",
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
          "3b5a2be002e7b29927f06442947e1cf709b9f8508b03823127387223d712703471c266efc355f1bc" +
          "2036f3027c",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "3b5a2be002e7b29927f06442947e1cf709b9f8508b03823127387223d712703471c266efc355f1bc" +
        "2036f3027c",
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
        "595ce0eff405d4b3bb1d08308d70a4e77226ce11766e0a94c4fdb5d90025c978",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "110472ee0ae328f57ef7332a9886a1992d2c45b9b8d5abc9424ff68630f7d38d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "18ee4d001a9d83a4c67e76f88dd747766576cac438723bad0700a910a4d717e6",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha512_aes128gcm Base mode" {
  let suite = hpke_p256_hkdf_sha512_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "4ab11a9dd78c39668f7038f921ffc0993b368171d3ddde8031501ee1e08c4c9a",
  )
  let pk_r = hex_to_bytes(
    "04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b4493570" +
    "96232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd",
  )
  let sk_r = hex_to_bytes(
    "3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38",
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
        "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c689788807007" +
        "0c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580",
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
          "d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b33200354375" +
          "4eb51917ba",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b33200354375" +
        "4eb51917ba",
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
          "d14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f1" +
          "24e0acc62d",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "d14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f1" +
        "24e0acc62d",
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
          "9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37" +
          "da4aafa800",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37" +
        "da4aafa800",
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
        "a32186b8946f61aeead1c093fe614945f85833b165b28c46bf271abf16b57208",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "84998b304a0ea2f11809398755f0abd5f9d2c141d1822def79dd15c194803c2a",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "93fb9411430b2cfa2cf0bed448c46922a5be9beff20e2e621df7e4655852edbc",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha512_aes128gcm PSK mode" {
  let suite = hpke_p256_hkdf_sha512_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "c11d883d6587f911d2ddbc2a0859d5b42fb13bf2c8e89ef408a25564893856f5",
  )
  let pk_r = hex_to_bytes(
    "043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd84d7f45dabfc1f556" +
    "64b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873",
  )
  let sk_r = hex_to_bytes(
    "bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522",
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
        "04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057f3079f6e0abae200" +
        "992610b25f48b63aacfcb669106ddee8aa023feed301901371",
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
          "57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e83" +
          "06da41d4cc",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a45b9faa88de39e83" +
        "06da41d4cc",
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
          "159d6b4c24bacaf2f5049b7863536d8f3ffede76302dace42080820fa51925d4e1c72a64f87b1429" +
          "1a3057e00a",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "159d6b4c24bacaf2f5049b7863536d8f3ffede76302dace42080820fa51925d4e1c72a64f87b1429" +
        "1a3057e00a",
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
          "bd24140859c99bf0055075e9c460032581dd1726d52cf980d308e9b20083ca62e700b17892bcf7fa" +
          "82bac751d0",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "bd24140859c99bf0055075e9c460032581dd1726d52cf980d308e9b20083ca62e700b17892bcf7fa" +
        "82bac751d0",
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
        "8158bea21a6700d37022bb7802866edca30ebf2078273757b656ef7fc2e428cf",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "6a348ba6e0e72bb3ef22479214a139ef8dac57be34509a61087a12565473da8d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "2f6d4f7a18ec48de1ef4469f596aada4afdf6d79b037ed3c07e0118f8723bffc",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha512_aes128gcm Auth mode" {
  let suite = hpke_p256_hkdf_sha512_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "6bb031aa9197562da0b44e737db2b9e61f6c3ea1138c37de28fc37ac29bc7350",
  )
  let pk_r = hex_to_bytes(
    "04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8adf84c8deba3155c" +
    "9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276",
  )
  let sk_r = hex_to_bytes(
    "1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579",
  )
  let pk_s = hex_to_bytes(
    "0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259b9b98a34ad17e216" +
    "17d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59178084d0dd66e0f7" +
        "9172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6",
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
          "2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d" +
          "7b38a9236e",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154157fa9eb44f2fa4d" +
        "7b38a9236e",
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
          "10cd81e3a816d29942b602a92884348171a31cbd0f042c3057c65cd93c540943a5b05115bd520c09" +
          "281061935b",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "10cd81e3a816d29942b602a92884348171a31cbd0f042c3057c65cd93c540943a5b05115bd520c09" +
        "281061935b",
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
          "920743a88d8cf6a09e1a3098e8be8edd09db136e9d543f215924043af8c7410f68ce6aa64fd2b1a1" +
          "76e7f6b3fd",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "920743a88d8cf6a09e1a3098e8be8edd09db136e9d543f215924043af8c7410f68ce6aa64fd2b1a1" +
        "76e7f6b3fd",
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
        "f03fbc82f321a0ab4840e487cb75d07aafd8e6f68485e4f7ff72b2f55ff24ad6",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "1ce0cadec0a8f060f4b5070c8f8888dcdfefc2e35819df0cd559928a11ff0891",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "70c405c707102fd0041ea716090753be47d68d238b111d542846bd0d84ba907c",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha512_aes128gcm AuthPSK mode" {
  let suite = hpke_p256_hkdf_sha512_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "37ae06a521cd555648c928d7af58ad2aa4a85e34b8cabd069e94ad55ab872cc8",
  )
  let pk_r = hex_to_bytes(
    "04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a111cbf6f7385fac55" +
    "edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9",
  )
  let sk_r = hex_to_bytes(
    "00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "d743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b",
  )
  let pk_s = hex_to_bytes(
    "04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2165b5bb1f07a6240" +
    "dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0aef5a7ef0bf405794" +
        "9a140285f774f1efc53b3860936b92279a11b68395d898d138",
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
          "840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d8" +
          "62c2fd7d16",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa910fc4296828cb9d8" +
        "62c2fd7d16",
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
          "d4680a48158d9a75fd09355878d6e33997a36ee01d4a8f22032b22373b795a941b7b9c5205ff99e0" +
          "ff284beef4",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "d4680a48158d9a75fd09355878d6e33997a36ee01d4a8f22032b22373b795a941b7b9c5205ff99e0" +
        "ff284beef4",
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
          "c45eb6597de2bac929a0f5d404ba9d2dc1ea031880930f1fd7a283f0a0cbebb35eac1a9ee0d1225f" +
          "5e0f181571",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "c45eb6597de2bac929a0f5d404ba9d2dc1ea031880930f1fd7a283f0a0cbebb35eac1a9ee0d1225f" +
        "5e0f181571",
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
        "c8c917e137a616d3d4e4c9fcd9c50202f366cb0d37862376bc79f9b72e8a8db9",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "33a5d4df232777008a06d0684f23bb891cfaef702f653c8601b6ad4d08dddddf",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "bed80f2e54f1285895c4a3f3b3625e6206f78f1ed329a0cfb5864f7c139b3c6a",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_chacha20poly1305 Base mode" {
  let suite = hpke_p256_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "f1f1a3bc95416871539ecb51c3a8f0cf608afb40fbbe305c0a72819d35c33f1f",
  )
  let pk_r = hex_to_bytes(
    "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c0" +
    "13806a790ec716ab8669f84f6b694596c2987cf35baba2a006",
  )
  let sk_r = hex_to_bytes(
    "a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b",
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
        "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c7" +
        "0cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
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
          "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea295" +
          "2a27bb458b",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea295" +
        "2a27bb458b",
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
          "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc54" +
          "6c9d114374",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "f1564199f7e0e110ec9c1bcdde332177fc35c1adf6e57f8d1df24022227ffa8716862dbda2b1dc54" +
        "6c9d114374",
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
          "39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592f" +
          "f87c3f310c",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "39de89728bcb774269f882af8dc5369e4f3d6322d986e872b3a8d074c7c18e8549ff3f85b6d6592f" +
        "f87c3f310c",
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
        "9b13c510416ac977b553bf1741018809c246a695f45eff6d3b0356dbefe1e660",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "6c8b7be3a20a5684edecb4253619d9051ce8583baf850e0cb53c402bdcaf8ebb",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "477a50d804c7c51941f69b8e32fe8288386ee1a84905fe4938d58972f24ac938",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_chacha20poly1305 PSK mode" {
  let suite = hpke_p256_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "e1a4e1d50c4bfcf890f2b4c7d6b2d2aca61368eddc3c84162df2856843e1057a",
  )
  let pk_r = hex_to_bytes(
    "041eb8f4f20ab72661af369ff3231a733672fa26f385ffb959fd1bae46bfda43ad55e2d573b88083" +
    "1381d9367417f554ce5b2134fbba5235b44db465feffc6189e",
  )
  let sk_r = hex_to_bytes(
    "12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3",
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
        "04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa805c1fec955e56266" +
        "3e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a7246",
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
          "21433eaff24d7706f3ed5b9b2e709b07230e2b11df1f2b1fe07b3c70d5948a53d6fa5c8bed194020" +
          "bd9df0877b",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "21433eaff24d7706f3ed5b9b2e709b07230e2b11df1f2b1fe07b3c70d5948a53d6fa5c8bed194020" +
        "bd9df0877b",
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
          "c74a764b4892072ea8c2c56b9bcd46c7f1e9ca8cb0a263f8b40c2ba59ac9c857033f176019562218" +
          "769d3e0452",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "c74a764b4892072ea8c2c56b9bcd46c7f1e9ca8cb0a263f8b40c2ba59ac9c857033f176019562218" +
        "769d3e0452",
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
          "dc8cd68863474d6e9cbb6a659335a86a54e036249d41acf909e738c847ff2bd36fe3fcacda4ededa" +
          "7032c0a220",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "dc8cd68863474d6e9cbb6a659335a86a54e036249d41acf909e738c847ff2bd36fe3fcacda4ededa" +
        "7032c0a220",
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
        "530bbc2f68f078dccc89cc371b4f4ade372c9472bafe4601a8432cbb934f528d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "6e25075ddcc528c90ef9218f800ca3dfe1b8ff4042de5033133adb8bd54c401d",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "6f6fbd0d1c7733f796461b3235a856cc34f676fe61ed509dfc18fa16efe6be78",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_chacha20poly1305 Auth mode" {
  let suite = hpke_p256_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "0ecd212019008138a31f9104d5dba76b9f8e34d5b996041fff9e3df221dd0d5d",
  )
  let pk_r = hex_to_bytes(
    "0444f6ee41818d9fe0f8265bffd016b7e2dd3964d610d0f7514244a60dbb7a11ece876bb110a97a2" +
    "ac6a9542d7344bf7d2bd59345e3e75e497f7416cf38d296233",
  )
  let sk_r = hex_to_bytes(
    "3cb2c125b8c5a81d165a333048f5dcae29a2ab2072625adad66dbb0f48689af9",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "39b19402e742d48d319d24d68e494daa4492817342e593285944830320912519",
  )
  let pk_s = hex_to_bytes(
    "04265529a04d4f46ab6fa3af4943774a9f1127821656a75a35fade898a9a1b014f64d874e88cddb2" +
    "4c1c3d79004d3a587db67670ca357ff4fba7e8b56ec013b98b",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5cbc5748b6be63597" +
        "60c73cfe10ca19521af704ca6d91ff32fc0739527b9385d415",
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
          "25881f219935eec5ba70d7b421f13c35005734f3e4d959680270f55d71e2f5cb3bd2daced2770bf3" +
          "d9d4916872",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "25881f219935eec5ba70d7b421f13c35005734f3e4d959680270f55d71e2f5cb3bd2daced2770bf3" +
        "d9d4916872",
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
          "653f0036e52a376f5d2dd85b3204b55455b7835c231255ae098d09ed138719b97185129786338ab6" +
          "543f753193",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "653f0036e52a376f5d2dd85b3204b55455b7835c231255ae098d09ed138719b97185129786338ab6" +
        "543f753193",
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
          "60878706117f22180c788e62df6a595bc41906096a11a9513e84f0141e43239e81a98d7a235abc64" +
          "112fcb8ddd",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "60878706117f22180c788e62df6a595bc41906096a11a9513e84f0141e43239e81a98d7a235abc64" +
        "112fcb8ddd",
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
        "56c4d6c1d3a46c70fd8f4ecda5d27c70886e348efb51bd5edeaa39ff6ce34389",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "d2d3e48ed76832b6b3f28fa84be5f11f09533c0e3c71825a34fb0f1320891b51",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "eb0d312b6263995b4c7761e64b688c215ffd6043ff3bad2368c862784cbe6eff",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 p256_hkdf_sha256_chacha20poly1305 AuthPSK mode" {
  let suite = hpke_p256_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "f3a07f194703e321ef1f753a1b9fe27a498dfdfa309151d70bedd896c239c499",
  )
  let pk_r = hex_to_bytes(
    "04d383fd920c42d018b9d57fd73a01f1eee480008923f67d35169478e55d2e8817068daf62a06b10" +
    "e0aad4a9e429fa7f904481be96b79a9c231a33e956c20b81b6",
  )
  let sk_r = hex_to_bytes(
    "c29fc577b7e74d525c0043f1c27540a1248e4f2c8d297298e99010a92e94865c",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "53541bd995f874a67f8bfd8038afa67fd68876801f42ff47d0dc2a4deea067ae",
  )
  let pk_s = hex_to_bytes(
    "0492cf8c9b144b742fe5a63d9a181a19d416f3ec8705f24308ad316564823c344e018bd7c03a33c9" +
    "26bb271b28ef5bf28c0ca00abff249fee5ef7f33315ff34fdb",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110f331400115855808" +
        "244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16f6",
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
          "9eadfa0f954835e7e920ffe56dec6b31a046271cf71fdda55db72926e1d8fae94cc6280fcfabd8db" +
          "71eaa65c05",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "9eadfa0f954835e7e920ffe56dec6b31a046271cf71fdda55db72926e1d8fae94cc6280fcfabd8db" +
        "71eaa65c05",
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
          "e357ad10d75240224d4095c9f6150a2ed2179c0f878e4f2db8ca95d365d174d059ff8c3eb38ea9a6" +
          "5cfc8eaeb8",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "e357ad10d75240224d4095c9f6150a2ed2179c0f878e4f2db8ca95d365d174d059ff8c3eb38ea9a6" +
        "5cfc8eaeb8",
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
          "2fa56d00f8dd479d67a2ec3308325cf3bbccaf102a64ffccdb006bd7dcb932685b9a7b49cdc094a8" +
          "5fec1da5ef",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "2fa56d00f8dd479d67a2ec3308325cf3bbccaf102a64ffccdb006bd7dcb932685b9a7b49cdc094a8" +
        "5fec1da5ef",
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
        "c52b4592cd33dd38b2a3613108ddda28dcf7f03d30f2a09703f758bfa8029c9a",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "2f03bebc577e5729e148554991787222b5c2a02b77e9b1ac380541f710e5a318",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "e01dd49e8bfc3d9216abc1be832f0418adf8b47a7b5a330a7436c31e33d765d7",
      ),
    ),
  )
}
