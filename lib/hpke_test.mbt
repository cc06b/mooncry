// HPKE official vectors (RFC 9180 Appendix A.1/A.2). v0.37.0.

///|
test "HPKE RFC9180 X25519+AES128GCM Base mode" {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
  )
  let pk_r = hex_to_bytes(
    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
  )
  let sk_r = hex_to_bytes(
    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
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
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 0, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea" +
          "87e13c512a",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea" +
        "87e13c512a",
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
  // sequence 1
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
          "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca" +
          "42c2063b84",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca" +
        "42c2063b84",
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
  // sequence 2
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
          "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a68351" +
          "8973dcc180",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a68351" +
        "8973dcc180",
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
        "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+AES128GCM PSK mode" {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b",
  )
  let pk_r = hex_to_bytes(
    "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366",
  )
  let sk_r = hex_to_bytes(
    "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd",
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
        "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 1, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4" +
          "cfc34db8ea",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4" +
        "cfc34db8ea",
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
  // sequence 1
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
          "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22c" +
          "d62437c8ba",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22c" +
        "d62437c8ba",
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
  // sequence 2
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
          "257ca6a08473dc851fde45afd598cc83e326ddd0abe1ef23baa3baa4dd8cde99fce2c1e8ce687b0b" +
          "47ead1adc9",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "257ca6a08473dc851fde45afd598cc83e326ddd0abe1ef23baa3baa4dd8cde99fce2c1e8ce687b0b" +
        "47ead1adc9",
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
        "dff17af354c8b41673567db6259fd6029967b4e1aad13023c2ae5df8f4f43bf6",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "6a847261d8207fe596befb52928463881ab493da345b10e1dcc645e3b94e2d95",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "8aff52b45a1be3a734bc7a41e20b4e055ad4c4d22104b0c20285a7c4302401cd",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+AES128GCM Auth mode" {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7",
  )
  let pk_r = hex_to_bytes(
    "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e",
  )
  let sk_r = hex_to_bytes(
    "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd",
  )
  let pk_s = hex_to_bytes(
    "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 2, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e2" +
          "1b680c141b",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e2" +
        "1b680c141b",
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
  // sequence 1
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
          "d3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd69" +
          "9f002bc8ed",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "d3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd69" +
        "9f002bc8ed",
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
  // sequence 2
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
          "122175cfd5678e04894e4ff8789e85dd381df48dcaf970d52057df2c9acc3b121313a2bfeaa98605" +
          "0f82d93645",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "122175cfd5678e04894e4ff8789e85dd381df48dcaf970d52057df2c9acc3b121313a2bfeaa98605" +
        "0f82d93645",
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
        "28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+AES128GCM AuthPSK mode" {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84",
  )
  let pk_r = hex_to_bytes(
    "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976",
  )
  let sk_r = hex_to_bytes(
    "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4",
  )
  let pk_s = hex_to_bytes(
    "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 3, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001" +
          "697737533e",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001" +
        "697737533e",
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
  // sequence 1
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
          "4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9" +
          "da127435d9",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9" +
        "da127435d9",
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
  // sequence 2
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
          "0c085a365fbfa63409943b00a3127abce6e45991bc653f182a80120868fc507e9e4d5e37bcc384fc" +
          "8f14153b24",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "0c085a365fbfa63409943b00a3127abce6e45991bc653f182a80120868fc507e9e4d5e37bcc384fc" +
        "8f14153b24",
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
        "08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+ChaCha20Poly1305 Base mode" {
  let suite = hpke_x25519_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
  )
  let pk_r = hex_to_bytes(
    "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  )
  let sk_r = hex_to_bytes(
    "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
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
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 0, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d" +
          "2dd1b51a28",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d" +
        "2dd1b51a28",
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
  // sequence 1
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
          "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f" +
          "59992dc98c",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f" +
        "59992dc98c",
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
  // sequence 2
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
          "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32" +
          "f878fae86b",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32" +
        "f878fae86b",
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
        "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+ChaCha20Poly1305 PSK mode" {
  let suite = hpke_x25519_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "35706a0b09fb26fb45c39c2f5079c709c7cf98e43afa973f14d88ece7e29c2e3",
  )
  let pk_r = hex_to_bytes(
    "13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062",
  )
  let sk_r = hex_to_bytes(
    "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
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
        "2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 1, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276" +
          "f4a89608ff",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276" +
        "f4a89608ff",
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
  // sequence 1
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
          "5c3cabae2f0b3e124d8d864c116fd8f20f3f56fda988c3573b40b09997fd6c769e77c8eda6cda4f9" +
          "47f5b704a8",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "5c3cabae2f0b3e124d8d864c116fd8f20f3f56fda988c3573b40b09997fd6c769e77c8eda6cda4f9" +
        "47f5b704a8",
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
  // sequence 2
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
          "14958900b44bdae9cbe5a528bf933c5c990dbb8e282e6e495adf8205d19da9eb270e3a6f1e0613ab" +
          "7e757962a4",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "14958900b44bdae9cbe5a528bf933c5c990dbb8e282e6e495adf8205d19da9eb270e3a6f1e0613ab" +
        "7e757962a4",
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
        "813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "2745cf3d5bb65c333658732954ee7af49eb895ce77f8022873a62a13c94cb4e1",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "ad40e3ae14f21c99bfdebc20ae14ab86f4ca2dc9a4799d200f43a25f99fa78ae",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+ChaCha20Poly1305 Auth mode" {
  let suite = hpke_x25519_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "938d3daa5a8904540bc24f48ae90eed3f4f7f11839560597b55e7c9598c996c0",
  )
  let pk_r = hex_to_bytes(
    "1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44",
  )
  let sk_r = hex_to_bytes(
    "3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82",
  )
  let psk = b""
  let psk_id = b""
  let sk_s = hex_to_bytes(
    "2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05",
  )
  let pk_s = hex_to_bytes(
    "f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 2, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 2, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347a" +
          "eb88e61bdf",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347a" +
        "eb88e61bdf",
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
  // sequence 1
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
          "3265c7807ffff7fdace21659a2c6ccffee52a26d270c76468ed74202a65478bfaedfff9c2b7634e2" +
          "4f10b71016",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "3265c7807ffff7fdace21659a2c6ccffee52a26d270c76468ed74202a65478bfaedfff9c2b7634e2" +
        "4f10b71016",
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
  // sequence 2
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
          "3aadee86ad2a05081ea860033a9d09dbccb4acac2ded0891da40f51d4df19925f7a767b076a5cbc9" +
          "355c8fd35e",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "3aadee86ad2a05081ea860033a9d09dbccb4acac2ded0891da40f51d4df19925f7a767b076a5cbc9" +
        "355c8fd35e",
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
        "070cffafd89b67b7f0eeb800235303a223e6ff9d1e774dce8eac585c8688c872",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "2852e728568d40ddb0edde284d36a4359c56558bb2fb8837cd3d92e46a3a14a8",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "1df39dc5dd60edcbf5f9ae804e15ada66e885b28ed7929116f768369a3f950ee",
      ),
    ),
  )
}

///|
test "HPKE RFC9180 X25519+ChaCha20Poly1305 AuthPSK mode" {
  let suite = hpke_x25519_hkdf_sha256_chacha20poly1305
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "49d6eac8c6c558c953a0a252929a818745bb08cd3d29e15f9f5db5eb2e7d4b84",
  )
  let pk_r = hex_to_bytes(
    "a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851",
  )
  let sk_r = hex_to_bytes(
    "7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c",
  )
  let psk = hex_to_bytes(
    "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
  )
  let psk_id = hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")
  let sk_s = hex_to_bytes(
    "90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418",
  )
  let pk_s = hex_to_bytes(
    "3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45",
  )
  let (enc, ctx_s) = hpke_setup_s(
    suite, 3, pk_r, ikm_e, info, psk, psk_id, sk_s,
  )
  assert_true(
    bytes_equal(
      enc,
      hex_to_bytes(
        "656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02",
      ),
    ),
  )
  let ctx_r = hpke_setup_r(suite, 3, sk_r, pk_r, enc, info, psk, psk_id, pk_s)
  // sequence 0
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
          "9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede0145" +
          "6ebc67d597",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d30"),
      hex_to_bytes(
        "9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede0145" +
        "6ebc67d597",
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
  // sequence 1
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
          "59460bacdbe7a920ef2806a74937d5a691d6d5062d7daafcad7db7e4d8c649adffe575c1889c5c2e" +
          "3a49af8e3e",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d31"),
      hex_to_bytes(
        "59460bacdbe7a920ef2806a74937d5a691d6d5062d7daafcad7db7e4d8c649adffe575c1889c5c2e" +
        "3a49af8e3e",
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
  // sequence 2
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
          "5688ff6a03ba26ae936044a5c800f286fb5d1eccdd2a0f268f6ff9773b51169318d1a1466bb36263" +
          "415071db00",
        ),
      ),
    )
  }
  match
    hpke_open(
      ctx_r,
      hex_to_bytes("436f756e742d32"),
      hex_to_bytes(
        "5688ff6a03ba26ae936044a5c800f286fb5d1eccdd2a0f268f6ff9773b51169318d1a1466bb36263" +
        "415071db00",
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
        "c23ebd4e7a0ad06a5dddf779f65004ce9481069ce0f0e6dd51a04539ddcbd5cd",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("00"), 32),
      hex_to_bytes(
        "ed7ff5ca40a3d84561067ebc8e01702bc36cf1eb99d42a92004642b9dfaadd37",
      ),
    ),
  )
  assert_true(
    bytes_equal(
      hpke_export(ctx_s, hex_to_bytes("54657374436f6e74657874"), 32),
      hex_to_bytes(
        "d3bae066aa8da27d527d85c040f7dd6ccb60221c902ee36a82f70bcd62a60ee4",
      ),
    ),
  )
}

///|
test "HPKE X448 round-trip (all modes structure)" {
  let suite = hpke_x448_hkdf_sha512_chacha20poly1305
  let ikm_r = Bytes::make(56, b'B')
  let ikm_e = Bytes::make(56, b'$')
  let (pk_r, sk_r) = hpke_derive_key_pair(suite, ikm_r)
  let info = b"mooncry x448 round-trip"
  let (enc, ctx_s) = hpke_setup_s(suite, 0, pk_r, ikm_e, info, b"", b"", b"")
  let ctx_r = hpke_setup_r(suite, 0, sk_r, pk_r, enc, info, b"", b"", b"")
  let msg = Bytes::make(300, b'X')
  let ct = hpke_seal(ctx_s, b"aad", msg)
  match hpke_open(ctx_r, b"aad", ct) {
    Some(pt) => assert_true(bytes_equal(pt, msg))
    None => assert_true(false)
  }
  assert_true(
    bytes_equal(hpke_export(ctx_s, b"ctx", 64), hpke_export(ctx_r, b"ctx", 64)),
  )
}
