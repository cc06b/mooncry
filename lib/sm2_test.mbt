// GB/T 32918.5-2017 standard example, values re-derived and verified by
// _sm2_extract.py against openssl-extracted curve parameters (see sm2_params.mbt).

///|
fn sm2_ex_sk() -> Bytes {
  hex_to_bytes(
    "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
  )
}

///|
fn sm2_ex_pk() -> Bytes {
  let out = Array::make(65, (0).to_byte())
  out[0] = (4).to_byte()
  let x = hex_to_bytes(
    "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020",
  )
  let y = hex_to_bytes(
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )
  for i in 0..<32 {
    out[1 + i] = x[i]
    out[33 + i] = y[i]
  }
  Bytes::from_array(out[:])
}

///|
fn sm2_ex_k() -> Bytes {
  hex_to_bytes(
    "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
  )
}

///|
fn sm2_ex_id() -> Bytes {
  b"1234567812345678"
}

///|
fn sm2_ex_msg() -> Bytes {
  b"message digest"
}

///|
fn sm2_ex_sig() -> Bytes {
  hex_to_bytes(
    "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa",
  )
}

///|
test "sm2-gb-example-keygen" {
  inspect(
    bytes_to_hex(sm2_public_key(sm2_ex_sk())),
    content="0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )
}

///|
test "sm2-gb-example-sign-fixed-k" {
  inspect(
    bytes_to_hex(
      sm2_sign_with_k(sm2_ex_sk(), sm2_ex_msg(), sm2_ex_id(), sm2_ex_k()),
    ),
    content="f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa",
  )
}

///|
test "sm2-gb-example-verify" {
  let sig = sm2_ex_sig()
  inspect(
    sm2_verify(sm2_ex_pk(), sm2_ex_msg(), sm2_ex_id(), sig),
    content="true",
  )
}

///|
test "sm2-reject-paths" {
  let sig = sm2_ex_sig()
  // tampered message
  inspect(
    sm2_verify(sm2_ex_pk(), b"message digesh", sm2_ex_id(), sig),
    content="false",
  )
  // wrong ID
  inspect(
    sm2_verify(sm2_ex_pk(), sm2_ex_msg(), b"8765432187654321", sig),
    content="false",
  )
  // flipped bit in r
  let bad = Array::make(64, (0).to_byte())
  for i in 0..<64 {
    bad[i] = sig[i]
  }
  bad[31] = (bad[31].to_int() ^ 1).to_byte()
  inspect(
    sm2_verify(
      sm2_ex_pk(),
      sm2_ex_msg(),
      sm2_ex_id(),
      Bytes::from_array(bad[:]),
    ),
    content="false",
  )
  // off-curve public key (x+1)
  let badpk = Array::make(65, (0).to_byte())
  let pk = sm2_ex_pk()
  for i in 0..<65 {
    badpk[i] = pk[i]
  }
  badpk[32] = (badpk[32].to_int() + 1).to_byte()
  inspect(
    sm2_verify(Bytes::from_array(badpk[:]), sm2_ex_msg(), sm2_ex_id(), sig),
    content="false",
  )
  // r out of range (all 0xff bytes = 2^256-1 > n)
  let big = Array::make(64, (0xFF).to_byte())
  inspect(
    sm2_verify(
      sm2_ex_pk(),
      sm2_ex_msg(),
      sm2_ex_id(),
      Bytes::from_array(big[:]),
    ),
    content="false",
  )
}

///|
fn sm2_test_rand(seed : Int) -> (Int) -> Bytes {
  fn(n) {
    let a = Array::make(n, (0).to_byte())
    for i in 0..<n {
      a[i] = ((seed * 31 + i * 17 + 5) % 251 + 1).to_byte()
    }
    Bytes::from_array(a[:])
  }
}

///|
test "sm2-random-roundtrip" {
  for seed in 1..<=3 {
    // sk from a simple pattern in [1, n-2]: small values are fine for tests
    let ska = Array::make(32, (0).to_byte())
    ska[31] = (seed * 7 + 3).to_byte()
    ska[30] = (seed * 11).to_byte()
    let sk = Bytes::from_array(ska[:])
    let pk = sm2_public_key(sk)
    let msg = Bytes::make(seed * 37, (0x61).to_byte())
    let sig = sm2_sign(sk, msg, sm2_ex_id(), sm2_test_rand(seed))
    inspect(sm2_verify(pk, msg, sm2_ex_id(), sig), content="true")
    // wrong message rejected
    inspect(sm2_verify(pk, b"other", sm2_ex_id(), sig), content="false")
  }
}

///|
fn sm2_ex_sig_hex() -> String {
  "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
}
