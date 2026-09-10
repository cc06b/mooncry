///|
fn sm2pem_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let a = Array::make(len, (0).to_byte())
  for i in 0..<len {
    a[i] = b[start + i]
  }
  Bytes::from_array(a[:])
}

// SM2 key serialization vectors: DER hexes and the PEM literal are exactly
// what openssl 3.2.4 produced/consumed in the GB-example interop run
// (gb.key.pem loads in openssl; gbp.pem is openssl pkey -pubout output,
// CRLF line endings included).

///|
test "sm2-sk-pkcs8-der-exact" {
  let der = sm2_sk_to_pkcs8_der(sm2_ex_sk())
  inspect(
    bytes_to_hex(der),
    content="308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b02010104203945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8a1440342000409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )
  let (sk, ok) = sm2_pkcs8_der_to_sk(der)
  inspect(ok, content="true")
  inspect(bytes_equal(sk, sm2_ex_sk()), content="true")
  // decoded key agrees with the GB example public key
  inspect(
    bytes_to_hex(sm2_public_key(sk)),
    content="0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )
}

///|
test "sm2-pk-spki-der-exact" {
  let pk = sm2_ex_pk()
  let der = sm2_pk_to_spki_der(pk)
  inspect(
    bytes_to_hex(der),
    content="3059301306072a8648ce3d020106082a811ccf5501822d0342000409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )
  let (back, ok) = sm2_spki_der_to_pk(der)
  inspect(ok, content="true")
  inspect(bytes_equal(back, pk), content="true")
}

///|
test "sm2-pem-roundtrip-and-openssl-literal" {
  // sk PEM roundtrip
  let pem = sm2_sk_to_pem(sm2_ex_sk())
  let (sk, ok) = sm2_sk_from_pem(pem)
  inspect(ok, content="true")
  inspect(bytes_equal(sk, sm2_ex_sk()), content="true")
  // pk PEM roundtrip
  let ppem = sm2_pk_to_pem(sm2_ex_pk())
  let (pk2, ok2) = sm2_pk_from_pem(ppem)
  inspect(ok2, content="true")
  inspect(bytes_equal(pk2, sm2_ex_pk()), content="true")
  // the literal PEM openssl wrote (with CRLF) must parse
  let ossl = "-----BEGIN PUBLIC KEY-----\r\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAECfnfMR5UIaFQ3X0WHkvFxnIXn60Y\r\nM/wHa7CP81bzUCDM6kkM4md1pS3G6nGMwapgCu0F+/NeCEpmMvYHLamtEw==\r\n-----END PUBLIC KEY-----\r\n"
  let (pk3, ok3) = sm2_pk_from_pem(ossl)
  inspect(ok3, content="true")
  inspect(bytes_equal(pk3, sm2_ex_pk()), content="true")
}

///|
test "sm2-key-decode-rejects" {
  let der = sm2_sk_to_pkcs8_der(sm2_ex_sk())
  // flipped curve OID byte
  let bad = Array::make(der.length(), (0).to_byte())
  for i in 0..<der.length() {
    bad[i] = der[i]
  }
  bad[25] = (bad[25].to_int() ^ 0xFF).to_byte()
  let (_, ok1) = sm2_pkcs8_der_to_sk(Bytes::from_array(bad[:]))
  inspect(ok1, content="false")
  // truncated
  let (_, ok2) = sm2_pkcs8_der_to_sk(sm2pem_slice(der, 0, 100))
  inspect(ok2, content="false")
  // trailing byte
  let longer = Array::make(der.length() + 1, (0).to_byte())
  for i in 0..<der.length() {
    longer[i] = der[i]
  }
  let (_, ok3) = sm2_pkcs8_der_to_sk(Bytes::from_array(longer[:]))
  inspect(ok3, content="false")
  // wrong header PEM
  let (_, ok4) = sm2_sk_from_pem(
    "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n",
  )
  inspect(ok4, content="false")
  // garbage body PEM
  let (_, ok5) = sm2_pk_from_pem(
    "-----BEGIN PUBLIC KEY-----\r\n!!!!\r\n-----END PUBLIC KEY-----\r\n",
  )
  inspect(ok5, content="false")
  // SPKI parse of a PKCS#8 blob must fail (and vice versa)
  let (_, ok6) = sm2_spki_der_to_pk(der)
  inspect(ok6, content="false")
  let (_, ok7) = sm2_pkcs8_der_to_sk(sm2_pk_to_spki_der(sm2_ex_pk()))
  inspect(ok7, content="false")
}
