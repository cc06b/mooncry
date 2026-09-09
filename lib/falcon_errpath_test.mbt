// Falcon error-path tests: malformed keys/signatures must be rejected
// without panics (cheap; no keygen required).

///|
test "falcon-errpath-verify" {
  let pk = m3_pk()
  let sig = m3_sig0()
  let msg = b""
  // wrong pk header
  let a1 : Array[Byte] = []
  for i = 0; i < pk.length(); i = i + 1 {
    a1.push(pk[i])
  }
  a1[0] = (0x0A).to_byte()
  inspect(falcon512_verify(Bytes::from_array(a1), sig, msg), content="false")
  // truncated pk
  let a2 : Array[Byte] = []
  for i = 0; i < 100; i = i + 1 {
    a2.push(pk[i])
  }
  inspect(falcon512_verify(Bytes::from_array(a2), sig, msg), content="false")
  // empty sig
  inspect(falcon512_verify(pk, b"", msg), content="false")
  // sig shorter than header+nonce
  inspect(
    falcon512_verify(pk, Bytes::from_array([(0x39).to_byte()]), msg),
    content="false",
  )
  // sig with wrong header
  let a3 : Array[Byte] = []
  for i = 0; i < sig.length(); i = i + 1 {
    a3.push(sig[i])
  }
  a3[0] = (0x38).to_byte()
  inspect(falcon512_verify(pk, Bytes::from_array(a3), msg), content="false")
  // corrupted comp body (non-canonical trailing bits) -> decode failure
  let a4 : Array[Byte] = []
  for i = 0; i < sig.length(); i = i + 1 {
    a4.push(sig[i])
  }
  let last = a4.length() - 1
  a4[last] = (a4[last].to_int() | 1).to_byte()
  inspect(falcon512_verify(pk, Bytes::from_array(a4), msg), content="false")
}

///|
test "falcon-errpath-sign" {
  // malformed sk: wrong header
  let r = falcon_test_rng_init()
  let rand = fn(k : Int) -> Bytes { falcon_test_rng_bytes(r, k) }
  let bad_sk = Bytes::from_array([(0x58).to_byte()])
  inspect(falcon512_sign(bad_sk, b"msg", rand).length(), content="0")
  // right header, wrong length
  let sk2 = Array::make(100, (0).to_byte())
  sk2[0] = (0x59).to_byte()
  inspect(
    falcon512_sign(Bytes::from_array(sk2), b"msg", rand).length(),
    content="0",
  )
}
