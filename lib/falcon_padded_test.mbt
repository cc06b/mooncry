// Falcon padded-form tests: padded signing = compact signature with
// zero fill to the fixed size; verification accepts both forms per
// the C padded/compact verifier semantics.

///|
fn pad_msg(len : Int) -> Bytes {
  let a : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    a.push(((i * 31) & 0xFF).to_byte())
  }
  Bytes::from_array(a)
}

///|
fn pad_rand_ctr(ctr : Int) -> (Int) -> Bytes {
  let r = falcon_test_rng_init()
  falcon_test_rng_set_ctr(r, ctr.to_uint64())
  fn(k : Int) -> Bytes {
    falcon_test_rng_bytes(r, k)
  }
}

test "falcon-padded-512-roundtrip" {
  // keypair from the official seed, then padded sign/verify
  let r = falcon_test_rng_init()
  let seed = falcon_test_rng_bytes(r, 48)
  let (pk, sk) = falcon512_keypair_from_seed(seed)
  let msg = pad_msg(17)
  let sig = falcon512_sign_padded(sk, msg, pad_rand_ctr(1))
  inspect(sig.length(), content="666")
  inspect(falcon512_verify(pk, sig, msg), content="true")
  // the compact form of the same signature also verifies
  let sig_c = falcon512_sign(sk, msg, pad_rand_ctr(1))
  inspect(falcon512_verify(pk, sig_c, msg), content="true")
  // padded = compact + zero fill
  let mut same = sig_c.length() <= 666
  for i = 0; i < sig_c.length(); i = i + 1 {
    if sig[i] != sig_c[i] {
      same = false
    }
  }
  for i = sig_c.length(); i < 666; i = i + 1 {
    if sig[i].to_int() != 0 {
      same = false
    }
  }
  inspect(same, content="true")
  // wrong-length padded body (extra zero byte beyond 666) must fail
  let too_long = Array::make(667, (0).to_byte())
  for i = 0; i < 666; i = i + 1 {
    too_long[i] = sig[i]
  }
  inspect(falcon512_verify(pk, Bytes::from_array(too_long), msg), content="false")
}
