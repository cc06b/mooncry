// ==================== RSA benchmarks (v0.21.0) ====================
// 1024-bit test key from rsa_test.mbt. CRT variants take (p, q, dP, dQ,
// qInv) — expect ~3.5-4x over the full-width private-key operation.

///|
test "bench RSA-1024 PKCS1-v1.5 sign" (it : @bench.T) {
  let msg = b"bench message for rsa sign"
  it.bench(fn() { it.keep(rsa_pkcs1_v15_sign(msg, rsa_test_n, rsa_test_d)) })
}

///|
test "bench RSA-1024 PKCS1-v1.5 sign CRT" (it : @bench.T) {
  let msg = b"bench message for rsa sign"
  it.bench(fn() {
    it.keep(
      rsa_pkcs1_v15_sign_crt(
        msg, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv,
      ),
    )
  })
}

///|
test "bench RSA-1024 PKCS1-v1.5 verify" (it : @bench.T) {
  let msg = b"bench message for rsa sign"
  let sig = rsa_pkcs1_v15_sign(msg, rsa_test_n, rsa_test_d)
  it.bench(fn() {
    it.keep(rsa_pkcs1_v15_verify(msg, sig, rsa_test_n, rsa_test_e))
  })
}

///|
test "bench RSA-1024 PSS sign" (it : @bench.T) {
  let msg = b"bench message for pss"
  let salt = Bytes::make(32, b'\x5a')
  it.bench(fn() { it.keep(rsa_pss_sign(msg, rsa_test_n, rsa_test_d, salt)) })
}

///|
test "bench RSA-1024 PSS sign CRT" (it : @bench.T) {
  let msg = b"bench message for pss"
  let salt = Bytes::make(32, b'\x5a')
  it.bench(fn() {
    it.keep(
      rsa_pss_sign_crt(
        msg, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv, salt,
      ),
    )
  })
}

///|
test "bench RSA-1024 OAEP decrypt" (it : @bench.T) {
  let msg = b"oaep bench"
  let seed = Bytes::make(32, b'\x33')
  let ct = rsa_oaep_encrypt(msg, rsa_test_n, rsa_test_e, seed, b"")
  it.bench(fn() { it.keep(rsa_oaep_decrypt(ct, rsa_test_n, rsa_test_d, b"")) })
}

///|
test "bench RSA-1024 OAEP decrypt CRT" (it : @bench.T) {
  let msg = b"oaep bench"
  let seed = Bytes::make(32, b'\x33')
  let ct = rsa_oaep_encrypt(msg, rsa_test_n, rsa_test_e, seed, b"")
  it.bench(fn() {
    it.keep(
      rsa_oaep_decrypt_crt(
        ct, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv, b"",
      ),
    )
  })
}

///|
test "bench RSA-1024 PKCS1-v1.5 decrypt" (it : @bench.T) {
  let msg = b"enc bench"
  let k = rsa_test_n.length()
  let ps = Bytes::make(k - msg.length() - 3, b'\x09')
  let ct = rsa_pkcs1_v15_encrypt(msg, rsa_test_n, rsa_test_e, ps)
  it.bench(fn() { it.keep(rsa_pkcs1_v15_decrypt(ct, rsa_test_n, rsa_test_d)) })
}

///|
test "bench RSA-1024 PKCS1-v1.5 decrypt CRT" (it : @bench.T) {
  let msg = b"enc bench"
  let k = rsa_test_n.length()
  let ps = Bytes::make(k - msg.length() - 3, b'\x09')
  let ct = rsa_pkcs1_v15_encrypt(msg, rsa_test_n, rsa_test_e, ps)
  it.bench(fn() {
    it.keep(
      rsa_pkcs1_v15_decrypt_crt(
        ct, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv,
      ),
    )
  })
}

///|
test "bench RSA-1024 PKCS1-v1.5 encrypt" (it : @bench.T) {
  let msg = b"enc bench"
  let k = rsa_test_n.length()
  let ps = Bytes::make(k - msg.length() - 3, b'\x09')
  it.bench(fn() {
    it.keep(rsa_pkcs1_v15_encrypt(msg, rsa_test_n, rsa_test_e, ps))
  })
}
