// ==================== Robustness fuzz: untrusted input ====================
//
// Reliability net for every public entry point that consumes bytes crossing a
// trust boundary (peer ciphertexts/signatures/public keys, decoded strings).
// Two properties are checked:
//
//   1. NO TRAP — a hostile blob must never abort or run off the end of an
//      array. A trap in a long-lived process is a denial of service, and on
//      wasm/native it kills the whole embedding application. Reaching the end
//      of these tests at all is the assertion.
//   2. NO FALSE ACCEPT — a mutated authentic value must be rejected
//      (false / None / Err), never handed back as valid.
//
// Everything is driven by a fixed xorshift64* PRNG, so a failure reproduces
// byte-for-byte on every target (wasm32, native64, js) and every run.

///|
struct RbRng {
  mut s : UInt64
}

///|
fn rb_rng(seed : UInt64) -> RbRng {
  { s: seed, }
}

///|
/// xorshift64* — deterministic, dependency-free, plenty for fuzzing.
fn rb_next(r : RbRng) -> UInt64 {
  let mut x = r.s
  x = x ^ (x >> 12)
  x = x ^ (x << 25)
  x = x ^ (x >> 27)
  r.s = x
  x * 0x2545F4914F6CDD1DUL
}

///|
/// Uniform-ish value in 0..<n (n <= 0 yields 0).
fn rb_upto(r : RbRng, n : Int) -> Int {
  if n <= 0 {
    0
  } else {
    (rb_next(r) % n.to_uint64()).to_int()
  }
}

///|
fn rb_bytes(r : RbRng, n : Int) -> Bytes {
  let a = Array::make(n, b'\x00')
  let mut i = 0
  while i < n {
    let w = rb_next(r)
    for k in 0..<8 {
      if i + k < n {
        a[i + k] = ((w >> (k * 8)) & 0xFFUL).to_int().to_byte()
      }
    }
    i = i + 8
  }
  Bytes::from_array(a)
}

///|
fn rb_slice(data : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = data[start + i]
  }
  Bytes::from_array(out)
}

///|
fn rb_cat(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(a.length() + b.length(), b'\x00')
  for i in 0..<a.length() {
    out[i] = a[i]
  }
  for i in 0..<b.length() {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out)
}

///|
/// Bytes content equality (`==` on Bytes is a reference comparison).
fn rb_eq(a : Bytes, b : Bytes) -> Bool {
  bytes_equal(a, b)
}

///|
/// Length-changing mutation: truncation, head drop, extension.
fn rb_resize(r : RbRng, data : Bytes) -> Bytes {
  let n = data.length()
  match rb_upto(r, 4) {
    0 => rb_slice(data, 0, rb_upto(r, n + 1))
    1 =>
      if n == 0 {
        data
      } else {
        let k = rb_upto(r, n)
        rb_slice(data, k, n - k)
      }
    2 => rb_cat(data, rb_bytes(r, 1 + rb_upto(r, 24)))
    _ =>
      if n == 0 {
        rb_bytes(r, 1 + rb_upto(r, 8))
      } else {
        rb_cat(rb_bytes(r, 1 + rb_upto(r, 4)), data)
      }
  }
}

///|
/// Length-preserving mutation: bit flip, byte replace, byte swap, wipe.
fn rb_flip(r : RbRng, data : Bytes) -> Bytes {
  let n = data.length()
  if n == 0 {
    return data
  }
  let a = data.to_array()
  match rb_upto(r, 4) {
    0 => {
      let i = rb_upto(r, n)
      a[i] = (a[i].to_int() ^ (1 << rb_upto(r, 8))).to_byte()
    }
    1 => {
      let i = rb_upto(r, n)
      a[i] = rb_upto(r, 256).to_byte()
    }
    2 => {
      let i = rb_upto(r, n)
      let j = rb_upto(r, n)
      let t = a[i]
      a[i] = a[j]
      a[j] = t
    }
    _ =>
      for i in 0..<n {
        a[i] = (if rb_upto(r, 2) == 0 { 0 } else { 0xFF }).to_byte()
      }
  }
  Bytes::from_array(a)
}

///|
/// Length-preserving hostile set (plus the unmodified value first). Use for
/// APIs whose parameter *lengths* are a documented contract (they abort on a
/// wrong-length key/nonce/tag) but whose *content* is attacker-controlled.
fn rb_flips(r : RbRng, data : Bytes, rounds : Int) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let n = data.length()
  out.push(data)
  if n > 1 {
    out.push(Bytes::make(n, b'\x00'))
    out.push(Bytes::make(n, b'\xff'))
    out.push(rb_cat(rb_slice(data, 1, n - 1), rb_slice(data, 0, 1)))
  }
  for _i in 0..<rounds {
    out.push(rb_flip(r, data))
  }
  out
}

///|
/// The full hostile set: edge cases, resizes and flips. Use for APIs that
/// report malformed input as a value (Bool / Option / Result) rather than
/// aborting.
fn rb_cases(r : RbRng, data : Bytes, rounds : Int) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let n = data.length()
  out.push(b"")
  out.push(Bytes::make(1, b'\x00'))
  out.push(Bytes::make(1, b'\xff'))
  out.push(Bytes::make(n, b'\x00'))
  out.push(Bytes::make(n, b'\xff'))
  if n > 0 {
    out.push(rb_slice(data, 0, n - 1))
    out.push(rb_slice(data, 1, n - 1))
  }
  out.push(data)
  for _i in 0..<rounds {
    out.push(
      if rb_upto(r, 2) == 0 {
        rb_resize(r, data)
      } else {
        rb_flip(r, data)
      },
    )
  }
  out
}

///|
/// Random blobs of exactly `n` bytes plus length-preserving mutations of one:
/// hostile input that still passes the outer length gate, so the parser runs
/// deep instead of bouncing off the first check.
fn rb_deep(r : RbRng, n : Int, rounds : Int) -> Array[Bytes] {
  let base = rb_bytes(r, n)
  let out : Array[Bytes] = [base]
  for _i in 0..<rounds {
    out.push(rb_flip(r, base))
  }
  out
}

// ---------- ML-DSA ----------

///|
test "robust-ml-dsa-verify" {
  let r = rb_rng(0x4D4C445341UL)
  let seed = rb_bytes(r, 32)
  let (pk, sk) = ml_dsa_44_keygen(seed)
  let sig_sz = 2420
  let msg = b"robustness"
  // hostile pk (any length) x well-formed-length random sig
  for p in rb_cases(r, pk, 8) {
    for s in rb_deep(r, sig_sz, 2) {
      assert_false(ml_dsa_44_verify(p, msg, s, b""))
    }
  }
  // real pk x hostile sig of every length
  for s in rb_cases(r, rb_bytes(r, sig_sz), 12) {
    assert_false(ml_dsa_44_verify(pk, msg, s, b""))
    assert_false(ml_dsa_44_verify_mu(pk, rb_bytes(r, 64), s))
  }
  // an authentic signature still verifies, and any change to it does not
  let rnd = rb_bytes(r, 32)
  let good = ml_dsa_44_sign(sk, msg, rnd, b"")
  assert_true(
    ml_dsa_44_verify(pk, msg, good, b""),
    msg="ml-dsa: good sig rejected",
  )
  for s in rb_flips(r, good, 8) {
    if !rb_eq(s, good) {
      assert_false(ml_dsa_44_verify(pk, msg, s, b""))
    }
  }
}

// ---------- SLH-DSA ----------

///|
test "robust-slh-verify" {
  let r = rb_rng(0x534C48445341UL)
  let p = slh_sha2_128s
  // SLH-DSA-SHA2-128s (FIPS 205 Table 3): n = 16, pk = 2n = 32 bytes,
  // sig = 7856 bytes. Hardcoded because the parameter struct is abstract
  // outside the library package.
  let n = 16
  let sig_sz = 7856
  let (pk, sk) = slh_keygen(p, rb_bytes(r, n), rb_bytes(r, n), rb_bytes(r, n))
  let _ = sk
  let msg = b"robustness"
  for pk_h in rb_cases(r, pk, 8) {
    for sig in rb_deep(r, sig_sz, 2) {
      assert_false(slh_verify(p, pk_h, msg, sig, b""))
      assert_false(slh_verify_raw(p, pk_h, msg, sig))
    }
  }
  for sig in rb_cases(r, rb_bytes(r, sig_sz), 10) {
    assert_false(slh_verify(p, pk, msg, sig, b""))
  }
}

// ---------- Falcon ----------

///|
test "robust-falcon-verify" {
  let r = rb_rng(0x46414C434FUL)
  let pk = m3_pk()
  let sig = m3_sig0()
  let msg = b""
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(falcon512_verify(pk_h, sig, msg))
    }
  }
  for sig_h in rb_cases(r, sig, 14) {
    if !rb_eq(sig_h, sig) {
      assert_false(falcon512_verify(pk, sig_h, msg))
    }
  }
  // deep hostile bodies at every plausible compressed length
  for len in [1, 8, 40, 100, 300, 600, 690] {
    for b in rb_deep(r, len, 3) {
      let head = Bytes::from_array([(0x38).to_byte()])
      assert_false(falcon512_verify(pk, rb_cat(head, b), msg))
      assert_false(falcon512_verify(pk, b, msg))
    }
  }
  // the raw public decoders must never run off the end either
  for b in rb_cases(r, rb_bytes(r, 897), 10) {
    let _ = falcon_modq_decode(b, 9).length()
    let _ = falcon_comp_decode(b, 9).length()
    let _ = falcon_trim_decode(b, 9, 8).length()
    let _ = falcon_trim_decode(b, 9, 14).length()
    let _ = falcon_trim_decode(b, 9, 16).length()
  }
}

// ---------- Ed25519 / Ed448 / ECDSA / SM2 ----------

///|
test "robust-ed-verify" {
  let r = rb_rng(0x45443235353139UL)
  let seed = rb_bytes(r, 32)
  let pk = ed25519_public_key(seed)
  let sig = ed25519_sign(seed, b"robust")
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(ed25519_verify(pk_h, b"robust", sig))
    }
  }
  for sig_h in rb_cases(r, sig, 12) {
    if !rb_eq(sig_h, sig) {
      assert_false(ed25519_verify(pk, b"robust", sig_h))
      assert_false(ed25519ctx_verify(pk, b"robust", sig_h, b"ctx"))
    }
  }
  assert_true(
    ed25519_verify(pk, b"robust", sig),
    msg="ed25519: good sig rejected",
  )
  for sig_h in rb_flips(r, sig, 6) {
    if !rb_eq(sig_h, sig) {
      assert_false(ed25519_verify(pk, b"robust", sig_h))
    }
  }
  // Ed448
  let seed4 = rb_bytes(r, 57)
  let pk4 = ed448_public_key(seed4)
  let sig4 = ed448_sign(seed4, b"robust")
  for pk_h in rb_cases(r, pk4, 8) {
    if !rb_eq(pk_h, pk4) {
      assert_false(ed448_verify(pk_h, b"robust", sig4))
    }
  }
  for sig_h in rb_cases(r, sig4, 10) {
    if !rb_eq(sig_h, sig4) {
      assert_false(ed448_verify(pk4, b"robust", sig_h))
      assert_false(ed448_verify_ctx(pk4, b"robust", sig_h, b"ctx"))
    }
  }
  assert_true(
    ed448_verify(pk4, b"robust", sig4),
    msg="ed448: good sig rejected",
  )
}

///|
test "robust-ecdsa-verify" {
  let r = rb_rng(0x454344534150UL)
  let d = rb_bytes(r, 32)
  let pk = ecdsa_p256_public_key(d)
  let msg = b"robust"
  let sig = ecdsa_p256_sign(d, msg)
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(ecdsa_p256_verify(pk_h, msg, sig))
    }
  }
  for sig_h in rb_cases(r, sig, 12) {
    if !rb_eq(sig_h, sig) {
      assert_false(ecdsa_p256_verify(pk, msg, sig_h))
    }
  }
  assert_true(
    ecdsa_p256_verify(pk, msg, sig),
    msg="ecdsa-p256: good sig rejected",
  )
  let pk_k = ecdsa_secp256k1_public_key(d)
  let sig_k = ecdsa_secp256k1_sign(d, msg)
  for pk_h in rb_cases(r, pk_k, 8) {
    if !rb_eq(pk_h, pk_k) {
      assert_false(ecdsa_secp256k1_verify(pk_h, msg, sig_k))
    }
  }
  for sig_h in rb_cases(r, sig_k, 10) {
    if !rb_eq(sig_h, sig_k) {
      assert_false(ecdsa_secp256k1_verify(pk_k, msg, sig_h))
    }
  }
  assert_true(
    ecdsa_secp256k1_verify(pk_k, msg, sig_k),
    msg="ecdsa-k1: good sig rejected",
  )
}

///|
test "robust-sm2-verify" {
  let r = rb_rng(0x534D32534947UL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let id = b"1234567812345678"
  let msg = b"robust"
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let sig = sm2_sign(sk, msg, id, rand)
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(sm2_verify(pk_h, msg, id, sig))
    }
  }
  for sig_h in rb_cases(r, sig, 12) {
    if !rb_eq(sig_h, sig) {
      assert_false(sm2_verify(pk, msg, id, sig_h))
    }
  }
  assert_true(sm2_verify(pk, msg, id, sig), msg="sm2: good sig rejected")
  for id_h in rb_cases(r, id, 6) {
    if !rb_eq(id_h, id) {
      assert_false(sm2_verify(pk, msg, id_h, sig))
    }
  }
}

// ---------- LMS / HSS / XMSS ----------

///|
test "robust-lms-hss-verify" {
  let r = rb_rng(0x4C4D53485353UL)
  let seed = rb_bytes(r, 32)
  let id = rb_slice(seed, 0, 16)
  let sk = lms_keygen(5, 4, seed, id)
  let pk = lms_public_key(sk)
  let msg = b"robust"
  let sig = lms_sign(sk, msg, None)
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(lms_verify(pk_h, msg, sig))
    }
  }
  for sig_h in rb_cases(r, sig, 14) {
    if !rb_eq(sig_h, sig) {
      assert_false(lms_verify(pk, msg, sig_h))
    }
  }
  assert_true(lms_verify(pk, msg, sig), msg="lms: good sig rejected")
  let s1 = rb_bytes(r, 32)
  let hsk = hss_keygen([
    (5, 4, seed, rb_slice(seed, 0, 16)),
    (5, 3, s1, rb_slice(s1, 0, 16)),
  ])
  let hpk = hss_public_key(hsk)
  let hsig = hss_sign(hsk, msg, None)
  for pk_h in rb_cases(r, hpk, 8) {
    if !rb_eq(pk_h, hpk) {
      assert_false(hss_verify(pk_h, msg, hsig))
    }
  }
  for sig_h in rb_cases(r, hsig, 12) {
    if !rb_eq(sig_h, hsig) {
      assert_false(hss_verify(hpk, msg, sig_h))
    }
  }
  assert_true(hss_verify(hpk, msg, hsig), msg="hss: good sig rejected")
}

///|
test "robust-xmss-verify" {
  let r = rb_rng(0x584D53535254UL)
  // small but multi-layer: full_height 4 = tree_height 2 x d 2
  let p = xmss_params(0, 32, 4, 2, 2)
  let seed = rb_bytes(r, 96) // 3 * n, n = 32
  let sk = xmss_keygen_from_seed(p, seed)
  let pk = xmss_public_key(sk)
  let msg = b"robust"
  let sig = xmss_sign(sk, msg)
  for pk_h in rb_cases(r, pk, 10) {
    if !rb_eq(pk_h, pk) {
      assert_false(xmss_verify(p, pk_h, msg, sig))
    }
  }
  for sig_h in rb_cases(r, sig, 14) {
    if !rb_eq(sig_h, sig) {
      assert_false(xmss_verify(p, pk, msg, sig_h))
    }
  }
  assert_true(xmss_verify(p, pk, msg, sig), msg="xmss: good sig rejected")
}

// ---------- AEAD: no trap, no false accept ----------

///|
test "robust-aead-authenticity" {
  let r = rb_rng(0x414541444655UL)
  let key32 = rb_bytes(r, 32)
  let key16 = rb_slice(key32, 0, 16)
  let nonce12 = rb_bytes(r, 12)
  let nonce24 = rb_bytes(r, 24)
  let aad = rb_bytes(r, 21)
  let pt = rb_bytes(r, 137)
  // ChaCha20-Poly1305
  let cp_box = chacha20_poly1305_encrypt(key32, nonce12, aad, pt)
  match chacha20_poly1305_decrypt_or(key32, nonce12, aad, cp_box) {
    Ok(got) => assert_true(rb_eq(got, pt))
    Err(_) =>
      assert_true(false, msg="chacha20_poly1305: authentic input rejected")
  }
  for c in rb_cases(r, cp_box, 14) {
    match chacha20_poly1305_decrypt_or(key32, nonce12, aad, c) {
      Ok(got) =>
        assert_true(
          rb_eq(c, cp_box) && rb_eq(got, pt),
          msg="chacha20_poly1305: forged input accepted",
        )
      Err(_) => ()
    }
    // a hostile key / nonce / aad must never authenticate the real cp_box box
    for k in rb_flips(r, key32, 3) {
      match chacha20_poly1305_decrypt_or(k, nonce12, aad, cp_box) {
        Ok(_) =>
          assert_true(
            rb_eq(k, key32),
            msg="chacha20_poly1305: wrong key accepted",
          )
        Err(_) => ()
      }
    }
    for nn in rb_flips(r, nonce12, 3) {
      match chacha20_poly1305_decrypt_or(key32, nn, aad, cp_box) {
        Ok(_) =>
          assert_true(
            rb_eq(nn, nonce12),
            msg="chacha20_poly1305: wrong nonce accepted",
          )
        Err(_) => ()
      }
    }
    for a in rb_flips(r, aad, 3) {
      match chacha20_poly1305_decrypt_or(key32, nonce12, a, cp_box) {
        Ok(_) =>
          assert_true(
            rb_eq(a, aad),
            msg="chacha20_poly1305: wrong aad accepted",
          )
        Err(_) => ()
      }
    }
  }
  // XChaCha20-Poly1305
  let xcp_box = xchacha20_poly1305_encrypt(key32, nonce24, aad, pt)
  match xchacha20_poly1305_decrypt_or(key32, nonce24, aad, xcp_box) {
    Ok(got) => assert_true(rb_eq(got, pt))
    Err(_) => assert_true(false, msg="xchacha20_poly1305: authentic rejected")
  }
  for c in rb_cases(r, xcp_box, 10) {
    match xchacha20_poly1305_decrypt_or(key32, nonce24, aad, c) {
      Ok(got) =>
        assert_true(
          rb_eq(c, xcp_box) && rb_eq(got, pt),
          msg="xchacha20_poly1305: forged input accepted",
        )
      Err(_) => ()
    }
  }
  // AES-CCM (mac_len 8 and 16)
  for mac_len in [8, 16] {
    let nonce11 = rb_bytes(r, 11)
    let ccp_box = aes_ccm_encrypt(pt, key16, nonce11, aad, mac_len)
    match aes_ccm_decrypt_or(ccp_box, key16, nonce11, aad, mac_len) {
      Ok(got) => assert_true(rb_eq(got, pt))
      Err(_) => assert_true(false, msg="aes_ccm: authentic input rejected")
    }
    for c in rb_cases(r, ccp_box, 10) {
      match aes_ccm_decrypt_or(c, key16, nonce11, aad, mac_len) {
        Ok(got) =>
          assert_true(
            rb_eq(c, ccp_box) && rb_eq(got, pt),
            msg="aes_ccm: forged input accepted",
          )
        Err(_) => ()
      }
    }
  }
  // AES-GCM (Bool convention)
  let (gct, gtag) = aes_gcm_encrypt(pt, key16, nonce12, aad)
  let (got, ok) = aes_gcm_decrypt(gct, key16, nonce12, aad, gtag)
  assert_true(ok)
  assert_true(rb_eq(got, pt))
  for c in rb_flips(r, gct, 8) {
    let (_, ok2) = aes_gcm_decrypt(c, key16, nonce12, aad, gtag)
    if !rb_eq(c, gct) {
      assert_false(ok2)
    }
  }
  for t in rb_flips(r, gtag, 8) {
    let (_, ok3) = aes_gcm_decrypt(gct, key16, nonce12, aad, t)
    if !rb_eq(t, gtag) {
      assert_false(ok3)
    }
  }
  // SM4-GCM
  let (sct, stag) = sm4_gcm_encrypt(pt, key16, nonce12, aad)
  let (sgot, sok) = sm4_gcm_decrypt(sct, key16, nonce12, aad, stag)
  assert_true(sok)
  assert_true(rb_eq(sgot, pt))
  for t in rb_flips(r, stag, 6) {
    let (_, ok4) = sm4_gcm_decrypt(sct, key16, nonce12, aad, t)
    if !rb_eq(t, stag) {
      assert_false(ok4)
    }
  }
  // AES-GCM-SIV (Option convention)
  let siv_ct = aes_gcm_siv_encrypt(key16, nonce12, aad, pt)
  match aes_gcm_siv_decrypt(key16, nonce12, aad, siv_ct) {
    Some(g) => assert_true(rb_eq(g, pt))
    None => assert_true(false, msg="aes_gcm_siv: authentic input rejected")
  }
  for c in rb_cases(r, siv_ct, 10) {
    match aes_gcm_siv_decrypt(key16, nonce12, aad, c) {
      Some(g) =>
        assert_true(
          rb_eq(c, siv_ct) && rb_eq(g, pt),
          msg="aes_gcm_siv: forged input accepted",
        )
      None => ()
    }
  }
  // AES-SIV (Result convention)
  let siv2 = aes_siv_encrypt(key32, pt, [aad])
  match aes_siv_decrypt(siv2, key32, [aad]) {
    Ok(g) => assert_true(rb_eq(g, pt))
    Err(_) => assert_true(false, msg="aes_siv: authentic input rejected")
  }
  for c in rb_cases(r, siv2, 10) {
    match aes_siv_decrypt(c, key32, [aad]) {
      Ok(g) =>
        assert_true(
          rb_eq(c, siv2) && rb_eq(g, pt),
          msg="aes_siv: forged input accepted",
        )
      Err(_) => ()
    }
  }
  // AES-KW (Result convention; the wrapped length itself is hostile)
  let wrapped = aes_kw_wrap(key16, rb_bytes(r, 32))
  match aes_kw_unwrap(key16, wrapped) {
    Ok(g) => assert_true(g.length() == 32)
    Err(_) => assert_true(false, msg="aes_kw: authentic wrap rejected")
  }
  for c in rb_cases(r, wrapped, 12) {
    match aes_kw_unwrap(key16, c) {
      Ok(g) =>
        assert_true(
          rb_eq(c, wrapped) && g.length() == 32,
          msg="aes_kw: forged wrap accepted",
        )
      Err(_) => ()
    }
  }
  // GMAC (Bool convention; the tag length is a contract)
  let tag = gmac(key16, nonce12, aad)
  assert_true(gmac_verify(key16, nonce12, aad, tag))
  for t in rb_flips(r, tag, 8) {
    if !rb_eq(t, tag) {
      assert_false(gmac_verify(key16, nonce12, aad, t))
    }
  }
  // cp_box box (Result convention)
  let mk = rb_bytes(r, 32)
  let env = sealed_box_seal(mk, nonce12, pt, aad, b"ctx")
  match sealed_box_open(mk, env, aad, b"ctx") {
    Ok(g) => assert_true(rb_eq(g, pt))
    Err(_) => assert_true(false, msg="cp_box_box: authentic envelope rejected")
  }
  for e in rb_cases(r, env, 12) {
    match sealed_box_open(mk, e, aad, b"ctx") {
      Ok(g) =>
        assert_true(
          rb_eq(e, env) && rb_eq(g, pt),
          msg="cp_box_box: forged envelope accepted",
        )
      Err(_) => ()
    }
  }
  for k in rb_cases(r, mk, 6) {
    match sealed_box_open(k, env, aad, b"ctx") {
      Ok(_) =>
        assert_true(rb_eq(k, mk), msg="cp_box_box: wrong master key accepted")
      Err(_) => ()
    }
  }
}

// ---------- CBC: strict padding must reject, not silently pass through ----------

///|
test "robust-cbc-padding" {
  let r = rb_rng(0x434243504144UL)
  let key = rb_bytes(r, 16)
  let iv = rb_bytes(r, 16)
  let pt = rb_bytes(r, 100)
  // aes_encrypt_cbc emits iv || ciphertext, matching aes_decrypt_cbc's shape
  let ct = aes_encrypt_cbc(pt, key, iv)
  match aes_decrypt_cbc_or(ct, key, iv) {
    Ok(got) => assert_true(rb_eq(got, pt))
    Err(_) =>
      assert_true(false, msg="aes_decrypt_cbc_or: authentic ct rejected")
  }
  // tampering must either be rejected outright or yield different plaintext
  let mut rejected = 0
  for c in rb_flips(r, ct, 16) {
    match aes_decrypt_cbc_or(c, key, iv) {
      Ok(got) =>
        if !rb_eq(c, ct) {
          assert_false(
            rb_eq(got, pt),
            msg="aes_decrypt_cbc_or: tampered ct returned the original plaintext",
          )
        }
      Err(_) => rejected = rejected + 1
    }
  }
  assert_true(rejected > 0, msg="aes_decrypt_cbc_or: no tamper was detected")
  // hostile lengths and keys are Err, never a trap
  for c in rb_cases(r, ct, 10) {
    match aes_decrypt_cbc_or(c, key, iv) {
      Ok(_) => ()
      Err(_) => ()
    }
  }
  for k in rb_cases(r, key, 6) {
    match aes_decrypt_cbc_or(ct, k, iv) {
      Ok(_) => ()
      Err(_) => ()
    }
  }
  // SM4-CBC raw
  let body = rb_bytes(r, 32)
  let sct = sm4_cbc_encrypt(key, iv, body)
  match sm4_cbc_decrypt_or(key, iv, sct) {
    Ok(g) => assert_true(rb_eq(g, body))
    Err(_) =>
      assert_true(false, msg="sm4_cbc_decrypt_or: authentic ct rejected")
  }
  for c in rb_cases(r, sct, 10) {
    match sm4_cbc_decrypt_or(key, iv, c) {
      Ok(_) => ()
      Err(_) => ()
    }
  }
}

// ---------- KEM / PKE ----------

///|
test "robust-kem" {
  let r = rb_rng(0x4B454D524F42UL)
  let d = rb_bytes(r, 32)
  let z = rb_bytes(r, 32)
  let (ek512, dk512) = ml_kem_512_keygen(d, z)
  let (ek768, dk768) = ml_kem_768_keygen(d, z)
  let (ek1024, dk1024) = ml_kem_1024_keygen(d, z)
  let m = rb_bytes(r, 32)
  let (k512, c512) = ml_kem_512_encaps(ek512, m)
  match ml_kem_512_decaps_or(dk512, c512) {
    Ok(k) => assert_true(rb_eq(k, k512))
    Err(_) => assert_true(false, msg="ml_kem_512: authentic ct rejected")
  }
  // hostile c: always decapsulates (implicit rejection) at the right length,
  // never traps, and never yields the real shared secret
  for c in rb_cases(r, c512, 12) {
    match ml_kem_512_decaps_or(dk512, c) {
      Ok(k) => {
        assert_true(k.length() == 32)
        if !rb_eq(c, c512) {
          assert_false(rb_eq(k, k512), msg="ml_kem_512: forged ct gave the key")
        }
      }
      Err(_) => assert_false(c.length() == c512.length())
    }
  }
  // hostile dk / ek
  for dk in rb_cases(r, dk512, 8) {
    match ml_kem_512_decaps_or(dk, c512) {
      Ok(k) => assert_true(k.length() == 32)
      Err(_) => assert_false(dk.length() == dk512.length())
    }
  }
  for ek in rb_cases(r, ek768, 8) {
    match ml_kem_768_encaps_or(ek, m) {
      Ok(pair) => assert_true(pair.1.length() == 1088)
      Err(_) => assert_false(ek.length() == ek768.length())
    }
  }
  // 768 / 1024 round trips + one hostile pass each
  let (k768, c768) = ml_kem_768_encaps(ek768, m)
  match ml_kem_768_decaps_or(dk768, c768) {
    Ok(k) => assert_true(rb_eq(k, k768))
    Err(_) => assert_true(false, msg="ml_kem_768: authentic ct rejected")
  }
  for c in rb_cases(r, c768, 6) {
    let _ = ml_kem_768_decaps_or(dk768, c)
  }
  let (k1024, c1024) = ml_kem_1024_encaps(ek1024, m)
  match ml_kem_1024_decaps_or(dk1024, c1024) {
    Ok(k) => assert_true(rb_eq(k, k1024))
    Err(_) => assert_true(false, msg="ml_kem_1024: authentic ct rejected")
  }
  for c in rb_cases(r, c1024, 6) {
    let _ = ml_kem_1024_decaps_or(dk1024, c)
  }
  // hybrid envelope: hostile blob or hostile dk must be None, never a trap
  let blob = ml_kem_512_hybrid_seal(ek512, m, b"aad", b"payload")
  match ml_kem_512_hybrid_open(dk512, blob, b"aad") {
    Some(g) => assert_true(rb_eq(g, b"payload"))
    None => assert_true(false, msg="ml_kem_hybrid: authentic blob rejected")
  }
  for e in rb_cases(r, blob, 12) {
    match ml_kem_512_hybrid_open(dk512, e, b"aad") {
      Some(g) =>
        assert_true(
          rb_eq(e, blob) && rb_eq(g, b"payload"),
          msg="ml_kem_hybrid: forged blob accepted",
        )
      None => ()
    }
  }
  for dk in rb_cases(r, dk512, 8) {
    match ml_kem_512_hybrid_open(dk, blob, b"aad") {
      Some(g) =>
        assert_true(
          rb_eq(dk, dk512) && rb_eq(g, b"payload"),
          msg="ml_kem_hybrid: wrong dk accepted",
        )
      None => ()
    }
  }
  // X-Wing
  let (xpk, xsk) = xwing_keygen(rb_bytes(r, 32))
  let eseed = rb_bytes(r, 64)
  let (xss, xct) = xwing_encaps(xpk, eseed)
  match xwing_decaps_or(xct, xsk) {
    Ok(ss) => assert_true(rb_eq(ss, xss))
    Err(_) => assert_true(false, msg="xwing: authentic ct rejected")
  }
  for c in rb_cases(r, xct, 10) {
    match xwing_decaps_or(c, xsk) {
      Ok(ss) => {
        assert_true(ss.length() == 32)
        if !rb_eq(c, xct) {
          assert_false(rb_eq(ss, xss), msg="xwing: forged ct gave the secret")
        }
      }
      Err(_) => assert_false(c.length() == xct.length())
    }
  }
  for pk in rb_cases(r, xpk, 8) {
    match xwing_encaps_or(pk, eseed) {
      Ok(pair) => assert_true(pair.1.length() == 1120)
      Err(_) => assert_false(pk.length() == xpk.length())
    }
  }
  for sk in rb_cases(r, xsk, 6) {
    match xwing_decaps_or(xct, sk) {
      Ok(ss) => assert_true(ss.length() == 32)
      Err(_) => assert_false(sk.length() == xsk.length())
    }
  }
}

///|
test "robust-rsa-decrypt" {
  let r = rb_rng(0x525341524F42UL)
  let n = rsa_test_n
  let d = rsa_test_d
  let e = rsa_test_e
  let msg = b"robust"
  let seed = rb_bytes(r, 32)
  let oaep_ct = rsa_oaep_encrypt(msg, n, e, seed, b"")
  match rsa_oaep_decrypt_or(oaep_ct, n, d, b"") {
    Ok(got) => assert_true(rb_eq(got, msg))
    Err(_) => assert_true(false, msg="rsa_oaep: authentic ct rejected")
  }
  for c in rb_cases(r, oaep_ct, 8) {
    match rsa_oaep_decrypt_or(c, n, d, b"") {
      Ok(got) =>
        assert_true(
          rb_eq(c, oaep_ct) && rb_eq(got, msg),
          msg="rsa_oaep: forged ct accepted",
        )
      // uniform error text: no oracle through distinguishable messages
      Err(m) => assert_true(m == "rsa_oaep decrypt: decryption error")
    }
  }
  let ps = rb_bytes(r, n.length() - msg.length() - 3)
  let v15_ct = rsa_pkcs1_v15_encrypt(msg, n, e, ps)
  match rsa_pkcs1_v15_decrypt_or(v15_ct, n, d) {
    Ok(got) => assert_true(rb_eq(got, msg))
    Err(_) => assert_true(false, msg="rsa_pkcs1_v15: authentic ct rejected")
  }
  for c in rb_cases(r, v15_ct, 8) {
    match rsa_pkcs1_v15_decrypt_or(c, n, d) {
      Ok(got) =>
        assert_true(
          rb_eq(c, v15_ct) && rb_eq(got, msg),
          msg="rsa_pkcs1_v15: forged ct accepted",
        )
      Err(m) => assert_true(m == "rsa_pkcs1_v15 decrypt: decryption error")
    }
  }
  // hostile public parameters must not trap either
  for nn in rb_cases(r, n, 4) {
    let _ = rsa_oaep_decrypt_or(oaep_ct, nn, d, b"")
    let _ = rsa_pkcs1_v15_decrypt_or(v15_ct, nn, d)
  }
  // verify paths: the public key is peer-supplied in every real protocol
  let v15_sig = rsa_pkcs1_v15_sign(msg, n, d)
  assert_true(
    rsa_pkcs1_v15_verify(msg, v15_sig, n, e),
    msg="rsa v1.5: good sig",
  )
  let salt = rb_bytes(r, 32)
  let pss_sig = rsa_pss_sign(msg, n, d, salt)
  assert_true(rsa_pss_verify(msg, pss_sig, n, e, 32), msg="rsa pss: good sig")
  for nn in rb_cases(r, n, 6) {
    if !rb_eq(nn, n) {
      assert_false(rsa_pkcs1_v15_verify(msg, v15_sig, nn, e))
      assert_false(rsa_pss_verify(msg, pss_sig, nn, e, 32))
      assert_false(
        rsa_pkcs1_v15_verify_with(msg, v15_sig, nn, e, rsa_hash_sha256),
      )
      assert_false(
        rsa_pss_verify_with(msg, pss_sig, nn, e, 32, rsa_hash_sha256),
      )
    }
  }
  for ee in rb_cases(r, e, 6) {
    if !rb_eq(ee, e) {
      assert_false(rsa_pkcs1_v15_verify(msg, v15_sig, n, ee))
      assert_false(rsa_pss_verify(msg, pss_sig, n, ee, 32))
    }
  }
  for s in rb_cases(r, pss_sig, 8) {
    if !rb_eq(s, pss_sig) {
      assert_false(rsa_pss_verify(msg, s, n, e, 32))
      assert_false(rsa_pkcs1_v15_verify(msg, s, n, e))
    }
  }
  // A modulus whose byte length overshoots its bit length (zero-padded n, as
  // a careless DER reader produces) must be rejected outright: it drives
  // `bits_to_clear` past 8 in the PSS EM mask, where the shift count wraps
  // and the check would otherwise pass or fail on garbage.
  let n_pad = rb_cat(Bytes::make(16, b'\x00'), n)
  let sig_pad = rb_cat(Bytes::make(16, b'\x00'), pss_sig)
  let v15_pad = rb_cat(Bytes::make(16, b'\x00'), v15_sig)
  assert_false(rsa_pss_verify(msg, sig_pad, n_pad, e, 32))
  assert_false(rsa_pss_verify_with(msg, sig_pad, n_pad, e, 32, rsa_hash_sha256))
  assert_false(rsa_pkcs1_v15_verify(msg, v15_pad, n_pad, e))
  let _ = rsa_oaep_decrypt_or(
    rb_cat(Bytes::make(16, b'\x00'), oaep_ct),
    n_pad,
    d,
    b"",
  )
  // a hostile salt_len must not blow up the EM bounds either
  for sl in [0, 1, 31, 33, 64, 200] {
    assert_false(rsa_pss_verify(msg, pss_sig, n, e, sl))
  }
}

///|
test "robust-sm2-encryption" {
  let r = rb_rng(0x534D32454E43UL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let msg = b"robust payload"
  let ct = sm2_encrypt(pk, msg, rand)
  let (got, ok) = sm2_decrypt(sk, ct)
  assert_true(ok)
  assert_true(rb_eq(got, msg))
  for c in rb_cases(r, ct, 12) {
    let (g, ok2) = sm2_decrypt(sk, c)
    if ok2 {
      assert_true(
        rb_eq(c, ct) && rb_eq(g, msg),
        msg="sm2_decrypt: forged ct accepted",
      )
    } else {
      assert_true(g.length() == 0)
    }
  }
  for k in rb_flips(r, sk, 6) {
    let (_, ok3) = sm2_decrypt(k, ct)
    if !rb_eq(k, sk) {
      assert_false(ok3)
    }
  }
  // GM/T 0009 style envelope
  let env = sm2_seal(pk, msg, rand)
  let (got2, ok4) = sm2_open(sk, env)
  assert_true(ok4)
  assert_true(rb_eq(got2, msg))
  for e in rb_cases(r, env, 12) {
    let (_, ok5) = sm2_open(sk, e)
    if ok5 {
      assert_true(rb_eq(e, env), msg="sm2_open: forged envelope accepted")
    }
  }
  // DER codecs: hostile DER must be (b"", false), never a trap
  let der = sm2_ct_to_der(ct)
  let (raw, okd) = sm2_ct_from_der(der)
  assert_true(okd)
  assert_true(rb_eq(raw, ct))
  for e in rb_cases(r, der, 14) {
    let _ = sm2_ct_from_der(e)
  }
  let sig = sm2_sign(sk, msg, b"1234567812345678", rand)
  let sder = sm2_sig_to_der(sig)
  let (sraw, oks) = sm2_sig_from_der(sder)
  assert_true(oks)
  assert_true(rb_eq(sraw, sig))
  for e in rb_cases(r, sder, 14) {
    let _ = sm2_sig_from_der(e)
  }
  // key serialization
  let p8 = sm2_sk_to_pkcs8_der(sk)
  let (sk2, okp) = sm2_pkcs8_der_to_sk(p8)
  assert_true(okp)
  assert_true(rb_eq(sk2, sk))
  for e in rb_cases(r, p8, 12) {
    let _ = sm2_pkcs8_der_to_sk(e)
  }
  let spki = sm2_pk_to_spki_der(pk)
  let (pk2, okq) = sm2_spki_der_to_pk(spki)
  assert_true(okq)
  assert_true(rb_eq(pk2, pk))
  for e in rb_cases(r, spki, 12) {
    let _ = sm2_spki_der_to_pk(e)
  }
}

// ---------- text decoders ----------

///|
test "robust-text-decoders" {
  let hostile : Array[String] = [
    "", "0", "00", "000", "z", "zz", "0x00", "-1", " 00", "00 ", "0\n0", "\t", "deadbeef",
    "DEADBEEF", "dead beef", "0123456789abcdef0123456789abcde", "ÿþ", "中文",
    "0123456789abcdefghijklmnopqrstuvwxyz", "!@#$%^&*()", "ffffffffffffffffffffffffffffffffffffffff",
  ]
  for h in hostile {
    match hex_to_bytes_or(h) {
      Ok(b) => {
        assert_true(b.length() * 2 == h.length())
        // a successful decode must agree with the fail-fast decoder
        assert_true(rb_eq(b, hex_to_bytes(h)))
      }
      Err(_) => ()
    }
    let _ = base64_decode(h)
    match base64_decode_or(h) {
      Ok(b) => assert_true(rb_eq(b, base64_decode(h)))
      Err(_) => ()
    }
  }
  // random bytes -> encode -> decode is always exact
  let r = rb_rng(0x484558444543UL)
  for _i in 0..<20 {
    let b = rb_bytes(r, rb_upto(r, 64))
    let h = bytes_to_hex(b)
    match hex_to_bytes_or(h) {
      Ok(got) => assert_true(rb_eq(got, b))
      Err(_) =>
        assert_true(false, msg="hex_to_bytes_or: rejected its own encoder")
    }
    let enc = base64_encode(b)
    match base64_decode_or(enc) {
      Ok(got) => assert_true(rb_eq(got, b))
      Err(_) =>
        assert_true(false, msg="base64_decode_or: rejected its own encoder")
    }
  }
  // PEM parsers: hostile text must be (b"", false)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let sk_pem = sm2_sk_to_pem(sk)
  let pk_pem = sm2_pk_to_pem(pk)
  let (sk2, ok1) = sm2_sk_from_pem(sk_pem)
  assert_true(ok1)
  assert_true(rb_eq(sk2, sk))
  let (pk2, ok2) = sm2_pk_from_pem(pk_pem)
  assert_true(ok2)
  assert_true(rb_eq(pk2, pk))
  for h in hostile {
    let (_, a) = sm2_sk_from_pem(h)
    assert_false(a)
    let (_, b) = sm2_pk_from_pem(h)
    assert_false(b)
  }
  // structurally valid PEM armour around a hostile payload
  for payload in rb_cases(r, rb_bytes(r, 64), 10) {
    let body = base64_encode(payload)
    let fake_sk = "-----BEGIN PRIVATE KEY-----\n" +
      body +
      "\n-----END PRIVATE KEY-----\n"
    let (_, a) = sm2_sk_from_pem(fake_sk)
    let _ = a
    let fake_pk = "-----BEGIN PUBLIC KEY-----\n" +
      body +
      "\n-----END PUBLIC KEY-----\n"
    let (_, b) = sm2_pk_from_pem(fake_pk)
    let _ = b
  }
}

// ---------- HPKE: peer keys and ciphertexts ----------

///|
test "robust-hpke" {
  let r = rb_rng(0x48504B45524FUL)
  let info = b"info"
  // X25519 suite: round trip, then hostile enc / ciphertext
  let s_x = hpke_x25519_hkdf_sha256_aes128gcm
  let (pk_r, sk_r) = hpke_derive_key_pair(s_x, rb_bytes(r, 32))
  assert_true(hpke_valid_pk(s_x, pk_r), msg="hpke: own x25519 pk rejected")
  let (enc, ctx_s) = hpke_setup_s(
    s_x,
    0,
    pk_r,
    rb_bytes(r, 32),
    info,
    b"",
    b"",
    b"",
  )
  let ctx_r = hpke_setup_r(s_x, 0, sk_r, pk_r, enc, info, b"", b"", b"")
  let ct = hpke_seal(ctx_s, b"aad", b"payload")
  match hpke_open(ctx_r, b"aad", ct) {
    Some(pt) => assert_true(rb_eq(pt, b"payload"))
    None => assert_true(false, msg="hpke: authentic ciphertext rejected")
  }
  for c in rb_cases(r, ct, 12) {
    let ctx = hpke_setup_r(s_x, 0, sk_r, pk_r, enc, info, b"", b"", b"")
    match hpke_open(ctx, b"aad", c) {
      Some(pt) =>
        assert_true(
          rb_eq(c, ct) && rb_eq(pt, b"payload"),
          msg="hpke: forged ciphertext accepted",
        )
      None => ()
    }
  }
  // X25519 accepts ANY 32-byte input by design (RFC 7748: low-order points
  // included, the cofactor is folded into the ladder and HPKE hashes the DH
  // output), so the only thing the validator can reject is a wrong length.
  for e in rb_cases(r, enc, 12) {
    match hpke_setup_r_or(s_x, 0, sk_r, pk_r, e, info, b"", b"", b"") {
      Ok(_) =>
        assert_true(e.length() == 32, msg="hpke: bad-length enc accepted")
      Err(_) => assert_false(e.length() == 32)
    }
    match hpke_decap_or(s_x, e, sk_r, pk_r) {
      Ok(_) =>
        assert_true(e.length() == 32, msg="hpke: bad-length enc decapsulated")
      Err(_) => assert_false(e.length() == 32)
    }
  }
  for p in rb_cases(r, pk_r, 8) {
    match hpke_setup_s_or(s_x, 0, p, rb_bytes(r, 32), info, b"", b"", b"") {
      Ok(_) =>
        assert_true(p.length() == 32, msg="hpke: bad-length pk_r accepted")
      Err(_) => assert_false(p.length() == 32)
    }
  }
  // NIST suites: the peer point must be ON the curve (invalid-curve attack)
  for
    triple in [
      (hpke_p256_hkdf_sha256_aes128gcm, 65),
      (hpke_p384_hkdf_sha384_aes256gcm, 97),
      (hpke_p521_hkdf_sha512_aes256gcm, 133),
    ] {
    let (s_p, pk_len) = triple
    let (pk_p, sk_p) = hpke_derive_key_pair(s_p, rb_bytes(r, 32))
    assert_true(pk_p.length() == pk_len)
    assert_true(hpke_valid_pk(s_p, pk_p), msg="hpke: own nist pk rejected")
    // y+1 is off the curve: exactly the point an invalid-curve attacker sends
    let off = pk_p.to_array()
    let last = off.length() - 1
    off[last] = (off[last].to_int() + 1).to_byte()
    let bad = Bytes::from_array(off)
    assert_false(hpke_valid_pk(s_p, bad))
    match hpke_decap_or(s_p, bad, sk_p, pk_p) {
      Ok(_) =>
        assert_true(
          false,
          msg="hpke: off-curve point accepted (invalid-curve attack!)",
        )
      Err(_) => ()
    }
    match hpke_setup_r_or(s_p, 0, sk_p, pk_p, bad, info, b"", b"", b"") {
      Ok(_) => assert_true(false, msg="hpke: off-curve enc accepted")
      Err(_) => ()
    }
    // every hostile pk shape must be rejected by the validator
    for p in rb_cases(r, pk_p, 10) {
      if !rb_eq(p, pk_p) {
        assert_false(hpke_valid_pk(s_p, p))
        match hpke_encap_or(s_p, p, rb_bytes(r, 32)) {
          Ok(_) => assert_true(false, msg="hpke: malformed pk_r reached the DH")
          Err(_) => ()
        }
      }
    }
    // an authentic exchange still works after all of that
    let (enc_p, ctx_sp) = match
      hpke_setup_s_or(s_p, 0, pk_p, rb_bytes(r, 32), info, b"", b"", b"") {
      Ok(pair) => pair
      Err(_) => {
        assert_true(false, msg="hpke: authentic nist sender setup rejected")
        (b"", hpke_setup_r(s_p, 0, sk_p, pk_p, pk_p, info, b"", b"", b""))
      }
    }
    match hpke_setup_r_or(s_p, 0, sk_p, pk_p, enc_p, info, b"", b"", b"") {
      Ok(ctx_rp) => {
        let c = hpke_seal(ctx_sp, b"aad", b"payload")
        match hpke_open(ctx_rp, b"aad", c) {
          Some(pt) => assert_true(rb_eq(pt, b"payload"))
          None => assert_true(false, msg="hpke: nist round trip failed")
        }
      }
      Err(_) => assert_true(false, msg="hpke: authentic nist setup rejected")
    }
  }
  // X448 suite: as with X25519 the contract is length-only (RFC 7748), so
  // validity must track the length and nothing else.
  let s_4 = hpke_x448_hkdf_sha512_aes256gcm
  let (pk_4, _) = hpke_derive_key_pair(s_4, rb_bytes(r, 32))
  assert_true(hpke_valid_pk(s_4, pk_4))
  assert_true(pk_4.length() == 56)
  for p in rb_cases(r, pk_4, 8) {
    assert_true(hpke_valid_pk(s_4, p) == (p.length() == 56))
  }
}

// ---------- X25519 / X448: hostile shares and the all-zero output ----------

///|
test "robust-xdh" {
  let r = rb_rng(0x5832353531394FUL)
  let sk_a = rb_bytes(r, 32)
  let sk_b = rb_bytes(r, 32)
  let pk_a = x25519_public_key(sk_a)
  let pk_b = x25519_public_key(sk_b)
  // an authentic exchange agrees and is not the degenerate output
  match (x25519_or(sk_a, pk_b), x25519_or(sk_b, pk_a)) {
    (Ok(s1), Ok(s2)) =>
      assert_true(
        rb_eq(s1, s2) && !dh_shared_is_zero(s1),
        msg="x25519: commutativity / zero output",
      )
    _ => assert_true(false, msg="x25519: authentic share rejected")
  }
  // hostile peer share: only a wrong length is an error (RFC 7748 accepts any
  // 32-byte u, low-order points included)
  for u in rb_cases(r, pk_b, 12) {
    match x25519_or(sk_a, u) {
      Ok(s) => assert_true(u.length() == 32 && s.length() == 32)
      Err(_) => assert_false(u.length() == 32)
    }
  }
  for k in rb_cases(r, sk_a, 8) {
    match x25519_or(k, pk_b) {
      Ok(s) => assert_true(k.length() == 32 && s.length() == 32)
      Err(_) => assert_false(k.length() == 32)
    }
  }
  // RFC 7748 §6.1: a low-order peer point yields an all-zero shared secret and
  // the ladder still SUCCEEDS — nothing to reject. The caller must check, so
  // pin the behaviour instead of leaving it to luck.
  match x25519_or(sk_a, Bytes::make(32, b'\x00')) {
    Ok(s) =>
      assert_true(
        dh_shared_is_zero(s),
        msg="x25519: u=0 must produce the zero output",
      )
    Err(_) => assert_true(false, msg="x25519: u=0 must complete the ladder")
  }
  assert_false(dh_shared_is_zero(pk_a))
  // X448
  let sk4_a = rb_bytes(r, 56)
  let sk4_b = rb_bytes(r, 56)
  let pk4_a = x448_public_key(sk4_a)
  let pk4_b = x448_public_key(sk4_b)
  match (x448_or(sk4_a, pk4_b), x448_or(sk4_b, pk4_a)) {
    (Ok(s1), Ok(s2)) =>
      assert_true(
        rb_eq(s1, s2) && !dh_shared_is_zero(s1),
        msg="x448: commutativity / zero output",
      )
    _ => assert_true(false, msg="x448: authentic share rejected")
  }
  for u in rb_cases(r, pk4_b, 10) {
    match x448_or(sk4_a, u) {
      Ok(s) => assert_true(u.length() == 56 && s.length() == 56)
      Err(_) => assert_false(u.length() == 56)
    }
  }
  match x448_or(sk4_a, Bytes::make(56, b'\x00')) {
    Ok(s) =>
      assert_true(
        dh_shared_is_zero(s),
        msg="x448: u=0 must produce the zero output",
      )
    Err(_) => assert_true(false, msg="x448: u=0 must complete the ladder")
  }
  assert_false(dh_shared_is_zero(pk4_a))
}

// ---------- Falcon: degenerate keys and a broken caller RNG ----------

///|
test "robust-falcon-degenerate" {
  let r = rb_rng(0x46414C434447UL)
  let kr = falcon_test_rng_init()
  let krand = fn(k : Int) -> Bytes { falcon_test_rng_bytes(kr, k) }
  let seed = falcon_test_rng_bytes(kr, 48)
  let (pk, sk) = falcon512_keypair_from_seed(seed)
  let msg = b"robustness"
  // the happy path still works after the rejection loops were bounded
  let good = falcon512_sign(sk, msg, krand)
  assert_true(good.length() > 0, msg="falcon: signing a real key failed")
  assert_true(falcon512_verify(pk, good, msg), msg="falcon: good sig rejected")
  // a structurally valid sk with an all-zero body (right header, right length)
  let zero_sk = Array::make(falcon512_sk_bytes, (0).to_byte())
  zero_sk[0] = (0x59).to_byte()
  assert_true(
    falcon512_sign(Bytes::from_array(zero_sk), msg, krand).length() == 0,
    msg="falcon: degenerate sk produced a signature",
  )
  // one flipped byte deep in the trimmed f/g/F body must be rejected, not
  // silently sign with a corrupted key
  for pos in [1, 100, 700, 1000, falcon512_sk_bytes - 1] {
    let bad = sk.to_array()
    bad[pos] = (bad[pos].to_int() ^ 0x5A).to_byte()
    let out = falcon512_sign(Bytes::from_array(bad), msg, krand)
    if out.length() > 0 {
      // if a corrupted key does still sign, the signature must at least be
      // rejected under the real public key
      assert_false(falcon512_verify(pk, out, msg))
    }
  }
  // a broken caller RNG (always all-zero bytes) must still TERMINATE: the
  // sign loop is bounded, and whatever comes back is either the empty
  // "cannot sign" signal or a signature that actually verifies
  let zrand = fn(k : Int) -> Bytes { Bytes::make(k, (0).to_byte()) }
  let zsig = falcon512_sign(sk, msg, zrand)
  if zsig.length() > 0 {
    assert_true(
      falcon512_verify(pk, zsig, msg),
      msg="falcon: zero-nonce signature does not verify",
    )
  }
  // keygen from a spread of seeds (the bounded (f,g) loop must not change the
  // happy path): every key signs and verifies
  for i in 0..<4 {
    let s2 = falcon_test_rng_bytes(kr, 48)
    let _ = i
    let (pk2, sk2) = falcon512_keypair_from_seed(s2)
    let sig2 = falcon512_sign(sk2, msg, krand)
    assert_true(sig2.length() > 0, msg="falcon: keygen/sign happy path broke")
    assert_true(
      falcon512_verify(pk2, sig2, msg),
      msg="falcon: fresh key rejected",
    )
  }
  let _ = r
}

///|
test "robust-zuc" {
  let r = rb_rng(0x5A3C2562EEA3UL)
  let key16 = rb_bytes(r, 16)
  let key32 = rb_bytes(r, 32)
  let iv16 = rb_bytes(r, 16)
  let iv23 = rb_bytes(r, 23)
  let count = 0x9E3779B9U
  // 67 bytes = 536 bits: not a keystream-word multiple, so the tail paths run
  let msg = rb_bytes(r, 67)
  let nbits = msg.length() * 8
  // ---- 128-EIA3: hostile message, hostile tag, hostile key --------------
  // In a real stack the message and the MAC-I both come off the air interface,
  // while COUNT/BEARER/DIRECTION are validated integers and the key is local.
  // LENGTH is a shape contract (data must hold exactly ceil(nbits/8) bytes),
  // so every mutated buffer is paired with the nbits derived from its own
  // length: verify must never trap, and must accept only the authentic pair.
  let mac4 = zuc_eia3_mac(key16, count, 3, 1, nbits, msg)
  for m in rb_cases(r, msg, 10) {
    let nb = m.length() * 8
    for t in rb_cases(r, mac4, 4) {
      assert_true(
        zuc_eia3_verify(key16, count, 3, 1, nb, m, t) ==
        (nb == nbits && rb_eq(m, msg) && rb_eq(t, mac4)),
        msg="eia3: forged (message, tag) accepted",
      )
    }
  }
  // key length is contract, so mutate content only
  for k in rb_flips(r, key16, 6) {
    assert_true(
      zuc_eia3_verify(k, count, 3, 1, nbits, msg, mac4) == rb_eq(k, key16),
      msg="eia3: wrong key accepted",
    )
  }
  // ---- ZUC-256 MAC: all three tag sizes ---------------------------------
  for macbits in [32, 64, 128] {
    let tag = zuc256_mac(key32, iv23, macbits, nbits, msg)
    assert_true(
      tag.length() == macbits / 8,
      msg="zuc256 mac: tag length at macbits=" + macbits.to_string(),
    )
    for m in rb_cases(r, msg, 8) {
      let nb = m.length() * 8
      for t in rb_cases(r, tag, 4) {
        assert_true(
          zuc256_mac_verify(key32, iv23, macbits, nb, m, t) ==
          (nb == nbits && rb_eq(m, msg) && rb_eq(t, tag)),
          msg="zuc256 mac: forged (message, tag) accepted",
        )
      }
    }
    for v in rb_flips(r, iv23, 4) {
      assert_true(
        zuc256_mac_verify(key32, v, macbits, nbits, msg, tag) == rb_eq(v, iv23),
        msg="zuc256 mac: wrong iv accepted",
      )
    }
    for k in rb_flips(r, key32, 4) {
      assert_true(
        zuc256_mac_verify(k, iv23, macbits, nbits, msg, tag) == rb_eq(k, key32),
        msg="zuc256 mac: wrong key accepted",
      )
    }
  }
  // ---- stream paths: no trap, involutive, and length-preserving ---------
  for d in rb_cases(r, msg, 10) {
    let ct = zuc_xor(key16, iv16, d)
    assert_true(ct.length() == d.length(), msg="zuc_xor: length changed")
    assert_true(
      rb_eq(zuc_xor(key16, iv16, ct), d),
      msg="zuc_xor: not involutive",
    )
    let ct2 = zuc256_xor(key32, iv23, d)
    assert_true(ct2.length() == d.length(), msg="zuc256_xor: length changed")
    assert_true(
      rb_eq(zuc256_xor(key32, iv23, ct2), d),
      msg="zuc256_xor: not involutive",
    )
    // a byte-multiple LENGTH means 128-EEA3 masks nothing, so the round trip
    // must recover the buffer exactly
    let nb = d.length() * 8
    let c3 = zuc_eea3_encrypt(key16, count, 3, 1, nb, d)
    assert_true(c3.length() == d.length(), msg="eea3: length changed")
    assert_true(
      rb_eq(zuc_eea3_decrypt(key16, count, 3, 1, nb, c3), d),
      msg="eea3: round trip",
    )
    // and the ciphertext really depends on the key: no key may reproduce
    // another key's ciphertext. (Skipped for the empty buffer — with nothing to
    // encrypt every key gives the empty ciphertext, so the property is vacuous
    // there rather than violated.)
    if d.length() > 0 {
      for k in rb_flips(r, key16, 2) {
        assert_true(
          rb_eq(zuc_eea3_encrypt(k, count, 3, 1, nb, d), c3) == rb_eq(k, key16),
          msg="eea3: wrong key gave the same ciphertext",
        )
      }
    }
  }
  let _ = r
}

///|
test "robust-rsa-encrypt" {
  let r = rb_rng(0x525341454E43UL)
  let n = rsa_test_n
  let d = rsa_test_d
  let e = rsa_test_e
  let msg = b"robust encrypt"
  let seed = rb_bytes(r, 32)
  // ---- authentic parameters: the _or twin encrypts and round-trips --------
  let ct = match rsa_oaep_encrypt_or(msg, n, e, seed, b"") {
    Ok(c) => c
    Err(m) => {
      assert_true(false, msg="oaep_or rejected valid input: " + m)
      b""
    }
  }
  assert_true(ct.length() == n.length(), msg="oaep_or: ct length")
  match rsa_oaep_decrypt_or(ct, n, d, b"") {
    Ok(got) => assert_true(rb_eq(got, msg), msg="oaep_or: round trip")
    Err(_) => assert_true(false, msg="oaep_or: own ct did not decrypt")
  }
  // OAEP with a fixed seed is deterministic, so the aborting twin must agree
  assert_true(
    rb_eq(rsa_oaep_encrypt(msg, n, e, seed, b""), ct),
    msg="oaep and oaep_or disagree",
  )
  // ---- the shapes that trapped before: a degenerate peer modulus ----------
  // A 1024-bit-sized modulus that happens to be 0 (or 1) reaches BigInt.pow
  // with modulus 0 unless the entry point checks first; n comes from a
  // certificate, so this is peer-controlled.
  //
  // n = 0 and n = 1 at a realistic width, plus the one-byte and empty forms.
  // Note `Bytes::make(128, b'\x01')` is NOT n=1 — it fills every byte, which
  // is a perfectly legal large modulus that the encrypt path must accept.
  let n_zero = Bytes::make(128, b'\x00')
  let n_one = rb_cat(Bytes::make(127, b'\x00'), b"\x01")
  for bad in [n_zero, n_one, b"\x00", b"\x01", b""] {
    match rsa_oaep_encrypt_or(msg, bad, e, seed, b"") {
      Ok(_) => assert_true(false, msg="oaep_or accepted a degenerate modulus")
      Err(m) =>
        assert_true(
          m == "rsa: modulus must be at least 2",
          msg="oaep_or: unexpected message " + m,
        )
    }
    match rsa_oaep_encrypt_with_or(msg, bad, e, seed, b"", rsa_hash_sha256) {
      Ok(_) =>
        assert_true(false, msg="oaep_with_or accepted a degenerate modulus")
      Err(_) => ()
    }
    match rsa_pkcs1_v15_encrypt_or(msg, bad, e, rb_bytes(r, 8)) {
      Ok(_) => assert_true(false, msg="v15_or accepted a degenerate modulus")
      Err(m) =>
        assert_true(
          m == "rsa: modulus must be at least 2",
          msg="v15_or: unexpected message " + m,
        )
    }
  }
  // ---- a message too long for the peer's modulus is a value, not a trap ---
  let big = rb_bytes(r, n.length())
  match rsa_oaep_encrypt_or(big, n, e, seed, b"") {
    Ok(_) => assert_true(false, msg="oaep_or accepted an over-long message")
    Err(m) =>
      assert_true(
        m == "rsa_oaep encrypt: message too long for modulus",
        msg="oaep_or: unexpected message " + m,
      )
  }
  match rsa_pkcs1_v15_encrypt_or(big, n, e, rb_bytes(r, 8)) {
    Ok(_) => assert_true(false, msg="v15_or accepted an over-long message")
    Err(_) => ()
  }
  // SHA-512 needs k >= 2*hLen + 2 + |M|: the same modulus that fits SHA-256
  // must reject a long message under SHA-512 rather than trap
  let seed64 = rb_bytes(r, 64)
  match rsa_oaep_encrypt_with_or(big, n, e, seed64, b"", rsa_hash_sha512) {
    Ok(_) => assert_true(false, msg="oaep sha512 accepted an over-long message")
    Err(_) => ()
  }
  match rsa_oaep_encrypt_with_or(msg, n, e, seed64, b"", rsa_hash_sha512) {
    // the 1024-bit fixture cannot hold OAEP-SHA-512 at all (k >= 2*hLen+2+|M|
    // needs >= 144 bytes), so the positive case uses the 2048-bit key from the
    // multi-hash suite
    Err(m) =>
      assert_true(
        m == "rsa_oaep encrypt: message too long for modulus",
        msg="oaep sha512 on a 1024-bit modulus: " + m,
      )
    Ok(_) => assert_true(false, msg="oaep sha512 fit a 1024-bit modulus?")
  }
  match
    rsa_oaep_encrypt_with_or(msg, om_n2048, e, seed64, b"", rsa_hash_sha512) {
    Ok(ct512) => {
      assert_true(
        ct512.length() == om_n2048.length(),
        msg="oaep sha512: ct length",
      )
      match
        rsa_oaep_decrypt_with_or(
          ct512, om_n2048, om_d2048, b"", rsa_hash_sha512,
        ) {
        Ok(got) => assert_true(rb_eq(got, msg), msg="oaep sha512: round trip")
        Err(_) => assert_true(false, msg="oaep sha512: own ct did not decrypt")
      }
      // and the aborting twin agrees on valid input
      assert_true(
        rb_eq(
          rsa_oaep_encrypt_with(msg, om_n2048, e, seed64, b"", rsa_hash_sha512),
          ct512,
        ),
        msg="oaep_with and oaep_with_or disagree",
      )
    }
    Err(m) => assert_true(false, msg="oaep sha512 rejected valid input: " + m)
  }
  // ---- hostile public parameters must never trap -------------------------
  for nn in rb_cases(r, n, 6) {
    match rsa_oaep_encrypt_or(msg, nn, e, seed, b"") {
      Ok(c) => assert_true(c.length() == nn.length(), msg="oaep_or: ct length")
      Err(_) => ()
    }
    match rsa_pkcs1_v15_encrypt_or(msg, nn, e, rb_bytes(r, 16)) {
      Ok(_) => ()
      Err(_) => ()
    }
  }
  for ee in rb_cases(r, e, 6) {
    match rsa_oaep_encrypt_or(msg, n, ee, seed, b"") {
      Ok(_) => ()
      Err(_) => ()
    }
  }
  // ---- v1.5: the aborting twin and the _or twin agree on valid input -----
  // RFC 8017 §7.2.1 step 3 wants *nonzero* PS octets, so the fixture must not
  // contain a zero byte — a random one does roughly a third of the time at this
  // length, and the unpad scans for the first 0x00 separator, so it would stop
  // early and the round trip would legitimately fail.
  let ps_len = n.length() - msg.length() - 3
  let ps_arr = rb_bytes(r, ps_len).to_array()
  for i in 0..<ps_len {
    if ps_arr[i] == b'\x00' {
      ps_arr[i] = b'\x2a'
    }
  }
  let ps = Bytes::from_array(ps_arr)
  match rsa_pkcs1_v15_encrypt_or(msg, n, e, ps) {
    Ok(ct2) => {
      assert_true(
        rb_eq(rsa_pkcs1_v15_encrypt(msg, n, e, ps), ct2),
        msg="v15 and v15_or disagree",
      )
      match rsa_pkcs1_v15_decrypt_or(ct2, n, d) {
        Ok(got) => assert_true(rb_eq(got, msg), msg="v15_or: round trip")
        Err(_) => assert_true(false, msg="v15_or: own ct did not decrypt")
      }
    }
    Err(m) => assert_true(false, msg="v15_or rejected valid input: " + m)
  }
  // a zero byte inside PS is reported rather than silently producing a
  // ciphertext the recipient unpads to a truncated message
  let ps0 = ps_arr.copy()
  ps0[0] = b'\x00'
  match rsa_pkcs1_v15_encrypt_or(msg, n, e, Bytes::from_array(ps0)) {
    Ok(_) => assert_true(false, msg="v15_or accepted a zero byte in rand_ps")
    Err(m) =>
      assert_true(
        m == "rsa_pkcs1_v15_encrypt: rand_ps must be nonzero (RFC 8017 7.2.1)",
        msg="v15_or zero-PS message: " + m,
      )
  }
  // house rule for the _or family: it never aborts, so a wrong-length seed is
  // an Err here and an abort only in the twin above
  match rsa_oaep_encrypt_or(msg, n, e, rb_bytes(r, 31), b"") {
    Ok(_) => assert_true(false, msg="oaep_or accepted a 31-byte seed")
    Err(_) => ()
  }
  match rsa_oaep_encrypt_with_or(msg, n, e, seed, b"", rsa_hash_sha384) {
    Ok(_) =>
      assert_true(false, msg="oaep_with_or accepted a 32-byte SHA-384 seed")
    Err(_) => ()
  }
}

///|
test "robust-kem-seal" {
  // The seal side of the hybrid construction takes the *recipient's* ek, which
  // in every real protocol is parsed out of something a peer sent. Before the
  // `_or` twins existed this path called the aborting `ml_kem_*_encaps`, so a
  // wrong-length ek trapped the process even though `hybrid_open` and
  // `xwing_encaps` were already graceful.
  let r = rb_rng(0x4B454D5345414CUL)
  let (ek512, dk512) = ml_kem_512_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let (ek768, _) = ml_kem_768_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let (ek1024, _) = ml_kem_1024_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let m = rb_bytes(r, 32)
  let aad = b"aad"
  let msg = rb_bytes(r, 77)
  // ---- authentic input: _or seals, the plain twin agrees, and it opens ----
  let blob = match ml_kem_512_hybrid_seal_or(ek512, m, aad, msg) {
    Ok(b) => b
    Err(e) => {
      assert_true(false, msg="seal_or rejected valid input: " + e)
      b""
    }
  }
  assert_true(
    rb_eq(ml_kem_512_hybrid_seal(ek512, m, aad, msg), blob),
    msg="hybrid_seal and hybrid_seal_or disagree",
  )
  match ml_kem_512_hybrid_open(dk512, blob, aad) {
    Some(got) => assert_true(rb_eq(got, msg), msg="seal_or blob did not open")
    None => assert_true(false, msg="seal_or blob rejected by open")
  }
  // ---- hostile ek: Err exactly when the length is wrong, never a trap -----
  for ek in rb_cases(r, ek512, 8) {
    match ml_kem_512_hybrid_seal_or(ek, m, aad, msg) {
      Ok(_) =>
        assert_true(ek.length() == ek512.length(), msg="seal_or: bad ek length")
      Err(_) =>
        assert_true(
          ek.length() != ek512.length(),
          msg="seal_or: good ek rejected",
        )
    }
  }
  for ek in rb_flips(r, ek768, 6) {
    match ml_kem_768_hybrid_seal_or(ek, m, aad, msg) {
      Ok(_) => ()
      Err(_) => assert_true(false, msg="768 seal_or rejected a same-length ek")
    }
  }
  for ek in rb_cases(r, ek1024, 6) {
    match ml_kem_1024_hybrid_seal_or(ek, m, aad, msg) {
      Ok(_) =>
        assert_true(ek.length() == ek1024.length(), msg="1024 seal_or: bad ek")
      Err(_) =>
        assert_true(ek.length() != ek1024.length(), msg="1024 seal_or: good ek")
    }
  }
  // ---- hostile m (the encapsulation randomness) --------------------------
  for mm in rb_cases(r, m, 6) {
    match ml_kem_768_hybrid_seal_or(ek768, mm, aad, msg) {
      Ok(_) =>
        assert_true(mm.length() == 32, msg="seal_or: bad m length accepted")
      Err(_) => assert_true(mm.length() != 32, msg="seal_or: good m rejected")
    }
  }
  // ---- the streaming entry point has the same contract -------------------
  match ml_kem_512_hybrid_seal_init_or(ek512, m, aad) {
    Ok((c, st)) => {
      assert_true(c.length() == 768, msg="seal_init_or: c length")
      let streamed = rb_cat(
        c,
        rb_cat(
          ml_kem_hybrid_stream_update(st, msg),
          ml_kem_hybrid_stream_final(st),
        ),
      )
      assert_true(
        rb_eq(streamed, blob),
        msg="seal_init_or disagrees with seal_or",
      )
    }
    Err(e) => assert_true(false, msg="seal_init_or rejected valid input: " + e)
  }
  for ek in rb_cases(r, ek512, 6) {
    match ml_kem_512_hybrid_seal_init_or(ek, m, aad) {
      Ok(_) =>
        assert_true(ek.length() == ek512.length(), msg="seal_init_or: bad ek")
      Err(_) =>
        assert_true(ek.length() != ek512.length(), msg="seal_init_or: good ek")
    }
  }
  for ek in rb_cases(r, ek1024, 4) {
    match ml_kem_1024_hybrid_seal_init_or(ek, m, aad) {
      Ok(_) =>
        assert_true(ek.length() == ek1024.length(), msg="1024 init_or: bad ek")
      Err(_) =>
        assert_true(ek.length() != ek1024.length(), msg="1024 init_or: good ek")
    }
  }
}

///|
test "robust-sm2-encrypt-pk" {
  // The recipient's public key is peer-supplied (a certificate, a key-agreement
  // message). sm2_parse_point used to abort on both a malformed point and an
  // off-curve one, so the *encrypt* side trapped on hostile input while
  // sm2_decrypt and sm2_verify were already graceful.
  let r = rb_rng(0x534D32504B524FUL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let msg = b"robust payload"
  // ---- authentic key: the twins agree and the ciphertext decrypts ---------
  let ct = match sm2_encrypt_or(pk, msg, rand) {
    Ok(c) => c
    Err(e) => {
      assert_true(false, msg="sm2_encrypt_or rejected a valid pk: " + e)
      b""
    }
  }
  let (got, ok) = sm2_decrypt(sk, ct)
  assert_true(ok, msg="sm2_encrypt_or: ct did not decrypt")
  assert_true(rb_eq(got, msg), msg="sm2_encrypt_or: round trip")
  // ---- hostile pk: never a trap, and the real key still works -------------
  for p in rb_cases(r, pk, 12) {
    match sm2_encrypt_or(p, msg, rand) {
      // a mutated uncompressed point is off-curve with overwhelming
      // probability, so Ok essentially only happens for the authentic key;
      // don't assert that as a fact, just check the round trip when it holds
      Ok(c) =>
        if rb_eq(p, pk) {
          let (g, o) = sm2_decrypt(sk, c)
          assert_true(o && rb_eq(g, msg), msg="sm2: authentic pk gave a bad ct")
        }
      Err(_) =>
        assert_false(rb_eq(p, pk), msg="sm2_encrypt_or rejected the real pk")
    }
  }
  // ---- the explicit-nonce twin: same contract, plus its own k checks -----
  let k = rb_bytes(r, 32)
  match sm2_encrypt_with_k_or(pk, msg, k) {
    Ok(c) => {
      let (g, o) = sm2_decrypt(sk, c)
      assert_true(o && rb_eq(g, msg), msg="with_k_or: round trip")
      assert_true(
        rb_eq(sm2_encrypt_with_k(pk, msg, k), c),
        msg="sm2_encrypt_with_k and its _or twin disagree",
      )
    }
    Err(e) => assert_true(false, msg="with_k_or rejected valid input: " + e)
  }
  for p in rb_cases(r, pk, 8) {
    match sm2_encrypt_with_k_or(p, msg, k) {
      Ok(_) => ()
      Err(_) => assert_false(rb_eq(p, pk), msg="with_k_or rejected the real pk")
    }
  }
  // k = 0 is outside [1, n-1] and used to abort deep in the scalar multiply
  match sm2_encrypt_with_k_or(pk, msg, Bytes::make(32, b'\x00')) {
    Ok(_) => assert_true(false, msg="with_k_or accepted k = 0")
    Err(m) =>
      assert_true(
        m == "sm2_encrypt_with_k: k out of range [1, n-1]",
        msg="with_k_or k=0 message: " + m,
      )
  }
  // a well-formed but off-curve point must be rejected: take the real x and
  // zero out y, which is off the curve for this x (y^2 = x^3 + ax + b has no
  // solution at y = 0 unless x^3 + ax + b == 0). This is the invalid-curve
  // attack surface, and it is deterministic rather than fuzz-probabilistic.
  let offcurve = rb_cat(rb_slice(pk, 0, 33), Bytes::make(32, b'\x00'))
  match sm2_encrypt_with_k_or(offcurve, msg, k) {
    Ok(_) => assert_true(false, msg="with_k_or accepted an off-curve point")
    Err(m) =>
      assert_true(
        m == "sm2 encryption: public key off curve",
        msg="with_k_or off-curve message: " + m,
      )
  }
  match sm2_encrypt_or(offcurve, msg, rand) {
    Ok(_) => assert_true(false, msg="encrypt_or accepted an off-curve point")
    Err(_) => ()
  }
  match sm2_seal_or(offcurve, msg, rand) {
    Ok(_) => assert_true(false, msg="seal_or accepted an off-curve point")
    Err(_) => ()
  }
  // an empty message is an Err on both twins (it was an abort)
  match sm2_encrypt_with_k_or(pk, b"", k) {
    Ok(_) => assert_true(false, msg="with_k_or accepted an empty message")
    Err(_) => ()
  }
  match sm2_encrypt_or(pk, b"", rand) {
    Ok(_) => assert_true(false, msg="encrypt_or accepted an empty message")
    Err(_) => ()
  }
  // ---- the GM/T 0009 envelope ------------------------------------------
  match sm2_seal_or(pk, msg, rand) {
    Ok(env) => {
      let (g2, ok2) = sm2_open(sk, env)
      assert_true(ok2, msg="sm2_seal_or: envelope did not open")
      assert_true(rb_eq(g2, msg), msg="sm2_seal_or: round trip")
    }
    Err(e) => assert_true(false, msg="sm2_seal_or rejected a valid pk: " + e)
  }
  for p in rb_cases(r, pk, 8) {
    match sm2_seal_or(p, msg, rand) {
      Ok(env) =>
        if rb_eq(p, pk) {
          let (g3, ok3) = sm2_open(sk, env)
          assert_true(ok3 && rb_eq(g3, msg), msg="sm2_seal_or: bad envelope")
        }
      Err(_) =>
        assert_false(rb_eq(p, pk), msg="sm2_seal_or rejected the real pk")
    }
  }
}

///|
test "robust-sm2-encoders" {
  // Re-encoding something a peer sent is a normal thing to do: store a raw
  // ciphertext as DER, put a raw signature into an ASN.1 structure, build a
  // certificate around a raw public key. All three encoders used to abort on a
  // malformed value; the `_or` twins report it instead, and both encoders of a
  // pair share one shape check so their conditions cannot drift apart.
  let r = rb_rng(0x534D324445524FUL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let msg = b"encode me"
  let ct = sm2_encrypt(pk, msg, rand)
  let sig = sm2_sign(sk, msg, b"1234567812345678", rand)
  // ---- authentic values encode, and the DER/PEM round-trips back ---------
  let ctder = match sm2_ct_to_der_or(ct) {
    Ok(d) => d
    Err(e) => {
      assert_true(false, msg="ct_to_der_or rejected a real ct: " + e)
      b""
    }
  }
  let (craw, cok) = sm2_ct_from_der(ctder)
  assert_true(cok, msg="ct DER did not parse back")
  assert_true(rb_eq(craw, ct), msg="ct DER round trip")
  assert_true(rb_eq(sm2_ct_to_der(ct), ctder), msg="ct encoder twins disagree")
  let sigder = match sm2_sig_to_der_or(sig) {
    Ok(d) => d
    Err(e) => {
      assert_true(false, msg="sig_to_der_or rejected a real sig: " + e)
      b""
    }
  }
  let (sraw, sok) = sm2_sig_from_der(sigder)
  assert_true(sok, msg="sig DER did not parse back")
  assert_true(rb_eq(sraw, sig), msg="sig DER round trip")
  assert_true(
    rb_eq(sm2_sig_to_der(sig), sigder),
    msg="sig encoder twins disagree",
  )
  let spki = match sm2_pk_to_spki_der_or(pk) {
    Ok(d) => d
    Err(e) => {
      assert_true(false, msg="spki_or rejected a real pk: " + e)
      b""
    }
  }
  let (praw, pok) = sm2_spki_der_to_pk(spki)
  assert_true(pok && rb_eq(praw, pk), msg="spki round trip")
  assert_true(rb_eq(sm2_pk_to_spki_der(pk), spki), msg="spki twins disagree")
  let pem = match sm2_pk_to_pem_or(pk) {
    Ok(s) => s
    Err(e) => {
      assert_true(false, msg="pem_or rejected a real pk: " + e)
      ""
    }
  }
  let (ppk, ppok) = sm2_pk_from_pem(pem)
  assert_true(ppok && rb_eq(ppk, pk), msg="pem round trip")
  assert_true(pem == sm2_pk_to_pem(pk), msg="pem twins disagree")
  // ---- hostile values: Err exactly when the shape is wrong ---------------
  for c in rb_cases(r, ct, 10) {
    match sm2_ct_to_der_or(c) {
      Ok(_) =>
        assert_true(
          c.length() >= 98 && c[0] == b'\x04',
          msg="ct_to_der_or accepted a malformed ciphertext",
        )
      Err(_) =>
        assert_true(
          c.length() < 98 || c[0] != b'\x04',
          msg="ct_to_der_or rejected an encodable ciphertext",
        )
    }
  }
  for s in rb_cases(r, sig, 10) {
    match sm2_sig_to_der_or(s) {
      Ok(_) => assert_true(s.length() == 64, msg="sig_to_der_or accepted junk")
      Err(_) =>
        assert_true(s.length() != 64, msg="sig_to_der_or rejected 64 bytes")
    }
  }
  for p in rb_cases(r, pk, 10) {
    let well_formed = p.length() == 65 && p[0] == b'\x04'
    match sm2_pk_to_spki_der_or(p) {
      Ok(_) =>
        assert_true(well_formed, msg="spki_or accepted a malformed point")
      Err(_) =>
        assert_false(well_formed, msg="spki_or rejected a well-formed point")
    }
    match sm2_pk_to_pem_or(p) {
      Ok(_) => assert_true(well_formed, msg="pem_or accepted a malformed point")
      Err(_) =>
        assert_false(well_formed, msg="pem_or rejected a well-formed point")
    }
  }
}
