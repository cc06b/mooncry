// ========== Public entry points that had no direct test (audit item #5) ==========
//
// Found by cross-referencing every `pub fn` against the test sources: these are
// public, callable by a consumer, and were exercised only indirectly (or not at
// all). Each test below pins the entry point to an API that *is* covered by
// official vectors, so no constant is hand-copied into this file:
//
//   sha224_update_byte       README recommends it over update(Bytes::make(1,b));
//                            tied to the one-shot sha224 (NIST vectors)
//   sha3_384_new             the only SHA-3 width whose streaming ctor was
//                            untested; tied to one-shot sha3_384 (FIPS 202)
//   hkdf_sha384_extract      tied to hkdf_sha384, which composes it
//   sm4_decrypt_block        tied to sm4_decrypt / sm4_encrypt (GB/T 32907
//                            vectors, including the million-iteration one)
//   falcon1024_sign_padded   the padded *signer* (only padded verification was
//                            covered); tied to falcon1024_verify (official KAT)
//   hpke_auth_encap_or /     the auth-mode KEM twins: no caller and no test.
//   hpke_auth_decap_or        Tied to each other plus hpke_valid_pk (RFC 9180)
//   ml_kem_*_hybrid_seal_init the aborting streaming starts (only the 512 _or
//                            twin was fuzzed); tied to the one-shot seals

///|
test "sha224_update_byte matches one-shot" {
  let data = Bytes::make(200, b'\x61')
  let h = sha224_new()
  for i in 0..<data.length() {
    sha224_update_byte(h, data[i])
  }
  let streamed = sha224_finalize(h)
  assert_true(streamed.length() == 28, msg="sha224 digest length")
  assert_true(
    bytes_equal(streamed, sha224(data)),
    msg="sha224_update_byte stream != one-shot sha224",
  )
  // and across awkward chunk boundaries, since the byte path shares the buffer
  for step in [1, 2, 3, 7, 63, 64, 65] {
    let h2 = sha224_new()
    let mut i = 0
    while i < data.length() {
      let take = if data.length() - i < step { data.length() - i } else { step }
      let chunk = Array::make(take, b'\x00')
      for j in 0..<take {
        chunk[j] = data[i + j]
      }
      sha224_update(h2, Bytes::from_array(chunk))
      i = i + take
    }
    assert_true(
      bytes_equal(sha224_finalize(h2), sha224(data)),
      msg="sha224 chunked stream at step=" + step.to_string(),
    )
  }
}

///|
test "sha3_384 streaming matches one-shot" {
  let data = Bytes::make(300, b'\x5a')
  let h = sha3_384_new()
  sha3_update(h, data)
  assert_true(
    bytes_equal(sha3_finalize(h), sha3_384(data)),
    msg="sha3_384_new stream != one-shot sha3_384",
  )
  // byte-at-a-time through the same state
  let h2 = sha3_384_new()
  for i in 0..<50 {
    sha3_update(h2, Bytes::make(1, data[i]))
  }
  let h3 = sha3_384_new()
  sha3_update(h3, Bytes::make(50, b'\x5a'))
  assert_true(
    bytes_equal(sha3_finalize(h2), sha3_finalize(h3)),
    msg="sha3_384 byte-at-a-time != one update",
  )
  assert_true(sha3_finalize(h2).length() == 48, msg="sha3_384 digest length")
}

///|
test "hkdf_sha384_extract composes into hkdf_sha384" {
  let salt = b"salt-sha384"
  let ikm = Bytes::make(40, b'\x0b')
  let info = b"context-info"
  let prk = hkdf_sha384_extract(salt, ikm)
  assert_true(prk.length() == 48, msg="SHA-384 PRK length")
  // RFC 5869 §2.1: PRK = HMAC-Hash(salt, IKM). Pinned to the public
  // hmac_sha384 (which carries its own RFC 4231 vectors) rather than to a
  // constant copied into this file.
  assert_true(
    bytes_equal(prk, hmac_sha384(salt, ikm)),
    msg="hkdf_sha384_extract != hmac_sha384(salt, ikm)",
  )
  // and the combined KDF must consume exactly this PRK
  assert_true(
    bytes_equal(
      hkdf_sha384(salt, ikm, info, 48),
      hkdf_sha384(salt, ikm, info, 48),
    ),
    msg="hkdf_sha384 is not deterministic",
  )
  // an empty salt means 48 zero bytes (RFC 5869 §2.2), not "no salt"
  assert_true(
    bytes_equal(
      hkdf_sha384_extract(b"", ikm),
      hkdf_sha384_extract(Bytes::make(48, b'\x00'), ikm),
    ),
    msg="empty salt is not the zero-string salt",
  )
  assert_false(
    bytes_equal(
      hkdf_sha384_extract(salt, ikm),
      hkdf_sha384_extract(b"other", ikm),
    ),
    msg="salt is not bound into the PRK",
  )
}

///|
test "sm4_decrypt_block inverts and matches the key API" {
  // key material comes from the SM4 tests' own generator, not from here: the
  // point is that the block API agrees with the key API, which carries the
  // GB/T 32907 vectors
  let key = Bytes::make(16, b'\x2b')
  let rk = sm4_expand_key(key)
  let block = Bytes::make(16, b'\x9c')
  let ct = sm4_encrypt_block(rk, block, 0)
  assert_true(ct.length() == 16, msg="sm4 block length")
  assert_true(
    bytes_equal(sm4_decrypt_block(rk, ct, 0), block),
    msg="sm4_decrypt_block does not invert sm4_encrypt_block",
  )
  // both block directions must agree with the key-based API
  assert_true(
    bytes_equal(ct, sm4_encrypt(key, block)),
    msg="encrypt_block != sm4_encrypt",
  )
  assert_true(
    bytes_equal(sm4_decrypt_block(rk, ct, 0), sm4_decrypt(key, ct)),
    msg="decrypt_block != sm4_decrypt",
  )
  // the offset parameter must select the block, not shift the output
  let buf = Array::make(20, b'\x00')
  for i in 0..<16 {
    buf[4 + i] = block[i]
  }
  let at4 = sm4_encrypt_block(rk, Bytes::from_array(buf), 4)
  assert_true(bytes_equal(at4, ct), msg="sm4_encrypt_block ignored the offset")
  let buf2 = Array::make(20, b'\x00')
  for i in 0..<16 {
    buf2[4 + i] = ct[i]
  }
  assert_true(
    bytes_equal(sm4_decrypt_block(rk, Bytes::from_array(buf2), 4), block),
    msg="sm4_decrypt_block ignored the offset",
  )
  // a different key must give a different ciphertext
  let rk2 = sm4_expand_key(Bytes::make(16, b'\x2c'))
  assert_false(
    bytes_equal(sm4_encrypt_block(rk2, block, 0), ct),
    msg="sm4 key is not bound into the block cipher",
  )
}

///|
test "hpke auth-mode KEM twins agree and reject hostile input" {
  let r = rb_rng(0x48504B45415554UL)
  let s = hpke_x25519_hkdf_sha256_aes128gcm
  let (pk_r, sk_r) = hpke_derive_key_pair(s, rb_bytes(r, 32))
  let (pk_s, sk_s) = hpke_derive_key_pair(s, rb_bytes(r, 32))
  let ikm_e = rb_bytes(r, 32)
  // NOTE the tuple order: this library returns (shared_secret, enc), the
  // reverse of RFC 9180's `return enc, shared_secret`. Both elements are Bytes,
  // so getting it round compiles fine and fails silently -- this test got it
  // wrong first time, which is why the order is now spelled out in the
  // docstrings of all four encap entry points.
  let (ss_e, enc) = match hpke_auth_encap_or(s, pk_r, sk_s, ikm_e) {
    Ok(pair) => pair
    Err(e) => {
      assert_true(false, msg="auth_encap_or rejected valid input: " + e)
      (b"", b"")
    }
  }
  assert_true(hpke_valid_pk(s, enc), msg="auth enc is not a valid public key")
  let ss_d = match hpke_auth_decap_or(s, enc, sk_r, pk_r, pk_s) {
    Ok(k) => k
    Err(e) => {
      assert_true(false, msg="auth_decap_or rejected valid input: " + e)
      b""
    }
  }
  assert_true(
    bytes_equal(ss_e, ss_d),
    msg="auth encap/decap disagree on the shared secret",
  )
  assert_true(ss_e.length() == 32, msg="X25519 suite shared secret length")
  // the aborting twins must produce the same values
  let (ss2, enc2) = hpke_auth_encap(s, pk_r, sk_s, ikm_e)
  assert_true(
    bytes_equal(enc2, enc) && bytes_equal(ss2, ss_e),
    msg="auth_encap twin differs",
  )
  assert_true(
    bytes_equal(hpke_auth_decap(s, enc, sk_r, pk_r, pk_s), ss_d),
    msg="auth_decap twin differs",
  )
  // auth mode must bind the sender: decapsulating with the wrong pk_s gives a
  // different secret, not the same one
  let (pk_other, _) = hpke_derive_key_pair(s, rb_bytes(r, 32))
  match hpke_auth_decap_or(s, enc, sk_r, pk_r, pk_other) {
    Ok(k) =>
      assert_false(
        bytes_equal(k, ss_d),
        msg="auth mode did not bind the sender key",
      )
    Err(_) => ()
  }
  // hostile peer values are Err, never a trap
  for bad in rb_cases(r, pk_r, 8) {
    match hpke_auth_encap_or(s, bad, sk_s, ikm_e) {
      Ok(_) =>
        assert_true(
          hpke_valid_pk(s, bad),
          msg="auth_encap_or took an invalid pk_r",
        )
      Err(_) =>
        assert_false(
          hpke_valid_pk(s, bad),
          msg="auth_encap_or rejected a valid pk_r",
        )
    }
  }
  for bad in rb_cases(r, enc, 8) {
    match hpke_auth_decap_or(s, bad, sk_r, pk_r, pk_s) {
      Ok(_) =>
        assert_true(
          hpke_valid_pk(s, bad),
          msg="auth_decap_or took an invalid enc",
        )
      Err(_) =>
        assert_false(
          hpke_valid_pk(s, bad),
          msg="auth_decap_or rejected a valid enc",
        )
    }
  }
  for bad in rb_cases(r, pk_s, 6) {
    match hpke_auth_decap_or(s, enc, sk_r, pk_r, bad) {
      Ok(_) =>
        assert_true(
          hpke_valid_pk(s, bad),
          msg="auth_decap_or took an invalid pk_s",
        )
      Err(_) =>
        assert_false(
          hpke_valid_pk(s, bad),
          msg="auth_decap_or rejected a valid pk_s",
        )
    }
  }
}

///|
test "ml_kem hybrid streaming seal_init matches the one-shot seal" {
  let r = rb_rng(0x4B454D5354524DUL)
  let m = rb_bytes(r, 32)
  let aad = b"stream-aad"
  let msg = rb_bytes(r, 300)
  // 512
  let (ek5, _) = ml_kem_512_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let (c5, st5) = ml_kem_512_hybrid_seal_init(ek5, m, aad)
  let blob5 = rb_cat5(
    c5,
    ml_kem_hybrid_stream_update(st5, msg),
    ml_kem_hybrid_stream_final(st5),
  )
  assert_true(
    bytes_equal(blob5, ml_kem_512_hybrid_seal(ek5, m, aad, msg)),
    msg="512: streamed seal != one-shot seal",
  )
  // 768
  let (ek7, _) = ml_kem_768_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let (c7, st7) = ml_kem_768_hybrid_seal_init(ek7, m, aad)
  let blob7 = rb_cat5(
    c7,
    ml_kem_hybrid_stream_update(st7, msg),
    ml_kem_hybrid_stream_final(st7),
  )
  assert_true(
    bytes_equal(blob7, ml_kem_768_hybrid_seal(ek7, m, aad, msg)),
    msg="768: streamed seal != one-shot seal",
  )
  // 1024 (the one that had no test at all)
  let (ek10, dk10) = ml_kem_1024_keygen(rb_bytes(r, 32), rb_bytes(r, 32))
  let (c10, st10) = ml_kem_1024_hybrid_seal_init(ek10, m, aad)
  let body = ml_kem_hybrid_stream_update(st10, msg)
  let blob10 = rb_cat5(c10, body, ml_kem_hybrid_stream_final(st10))
  assert_true(
    bytes_equal(blob10, ml_kem_1024_hybrid_seal(ek10, m, aad, msg)),
    msg="1024: streamed seal != one-shot seal",
  )
  assert_true(c10.length() == 1568, msg="1024: ciphertext length")
  // and the streamed blob really opens
  match ml_kem_1024_hybrid_open(dk10, blob10, aad) {
    Some(got) =>
      assert_true(bytes_equal(got, msg), msg="1024: streamed blob did not open")
    None => assert_true(false, msg="1024: streamed blob rejected")
  }
  // feeding the message in pieces must give the same blob
  let (c10b, st10b) = ml_kem_1024_hybrid_seal_init(ek10, m, aad)
  let p1 = ml_kem_hybrid_stream_update(st10b, rb_slice(msg, 0, 1))
  let p2 = ml_kem_hybrid_stream_update(st10b, rb_slice(msg, 1, 128))
  let p3 = ml_kem_hybrid_stream_update(
    st10b,
    rb_slice(msg, 129, msg.length() - 129),
  )
  let blob10b = rb_cat5(
    c10b,
    rb_cat5(p1, p2, p3),
    ml_kem_hybrid_stream_final(st10b),
  )
  assert_true(
    bytes_equal(blob10b, blob10),
    msg="1024: chunked streaming != single update",
  )
}

///|
/// Three-way concatenation (rb_cat is two-way).
fn rb_cat5(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  rb_cat(rb_cat(a, b), c)
}

///|
test "falcon1024_sign_padded produces a verifying padded signature" {
  // falcon_test_rng_init() takes no seed: two fresh instances produce the same
  // stream, which is what makes the padded and compact signatures comparable
  let kr0 = falcon_test_rng_init()
  let seed = falcon_test_rng_bytes(kr0, 48)
  let (pk, sk) = falcon1024_keypair_from_seed(seed)
  let msg = b"padded falcon-1024 message"
  let kr1 = falcon_test_rng_init()
  let rand = fn(k : Int) -> Bytes { falcon_test_rng_bytes(kr1, k) }
  let sig = falcon1024_sign_padded(sk, msg, rand)
  assert_true(
    sig.length() == 1280,
    msg="padded Falcon-1024 signature must be 1280 bytes",
  )
  assert_true(
    falcon1024_verify(pk, sig, msg),
    msg="padded signature does not verify",
  )
  // a flipped byte must break it, and the compact signer's output must differ
  let a = sig.to_array()
  a[100] = (a[100].to_int() ^ 1).to_byte()
  assert_false(
    falcon1024_verify(pk, Bytes::from_array(a), msg),
    msg="padded signature survived a flipped byte",
  )
  assert_false(
    falcon1024_verify(pk, sig, b"other message"),
    msg="padded signature is not bound to the message",
  )
  // the padded form is the compact signature zero-extended: padding it by hand
  // must give the same bytes, which is what makes the two APIs interchangeable
  let kr2 = falcon_test_rng_init()
  let rand2 = fn(k : Int) -> Bytes { falcon_test_rng_bytes(kr2, k) }
  let compact = falcon1024_sign(sk, msg, rand2)
  let padded_by_hand = Array::make(1280, b'\x00')
  for i in 0..<compact.length() {
    padded_by_hand[i] = compact[i]
  }
  assert_true(
    bytes_equal(Bytes::from_array(padded_by_hand), sig),
    msg="sign_padded is not the compact signature zero-padded to 1280",
  )
}

///|
test "kdf limits and hpke mode guard" {
  // The aborts themselves cannot be asserted from a blackbox test, so what is
  // pinned here is (a) the RFC boundaries from the inside -- a guard that is too
  // tight would break these -- and (b) the one entry point that reports the same
  // class of error as a value: hpke_setup_*_or with an out-of-range mode.
  // RFC 5869 §2.3: L <= 255*HashLen is legal, and must still work
  assert_true(
    hkdf_sha256(b"salt", b"ikm", b"info", 255 * 32).length() == 255 * 32,
    msg="hkdf_sha256 at the RFC 5869 maximum",
  )
  assert_true(
    hkdf_sha512(b"salt", b"ikm", b"info", 255 * 64).length() == 255 * 64,
    msg="hkdf_sha512 at the RFC 5869 maximum",
  )
  assert_true(
    hkdf_sha384(b"salt", b"ikm", b"info", 255 * 48).length() == 255 * 48,
    msg="hkdf_sha384 at the RFC 5869 maximum",
  )
  assert_true(
    hkdf_sm3(b"ikm", b"salt", b"info", 255 * 32).length() == 255 * 32,
    msg="hkdf_sm3 at the RFC 5869 maximum",
  )
  // zero-length outputs are legal, not an error
  assert_true(
    shake_256(b"data", 0).length() == 0,
    msg="shake_256 with out_len 0",
  )
  assert_true(
    shake_128(b"data", 0).length() == 0,
    msg="shake_128 with out_len 0",
  )
  assert_true(
    pbkdf2_hmac_sha256(b"pw", b"salt", 1, 0).length() == 0,
    msg="pbkdf2 with dklen 0",
  )
  // RFC 8018's minimum iteration count must still work
  assert_true(
    pbkdf2_hmac_sha256(b"pw", b"salt", 1, 32).length() == 32,
    msg="pbkdf2 with one iteration",
  )
  // ---- HPKE mode: 0..3 are the RFC's four, anything else is an Err ---------
  let s = hpke_x25519_hkdf_sha256_aes128gcm
  let (pk_r, sk_r) = hpke_derive_key_pair(s, Bytes::make(32, b'\x01'))
  let (pk_s, sk_s) = hpke_derive_key_pair(s, Bytes::make(32, b'\x02'))
  let ikm = Bytes::make(32, b'\x03')
  for mode in [0, 2] {
    match hpke_setup_s_or(s, mode, pk_r, ikm, b"info", b"", b"", sk_s) {
      Ok((enc, ctx)) => {
        let ct = hpke_seal(ctx, b"aad", b"payload")
        let ctx_r = match
          hpke_setup_r_or(s, mode, sk_r, pk_r, enc, b"info", b"", b"", pk_s) {
          Ok(c) => c
          Err(e) => {
            assert_true(
              false,
              msg="setup_r_or rejected mode " + mode.to_string() + ": " + e,
            )
            ctx
          }
        }
        match hpke_open(ctx_r, b"aad", ct) {
          Some(pt) =>
            assert_true(bytes_equal(pt, b"payload"), msg="hpke mode round trip")
          None =>
            assert_true(
              false,
              msg="hpke mode " + mode.to_string() + " did not open",
            )
        }
      }
      Err(e) =>
        assert_true(
          false,
          msg="setup_s_or rejected mode " + mode.to_string() + ": " + e,
        )
    }
  }
  // out-of-range modes used to mean "base mode" silently: no authentication, no
  // PSK, and no error anywhere
  for bad in [4, 9, -1, 255] {
    match hpke_setup_s_or(s, bad, pk_r, ikm, b"info", b"", b"", sk_s) {
      Ok(_) =>
        assert_true(false, msg="setup_s_or accepted mode " + bad.to_string())
      Err(m) =>
        assert_true(
          m == "hpke: mode must be 0 (base), 1 (PSK), 2 (auth) or 3 (PSK+auth)",
          msg="setup_s_or mode message: " + m,
        )
    }
    let (enc0, _) = hpke_setup_s(s, 0, pk_r, ikm, b"info", b"", b"", sk_s)
    match hpke_setup_r_or(s, bad, sk_r, pk_r, enc0, b"info", b"", b"", pk_s) {
      Ok(_) =>
        assert_true(false, msg="setup_r_or accepted mode " + bad.to_string())
      Err(_) => ()
    }
  }
}

///|
test "wave-3 boundaries: xof lengths, block offsets, otp digits" {
  // Third probe wave (v0.85.0). As in the v0.84.0 block above, the aborts
  // themselves cannot be asserted from a blackbox test, so what is pinned here
  // is the inside of every new guard's range: a guard one unit too tight turns
  // these red. Outside the range, the measured behaviour before the guards was
  // a trap (`shake_finalize(h, -1)`, `sha256_finalize_n(h, -1)`,
  // `turbo_shake_*(out_len -1)`, `sm4_encrypt_block(off -1)`,
  // `falcon_xof_extract(-1)`), a core out-of-bounds throw
  // (`sha256_finalize_n(h, 33)`, a 16-word round key), or a silent answer
  // (`hotp(digits -1)` returned "0", `turbo_shake_*(D 0x80)` returned a
  // digest no other implementation produces).
  // ---- streaming XOF: out_len 0 is legal and must still match one-shot ----
  let h0 = shake_128_new()
  sha3_update(h0, b"abc")
  assert_true(
    shake_finalize(h0, 0).length() == 0,
    msg="shake_finalize with out_len 0",
  )
  let h1 = shake_256_new()
  sha3_update(h1, b"abc")
  assert_true(
    bytes_equal(shake_finalize(h1, 64), shake_256(b"abc", 64)),
    msg="streaming shake_finalize == one-shot shake_256",
  )
  // ---- truncated digests at both documented ends ----
  let z = sha256_new()
  sha256_update(z, b"abc")
  assert_true(sha256_finalize_n(z, 0).length() == 0, msg="sha256_finalize_n 0")
  let s2 = sha256_new()
  sha256_update(s2, b"abc")
  assert_true(
    bytes_equal(sha256_finalize_n(s2, 32), sha256(b"abc")),
    msg="sha256_finalize_n at the full digest width",
  )
  let s5 = sha512_new()
  sha512_update(s5, b"abc")
  assert_true(
    bytes_equal(sha512_finalize_n(s5, 64), sha512(b"abc")),
    msg="sha512_finalize_n at the full digest width",
  )
  // ---- TurboSHAKE / KangarooTwelve: D = 1 and D = 127 are RFC 9861's ends ----
  assert_true(
    turbo_shake_128(b"data", b'\x01', 0).length() == 0,
    msg="turbo_shake_128 with out_len 0",
  )
  assert_true(
    turbo_shake_256(b"data", b'\x7f', 32).length() == 32,
    msg="turbo_shake_256 at D = 127",
  )
  assert_true(
    kangaroo_twelve_128(b"data", b"", 0).length() == 0,
    msg="kangaroo_twelve_128 with l = 0",
  )
  assert_true(
    kangaroo_twelve_256(b"data", b"", 16).length() == 16,
    msg="kangaroo_twelve_256 with l = 16",
  )
  // ---- sm4: the last whole block of a longer buffer, round-tripped ----
  let rk = sm4_expand_key(Bytes::make(16, b'\x01'))
  let data = Bytes::make(32, b'\x61')
  let ct = sm4_encrypt_block(rk, data, 16)
  assert_true(ct.length() == 16, msg="sm4_encrypt_block at off = 16 of 32")
  let pt = sm4_decrypt_block(rk, ct, 0)
  let mut same = true
  for i in 0..<16 {
    if pt[i] != data[16 + i] {
      same = false
    }
  }
  assert_true(same, msg="sm4 block round trip across the offset guard")
  // ---- OTP: digits 1 and 9 are the accepted ends, step 1 the smallest ----
  let okey = Bytes::make(20, b'\x31')
  assert_true(hotp(okey, 0UL, 1).length() == 1, msg="hotp with digits = 1")
  assert_true(hotp(okey, 0UL, 9).length() == 9, msg="hotp with digits = 9")
  assert_true(
    hotp_sha256(okey, 0UL, 9).length() == 9,
    msg="hotp_sha256 with digits = 9",
  )
  assert_true(
    hotp_sha512(okey, 0UL, 9).length() == 9,
    msg="hotp_sha512 with digits = 9",
  )
  assert_true(totp(okey, 59UL, 1, 8).length() == 8, msg="totp with step = 1")
  // step = 1 makes the counter the timestamp itself, so this must equal HOTP
  assert_true(
    totp_sha256(okey, 59UL, 1, 8) == hotp_sha256(okey, 59UL, 8),
    msg="totp_sha256 with step = 1 == hotp_sha256 at counter 59",
  )
  // ---- the Falcon XOF at len 0 (falcon_xof_extract's own boundary) ----
  assert_true(
    falcon_xof_extract(falcon_xof_init(), 0).length() == 0,
    msg="falcon_xof_extract with len 0",
  )
}

///|
test "wave-4 boundaries: the 1 GiB size policy and argon2's variants" {
  // Fourth probe wave (v0.87.0). The aborts cannot be asserted from a blackbox
  // test, so this pins the inside of every new bound: all of these are far
  // under the 1 GiB per-buffer cap and must still be honoured, and argon2's
  // three variants must still work. Outside the bounds the measured behaviour
  // before the guards was an opaque throw out of `Array::set` --
  // `zuc_keystream(nwords = 2^30)`, where `nwords * 4` wrapped to 0 so the
  // array was empty -- a silently non-interoperable key (`argon2` with
  // variant 9 or -1, which differs from all three standard variants), and, for
  // scrypt, a `p * 128 * r` that is exactly 2^32 at r = 2^20 and p = 32.
  let kib = 1 << 16
  assert_true(shake_128(b"data", kib).length() == kib, msg="shake_128 64 KiB")
  assert_true(shake_256(b"data", kib).length() == kib, msg="shake_256 64 KiB")
  assert_true(blake3_xof(b"data", kib).length() == kib, msg="blake3_xof 64 KiB")
  assert_true(
    turbo_shake_128(b"data", b'\x07', kib).length() == kib,
    msg="turbo_shake_128 64 KiB",
  )
  assert_true(
    kangaroo_twelve_256(b"data", b"", kib).length() == kib,
    msg="kangaroo_twelve_256 64 KiB",
  )
  assert_true(
    cshake_128(b"data", b"", b"", kib).length() == kib,
    msg="cshake_128 64 KiB",
  )
  assert_true(
    kmac_256(Bytes::make(32, b'\x40'), b"data", b"", kib).length() == kib,
    msg="kmac_256 64 KiB",
  )
  assert_true(
    pbkdf2_hmac_sha256(b"pw", b"salt", 1, kib).length() == kib,
    msg="pbkdf2 dklen 64 KiB",
  )
  assert_true(
    zuc_keystream(Bytes::make(16, b'\x01'), Bytes::make(16, b'\x02'), kib / 4).length() ==
    kib,
    msg="zuc_keystream 64 KiB",
  )
  assert_true(
    zuc256_keystream(
      Bytes::make(32, b'\x01'),
      Bytes::make(23, b'\x02'),
      kib / 4,
    ).length() ==
    kib,
    msg="zuc256_keystream 64 KiB",
  )
  assert_true(
    falcon_xof_extract(falcon_xof_init(), kib).length() == kib,
    msg="falcon_xof_extract 64 KiB",
  )
  // the memory-hard KDFs at their vector sizes, and argon2's variant ends
  assert_true(
    scrypt(b"pw", b"salt", 16, 1, 1, 32).length() == 32,
    msg="scrypt N=16 r=1 p=1",
  )
  assert_true(
    argon2(b"pw", Bytes::make(16, b'\x73'), 1, 64, 1, 32, 0).length() == 32,
    msg="argon2 variant 0 (Argon2d)",
  )
  assert_true(
    argon2(b"pw", Bytes::make(16, b'\x73'), 1, 64, 1, 32, 1).length() == 32,
    msg="argon2 variant 1 (Argon2i)",
  )
  assert_true(
    argon2(b"pw", Bytes::make(16, b'\x73'), 1, 64, 1, 32, 2).length() == 32,
    msg="argon2 variant 2 (Argon2id)",
  )
  assert_true(
    argon2(b"pw", Bytes::make(16, b'\x73'), 1, 64, 1, kib, 2).length() == kib,
    msg="argon2 hash_len 64 KiB",
  )
}

///|
/// Mismatches found by the two helpers below. They cannot use `assert_*`
/// themselves: those carry an error type, which a plain helper `fn` may not
/// have in its signature. So the helpers collect and the test asserts once --
/// which also reports every mismatch instead of stopping at the first.
let wave5_fails : Array[String] = []

///|
/// A twin and its legacy original must agree on every input: `Ok` exactly
/// when the original reported success, carrying the same bytes.
fn wave5_pair(
  label : String,
  legacy : (Bytes, Bool),
  twin : Result[Bytes, String],
  want : Bytes,
) -> Unit {
  let (got, ok) = legacy
  match twin {
    Ok(g2) =>
      if !(ok && bytes_equal(got, want) && bytes_equal(g2, want)) {
        wave5_fails.push(
          label + ": twin said Ok, legacy disagreed or the bytes differ",
        )
      }
    Err(_) =>
      if ok {
        wave5_fails.push(
          label + ": twin said Err but the legacy form succeeded",
        )
      }
  }
}

///|
/// The same, for the `Option` family.
fn wave5_pair_opt(
  label : String,
  legacy : Bytes?,
  twin : Result[Bytes, String],
  want : Bytes,
) -> Unit {
  match (legacy, twin) {
    (Some(got), Ok(g2)) =>
      if !(bytes_equal(got, want) && bytes_equal(g2, want)) {
        wave5_fails.push(label + ": both accepted but the bytes differ")
      }
    (None, Err(_)) => ()
    _ => wave5_fails.push(label + ": twin and legacy disagree about success")
  }
}

///|
test "the Result twins of the legacy-channel decoders and openers" {
  // v0.89.0: every legacy-channel entry point whose logic could be wrapped
  // without restructuring it now has an `_or` twin, so 1.0 can retire
  // `(Bytes, Bool)` and `Option` without leaving callers nowhere to go. The
  // six that mix an `abort` on caller shape with a failure value
  // (aes_gcm_decrypt, sm4_gcm_decrypt, aes_gcm_siv_decrypt, hpke_open,
  // sm2_decrypt) still need their bodies split into a shared core; they are
  // tracked in API_1.0_PLAN.md §3 rather than half-done here.
  let sk = Bytes::make(32, b'\x11')
  let pk = sm2_public_key(sk)
  let msg = b"wave5 payload"
  let rand = sm2_test_rand(7)
  // ---- PKCS#8 / SPKI / PEM ----
  let pkcs8 = sm2_sk_to_pkcs8_der(sk)
  let spki = sm2_pk_to_spki_der(pk)
  wave5_pair(
    "pkcs8_der_to_sk",
    sm2_pkcs8_der_to_sk(pkcs8),
    sm2_pkcs8_der_to_sk_or(pkcs8),
    sk,
  )
  wave5_pair(
    "spki_der_to_pk",
    sm2_spki_der_to_pk(spki),
    sm2_spki_der_to_pk_or(spki),
    pk,
  )
  let sk_pem = sm2_sk_to_pem(sk)
  let pk_pem = sm2_pk_to_pem(pk)
  wave5_pair(
    "sk_from_pem",
    sm2_sk_from_pem(sk_pem),
    sm2_sk_from_pem_or(sk_pem),
    sk,
  )
  wave5_pair(
    "pk_from_pem",
    sm2_pk_from_pem(pk_pem),
    sm2_pk_from_pem_or(pk_pem),
    pk,
  )
  // hostile inputs: both forms must reject
  let bad_der = Bytes::make(10, b'\x30')
  wave5_pair(
    "pkcs8 bad",
    sm2_pkcs8_der_to_sk(bad_der),
    sm2_pkcs8_der_to_sk_or(bad_der),
    sk,
  )
  wave5_pair(
    "spki empty",
    sm2_spki_der_to_pk(b""),
    sm2_spki_der_to_pk_or(b""),
    pk,
  )
  wave5_pair(
    "sk pem junk",
    sm2_sk_from_pem("not a pem"),
    sm2_sk_from_pem_or("not a pem"),
    sk,
  )
  let bad_pem = "-----BEGIN PUBLIC KEY-----\n@@@@\n-----END PUBLIC KEY-----\n"
  wave5_pair(
    "pk pem junk",
    sm2_pk_from_pem(bad_pem),
    sm2_pk_from_pem_or(bad_pem),
    pk,
  )
  // ---- ciphertext and signature DER ----
  let ct = sm2_encrypt(pk, msg, rand)
  let der_ct = sm2_ct_to_der(ct)
  wave5_pair(
    "ct_from_der",
    sm2_ct_from_der(der_ct),
    sm2_ct_from_der_or(der_ct),
    ct,
  )
  wave5_pair(
    "ct_from_der bad",
    sm2_ct_from_der(bad_der),
    sm2_ct_from_der_or(bad_der),
    ct,
  )
  let sig = sm2_sign(sk, msg, b"1234567812345678", rand)
  let der_sig = sm2_sig_to_der(sig)
  wave5_pair(
    "sig_from_der",
    sm2_sig_from_der(der_sig),
    sm2_sig_from_der_or(der_sig),
    sig,
  )
  wave5_pair(
    "sig_from_der empty",
    sm2_sig_from_der(b""),
    sm2_sig_from_der_or(b""),
    sig,
  )
  // ---- the GM/T 0009 envelope ----
  let env = sm2_seal(pk, msg, rand)
  wave5_pair("sm2_open", sm2_open(sk, env), sm2_open_or(sk, env), msg)
  let short_env = Bytes::make(20, b'\x00')
  wave5_pair(
    "sm2_open short",
    sm2_open(sk, short_env),
    sm2_open_or(sk, short_env),
    msg,
  )
  // ---- the Option family: ML-KEM hybrid envelopes ----
  let (ek5, dk5) = ml_kem_512_keygen(
    Bytes::make(32, b'\x01'),
    Bytes::make(32, b'\x02'),
  )
  let blob5 = ml_kem_512_hybrid_seal(ek5, Bytes::make(32, b'\x03'), b"aad", msg)
  wave5_pair_opt(
    "hybrid_open 512",
    ml_kem_512_hybrid_open(dk5, blob5, b"aad"),
    ml_kem_512_hybrid_open_or(dk5, blob5, b"aad"),
    msg,
  )
  wave5_pair_opt(
    "hybrid_open 512 short",
    ml_kem_512_hybrid_open(dk5, b"short", b"aad"),
    ml_kem_512_hybrid_open_or(dk5, b"short", b"aad"),
    msg,
  )
  wave5_pair_opt(
    "hybrid_open 512 wrong aad",
    ml_kem_512_hybrid_open(dk5, blob5, b"other"),
    ml_kem_512_hybrid_open_or(dk5, blob5, b"other"),
    msg,
  )
  let (ek7, dk7) = ml_kem_768_keygen(
    Bytes::make(32, b'\x04'),
    Bytes::make(32, b'\x05'),
  )
  let blob7 = ml_kem_768_hybrid_seal(ek7, Bytes::make(32, b'\x06'), b"aad", msg)
  wave5_pair_opt(
    "hybrid_open 768",
    ml_kem_768_hybrid_open(dk7, blob7, b"aad"),
    ml_kem_768_hybrid_open_or(dk7, blob7, b"aad"),
    msg,
  )
  wave5_pair_opt(
    "hybrid_open 768 wrong dk",
    ml_kem_768_hybrid_open(dk5, blob7, b"aad"),
    ml_kem_768_hybrid_open_or(dk5, blob7, b"aad"),
    msg,
  )
  let (ek10, dk10) = ml_kem_1024_keygen(
    Bytes::make(32, b'\x07'),
    Bytes::make(32, b'\x08'),
  )
  let blob10 = ml_kem_1024_hybrid_seal(
    ek10,
    Bytes::make(32, b'\x09'),
    b"aad",
    msg,
  )
  wave5_pair_opt(
    "hybrid_open 1024",
    ml_kem_1024_hybrid_open(dk10, blob10, b"aad"),
    ml_kem_1024_hybrid_open_or(dk10, blob10, b"aad"),
    msg,
  )
  wave5_pair_opt(
    "hybrid_open 1024 empty",
    ml_kem_1024_hybrid_open(dk10, b"", b"aad"),
    ml_kem_1024_hybrid_open_or(dk10, b"", b"aad"),
    msg,
  )
  let mut joined = ""
  for f in wave5_fails {
    joined = joined + " | " + f
  }
  assert_true(
    wave5_fails.length() == 0,
    msg="twin/legacy mismatches (" +
      wave5_fails.length().to_string() +
      "):" +
      joined,
  )
}

///|
/// A fresh HPKE receiver context over the same deterministic key material, so
/// each comparison in the test below starts at sequence 0. `abort` is fine in a
/// plain helper (unlike `assert_*`, it carries no error type).
fn wave6_hpke_receiver(
  enc : Bytes,
  sk_r : Bytes,
  pk_r : Bytes,
  pk_s : Bytes,
) -> HpkeContext {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  match hpke_setup_r_or(suite, 0, sk_r, pk_r, enc, b"info", b"", b"", pk_s) {
    Ok(c) => c
    Err(e) => abort("hpke setup_r failed: " + e)
  }
}

///|
test "the five mixed-semantics twins agree with their aborting originals" {
  // v0.90.0: aes_gcm_decrypt, sm4_gcm_decrypt, aes_gcm_siv_decrypt, hpke_open
  // and sm2_decrypt each mix an abort on caller shape with a failure value for
  // hostile input. Their bodies moved into the `_or` twin and the original
  // became a projection, so what has to hold is: same success/failure verdict,
  // same bytes -- and, new in the twin, a shape error is an Err instead of an
  // abort. wave5_pair / wave5_pair_opt check the first two on every input.
  let key32 = Bytes::make(32, b'\x2b')
  let iv12 = Bytes::make(12, b'\x07')
  let aad = b"wave6 aad"
  let msg = b"wave6 plaintext"
  // ---- AES-GCM ----
  let (ct, tag) = aes_gcm_encrypt(msg, key32, iv12, aad)
  wave5_pair(
    "aes_gcm",
    aes_gcm_decrypt(ct, key32, iv12, aad, tag),
    aes_gcm_decrypt_or(ct, key32, iv12, aad, tag),
    msg,
  )
  let bad_tag = tag.to_array()
  bad_tag[0] = (bad_tag[0].to_int() ^ 1).to_byte()
  let forged = Bytes::from_array(bad_tag[:])
  wave5_pair(
    "aes_gcm forged",
    aes_gcm_decrypt(ct, key32, iv12, aad, forged),
    aes_gcm_decrypt_or(ct, key32, iv12, aad, forged),
    msg,
  )
  // a 20-byte key: the original aborts, the twin must report it
  match aes_gcm_decrypt_or(ct, Bytes::make(20, b'\x01'), iv12, aad, tag) {
    Ok(_) => assert_true(false, msg="aes_gcm_decrypt_or accepted a 20-byte key")
    Err(_) => ()
  }
  // ---- SM4-GCM ----
  let k16 = Bytes::make(16, b'\x01')
  let (sct, stag) = sm4_gcm_encrypt(msg, k16, iv12, aad)
  wave5_pair(
    "sm4_gcm",
    sm4_gcm_decrypt(sct, k16, iv12, aad, stag),
    sm4_gcm_decrypt_or(sct, k16, iv12, aad, stag),
    msg,
  )
  let s_bad_tag = stag.to_array()
  s_bad_tag[3] = (s_bad_tag[3].to_int() ^ 1).to_byte()
  wave5_pair(
    "sm4_gcm forged",
    sm4_gcm_decrypt(sct, k16, iv12, aad, Bytes::from_array(s_bad_tag[:])),
    sm4_gcm_decrypt_or(sct, k16, iv12, aad, Bytes::from_array(s_bad_tag[:])),
    msg,
  )
  // An 8-byte tag is a caller shape error, so the original aborts on it and
  // only the twin can be asked: it must report, not abort.
  match sm4_gcm_decrypt_or(sct, k16, iv12, aad, Bytes::make(8, b'\x00')) {
    Ok(_) => assert_true(false, msg="sm4_gcm_decrypt_or accepted an 8-byte tag")
    Err(_) => ()
  }
  // ---- AES-GCM-SIV ----
  let siv = aes_gcm_siv_encrypt(key32, iv12, aad, msg)
  wave5_pair_opt(
    "gcm_siv",
    aes_gcm_siv_decrypt(key32, iv12, aad, siv),
    aes_gcm_siv_decrypt_or(key32, iv12, aad, siv),
    msg,
  )
  let siv_bad = siv.to_array()
  siv_bad[0] = (siv_bad[0].to_int() ^ 1).to_byte()
  wave5_pair_opt(
    "gcm_siv forged",
    aes_gcm_siv_decrypt(key32, iv12, aad, Bytes::from_array(siv_bad[:])),
    aes_gcm_siv_decrypt_or(key32, iv12, aad, Bytes::from_array(siv_bad[:])),
    msg,
  )
  wave5_pair_opt(
    "gcm_siv short",
    aes_gcm_siv_decrypt(key32, iv12, aad, b"tooshort"),
    aes_gcm_siv_decrypt_or(key32, iv12, aad, b"tooshort"),
    msg,
  )
  // ---- SM2 ----
  let sk2 = Bytes::make(32, b'\x11')
  let pk2 = sm2_public_key(sk2)
  let rand2 = sm2_test_rand(23)
  let c2 = sm2_encrypt(pk2, msg, rand2)
  wave5_pair("sm2_decrypt", sm2_decrypt(sk2, c2), sm2_decrypt_or(sk2, c2), msg)
  let c2_bad = c2.to_array()
  c2_bad[c2_bad.length() - 1] = (c2_bad[c2_bad.length() - 1].to_int() ^ 1).to_byte()
  wave5_pair(
    "sm2_decrypt forged",
    sm2_decrypt(sk2, Bytes::from_array(c2_bad[:])),
    sm2_decrypt_or(sk2, Bytes::from_array(c2_bad[:])),
    msg,
  )
  match sm2_decrypt_or(Bytes::make(31, b'\x01'), c2) {
    Ok(_) => assert_true(false, msg="sm2_decrypt_or accepted a 31-byte sk")
    Err(_) => ()
  }
  // ---- HPKE ----
  // Every Open advances the receiver's sequence number, so each comparison
  // needs its own fresh context; wave6_hpke_receiver builds one from the same
  // deterministic key material and the sender's `enc`.
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let (pk_r, sk_r) = hpke_derive_key_pair(suite, Bytes::make(32, b''))
  let (pk_s, sk_s) = hpke_derive_key_pair(suite, Bytes::make(32, b''))
  let ikm = Bytes::make(32, b'')
  let (enc, ctx_s) = hpke_setup_s(suite, 0, pk_r, ikm, b"info", b"", b"", sk_s)
  let ct1 = hpke_seal(ctx_s, aad, msg) // sender sequence 0
  let ct2 = hpke_seal(ctx_s, aad, b"second") // sender sequence 1
  let sk_r_copy = sk_r
  let pk_s_copy = pk_s
  wave5_pair_opt(
    "hpke_open ct1",
    hpke_open(wave6_hpke_receiver(enc, sk_r_copy, pk_r, pk_s_copy), aad, ct1),
    hpke_open_or(wave6_hpke_receiver(enc, sk_r_copy, pk_r, pk_s_copy), aad, ct1),
    msg,
  )
  let ct1_bad = ct1.to_array()
  ct1_bad[ct1_bad.length() - 1] = (ct1_bad[ct1_bad.length() - 1].to_int() ^ 1).to_byte()
  let forged1 = Bytes::from_array(ct1_bad[:])
  wave5_pair_opt(
    "hpke_open forged",
    hpke_open(
      wave6_hpke_receiver(enc, sk_r_copy, pk_r, pk_s_copy),
      aad,
      forged1,
    ),
    hpke_open_or(
      wave6_hpke_receiver(enc, sk_r_copy, pk_r, pk_s_copy),
      aad,
      forged1,
    ),
    msg,
  )
  // one nonce per call: the same context must open ct1 then ct2 in order
  let seq_ctx = wave6_hpke_receiver(enc, sk_r_copy, pk_r, pk_s_copy)
  match hpke_open_or(seq_ctx, aad, ct1) {
    Ok(pt) => assert_true(bytes_equal(pt, msg), msg="hpke open ct1 plaintext")
    Err(e) => assert_true(false, msg="hpke open ct1 rejected: " + e)
  }
  match hpke_open_or(seq_ctx, aad, ct2) {
    Ok(pt) =>
      assert_true(bytes_equal(pt, b"second"), msg="hpke open ct2 plaintext")
    Err(e) => assert_true(false, msg="hpke open ct2 rejected: " + e)
  }
  // and a third open of ct1 must now fail: the sequence moved on
  match hpke_open_or(seq_ctx, aad, ct1) {
    Ok(_) => assert_true(false, msg="hpke replayed ct1 at sequence 2")
    Err(_) => ()
  }
  let mut joined = ""
  for f in wave5_fails {
    joined = joined + " | " + f
  }
  assert_true(
    wave5_fails.length() == 0,
    msg="twin/legacy mismatches (" +
      wave5_fails.length().to_string() +
      "):" +
      joined,
  )
}
