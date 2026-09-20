// ==================== Boundary-length sweeps ====================
//
// The randomized property tests (`property_test.mbt`, `phase3_property_test.mbt`)
// cover "many sizes" drawn from a PRNG; this file pins the sizes that actually
// matter for block-oriented code: every multiple and off-by-one around the
// 16-byte block boundary, the empty input, and the 255/256/257 lengths that
// stress length-encoding fields (CCM's q, GHASH/Poly1305 padding, PKCS#7's
// extra full block, GCM-SIV's counter block).
//
// For each scheme and length: encrypt -> decrypt must recover the plaintext
// exactly, the output length must be what the format specifies, and a
// single-bit flip anywhere in the box blob must be rejected.

///|
/// Plaintext lengths: empty, the 16-byte block boundary +/-1, and the
/// 255/256/257 range that crosses byte-width thresholds in length fields.
let rb_pt_lens : Array[Int] = [
  0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
]

///|
/// AAD lengths: the same boundaries, since AAD goes through its own padding
/// path in GHASH / Poly1305 / CCM / S2V.
let rb_aad_lens : Array[Int] = [0, 1, 15, 16, 17]

///|
/// Flip one bit in `data` (deterministic position) and require that `check`
/// rejects the result.
fn rb_assert_tamper_rejected(
  r : RbRng,
  data : Bytes,
  check : (Bytes) -> Bool,
  what : String,
) -> Unit {
  if data.length() == 0 {
    return
  }
  let a = data.to_array()
  let i = rb_upto(r, a.length())
  a[i] = (a[i].to_int() ^ (1 << rb_upto(r, 8))).to_byte()
  if check(Bytes::from_array(a)) {
    abort(what + ": tampered input was accepted")
  }
}

///|
test "boundary-chacha20-poly1305" {
  let r = rb_rng(0x424F554E444350UL)
  let key = rb_bytes(r, 32)
  for pt_len in rb_pt_lens {
    let pt = rb_bytes(r, pt_len)
    for aad_len in rb_aad_lens {
      let aad = rb_bytes(r, aad_len)
      let nonce = rb_bytes(r, 12)
      let label = "chacha20_poly1305 pt=" +
        pt_len.to_string() +
        " aad=" +
        aad_len.to_string()
      let box = chacha20_poly1305_encrypt(key, nonce, aad, pt)
      assert_true(box.length() == pt_len + 16, msg=label + ": wrong box length")
      match chacha20_poly1305_decrypt_or(key, nonce, aad, box) {
        Ok(got) => assert_true(rb_eq(got, pt), msg=label + ": round trip")
        Err(_) => assert_true(false, msg=label + ": rejected authentic input")
      }
      rb_assert_tamper_rejected(
        r,
        box,
        fn(c : Bytes) -> Bool {
          match chacha20_poly1305_decrypt_or(key, nonce, aad, c) {
            Ok(_) => true
            Err(_) => false
          }
        },
        label,
      )
      // XChaCha20-Poly1305 shares the code path with a 24-byte nonce
      let nonce24 = rb_bytes(r, 24)
      let xsealed = xchacha20_poly1305_encrypt(key, nonce24, aad, pt)
      assert_true(xsealed.length() == pt_len + 16, msg="xchacha20: length")
      match xchacha20_poly1305_decrypt_or(key, nonce24, aad, xsealed) {
        Ok(got) => assert_true(rb_eq(got, pt), msg="xchacha20 " + label)
        Err(_) => assert_true(false, msg="xchacha20 " + label + ": rejected")
      }
    }
  }
}

///|
test "boundary-aes-gcm-family" {
  let r = rb_rng(0x424F554E444743UL)
  let key32 = rb_bytes(r, 32)
  let key24 = rb_slice(key32, 0, 24)
  let key16 = rb_slice(key32, 0, 16)
  for pt_len in rb_pt_lens {
    let pt = rb_bytes(r, pt_len)
    for aad_len in rb_aad_lens {
      let aad = rb_bytes(r, aad_len)
      let nonce = rb_bytes(r, 12)
      let label = "pt=" + pt_len.to_string() + " aad=" + aad_len.to_string()
      // AES-GCM across all three key sizes
      for key in [key16, key24, key32] {
        let { ct, tag, } = aes_gcm_encrypt(pt, key, nonce, aad)
        assert_true(ct.length() == pt_len, msg="aes_gcm " + label + ": ct len")
        assert_true(tag.length() == 16, msg="aes_gcm " + label + ": tag len")
        let (got, ok) = bb_flag(aes_gcm_decrypt(ct, key, nonce, aad, tag))
        assert_true(ok && rb_eq(got, pt), msg="aes_gcm " + label)
        rb_assert_tamper_rejected(
          r,
          ct,
          fn(c : Bytes) -> Bool {
            bb_flag(aes_gcm_decrypt(c, key, nonce, aad, tag)).1
          },
          "aes_gcm " + label,
        )
        // GMAC is the empty-plaintext GCM tag: it must match
        assert_true(
          gmac_verify(
            key,
            nonce,
            aad,
            aes_gcm_encrypt(b"", key, nonce, aad).tag,
          ),
          msg="gmac " + label,
        )
      }
      // SM4-GCM (128-bit key only)
      let kpr1 = sm4_gcm_encrypt(pt, key16, nonce, aad)
      let sct = kpr1.ct
      let stag = kpr1.tag
      assert_true(sct.length() == pt_len, msg="sm4_gcm " + label + ": ct len")
      let (sgot, sok) = bb_flag(sm4_gcm_decrypt(sct, key16, nonce, aad, stag))
      assert_true(sok && rb_eq(sgot, pt), msg="sm4_gcm " + label)
      rb_assert_tamper_rejected(
        r,
        sct,
        fn(c : Bytes) -> Bool {
          bb_flag(sm4_gcm_decrypt(c, key16, nonce, aad, stag)).1
        },
        "sm4_gcm " + label,
      )
      // AES-GCM-SIV (RFC 8452), both key sizes
      for key in [key16, key32] {
        let box = aes_gcm_siv_encrypt(key, nonce, aad, pt)
        assert_true(
          box.length() == pt_len + 16,
          msg="gcm_siv " + label + ": length",
        )
        match aes_gcm_siv_decrypt(key, nonce, aad, box) {
          Ok(got) => assert_true(rb_eq(got, pt), msg="gcm_siv " + label)
          Err(_) => assert_true(false, msg="gcm_siv " + label + ": rejected")
        }
        rb_assert_tamper_rejected(
          r,
          box,
          fn(c : Bytes) -> Bool {
            match aes_gcm_siv_decrypt(key, nonce, aad, c) {
              Ok(_) => true
              Err(_) => false
            }
          },
          "gcm_siv " + label,
        )
      }
    }
  }
}

///|
test "boundary-aes-ccm" {
  let r = rb_rng(0x424F554E444343UL)
  let key = rb_bytes(r, 16)
  // nonce length 7..13 sets q = 15 - nonce_len, the width of the CCM length
  // field: 7 (q=8), 11 (q=4) and 13 (q=2) exercise all three encodings.
  for nonce_len in [7, 11, 13] {
    for mac_len in [4, 8, 16] {
      for pt_len in rb_pt_lens {
        let pt = rb_bytes(r, pt_len)
        for aad_len in [0, 16] {
          let aad = rb_bytes(r, aad_len)
          let nonce = rb_bytes(r, nonce_len)
          let label = "ccm n=" +
            nonce_len.to_string() +
            " mac=" +
            mac_len.to_string() +
            " pt=" +
            pt_len.to_string() +
            " aad=" +
            aad_len.to_string()
          let box = aes_ccm_encrypt(pt, key, nonce, aad, mac_len)
          assert_true(
            box.length() == pt_len + mac_len,
            msg=label + ": wrong box length",
          )
          match aes_ccm_decrypt_or(box, key, nonce, aad, mac_len) {
            Ok(got) => assert_true(rb_eq(got, pt), msg=label + ": round trip")
            Err(_) => assert_true(false, msg=label + ": rejected authentic")
          }
          rb_assert_tamper_rejected(
            r,
            box,
            fn(c : Bytes) -> Bool {
              match aes_ccm_decrypt_or(c, key, nonce, aad, mac_len) {
                Ok(_) => true
                Err(_) => false
              }
            },
            label,
          )
        }
      }
    }
  }
}

///|
test "boundary-siv-kw-cbc-ctr" {
  let r = rb_rng(0x424F554E445349UL)
  let key64 = rb_bytes(r, 64)
  let key48 = rb_slice(key64, 0, 48)
  let key32 = rb_slice(key64, 0, 32)
  let key16 = rb_slice(key64, 0, 16)
  let iv = rb_bytes(r, 16)
  for pt_len in rb_pt_lens {
    let pt = rb_bytes(r, pt_len)
    let label = "pt=" + pt_len.to_string()
    // AES-SIV across all three key sizes, with 0/1/2 associated-data entries
    for key in [key32, key48, key64] {
      let ads_list : Array[Array[Bytes]] = [[], [b"aad"], [b"aad", b"more"]]
      for ads in ads_list {
        let box = aes_siv_encrypt(key, pt, ads)
        assert_true(
          box.length() == pt_len + 16,
          msg="aes_siv " + label + ": length",
        )
        match aes_siv_decrypt(box, key, ads) {
          Ok(got) => assert_true(rb_eq(got, pt), msg="aes_siv " + label)
          Err(_) => assert_true(false, msg="aes_siv " + label + ": rejected")
        }
        rb_assert_tamper_rejected(
          r,
          box,
          fn(c : Bytes) -> Bool {
            match aes_siv_decrypt(c, key, ads) {
              Ok(_) => true
              Err(_) => false
            }
          },
          "aes_siv " + label,
        )
      }
    }
    // AES-KW: key_data must be a nonzero multiple of 8
    if pt_len > 0 && pt_len % 8 == 0 {
      let wrapped = aes_kw_wrap(key16, pt)
      assert_true(
        wrapped.length() == pt_len + 8,
        msg="aes_kw " + label + ": length",
      )
      match aes_kw_unwrap(key16, wrapped) {
        Ok(got) => assert_true(rb_eq(got, pt), msg="aes_kw " + label)
        Err(_) => assert_true(false, msg="aes_kw " + label + ": rejected")
      }
      rb_assert_tamper_rejected(
        r,
        wrapped,
        fn(c : Bytes) -> Bool {
          match aes_kw_unwrap(key16, c) {
            Ok(_) => true
            Err(_) => false
          }
        },
        "aes_kw " + label,
      )
    }
    // AES-CBC with PKCS#7: a plaintext that is an exact multiple of 16 must
    // gain a FULL extra padding block (the classic off-by-one).
    let cbc = aes_encrypt_cbc(pt, key16, iv)
    let expected = 16 + (pt_len / 16 + 1) * 16
    assert_true(
      cbc.length() == expected,
      msg="aes_cbc " +
        label +
        ": padded length " +
        cbc.length().to_string() +
        " != " +
        expected.to_string(),
    )
    match aes_decrypt_cbc_or(cbc, key16, iv) {
      Ok(got) => assert_true(rb_eq(got, pt), msg="aes_cbc " + label)
      Err(_) => assert_true(false, msg="aes_cbc " + label + ": rejected")
    }
    // AES-CTR is a pure stream: length in == length out
    let ctr = aes_ctr(pt, key16, iv)
    assert_true(ctr.length() == pt_len, msg="aes_ctr " + label + ": length")
    assert_true(
      rb_eq(aes_ctr(ctr, key16, iv), pt),
      msg="aes_ctr " + label + ": round trip",
    )
    // SM4 raw modes only accept whole blocks
    if pt_len > 0 && pt_len % 16 == 0 {
      let sct = sm4_cbc_encrypt(key16, iv, pt)
      assert_true(sct.length() == pt_len, msg="sm4_cbc " + label + ": length")
      match sm4_cbc_decrypt_or(key16, iv, sct) {
        Ok(got) => assert_true(rb_eq(got, pt), msg="sm4_cbc " + label)
        Err(_) => assert_true(false, msg="sm4_cbc " + label + ": rejected")
      }
      assert_true(
        rb_eq(sm4_ctr(key16, iv, sm4_ctr(key16, iv, pt)), pt),
        msg="sm4_ctr " + label,
      )
    }
    // box box and the ML-KEM hybrid envelope wrap an AEAD around a KEM
    let nonce12 = rb_bytes(r, 12)
    let env = sealed_box_seal(key32, nonce12, pt, b"aad", b"ctx")
    assert_true(
      env.length() == pt_len + 1 + 12 + 16,
      msg="sealed_box " + label + ": length",
    )
    match sealed_box_open(key32, env, b"aad", b"ctx") {
      Ok(got) => assert_true(rb_eq(got, pt), msg="sealed_box " + label)
      Err(_) => assert_true(false, msg="sealed_box " + label + ": rejected")
    }
    rb_assert_tamper_rejected(
      r,
      env,
      fn(e : Bytes) -> Bool {
        match sealed_box_open(key32, e, b"aad", b"ctx") {
          Ok(_) => true
          Err(_) => false
        }
      },
      "sealed_box " + label,
    )
  }
}

///|
test "boundary-kem-envelopes" {
  let r = rb_rng(0x424F554E444B45UL)
  let d = rb_bytes(r, 32)
  let z = rb_bytes(r, 32)
  let { ek, dk, } = ml_kem_512_keygen(d, z)
  let m = rb_bytes(r, 32)
  let aad = rb_bytes(r, 13)
  for pt_len in rb_pt_lens {
    let pt = rb_bytes(r, pt_len)
    let label = "hybrid pt=" + pt_len.to_string()
    let blob = ml_kem_512_hybrid_seal(ek, m, aad, pt)
    assert_true(
      blob.length() == 768 + pt_len + 16,
      msg=label + ": blob length " + blob.length().to_string(),
    )
    match ml_kem_512_hybrid_open(dk, blob, aad) {
      Ok(got) => assert_true(rb_eq(got, pt), msg=label + ": round trip")
      Err(_) => assert_true(false, msg=label + ": rejected authentic blob")
    }
    rb_assert_tamper_rejected(
      r,
      blob,
      fn(e : Bytes) -> Bool {
        match ml_kem_512_hybrid_open(dk, e, aad) {
          Ok(_) => true
          Err(_) => false
        }
      },
      label,
    )
  }
  // SM2 box envelope (GM/T 0009 style): 125-byte wrapped key + 12-byte IV
  // + SM4-GCM body, so the payload sweep doubles as an SM4-GCM boundary sweep.
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  for pt_len in rb_pt_lens {
    if pt_len == 0 {
      continue // sm2_seal carries a payload; the empty case is covered by GCM
    }
    let pt = rb_bytes(r, pt_len)
    let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
    let label = "sm2_seal pt=" + pt_len.to_string()
    let env = sm2_seal(pk, pt, rand)
    assert_true(
      env.length() == 125 + 12 + pt_len + 16,
      msg=label + ": envelope length " + env.length().to_string(),
    )
    let (got, ok) = bb_flag(sm2_open(sk, env))
    assert_true(ok && rb_eq(got, pt), msg=label + ": round trip")
    rb_assert_tamper_rejected(
      r,
      env,
      fn(e : Bytes) -> Bool { bb_flag(sm2_open(sk, e)).1 },
      label,
    )
  }
}
