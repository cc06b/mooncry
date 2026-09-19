// ==================== Streaming state: independence & consistency ====================
//
// Streaming hashers keep mutable state, which opens two failure modes that
// one-shot KATs cannot see:
//
//   * a `clone` that shares its buffer/state arrays with the original, so
//     updating one corrupts the other (nested `Array::make` aliasing has bitten
//     this codebase before);
//   * a prefix shorter than one block being overwritten when absorption
//     crosses the block boundary.
//
// Both are probed at every block boundary below. The rest of the file pins
// streaming-vs-one-shot equality for the hashers the randomized property tests
// do not already cover (MD5, SHA-1, SHA-224/384/512, SHA-512/224, SHA-512/256,
// SHA-3, SHAKE, SM3, Poly1305) and for the two streaming AEAD constructions
// (incremental GMAC and the ML-KEM hybrid envelope).

///|
/// Block boundaries worth probing: empty, one byte, block-1, block, block+1,
/// and the two-block range where a buffer flush happens mid-absorption.
let rb_b64 : Array[Int] = [0, 1, 2, 62, 63, 64, 65, 66, 127, 128, 129]

///|
/// The same, for the 128-byte-block hashes.
let rb_b128 : Array[Int] = [0, 1, 2, 126, 127, 128, 129, 130, 255, 256, 257]

///|
/// SHA-3 rates differ per variant (136 for SHA3-256, 168 for SHAKE128), so
/// probe around both.
let rb_b136 : Array[Int] = [0, 1, 135, 136, 137, 167, 168, 169, 200]

///|
/// Split `data` into chunks of exactly `step` bytes (last one shorter).
fn rb_split(data : Bytes, step : Int) -> Array[Bytes] {
  let out : Array[Bytes] = []
  let mut off = 0
  while off < data.length() {
    let take = if data.length() - off < step {
      data.length() - off
    } else {
      step
    }
    out.push(rb_slice(data, off, take))
    off = off + take
  }
  out
}

///|
test "robust-stream-clone-independence" {
  let r = rb_rng(0x434C4F4E4553UL)
  // SHA-256 (64-byte blocks)
  for plen in rb_b64 {
    let prefix = rb_bytes(r, plen)
    let s1 = rb_bytes(r, 70)
    let s2 = rb_bytes(r, 70)
    let h = sha256_new()
    sha256_update(h, prefix)
    let hc = sha256_clone(h)
    sha256_update(h, s1)
    sha256_update(hc, s2)
    let label = "sha256 clone prefix=" + plen.to_string()
    assert_true(
      rb_eq(sha256_finalize(h), sha256(rb_cat(prefix, s1))),
      msg=label + ": original",
    )
    assert_true(
      rb_eq(sha256_finalize(hc), sha256(rb_cat(prefix, s2))),
      msg=label + ": clone saw the original's suffix",
    )
    // SHA-224 shares the Sha256Hasher type
    let t = sha224_new()
    sha224_update(t, prefix)
    let tc = sha256_clone(t)
    sha224_update(t, s1)
    sha224_update(tc, s2)
    assert_true(
      rb_eq(sha224_finalize(t), sha224(rb_cat(prefix, s1))),
      msg="sha224 clone prefix=" + plen.to_string(),
    )
    assert_true(
      rb_eq(sha224_finalize(tc), sha224(rb_cat(prefix, s2))),
      msg="sha224 clone prefix=" + plen.to_string(),
    )
    // SM3 (also 64-byte blocks)
    let m = sm3_new()
    sm3_update(m, prefix)
    let mc = sm3_clone(m)
    sm3_update(m, s1)
    sm3_update(mc, s2)
    assert_true(
      rb_eq(sm3_finalize(m), sm3(rb_cat(prefix, s1))),
      msg="sm3 streaming prefix=" + plen.to_string(),
    )
    assert_true(
      rb_eq(sm3_finalize(mc), sm3(rb_cat(prefix, s2))),
      msg="sm3 fork prefix=" + plen.to_string(),
    )
  }
  // SHA-512 family (128-byte blocks)
  for plen in rb_b128 {
    let prefix = rb_bytes(r, plen)
    let s1 = rb_bytes(r, 140)
    let s2 = rb_bytes(r, 140)
    let h = sha512_new()
    sha512_update(h, prefix)
    let hc = sha512_clone(h)
    sha512_update(h, s1)
    sha512_update(hc, s2)
    let label = "sha512 clone prefix=" + plen.to_string()
    assert_true(
      rb_eq(sha512_finalize(h), sha512(rb_cat(prefix, s1))),
      msg=label + ": original",
    )
    assert_true(
      rb_eq(sha512_finalize(hc), sha512(rb_cat(prefix, s2))),
      msg=label + ": clone saw the original's suffix",
    )
    let t = sha384_new()
    sha384_update(t, prefix)
    let tc = sha512_clone(t)
    sha384_update(t, s1)
    sha384_update(tc, s2)
    assert_true(
      rb_eq(sha384_finalize(t), sha384(rb_cat(prefix, s1))),
      msg="sha384 clone prefix=" + plen.to_string(),
    )
    assert_true(
      rb_eq(sha384_finalize(tc), sha384(rb_cat(prefix, s2))),
      msg="sha384 clone prefix=" + plen.to_string(),
    )
  }
  // SHA-3 / SHAKE (rate-sized blocks, no length padding until finalize)
  for plen in rb_b136 {
    let prefix = rb_bytes(r, plen)
    let s1 = rb_bytes(r, 100)
    let s2 = rb_bytes(r, 100)
    let h = sha3_256_new()
    sha3_update(h, prefix)
    let hc = sha3_clone(h)
    sha3_update(h, s1)
    sha3_update(hc, s2)
    let label = "sha3_256 clone prefix=" + plen.to_string()
    assert_true(
      rb_eq(sha3_finalize(h), sha3_256(rb_cat(prefix, s1))),
      msg=label + ": original",
    )
    assert_true(
      rb_eq(sha3_finalize(hc), sha3_256(rb_cat(prefix, s2))),
      msg=label + ": clone saw the original's suffix",
    )
    let x = shake_128_new()
    sha3_update(x, prefix)
    let xc = sha3_clone(x)
    sha3_update(x, s1)
    sha3_update(xc, s2)
    assert_true(
      rb_eq(shake_finalize(x, 64), shake_128(rb_cat(prefix, s1), 64)),
      msg="shake128 clone prefix=" + plen.to_string(),
    )
    assert_true(
      rb_eq(shake_finalize(xc, 64), shake_128(rb_cat(prefix, s2), 64)),
      msg="shake128 clone prefix=" + plen.to_string(),
    )
  }
}

///|
test "robust-stream-vs-oneshot" {
  let r = rb_rng(0x53545245414D53UL)
  let data = rb_bytes(r, 1000)
  // every chunk size that can misalign a block buffer
  for
    step in [
      1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 256, 999, 1000,
    ] {
    let parts = rb_split(data, step)
    let label = "step=" + step.to_string()
    {
      let h = md5_new()
      for p in parts {
        md5_update(h, p)
      }
      assert_true(rb_eq(md5_finalize(h), md5(data)), msg="md5 " + label)
    }
    {
      let h = sha1_new()
      for p in parts {
        sha1_update(h, p)
      }
      assert_true(rb_eq(sha1_finalize(h), sha1(data)), msg="sha1 " + label)
    }
    {
      let h = sha224_new()
      for p in parts {
        sha224_update(h, p)
      }
      assert_true(
        rb_eq(sha224_finalize(h), sha224(data)),
        msg="sha224 " + label,
      )
    }
    {
      let h = sha256_new()
      for p in parts {
        sha256_update_byte_or_bytes(h, p)
      }
      assert_true(
        rb_eq(sha256_finalize(h), sha256(data)),
        msg="sha256 " + label,
      )
    }
    {
      let h = sha384_new()
      for p in parts {
        sha384_update(h, p)
      }
      assert_true(
        rb_eq(sha384_finalize(h), sha384(data)),
        msg="sha384 " + label,
      )
    }
    {
      let h = sha512_new()
      for p in parts {
        sha512_update(h, p)
      }
      assert_true(
        rb_eq(sha512_finalize(h), sha512(data)),
        msg="sha512 " + label,
      )
    }
    {
      let h = sha512_224_new()
      for p in parts {
        sha512_224_update(h, p)
      }
      assert_true(
        rb_eq(sha512_224_finalize(h), sha512_224(data)),
        msg="sha512_224 " + label,
      )
    }
    {
      let h = sha512_256_new()
      for p in parts {
        sha512_256_update(h, p)
      }
      assert_true(
        rb_eq(sha512_256_finalize(h), sha512_256(data)),
        msg="sha512_256 " + label,
      )
    }
    {
      let h = sm3_new()
      for p in parts {
        sm3_update(h, p)
      }
      assert_true(rb_eq(sm3_finalize(h), sm3(data)), msg="sm3 " + label)
    }
    {
      let h = sha3_224_new()
      for p in parts {
        sha3_update(h, p)
      }
      assert_true(
        rb_eq(sha3_finalize(h), sha3_224(data)),
        msg="sha3_224 " + label,
      )
    }
    {
      let h = sha3_512_new()
      for p in parts {
        sha3_update(h, p)
      }
      assert_true(
        rb_eq(sha3_finalize(h), sha3_512(data)),
        msg="sha3_512 " + label,
      )
    }
    {
      let h = shake_256_new()
      for p in parts {
        sha3_update(h, p)
      }
      assert_true(
        rb_eq(shake_finalize(h, 100), shake_256(data, 100)),
        msg="shake256 " + label,
      )
    }
    let key = rb_bytes(r, 32)
    let st = poly1305_new(key)
    for p in parts {
      poly1305_update(st, p)
    }
    assert_true(
      rb_eq(poly1305_finalize(st), poly1305(key, data)),
      msg="poly1305 " + label,
    )
  }
  // interleaved hashers must not share state
  let a = sha256_new()
  let b = sha256_new()
  let msg_a = rb_bytes(r, 300)
  let msg_b = rb_bytes(r, 300)
  let pa = rb_split(msg_a, 7)
  let pb = rb_split(msg_b, 11)
  let n = if pa.length() > pb.length() { pa.length() } else { pb.length() }
  for i = 0; i < n; i = i + 1 {
    if i < pa.length() {
      sha256_update(a, pa[i])
    }
    if i < pb.length() {
      sha256_update(b, pb[i])
    }
  }
  assert_true(rb_eq(sha256_finalize(a), sha256(msg_a)), msg="interleaved a")
  assert_true(rb_eq(sha256_finalize(b), sha256(msg_b)), msg="interleaved b")
}

///|
/// sha256_update / sha256_update_byte mix: exercises both entry points on the
/// same hasher, which is how a real protocol parses a length-prefixed stream.
fn sha256_update_byte_or_bytes(h : Sha256Hasher, p : Bytes) -> Unit {
  if p.length() == 1 {
    sha256_update_byte(h, p[0])
  } else {
    sha256_update(h, p)
  }
}

///|
test "robust-stream-aead" {
  let r = rb_rng(0x53545245414D41UL)
  let key = rb_bytes(r, 16)
  let aad = rb_bytes(r, 37)
  // incremental GMAC == one-shot GMAC, at every chunk size and IV length
  for iv_len in [12, 8, 16, 4] {
    let iv = rb_bytes(r, iv_len)
    let one_shot = if iv_len == 12 {
      gmac(key, iv, aad)
    } else {
      gmac_iv(key, iv, aad)
    }
    for step in [1, 3, 16, 17, 37] {
      let st = if iv_len == 12 {
        gmac_new(key, iv)
      } else {
        gmac_new_iv(key, iv)
      }
      for p in rb_split(aad, step) {
        gmac_update(st, p)
      }
      assert_true(
        rb_eq(gmac_finalize(st), one_shot),
        msg="gmac stream iv=" + iv_len.to_string() + " step=" + step.to_string(),
      )
      if iv_len == 12 {
        // gmac_stream_verify is the 12-byte-IV convenience form
        assert_true(
          gmac_stream_verify(key, iv, aad, one_shot),
          msg="gmac_stream_verify",
        )
        // a flipped bit in the tag must not verify
        assert_false(gmac_stream_verify(key, iv, aad, rb_flip(r, one_shot)))
      }
    }
  }
  // the ML-KEM hybrid envelope: streaming seal == one-shot seal
  let d = rb_bytes(r, 32)
  let z = rb_bytes(r, 32)
  let (ek, _dk) = ml_kem_512_keygen(d, z)
  let m = rb_bytes(r, 32)
  let msg = rb_bytes(r, 500)
  for step in [1, 7, 64, 65, 128, 499, 500] {
    let (c, st) = ml_kem_512_hybrid_seal_init(ek, m, aad)
    let parts : Array[Bytes] = [c]
    for p in rb_split(msg, step) {
      parts.push(ml_kem_hybrid_stream_update(st, p))
    }
    parts.push(ml_kem_hybrid_stream_final(st))
    let mut streamed = b""
    for p in parts {
      streamed = rb_cat(streamed, p)
    }
    let one_shot = ml_kem_512_hybrid_seal(ek, m, aad, msg)
    assert_true(
      rb_eq(streamed, one_shot),
      msg="hybrid stream step=" + step.to_string(),
    )
    match ml_kem_512_hybrid_open(_dk, streamed, aad) {
      Ok(got) => assert_true(rb_eq(got, msg), msg="hybrid stream open")
      Err(_) => assert_true(false, msg="hybrid stream: open rejected")
    }
  }
}

///|
/// Append one keystream word to a byte buffer, big-endian.
fn rb_zuc_word(a : Array[Byte], v : UInt64) -> Unit {
  a.push(((v >> 24) & 0xFFUL).to_int().to_byte())
  a.push(((v >> 16) & 0xFFUL).to_int().to_byte())
  a.push(((v >> 8) & 0xFFUL).to_int().to_byte())
  a.push((v & 0xFFUL).to_int().to_byte())
}

///|
test "robust-zuc-state" {
  // ZucState is mutable and handed to the caller, who drives it one word at a
  // time, so two live states must not share anything. The engine reads two
  // module-level S-box tables (widened to UInt64 once at load) and writes only
  // its own state's LFSR cells and R1/R2 — interleave two states word by word
  // and require each to reproduce its own one-shot keystream.
  let r = rb_rng(0x5A3C53544154UL)
  let k1 = rb_bytes(r, 16)
  let v1 = rb_bytes(r, 16)
  let k2 = rb_bytes(r, 16)
  let v2 = rb_bytes(r, 16)
  let a = zuc_init(k1, v1)
  let b = zuc_init(k2, v2)
  let wa : Array[Byte] = []
  let wb : Array[Byte] = []
  for _i in 0..<40 {
    rb_zuc_word(wa, zuc_next_word(a))
    rb_zuc_word(wb, zuc_next_word(b))
  }
  assert_true(
    rb_eq(Bytes::from_array(wa), zuc_keystream(k1, v1, 40)),
    msg="zuc: state a drifted when interleaved with state b",
  )
  assert_true(
    rb_eq(Bytes::from_array(wb), zuc_keystream(k2, v2, 40)),
    msg="zuc: state b drifted when interleaved with state a",
  )
  // the same for ZUC-256: a different key schedule, the same engine
  let k3 = rb_bytes(r, 32)
  let v3 = rb_bytes(r, 23)
  let k4 = rb_bytes(r, 32)
  let v4 = rb_bytes(r, 23)
  let c = zuc256_init(k3, v3)
  let d = zuc256_init(k4, v4)
  let wc : Array[Byte] = []
  let wd : Array[Byte] = []
  for _i in 0..<40 {
    rb_zuc_word(wd, zuc_next_word(d))
    rb_zuc_word(wc, zuc_next_word(c))
  }
  assert_true(
    rb_eq(Bytes::from_array(wc), zuc256_keystream(k3, v3, 40)),
    msg="zuc256: state c drifted when interleaved",
  )
  assert_true(
    rb_eq(Bytes::from_array(wd), zuc256_keystream(k4, v4, 40)),
    msg="zuc256: state d drifted when interleaved",
  )
  // and a mixed pair must not cross-contaminate either
  let e = zuc_init(k1, v1)
  let f = zuc256_init(k3, v3)
  let we : Array[Byte] = []
  let wf : Array[Byte] = []
  for _i in 0..<16 {
    rb_zuc_word(we, zuc_next_word(e))
    rb_zuc_word(wf, zuc_next_word(f))
  }
  assert_true(
    rb_eq(Bytes::from_array(we), zuc_keystream(k1, v1, 16)),
    msg="zuc: 128-bit state drifted against a 256-bit state",
  )
  assert_true(
    rb_eq(Bytes::from_array(wf), zuc256_keystream(k3, v3, 16)),
    msg="zuc256: 256-bit state drifted against a 128-bit state",
  )
}
