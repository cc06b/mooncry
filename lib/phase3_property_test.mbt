// ==================== Phase-3 property tests (AES-SIV / AES-KW / ECDSA / Argon2) ====================
// Deterministic-PRNG-driven round-trip + determinism + tamper-reject checks
// for the algorithms added in 0.9.0–0.13.0. Broader input coverage than the
// static standard vectors.

///|
priv struct P3Rng {
  mut state : UInt
}

///|
fn p3_next(r : P3Rng) -> UInt {
  let mut x = r.state
  x = x ^ (x << 13)
  x = x ^ (x >> 7)
  x = x ^ (x << 17)
  r.state = x
  x
}

///|
fn p3_int(r : P3Rng, max : Int) -> Int {
  (p3_next(r) & 0x7FFFFFFFU).reinterpret_as_int() % max
}

///|
fn p3_bytes(r : P3Rng, len : Int) -> Bytes {
  let arr = Array::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let v = p3_next(r)
    let take = if len - i < 4 { len - i } else { 4 }
    for j in 0..<take {
      arr[i + j] = ((v >> (j * 8)) & 0xFFU).to_byte()
    }
    i = i + take
  }
  Bytes::from_array(arr[:])
}

// ---- AES-SIV ----

///|
test "property: AES-SIV round-trip (many sizes)" {
  let r = P3Rng::{ state: 0xA5A5A5A5U, }
  for _ in 0..<16 {
    let klen = [32, 48, 64][p3_int(r, 3)]
    let key = p3_bytes(r, klen)
    let pt = p3_bytes(r, p3_int(r, 200))
    let n_ad = p3_int(r, 3)
    let ads : Array[Bytes] = []
    for _ in 0..<n_ad {
      ads.push(p3_bytes(r, p3_int(r, 40) + 1))
    }
    let env = aes_siv_encrypt(key, pt, ads)
    match aes_siv_decrypt(env, key, ads) {
      Ok(rec) => {
        let ok = bytes_equal(pt, rec)
        if !ok {
          println("AES-SIV round-trip mismatch")
          assert_true(false)
        }
      }
      Err(_) => {
        println("AES-SIV decrypt failed")
        assert_true(false)
      }
    }
    // tamper: flip a byte of the IV -> must fail
    if env.length() > 0 {
      let bad = Array::make(env.length(), b'\x00')
      for i in 0..<env.length() {
        bad[i] = env[i]
      }
      bad[0] = (bad[0].to_int() ^ 0x01).to_byte()
      match aes_siv_decrypt(Bytes::from_array(bad[:]), key, ads) {
        Ok(_) => {
          println("AES-SIV tamper should have failed")
          assert_true(false)
        }
        Err(_) => assert_true(true)
      }
    }
  }
}

// ---- AES-KW ----

///|
test "property: AES-KW round-trip (many sizes)" {
  let r = P3Rng::{ state: 0x12345678U, }
  for _ in 0..<16 {
    let klen = [16, 24, 32][p3_int(r, 3)]
    let kek = p3_bytes(r, klen)
    let dlen = (p3_int(r, 4) + 1) * 8 // 8,16,24,32,40 bytes
    let data = p3_bytes(r, dlen)
    let wrapped = aes_kw_wrap(kek, data)
    match aes_kw_unwrap(kek, wrapped) {
      Ok(rec) => assert_true(bytes_equal(data, rec))
      Err(_) => {
        println("AES-KW unwrap failed")
        assert_true(false)
      }
    }
  }
}

// ---- ECDSA P-256 ----

///|
test "property: ECDSA P-256 sign/verify round-trip + determinism" {
  let r = P3Rng::{ state: 0xDEADBEEFU, }
  // fixed private key (deterministic sign)
  let d = p3_bytes(r, 32)
  let q = ecdsa_p256_public_key(d)
  for _ in 0..<8 {
    let msg = p3_bytes(r, p3_int(r, 200))
    let sig = ecdsa_p256_sign(d, msg)
    assert_true(ecdsa_p256_verify(q, msg, sig))
    // determinism: same (d, msg) -> same sig
    let sig2 = ecdsa_p256_sign(d, msg)
    assert_true(bytes_equal(sig, sig2))
    // tamper msg -> reject
    let bad_msg = p3_bytes(r, 10)
    assert_true(!ecdsa_p256_verify(q, bad_msg, sig))
    // tamper sig -> reject
    let bad = Array::make(64, b'\x00')
    for i in 0..<64 {
      bad[i] = sig[i]
    }
    bad[0] = (bad[0].to_int() ^ 0x01).to_byte()
    assert_true(!ecdsa_p256_verify(q, msg, Bytes::from_array(bad[:])))
  }
}

// ---- Argon2 ----

///|
test "property: Argon2 determinism + variant separation" {
  // determinism: same params -> same tag (all three variants)
  let pw = b"deterministic password"
  let salt = b"saltforsalt"
  for variant in [0, 1, 2] {
    let t1 = argon2(pw, salt, 1, 8, 1, 16, variant)
    let t2 = argon2(pw, salt, 1, 8, 1, 16, variant)
    assert_true(bytes_equal(t1, t2))
  }
  // variant separation: 2d/2i/2id produce different tags
  let d = argon2d(pw, salt, 1, 16, 1, 16)
  let i = argon2i(pw, salt, 1, 16, 1, 16)
  let id = argon2id(pw, salt, 1, 16, 1, 16)
  assert_true(!bytes_equal(d, i))
  assert_true(!bytes_equal(d, id))
  assert_true(!bytes_equal(i, id))
  // parameter sensitivity: different m/t/p -> different tag
  let a = argon2id(pw, salt, 1, 8, 1, 16)
  let b = argon2id(pw, salt, 2, 8, 1, 16)
  assert_true(!bytes_equal(a, b))
}
