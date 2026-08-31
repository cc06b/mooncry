// ==================== Property-based round-trip tests ====================
// A deterministic xorshift32 PRNG drives randomized round-trip checks:
// encrypt then decrypt must recover the plaintext for every cipher, and a
// tampered ciphertext/tag must fail for AEAD. No CSPRNG is used — the goal is
// broad logical self-consistency, not key generation.

///|
/// xorshift32 PRNG state (deterministic). Not for security use.
struct Rng {
  mut state : UInt
}

///|
fn rng_next(r : Rng) -> UInt {
  let mut x = r.state
  x = x ^ (x << 13)
  x = x ^ (x >> 17)
  x = x ^ (x << 5)
  r.state = x
  x
}

///|
/// A non-negative Int in [0, max) derived from the PRNG.
fn rng_int(r : Rng, max : Int) -> Int {
  let v = (rng_next(r) & 0x7FFFFFFFU).reinterpret_as_int()
  v % max
}

///|
/// Fill an array with deterministic bytes and return as Bytes.
fn rng_bytes(r : Rng, len : Int) -> Bytes {
  let arr = Array::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let v = rng_next(r)
    let take = if len - i < 4 { len - i } else { 4 }
    for j in 0..<take {
      arr[i + j] = ((v >> (j * 8)) & 0xFFU).to_byte()
    }
    i = i + take
  }
  Bytes::from_array(arr[:])
}

///|
fn assert_roundtrip(label : String, pt : Bytes, recovered : Bytes) -> Unit {
  if !bytes_equal(pt, recovered) {
    abort("round-trip failed: " + label)
  }
}

///|
test "property: AES-256-GCM round-trip (many sizes)" {
  let r = Rng::{ state: 0x01234567U, }
  let key_sizes = [16, 24, 32]
  for _ in 0..<32 {
    let kl = key_sizes[rng_int(r, 3)]
    let key = rng_bytes(r, kl)
    let nonce = rng_bytes(r, 12)
    let pt = rng_bytes(r, rng_int(r, 200))
    let aad = rng_bytes(r, rng_int(r, 40))
    let (ct, tag) = aes_gcm_encrypt(pt, key, nonce, aad)
    let (rec, ok) = aes_gcm_decrypt(ct, key, nonce, aad, tag)
    assert_true(ok)
    assert_roundtrip("aes-gcm", pt, rec)
    // tamper: flip a ct byte if ct non-empty -> must fail
    if ct.length() > 0 {
      let bad = Array::make(ct.length(), b'\x00')
      for i in 0..<ct.length() {
        bad[i] = ct[i]
      }
      bad[0] = (bad[0].to_int() ^ 0x01).to_byte()
      let (_, ok2) = aes_gcm_decrypt(
        Bytes::from_array(bad[:]),
        key,
        nonce,
        aad,
        tag,
      )
      assert_true(!ok2)
    }
  }
}

///|
test "property: AES-CBC round-trip (many sizes)" {
  let r = Rng::{ state: 0x12345678U, }
  let key_sizes = [16, 24, 32]
  for _ in 0..<24 {
    let kl = key_sizes[rng_int(r, 3)]
    let key = rng_bytes(r, kl)
    let iv = rng_bytes(r, 16)
    let pt = rng_bytes(r, rng_int(r, 200))
    let env = aes_encrypt_cbc(pt, key, iv)
    let rec = aes_decrypt_cbc(env, key, iv)
    assert_roundtrip("aes-cbc", pt, rec)
  }
}

///|
test "property: AES-CTR round-trip (many sizes)" {
  let r = Rng::{ state: 0x76543210U, }
  let key_sizes = [16, 24, 32]
  for _ in 0..<24 {
    let kl = key_sizes[rng_int(r, 3)]
    let key = rng_bytes(r, kl)
    let iv = rng_bytes(r, 16)
    let pt = rng_bytes(r, rng_int(r, 200))
    let ct = aes_ctr(pt, key, iv)
    let rec = aes_ctr(ct, key, iv)
    assert_roundtrip("aes-ctr", pt, rec)
  }
}

///|
test "property: ChaCha20-Poly1305 round-trip (many sizes)" {
  let r = Rng::{ state: 0xABCDEF01U, }
  for _ in 0..<24 {
    let key = rng_bytes(r, 32)
    let nonce = rng_bytes(r, 12)
    let aad = rng_bytes(r, rng_int(r, 40))
    let pt = rng_bytes(r, rng_int(r, 200))
    let env = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    let rec = chacha20_poly1305_decrypt(key, nonce, aad, env)
    assert_roundtrip("chacha20-poly1305", pt, rec)
  }
}

///|
test "property: AES-CMAC determinism" {
  let r = Rng::{ state: 0x2468ACE0U, }
  let key_sizes = [16, 24, 32]
  for _ in 0..<16 {
    let kl = key_sizes[rng_int(r, 3)]
    let key = rng_bytes(r, kl)
    let pt = rng_bytes(r, rng_int(r, 100))
    let mac1 = cmac_aes(pt, key)
    let mac2 = cmac_aes(pt, key)
    assert_true(bytes_equal(mac1, mac2))
    assert_true(mac1.length() == 16)
  }
}

///|
test "property: hex/base64 round-trip" {
  let r = Rng::{ state: 0x369CF147U, }
  for _ in 0..<16 {
    let data = rng_bytes(r, rng_int(r, 300))
    let h = bytes_to_hex(data)
    assert_true(bytes_equal(data, hex_to_bytes(h)))
    let b = base64_encode(data)
    assert_true(bytes_equal(data, base64_decode(b)))
  }
}

///|
test "property: streaming vs one-shot hash consistency" {
  let r = Rng::{ state: 0x4C1E0B2AU, }
  for _ in 0..<8 {
    let data = rng_bytes(r, rng_int(r, 500))
    let one = sha256(data)
    let h = sha256_new()
    // feed in awkward chunk sizes
    let mut off = 0
    while off < data.length() {
      let step = 1 + rng_int(r, 7)
      let take = if off + step > data.length() {
        data.length() - off
      } else {
        step
      }
      let chunk_arr = Array::make(take, b'\x00')
      for i in 0..<take {
        chunk_arr[i] = data[off + i]
      }
      sha256_update(h, Bytes::from_array(chunk_arr[:]))
      off = off + take
    }
    assert_true(bytes_equal(one, sha256_finalize(h)))
    // byte-at-a-time + mixed path (sha256_update_byte)
    let hb = sha256_new()
    let mut offb = 0
    while offb < data.length() {
      if rng_int(r, 2) == 0 {
        sha256_update_byte(hb, data[offb])
        offb = offb + 1
      } else {
        let take = if offb + 3 > data.length() {
          data.length() - offb
        } else {
          3
        }
        let arr = Array::make(take, b'\x00')
        for i in 0..<take {
          arr[i] = data[offb + i]
        }
        sha256_update(hb, Bytes::from_array(arr[:]))
        offb = offb + take
      }
    }
    assert_true(bytes_equal(one, sha256_finalize(hb)))
  }
}

///|
test "property: Result variants (hex_to_bytes_or / base64_decode_or)" {
  // valid input -> Ok with equal bytes
  let ok_hex = hex_to_bytes_or("48656c6c6f")
  match ok_hex {
    Ok(b) => assert_true(bytes_equal(b, b"Hello"))
    Err(_) => {
      println("hex_to_bytes_or on valid input returned Err")
      assert_true(false)
    }
  }
  // invalid input -> Err (no abort)
  let bad_hex = hex_to_bytes_or("zz")
  match bad_hex {
    Ok(_) => {
      println("hex_to_bytes_or on invalid input returned Ok")
      assert_true(false)
    }
    Err(_) => assert_true(true)
  }
  // odd length -> Err
  match hex_to_bytes_or("abc") {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
  // base64 valid + invalid
  match base64_decode_or("SGVsbG8=") {
    Ok(b) => assert_true(bytes_equal(b, b"Hello"))
    Err(_) => assert_true(false)
  }
  match base64_decode_or("!!!!") {
    Ok(_) => assert_true(false)
    Err(_) => assert_true(true)
  }
}
