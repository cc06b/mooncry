// ==================== GMAC arbitrary-length IV tests (v0.24.0) ============
// Vectors from pycryptodome AES-GCM (empty plaintext => GMAC tag) with
// nonces of various lengths. key = 000102...0f, aad = 001122...ff unless
// noted. SP 800-38D §8.2.1: 96-bit IVs use J0 = IV || 0^31 || 1; other
// lengths use J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64).

///|
let gi_key : Bytes = hex_to_bytes("000102030405060708090a0b0c0d0e0f")

///|
let gi_aad : Bytes = hex_to_bytes("00112233445566778899aabbccddeeff")

///|
test "gmac_iv: 1-byte IV (pycryptodome)" {
  let tag = gmac_iv(gi_key, hex_to_bytes("64"), gi_aad)
  assert_true(
    bytes_equal(tag, hex_to_bytes("00fa0452e1f5244969a720da76ee3010")),
  )
}

///|
test "gmac_iv: 8-byte IV (pycryptodome)" {
  let tag = gmac_iv(gi_key, hex_to_bytes("6465666768696a6b"), gi_aad)
  assert_true(
    bytes_equal(tag, hex_to_bytes("502de6a2bed52248db7958c9c10c0759")),
  )
}

///|
test "gmac_iv: 16-byte IV (pycryptodome)" {
  let tag = gmac_iv(
    gi_key,
    hex_to_bytes("6465666768696a6b6c6d6e6f70717273"),
    gi_aad,
  )
  assert_true(
    bytes_equal(tag, hex_to_bytes("4d019c65f91817d0873c05c13cc0ecf0")),
  )
}

///|
test "gmac_iv: 20-byte IV (pycryptodome)" {
  let tag = gmac_iv(
    gi_key,
    hex_to_bytes("6465666768696a6b6c6d6e6f7071727374757677"),
    gi_aad,
  )
  assert_true(
    bytes_equal(tag, hex_to_bytes("bd3e9c94a29377ea77e133039d3dd759")),
  )
}

///|
test "gmac_iv: 32-byte IV (pycryptodome)" {
  let tag = gmac_iv(
    gi_key,
    hex_to_bytes(
      "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283",
    ),
    gi_aad,
  )
  assert_true(
    bytes_equal(tag, hex_to_bytes("c9ddfe1770ed495905d61ff3c050a998")),
  )
}

///|
test "gmac_iv: 12-byte IV == fast-path gmac (compat)" {
  let iv = hex_to_bytes("6465666768696a6b6c6d6e6f")
  assert_true(
    bytes_equal(gmac_iv(gi_key, iv, gi_aad), gmac(gi_key, iv, gi_aad)),
  )
  assert_true(
    bytes_equal(
      gmac_iv(gi_key, iv, gi_aad),
      hex_to_bytes("81a272cf0e0c320a1c9a68a33897d589"),
    ),
  )
}

///|
test "gmac_iv: long AAD (100 bytes, pycryptodome)" {
  let aad = Bytes::from_array(
    (fn() {
      let arr = Array::make(100, b'\x00')
      for i in 0..<100 {
        arr[i] = i.to_byte()
      }
      arr
    })(),
  )
  let tag16 = gmac_iv(
    gi_key,
    hex_to_bytes("6465666768696a6b6c6d6e6f70717273"),
    aad,
  )
  assert_true(
    bytes_equal(tag16, hex_to_bytes("f949e6ec4c9ecf2912fb0eef132078f1")),
  )
  let tag33 = gmac_iv(
    gi_key,
    hex_to_bytes(
      "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384",
    ),
    aad,
  )
  assert_true(
    bytes_equal(tag33, hex_to_bytes("0f54ba0bda7777afe6b0fa90b7546aa7")),
  )
}

///|
test "gmac_iv_verify accepts/rejects" {
  let iv = hex_to_bytes("6465666768696a6b6c6d6e6f70717273")
  assert_true(
    gmac_iv_verify(
      gi_key,
      iv,
      gi_aad,
      hex_to_bytes("4d019c65f91817d0873c05c13cc0ecf0"),
    ),
  )
  assert_false(
    gmac_iv_verify(
      gi_key,
      iv,
      gi_aad,
      hex_to_bytes("4d019c65f91817d0873c05c13cc0ecf1"),
    ),
  )
}

///|
test "property: streaming gmac_new_iv == one-shot gmac_iv" {
  let r = Rng::{ state: 0x61AC1A01U, }
  for trial in 0..<6 {
    let iv_len = [1, 11, 12, 16, 20, 33][trial]
    let iv = rng_bytes(r, iv_len)
    let aad = rng_bytes(r, trial * 19 + 5)
    let expected = gmac_iv(gi_key, iv, aad)
    let st = gmac_new_iv(gi_key, iv)
    let mut off = 0
    while off < aad.length() {
      let take = if off + 7 > aad.length() { aad.length() - off } else { 7 }
      let arr = Array::make(take, b'\x00')
      for i in 0..<take {
        arr[i] = aad[off + i]
      }
      gmac_update(st, Bytes::from_array(arr[:]))
      off = off + take
    }
    assert_true(bytes_equal(expected, gmac_finalize(st)))
  }
}
