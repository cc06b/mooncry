// ==================== Incremental GMAC tests (v0.22.0) ====================
// External vectors are AES-GCM tags of an empty plaintext from
// pycryptodome (key = 000102...0f, iv = 646566...6f), i.e. GMAC tags.
// The chunked-vs-one-shot property covers boundary cases (exact block
// multiples, trailing partials).

///|
let gs_key : Bytes = hex_to_bytes("000102030405060708090a0b0c0d0e0f")

///|
let gs_iv : Bytes = hex_to_bytes("6465666768696a6b6c6d6e6f")

///|
test "incremental GMAC (pycryptodome vectors)" {
  // empty AAD
  let t0 = gmac_finalize(gmac_new(gs_key, gs_iv))
  assert_true(bytes_equal(t0, hex_to_bytes("6582ac05e04711a826bdfe2e144440ab")))
  // 1 byte
  let st1 = gmac_new(gs_key, gs_iv)
  gmac_update(st1, hex_to_bytes("00"))
  assert_true(
    bytes_equal(
      gmac_finalize(st1),
      hex_to_bytes("d7d1449c21962f176cae4d566cb1f88d"),
    ),
  )
  // 3 bytes
  let st3 = gmac_new(gs_key, gs_iv)
  gmac_update(st3, hex_to_bytes("616263"))
  assert_true(
    bytes_equal(
      gmac_finalize(st3),
      hex_to_bytes("670dc1e21090cf0d716276f536f3449c"),
    ),
  )
  // exactly 16 bytes
  let st16 = gmac_new(gs_key, gs_iv)
  gmac_update(st16, hex_to_bytes("00112233445566778899aabbccddeeff"))
  assert_true(
    bytes_equal(
      gmac_finalize(st16),
      hex_to_bytes("81a272cf0e0c320a1c9a68a33897d589"),
    ),
  )
  // 40 bytes
  let st40 = gmac_new(gs_key, gs_iv)
  gmac_update(
    st40,
    hex_to_bytes(
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
  )
  assert_true(
    bytes_equal(
      gmac_finalize(st40),
      hex_to_bytes("07f60ff4dca69326e8510279381977e5"),
    ),
  )
}

///|
test "property: chunked GMAC == one-shot GMAC" {
  let r = Rng::{ state: 0x2A6E1D57U, }
  for trial in 0..<10 {
    let data = rng_bytes(r, trial * 37 + 13)
    let expected = gmac(gs_key, gs_iv, data)
    // chunk sizes 1..8
    let chunk = 1 + trial % 8
    let st = gmac_new(gs_key, gs_iv)
    let mut off = 0
    while off < data.length() {
      let take = if off + chunk > data.length() {
        data.length() - off
      } else {
        chunk
      }
      let arr = Array::make(take, b'\x00')
      for i in 0..<take {
        arr[i] = data[off + i]
      }
      gmac_update(st, Bytes::from_array(arr[:]))
      off = off + take
    }
    assert_true(bytes_equal(expected, gmac_finalize(st)))
  }
}

///|
test "incremental GMAC single-byte feeding == one-shot" {
  let data = Bytes::make(100, b'\x5a')
  let expected = gmac(gs_key, gs_iv, data)
  let st = gmac_new(gs_key, gs_iv)
  for i in 0..<data.length() {
    gmac_update(st, Bytes::make(1, data[i]))
  }
  assert_true(bytes_equal(expected, gmac_finalize(st)))
}

///|
test "incremental GMAC verify helper" {
  let data = hex_to_bytes("00112233445566778899aabbccddeeff")
  let tag = hex_to_bytes("81a272cf0e0c320a1c9a68a33897d589")
  assert_true(gmac_stream_verify(gs_key, gs_iv, data, tag))
  let bad = Array::make(16, b'\x00')
  for i in 0..<16 {
    bad[i] = tag[i]
  }
  bad[0] = (bad[0].to_int() ^ 1).to_byte()
  assert_false(
    gmac_stream_verify(gs_key, gs_iv, data, Bytes::from_array(bad[:])),
  )
}
