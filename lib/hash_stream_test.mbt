///|
/// finalize_n must equal the truncated one-shot digest (v0.34.0).
test "sha256/sha512 finalize_n equals truncated digest" {
  let data = b"mooncry finalize_n regression data spanning several blocks of input"
  let h1 = sha256_new()
  sha256_update(h1, data)
  assert_true(
    bytes_equal(
      sha256_finalize_n(h1, 16),
      Bytes::from_array(sha256(data).to_array()[0:16]),
    ),
  )
  let h2 = sha256_new()
  sha256_update(h2, data)
  assert_true(bytes_equal(sha256_finalize_n(h2, 32), sha256(data)))
  let h3 = sha512_new()
  sha512_update(h3, data)
  assert_true(
    bytes_equal(
      sha512_finalize_n(h3, 24),
      Bytes::from_array(sha512(data).to_array()[0:24]),
    ),
  )
  let h4 = sha512_new()
  sha512_update(h4, data)
  assert_true(bytes_equal(sha512_finalize_n(h4, 64), sha512(data)))
  // empty input edge
  let h5 = sha256_new()
  assert_true(
    bytes_equal(
      sha256_finalize_n(h5, 20),
      Bytes::from_array(sha256(b"").to_array()[0:20]),
    ),
  )
}
