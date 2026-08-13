// SHA-512/224 and SHA-512/256 vectors (FIPS 180-4 §5.3.6). Generated
// with Python hashlib (sha512_224/sha512_256), anchored on the FIPS
// sample values for "abc".

///|
/// The 896-bit FIPS 180-4 multi-block message
fn sha512t_long_msg() -> Bytes {
  b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
}

///|
/// Bytes 00 01 ... n-1
fn sha512t_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

// ==================== SHA-512/224 ====================

///|
test "SHA-512/224: empty" {
  let expected = hex_to_bytes(
    "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
  )
  assert_true(bytes_equal(expected, sha512_224(b"")))
}

///|
test "SHA-512/224: abc (FIPS 180-4 sample)" {
  let expected = hex_to_bytes(
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
  )
  assert_true(bytes_equal(expected, sha512_224(b"abc")))
}

///|
test "SHA-512/224: fox" {
  let expected = hex_to_bytes(
    "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
  )
  assert_true(
    bytes_equal(
      expected,
      sha512_224(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "SHA-512/224: 896-bit two-block message" {
  let expected = hex_to_bytes(
    "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
  )
  assert_true(bytes_equal(expected, sha512_224(sha512t_long_msg())))
}

///|
test "SHA-512/224: 32B sequence" {
  let expected = hex_to_bytes(
    "cf2fc8b204143a496c4151113069636b288874d2cd9bea3bd41b8495",
  )
  assert_true(bytes_equal(expected, sha512_224(sha512t_range_bytes(32))))
}

///|
test "SHA-512/224: streaming equals one-shot" {
  let data = sha512t_range_bytes(200)
  let h = sha512_224_new()
  sha512_224_update(h, sha512t_range_bytes(83))
  sha512_224_update(h, bytes_sub_range(data, 83, 117))
  assert_true(bytes_equal(sha512_224(data), sha512_224_finalize(h)))
}

// ==================== SHA-512/256 ====================

///|
test "SHA-512/256: empty" {
  let expected = hex_to_bytes(
    "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
  )
  assert_true(bytes_equal(expected, sha512_256(b"")))
}

///|
test "SHA-512/256: abc (FIPS 180-4 sample)" {
  let expected = hex_to_bytes(
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
  )
  assert_true(bytes_equal(expected, sha512_256(b"abc")))
}

///|
test "SHA-512/256: fox" {
  let expected = hex_to_bytes(
    "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
  )
  assert_true(
    bytes_equal(
      expected,
      sha512_256(b"The quick brown fox jumps over the lazy dog"),
    ),
  )
}

///|
test "SHA-512/256: 896-bit two-block message" {
  let expected = hex_to_bytes(
    "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
  )
  assert_true(bytes_equal(expected, sha512_256(sha512t_long_msg())))
}

///|
test "SHA-512/256: 32B sequence" {
  let expected = hex_to_bytes(
    "b1915eae84b12616ce51d7e259b7aec3798d427a735bb13226d07119f651e981",
  )
  assert_true(bytes_equal(expected, sha512_256(sha512t_range_bytes(32))))
}

///|
test "SHA-512/256: streaming equals one-shot" {
  let data = sha512t_range_bytes(200)
  let h = sha512_256_new()
  sha512_256_update(h, sha512t_range_bytes(83))
  sha512_256_update(h, bytes_sub_range(data, 83, 117))
  assert_true(bytes_equal(sha512_256(data), sha512_256_finalize(h)))
}

///|
test "SHA-512/t: truncated variants differ from each other" {
  // SHA-512/224 is not a truncation of SHA-512/256 (distinct IVs)
  assert_true(
    !bytes_equal(sha512_224(b"abc"), bytes_sub_range(sha512_256(b"abc"), 0, 28)),
  )
}

///|
/// Sub-range helper: data[start..start+len)
fn bytes_sub_range(data : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = data[start + i]
  }
  Bytes::from_array(out[:])
}
