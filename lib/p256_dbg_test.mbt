/// P-256 native (8x32-limb Solinas) differential probes: the native
/// field multiply and scalar multiplication are checked against the
/// generic BigInt path on derived pseudorandom inputs. The dbg hooks
/// live in p256.mbt (p256_dbg_*).

///|
test "p256 native field mul differential" {
  for i in 0..<64 {
    let a = sha256(Bytes::make(1, (i + 1).to_byte()))
    let b = sha256(Bytes::make(1, (i + 100).to_byte()))
    assert_true(bytes_equal(p256_dbg_mul(a, b), p256_dbg_ref_mul(a, b)))
  }
}

///|
test "p256 native scalar mult differential" {
  for k in [1, 2, 3, 15, 16, 17, 255, 1000, 65537, 123456789] {
    assert_true(bytes_equal(p256_dbg_gmul(k), p256_dbg_ref_gmul(k)))
  }
}
