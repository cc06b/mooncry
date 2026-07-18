///|
test "hex_to_bytes: known vector + round-trip" {
  let h = "deadbeef"
  let b = hex_to_bytes(h)
  assert_true(b[0].to_int() == 0xde)
  assert_true(b[1].to_int() == 0xad)
  assert_true(b[2].to_int() == 0xbe)
  assert_true(b[3].to_int() == 0xef)
  assert_true(bytes_to_hex(b) == h)
  let long = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
  assert_true(bytes_to_hex(hex_to_bytes(long)) == long)
}
