///|
fn poly1305_hex(key : Bytes, msg : Bytes) -> String {
  bytes_to_hex(poly1305(key, msg))
}

///|
test "Poly1305: RFC 8439 2.5.2" {
  let key = hex_to_bytes(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  let msg = b"Cryptographic Forum Research Group"
  assert_true(poly1305_hex(key, msg) == "a8061dc1305136c6c22b8baf0c0127a9")
}

///|
test "Poly1305: empty msg (tag == s)" {
  let key = hex_to_bytes(
    "b33bede78e59c02b66436c927488389fb5f9e0b3a5d0cf9dedf626dfbd297992",
  )
  assert_true(poly1305_hex(key, b"") == "b5f9e0b3a5d0cf9dedf626dfbd297992")
}

///|
test "Poly1305: abc" {
  let key = hex_to_bytes(
    "d2383189bc42ac33065de6cf71311e64abe9eee5c9c6665f1794635b782b0607",
  )
  assert_true(poly1305_hex(key, b"abc") == "89fa9204d0caf83fe573d98d77d9c9b3")
}

///|
test "Poly1305: 50-byte msg" {
  let key = hex_to_bytes(
    "a578f7c6b983d4096ae790c38b9327d35fb8c680dfde74024569333149395524",
  )
  let msg = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
  )
  assert_true(poly1305_hex(key, msg) == "2cbcc8a1b694954a960a788ea5ac6d41")
}
