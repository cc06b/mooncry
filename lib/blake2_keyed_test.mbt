// Keyed BLAKE2b / BLAKE2s vectors generated with Python
// hashlib.blake2b/blake2s (key=...), the reference implementation of
// RFC 7693 keyed hashing.

///|
fn blake2k_key(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "Keyed BLAKE2b-512: abc, 16-byte key" {
  let expected = hex_to_bytes(
    "4c76bc7ad0fc52e4bde231b38727c331172cfe3eeaf10cd2fa5c65abbdb8faeaad2da338531b382ac103f10ccaf41f74d8870d016c48b269c0d9a5cf5752c8c3",
  )
  assert_true(bytes_equal(expected, blake2b_keyed(b"abc", blake2k_key(16), 64)))
}

///|
test "Keyed BLAKE2b-512: abc, 32-byte key" {
  let expected = hex_to_bytes(
    "9af0244b7da7fe29d90a89727e06a0c93977ce1ad7edcb76ac0b24142194ea00c77be4a1d3fededd31d5a593625a508e742fc90d708f8b48a5c246e4e8e42d94",
  )
  assert_true(bytes_equal(expected, blake2b_keyed(b"abc", blake2k_key(32), 64)))
}

///|
test "Keyed BLAKE2b-512: abc, 64-byte key (max)" {
  let expected = hex_to_bytes(
    "06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579ed590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51",
  )
  assert_true(bytes_equal(expected, blake2b_keyed(b"abc", blake2k_key(64), 64)))
}

///|
test "Keyed BLAKE2b: empty message (key block is the last block)" {
  let expected = hex_to_bytes(
    "84bfa69f0d90df7db2a3ee026042988b5bd9caa2320af1f371823dd28351202f8e6277c40c050711c8dd4e2c1ac30c34c9aed0bddd468b031287fe872675e0cc",
  )
  assert_true(bytes_equal(expected, blake2b_keyed(b"", blake2k_key(32), 64)))
}

///|
test "Keyed BLAKE2b: 200B input spans multiple blocks" {
  let expected = hex_to_bytes(
    "9093518bf78f2721ca56ba259b17cae6a3c1851e8d09f996d5897febc9188502fb1f1382fe6acc16cf593e744db24b6c51b09978a7b458341f2a1043823244b6",
  )
  assert_true(
    bytes_equal(expected, blake2b_keyed(blake2k_key(200), blake2k_key(32), 64)),
  )
}

///|
test "Keyed BLAKE2b: shorter digest (out_len=16)" {
  let expected = hex_to_bytes("1a64be47e4729d951c302ee543f97cf3")
  assert_true(bytes_equal(expected, blake2b_keyed(b"abc", blake2k_key(32), 16)))
}

///|
test "Keyed BLAKE2s-256: abc, 8-byte key" {
  let expected = hex_to_bytes(
    "5cbb58e3b3c8a5b9cb8f209c2cb1f0f11d19bb4fe534c5c3baecd9d861a6aadd",
  )
  assert_true(bytes_equal(expected, blake2s_keyed(b"abc", blake2k_key(8), 32)))
}

///|
test "Keyed BLAKE2s-256: abc, 16-byte key" {
  let expected = hex_to_bytes(
    "033a40b64c6296fc2e3584d2a06bcf1a8003ebb9b8007940e2f820b645917a4e",
  )
  assert_true(bytes_equal(expected, blake2s_keyed(b"abc", blake2k_key(16), 32)))
}

///|
test "Keyed BLAKE2s-256: abc, 32-byte key (max)" {
  let expected = hex_to_bytes(
    "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65",
  )
  assert_true(bytes_equal(expected, blake2s_keyed(b"abc", blake2k_key(32), 32)))
}

///|
test "Keyed BLAKE2s: empty message" {
  let expected = hex_to_bytes(
    "fcfc1128807d157b01adec1ebe0a0927e5ac0ea65000fcec0852218dbb147106",
  )
  assert_true(bytes_equal(expected, blake2s_keyed(b"", blake2k_key(16), 32)))
}

///|
test "Keyed BLAKE2s: 200B input spans multiple blocks" {
  let expected = hex_to_bytes(
    "13c88480a5d00d6c8c7ad2110d76a82d9b70f4fa6696d4e5dd42a066dcaf9920",
  )
  assert_true(
    bytes_equal(expected, blake2s_keyed(blake2k_key(200), blake2k_key(32), 32)),
  )
}

///|
test "Keyed vs unkeyed BLAKE2 differ" {
  assert_true(
    !bytes_equal(
      blake2b_keyed(b"abc", blake2k_key(32), 64),
      blake2b(b"abc", 64),
    ),
  )
  assert_true(
    !bytes_equal(
      blake2s_keyed(b"abc", blake2k_key(32), 32),
      blake2s(b"abc", 32),
    ),
  )
}
