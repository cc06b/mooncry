// ==================== scrypt (RFC 7914) ====================
// Vectors cross-checked against Python hashlib.scrypt.

///|
test "scrypt: n=16 r=1 p=1 dk=64" {
  let expected = hex_to_bytes(
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
  )
  assert_true(bytes_equal(expected, scrypt(b"", b"", 16, 1, 1, 64)))
}

///|
test "scrypt: n=1024 r=8 p=16 dk=64" {
  let expected = hex_to_bytes(
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
  )
  assert_true(
    bytes_equal(
      expected,
      scrypt(
        b"\x70\x61\x73\x73\x77\x6f\x72\x64", b"\x4e\x61\x43\x6c", 1024, 8, 16, 64,
      ),
    ),
  )
}

///|
test "scrypt: n=16384 r=8 p=1 dk=64" {
  let expected = hex_to_bytes(
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
  )
  assert_true(
    bytes_equal(
      expected,
      scrypt(
        b"\x70\x6c\x65\x61\x73\x65\x6c\x65\x74\x6d\x65\x69\x6e", b"\x53\x6f\x64\x69\x75\x6d\x43\x68\x6c\x6f\x72\x69\x64\x65",
        16384, 8, 1, 64,
      ),
    ),
  )
}

///|
test "scrypt: n=16 r=2 p=1 dk=32" {
  let expected = hex_to_bytes(
    "af269b4b8249385a7c0f307603d3b0cfc09d3541e20fc126fb915c4d1eb4a565",
  )
  assert_true(
    bytes_equal(
      expected,
      scrypt(b"\x61\x62\x63", b"\x31\x32\x33", 16, 2, 1, 32),
    ),
  )
}

///|
test "scrypt: n=64 r=4 p=2 dk=48" {
  let expected = hex_to_bytes(
    "90277745029042ae49cc1895a55f51ada54e00382064e0e2135aea975838284851fda371fba676533a6e535d1639127a",
  )
  assert_true(
    bytes_equal(
      expected,
      scrypt(b"\x74\x65\x73\x74", b"\x73\x61\x6c\x74", 64, 4, 2, 48),
    ),
  )
}
