///|
fn blake2b_hex(data : Bytes, out_len : Int) -> String {
  bytes_to_hex(blake2b(data, out_len))
}

///|
test "BLAKE2b vector 0" {
  assert_true(
    blake2b_hex(hex_to_bytes(""), 64) ==
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  )
}

///|
test "BLAKE2b vector 1" {
  assert_true(
    blake2b_hex(hex_to_bytes(""), 32) ==
    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
  )
}

///|
test "BLAKE2b vector 2" {
  assert_true(
    blake2b_hex(hex_to_bytes(""), 16) == "cae66941d9efbd404e4d88758ea67670",
  )
}

///|
test "BLAKE2b vector 3" {
  assert_true(blake2b_hex(hex_to_bytes(""), 1) == "2e")
}

///|
test "BLAKE2b vector 4" {
  assert_true(
    blake2b_hex(hex_to_bytes("616263"), 64) ==
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  )
}

///|
test "BLAKE2b vector 5" {
  assert_true(
    blake2b_hex(hex_to_bytes("616263"), 32) ==
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  )
}

///|
test "BLAKE2b vector 6" {
  assert_true(
    blake2b_hex(hex_to_bytes("616263"), 16) ==
    "cf4ab791c62b8d2b2109c90275287816",
  )
}

///|
test "BLAKE2b vector 7" {
  assert_true(blake2b_hex(hex_to_bytes("616263"), 1) == "6b")
}

///|
test "BLAKE2b vector 8" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      ),
      64,
    ) ==
    "5c52920a7263e39d57920ca0cb752ac6d79a04fef8a7a216a1ecb7115ce06d89fd7d735bd6f4272555dba22c2d1c96e6352322c62c5630fde0f4777a76c3de2c",
  )
}

///|
test "BLAKE2b vector 9" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      ),
      32,
    ) ==
    "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6",
  )
}

///|
test "BLAKE2b vector 10" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      ),
      16,
    ) ==
    "f39a2cad58411cd49f577e5086b8031f",
  )
}

///|
test "BLAKE2b vector 11" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      ),
      1,
    ) ==
    "57",
  )
}

///|
test "BLAKE2b vector 12" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      ),
      64,
    ) ==
    "2fc6e69fa26a89a5ed269092cb9b2a449a4409a7a44011eecad13d7c4b0456602d402fa5844f1a7a758136ce3d5d8d0e8b86921ffff4f692dd95bdc8e5ff0052",
  )
}

///|
test "BLAKE2b vector 13" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      ),
      32,
    ) ==
    "10d8e6d534b00939843fe9dcc4dae48cdf008f6b8b2b82b156f5404d874887f5",
  )
}

///|
test "BLAKE2b vector 14" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      ),
      16,
    ) ==
    "59059895958b8a56277edb046df67166",
  )
}

///|
test "BLAKE2b vector 15" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      ),
      1,
    ) ==
    "ce",
  )
}

///|
test "BLAKE2b vector 16" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
      ),
      64,
    ) ==
    "fb3c1f0f56a56f8e316fdf5d853c8c872c39635d083634c3904fc3ac07d1b578e85ff0e480e92d44ade33b62e893ee32343e79ddf6ef292e89b582d312502314",
  )
}

///|
test "BLAKE2b vector 17" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
      ),
      32,
    ) ==
    "63c3d97a9f8894d5e043a707b0fee7f7ec4c049a23bbf1079df20b4165f9e22d",
  )
}

///|
test "BLAKE2b vector 18" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
      ),
      16,
    ) ==
    "61479efa6267fea757b3f881e2979bbc",
  )
}

///|
test "BLAKE2b vector 19" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
      ),
      1,
    ) ==
    "5f",
  )
}

///|
test "BLAKE2b vector 20" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
      ),
      64,
    ) ==
    "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
  )
}

///|
test "BLAKE2b vector 21" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
      ),
      32,
    ) ==
    "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9",
  )
}

///|
test "BLAKE2b vector 22" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
      ),
      16,
    ) ==
    "249df9a49f517ddcd37f5c897620ec73",
  )
}

///|
test "BLAKE2b vector 23" {
  assert_true(
    blake2b_hex(
      hex_to_bytes(
        "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
      ),
      1,
    ) ==
    "b5",
  )
}
