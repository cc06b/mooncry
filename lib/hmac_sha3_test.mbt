// ==================== HMAC-SHA3 (RFC 2104 + FIPS 202) ====================
// Vectors cross-checked against Python hmac + hashlib (sha3_256/sha3_512).

///|
test "HMAC-SHA3: hmac_sha3_256 key=20B msg=0B" {
  let expected = hex_to_bytes(
    "b55e797f7ee8110da3217be6b2a033b242a7d4e0bf0ca42bcafe3706fb519556",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        b"",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=20B msg=0B" {
  let expected = hex_to_bytes(
    "ebc40f1b0909e5d2a51934726c228b72199a1c7f79b8423d2145f26e03bfc4920701c0d20b303362569db46d8bbbeb30645dfb356088ba348a454e6618cd9f57",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        b"",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_256 key=20B msg=8B" {
  let expected = hex_to_bytes(
    "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        b"\x48\x69\x20\x54\x68\x65\x72\x65",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=20B msg=8B" {
  let expected = hex_to_bytes(
    "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        b"\x48\x69\x20\x54\x68\x65\x72\x65",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_256 key=20B msg=43B" {
  let expected = hex_to_bytes(
    "04d84c9ff7bd85ce02a06dc512d1b316f93a8adeb347cd9165c808d4b6233d54",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        hex_to_bytes(
          "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        ),
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=20B msg=43B" {
  let expected = hex_to_bytes(
    "866f3a512861c296c9aaeb5f4fe1224e2f953cb9fc139604c7e27ab86a996ae28aae94ee80555bb5abea400776a5f7dd54330917b40d00c4e31a703fb9bef19a",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        hex_to_bytes(
          "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        ),
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_256 key=200B msg=0B" {
  let expected = hex_to_bytes(
    "b0880d433119fbf545114f0a664f57f6c387eaf3ba4f8a1b64e46af61636f12a",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        hex_to_bytes(
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        b"",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_256 key=200B msg=8B" {
  let expected = hex_to_bytes(
    "ed16f59f82e8e7c3cd79d3c24f7c7bf692b47bfedf6598ea3be41e5c9b8e5194",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        hex_to_bytes(
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        b"\x48\x69\x20\x54\x68\x65\x72\x65",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_256 key=200B msg=43B" {
  let expected = hex_to_bytes(
    "7e327d8e0b4230ee60dde5235ca19f0e615311c308eefd39423baddc8cb8596b",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_256(
        hex_to_bytes(
          "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        hex_to_bytes(
          "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        ),
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=131B msg=0B" {
  let expected = hex_to_bytes(
    "bb2b2d73e3be96876d2199ec358ef3cc1d52a59ed0b06ed1071e1a70474a0a3bfa442dea21cc9bf6075161e555455a08cd8c8252ce78d818ee98d4d86bec7eb9",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        hex_to_bytes(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        b"",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=131B msg=8B" {
  let expected = hex_to_bytes(
    "ba271f5075da0868cf4cd3362688ecce4bbc20b0eaa6ad1361fa05d1d2c84ac54a8773bb9cbf19d89bd284edebbc670242eeffd915406f3c4e2ab8e8b829226c",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        hex_to_bytes(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        b"\x48\x69\x20\x54\x68\x65\x72\x65",
      ),
    ),
  )
}

///|
test "HMAC-SHA3: hmac_sha3_512 key=131B msg=43B" {
  let expected = hex_to_bytes(
    "d7163087d4418677a86f46dc42b9bd95b65132673d5a19d1a19ba9ceae15042e52229f44da6a7504f53e8a86482e2d0431e9069a769a004b1be1dd85204f1b89",
  )
  assert_true(
    bytes_equal(
      expected,
      hmac_sha3_512(
        hex_to_bytes(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        hex_to_bytes(
          "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
        ),
      ),
    ),
  )
}
