///|
fn sm4m_key() -> Bytes {
  hex_to_bytes("0123456789abcdeffedcba9876543210")
}

///|
fn sm4m_iv16() -> Bytes {
  hex_to_bytes("000102030405060708090a0b0c0d0e0f")
}

///|
fn sm4m_pt48() -> Bytes {
  hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
  )
}

///|
test "sm4-ctr-oracle" {
  // openssl (cryptography) SM4-CTR, 128-bit BE counter
  inspect(
    bytes_to_hex(sm4_ctr(sm4m_key(), sm4m_iv16(), sm4m_pt48())),
    content="06999e6239a36eaa2284fd89eda5f7657f161f5854b6ea16c28809fe9d1db3053cfb70c3ee0ad1492ac453e5df31aa42",
  )
  // CTR is symmetric: applying twice recovers the plaintext
  let ct = sm4_ctr(sm4m_key(), sm4m_iv16(), sm4m_pt48())
  inspect(
    bytes_equal(sm4_ctr(sm4m_key(), sm4m_iv16(), ct), sm4m_pt48()),
    content="true",
  )
}

///|
test "sm4-cbc-oracle" {
  // openssl (cryptography) SM4-CBC, raw (no padding)
  let ct = sm4_cbc_encrypt(sm4m_key(), sm4m_iv16(), sm4m_pt48())
  inspect(
    bytes_to_hex(ct),
    content="2677f46b09c122cc975533105bd4a22ad9ee98830e69745c9827f934a19621f8db45a48645909eefda6bae89a72e659b",
  )
  inspect(
    bytes_equal(sm4_cbc_decrypt(sm4m_key(), sm4m_iv16(), ct), sm4m_pt48()),
    content="true",
  )
}

///|
test "sm4-gcm-oracle" {
  // openssl (cryptography) SM4-GCM: zero IV / no AAD ...
  let ziv = Bytes::make(12, (0).to_byte())
  let (ct1, tag1) = sm4_gcm_encrypt(sm4m_pt48(), sm4m_key(), ziv, b"")
  inspect(
    bytes_to_hex(ct1),
    content="b3126e074a904e2a476c2462432a4fc2b13400469f1bf14583e4bd0e2cdc5efeba043987d8e1026ab4e59a21542aba15",
  )
  inspect(bytes_to_hex(tag1), content="e0f8639234cb01599554311a819433ad")
  // ... and patterned IV + AAD + 60-byte plaintext
  let iv = hex_to_bytes("000102030405060708090a0b")
  let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let pt = hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b",
  )
  let (ct2, tag2) = sm4_gcm_encrypt(pt, sm4m_key(), iv, aad)
  inspect(
    bytes_to_hex(ct2),
    content="55201a92b5b4af186c8989a0d751685a98e83bbe5444a8a85eadb3348cf00d646924ef79002c1b322f98751b38bca5bf2abe16900f4a3a4cfc73afb4",
  )
  inspect(bytes_to_hex(tag2), content="cce54938447af8c920031210ec3de57a")
  // decrypt roundtrip + tamper rejection
  let (rt, ok) = sm4_gcm_decrypt(ct2, sm4m_key(), iv, aad, tag2)
  inspect(ok, content="true")
  inspect(bytes_equal(rt, pt), content="true")
  let badtag = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    badtag[i] = tag2[i]
  }
  badtag[0] = (badtag[0].to_int() ^ 1).to_byte()
  let (_, ok2) = sm4_gcm_decrypt(
    ct2,
    sm4m_key(),
    iv,
    aad,
    Bytes::from_array(badtag[:]),
  )
  inspect(ok2, content="false")
  // AAD tamper rejection
  let (_, ok3) = sm4_gcm_decrypt(ct2, sm4m_key(), iv, b"other", tag2)
  inspect(ok3, content="false")
}

///|
test "hmac-sm3-oracle" {
  // openssl HMAC-SM3 (python hashlib/hmac + SM3): short key, exact-block key,
  // long key (>64 -> hashed first)
  let msg = b"the quick brown fox jumps over the lazy dog"
  inspect(
    bytes_to_hex(
      hmac_sm3(hex_to_bytes("0714212e3b4855626f7c8996a3b0bdca"), msg),
    ),
    content="0dc7968238caad21a9f09af7492cdc25161425494a735662d2fdeac969b4dcc2",
  )
  let k64 = hex_to_bytes(
    "0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a",
  )
  let m64 = hex_to_bytes(
    "46464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646",
  )
  inspect(
    bytes_to_hex(hmac_sm3(k64, m64)),
    content="308a737e5b054db107f94bbf94a9d4fd1f8b56473a953aaca5249e5d539e7220",
  )
  let k100 = hex_to_bytes(
    "0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e",
  )
  let mlong = hex_to_bytes(
    "6c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d746573746c6f6e672d6b65792d74657374",
  )
  inspect(
    bytes_to_hex(hmac_sm3(k100, mlong)),
    content="3b2bc34e58128b360a11bbb0fe7e38ae9f29793b0448221945c6baa604273220",
  )
}

///|
test "hkdf-sm3-oracle" {
  // openssl (cryptography HKDF, SM3): RFC 5869-style test input
  let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hex_to_bytes("000102030405060708090a0b0c")
  let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")
  inspect(
    bytes_to_hex(hkdf_sm3(ikm, salt, info, 42)),
    content="c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b",
  )
  // extract+expand split must equal the one-shot
  let prk = hkdf_sm3_extract(salt, ikm)
  inspect(
    bytes_equal(hkdf_sm3_expand(prk, info, 42), hkdf_sm3(ikm, salt, info, 42)),
    content="true",
  )
  // empty salt path (zeros) works and differs from the salted PRK
  let prk0 = hkdf_sm3_extract(b"", ikm)
  inspect(bytes_equal(prk0, prk), content="false")
}

///|
test "pbkdf2-sm3-oracle" {
  // openssl (cryptography PBKDF2HMAC, SM3, 1000 iterations)
  let salt = hex_to_bytes("000102030405060708090a0b0c")
  inspect(
    bytes_to_hex(pbkdf2_sm3(b"password", salt, 1000, 32)),
    content="20001962d8066f7945391a8b79f0776c2e4b1bde2265c7890e7cb30876c0ffb2",
  )
  // 2-block output: first block equals the 32-byte derivation
  let dk64 = pbkdf2_sm3(b"password", salt, 1000, 64)
  let one = pbkdf2_sm3(b"password", salt, 1000, 32)
  let mut same = true
  for i in 0..<32 {
    if dk64[i] != one[i] {
      same = false
    }
  }
  inspect(same, content="true")
  inspect(dk64.length(), content="64")
}
