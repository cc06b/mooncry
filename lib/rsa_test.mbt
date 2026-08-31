// ==================== RSA (RFC 8017) ====================
// Vectors cross-checked against pycryptodome (Crypto.PublicKey.RSA +
// PKCS1_v1_5 / PKCS1_OAEP / pkcs1_15 / pss). Key is a fixed 1024-bit pair.
// n = 128-byte modulus, e = 65537.

///|
let rsa_test_n : Bytes = hex_to_bytes(
  "b39bd6ce030d887d489373b37a3818821bba72e7d4c02c466cbdb15d5f7904ba564c21db02d5fa4e6aaa50ac21c7e951702929fb559b3d85a111f1fa2afe0c52f4a268ee830b2925c5004829064c800583fe0a243da0d4734c973803bb86f28f5ceafafe7f9cf93c08050d1d21d88f464ebc188c942622d77a1f87565855dc03",
)

///|
let rsa_test_d : Bytes = hex_to_bytes(
  "4cbcc1f76dfd7bb9cf66d471b3bfc0d4e204f4b01149740138d7892e942a6ff72f04c318402b6d10d0e8e8a3caa10f9210623e0218aec587d0ec0a5f30bc2f4610ed01a59af1ae4cfe6edeb7641e92a12591e89037859ab86a9f952d67acff629f7867f76ef50f585bf9c8aa5e4ff16c42c4b5d40fd47ca5d5cafa1db4dcb401",
)

///|
let rsa_test_e : Bytes = hex_to_bytes("010001")

///|
test "RSA PKCS1-v1.5 decrypt (pkcs1_v15)" {
  let ct = hex_to_bytes(
    "23deaa582bff9687d7b952d413f7937cb96fbda4d486af193661c1a25b5659492d55dc5e576d6f9a333e348da25a35048a989f452f7c87a1d4dcf722d13095efc1841c5ac0a3eaff7a4a0145b90cfabb77429e5f8b7c5dd7c73f3233d9ede8e17d7abfcd33cd3c6607a367dd0fce49c54decc3ee0771fe5fbfa4c00e57ba471a",
  )
  let pt = rsa_pkcs1_v15_decrypt(ct, rsa_test_n, rsa_test_d)
  assert_true(
    bytes_equal(pt, hex_to_bytes("52534120504b4353312076312e352074657374")),
  )
}

///|
test "RSA PKCS1-v1.5 decrypt (pkcs1_v15_b)" {
  let ct = hex_to_bytes(
    "2ab59d8f1e5f0490a17813bc5ef7db4e6eb25e371883d704bd228aaa81d4ba036c498e99ff850569176b02b51149cb4fd385423b2e821e69a8a0bd0bb0c00c3ae6ac4056ba9a177eb409acec1cd7b8ded0143a63c4cf88d2ca2ad58cac95ad7bb9f2ef76ea295ce25f19fa1d5965f53f39e67f4b0d40589cbe673817c293f1ff",
  )
  let pt = rsa_pkcs1_v15_decrypt(ct, rsa_test_n, rsa_test_d)
  assert_true(bytes_equal(pt, hex_to_bytes("68656c6c6f20727361")))
}

///|
test "RSA PKCS1-v1.5 round-trip" {
  let msg = b"round trip pkcs1"
  let k = rsa_test_n.length()
  // deterministic nonzero padding bytes (NOT for security use)
  let ps = Bytes::make(k - msg.length() - 3, b'\x05')
  let ct = rsa_pkcs1_v15_encrypt(msg, rsa_test_n, rsa_test_e, ps)
  let pt = rsa_pkcs1_v15_decrypt(ct, rsa_test_n, rsa_test_d)
  assert_true(bytes_equal(pt, msg))
}

///|
test "RSA-OAEP decrypt (pycryptodome ct)" {
  let ct = hex_to_bytes(
    "6a3ed762e32a0b10bcc7ee2bc8daa211d8504c2cd6aa46f97b154423e9951ce41c2ffaea548320480260a1b1eb63be8b361ad648ecc6eaed1f0c57ff8452baaa8b05877858f09520bef7a218b25b7613e3b0fac521a64983b36e140a30c502b0bd34c2177552e42711b0e5015e8cb7129c86e9247ddfa981fda390fc7197cd74",
  )
  let pt = rsa_oaep_decrypt(ct, rsa_test_n, rsa_test_d, b"")
  assert_true(
    bytes_equal(pt, hex_to_bytes("4f41455020736563726574207061796c6f6164")),
  )
}

///|
test "RSA-OAEP round-trip" {
  let msg = b"oaep round trip"
  let seed = Bytes::make(32, b'\x09') // deterministic, NOT for security use
  let ct = rsa_oaep_encrypt(msg, rsa_test_n, rsa_test_e, seed, b"")
  let pt = rsa_oaep_decrypt(ct, rsa_test_n, rsa_test_d, b"")
  assert_true(bytes_equal(pt, msg))
}

///|
test "RSA PKCS1-v1.5 sign (exact, SHA-256)" {
  let msg = hex_to_bytes("6d65737361676520746f207369676e")
  let sig = rsa_pkcs1_v15_sign(msg, rsa_test_n, rsa_test_d)
  assert_true(
    bytes_equal(
      sig,
      hex_to_bytes(
        "48d5b8597196f1d0dd2157dba6599d8a2d355b56e4939fefb56e08d4d1a2cea5105bc49e17c4c341c44611f4aff208a57038a923a7fa83996aede99e5dea72615f788df3d92a5e66c38c63165627d9c55d507faf20e3156f0311fa261b1eb876f3011017b5d9bb44755f4f6d7c9eefe6649c1279dfea5a712adaed7fc2d6d164",
      ),
    ),
  )
}

///|
test "RSA PKCS1-v1.5 verify" {
  let msg = hex_to_bytes("6d65737361676520746f207369676e")
  let sig = hex_to_bytes(
    "48d5b8597196f1d0dd2157dba6599d8a2d355b56e4939fefb56e08d4d1a2cea5105bc49e17c4c341c44611f4aff208a57038a923a7fa83996aede99e5dea72615f788df3d92a5e66c38c63165627d9c55d507faf20e3156f0311fa261b1eb876f3011017b5d9bb44755f4f6d7c9eefe6649c1279dfea5a712adaed7fc2d6d164",
  )
  assert_true(rsa_pkcs1_v15_verify(msg, sig, rsa_test_n, rsa_test_e))
}

///|
test "RSA PKCS1-v1.5 verify rejects tampered msg" {
  let bad_msg = b"wrong message"
  let sig = hex_to_bytes(
    "48d5b8597196f1d0dd2157dba6599d8a2d355b56e4939fefb56e08d4d1a2cea5105bc49e17c4c341c44611f4aff208a57038a923a7fa83996aede99e5dea72615f788df3d92a5e66c38c63165627d9c55d507faf20e3156f0311fa261b1eb876f3011017b5d9bb44755f4f6d7c9eefe6649c1279dfea5a712adaed7fc2d6d164",
  )
  assert_true(!rsa_pkcs1_v15_verify(bad_msg, sig, rsa_test_n, rsa_test_e))
}

///|
test "RSA-PSS verify (pycryptodome sig, SHA-256, salt 32)" {
  let msg = hex_to_bytes("6d65737361676520746f207369676e")
  let sig = hex_to_bytes(
    "5470babd057972e37758f27f219b3067767092c38edd9cfd8ec39f7ca42e8450a22e6ffc561ea3a10c4446414833e505f91b7609e81b9e5245b0b298a89943bf9ca8968238a4d5e85a95ae8962e4d1d6c6a0cf112bc9ff2002e72cfc7389b602144fef1c3b68d185eda711f2f0ee0a246be8b0c71ac0a0f82c53f28848f9fa93",
  )
  assert_true(rsa_pss_verify(msg, sig, rsa_test_n, rsa_test_e, 32))
}

///|
test "RSA-PSS round-trip (SHA-256, salt 32)" {
  let msg = b"pss round trip"
  let salt = Bytes::make(32, b'\x0a') // deterministic, NOT for security use
  let sig = rsa_pss_sign(msg, rsa_test_n, rsa_test_d, salt)
  assert_true(rsa_pss_verify(msg, sig, rsa_test_n, rsa_test_e, 32))
}

///|
test "RSA-PSS verify rejects tampered msg" {
  let msg = b"pss original"
  let salt = Bytes::make(32, b'\x0a')
  let sig = rsa_pss_sign(msg, rsa_test_n, rsa_test_d, salt)
  assert_true(!rsa_pss_verify(b"different", sig, rsa_test_n, rsa_test_e, 32))
}

// ==================== RSA CRT (v0.21.0) ====================
// CRT parameters (p, q, dP, dQ, qInv) derived in Python from the test key
// above via the standard (n, e, d) factoring method; sanity-checked that CRT
// decryption reproduces plaintexts.

///|
let rsa_crt_p : Bytes = hex_to_bytes(
  "d6da0a4cb4e15854071012a637c0d3333d36d6d72d826acd3c3d0637d205ab98fdc59dff06db6fa4d8bcb4c90af13627280ed518fc1a13de975ab94b8b0eb401",
)

///|
let rsa_crt_q : Bytes = hex_to_bytes(
  "d601df3917dd5360189b8f5e175ce86e041039f82f9cc90d71162b8d5bf1ea2508607fb0fca85fbec5065fe8083c68dbe54b08931dd292f1ad66671ddc29c003",
)

///|
let rsa_crt_dp : Bytes = hex_to_bytes(
  "b21a0745b4ffc48fcb57088e9f530a00c4b2cbff8deb398bae6ecbd3c4170d3b82caa98179f6b7a2c8440dfd4643d4673b2ea879d0a9f164a8c4fd2b6137ac01",
)

///|
let rsa_crt_dq : Bytes = hex_to_bytes(
  "23f73092a1c61a6afdf7b6c2735eb3d9396998b4731c0055f7f967dc5be56e1a472c2089980c9bfaad9602ac362620e143c9b669330bde922b381880562dd60d",
)

///|
let rsa_crt_qinv : Bytes = hex_to_bytes(
  "23305d86acaa19739ec14d23ec52181570c596378b87204082ef51a1d18e4a753d1394fa39216797fd5eaf75730b153053cde7e992e78d442ef97720b01d6e70",
)

///|
test "RSA PKCS1-v1.5 CRT sign == standard sign" {
  let msg = b"hello crt signing"
  let sig_std = rsa_pkcs1_v15_sign(msg, rsa_test_n, rsa_test_d)
  let sig_crt = rsa_pkcs1_v15_sign_crt(
    msg, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv,
  )
  // Deterministic PKCS1-v1.5: CRT and single-exponentiation must agree
  // byte-for-byte (standard sign was verified against pycryptodome).
  assert_true(bytes_equal(sig_std, sig_crt))
  assert_true(rsa_pkcs1_v15_verify(msg, sig_crt, rsa_test_n, rsa_test_e))
}

///|
test "RSA PSS CRT sign == standard sign" {
  let msg = b"hello crt pss"
  let salt = Bytes::make(32, b'\x2a')
  let sig_std = rsa_pss_sign(msg, rsa_test_n, rsa_test_d, salt)
  let sig_crt = rsa_pss_sign_crt(
    msg, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv, salt,
  )
  assert_true(bytes_equal(sig_std, sig_crt))
  assert_true(
    rsa_pss_verify(msg, sig_crt, rsa_test_n, rsa_test_e, salt.length()),
  )
}

///|
test "RSA PKCS1-v1.5 CRT decrypt round-trip" {
  let msg = b"crt decrypt test"
  let k = rsa_test_n.length()
  let ps = Bytes::make(k - msg.length() - 3, b'\x07')
  let ct = rsa_pkcs1_v15_encrypt(msg, rsa_test_n, rsa_test_e, ps)
  let pt = rsa_pkcs1_v15_decrypt_crt(
    ct, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv,
  )
  assert_true(bytes_equal(pt, msg))
}

///|
test "RSA OAEP CRT decrypt round-trip" {
  let msg = b"oaep crt"
  let label = b""
  let seed = Bytes::make(32, b'\x11')
  let ct = rsa_oaep_encrypt(msg, rsa_test_n, rsa_test_e, seed, label)
  let pt = rsa_oaep_decrypt_crt(
    ct, rsa_crt_p, rsa_crt_q, rsa_crt_dp, rsa_crt_dq, rsa_crt_qinv, label,
  )
  assert_true(bytes_equal(pt, msg))
}
