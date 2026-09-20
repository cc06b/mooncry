///|
/// Verify the exact README Quick start example compiles and runs against the
/// local library source (the same code users paste into their main).
test "README Quick start example" {
  let digest = sha256(b"Hello, world!")
  assert_true(
    bytes_to_hex(digest) ==
    "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3",
  )

  let key = Bytes::make(32, b'\x00')
  let iv = Bytes::make(12, b'\x00')
  let kpr1 = aes_gcm_encrypt(b"secret data", key, iv, b"aad")
  let ciphertext = kpr1.ct
  let tag = kpr1.tag
  let (plaintext, ok) = bb_flag(
    aes_gcm_decrypt(ciphertext, key, iv, b"aad", tag),
  )
  assert_true(ok)
  assert_true(bytes_to_hex(plaintext) == "7365637265742064617461")

  // Sealed-box envelope (HKDF-SHA256 + AES-256-GCM) from the README example.
  let master = Bytes::make(32, b'\x07')
  let nonce = Bytes::make(12, b'\x01')
  let envelope = sealed_box_seal(
    master, nonce, b"plaintext", b"aad", b"tenant-1",
  )
  match sealed_box_open(master, envelope, b"aad", b"tenant-1") {
    Ok(pt) => assert_true(bytes_to_hex(pt) == "706c61696e74657874")
    Err(_) => assert_true(false)
  }
}
