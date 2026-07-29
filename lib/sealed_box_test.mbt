// ==================== Sealed Box round-trip tests ====================

///|
test "sealed_box: round-trip" {
  let key = Bytes::make(32, b'\x00')
  let nonce = Bytes::make(12, b'\x01')
  let pt = b"the eagle has landed at dawn"
  let aad = b"metadata:v1"
  let ctx = b"tenant-42"
  let env = sealed_box_seal(key, nonce, pt, aad, ctx)
  let r = sealed_box_open(key, env, aad, ctx)
  match r {
    Ok(recovered) => assert_true(bytes_equal(pt, recovered))
    Err(_) => {
      println("unexpected open failure")
      assert_true(false)
    }
  }
}

///|
test "sealed_box: tampered tag fails" {
  let key = Bytes::make(32, b'\x00')
  let nonce = Bytes::make(12, b'\x01')
  let pt = b"do not trust the messenger"
  let env = sealed_box_seal(key, nonce, pt, b"", b"ctx")
  // Flip the last byte of the envelope (the last tag byte).
  let tampered = Array::make(env.length(), b'\x00')
  for i in 0..<env.length() {
    tampered[i] = env[i]
  }
  tampered[env.length() - 1] = (tampered[env.length() - 1].to_int() ^ 0xFF).to_byte()
  let r = sealed_box_open(key, Bytes::from_array(tampered[:]), b"", b"ctx")
  match r {
    Ok(_) => {
      println("tampered envelope opened — should have failed")
      assert_true(false)
    }
    Err(_) => assert_true(true)
  }
}

///|
test "sealed_box: wrong context fails" {
  let key = Bytes::make(32, b'\x00')
  let nonce = Bytes::make(12, b'\x01')
  let pt = b"context separation"
  let env = sealed_box_seal(key, nonce, pt, b"", b"context-A")
  let r = sealed_box_open(key, env, b"", b"context-B")
  match r {
    Ok(_) => {
      println("wrong context opened — should have failed")
      assert_true(false)
    }
    Err(_) => assert_true(true)
  }
}

///|
test "sealed_box: envelope structure" {
  let key = Bytes::make(16, b'\x07')
  let nonce = Bytes::make(12, b'\x02')
  let pt = b"0123456789ABCDEF" // 16 bytes
  let env = sealed_box_seal(key, nonce, pt, b"", b"c")
  // version(1) + nonce(12) + ct(16) + tag(16) = 45 bytes
  assert_true(env.length() == 45)
  assert_true(env[0] == b'\x01')
  // nonce echoed verbatim
  assert_true(env[1] == b'\x02')
  assert_true(env[12] == b'\x02')
}
