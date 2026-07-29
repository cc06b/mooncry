// ==================== AES Key Wrap (RFC 3397 / NIST SP 800-38F) ====================
// Wrap/unwrap key material under a Key Encryption Key (KEK). Reuses the AES
// block cipher. Verified against pycryptodome (Crypto.Cipher.AES + manual
// RFC 3397 vectors).

///|
fn kw_aes_nr(key : Bytes) -> Int {
  if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
}

///|
/// 8-byte big-endian representation of a 64-bit counter value.
fn kw_u64_be(t : Int) -> Bytes {
  let out = Array::make(8, b'\x00')
  out[0] = b'\x00'
  out[1] = b'\x00'
  out[2] = b'\x00'
  out[3] = b'\x00'
  out[4] = ((t >> 24) & 0xFF).to_byte()
  out[5] = ((t >> 16) & 0xFF).to_byte()
  out[6] = ((t >> 8) & 0xFF).to_byte()
  out[7] = (t & 0xFF).to_byte()
  Bytes::from_array(out[:])
}

///|
fn kw_xor8(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(8, b'\x00')
  for i in 0..<8 {
    out[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// AES-KW wrap: encrypt `key_data` (a multiple of 8 bytes) under `kek`.
/// Returns the 8*(n+1)-byte ciphertext (IV || wrapped blocks).
pub fn aes_kw_wrap(kek : Bytes, key_data : Bytes) -> Bytes {
  if kek.length() != 16 && kek.length() != 24 && kek.length() != 32 {
    abort("aes_kw_wrap: kek length must be 16, 24, or 32 bytes")
  }
  if key_data.length() == 0 || key_data.length() % 8 != 0 {
    abort("aes_kw_wrap: key_data length must be a non-zero multiple of 8")
  }
  let nr = kw_aes_nr(kek)
  let round_keys = aes_key_expansion(kek)
  let n = key_data.length() / 8
  // A = 0xA6A6A6A6A6A6A6A6 ; R[1..n] = key_data blocks
  let a = Array::make(8, b'\xa6')
  // R as an array of 8-byte blocks (mutable). NB: Array::make(n, arr) shares
  // the inner reference, so build distinct blocks with a push loop.
  let r_arr : Array[Array[Byte]] = []
  for _ in 0..<n {
    r_arr.push(Array::make(8, b'\x00'))
  }
  for i in 0..<n {
    for k in 0..<8 {
      r_arr[i][k] = key_data[i * 8 + k]
    }
  }
  for j in 0..<6 {
    for i in 0..<n {
      // B = AES_E(kek, A || R[i])
      let block = Array::make(16, b'\x00')
      for k in 0..<8 {
        block[k] = a[k]
        block[8 + k] = r_arr[i][k]
      }
      let b = encrypt_block(Bytes::from_array(block[:]), round_keys, nr)
      // A = MSB_64(B) XOR (n*j + i + 1)
      let t = n * j + i + 1
      let msb = Array::make(8, b'\x00')
      for k in 0..<8 {
        msb[k] = b[k]
      }
      let a_new = kw_xor8(Bytes::from_array(msb[:]), kw_u64_be(t))
      for k in 0..<8 {
        a[k] = a_new[k]
      }
      // R[i] = LSB_64(B)
      for k in 0..<8 {
        r_arr[i][k] = b[8 + k]
      }
    }
  }
  // output = A || R[0] || ... || R[n-1]
  let out = Array::make(8 * (n + 1), b'\x00')
  for k in 0..<8 {
    out[k] = a[k]
  }
  for i in 0..<n {
    for k in 0..<8 {
      out[8 + i * 8 + k] = r_arr[i][k]
    }
  }
  Bytes::from_array(out[:])
}

///|
/// AES-KW unwrap: returns `Ok(key_data)` if the integrity check (IV) passes,
/// `Err` otherwise. Aborts on bad lengths.
pub fn aes_kw_unwrap(kek : Bytes, wrapped : Bytes) -> Result[Bytes, String] {
  if kek.length() != 16 && kek.length() != 24 && kek.length() != 32 {
    abort("aes_kw_unwrap: kek length must be 16, 24, or 32 bytes")
  }
  if wrapped.length() < 16 || (wrapped.length() - 8) % 8 != 0 {
    abort("aes_kw_unwrap: wrapped length must be 8*(n+1), n>=1")
  }
  let nr = kw_aes_nr(kek)
  let round_keys = aes_key_expansion(kek)
  let n = (wrapped.length() - 8) / 8
  // A = wrapped[0:8] ; R[1..n] = wrapped[8..]
  let a = Array::make(8, b'\x00')
  for k in 0..<8 {
    a[k] = wrapped[k]
  }
  let r_arr : Array[Array[Byte]] = []
  for _ in 0..<n {
    r_arr.push(Array::make(8, b'\x00'))
  }
  for i in 0..<n {
    for k in 0..<8 {
      r_arr[i][k] = wrapped[8 + i * 8 + k]
    }
  }
  // j = 5 down to 0 ; i = n down to 1
  let mut j = 5
  while j >= 0 {
    let mut i = n
    while i >= 1 {
      let t = n * j + i
      // B = AES_D(kek, (A XOR t) || R[i-1])
      let block = Array::make(16, b'\x00')
      let a_xored = kw_xor8(Bytes::from_array(a[:]), kw_u64_be(t))
      for k in 0..<8 {
        block[k] = a_xored[k]
        block[8 + k] = r_arr[i - 1][k]
      }
      let b = decrypt_block(Bytes::from_array(block[:]), round_keys, nr)
      for k in 0..<8 {
        a[k] = b[k]
      }
      for k in 0..<8 {
        r_arr[i - 1][k] = b[8 + k]
      }
      i = i - 1
    }
    j = j - 1
  }
  // integrity check: A must be 0xA6..A6
  let mut ok = true
  for k in 0..<8 {
    if a[k] != b'\xa6' {
      ok = false
    }
  }
  if !ok {
    return Err("aes_kw_unwrap: integrity check failed")
  }
  let out = Array::make(8 * n, b'\x00')
  for i in 0..<n {
    for k in 0..<8 {
      out[i * 8 + k] = r_arr[i][k]
    }
  }
  Ok(Bytes::from_array(out[:]))
}
