// ============================================================
// Key Derivation Functions over SHA-512: HKDF-SHA512 (RFC 5869)
// and PBKDF2-HMAC-SHA512 (RFC 8018). Same constructions as
// kdf.mbt, parameterized on hmac_sha512 (64-byte hash output).
// ============================================================

///|
/// HKDF-Extract (SHA-512): PRK = HMAC-SHA512(salt, IKM). Empty salt
/// defaults to 64 zero bytes.
fn hkdf_sha512_extract(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 {
    let z = Array::make(64, b'\x00')
    Bytes::from_array(z[:])
  } else {
    salt
  }
  hmac_sha512(s, ikm)
}

///|
/// HKDF-SHA512 (RFC 5869): expand IKM into `length` bytes using salt +
/// info. Maximum output is 255 * 64 = 16320 bytes; longer requests are
/// clamped.
pub fn hkdf_sha512(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hkdf_sha512_extract(salt, ikm)
  let mut okm = b""
  let mut t = b""
  let mut i = 1
  while okm.length() < length && i <= 255 {
    t = hmac_sha512(
      prk,
      concat_bytes(concat_bytes(t, info), Bytes::make(1, i.to_byte())),
    )
    okm = concat_bytes(okm, t)
    i = i + 1
  }
  let out = Array::make(length, b'\x00')
  for j in 0..<length {
    if j < okm.length() {
      out[j] = okm[j]
    }
  }
  Bytes::from_array(out[:])
}

///|
/// PBKDF2-HMAC-SHA512 (RFC 8018): derive `dklen` bytes from password +
/// salt over `iterations` rounds. Same structure as
/// `pbkdf2_hmac_sha256` with a 64-byte hash output.
pub fn pbkdf2_hmac_sha512(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dklen : Int,
) -> Bytes {
  let h_len = 64
  let num_blocks = (dklen + h_len - 1) / h_len
  let result = Array::make(dklen, b'\x00')
  let mut out_pos = 0
  for block_index in 1..<=num_blocks {
    let int_block = Array::make(4, b'\x00')
    int_block[0] = ((block_index >> 24) & 0xFF).to_byte()
    int_block[1] = ((block_index >> 16) & 0xFF).to_byte()
    int_block[2] = ((block_index >> 8) & 0xFF).to_byte()
    int_block[3] = (block_index & 0xFF).to_byte()
    let salt_with_index = concat_bytes(salt, Bytes::from_array(int_block[:]))
    let mut u = hmac_sha512(password, salt_with_index)
    let mut t = u
    for _ in 1..<iterations {
      u = hmac_sha512(password, u)
      let t_arr = Array::make(h_len, b'\x00')
      for k in 0..<h_len {
        t_arr[k] = (t[k].to_int() ^ u[k].to_int()).to_byte()
      }
      t = Bytes::from_array(t_arr[:])
    }
    let copy_len = if out_pos + h_len <= dklen {
      h_len
    } else {
      dklen - out_pos
    }
    for k in 0..<copy_len {
      result[out_pos + k] = t[k]
    }
    out_pos = out_pos + h_len
  }
  Bytes::from_array(result[:])
}

///|
/// HKDF-Extract (SHA-384): PRK = HMAC-SHA384(salt, IKM). Empty salt
/// defaults to 48 zero bytes. v0.41.0.
pub fn hkdf_sha384_extract(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 {
    let z = Array::make(48, b'\x00')
    Bytes::from_array(z[:])
  } else {
    salt
  }
  hmac_sha384(s, ikm)
}

///|
/// HKDF-SHA384 (RFC 5869): expand IKM into `length` bytes. v0.41.0.
pub fn hkdf_sha384(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hkdf_sha384_extract(salt, ikm)
  let mut okm = b""
  let mut t = b""
  let mut i = 1
  while okm.length() < length && i <= 255 {
    t = hmac_sha384(
      prk,
      concat_bytes(concat_bytes(t, info), Bytes::make(1, i.to_byte())),
    )
    okm = concat_bytes(okm, t)
    i = i + 1
  }
  Bytes::from_array(okm.to_array()[0:length])
}
