// ==================== HKDF / PBKDF2 over SHA-3 (RFC 5869 / RFC 8018) ====================
// Mirrors the SHA-256 KDFs, reusing hmac_sha3_256. Block size for SHA-3
// is its rate: SHA3-256 rate = 136 bytes.

///|
/// HKDF-SHA3-256 (RFC 5869): extract+expand over HMAC-SHA3-256.
/// `salt` is the extraction salt, `ikm` the input keying material, `info` the
/// context, `length` the output length (<= 255 * 32).
pub fn hkdf_sha3_256(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hmac_sha3_256(salt, ikm)
  let mut okm = b""
  let mut t = b""
  let mut i = 1
  while okm.length() < length && i <= 255 {
    t = hmac_sha3_256(
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
/// PBKDF2-HMAC-SHA3-256 (RFC 8018): derive `dklen` bytes from `password` +
/// `salt` over `iterations` rounds. Block size = SHA3-256 rate (136), but
/// HMAC handles arbitrary-length keys internally so the result matches the
/// standard regardless.
pub fn pbkdf2_hmac_sha3_256(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dklen : Int,
) -> Bytes {
  let h_len = 32
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
    let mut u = hmac_sha3_256(password, salt_with_index)
    let mut t = u
    for _ in 1..<iterations {
      u = hmac_sha3_256(password, u)
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
    out_pos = out_pos + copy_len
  }
  Bytes::from_array(result[:])
}
