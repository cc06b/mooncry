///|
/// PBKDF2-HMAC-SHA1 (RFC 8018 over RFC 2104/HMAC-SHA1). The classic
/// password-based KDF (WPA2, legacy TLS), verified against the
/// official RFC 6070 test vectors. Same construction as
/// `pbkdf2_hmac_sha256` with a 20-byte hash output.

///|
/// PBKDF2-HMAC-SHA1 (RFC 8018): derive `dklen` bytes from password +
/// salt over `iterations` rounds.
pub fn pbkdf2_hmac_sha1(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dklen : Int,
) -> Bytes {
  let h_len = 20
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
    let mut u = hmac_sha1(password, salt_with_index)
    let mut t = u
    for _ in 1..<iterations {
      u = hmac_sha1(password, u)
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
