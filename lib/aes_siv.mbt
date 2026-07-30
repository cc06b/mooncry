// ==================== AES-SIV (RFC 5297, misuse-resistant AEAD) ====================
// AES-SIV authenticated encryption with associated data. Reuses cmac_aes
// (for S2V) and aes_ctr (for the CTR mode). The S2V structure and the CTR IV
// masking (clear bits 63 & 31) follow the reference (pycryptodome _S2V /
// _mode_siv): for |P|>=16 the plaintext's last block is XOR'd with D
// directly (no extra double); for |P|<16 the padded plaintext is XOR'd with
// double(D). Verified against pycryptodome AES.MODE_SIV.

///|
/// GF(2^128) double: left-shift a 16-byte block by 1 bit; XOR Rb=0x..87 if
/// the MSB was set.
fn siv_double(block : Bytes) -> Bytes {
  let out = Array::make(16, b'\x00')
  let mut carry = 0
  for i in 0..<16 {
    let b = block[15 - i].to_int()
    out[15 - i] = (((b << 1) | carry) & 0xFF).to_byte()
    carry = (b >> 7) & 1
  }
  if (block[0].to_int() & 0x80) != 0 {
    out[15] = (out[15].to_int() ^ 0x87).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
fn siv_xor(a : Bytes, b : Bytes) -> Bytes {
  let out = Array::make(a.length(), b'\x00')
  for i in 0..<a.length() {
    out[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// S2V (RFC 5297): D = CMAC(K1, zeros); for each AD: D = double(D) XOR
/// CMAC(K1, AD). For |P|>=16: T = P[-16:] XOR D, S2V = CMAC(K1, P[:-16] || T).
/// For |P|<16: T = pad(P) XOR double(D), S2V = CMAC(K1, T).
fn siv_s2v(k1 : Bytes, ads : Array[Bytes], p : Bytes) -> Bytes {
  let zero16 = Bytes::make(16, b'\x00')
  let mut d = cmac_aes(zero16, k1)
  for i in 0..<ads.length() {
    d = siv_xor(siv_double(d), cmac_aes(ads[i], k1))
  }
  if p.length() >= 16 {
    let t = siv_xor(siv_slice(p, p.length() - 16, 16), d)
    let pre = siv_slice(p, 0, p.length() - 16)
    cmac_aes(concat_bytes(pre, t), k1)
  } else {
    let padded = Array::make(16, b'\x00')
    for i in 0..<p.length() {
      padded[i] = p[i]
    }
    padded[p.length()] = b'\x80'
    let t = siv_xor(Bytes::from_array(padded[:]), siv_double(d))
    cmac_aes(t, k1)
  }
}

///|
fn siv_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out[:])
}

///|
/// Clear bits 63 (MSB of byte 8) and 31 (MSB of byte 12) of the 16-byte IV,
/// the SIV CTR IV masking.
fn siv_mask_iv(iv : Bytes) -> Bytes {
  let out = Array::make(16, b'\x00')
  for i in 0..<16 {
    out[i] = iv[i]
  }
  out[8] = (out[8].to_int() & 0x7F).to_byte()
  out[12] = (out[12].to_int() & 0x7F).to_byte()
  Bytes::from_array(out[:])
}

///|
/// AES-SIV encrypt. `key` 32/48/64 bytes (AES-128/192/256-SIV). Returns the
/// 16-byte IV (tag) || ciphertext. `ads` is the vector of associated-data
/// components (each authenticated, not encrypted).
pub fn aes_siv_encrypt(
  key : Bytes,
  plaintext : Bytes,
  ads : Array[Bytes],
) -> Bytes {
  if key.length() != 32 && key.length() != 48 && key.length() != 64 {
    abort("aes_siv_encrypt: key must be 32, 48, or 64 bytes")
  }
  let half = key.length() / 2
  let k1 = siv_slice(key, 0, half)
  let k2 = siv_slice(key, half, half)
  let iv = siv_s2v(k1, ads, plaintext)
  let q = siv_mask_iv(iv)
  let ct = aes_ctr(plaintext, k2, q)
  concat_bytes(iv, ct)
}

///|
/// AES-SIV decrypt. Returns `Ok(plaintext)` if the tag verifies, `Err` otherwise.
pub fn aes_siv_decrypt(
  envelope : Bytes,
  key : Bytes,
  ads : Array[Bytes],
) -> Result[Bytes, String] {
  if key.length() != 32 && key.length() != 48 && key.length() != 64 {
    abort("aes_siv_decrypt: key must be 32, 48, or 64 bytes")
  }
  if envelope.length() < 16 {
    return Err("aes_siv_decrypt: envelope too short")
  }
  let half = key.length() / 2
  let k1 = siv_slice(key, 0, half)
  let k2 = siv_slice(key, half, half)
  let iv = siv_slice(envelope, 0, 16)
  let ct = siv_slice(envelope, 16, envelope.length() - 16)
  let q = siv_mask_iv(iv)
  let pt = aes_ctr(ct, k2, q)
  let expected = siv_s2v(k1, ads, pt)
  if bytes_equal(iv, expected) {
    Ok(pt)
  } else {
    Err("aes_siv_decrypt: authentication failed")
  }
}
