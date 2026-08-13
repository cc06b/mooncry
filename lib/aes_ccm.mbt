// ============================================================
// AES-CCM (NIST SP 800-38C / RFC 3610). CBC-MAC + CTR mode AEAD over
// the AES block cipher. Nonce 7..13 bytes, tag 4..16 bytes (even).
// Reuses aes_key_expansion / encrypt_block from crypto.mbt.
// ============================================================

///|
/// CCM payload-counter width q = 15 - nonce length
fn ccm_q(nonce : Bytes) -> Int {
  15 - nonce.length()
}

///|
/// Write `v` into `out` at `off` as `width` big-endian bytes
fn ccm_write_be(out : Array[Byte], off : Int, v : UInt64, width : Int) -> Unit {
  let mut i = 0
  while i < width {
    out[off + i] = ((v >> ((width - 1 - i) * 8)) & 0xFFUL).to_byte()
    i = i + 1
  }
}

///|
/// XOR 16 bytes of `b` into `y` in place
fn ccm_xor16(y : Array[Byte], b : Bytes, off : Int) -> Unit {
  for i in 0..<16 {
    y[i] = (y[i].to_int() ^ b[off + i].to_int()).to_byte()
  }
}

///|
/// Build the CTR block A_i: flags = q-1, then nonce, then i in q bytes BE
fn ccm_ctr_block(nonce : Bytes, counter : UInt64) -> Bytes {
  let q = ccm_q(nonce)
  let arr = Array::make(16, b'\x00')
  arr[0] = (q - 1).to_byte()
  for i in 0..<nonce.length() {
    arr[1 + i] = nonce[i]
  }
  ccm_write_be(arr, 1 + nonce.length(), counter, q)
  Bytes::from_array(arr[:])
}

///|
/// CBC-MAC (SP 800-38C §6.2) over B0, the encoded AAD and the payload.
/// Returns the full 16-byte final block Y.
fn ccm_cbc_mac(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  payload : Bytes,
  mac_len : Int,
) -> Bytes {
  let q = ccm_q(nonce)
  let a_len = aad.length()
  if a_len >= 0xFF00 {
    abort(
      "ccm: aad shorter than 2^16 - 2^8 bytes required in this implementation",
    )
  }
  // B0: flags || nonce || Q (payload length in q BE bytes)
  let flags = (if a_len > 0 { 0x40 } else { 0x00 }) +
    (((mac_len - 2) / 2) << 3) +
    (q - 1)
  let b0 = Array::make(16, b'\x00')
  b0[0] = flags.to_byte()
  for i in 0..<nonce.length() {
    b0[1 + i] = nonce[i]
  }
  ccm_write_be(b0, 1 + nonce.length(), payload.length().to_uint64(), q)
  // adata encoding: 2-byte BE length prefix when aad is non-empty
  let adata_len = if a_len > 0 { 2 + a_len } else { 0 }
  let adata = Array::make(adata_len, b'\x00')
  if a_len > 0 {
    adata[0] = ((a_len >> 8) & 0xFF).to_byte()
    adata[1] = (a_len & 0xFF).to_byte()
    for i in 0..<a_len {
      adata[2 + i] = aad[i]
    }
  }
  // stream to MAC: B0 || (adata encoding zero-padded to a 16-byte
  // boundary, RFC 3610 §2.2 / SP 800-38C A.2.3) || payload, with a
  // final zero pad to 16-byte blocks
  let adata_pad = if a_len > 0 { (16 - (2 + a_len) % 16) % 16 } else { 0 }
  let total = 16 + adata_len + adata_pad + payload.length()
  let pad = (16 - total % 16) % 16
  let buf = Array::make(total + pad, b'\x00')
  for i in 0..<16 {
    buf[i] = b0[i]
  }
  for i in 0..<adata_len {
    buf[16 + i] = adata[i]
  }
  for i in 0..<payload.length() {
    buf[16 + adata_len + adata_pad + i] = payload[i]
  }
  let round_keys = aes_key_expansion(key)
  let nr = kw_aes_nr(key)
  let first = Array::make(16, b'\x00')
  for i in 0..<16 {
    first[i] = buf[i]
  }
  let mut y = encrypt_block(Bytes::from_array(first[:]), round_keys, nr)
  let y_arr = Array::make(16, b'\x00')
  for i in 0..<16 {
    y_arr[i] = y[i]
  }
  let mut off = 16
  while off < buf.length() {
    ccm_xor16(y_arr, Bytes::from_array(buf[:]), off)
    y = encrypt_block(Bytes::from_array(y_arr[:]), round_keys, nr)
    for i in 0..<16 {
      y_arr[i] = y[i]
    }
    off = off + 16
  }
  Bytes::from_array(y_arr[:])
}

///|
/// AES-CCM encrypt (NIST SP 800-38C). Key 16/24/32 bytes, nonce 7..13
/// bytes, `mac_len` one of 4/6/8/10/12/14/16. Returns
/// ciphertext || tag.
pub fn aes_ccm_encrypt(
  plaintext : Bytes,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  mac_len : Int,
) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_ccm_encrypt: key must be 16, 24, or 32 bytes")
  }
  if nonce.length() < 7 || nonce.length() > 13 {
    abort("aes_ccm_encrypt: nonce must be 7..13 bytes")
  }
  if mac_len < 4 || mac_len > 16 || mac_len % 2 != 0 {
    abort("aes_ccm_encrypt: mac_len must be even and in 4..16")
  }
  let q = ccm_q(nonce)
  // payload length must fit the q-byte counter field (q = 8 covers all
  // 64-bit lengths, so no check is needed)
  if q < 8 {
    let mut max_len = 1UL
    for _ in 0..<q {
      max_len = max_len << 8
    }
    if plaintext.length().to_uint64() >= max_len {
      abort("aes_ccm_encrypt: plaintext too long for the nonce length")
    }
  }
  let y = ccm_cbc_mac(key, nonce, aad, plaintext, mac_len)
  let round_keys = aes_key_expansion(key)
  let nr = kw_aes_nr(key)
  // S0 encrypts the tag; payload uses counters 1..
  let s0 = encrypt_block(ccm_ctr_block(nonce, 0UL), round_keys, nr)
  let tag = Array::make(mac_len, b'\x00')
  for i in 0..<mac_len {
    tag[i] = (y[i].to_int() ^ s0[i].to_int()).to_byte()
  }
  let ct = Array::make(plaintext.length(), b'\x00')
  let mut off = 0
  let mut counter = 1UL
  while off < plaintext.length() {
    let ks = encrypt_block(ccm_ctr_block(nonce, counter), round_keys, nr)
    let take = if plaintext.length() - off < 16 {
      plaintext.length() - off
    } else {
      16
    }
    for i in 0..<take {
      ct[off + i] = (plaintext[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    off = off + take
    counter = counter + 1UL
  }
  let out = Array::make(ct.length() + mac_len, b'\x00')
  for i in 0..<ct.length() {
    out[i] = ct[i]
  }
  for i in 0..<mac_len {
    out[ct.length() + i] = tag[i]
  }
  Bytes::from_array(out[:])
}

///|
/// AES-CCM decrypt. `input` = ciphertext || tag. Verifies the tag
/// (constant-time) and returns the plaintext, or aborts on mismatch.
pub fn aes_ccm_decrypt(
  input : Bytes,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  mac_len : Int,
) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("aes_ccm_decrypt: key must be 16, 24, or 32 bytes")
  }
  if nonce.length() < 7 || nonce.length() > 13 {
    abort("aes_ccm_decrypt: nonce must be 7..13 bytes")
  }
  if mac_len < 4 || mac_len > 16 || mac_len % 2 != 0 {
    abort("aes_ccm_decrypt: mac_len must be even and in 4..16")
  }
  if input.length() < mac_len {
    abort("aes_ccm_decrypt: input must be at least mac_len bytes")
  }
  let ct_len = input.length() - mac_len
  let ct = Array::make(ct_len, b'\x00')
  for i in 0..<ct_len {
    ct[i] = input[i]
  }
  let ct_bytes = Bytes::from_array(ct[:])
  let received_tag = Array::make(mac_len, b'\x00')
  for i in 0..<mac_len {
    received_tag[i] = input[ct_len + i]
  }
  // recover the plaintext first (CTR layer is independent of the MAC)
  let round_keys = aes_key_expansion(key)
  let nr = kw_aes_nr(key)
  let pt = Array::make(ct_len, b'\x00')
  let mut off = 0
  let mut counter = 1UL
  while off < ct_len {
    let ks = encrypt_block(ccm_ctr_block(nonce, counter), round_keys, nr)
    let take = if ct_len - off < 16 { ct_len - off } else { 16 }
    for i in 0..<take {
      pt[off + i] = (ct_bytes[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    off = off + take
    counter = counter + 1UL
  }
  let pt_bytes = Bytes::from_array(pt[:])
  let y = ccm_cbc_mac(key, nonce, aad, pt_bytes, mac_len)
  let s0 = encrypt_block(ccm_ctr_block(nonce, 0UL), round_keys, nr)
  let expected = Array::make(mac_len, b'\x00')
  for i in 0..<mac_len {
    expected[i] = (y[i].to_int() ^ s0[i].to_int()).to_byte()
  }
  if !bytes_equal(
      Bytes::from_array(expected[:]),
      Bytes::from_array(received_tag[:]),
    ) {
    abort("aes_ccm_decrypt: tag verification failed")
  }
  pt_bytes
}
