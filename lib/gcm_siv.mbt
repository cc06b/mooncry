// ============================================================
// AES-GCM-SIV (RFC 8452): nonce-misuse-resistant authenticated
// encryption. AEAD_AES_128_GCM_SIV / AEAD_AES_256_GCM_SIV. v0.39.0.
// ============================================================

///|
/// POLYVAL (RFC 8452 section 3) over a whole number of 16-byte blocks,
/// computed via the Appendix A equivalence
/// POLYVAL(H, X1..) = ByteReverse(GHASH(ByteReverse(H)·x, ByteReverse(Xi)..))
/// using the library's table-accelerated GHASH multiplication.
fn gcm_siv_polyval(h : Bytes, data : Bytes) -> Bytes {
  if data.length() % 16 != 0 {
    abort("gcm_siv polyval: input must be a multiple of 16 bytes")
  }
  // Hv = mulX_GHASH(ByteReverse(H)); ByteReverse + BE-word read = LE read
  let hv = Array::make(4, 0U)
  for j in 0..<4 {
    let off = (3 - j) * 4
    hv[j] = h[off].to_uint() |
      (h[off + 1].to_uint() << 8) |
      (h[off + 2].to_uint() << 16) |
      (h[off + 3].to_uint() << 24)
  }
  ghash_double(hv) // multiplication by x in the GHASH convention
  let tab = ghash_make_table(hv)
  let y = Array::make(4, 0U)
  let blk = Array::make(4, 0U)
  let prod = Array::make(4, 0U)
  let mut off = 0
  let len = data.length()
  while off < len {
    for j in 0..<4 {
      let o = off + (3 - j) * 4
      blk[j] = data[o].to_uint() |
        (data[o + 1].to_uint() << 8) |
        (data[o + 2].to_uint() << 16) |
        (data[o + 3].to_uint() << 24)
    }
    y[0] = y[0] ^ blk[0]
    y[1] = y[1] ^ blk[1]
    y[2] = y[2] ^ blk[2]
    y[3] = y[3] ^ blk[3]
    ghash_mul_into(tab, y, prod)
    y[0] = prod[0]
    y[1] = prod[1]
    y[2] = prod[2]
    y[3] = prod[3]
    off = off + 16
  }
  // ByteReverse(y)
  let out = Array::make(16, b'\x00')
  for i in 0..<16 {
    let b = 15 - i
    out[i] = ((y[b / 4] >> ((3 - b % 4) * 8)) & 0xFFU).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
fn gcm_siv_pad16(x : Bytes) -> Bytes {
  let r = x.length() % 16
  if r == 0 {
    x
  } else {
    concat_bytes(x, Bytes::make(16 - r, b'\x00'))
  }
}

///|
fn gcm_siv_le32(x : Int) -> Bytes {
  let out = Array::make(4, b'\x00')
  out[0] = (x & 0xFF).to_byte()
  out[1] = ((x >> 8) & 0xFF).to_byte()
  out[2] = ((x >> 16) & 0xFF).to_byte()
  out[3] = ((x >> 24) & 0xFF).to_byte()
  Bytes::from_array(out[:])
}

///|
fn gcm_siv_le64(x : Int) -> Bytes {
  let out = Array::make(8, b'\x00')
  let mut v = x.to_uint64()
  for i in 0..<8 {
    out[i] = (v & 0xFFUL).to_byte()
    v = v >> 8
  }
  Bytes::from_array(out[:])
}

///|
fn gcm_siv_derive_keys(
  key : Bytes,
  nonce : Bytes,
) -> (Bytes, Bytes, Array[Array[Int]], Int) {
  let round_keys = aes_key_expansion(key)
  let nr = if key.length() == 16 { 10 } else { 14 }
  let blocks = if key.length() == 16 { 4 } else { 6 }
  let parts : Array[Bytes] = []
  for c in 0..<blocks {
    let out = encrypt_block(
      concat_bytes(gcm_siv_le32(c), nonce),
      round_keys,
      nr,
    )
    parts.push(bytes_sub(out, 0, 8))
  }
  let auth_key = concat_bytes(parts[0], parts[1])
  let mut enc_key = concat_bytes(parts[2], parts[3])
  if blocks == 6 {
    enc_key = concat_all([enc_key, parts[4], parts[5]])
  }
  (auth_key, enc_key, round_keys, nr)
}

// AES-CTR with the GCM-SIV counter convention: the first 32 bits are an
// unsigned little-endian counter, wrapping at 2^32.

///|
fn gcm_siv_ctr(
  enc_key_rk : Array[Array[Int]],
  nr : Int,
  initial_counter_block : Bytes,
  data : Bytes,
) -> Bytes {
  let block = initial_counter_block.to_array()
  let out_parts : Array[Bytes] = []
  let mut off = 0
  let len = data.length()
  while off < len {
    let ks = encrypt_block(Bytes::from_array(block[:]), enc_key_rk, nr)
    // increment the little-endian 32-bit counter in block[0..4] (wraps
    // at 2^32 via 32-bit Int overflow-free modular arithmetic)
    let c0 = block[0].to_int() & 0xFF
    let c1 = block[1].to_int() & 0xFF
    let c2 = block[2].to_int() & 0xFF
    let c3 = block[3].to_int() & 0xFF
    let cv = (c0 | (c1 << 8) | (c2 << 16) | (c3 << 24)) + 1
    block[0] = (cv & 0xFF).to_byte()
    block[1] = ((cv >> 8) & 0xFF).to_byte()
    block[2] = ((cv >> 16) & 0xFF).to_byte()
    block[3] = ((cv >> 24) & 0xFF).to_byte()
    let take = if 16 < len - off { 16 } else { len - off }
    let piece = Array::make(take, b'\x00')
    for i in 0..<take {
      piece[i] = (data[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    out_parts.push(Bytes::from_array(piece[:]))
    off = off + take
  }
  concat_all(out_parts)
}

///|
/// AEAD_AES_128_GCM_SIV / AEAD_AES_256_GCM_SIV encryption (RFC 8452).
/// `key` is 16 or 32 bytes, `nonce` 12 bytes. Returns ciphertext || tag.
/// The construction is nonce-misuse-resistant: reusing a nonce with the
/// same key only leaks whether identical messages were encrypted. v0.39.0.
pub fn aes_gcm_siv_encrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes {
  if key.length() != 16 && key.length() != 32 {
    abort("aes_gcm_siv_encrypt: key must be 16 or 32 bytes")
  }
  if nonce.length() != 12 {
    abort("aes_gcm_siv_encrypt: nonce must be 12 bytes")
  }
  let (auth_key, enc_key, _, _) = gcm_siv_derive_keys(key, nonce)
  let rk_enc = aes_key_expansion(enc_key)
  let nr_enc = if enc_key.length() == 16 { 10 } else { 14 }
  let length_block = concat_bytes(
    gcm_siv_le64(aad.length() * 8),
    gcm_siv_le64(plaintext.length() * 8),
  )
  let poly_input = concat_all([
    gcm_siv_pad16(aad),
    gcm_siv_pad16(plaintext),
    length_block,
  ])
  let ss = gcm_siv_polyval(auth_key, poly_input).to_array()
  for i in 0..<12 {
    ss[i] = (ss[i].to_int() ^ nonce[i].to_int()).to_byte()
  }
  ss[15] = ss[15] & 0x7f
  let tag = encrypt_block(Bytes::from_array(ss[:]), rk_enc, nr_enc)
  let counter_block = tag.to_array()
  counter_block[15] = counter_block[15] | 0x80
  let ct = gcm_siv_ctr(
    rk_enc,
    nr_enc,
    Bytes::from_array(counter_block[:]),
    plaintext,
  )
  concat_bytes(ct, tag)
}

///|
/// AEAD_AES_GCM_SIV decryption: verifies the tag over the decrypted
/// plaintext and returns `None` on mismatch (constant-time tag compare).
/// v0.39.0.
pub fn aes_gcm_siv_decrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ct_and_tag : Bytes,
) -> Bytes? {
  if key.length() != 16 && key.length() != 32 {
    abort("aes_gcm_siv_decrypt: key must be 16 or 32 bytes")
  }
  if nonce.length() != 12 {
    abort("aes_gcm_siv_decrypt: nonce must be 12 bytes")
  }
  if ct_and_tag.length() < 16 {
    return None
  }
  let ct_len = ct_and_tag.length() - 16
  let ct = bytes_sub(ct_and_tag, 0, ct_len)
  let tag = bytes_sub(ct_and_tag, ct_len, 16)
  let (auth_key, enc_key, _, _) = gcm_siv_derive_keys(key, nonce)
  let rk_enc = aes_key_expansion(enc_key)
  let nr_enc = if enc_key.length() == 16 { 10 } else { 14 }
  let counter_block = tag.to_array()
  counter_block[15] = counter_block[15] | 0x80
  let pt = gcm_siv_ctr(rk_enc, nr_enc, Bytes::from_array(counter_block[:]), ct)
  // authenticate the recovered plaintext
  let length_block = concat_bytes(
    gcm_siv_le64(aad.length() * 8),
    gcm_siv_le64(pt.length() * 8),
  )
  let poly_input = concat_all([
    gcm_siv_pad16(aad),
    gcm_siv_pad16(pt),
    length_block,
  ])
  let ss = gcm_siv_polyval(auth_key, poly_input).to_array()
  for i in 0..<12 {
    ss[i] = (ss[i].to_int() ^ nonce[i].to_int()).to_byte()
  }
  ss[15] = ss[15] & 0x7f
  let expected = encrypt_block(Bytes::from_array(ss[:]), rk_enc, nr_enc)
  if bytes_equal(expected, tag) {
    Some(pt)
  } else {
    None
  }
}
