// SM4 modes of operation (GB/T 32907 block cipher + standard modes) and
// HMAC-SM3 (RFC 2104). CTR/CBC/GCM conventions mirror the AES counterparts
// in crypto.mbt; GCM reuses the cipher-independent gcm_ghash.
// Vectors cross-checked against openssl's SM4 via the cryptography package.

///|
fn sm4_xor_into(
  out : Array[Byte],
  data : Bytes,
  ks : Bytes,
  off : Int,
  len : Int,
) -> Unit {
  for j in 0..<len {
    out[off + j] = (data[off + j].to_int() ^ ks[j].to_int()).to_byte()
  }
}

///|
fn sm4_inc_be128(ctr : Array[Byte]) -> Unit {
  let mut i = 15
  let mut carry = 1
  while i >= 0 && carry == 1 {
    let v = ctr[i].to_int() + 1
    ctr[i] = (v % 256).to_byte()
    carry = if v > 255 { 1 } else { 0 }
    i = i - 1
  }
}

///|
/// SM4-CTR: 128-bit big-endian counter over the full block (same convention
/// as aes_ctr). `iv` is the 16-byte initial counter block.
pub fn sm4_ctr(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  guard key.length() == 16 && iv.length() == 16 else {
    abort("sm4_ctr: key and iv must be 16 bytes")
  }
  let rk = sm4_expand_key(key)
  let len = data.length()
  let out = Array::make(len, (0).to_byte())
  let ctr = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    ctr[i] = iv[i]
  }
  let mut off = 0
  while off < len {
    let ks = sm4_encrypt_block(rk, Bytes::from_array(ctr[:]), 0)
    let n = if off + 16 <= len { 16 } else { len - off }
    sm4_xor_into(out, data, ks, off, n)
    off = off + n
    sm4_inc_be128(ctr)
  }
  Bytes::from_array(out[:])
}

///|
/// SM4-CBC encrypt (raw, no padding): data length must be a multiple of 16.
pub fn sm4_cbc_encrypt(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  guard key.length() == 16 && iv.length() == 16 else {
    abort("sm4_cbc_encrypt: key and iv must be 16 bytes")
  }
  guard data.length() % 16 == 0 else {
    abort("sm4_cbc_encrypt: data must be a multiple of 16 bytes (no padding)")
  }
  let rk = sm4_expand_key(key)
  let out = Array::make(data.length(), (0).to_byte())
  let prev = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    prev[i] = iv[i]
  }
  let mut off = 0
  while off < data.length() {
    let x = Array::make(16, (0).to_byte())
    for j in 0..<16 {
      x[j] = (data[off + j].to_int() ^ prev[j].to_int()).to_byte()
    }
    let ct = sm4_encrypt_block(rk, Bytes::from_array(x[:]), 0)
    for j in 0..<16 {
      out[off + j] = ct[j]
      prev[j] = ct[j]
    }
    off = off + 16
  }
  Bytes::from_array(out[:])
}

///|
/// SM4-CBC decrypt (raw, no padding): data length must be a multiple of 16.
pub fn sm4_cbc_decrypt(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  guard key.length() == 16 && iv.length() == 16 else {
    abort("sm4_cbc_decrypt: key and iv must be 16 bytes")
  }
  guard data.length() % 16 == 0 && data.length() > 0 else {
    abort("sm4_cbc_decrypt: data must be a nonzero multiple of 16 bytes")
  }
  let rk = sm4_expand_key(key)
  let out = Array::make(data.length(), (0).to_byte())
  let mut prev = iv
  let mut off = 0
  while off < data.length() {
    let pt = sm4_decrypt_block(rk, data, off)
    for j in 0..<16 {
      out[off + j] = (pt[j].to_int() ^ prev[j].to_int()).to_byte()
    }
    prev = ec_slice(data, off, 16)
    off = off + 16
  }
  Bytes::from_array(out[:])
}

///|
fn sm4_gctr(rk : Array[UInt], icb : Bytes, data : Bytes) -> Bytes {
  let len = data.length()
  if len == 0 {
    return b""
  }
  let out = Array::make(len, (0).to_byte())
  let ctr = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    ctr[i] = icb[i]
  }
  let mut off = 0
  while off < len {
    let ks = sm4_encrypt_block(rk, Bytes::from_array(ctr[:]), 0)
    let n = if off + 16 <= len { 16 } else { len - off }
    sm4_xor_into(out, data, ks, off, n)
    off = off + n
    // GCM increments only the rightmost 32 bits
    let c3 = (
        (ctr[12].to_uint() << 24) |
        (ctr[13].to_uint() << 16) |
        (ctr[14].to_uint() << 8) |
        ctr[15].to_uint()
      ) +
      1U
    ctr[12] = ((c3 >> 24) & 0xFFU).to_byte()
    ctr[13] = ((c3 >> 16) & 0xFFU).to_byte()
    ctr[14] = ((c3 >> 8) & 0xFFU).to_byte()
    ctr[15] = (c3 & 0xFFU).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// SM4-GCM encrypt (RFC 5116 / SP 800-38D structure with SM4): 12-byte IV,
/// returns (ciphertext, 16-byte tag).
pub fn sm4_gcm_encrypt(
  plaintext : Bytes,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) {
  guard key.length() == 16 && iv.length() == 12 else {
    abort("sm4_gcm_encrypt: key must be 16 bytes, iv 12 bytes")
  }
  let rk = sm4_expand_key(key)
  let h = sm4_encrypt_block(rk, Bytes::make(16, (0).to_byte()), 0)
  let j0 = Array::make(16, (0).to_byte())
  for i in 0..<12 {
    j0[i] = iv[i]
  }
  j0[15] = (1).to_byte()
  let j0b = Bytes::from_array(j0[:])
  // C = GCTR(inc32(J0), P)
  let icb = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    icb[i] = j0b[i]
  }
  icb[15] = (2).to_byte() // inc32(J0): low word 1 -> 2
  let ct = sm4_gctr(rk, Bytes::from_array(icb[:]), plaintext)
  let s = gcm_ghash(bytes_to_block(h, 0), aad, ct)
  let ej0 = sm4_encrypt_block(rk, j0b, 0)
  let tag = Array::make(16, (0).to_byte())
  for i in 0..<4 {
    let w = s[i] ^ bytes_to_block(ej0, 0)[i]
    tag[i * 4] = ((w >> 24) & 0xFFU).to_byte()
    tag[i * 4 + 1] = ((w >> 16) & 0xFFU).to_byte()
    tag[i * 4 + 2] = ((w >> 8) & 0xFFU).to_byte()
    tag[i * 4 + 3] = (w & 0xFFU).to_byte()
  }
  (ct, Bytes::from_array(tag[:]))
}

///|
/// SM4-GCM decrypt: verifies the tag first; returns (b"", false) on mismatch.
pub fn sm4_gcm_decrypt(
  ciphertext : Bytes,
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  tag : Bytes,
) -> (Bytes, Bool) {
  guard key.length() == 16 && iv.length() == 12 && tag.length() == 16 else {
    abort("sm4_gcm_decrypt: key 16 bytes, iv 12 bytes, tag 16 bytes")
  }
  let rk = sm4_expand_key(key)
  let h = sm4_encrypt_block(rk, Bytes::make(16, (0).to_byte()), 0)
  let j0 = Array::make(16, (0).to_byte())
  for i in 0..<12 {
    j0[i] = iv[i]
  }
  j0[15] = (1).to_byte()
  let j0b = Bytes::from_array(j0[:])
  let s = gcm_ghash(bytes_to_block(h, 0), aad, ciphertext)
  let ej0 = sm4_encrypt_block(rk, j0b, 0)
  let ej0b = bytes_to_block(ej0, 0)
  let expect_block = [
    s[0] ^ ej0b[0],
    s[1] ^ ej0b[1],
    s[2] ^ ej0b[2],
    s[3] ^ ej0b[3],
  ]
  // constant-time compare (same idiom as aes_gcm_decrypt)
  if !bytes_equal(block_to_bytes(expect_block), tag) {
    return (b"", false)
  }
  let icb = Array::make(16, (0).to_byte())
  for i in 0..<16 {
    icb[i] = j0b[i]
  }
  icb[15] = (2).to_byte()
  let pt = sm4_gctr(rk, Bytes::from_array(icb[:]), ciphertext)
  (pt, true)
}

///|
/// HMAC-SM3 (RFC 2104, 64-byte block, 32-byte MAC). Keys longer than the
/// block are hashed first.
pub fn hmac_sm3(key : Bytes, msg : Bytes) -> Bytes {
  let block_size = 64
  let k_prime = if key.length() > block_size { sm3(key) } else { key }
  let kp = Array::make(block_size, (0).to_byte())
  for i in 0..<k_prime.length() {
    kp[i] = k_prime[i]
  }
  let inner = Array::make(block_size + msg.length(), (0).to_byte())
  let outer = Array::make(block_size, (0).to_byte())
  for i in 0..<block_size {
    inner[i] = (kp[i].to_int() ^ 0x36).to_byte()
    outer[i] = (kp[i].to_int() ^ 0x5C).to_byte()
  }
  for i in 0..<msg.length() {
    inner[block_size + i] = msg[i]
  }
  let ih = sm3(Bytes::from_array(inner[:]))
  let oh = Array::make(block_size + 32, (0).to_byte())
  for i in 0..<block_size {
    oh[i] = outer[i]
  }
  for i in 0..<32 {
    oh[block_size + i] = ih[i]
  }
  sm3(Bytes::from_array(oh[:]))
}
