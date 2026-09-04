// ============================================================
// ML-KEM hybrid encryption ("KEM + DEM" composition). v0.33.0.
//
// seal: (K, c) = ML-KEM.Encaps(ek, m); derive (key, nonce) =
// HKDF-SHA256(salt = c, ikm = K, info = label, 44); ciphertext blob =
// c || ChaCha20-Poly1305(key, nonce, aad, msg). open decapsulates and
// verifies the tag, returning None on ANY failure (KEM implicit
// rejection lands in a tag mismatch). The HKDF salt binds the AEAD key
// to the KEM ciphertext; the label domain-separates this construction.
//
// A streaming API (seal_init / stream_update / stream_final) processes
// the message in chunks without holding it all at once.
// ============================================================

///|
fn ml_kem_hybrid_label() -> Bytes {
  b"mooncry/ml-kem-hybrid/v1"
}

///|
fn ml_kem_hybrid_derive(c : Bytes, k : Bytes) -> (Bytes, Bytes) {
  let km = hkdf_sha256(c, k, ml_kem_hybrid_label(), 44)
  (bytes_sub(km, 0, 32), bytes_sub(km, 32, 12))
}

///|
/// Streaming hybrid-encryption state. Create with one of the
/// `*_hybrid_seal_init` functions, feed the message through
/// `ml_kem_hybrid_stream_update`, finish with
/// `ml_kem_hybrid_stream_final`. v0.33.0.
pub struct MlKemHybridStream {
  key : Bytes
  nonce : Bytes
  mac : Poly1305State
  aad_len : Int
  mut ct_len : Int
  mut blocks : UInt
  residue : Array[Byte]
  mut residue_len : Int
}

///|
fn ml_kem_hybrid_init(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
) -> MlKemHybridStream {
  let otk = chacha20_poly1305_otk(key, nonce)
  let mac = poly1305_new(otk)
  poly1305_update(mac, aad)
  poly1305_update(mac, pad16(aad))
  MlKemHybridStream::{
    key,
    nonce,
    mac,
    aad_len: aad.length(),
    ct_len: 0,
    blocks: 0U,
    residue: Array::make(64, b'\x00'),
    residue_len: 0,
  }
}

///|
/// Feed a chunk of plaintext; returns the corresponding ciphertext
/// chunk (possibly shorter — full 64-byte blocks are emitted as they
/// accumulate). v0.33.0.
pub fn ml_kem_hybrid_stream_update(
  st : MlKemHybridStream,
  chunk : Bytes,
) -> Bytes {
  let parts : Array[Bytes] = []
  let mut off = 0
  let len = chunk.length()
  while off < len {
    let space = 64 - st.residue_len
    let take = if space < len - off { space } else { len - off }
    for i in 0..<take {
      st.residue[st.residue_len + i] = chunk[off + i]
    }
    st.residue_len = st.residue_len + take
    off = off + take
    if st.residue_len == 64 {
      let blk = Bytes::from_array(st.residue)
      let ct = chacha20_xor(blk, st.key, st.nonce, 1U + st.blocks)
      poly1305_update(st.mac, ct)
      st.blocks = st.blocks + 1U
      st.ct_len = st.ct_len + 64
      st.residue_len = 0
      parts.push(ct)
    }
  }
  concat_all(parts)
}

///|
/// Finish the stream: encrypts the residue and returns
/// `tail_ciphertext || 16-byte tag`. v0.33.0.
pub fn ml_kem_hybrid_stream_final(st : MlKemHybridStream) -> Bytes {
  let mut tail = Bytes::make(0, b'\x00')
  if st.residue_len > 0 {
    let blk = Bytes::from_array(st.residue[:st.residue_len])
    tail = chacha20_xor(blk, st.key, st.nonce, 1U + st.blocks)
    poly1305_update(st.mac, tail)
    st.ct_len = st.ct_len + st.residue_len
    st.residue_len = 0
  }
  let cpad = (16 - st.ct_len % 16) % 16
  poly1305_update(st.mac, Bytes::make(cpad, b'\x00'))
  poly1305_update(st.mac, le64(st.aad_len))
  poly1305_update(st.mac, le64(st.ct_len))
  let tag = poly1305_finalize(st.mac)
  concat_bytes(tail, tag)
}

// ==================== one-shot API ====================

///|
/// ML-KEM-512 hybrid seal: returns `c || ct || tag`. `m` is the 32-byte
/// encapsulation randomness; `aad` is associated data (authenticated but
/// not encrypted). v0.33.0.
pub fn ml_kem_512_hybrid_seal(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
  msg : Bytes,
) -> Bytes {
  let (k, c) = ml_kem_512_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let st = ml_kem_hybrid_init(key, nonce, aad)
  let ct = ml_kem_hybrid_stream_update(st, msg)
  let tail = ml_kem_hybrid_stream_final(st)
  concat_all([c, ct, tail])
}

///|
/// ML-KEM-512 hybrid open: decapsulates and verifies; `None` on any
/// failure (bad tag, truncated blob). v0.33.0.
pub fn ml_kem_512_hybrid_open(dk : Bytes, blob : Bytes, aad : Bytes) -> Bytes? {
  let c_len = 768
  if blob.length() < c_len + 16 {
    return None
  }
  let c = bytes_sub(blob, 0, c_len)
  let k = ml_kem_512_decaps(dk, c)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let body = bytes_sub(blob, c_len, blob.length() - c_len)
  let ct = bytes_sub(body, 0, body.length() - 16)
  let tag = bytes_sub(body, body.length() - 16, 16)
  let expected = poly1305(
    chacha20_poly1305_otk(key, nonce),
    poly1305_mac_data(aad, ct),
  )
  if !bytes_equal(expected, tag) {
    return None
  }
  Some(chacha20_xor(ct, key, nonce, 1U))
}

///|
/// ML-KEM-512 streaming hybrid seal start: encapsulates with `m` and
/// returns `(c, stream)`. Feed the message through the stream with
/// `ml_kem_hybrid_stream_update` / `ml_kem_hybrid_stream_final`, then
/// concatenate `c` with the stream outputs. v0.33.0.
pub fn ml_kem_512_hybrid_seal_init(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
) -> (Bytes, MlKemHybridStream) {
  let (k, c) = ml_kem_512_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  (c, ml_kem_hybrid_init(key, nonce, aad))
}

///|
/// ML-KEM-768 hybrid seal. See `ml_kem_512_hybrid_seal`. v0.33.0.
pub fn ml_kem_768_hybrid_seal(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
  msg : Bytes,
) -> Bytes {
  let (k, c) = ml_kem_768_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let st = ml_kem_hybrid_init(key, nonce, aad)
  let ct = ml_kem_hybrid_stream_update(st, msg)
  let tail = ml_kem_hybrid_stream_final(st)
  concat_all([c, ct, tail])
}

///|
/// ML-KEM-768 hybrid open. See `ml_kem_512_hybrid_open`. v0.33.0.
pub fn ml_kem_768_hybrid_open(dk : Bytes, blob : Bytes, aad : Bytes) -> Bytes? {
  let c_len = 1088
  if blob.length() < c_len + 16 {
    return None
  }
  let c = bytes_sub(blob, 0, c_len)
  let k = ml_kem_768_decaps(dk, c)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let body = bytes_sub(blob, c_len, blob.length() - c_len)
  let ct = bytes_sub(body, 0, body.length() - 16)
  let tag = bytes_sub(body, body.length() - 16, 16)
  let expected = poly1305(
    chacha20_poly1305_otk(key, nonce),
    poly1305_mac_data(aad, ct),
  )
  if !bytes_equal(expected, tag) {
    return None
  }
  Some(chacha20_xor(ct, key, nonce, 1U))
}

///|
/// ML-KEM-768 streaming hybrid seal start. See
/// `ml_kem_512_hybrid_seal_init`. v0.33.0.
pub fn ml_kem_768_hybrid_seal_init(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
) -> (Bytes, MlKemHybridStream) {
  let (k, c) = ml_kem_768_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  (c, ml_kem_hybrid_init(key, nonce, aad))
}

///|
/// ML-KEM-1024 hybrid seal. See `ml_kem_512_hybrid_seal`. v0.33.0.
pub fn ml_kem_1024_hybrid_seal(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
  msg : Bytes,
) -> Bytes {
  let (k, c) = ml_kem_1024_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let st = ml_kem_hybrid_init(key, nonce, aad)
  let ct = ml_kem_hybrid_stream_update(st, msg)
  let tail = ml_kem_hybrid_stream_final(st)
  concat_all([c, ct, tail])
}

///|
/// ML-KEM-1024 hybrid open. See `ml_kem_512_hybrid_open`. v0.33.0.
pub fn ml_kem_1024_hybrid_open(dk : Bytes, blob : Bytes, aad : Bytes) -> Bytes? {
  let c_len = 1568
  if blob.length() < c_len + 16 {
    return None
  }
  let c = bytes_sub(blob, 0, c_len)
  let k = ml_kem_1024_decaps(dk, c)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  let body = bytes_sub(blob, c_len, blob.length() - c_len)
  let ct = bytes_sub(body, 0, body.length() - 16)
  let tag = bytes_sub(body, body.length() - 16, 16)
  let expected = poly1305(
    chacha20_poly1305_otk(key, nonce),
    poly1305_mac_data(aad, ct),
  )
  if !bytes_equal(expected, tag) {
    return None
  }
  Some(chacha20_xor(ct, key, nonce, 1U))
}

///|
/// ML-KEM-1024 streaming hybrid seal start. See
/// `ml_kem_512_hybrid_seal_init`. v0.33.0.
pub fn ml_kem_1024_hybrid_seal_init(
  ek : Bytes,
  m : Bytes,
  aad : Bytes,
) -> (Bytes, MlKemHybridStream) {
  let (k, c) = ml_kem_1024_encaps(ek, m)
  let (key, nonce) = ml_kem_hybrid_derive(c, k)
  (c, ml_kem_hybrid_init(key, nonce, aad))
}
