// ==================== Incremental GMAC (v0.22.0) ====================
// Streaming/incremental GMAC (NIST SP 800-38D): the authentication-only
// specialization of AES-GCM, fed chunk-by-chunk. Equivalent to `gmac(key,
// iv, concat(chunks))` and to the AES-GCM tag of an empty plaintext with
// the same AAD — verified in-tree against the one-shot `gmac`.
//
// Uses the same table-accelerated GHASH as AES-GCM (v0.19.0). The GHASH
// table lookups are not constant-time with respect to the AAD; see the
// security notes in the README (same property as `aes_gcm_encrypt`).

///|
/// Incremental GMAC state. Create with `gmac_new`, feed AAD chunks with
/// `gmac_update`, get the 16-byte tag with `gmac_finalize`.
pub struct GmacState {
  tab : Array[UInt]
  y : Array[UInt]
  blk : Array[UInt]
  prod : Array[UInt]
  buffer : Array[Byte]
  round_keys : Array[Array[Int]]
  j0 : Array[UInt]
  nr : Int
  mut buf_len : Int
  mut total_len : UInt64
}

///|
/// Build the incremental GMAC state for any IV length (SP 800-38D §8.2.1):
/// 96-bit IVs use J0 = IV || 0^31 || 1; other lengths use
/// J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64).
fn gmac_state_init(key : Bytes, iv : Bytes) -> GmacState {
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)
  // H = AES_K(0^128) — hash subkey
  let h_bytes = encrypt_block(
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", round_keys,
    nr,
  )
  let h = bytes_to_block(h_bytes, 0)
  let tab = ghash_make_table(h)
  let j0 = if iv.length() == 12 {
    // J0 = IV || 0^31 || 1 (96-bit IV)
    let arr = Array::make(4, 0U)
    arr[0] = (iv[0].to_uint() << 24) |
      (iv[1].to_uint() << 16) |
      (iv[2].to_uint() << 8) |
      iv[3].to_uint()
    arr[1] = (iv[4].to_uint() << 24) |
      (iv[5].to_uint() << 16) |
      (iv[6].to_uint() << 8) |
      iv[7].to_uint()
    arr[2] = (iv[8].to_uint() << 24) |
      (iv[9].to_uint() << 16) |
      (iv[10].to_uint() << 8) |
      iv[11].to_uint()
    arr[3] = 0x00000001U
    arr
  } else {
    // J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
    let y = Array::make(4, 0U)
    let blk = Array::make(4, 0U)
    let prod = Array::make(4, 0U)
    let iv_len = iv.length()
    let mut off = 0
    while off < iv_len {
      ghash_read_block_into(iv, off, blk)
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
    // trailing block: [0]_64 || [len(IV) in bits]_64
    let iv_bits = (iv_len * 8).to_uint64()
    blk[0] = 0U
    blk[1] = 0U
    blk[2] = ((iv_bits >> 32) & 0xFFFFFFFFUL).to_uint()
    blk[3] = (iv_bits & 0xFFFFFFFFUL).to_uint()
    y[0] = y[0] ^ blk[0]
    y[1] = y[1] ^ blk[1]
    y[2] = y[2] ^ blk[2]
    y[3] = y[3] ^ blk[3]
    ghash_mul_into(tab, y, prod)
    prod
  }
  GmacState::{
    tab,
    y: Array::make(4, 0U),
    blk: Array::make(4, 0U),
    prod: Array::make(4, 0U),
    buffer: Array::make(16, b'\x00'),
    round_keys,
    j0,
    nr,
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
/// Start an incremental GMAC over `aad` chunks under `key` (16/24/32
/// bytes) and a 12-byte `iv` (same rules as `aes_gcm_encrypt`).
pub fn gmac_new(key : Bytes, iv : Bytes) -> GmacState {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("gmac_new: key length must be 16, 24, or 32 bytes")
  }
  if iv.length() != 12 {
    abort("gmac_new: iv/nonce length must be 12 bytes (96 bits)")
  }
  gmac_state_init(key, iv)
}

///|
/// Start an incremental GMAC with an IV of ANY length (SP 800-38D §8.2.1).
/// 12-byte IVs take the fast J0 = IV || 0^31 || 1 path; other lengths
/// derive J0 via GHASH (slightly slower setup, identical security).
/// Avoid empty IVs (valid per spec but strongly discouraged).
pub fn gmac_new_iv(key : Bytes, iv : Bytes) -> GmacState {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("gmac_new_iv: key length must be 16, 24, or 32 bytes")
  }
  gmac_state_init(key, iv)
}

///|
/// Multiply the accumulator by H in place (Y <- Y·H).
fn gmac_mul(st : GmacState) -> Unit {
  ghash_mul_into(st.tab, st.y, st.prod)
  st.y[0] = st.prod[0]
  st.y[1] = st.prod[1]
  st.y[2] = st.prod[2]
  st.y[3] = st.prod[3]
}

///|
/// Feed an AAD chunk into the incremental GMAC. May be called any number
/// of times with chunks of any length.
pub fn gmac_update(st : GmacState, aad : Bytes) -> Unit {
  let len = aad.length()
  if len == 0 {
    return
  }
  st.total_len = st.total_len + len.to_uint64()
  let mut off = 0
  if st.buf_len > 0 {
    let space = 16 - st.buf_len
    let to_copy = if len < space { len } else { space }
    for i in 0..<to_copy {
      st.buffer[st.buf_len + i] = aad[i]
    }
    st.buf_len = st.buf_len + to_copy
    off = to_copy
    if st.buf_len == 16 {
      for j in 0..<=3 {
        st.blk[j] = (st.buffer[j * 4].to_uint() << 24) |
          (st.buffer[j * 4 + 1].to_uint() << 16) |
          (st.buffer[j * 4 + 2].to_uint() << 8) |
          st.buffer[j * 4 + 3].to_uint()
      }
      st.y[0] = st.y[0] ^ st.blk[0]
      st.y[1] = st.y[1] ^ st.blk[1]
      st.y[2] = st.y[2] ^ st.blk[2]
      st.y[3] = st.y[3] ^ st.blk[3]
      gmac_mul(st)
      st.buf_len = 0
    }
  }
  let remaining = len - off
  let num_full = remaining / 16
  for b in 0..<num_full {
    ghash_read_block_into(aad, off + b * 16, st.blk)
    st.y[0] = st.y[0] ^ st.blk[0]
    st.y[1] = st.y[1] ^ st.blk[1]
    st.y[2] = st.y[2] ^ st.blk[2]
    st.y[3] = st.y[3] ^ st.blk[3]
    gmac_mul(st)
  }
  let rem_count = remaining - num_full * 16
  if rem_count > 0 {
    let rem_start = off + num_full * 16
    for i in 0..<rem_count {
      st.buffer[i] = aad[rem_start + i]
    }
    st.buf_len = rem_count
  }
}

///|
/// Finalize the incremental GMAC and return the 16-byte tag. For chunked
/// AAD `c1, c2, ...` the result equals `gmac(key, iv, concat(c1, c2, ...))`.
pub fn gmac_finalize(st : GmacState) -> Bytes {
  // Zero-pad a trailing partial block.
  if st.buf_len > 0 {
    for i in st.buf_len..<16 {
      st.buffer[i] = b'\x00'
    }
    for j in 0..<=3 {
      st.blk[j] = (st.buffer[j * 4].to_uint() << 24) |
        (st.buffer[j * 4 + 1].to_uint() << 16) |
        (st.buffer[j * 4 + 2].to_uint() << 8) |
        st.buffer[j * 4 + 3].to_uint()
    }
    st.y[0] = st.y[0] ^ st.blk[0]
    st.y[1] = st.y[1] ^ st.blk[1]
    st.y[2] = st.y[2] ^ st.blk[2]
    st.y[3] = st.y[3] ^ st.blk[3]
    gmac_mul(st)
  }
  // Length block: [len(AAD) in bits]_64 || [0]_64 (empty plaintext).
  let aad_bits = st.total_len * 8UL
  st.blk[0] = ((aad_bits >> 32) & 0xFFFFFFFFUL).to_uint()
  st.blk[1] = (aad_bits & 0xFFFFFFFFUL).to_uint()
  st.blk[2] = 0U
  st.blk[3] = 0U
  st.y[0] = st.y[0] ^ st.blk[0]
  st.y[1] = st.y[1] ^ st.blk[1]
  st.y[2] = st.y[2] ^ st.blk[2]
  st.y[3] = st.y[3] ^ st.blk[3]
  gmac_mul(st)
  // T = Y XOR AES_K(J0)
  let j0_bytes = block_to_bytes(st.j0)
  let e_j0 = encrypt_block(j0_bytes, st.round_keys, st.nr)
  let e_j0_block = bytes_to_block(e_j0, 0)
  let tag = Array::make(4, 0U)
  tag[0] = st.y[0] ^ e_j0_block[0]
  tag[1] = st.y[1] ^ e_j0_block[1]
  tag[2] = st.y[2] ^ e_j0_block[2]
  tag[3] = st.y[3] ^ e_j0_block[3]
  block_to_bytes(tag)
}

///|
/// Verify a 16-byte tag produced by the incremental GMAC in constant time.
pub fn gmac_stream_verify(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  tag : Bytes,
) -> Bool {
  bytes_equal(gmac(key, iv, aad), tag)
}
