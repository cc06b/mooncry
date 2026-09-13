// ============ ZUC modes: 128-EEA3 and 128-EIA3 (3GPP TS 35.221 / 35.222 / 35.223) ============
//
// The two 3GPP algorithms built on ZUC-128:
//
//   * 128-EEA3 (f8) — confidentiality. The IV is assembled from COUNT, BEARER
//     and DIRECTION, then ceil(LENGTH/32) keystream words are XORed into the
//     message and the final word is masked down to LENGTH bits.
//   * 128-EIA3 (f9) — integrity. A ZUC-driven word-wise MAC over LENGTH bits of
//     message, producing the 32-bit MAC-I.
//
// Both are bit-oriented: LENGTH is a bit count, and the buffer carrying the
// message holds ceil(LENGTH/8) bytes whose trailing bits beyond LENGTH are not
// part of the input (EEA3 zeroes them in the output; EIA3 never reads them).
//
// Neither is authenticated encryption: EEA3 provides no integrity at all, so
// pair it with EIA3 the way LTE/NR does, or use an AEAD when the protocol
// allows it.

///|
/// COUNT is a 32-bit unsigned counter; `UInt` is 32-bit on every MoonBit
/// target, so no value is unrepresentable (wasm32's `Int` is signed 32-bit and
/// would lose the top half of the range).
fn zuc_count_bytes(count : UInt) -> (Byte, Byte, Byte, Byte) {
  (
    ((count >> 24) & 0xFFU).to_byte(),
    ((count >> 16) & 0xFFU).to_byte(),
    ((count >> 8) & 0xFFU).to_byte(),
    (count & 0xFFU).to_byte(),
  )
}

///|
/// The 128-EEA3 IV (TS 35.222 §3.2): COUNT twice, and BEARER/DIRECTION packed
/// into bytes 4 and 12.
fn zuc_eea3_iv(count : UInt, bearer : Int, direction : Int) -> Bytes {
  let (c0, c1, c2, c3) = zuc_count_bytes(count)
  let bd = (((bearer << 1) | (direction & 1)) << 2).to_byte()
  Bytes::from_array([
    c0,
    c1,
    c2,
    c3,
    bd,
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    c0,
    c1,
    c2,
    c3,
    bd,
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
  ])
}

///|
/// The 128-EIA3 IV (TS 35.223 §3.2): COUNT with DIRECTION folded into its top
/// bit at byte 8, BEARER in bytes 4 and 12, DIRECTION again at byte 14.
fn zuc_eia3_iv(count : UInt, bearer : Int, direction : Int) -> Bytes {
  let (c0, c1, c2, c3) = zuc_count_bytes(count)
  let b = (bearer << 3).to_byte()
  let d7 = ((direction & 1) << 7).to_byte()
  Bytes::from_array([
    c0,
    c1,
    c2,
    c3,
    b,
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    (c0.to_int() ^ d7.to_int()).to_byte(),
    c1,
    c2,
    c3,
    b,
    (0).to_byte(),
    d7,
    (0).to_byte(),
  ])
}

///|
/// Validate the shared parameter contract of both modes. LENGTH is in bits and
/// `data` must hold exactly ceil(nbits/8) bytes.
fn zuc_mode_check(
  what : String,
  key : Bytes,
  bearer : Int,
  direction : Int,
  nbits : Int,
  data : Bytes,
) -> Unit {
  guard key.length() == 16 else { abort(what + ": key must be 16 bytes") }
  guard bearer >= 0 && bearer < 32 else {
    abort(what + ": bearer must be a 5-bit value (0..31)")
  }
  guard direction == 0 || direction == 1 else {
    abort(what + ": direction must be 0 or 1")
  }
  guard nbits >= 0 else { abort(what + ": nbits must be non-negative") }
  guard data.length() == (nbits + 7) / 8 else {
    abort(what + ": data must hold exactly ceil(nbits/8) bytes")
  }
}

///|
/// 128-EEA3 (f8) confidentiality: XOR the message with the ZUC keystream
/// derived from (key, COUNT, BEARER, DIRECTION), masking the output to exactly
/// `nbits` bits (trailing bits of the last byte are zeroed).
///
/// `data` must hold exactly ceil(nbits/8) bytes. Returns a buffer of the same
/// length. Decryption is the same call — `zuc_eea3_decrypt` is provided for
/// readability.
pub fn zuc_eea3_encrypt(
  key : Bytes,
  count : UInt,
  bearer : Int,
  direction : Int,
  nbits : Int,
  data : Bytes,
) -> Bytes {
  zuc_mode_check("zuc_eea3_encrypt", key, bearer, direction, nbits, data)
  let iv = zuc_eea3_iv(count, bearer, direction)
  let nbytes = (nbits + 7) / 8
  let nwords = (nbits + 31) / 32
  let ks = zuc_keystream(key, iv, nwords)
  let out = Array::make(nbytes, (0).to_byte())
  for i in 0..<nbytes {
    out[i] = (data[i].to_int() ^ ks[i].to_int()).to_byte()
  }
  // mask the bits beyond LENGTH in the final byte
  let rem = nbits % 8
  if rem != 0 && nbytes > 0 {
    out[nbytes - 1] = (out[nbytes - 1].to_int() & (0xFF << (8 - rem))).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// 128-EEA3 decryption. Identical to `zuc_eea3_encrypt` (a stream cipher), and
/// equally unauthenticated — verify the MAC-I (128-EIA3) separately.
pub fn zuc_eea3_decrypt(
  key : Bytes,
  count : UInt,
  bearer : Int,
  direction : Int,
  nbits : Int,
  data : Bytes,
) -> Bytes {
  zuc_eea3_encrypt(key, count, bearer, direction, nbits, data)
}

///|
/// One MAC round: consume `n` bits of the big-endian word `m`, shifting the
/// (k0, k1) pair along and XORing k0 into the accumulator wherever a message
/// bit is set. This is the TS 35.223 §4 core loop. Returns the updated
/// (accumulator, k0, k1): after a full 32-bit round k0 has slid into what was
/// k1 and k1 is exhausted, which is exactly how the next word continues.
fn zuc_eia3_round(
  t : UInt64,
  m0 : UInt64,
  n : Int,
  k0 : UInt64,
  k1 : UInt64,
) -> (UInt64, UInt64, UInt64) {
  let mut m = m0
  let mut acc = t
  let mut a = k0
  let mut b = k1
  for _i = 0; _i < n; _i = _i + 1 {
    if (m & 0x80000000UL) != 0UL {
      acc = acc ^ a
    }
    m = (m << 1) & zuc_m32
    a = ((a << 1) | (b >> 31)) & zuc_m32
    b = (b << 1) & zuc_m32
  }
  (acc, a, b)
}

///|
/// Read 4 bytes big-endian at `off`, zero-padding past the end of `data`.
fn zuc_word_at(data : Bytes, off : Int) -> UInt64 {
  let mut w = 0UL
  for i in 0..<4 {
    let v = if off + i < data.length() {
      data[off + i].to_int().to_uint64()
    } else {
      0UL
    }
    w = (w << 8) | v
  }
  w
}

///|
/// 128-EIA3 (f9) integrity: the 32-bit MAC-I over `nbits` bits of `data`,
/// keyed by `key` and the COUNT/BEARER/DIRECTION-derived IV. Big-endian output
/// (4 bytes), matching the network order the RRC/PDCP layers expect.
///
/// `data` must hold exactly ceil(nbits/8) bytes; bits beyond `nbits` are never
/// read.
pub fn zuc_eia3_mac(
  key : Bytes,
  count : UInt,
  bearer : Int,
  direction : Int,
  nbits : Int,
  data : Bytes,
) -> Bytes {
  zuc_mode_check("zuc_eia3_mac", key, bearer, direction, nbits, data)
  let iv = zuc_eia3_iv(count, bearer, direction)
  let st = zuc_init(key, iv)
  let mut acc = 0UL
  let mut k0 = zuc_next_word(st)
  // full 32-bit words
  let nwords = nbits / 32
  for w in 0..<nwords {
    let k1 = zuc_next_word(st)
    let (t, a, _) = zuc_eia3_round(acc, zuc_word_at(data, w * 4), 32, k0, k1)
    acc = t
    k0 = a
  }
  // the remaining 1..31 bits live in the top of the next word
  let rem = nbits % 32
  if rem > 0 {
    let k1 = zuc_next_word(st)
    let (t, a, _) = zuc_eia3_round(
      acc,
      zuc_word_at(data, nwords * 4),
      rem,
      k0,
      k1,
    )
    acc = t
    k0 = a
  }
  // finalisation: T ^= K0, then T ^= the next keystream word
  let mut mac = acc ^ k0
  mac = mac ^ zuc_next_word(st)
  let out = Array::make(4, (0).to_byte())
  out[0] = ((mac >> 24) & 0xFFUL).to_int().to_byte()
  out[1] = ((mac >> 16) & 0xFFUL).to_int().to_byte()
  out[2] = ((mac >> 8) & 0xFFUL).to_int().to_byte()
  out[3] = (mac & 0xFFUL).to_int().to_byte()
  Bytes::from_array(out)
}

///|
/// Verify a 128-EIA3 MAC-I in constant time. Returns false for a wrong-length
/// tag instead of aborting: the tag is peer-supplied.
pub fn zuc_eia3_verify(
  key : Bytes,
  count : UInt,
  bearer : Int,
  direction : Int,
  nbits : Int,
  data : Bytes,
  mac : Bytes,
) -> Bool {
  if mac.length() != 4 {
    return false
  }
  bytes_equal(zuc_eia3_mac(key, count, bearer, direction, nbits, data), mac)
}
