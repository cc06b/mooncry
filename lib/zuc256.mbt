// ============ ZUC-256 (GM/T 0001.2 / 3GPP TS 35.221 v17+, the 256-bit variant) ============
//
// ZUC-256 keeps ZUC-128's engine — the same 16-cell LFSR over GF(2^31-1), the
// same bit reorganization, the same F function and S-boxes — and changes two
// things:
//
//   * the key loader. A 32-byte key and a 23-byte IV are packed into the cells
//     as four 8/7/8/8-bit fields (K[i] || D[i] || K[j] || K[k], with the IV
//     occupying eight cells and eight 6-bit frame parameters IV17..IV24 ORed
//     into the D positions that leave room for them);
//   * the MAC, which produces 32, 64 or 128 bits of tag instead of 32, by
//     keeping n = macbits/32 accumulators and shifting an n-word key register
//     one bit per message bit.
//
// Because the engine is shared, `ZucState`, `zuc_next_word` and the LFSR/F
// helpers in zuc.mbt are reused unchanged; only the loader and the MAC live
// here. Verified byte-exact against the ZUC-256 draft vectors and a compiled
// reference for both keystreams and all three tag sizes.

///|
/// ZUC-256 D row for a MAC size: row 0 is the keystream (EEA) loader, rows
/// 1..3 select MAC-32/64/128. The rows leave the low bits of the D field free
/// exactly where a 6-bit frame parameter or a nibble of K[31] is ORed in.
fn zuc256_d_row(macbits : Int) -> Int {
  match macbits {
    0 => 0
    32 => 1
    64 => 2
    128 => 3
    _ => abort("zuc256: macbits must be 0 (keystream), 32, 64 or 128")
  }
}

///|
/// Pack one LFSR cell from four fields: an 8-bit high part, the 7-bit D
/// (possibly ORed with frame-parameter bits), and two more 8-bit parts.
fn zuc256_cell(a : UInt64, d : UInt64, c : UInt64, e : UInt64) -> UInt64 {
  (a << 23) | (d << 16) | (c << 8) | e
}

///|
/// Load a 32-byte key and 23-byte IV into the LFSR (the ZUC-256 key schedule).
fn zuc256_load(key : Bytes, iv : Bytes, row : Int) -> Array[UInt64] {
  // eight 6-bit frame parameters, packed into IV[17..22]
  let iv17 = (iv[17].to_int() >> 2).to_uint64()
  let iv18 = (((iv[17].to_int() & 0x3) << 4) | (iv[18].to_int() >> 4)).to_uint64()
  let iv19 = (((iv[18].to_int() & 0xF) << 2) | (iv[19].to_int() >> 6)).to_uint64()
  let iv20 = (iv[19].to_int() & 0x3F).to_uint64()
  let iv21 = (iv[20].to_int() >> 2).to_uint64()
  let iv22 = (((iv[20].to_int() & 0x3) << 4) | (iv[21].to_int() >> 4)).to_uint64()
  let iv23 = (((iv[21].to_int() & 0xF) << 2) | (iv[22].to_int() >> 6)).to_uint64()
  let iv24 = (iv[22].to_int() & 0x3F).to_uint64()
  let k = fn(i : Int) -> UInt64 { key[i].to_int().to_uint64() }
  let v = fn(i : Int) -> UInt64 { iv[i].to_int().to_uint64() }
  let d = fn(i : Int) -> UInt64 { zuc256_d[row * 16 + i].to_int().to_uint64() }
  let l = Array::make(16, 0UL)
  l[0] = zuc256_cell(k(0), d(0), k(21), k(16))
  l[1] = zuc256_cell(k(1), d(1), k(22), k(17))
  l[2] = zuc256_cell(k(2), d(2), k(23), k(18))
  l[3] = zuc256_cell(k(3), d(3), k(24), k(19))
  l[4] = zuc256_cell(k(4), d(4), k(25), k(20))
  l[5] = zuc256_cell(v(0), d(5) | iv17, k(5), k(26))
  l[6] = zuc256_cell(v(1), d(6) | iv18, k(6), k(27))
  l[7] = zuc256_cell(v(10), d(7) | iv19, k(7), v(2))
  l[8] = zuc256_cell(k(8), d(8) | iv20, v(3), v(11))
  l[9] = zuc256_cell(k(9), d(9) | iv21, v(12), v(4))
  l[10] = zuc256_cell(v(5), d(10) | iv22, k(10), k(28))
  l[11] = zuc256_cell(k(11), d(11) | iv23, v(6), v(13))
  l[12] = zuc256_cell(k(12), d(12) | iv24, v(7), v(14))
  l[13] = zuc256_cell(k(13), d(13), v(15), v(8))
  l[14] = zuc256_cell(k(14), d(14) | (k(31) >> 4), v(16), v(9))
  l[15] = zuc256_cell(k(15), d(15) | (k(31) & 0xFUL), k(30), k(29))
  l
}

///|
/// Initialise ZUC-256 for keystream generation (32-byte key, 23-byte IV): the
/// 32 initialisation-mode clocks, the discarded F update and the first work
/// clock — identical to ZUC-128 apart from the loaded state.
pub fn zuc256_init(key : Bytes, iv : Bytes) -> ZucState {
  guard key.length() == 32 && iv.length() == 23 else {
    abort("zuc256_init: key must be 32 bytes and iv 23 bytes")
  }
  zuc256_init_row(key, iv, 0)
}

///|
/// Shared initialisation: load the cells for a given D row and run the 32
/// initialisation rounds.
fn zuc256_init_row(key : Bytes, iv : Bytes, row : Int) -> ZucState {
  let st : ZucState = { lfsr: zuc256_load(key, iv, row), r1: 0UL, r2: 0UL, }
  for _i = 0; _i < 32; _i = _i + 1 {
    let (x0, x1, x2, _) = zuc_br(st)
    let w = zuc_f(st, x0, x1, x2)
    zuc_lfsr_init(st, w >> 1)
  }
  let (_, x1, x2, _) = zuc_br(st)
  zuc_f_update(st, x1, x2)
  zuc_lfsr_work(st)
  st
}

///|
/// `nwords` ZUC-256 keystream words as big-endian bytes (4 * nwords).
pub fn zuc256_keystream(key : Bytes, iv : Bytes, nwords : Int) -> Bytes {
  // see zuc_keystream: the 4-byte word product wraps on a 32-bit Int
  check_count("zuc256_keystream: nwords", nwords, 4)
  let st = zuc256_init(key, iv)
  let out = Array::make(nwords * 4, (0).to_byte())
  zuc_words_into(st, out, nwords)
  Bytes::from_array(out)
}

///|
/// ZUC-256 in raw stream mode: XOR `data` with the keystream. Encryption and
/// decryption are the same call. As with `zuc_xor`, this is the bare cipher,
/// not a 3GPP mode.
pub fn zuc256_xor(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  let n = data.length()
  let st = zuc256_init(key, iv)
  let out = Array::make(n, (0).to_byte())
  zuc_xor_into(st, data, out, n)
  Bytes::from_array(out)
}

///|
/// ZUC-256 MAC body for a 32-bit tag: one accumulator word and a two-word key
/// register (the key word `r0` plus the fresh keystream word `r1` that feeds
/// its tail).
///
/// All three tag sizes keep the accumulator and the key register in locals
/// rather than arrays. The register slides one bit per message bit, so over
/// 8192 bits an array-based register pays a bounds-checked load *and* store per
/// word per bit — several times the cost of the shifts and XORs themselves
/// (measured: 480 µs per 1 KiB with an array register, 122 µs with locals).
/// The conditional XOR is a masked AND rather than a branch: the two measured
/// the same, and this way the round's cost does not depend on the message bits
/// at all. `nwords` full 32-bit words are consumed, then one `rem`-bit
/// word when rem > 0 (bits past `rem` in it are never read: `zuc_word_at`
/// zero-pads and the inner loop stops at `rem`).
fn zuc256_mac32(st : ZucState, data : Bytes, nwords : Int, rem : Int) -> UInt64 {
  let mut t0 = zuc_next_word(st)
  let mut r0 = zuc_next_word(st)
  let rounds = nwords + (if rem > 0 { 1 } else { 0 })
  for w in 0..<rounds {
    let mut r1 = zuc_next_word(st)
    let mut m = zuc_word_at(data, w * 4)
    let nb = if w < nwords { 32 } else { rem }
    for _i in 0..<nb {
      let mask = ((m >> 31) & 1UL) * zuc_m32
      t0 = t0 ^ (r0 & mask)
      r0 = ((r0 << 1) | (r1 >> 31)) & zuc_m32
      r1 = (r1 << 1) & zuc_m32
      m = (m << 1) & zuc_m32
    }
  }
  t0 ^ r0
}

///|
/// ZUC-256 MAC body for a 64-bit tag: two accumulator words and a three-word
/// key register. See `zuc256_mac32` for the shape of the loop.
fn zuc256_mac64(
  st : ZucState,
  data : Bytes,
  nwords : Int,
  rem : Int,
) -> (UInt64, UInt64) {
  let mut t0 = zuc_next_word(st)
  let mut t1 = zuc_next_word(st)
  let mut r0 = zuc_next_word(st)
  let mut r1 = zuc_next_word(st)
  let rounds = nwords + (if rem > 0 { 1 } else { 0 })
  for w in 0..<rounds {
    let mut r2 = zuc_next_word(st)
    let mut m = zuc_word_at(data, w * 4)
    let nb = if w < nwords { 32 } else { rem }
    for _i in 0..<nb {
      let mask = ((m >> 31) & 1UL) * zuc_m32
      t0 = t0 ^ (r0 & mask)
      t1 = t1 ^ (r1 & mask)
      r0 = ((r0 << 1) | (r1 >> 31)) & zuc_m32
      r1 = ((r1 << 1) | (r2 >> 31)) & zuc_m32
      r2 = (r2 << 1) & zuc_m32
      m = (m << 1) & zuc_m32
    }
  }
  (t0 ^ r0, t1 ^ r1)
}

///|
/// ZUC-256 MAC body for a 128-bit tag: four accumulator words and a five-word
/// key register. See `zuc256_mac32` for the shape of the loop.
fn zuc256_mac128(
  st : ZucState,
  data : Bytes,
  nwords : Int,
  rem : Int,
) -> (UInt64, UInt64, UInt64, UInt64) {
  let mut t0 = zuc_next_word(st)
  let mut t1 = zuc_next_word(st)
  let mut t2 = zuc_next_word(st)
  let mut t3 = zuc_next_word(st)
  let mut r0 = zuc_next_word(st)
  let mut r1 = zuc_next_word(st)
  let mut r2 = zuc_next_word(st)
  let mut r3 = zuc_next_word(st)
  let rounds = nwords + (if rem > 0 { 1 } else { 0 })
  for w in 0..<rounds {
    let mut r4 = zuc_next_word(st)
    let mut m = zuc_word_at(data, w * 4)
    let nb = if w < nwords { 32 } else { rem }
    for _i in 0..<nb {
      let mask = ((m >> 31) & 1UL) * zuc_m32
      t0 = t0 ^ (r0 & mask)
      t1 = t1 ^ (r1 & mask)
      t2 = t2 ^ (r2 & mask)
      t3 = t3 ^ (r3 & mask)
      r0 = ((r0 << 1) | (r1 >> 31)) & zuc_m32
      r1 = ((r1 << 1) | (r2 >> 31)) & zuc_m32
      r2 = ((r2 << 1) | (r3 >> 31)) & zuc_m32
      r3 = ((r3 << 1) | (r4 >> 31)) & zuc_m32
      r4 = (r4 << 1) & zuc_m32
      m = (m << 1) & zuc_m32
    }
  }
  (t0 ^ r0, t1 ^ r1, t2 ^ r2, t3 ^ r3)
}

///|
/// ZUC-256 MAC (the 256-bit counterpart of 128-EIA3): a `macbits`-bit tag
/// (32, 64 or 128) over `nbits` bits of `data`, big-endian.
///
/// `data` must hold exactly ceil(nbits/8) bytes; bits beyond `nbits` are never
/// read. The key (32 bytes), IV (23 bytes) and `macbits` are caller-supplied
/// contract, so a violation aborts; the message itself is data, not structure.
///
/// `nbits` sits in between: it is a shape, so a disagreement with the buffer
/// aborts, but in a 3GPP stack LENGTH is peer-derived. Check
/// `data.length() == (nbits + 7) / 8` yourself if the packet could have been
/// truncated, rather than letting a peer trigger the abort (see `zuc_mode_check`
/// for the same caveat on the 128-bit modes).
pub fn zuc256_mac(
  key : Bytes,
  iv : Bytes,
  macbits : Int,
  nbits : Int,
  data : Bytes,
) -> Bytes {
  guard key.length() == 32 && iv.length() == 23 else {
    abort("zuc256_mac: key must be 32 bytes and iv 23 bytes")
  }
  let row = zuc256_d_row(macbits)
  guard row >= 1 else { abort("zuc256_mac: macbits must be 32, 64 or 128") }
  guard nbits >= 0 else { abort("zuc256_mac: nbits must be non-negative") }
  guard data.length() == (nbits + 7) / 8 else {
    abort("zuc256_mac: data must hold exactly ceil(nbits/8) bytes")
  }
  let st = zuc256_init_row(key, iv, row)
  let nwords = nbits / 32
  let rem = nbits % 32
  let out = Array::make(macbits / 8, (0).to_byte())
  match macbits {
    32 => zuc_put_word(out, 0, zuc256_mac32(st, data, nwords, rem))
    64 => {
      let (t0, t1) = zuc256_mac64(st, data, nwords, rem)
      zuc_put_word(out, 0, t0)
      zuc_put_word(out, 4, t1)
    }
    _ => {
      let (t0, t1, t2, t3) = zuc256_mac128(st, data, nwords, rem)
      zuc_put_word(out, 0, t0)
      zuc_put_word(out, 4, t1)
      zuc_put_word(out, 8, t2)
      zuc_put_word(out, 12, t3)
    }
  }
  Bytes::from_array(out)
}

///|
/// Verify a ZUC-256 MAC in constant time. A tag of the wrong length returns
/// false rather than trapping (it is peer-supplied).
pub fn zuc256_mac_verify(
  key : Bytes,
  iv : Bytes,
  macbits : Int,
  nbits : Int,
  data : Bytes,
  mac : Bytes,
) -> Bool {
  if mac.length() != macbits / 8 {
    return false
  }
  bytes_equal(zuc256_mac(key, iv, macbits, nbits, data), mac)
}
