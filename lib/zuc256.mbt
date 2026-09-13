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
  guard nwords >= 0 else {
    abort("zuc256_keystream: nwords must be non-negative")
  }
  let st = zuc256_init(key, iv)
  let out = Array::make(nwords * 4, (0).to_byte())
  for i in 0..<nwords {
    let z = zuc_next_word(st)
    out[i * 4] = ((z >> 24) & 0xFFUL).to_int().to_byte()
    out[i * 4 + 1] = ((z >> 16) & 0xFFUL).to_int().to_byte()
    out[i * 4 + 2] = ((z >> 8) & 0xFFUL).to_int().to_byte()
    out[i * 4 + 3] = (z & 0xFFUL).to_int().to_byte()
  }
  Bytes::from_array(out)
}

///|
/// ZUC-256 in raw stream mode: XOR `data` with the keystream. Encryption and
/// decryption are the same call. As with `zuc_xor`, this is the bare cipher,
/// not a 3GPP mode.
pub fn zuc256_xor(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  let n = data.length()
  let ks = zuc256_keystream(key, iv, (n + 3) / 4)
  let out = Array::make(n, (0).to_byte())
  for i in 0..<n {
    out[i] = (data[i].to_int() ^ ks[i].to_int()).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// One ZUC-256 MAC round over `n` message bits: for every set message bit the
/// whole n-word accumulator is XORed with the n-word key register, and the key
/// register slides left by one bit per message bit with the fresh keystream
/// word K1 feeding its tail.
fn zuc256_mac_round(
  t : Array[UInt64],
  k0 : Array[UInt64],
  m0 : UInt64,
  nbits : Int,
  k1_0 : UInt64,
) -> Unit {
  let n = t.length()
  let mut m = m0
  let mut k1 = k1_0
  for _i = 0; _i < nbits; _i = _i + 1 {
    if (m & 0x80000000UL) != 0UL {
      for j in 0..<n {
        t[j] = t[j] ^ k0[j]
      }
    }
    m = (m << 1) & zuc_m32
    for j = 0; j < n - 1; j = j + 1 {
      k0[j] = ((k0[j] << 1) | (k0[j + 1] >> 31)) & zuc_m32
    }
    k0[n - 1] = ((k0[n - 1] << 1) | (k1 >> 31)) & zuc_m32
    k1 = (k1 << 1) & zuc_m32
  }
}

///|
/// ZUC-256 MAC (the 256-bit counterpart of 128-EIA3): a `macbits`-bit tag
/// (32, 64 or 128) over `nbits` bits of `data`, big-endian.
///
/// `data` must hold exactly ceil(nbits/8) bytes; bits beyond `nbits` are never
/// read. The key (32 bytes), IV (23 bytes) and `macbits` are caller-supplied
/// contract, so a violation aborts; the message itself is data, not structure.
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
  let n = macbits / 32
  let st = zuc256_init_row(key, iv, row)
  let t = Array::make(n, 0UL)
  let k0 = Array::make(n, 0UL)
  // T and K0 are each filled with n keystream words before the message
  for j in 0..<n {
    t[j] = zuc_next_word(st)
  }
  for j in 0..<n {
    k0[j] = zuc_next_word(st)
  }
  let nwords = nbits / 32
  for w in 0..<nwords {
    let k1 = zuc_next_word(st)
    zuc256_mac_round(t, k0, zuc_word_at(data, w * 4), 32, k1)
  }
  let rem = nbits % 32
  if rem > 0 {
    let k1 = zuc_next_word(st)
    zuc256_mac_round(t, k0, zuc_word_at(data, nwords * 4), rem, k1)
  }
  let out = Array::make(macbits / 8, (0).to_byte())
  for j in 0..<n {
    let v = t[j] ^ k0[j]
    out[j * 4] = ((v >> 24) & 0xFFUL).to_int().to_byte()
    out[j * 4 + 1] = ((v >> 16) & 0xFFUL).to_int().to_byte()
    out[j * 4 + 2] = ((v >> 8) & 0xFFUL).to_int().to_byte()
    out[j * 4 + 3] = (v & 0xFFUL).to_int().to_byte()
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
