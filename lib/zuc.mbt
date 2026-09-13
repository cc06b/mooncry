// ==================== ZUC-128 (GM/T 0001.1-2012, 3GPP TS 35.221) ====================
//
// The ZUC stream cipher: a 16-cell linear feedback shift register over
// GF(2^31 - 1), a bit-reorganization stage that lifts four 32-bit words out of
// it, and the nonlinear function F (two S-box layers S0/S1 with the L1/L2
// linear transforms). Keystream words are produced one per clock in work mode.
//
// Every intermediate is held in UInt64 with explicit masks: wasm32 has 32-bit
// `Int`, native64 has 64-bit, and the debug build traps on signed overflow, so
// widening once and masking at each step keeps the three targets bit-identical.
//
// Verified byte-exact against the official vectors (GM/T 0001.1-2012 / 3GPP TS
// 35.221) and against a compiled reference for 1024-word keystreams.

///|
/// ZUC state: the 16 LFSR cells (each a 31-bit value) and the two F-function
/// memory words R1/R2.
pub struct ZucState {
  lfsr : Array[UInt64]
  mut r1 : UInt64
  mut r2 : UInt64
}

///|
let zuc_m31 : UInt64 = 0x7FFFFFFFUL

///|
let zuc_m32 : UInt64 = 0xFFFFFFFFUL

///|
/// 31-bit left rotation.
fn zuc_rot31(x : UInt64, k : Int) -> UInt64 {
  ((x << k) | (x >> (31 - k))) & zuc_m31
}

///|
/// Addition modulo 2^31 - 1 (the LFSR's field): the carry bit folds back in.
/// Both operands are < 2^31, so one fold is exact.
fn zuc_add31(a : UInt64, b : UInt64) -> UInt64 {
  let s = a + b
  (s & zuc_m31) + (s >> 31)
}

///|
/// 32-bit left rotation.
fn zuc_rot32(x : UInt64, k : Int) -> UInt64 {
  ((x << k) | (x >> (32 - k))) & zuc_m32
}

///|
/// L1, used on the first half of F's input.
fn zuc_l1(x : UInt64) -> UInt64 {
  (x ^ zuc_rot32(x, 2) ^ zuc_rot32(x, 10) ^ zuc_rot32(x, 18) ^ zuc_rot32(x, 24)) &
  zuc_m32
}

///|
/// L2, used on the second half.
fn zuc_l2(x : UInt64) -> UInt64 {
  (x ^ zuc_rot32(x, 8) ^ zuc_rot32(x, 14) ^ zuc_rot32(x, 22) ^ zuc_rot32(x, 30)) &
  zuc_m32
}

///|
/// Pack four S-box outputs into one 32-bit word: S0|S1|S0|S1.
fn zuc_sbox_word(v : UInt64) -> UInt64 {
  let b0 = ((v >> 24) & 0xFFUL).to_int()
  let b1 = ((v >> 16) & 0xFFUL).to_int()
  let b2 = ((v >> 8) & 0xFFUL).to_int()
  let b3 = (v & 0xFFUL).to_int()
  (zuc_s0[b0].to_int().to_uint64() << 24) |
  (zuc_s1[b1].to_int().to_uint64() << 16) |
  (zuc_s0[b2].to_int().to_uint64() << 8) |
  zuc_s1[b3].to_int().to_uint64()
}

///|
/// The F function's memory update: consumes X1/X2, rewrites R1/R2.
fn zuc_f_update(st : ZucState, x1 : UInt64, x2 : UInt64) -> Unit {
  let w1 = (st.r1 + x1) & zuc_m32
  let w2 = st.r2 ^ x2
  let u = zuc_l1(((w1 << 16) | (w2 >> 16)) & zuc_m32)
  let v = zuc_l2(((w2 << 16) | (w1 >> 16)) & zuc_m32)
  st.r1 = zuc_sbox_word(u)
  st.r2 = zuc_sbox_word(v)
}

///|
/// Full F: returns (X0 ^ R1) + R2 with the R1/R2 of *this* round, then updates
/// the memory words from X1/X2 (the reference expands to exactly this order).
fn zuc_f(st : ZucState, x0 : UInt64, x1 : UInt64, x2 : UInt64) -> UInt64 {
  let w = ((x0 ^ st.r1) + st.r2) & zuc_m32
  zuc_f_update(st, x1, x2)
  w
}

///|
/// Bit reorganization: pull X0..X3 out of the LFSR (32-bit values assembled from
/// the top 16 bits of one cell and the low 15 bits of another).
fn zuc_br(st : ZucState) -> (UInt64, UInt64, UInt64, UInt64) {
  let l = st.lfsr
  let x0 = (((l[15] & 0x7FFF8000UL) << 1) | (l[14] & 0xFFFFUL)) & zuc_m32
  let x1 = (((l[11] & 0xFFFFUL) << 16) | (l[9] >> 15)) & zuc_m32
  let x2 = (((l[7] & 0xFFFFUL) << 16) | (l[5] >> 15)) & zuc_m32
  let x3 = (((l[2] & 0xFFFFUL) << 16) | (l[0] >> 15)) & zuc_m32
  (x0, x1, x2, x3)
}

///|
/// One LFSR clock in initialisation mode: the feedback word `u` (the top 31
/// bits of F's output) enters the recurrence.
fn zuc_lfsr_init(st : ZucState, u : UInt64) -> Unit {
  let l = st.lfsr
  let mut v = l[0]
  v = zuc_add31(v, zuc_rot31(l[0], 8))
  v = zuc_add31(v, zuc_rot31(l[4], 20))
  v = zuc_add31(v, zuc_rot31(l[10], 21))
  v = zuc_add31(v, zuc_rot31(l[13], 17))
  v = zuc_add31(v, zuc_rot31(l[15], 15))
  v = zuc_add31(v, u)
  for i in 0..<15 {
    l[i] = l[i + 1]
  }
  l[15] = v
}

///|
/// One LFSR clock in work mode. The reference accumulates the five feedback
/// terms in 64 bits before folding twice, so the sum is done the same way here.
fn zuc_lfsr_work(st : ZucState) -> Unit {
  let l = st.lfsr
  let mut a = l[0]
  a = a + (l[0] << 8)
  a = a + (l[4] << 20)
  a = a + (l[10] << 21)
  a = a + (l[13] << 17)
  a = a + (l[15] << 15)
  a = (a & zuc_m31) + (a >> 31)
  let v = (a & zuc_m31) + (a >> 31)
  for i in 0..<15 {
    l[i] = l[i + 1]
  }
  l[15] = v
}

///|
/// Load the key and IV into the LFSR: s[i] = k[i] || D[i] || IV[i], with the
/// 15-bit constant D[i] occupying the middle bits.
fn zuc_load(key : Bytes, iv : Bytes) -> Array[UInt64] {
  let l = Array::make(16, 0UL)
  for i in 0..<16 {
    let k = key[i].to_int().to_uint64()
    let d = zuc_kd[i].to_uint64()
    let v = iv[i].to_int().to_uint64()
    l[i] = (k << 23) | (d << 8) | v
  }
  l
}

///|
/// Initialise ZUC-128 with a 16-byte key and 16-byte IV: 32 initialisation-mode
/// clocks, then the single work-mode clock that discards the first F output.
///
/// Aborts on a wrong-length key/IV — those are caller-side contract violations
/// (both are secret/local), not peer input.
pub fn zuc_init(key : Bytes, iv : Bytes) -> ZucState {
  guard key.length() == 16 && iv.length() == 16 else {
    abort("zuc_init: key and iv must be 16 bytes")
  }
  let st : ZucState = { lfsr: zuc_load(key, iv), r1: 0UL, r2: 0UL, }
  for _i = 0; _i < 32; _i = _i + 1 {
    let (x0, x1, x2, _) = zuc_br(st)
    let w = zuc_f(st, x0, x1, x2)
    zuc_lfsr_init(st, w >> 1)
  }
  // the reference's post-initialisation step: one F memory update whose output
  // is discarded, followed by a work-mode clock
  let (_, x1, x2, _) = zuc_br(st)
  zuc_f_update(st, x1, x2)
  zuc_lfsr_work(st)
  st
}

///|
/// The next keystream word (work mode).
pub fn zuc_next_word(st : ZucState) -> UInt64 {
  let (x0, x1, x2, x3) = zuc_br(st)
  let z = (x3 ^ zuc_f(st, x0, x1, x2)) & zuc_m32
  zuc_lfsr_work(st)
  z
}

///|
/// `nwords` keystream words as a big-endian byte string (4 * nwords bytes).
/// This is the raw ZUC keystream: 128-EEA3 is its XOR against the plaintext,
/// and the words are also what the EIA3 MAC consumes.
pub fn zuc_keystream(key : Bytes, iv : Bytes, nwords : Int) -> Bytes {
  guard nwords >= 0 else { abort("zuc_keystream: nwords must be non-negative") }
  let st = zuc_init(key, iv)
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
/// ZUC in raw stream mode: XOR `data` with the keystream generated from
/// (key, iv). Encryption and decryption are the same operation. The last
/// keystream word is used only as far as the data reaches, so `data` may be any
/// length (no padding, no length restriction).
///
/// This is *not* 128-EEA3: EEA3 builds the IV from COUNT/BEARER/DIRECTION and
/// masks the final partial word to the exact bit length. Use `zuc_eea3_encrypt`
/// for the 3GPP confidentiality algorithm.
pub fn zuc_xor(key : Bytes, iv : Bytes, data : Bytes) -> Bytes {
  let n = data.length()
  let nwords = (n + 3) / 4
  let ks = zuc_keystream(key, iv, nwords)
  let out = Array::make(n, (0).to_byte())
  for i in 0..<n {
    out[i] = (data[i].to_int() ^ ks[i].to_int()).to_byte()
  }
  Bytes::from_array(out)
}
