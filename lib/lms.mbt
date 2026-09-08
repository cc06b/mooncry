/// LMS / HSS hash-based signatures (RFC 8554), SHA256 parameter sets.
///
/// STATEFUL signature scheme: each LM-OTS leaf signs at most one
/// message. `lms_sign` consumes and increments the leaf counter `q`
/// and aborts when the tree is exhausted. HSS chains L levels of LMS
/// trees; this implementation uses fixed level keys (the caller must
/// re-key when the bottom level is exhausted — the simplified model
/// of RFC 8554 §6.2 without on-the-fly subtree regeneration).
///
/// Public keys: LMS pk = u32str(type) || u32str(otstype) || I || T[1]
/// (56 bytes); HSS pk = u32str(L) || LMS pk[0] (60 bytes).
/// Signatures: LMS sig = u32str(q) || lmots_sig || u32str(type) ||
/// path[0..h-1]; HSS sig = u32str(L-1) || (sig[i] || pub[i+1])* ||
/// sig[L-1].
///
/// Verified against the RFC 8554 Appendix F test cases plus
/// oracle-generated vectors covering W1/W2/W4/W8, H5/H10/H15,
/// non-zero q, and HSS L=1/2/3 (v0.43.0).

///|
/// LM-OTS parameters: typecode -> (w, p, ls). 0 = invalid.
fn lms_ots_params(t : Int) -> (Int, Int, Int) {
  match t {
    1 => (1, 265, 7)
    2 => (2, 133, 6)
    3 => (4, 67, 4)
    4 => (8, 34, 0)
    _ => (0, 0, 0)
  }
}

///|
/// LMS parameters: typecode -> h (m = 32 always). 0 = invalid.
fn lms_tree_h(t : Int) -> Int {
  match t {
    5 => 5
    6 => 10
    7 => 15
    8 => 20
    9 => 25
    _ => 0
  }
}

///|
fn lms_slice(b : Bytes, off : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[off + i]
  }
  Bytes::from_array(out)
}

///|
fn lms_u32str(x : Int) -> Bytes {
  Bytes::from_array([
    ((x >> 24) & 0xff).to_byte(),
    ((x >> 16) & 0xff).to_byte(),
    ((x >> 8) & 0xff).to_byte(),
    (x & 0xff).to_byte(),
  ])
}

///|
fn lms_u16str(x : Int) -> Bytes {
  Bytes::from_array([((x >> 8) & 0xff).to_byte(), (x & 0xff).to_byte()])
}

///|
fn lms_u8str(x : Int) -> Bytes {
  Bytes::make(1, (x & 0xff).to_byte())
}

///|
fn lms_strtou32(b : Bytes, off : Int) -> Int {
  (b[off].to_int() << 24) |
  (b[off + 1].to_int() << 16) |
  (b[off + 2].to_int() << 8) |
  b[off + 3].to_int()
}

// domain separators

///|
let lms_d_mesc : Int = 0x8181

///|
let lms_d_pblc : Int = 0x8080

///|
let lms_d_leaf : Int = 0x8282

///|
let lms_d_intr : Int = 0x8383

///|
/// coef(S, i, w): the i-th w-bit coefficient of S (RFC 8554 §3.1.3).
fn lms_coef(s : Bytes, i : Int, w : Int) -> Int {
  let mask = (1 << w) - 1
  let sh = 8 - (w * (i % (8 / w)) + w)
  (s[i * w / 8].to_int() >> sh) & mask
}

///|
fn lms_cksm(q : Bytes, w : Int, ls : Int) -> Int {
  let mut sum = 0
  let cnt = 32 * 8 / w
  let mx = (1 << w) - 1
  for i in 0..<cnt {
    sum = sum + mx - lms_coef(q, i, w)
  }
  sum << ls
}

///|
/// Winternitz chain: iterate H(I || u32str(q) || u16str(i) || u8str(j)
/// || tmp) for j in [j0, j1).
/// Fast single-block SHA-256 path for the 55-byte chain hash
/// H(pre22 || byte1 || val32): a pre-padded buffer template, the IV
/// restored per iteration, and one raw process_block call — no
/// per-hash allocations beyond the 32-byte output (v0.44.0 perf).
fn lms_mk_hasher(pre22 : Bytes) -> Sha256Hasher {
  let h = sha256_new()
  for k in 0..<22 {
    h.buffer[k] = pre22[k]
  }
  // padding for a 55-byte message: 0x80, zeros, bit length 440 = 0x1B8
  h.buffer[55] = (128).to_byte()
  for k in 56..<62 {
    h.buffer[k] = b'\x00'
  }
  h.buffer[62] = (1).to_byte()
  h.buffer[63] = (184).to_byte()
  h
}

///|
fn lms_iv_state() -> Array[UInt] {
  let h = sha256_new()
  let iv = Array::make(8, 0U)
  for k in 0..<8 {
    iv[k] = h.state[k]
  }
  iv
}

///|

///|
/// In-place single-block chain step: buffer[22] = b1, buffer[23..55)
/// holds the current value; the digest is written straight back into
/// buffer[23..55). Zero allocations per iteration (v0.44.0 perf).
fn lms_hash1_ip(h : Sha256Hasher, iv : Array[UInt], b1 : Byte) -> Unit {
  h.buffer[22] = b1
  for k in 0..<8 {
    h.state[k] = iv[k]
  }
  sha256_words_from_buffer(h)
  process_block(h.state, h.w)
  for k in 0..<8 {
    let v = h.state[k]
    h.buffer[23 + 4 * k] = ((v >> 24) & 0xFFU).to_byte()
    h.buffer[23 + 4 * k + 1] = ((v >> 16) & 0xFFU).to_byte()
    h.buffer[23 + 4 * k + 2] = ((v >> 8) & 0xFFU).to_byte()
    h.buffer[23 + 4 * k + 3] = (v & 0xFFU).to_byte()
  }
}

///|
fn lms_value_of(h : Sha256Hasher) -> Bytes {
  let out = Array::make(32, b'\x00')
  for k in 0..<32 {
    out[k] = h.buffer[23 + k]
  }
  Bytes::from_array(out)
}

///|
/// OTS_PUB_HASH[q]: the K value of the q-th LM-OTS public key.
fn lms_ots_pub_hash(id : Bytes, q : Int, otstype : Int, seed : Bytes) -> Bytes {
  let w = lms_ots_params(otstype).0
  let p = lms_ots_params(otstype).1
  let iv = lms_iv_state()
  let parts = [id, lms_u32str(q), lms_u16str(lms_d_pblc)]
  // one shared hasher; only the u16str(i) tail of the 22-byte prefix
  // changes per element (rewritten in place)
  let pre = concat_all([id, lms_u32str(q), lms_u16str(0)])
  let h = lms_mk_hasher(pre)
  for i in 0..<p {
    h.buffer[20] = ((i >> 8) & 0xff).to_byte()
    h.buffer[21] = (i & 0xff).to_byte()
    // re-seed: the previous digest overwrote buffer[23..55]
    for k in 0..<32 {
      h.buffer[23 + k] = seed[k]
    }
    lms_hash1_ip(h, iv, (255).to_byte()) // x_q[i]
    for j in 0..<((1 << w) - 1) {
      lms_hash1_ip(h, iv, j.to_byte())
    }
    parts.push(lms_value_of(h))
  }
  sha256(concat_all(parts))
}

///|
/// Full LMS Merkle tree, nodes 1..2^(h+1)-1 (index 0 unused).
fn lms_tree(id : Bytes, seed : Bytes, h : Int, otstype : Int) -> Array[Bytes] {
  let base = 1 << h
  let t = Array::make(2 * base, Bytes::make(0, b'\x00'))
  for q in 0..<base {
    let k = lms_ots_pub_hash(id, q, otstype, seed)
    t[base + q] = sha256(
      concat_all([id, lms_u32str(base + q), lms_u16str(lms_d_leaf), k]),
    )
  }
  for r = base - 1; r >= 1; r = r - 1 {
    t[r] = sha256(
      concat_all([
        id,
        lms_u32str(r),
        lms_u16str(lms_d_intr),
        t[2 * r],
        t[2 * r + 1],
      ]),
    )
  }
  t
}

///|
/// Single-level LMS private key (stateful: q advances per signature).
pub struct LmsPrivateKey {
  lmstype : Int
  otstype : Int
  id16 : Bytes
  seed : Bytes
  mut q : Int
}

///|
/// Generate an LMS key pair (RFC 8554 §5, Appendix A pseudorandom).
/// `lmstype` in {5..9} (H5..H25), `otstype` in {1..4} (W1..W8),
/// `seed` 32 bytes, `id` 16 bytes. Key generation builds the full
/// Merkle tree — cost is 2^h LM-OTS public keys (H10/W8 ≈ 9M hashes).
pub fn lms_keygen(
  lmstype : Int,
  otstype : Int,
  seed : Bytes,
  id : Bytes,
) -> LmsPrivateKey {
  if lms_tree_h(lmstype) == 0 {
    abort("lms_keygen: invalid lmstype (use 5..9)")
  }
  let wp = lms_ots_params(otstype)
  if wp.0 == 0 {
    abort("lms_keygen: invalid otstype (use 1..4)")
  }
  if seed.length() != 32 || id.length() != 16 {
    abort("lms_keygen: seed must be 32 bytes, id 16 bytes")
  }
  LmsPrivateKey::{ lmstype, otstype, id16: id, seed, q: 0, }
}

///|
/// The LMS public key: u32str(type) || u32str(otstype) || I || T[1].
pub fn lms_public_key(sk : LmsPrivateKey) -> Bytes {
  let h = lms_tree_h(sk.lmstype)
  let t = lms_tree(sk.id16, sk.seed, h, sk.otstype)
  concat_all([lms_u32str(sk.lmstype), lms_u32str(sk.otstype), sk.id16, t[1]])
}

///|
/// Sign with the next leaf (sk.q) and advance it. `rand` overrides the
/// n-byte randomizer C (testing); the default derives C deterministically
/// from (SEED, q, message) — unpredictable without the secret seed.
pub fn lms_sign(sk : LmsPrivateKey, msg : Bytes, rand : Bytes?) -> Bytes {
  let h = lms_tree_h(sk.lmstype)
  let base = 1 << h
  if sk.q >= base {
    abort("lms_sign: key exhausted (stateful scheme — re-key)")
  }
  let q = sk.q
  let w = lms_ots_params(sk.otstype).0
  let p = lms_ots_params(sk.otstype).1
  let ls = lms_ots_params(sk.otstype).2
  let c = match rand {
    Some(x) =>
      if x.length() != 32 {
        abort("lms_sign: rand (C) must be 32 bytes")
      } else {
        x
      }
    None => sha256(concat_all([sk.seed, lms_u32str(q), msg, lms_u8str(0xcc)]))
  }
  // LM-OTS signature
  let qhash = sha256(
    concat_all([sk.id16, lms_u32str(q), lms_u16str(lms_d_mesc), c, msg]),
  )
  let qc = concat_all([qhash, lms_u16str(lms_cksm(qhash, w, ls))])
  let parts = [lms_u32str(q), lms_u32str(sk.otstype), c]
  {
    let iv = lms_iv_state()
    let pre = concat_all([sk.id16, lms_u32str(q), lms_u16str(0)])
    let h = lms_mk_hasher(pre)
    for i in 0..<p {
      h.buffer[20] = ((i >> 8) & 0xff).to_byte()
      h.buffer[21] = (i & 0xff).to_byte()
      for k in 0..<32 {
        h.buffer[23 + k] = sk.seed[k]
      }
      lms_hash1_ip(h, iv, (255).to_byte()) // x_q[i]
      let a = lms_coef(qc, i, w)
      for j in 0..<a {
        lms_hash1_ip(h, iv, j.to_byte())
      }
      parts.push(lms_value_of(h))
    }
  }
  // LMS typecode, then the authentication path (§5.4 order)
  parts.push(lms_u32str(sk.lmstype))
  let t = lms_tree(sk.id16, sk.seed, h, sk.otstype)
  let mut r = base + q
  for _ in 0..<h {
    parts.push(t[r ^ 1])
    r = r >> 1
  }
  sk.q = sk.q + 1
  concat_all(parts)
}

///|
/// Verify an LMS signature (RFC 8554 §5.4.2 / Algorithm 6).
pub fn lms_verify(pk : Bytes, msg : Bytes, sig : Bytes) -> Bool {
  if pk.length() != 56 {
    return false
  }
  let lmstype = lms_strtou32(pk, 0)
  let otstype = lms_strtou32(pk, 4)
  let id = lms_slice(pk, 8, 16)
  let t1 = lms_slice(pk, 24, 32)
  let h = lms_tree_h(lmstype)
  if h == 0 || lms_ots_params(otstype).0 == 0 {
    return false
  }
  if sig.length() < 8 {
    return false
  }
  let q = lms_strtou32(sig, 0)
  let w = lms_ots_params(otstype).0
  let p = lms_ots_params(otstype).1
  let ls = lms_ots_params(otstype).2
  let ots_len = 4 + 32 * (p + 1)
  if sig.length() != 4 + ots_len + 4 + 32 * h {
    return false
  }
  let sig_otstype = lms_strtou32(sig, 4)
  if sig_otstype != otstype {
    return false
  }
  let sig_lmstype = lms_strtou32(sig, 4 + ots_len)
  if sig_lmstype != lmstype {
    return false
  }
  if q >= 1 << h {
    return false
  }
  // candidate K from the OTS signature
  let c = lms_slice(sig, 8, 32)
  let qhash = sha256(
    concat_all([id, lms_u32str(q), lms_u16str(lms_d_mesc), c, msg]),
  )
  let qc = concat_all([qhash, lms_u16str(lms_cksm(qhash, w, ls))])
  let zparts = [id, lms_u32str(q), lms_u16str(lms_d_pblc)]
  let yoff = 8 + 32 // after ots type + C
  {
    let iv = lms_iv_state()
    let pre = concat_all([id, lms_u32str(q), lms_u16str(0)])
    let h = lms_mk_hasher(pre)
    for i in 0..<p {
      h.buffer[20] = ((i >> 8) & 0xff).to_byte()
      h.buffer[21] = (i & 0xff).to_byte()
      let a = lms_coef(qc, i, w)
      for k in 0..<32 {
        h.buffer[23 + k] = sig[yoff + 32 * i + k]
      }
      for j in a..<((1 << w) - 1) {
        lms_hash1_ip(h, iv, j.to_byte())
      }
      zparts.push(lms_value_of(h))
    }
  }
  let kc = sha256(concat_all(zparts))
  // walk the authentication path to the root
  let mut r = (1 << h) + q
  let mut node = sha256(
    concat_all([id, lms_u32str(r), lms_u16str(lms_d_leaf), kc]),
  )
  let path_off = 4 + ots_len + 4
  for d in 0..<h {
    let a = lms_slice(sig, path_off + 32 * d, 32)
    r = r >> 1
    // left/right depends on the bit of the original r at level d
    let is_right = ((((1 << h) + q) >> d) & 1) == 1
    let node_parts = if is_right {
      [id, lms_u32str(r), lms_u16str(lms_d_intr), a, node]
    } else {
      [id, lms_u32str(r), lms_u16str(lms_d_intr), node, a]
    }
    node = sha256(concat_all(node_parts))
  }
  bytes_equal(node, t1)
}

// ==================== HSS (multi-level) ====================

///|
/// HSS private key: L level keys, the level public keys, and the
/// inter-level signatures sig[i] = LMS_sign(prv[i], pub[i+1]).
pub struct HssPrivateKey {
  keys : Array[LmsPrivateKey]
  pubs : Array[Bytes]
  sigs : Array[Bytes]
}

///|
/// Generate an HSS key pair. `specs` = L tuples of (lmstype, otstype,
/// seed32, id16), level 0 = top. L >= 1 (L=1 is plain LMS).
pub fn hss_keygen(specs : Array[(Int, Int, Bytes, Bytes)]) -> HssPrivateKey {
  if specs.is_empty() {
    abort("hss_keygen: need at least one level")
  }
  let keys : Array[LmsPrivateKey] = []
  for sp in specs {
    keys.push(lms_keygen(sp.0, sp.1, sp.2, sp.3))
  }
  hss_finalize(keys)
}

///|
/// Key generation with explicit starting leaf counters and randomizers
/// (interop testing; `qs`/`cs` give each level's first q and the C used
/// for its inter-level signature).
pub fn hss_keygen_with(
  specs : Array[(Int, Int, Bytes, Bytes)],
  qs : Array[Int],
  cs : Array[Bytes],
) -> HssPrivateKey {
  if specs.is_empty() ||
    qs.length() != specs.length() ||
    cs.length() != specs.length() {
    abort("hss_keygen_with: length mismatch")
  }
  let keys : Array[LmsPrivateKey] = []
  for i in 0..<specs.length() {
    let sp = specs[i]
    let k = lms_keygen(sp.0, sp.1, sp.2, sp.3)
    k.q = qs[i]
    keys.push(k)
  }
  hss_finalize_with(keys, cs)
}

///|
fn hss_finalize(keys : Array[LmsPrivateKey]) -> HssPrivateKey {
  let n = keys.length()
  let cs : Array[Bytes] = []
  for i in 0..<n {
    let k = keys[i]
    cs.push(sha256(concat_all([k.seed, lms_u32str(k.q), lms_u8str(0xcc)])))
  }
  hss_finalize_with(keys, cs)
}

///|
fn hss_finalize_with(
  keys : Array[LmsPrivateKey],
  cs : Array[Bytes],
) -> HssPrivateKey {
  let n = keys.length()
  let pubs : Array[Bytes] = []
  for k in keys {
    pubs.push(lms_public_key(k))
  }
  let sigs : Array[Bytes] = []
  for i in 0..<(n - 1) {
    sigs.push(lms_sign(keys[i], pubs[i + 1], Some(cs[i])))
  }
  HssPrivateKey::{ keys, pubs, sigs, }
}

///|
/// The HSS public key: u32str(L) || pub[0].
pub fn hss_public_key(sk : HssPrivateKey) -> Bytes {
  concat_all([lms_u32str(sk.keys.length()), sk.pubs[0]])
}

///|
/// Sign with HSS (simplified fixed-level model, RFC 8554 §6.2):
/// u32str(L-1) || sig[0] || pub[1] || ... || sig[L-2] || pub[L-1] ||
/// sig[L-1](message). The bottom level's leaf counter advances.
pub fn hss_sign(sk : HssPrivateKey, msg : Bytes, rand : Bytes?) -> Bytes {
  let n = sk.keys.length()
  let parts = [lms_u32str(n - 1)]
  for i in 0..<(n - 1) {
    parts.push(sk.sigs[i])
    parts.push(sk.pubs[i + 1])
  }
  parts.push(lms_sign(sk.keys[n - 1], msg, rand))
  concat_all(parts)
}

///|
/// Verify an HSS signature (RFC 8554 §6.3).
pub fn hss_verify(pk : Bytes, msg : Bytes, sig : Bytes) -> Bool {
  if pk.length() < 4 {
    return false
  }
  let l = lms_strtou32(pk, 0)
  if l < 1 || pk.length() != 4 + 56 {
    return false
  }
  if sig.length() < 4 {
    return false
  }
  let nspk = lms_strtou32(sig, 0)
  if nspk != l - 1 {
    return false
  }
  let mut off = 4
  let mut pk_cur = lms_slice(pk, 4, 56)
  for _ in 0..<(l - 1) {
    let sig_len = lms_sig_len(pk_cur)
    if sig_len <= 0 || off + sig_len + 56 > sig.length() {
      return false
    }
    let sig_i = lms_slice(sig, off, sig_len)
    off = off + sig_len
    let pk_next = lms_slice(sig, off, 56)
    off = off + 56
    if lms_verify(pk_cur, pk_next, sig_i) == false {
      return false
    }
    pk_cur = pk_next
  }
  let sig_len = lms_sig_len(pk_cur)
  if sig_len <= 0 || off + sig_len != sig.length() {
    return false
  }
  lms_verify(pk_cur, msg, lms_slice(sig, off, sig_len))
}

///|
/// Expected LMS signature length for a public key, or 0 if invalid.
fn lms_sig_len(pk : Bytes) -> Int {
  if pk.length() != 56 {
    return 0
  }
  let lmstype = lms_strtou32(pk, 0)
  let otstype = lms_strtou32(pk, 4)
  let h = lms_tree_h(lmstype)
  let wp = lms_ots_params(otstype)
  if h == 0 || wp.0 == 0 {
    return 0
  }
  4 + 4 + 32 * (wp.1 + 1) + 4 + 32 * h
}
