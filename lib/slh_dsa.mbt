// SLH-DSA (SPHINCS+, FIPS 205) — stateless hash-based signatures.
// All 12 approved parameter sets (SHA2/SHAKE × 128s/128f/192s/192f/256s/256f).
// Ported from the FIPS 205 text; verified against the official NIST ACVP
// vector sets (keyGen, sigGen deterministic pure/preHash/internal,
// full sigVer suite). v0.31.0.

pub enum SlhKind {
  Sha2
  Shake
}

///|
/// SLH-DSA parameter set (FIPS 205 Table 2). `n` is the hash output size,
/// `h` the hypertree height, `d` the number of layers, `hp` the XMSS tree
/// height, `a` the FORS subtree height, `k` the number of FORS subtrees
/// and `m` the message-digest length.
struct SlhParams {
  n : Int
  h : Int
  d : Int
  hp : Int
  a : Int
  k : Int
  m : Int
  kind : SlhKind
  cat : Int  // security category: 1, 3 or 5 (SHA2 only)
}

///| SLH-DSA-SHA2-128s parameter set (FIPS 205).
pub let slh_sha2_128s : SlhParams = {
  n: 16,
  h: 63,
  d: 7,
  hp: 9,
  a: 12,
  k: 14,
  m: 30,
  kind: Sha2,
  cat: 1,
}

///| SLH-DSA-SHA2-128f parameter set.
pub let slh_sha2_128f : SlhParams = {
  n: 16,
  h: 66,
  d: 22,
  hp: 3,
  a: 6,
  k: 33,
  m: 34,
  kind: Sha2,
  cat: 1,
}

///| SLH-DSA-SHA2-192s parameter set.
pub let slh_sha2_192s : SlhParams = {
  n: 24,
  h: 63,
  d: 7,
  hp: 9,
  a: 14,
  k: 17,
  m: 39,
  kind: Sha2,
  cat: 3,
}

///| SLH-DSA-SHA2-192f parameter set.
pub let slh_sha2_192f : SlhParams = {
  n: 24,
  h: 66,
  d: 22,
  hp: 3,
  a: 8,
  k: 33,
  m: 42,
  kind: Sha2,
  cat: 3,
}

///| SLH-DSA-SHA2-256s parameter set.
pub let slh_sha2_256s : SlhParams = {
  n: 32,
  h: 64,
  d: 8,
  hp: 8,
  a: 14,
  k: 22,
  m: 47,
  kind: Sha2,
  cat: 5,
}

///| SLH-DSA-SHA2-256f parameter set.
pub let slh_sha2_256f : SlhParams = {
  n: 32,
  h: 68,
  d: 17,
  hp: 4,
  a: 9,
  k: 35,
  m: 49,
  kind: Sha2,
  cat: 5,
}

///| SLH-DSA-SHAKE-128s parameter set.
pub let slh_shake_128s : SlhParams = {
  n: 16,
  h: 63,
  d: 7,
  hp: 9,
  a: 12,
  k: 14,
  m: 30,
  kind: Shake,
  cat: 1,
}

///| SLH-DSA-SHAKE-128f parameter set.
pub let slh_shake_128f : SlhParams = {
  n: 16,
  h: 66,
  d: 22,
  hp: 3,
  a: 6,
  k: 33,
  m: 34,
  kind: Shake,
  cat: 1,
}

///| SLH-DSA-SHAKE-192s parameter set.
pub let slh_shake_192s : SlhParams = {
  n: 24,
  h: 63,
  d: 7,
  hp: 9,
  a: 14,
  k: 17,
  m: 39,
  kind: Shake,
  cat: 3,
}

///| SLH-DSA-SHAKE-192f parameter set.
pub let slh_shake_192f : SlhParams = {
  n: 24,
  h: 66,
  d: 22,
  hp: 3,
  a: 8,
  k: 33,
  m: 42,
  kind: Shake,
  cat: 3,
}

///| SLH-DSA-SHAKE-256s parameter set.
pub let slh_shake_256s : SlhParams = {
  n: 32,
  h: 64,
  d: 8,
  hp: 8,
  a: 14,
  k: 22,
  m: 47,
  kind: Shake,
  cat: 5,
}

///| SLH-DSA-SHAKE-256f parameter set.
pub let slh_shake_256f : SlhParams = {
  n: 32,
  h: 68,
  d: 17,
  hp: 4,
  a: 9,
  k: 35,
  m: 49,
  kind: Shake,
  cat: 5,
}

// ==================== byte helpers ====================

fn slh_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  for i in 0..<len {
    out[i] = b[start + i]
  }
  Bytes::from_array(out)
}

fn slh_int_to_bytes(v : Int64, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  let mut x = v
  let mut i = len - 1
  while i >= 0 {
    out[i] = (x & 0xFFL).to_int().to_byte()
    x = x >> 8
    i = i - 1
  }
  Bytes::from_array(out)
}

fn slh_bytes_to_int(b : Bytes, start : Int, len : Int) -> UInt64 {
  let mut t = 0UL
  for i in 0..<len {
    t = (t << 8) + (b[start + i].to_int() & 0xFF).to_uint64()
  }
  t
}

// ==================== ADRS (32-byte address, FIPS 205 §4) ====================
// layout: layer word @0..3 (byte 3), tree @8..15, type word @16..19 (byte
// 19), keypair @20..23, chain/height @24..27, hash/index @28..31.

fn adrs_new() -> Array[Byte] {
  Array::make(32, b'\x00')
}

fn adrs_copy(a : Array[Byte]) -> Array[Byte] {
  let c = Array::make(32, b'\x00')
  for i in 0..<32 {
    c[i] = a[i]
  }
  c
}

fn adrs_put_u32(a : Array[Byte], off : Int, v : Int) -> Unit {
  a[off] = ((v >> 24) & 0xFF).to_byte()
  a[off + 1] = ((v >> 16) & 0xFF).to_byte()
  a[off + 2] = ((v >> 8) & 0xFF).to_byte()
  a[off + 3] = (v & 0xFF).to_byte()
}

fn adrs_get_u32(a : Array[Byte], off : Int) -> Int {
  (a[off].to_int() << 24) +
  (a[off + 1].to_int() << 16) +
  (a[off + 2].to_int() << 8) +
  a[off + 3].to_int()
}

fn adrs_set_layer(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 0, x)
}

fn adrs_set_tree(a : Array[Byte], x : UInt64) -> Unit {
  for i in 0..<8 {
    a[8 + i] = ((x >> ((7 - i) * 8)) & 0xFFUL).to_int().to_byte()
  }
}

fn adrs_set_type_and_clear(a : Array[Byte], t : Int) -> Unit {
  adrs_put_u32(a, 16, t)
  for i in 20..<32 {
    a[i] = b'\x00'
  }
}

fn adrs_set_keypair(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 20, x)
}

fn adrs_get_keypair(a : Array[Byte]) -> Int {
  adrs_get_u32(a, 20)
}

fn adrs_set_chain(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 24, x)
}

fn adrs_set_height(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 24, x)
}

fn adrs_set_hash(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 28, x)
}

fn adrs_set_index(a : Array[Byte], x : Int) -> Unit {
  adrs_put_u32(a, 28, x)
}

// Compressed 22-byte address for the SHA2 instance:
// ADRS[3] || ADRS[8..16] || ADRS[19..32].
fn adrs_compressed(a : Array[Byte]) -> Bytes {
  let out = Array::make(22, b'\x00')
  out[0] = a[3]
  for i in 0..<8 {
    out[1 + i] = a[8 + i]
  }
  for i in 0..<13 {
    out[9 + i] = a[19 + i]
  }
  Bytes::from_array(out)
}

// ADRS type constants
let slh_wots_hash = 0
let slh_wots_pk = 1
let slh_tree = 2
let slh_fors_tree = 3
let slh_fors_roots = 4
let slh_wots_prf = 5
let slh_fors_prf = 6

// ==================== hash instantiations ====================

fn mgf1_sha256(seed : Bytes, len : Int) -> Bytes {
  let parts : Array[Bytes] = []
  let mut need = len
  let mut c = 0
  while need > 0 {
    let blk = sha256(concat_bytes(seed, slh_int_to_bytes(c.to_int64(), 4)))
    if need >= 32 {
      parts.push(blk)
      need = need - 32
    } else {
      parts.push(slh_slice(blk, 0, need))
      need = 0
    }
    c = c + 1
  }
  concat_all(parts)
}

fn mgf1_sha512(seed : Bytes, len : Int) -> Bytes {
  let parts : Array[Bytes] = []
  let mut need = len
  let mut c = 0
  while need > 0 {
    let blk = sha512(concat_bytes(seed, slh_int_to_bytes(c.to_int64(), 4)))
    if need >= 64 {
      parts.push(blk)
      need = need - 64
    } else {
      parts.push(slh_slice(blk, 0, need))
      need = 0
    }
    c = c + 1
  }
  concat_all(parts)
}

///| H_msg(R, PK.seed, PK.root, M, ctx): the message digest (m bytes).
fn slh_h_msg(
  p : SlhParams,
  pk_seed : Bytes,
  pk_root : Bytes,
  r : Bytes,
  msg : Bytes,
  ctx : Option[Bytes],
) -> Bytes {
  let ctxb : Bytes = match ctx {
    Some(c) => concat_all([Bytes::make(1, b'\x00'), Bytes::make(1, c.length().to_byte()), c])
    None => Bytes::make(0, b'\x00')
  }
  let inner = concat_all([r, pk_seed, pk_root, ctxb, msg])
  match p.kind {
    Shake => shake_256(inner, p.m)
    Sha2 =>
      if p.cat == 1 {
        let dg = sha256(inner)
        mgf1_sha256(concat_all([r, pk_seed, dg]), p.m)
      } else {
        let dg = sha512(inner)
        mgf1_sha512(concat_all([r, pk_seed, dg]), p.m)
      }
  }
}

///| PRF_msg(SK.prf, opt_rand, M, ctx): the n-byte randomizer R.
fn slh_prf_msg(
  p : SlhParams,
  sk_prf : Bytes,
  opt_rand : Bytes,
  msg : Bytes,
  ctx : Option[Bytes],
) -> Bytes {
  let ctxb : Bytes = match ctx {
    Some(c) => concat_all([Bytes::make(1, b'\x00'), Bytes::make(1, c.length().to_byte()), c])
    None => Bytes::make(0, b'\x00')
  }
  let inner = concat_all([opt_rand, ctxb, msg])
  match p.kind {
    Shake => shake_256(concat_bytes(sk_prf, inner), p.n)
    Sha2 =>
      if p.cat == 1 {
        slh_slice(hmac_sha256(sk_prf, inner), 0, p.n)
      } else {
        slh_slice(hmac_sha512(sk_prf, inner), 0, p.n)
      }
  }
}

// SHA2 keyed-hash core: SHA-256/512(PK.seed || zero-pad || ADRSc || data)
fn slh_sha2_core(
  p : SlhParams,
  pk_seed : Bytes,
  adrs : Array[Byte],
  data : Bytes,
  out_len : Int,
  use512 : Bool,
) -> Bytes {
  let pad_len = (if use512 { 128 } else { 64 }) - p.n
  let input = concat_all([pk_seed, Bytes::make(pad_len, b'\x00'), adrs_compressed(adrs), data])
  if use512 {
    slh_slice(sha512(input), 0, out_len)
  } else {
    slh_slice(sha256(input), 0, out_len)
  }
}

///| PRF(PK.seed, SK.seed, ADRS): n-byte secret value.
fn slh_prf(p : SlhParams, pk_seed : Bytes, sk_seed : Bytes, adrs : Array[Byte]) -> Bytes {
  match p.kind {
    Shake => shake_256(concat_all([pk_seed, Bytes::from_array(adrs), sk_seed]), p.n)
    Sha2 => slh_sha2_core(p, pk_seed, adrs, sk_seed, p.n, false)
  }
}

///| F(PK.seed, ADRS, M1): n-byte hash of one n-byte block.
fn slh_f(p : SlhParams, pk_seed : Bytes, adrs : Array[Byte], m1 : Bytes) -> Bytes {
  match p.kind {
    Shake => shake_256(concat_all([pk_seed, Bytes::from_array(adrs), m1]), p.n)
    Sha2 => slh_sha2_core(p, pk_seed, adrs, m1, p.n, false)
  }
}

///| H(PK.seed, ADRS, M2): n-byte hash of two n-byte blocks.
fn slh_h(
  p : SlhParams,
  pk_seed : Bytes,
  adrs : Array[Byte],
  m1 : Bytes,
  m2 : Bytes,
) -> Bytes {
  match p.kind {
    Shake => shake_256(concat_all([pk_seed, Bytes::from_array(adrs), m1, m2]), p.n)
    Sha2 =>
      if p.cat == 1 {
        slh_sha2_core(p, pk_seed, adrs, concat_bytes(m1, m2), p.n, false)
      } else {
        slh_sha2_core(p, pk_seed, adrs, concat_bytes(m1, m2), p.n, true)
      }
  }
}

///| T_l(PK.seed, ADRS, M_l): n-byte hash of l n-byte blocks.
fn slh_t_l(
  p : SlhParams,
  pk_seed : Bytes,
  adrs : Array[Byte],
  ml : Bytes,
) -> Bytes {
  match p.kind {
    Shake => shake_256(concat_all([pk_seed, Bytes::from_array(adrs), ml]), p.n)
    Sha2 =>
      if p.cat == 1 {
        slh_sha2_core(p, pk_seed, adrs, ml, p.n, false)
      } else {
        slh_sha2_core(p, pk_seed, adrs, ml, p.n, true)
      }
  }
}

// ==================== WOTS+ ====================

fn slh_len1(p : SlhParams) -> Int {
  (8 * p.n + 3) / 4
}

fn slh_wlen(p : SlhParams) -> Int {
  slh_len1(p) + 3
}

///| base_2b(X, b, out_len): big-endian bit reader.
fn slh_base_2b(x : Bytes, b : Int, out_len : Int) -> Array[Int] {
  let v = Array::make(out_len, 0)
  let mask = (1 << b) - 1
  let mut t = 0
  let mut l = 0
  let mut j = 0
  for i in 0..<out_len {
    while l < b {
      t = (t << 8) + x[j].to_int()
      j = j + 1
      l = l + 8
    }
    l = l - b
    v[i] = (t >> l) & mask
  }
  v
}

///| Message digits + checksum (Algorithms 7/8 shared part).
fn slh_wots_csum(p : SlhParams, msg : Bytes) -> Array[Int] {
  let l1 = slh_len1(p)
  let l2 = 3
  let vm = slh_base_2b(msg, 4, l1)
  let mut csum = 0
  for i in 0..<l1 {
    csum = csum + (15 - vm[i])
  }
  let shift = (8 - ((l2 * 4) % 8)) % 8
  csum = csum << shift
  let nbytes = (l2 * 4 + 7) / 8
  let cb = slh_int_to_bytes(csum.to_int64(), nbytes)
  let v2 = slh_base_2b(cb, 4, l2)
  for i in 0..<l2 {
    vm.push(v2[i])
  }
  vm
}

///| chain(X, i, s): iterate F from hash address i for s steps.
fn slh_chain(
  p : SlhParams,
  pk_seed : Bytes,
  x : Bytes,
  i : Int,
  s : Int,
  adrs : Array[Byte],
) -> Bytes {
  if s == 0 {
    return x
  }
  adrs_set_hash(adrs, i)
  let mut v = slh_f(p, pk_seed, adrs, x)
  let mut j = 1
  while j < s {
    adrs_set_hash(adrs, i + j)
    v = slh_f(p, pk_seed, adrs, v)
    j = j + 1
  }
  v
}

///| WOTS+ signature (Algorithm 7).
fn slh_wots_sign(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  msg : Bytes,
  adrs : Array[Byte],
) -> Bytes {
  let vm = slh_wots_csum(p, msg)
  let sk_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(sk_adrs, slh_wots_prf)
  adrs_set_keypair(sk_adrs, adrs_get_keypair(adrs))
  let len = slh_wlen(p)
  let parts : Array[Bytes] = []
  for i in 0..<len {
    adrs_set_chain(sk_adrs, i)
    adrs_set_hash(sk_adrs, 0)
    let sk = slh_prf(p, pk_seed, sk_seed, sk_adrs)
    adrs_set_chain(adrs, i)
    parts.push(slh_chain(p, pk_seed, sk, 0, vm[i], adrs))
  }
  concat_all(parts)
}

///| WOTS+ public key from signature (Algorithm 8).
fn slh_wots_pk_from_sig(
  p : SlhParams,
  pk_seed : Bytes,
  sig : Bytes,
  msg : Bytes,
  adrs : Array[Byte],
) -> Bytes {
  let vm = slh_wots_csum(p, msg)
  let len = slh_wlen(p)
  let parts : Array[Bytes] = []
  for i in 0..<len {
    adrs_set_chain(adrs, i)
    let s = slh_slice(sig, i * p.n, p.n)
    parts.push(slh_chain(p, pk_seed, s, vm[i], 15 - vm[i], adrs))
  }
  let pk_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(pk_adrs, slh_wots_pk)
  adrs_set_keypair(pk_adrs, adrs_get_keypair(adrs))
  slh_t_l(p, pk_seed, pk_adrs, concat_all(parts))
}

// ==================== XMSS ====================

///| xmss_node(i, z): root of the subtree of 2^z leaves starting at leaf
/// i·2^z (Algorithm 9, iterative with a stack).
fn slh_xmss_node(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  i : Int,
  z : Int,
  adrs : Array[Byte],
) -> Bytes {
  let len = slh_wlen(p)
  let stack : Array[Bytes] = []
  let mut idx = i << z
  for j in 0..<(1 << z) {
    // WOTS+ public key of leaf idx (Algorithm 6)
    let pk_parts : Array[Bytes] = []
    let w1 = 15
    let sk_adrs = adrs_copy(adrs)
    adrs_set_type_and_clear(sk_adrs, slh_wots_prf)
    adrs_set_keypair(sk_adrs, idx)
    for c in 0..<len {
      adrs_set_chain(sk_adrs, c)
      adrs_set_hash(sk_adrs, 0)
      let sk = slh_prf(p, pk_seed, sk_seed, sk_adrs)
      let h_adrs = adrs_copy(adrs)
      adrs_set_type_and_clear(h_adrs, slh_wots_hash)
      adrs_set_keypair(h_adrs, idx)
      adrs_set_chain(h_adrs, c)
      pk_parts.push(slh_chain(p, pk_seed, sk, 0, w1, h_adrs))
    }
    let pk_adrs = adrs_copy(adrs)
    adrs_set_type_and_clear(pk_adrs, slh_wots_pk)
    adrs_set_keypair(pk_adrs, idx)
    stack.push(slh_t_l(p, pk_seed, pk_adrs, concat_all(pk_parts)))
    // fold completed subtrees
    let mut k = 0
    while ((j >> k) & 1) == 1 {
      let right = stack.pop().unwrap()
      let left = stack.pop().unwrap()
      let t_adrs = adrs_copy(adrs)
      adrs_set_type_and_clear(t_adrs, slh_tree)
      adrs_set_height(t_adrs, k + 1)
      adrs_set_index(t_adrs, idx >> (k + 1))
      stack.push(slh_h(p, pk_seed, t_adrs, left, right))
      k = k + 1
    }
    idx = idx + 1
  }
  stack[0]
}

///| xmss_sign(M, idx) (Algorithm 10): WOTS+ signature || AUTH path.
fn slh_xmss_sign(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  msg : Bytes,
  idx : Int,
  adrs : Array[Byte],
) -> Bytes {
  let auth : Array[Bytes] = []
  for j in 0..<p.hp {
    let k = ((idx >> j) ^ 1)
    let a2 = adrs_copy(adrs)
    adrs_set_type_and_clear(a2, slh_tree)
    auth.push(slh_xmss_node(p, pk_seed, sk_seed, k, j, a2))
  }
  let w_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(w_adrs, slh_wots_hash)
  adrs_set_keypair(w_adrs, idx)
  concat_bytes(slh_wots_sign(p, pk_seed, sk_seed, msg, w_adrs), concat_all(auth))
}

///| xmss_pkFromSig(idx, SIG, M) (Algorithm 11).
fn slh_xmss_pk_from_sig(
  p : SlhParams,
  pk_seed : Bytes,
  idx : Int,
  sig : Bytes,
  msg : Bytes,
  adrs : Array[Byte],
) -> Bytes {
  let w_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(w_adrs, slh_wots_hash)
  adrs_set_keypair(w_adrs, idx)
  let mut node = slh_wots_pk_from_sig(
    p,
    pk_seed,
    slh_slice(sig, 0, slh_wlen(p) * p.n),
    msg,
    w_adrs,
  )
  let auth_off = slh_wlen(p) * p.n
  let t_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(t_adrs, slh_tree)
  for k in 0..<p.hp {
    adrs_set_height(t_adrs, k + 1)
    adrs_set_index(t_adrs, idx >> (k + 1))
    let a = slh_slice(sig, auth_off + k * p.n, p.n)
    node = if ((idx >> k) & 1) == 0 {
      slh_h(p, pk_seed, t_adrs, node, a)
    } else {
      slh_h(p, pk_seed, t_adrs, a, node)
    }
  }
  node
}

// ==================== hypertree ====================

fn slh_ht_sign(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  msg : Bytes,
  i_tree : UInt64,
  i_leaf : Int,
) -> Bytes {
  let adrs = adrs_new()
  adrs_set_tree(adrs, i_tree)
  let mut sig = slh_xmss_sign(p, pk_seed, sk_seed, msg, i_leaf, adrs)
  let mut m = msg
  let st = (slh_wlen(p) + p.hp) * p.n
  let mut layer = 1
  let mut tree = i_tree
  let mut leaf = i_leaf
  let mut cur_adrs = adrs
  while layer < p.d {
    m = slh_xmss_pk_from_sig(
      p,
      pk_seed,
      leaf,
      slh_slice(sig, (layer - 1) * st, st),
      m,
      cur_adrs,
    )
    leaf = (tree & ((1UL << p.hp) - 1UL)).to_int()
    tree = tree >> p.hp
    cur_adrs = adrs_new()
    adrs_set_layer(cur_adrs, layer)
    adrs_set_tree(cur_adrs, tree)
    sig = concat_bytes(sig, slh_xmss_sign(p, pk_seed, sk_seed, m, leaf, cur_adrs))
    layer = layer + 1
  }
  sig
}

fn slh_ht_verify(
  p : SlhParams,
  pk_seed : Bytes,
  pk_root : Bytes,
  msg : Bytes,
  sig_ht : Bytes,
  i_tree : UInt64,
  i_leaf : Int,
) -> Bool {
  let adrs = adrs_new()
  adrs_set_tree(adrs, i_tree)
  let st = (slh_wlen(p) + p.hp) * p.n
  let mut node = slh_xmss_pk_from_sig(
    p,
    pk_seed,
    i_leaf,
    slh_slice(sig_ht, 0, st),
    msg,
    adrs,
  )
  let mut layer = 1
  let mut tree = i_tree
  let mut leaf = i_leaf
  while layer < p.d {
    leaf = (tree & ((1UL << p.hp) - 1UL)).to_int()
    tree = tree >> p.hp
    let adrs2 = adrs_new()
    adrs_set_layer(adrs2, layer)
    adrs_set_tree(adrs2, tree)
    node = slh_xmss_pk_from_sig(
      p,
      pk_seed,
      leaf,
      slh_slice(sig_ht, layer * st, st),
      node,
      adrs2,
    )
    layer = layer + 1
  }
  node == pk_root
}

// ==================== FORS ====================

fn slh_fors_skgen(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  adrs : Array[Byte],
  idx : Int,
) -> Bytes {
  let sk_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(sk_adrs, slh_fors_prf)
  adrs_set_keypair(sk_adrs, adrs_get_keypair(adrs))
  adrs_set_height(sk_adrs, 0)
  adrs_set_index(sk_adrs, idx)
  slh_prf(p, pk_seed, sk_seed, sk_adrs)
}

///| fors_node(i, z): root of the FORS subtree (Algorithm 15, iterative).
fn slh_fors_node(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  i : Int,
  z : Int,
  adrs : Array[Byte],
) -> Bytes {
  let stack : Array[Bytes] = []
  let mut idx = i << z
  for j in 0..<(1 << z) {
    let l_adrs = adrs_copy(adrs)
    adrs_set_height(l_adrs, 0)
    adrs_set_index(l_adrs, idx)
    let sk = slh_fors_skgen(p, pk_seed, sk_seed, adrs, idx)
    stack.push(slh_f(p, pk_seed, l_adrs, sk))
    let mut k = 0
    while ((j >> k) & 1) == 1 {
      let right = stack.pop().unwrap()
      let left = stack.pop().unwrap()
      let t_adrs = adrs_copy(adrs)
      adrs_set_height(t_adrs, k + 1)
      adrs_set_index(t_adrs, idx >> (k + 1))
      stack.push(slh_h(p, pk_seed, t_adrs, left, right))
      k = k + 1
    }
    idx = idx + 1
  }
  stack[0]
}

///| fors_sign(md) (Algorithm 16).
fn slh_fors_sign(
  p : SlhParams,
  pk_seed : Bytes,
  sk_seed : Bytes,
  md : Bytes,
  adrs : Array[Byte],
) -> Bytes {
  let vi = slh_base_2b(md, p.a, p.k)
  let parts : Array[Bytes] = []
  for i in 0..<p.k {
    let leaf = (i << p.a) + vi[i]
    parts.push(slh_fors_skgen(p, pk_seed, sk_seed, adrs, leaf))
    for j in 0..<p.a {
      let s = (vi[i] >> j) ^ 1
      let a2 = adrs_copy(adrs)
      parts.push(slh_fors_node(p, pk_seed, sk_seed, (i << (p.a - j)) + s, j, a2))
    }
  }
  concat_all(parts)
}

///| fors_pkFromSig(SIG, md) (Algorithm 17).
fn slh_fors_pk_from_sig(
  p : SlhParams,
  pk_seed : Bytes,
  sig_fors : Bytes,
  md : Bytes,
  adrs : Array[Byte],
) -> Bytes {
  let vi = slh_base_2b(md, p.a, p.k)
  let roots : Array[Bytes] = []
  let mut off = 0
  for i in 0..<p.k {
    let idx = (i << p.a) + vi[i]
    let a2 = adrs_copy(adrs)
    adrs_set_height(a2, 0)
    adrs_set_index(a2, idx)
    let mut node = slh_f(p, pk_seed, a2, slh_slice(sig_fors, off, p.n))
    off = off + p.n
    for j in 0..<p.a {
      adrs_set_height(a2, j + 1)
      adrs_set_index(a2, idx >> (j + 1))
      let a = slh_slice(sig_fors, off, p.n)
      off = off + p.n
      node = if ((vi[i] >> j) & 1) == 0 {
        slh_h(p, pk_seed, a2, node, a)
      } else {
        slh_h(p, pk_seed, a2, a, node)
      }
    }
    roots.push(node)
  }
  let r_adrs = adrs_copy(adrs)
  adrs_set_type_and_clear(r_adrs, slh_fors_roots)
  adrs_set_keypair(r_adrs, adrs_get_keypair(adrs))
  slh_t_l(p, pk_seed, r_adrs, concat_all(roots))
}

// ==================== top level ====================

fn slh_keygen_internal(
  p : SlhParams,
  sk_seed : Bytes,
  sk_prf : Bytes,
  pk_seed : Bytes,
) -> (Bytes, Bytes) {
  let adrs = adrs_new()
  adrs_set_layer(adrs, p.d - 1)
  let pk_root = slh_xmss_node(p, pk_seed, sk_seed, 0, p.hp, adrs)
  (concat_bytes(pk_seed, pk_root), concat_all([sk_seed, sk_prf, pk_seed, pk_root]))
}

fn slh_split_digest(
  p : SlhParams,
  digest : Bytes,
) -> (Bytes, UInt64, Int) {
  let md_sz = (p.k * p.a + 7) / 8
  let tree_sz = (p.h - p.hp + 7) / 8
  let md = slh_slice(digest, 0, md_sz)
  let i_tree_raw = slh_bytes_to_int(digest, md_sz, tree_sz)
  let i_tree = if p.h - p.hp == 64 {
    i_tree_raw
  } else {
    i_tree_raw & ((1UL << (p.h - p.hp)) - 1UL)
  }
  let i_leaf = (slh_bytes_to_int(digest, md_sz + tree_sz, p.m - md_sz - tree_sz) &
    ((1UL << p.hp) - 1UL)).to_int()
  (md, i_tree, i_leaf)
}

fn slh_sign_internal(
  p : SlhParams,
  sk : Bytes,
  mpr : Bytes,
  opt_rand : Option[Bytes],
  ctx : Option[Bytes],
) -> Bytes {
  let n = p.n
  let sk_seed = slh_slice(sk, 0, n)
  let sk_prf = slh_slice(sk, n, n)
  let pk_seed = slh_slice(sk, 2 * n, n)
  let pk_root = slh_slice(sk, 3 * n, n)
  let ornd : Bytes = match opt_rand {
    Some(x) => x
    None => pk_seed
  }
  let r = slh_prf_msg(p, sk_prf, ornd, mpr, ctx)
  let digest = slh_h_msg(p, pk_seed, pk_root, r, mpr, ctx)
  let (md, i_tree, i_leaf) = slh_split_digest(p, digest)
  let adrs = adrs_new()
  adrs_set_tree(adrs, i_tree)
  adrs_set_type_and_clear(adrs, slh_fors_tree)
  adrs_set_keypair(adrs, i_leaf)
  let sig_fors = slh_fors_sign(p, pk_seed, sk_seed, md, adrs)
  let pk_fors = slh_fors_pk_from_sig(p, pk_seed, sig_fors, md, adrs)
  let sig_ht = slh_ht_sign(p, pk_seed, sk_seed, pk_fors, i_tree, i_leaf)
  concat_all([r, sig_fors, sig_ht])
}

fn slh_verify_internal(
  p : SlhParams,
  pk : Bytes,
  mpr : Bytes,
  sig : Bytes,
  ctx : Option[Bytes],
) -> Bool {
  let n = p.n
  let sig_sz = (1 + p.k * (1 + p.a) + p.h + p.d * slh_wlen(p)) * n
  if sig.length() != sig_sz {
    return false
  }
  let pk_seed = slh_slice(pk, 0, n)
  let pk_root = slh_slice(pk, n, n)
  let r = slh_slice(sig, 0, n)
  let digest = slh_h_msg(p, pk_seed, pk_root, r, mpr, ctx)
  let (md, i_tree, i_leaf) = slh_split_digest(p, digest)
  let fors_sz = p.k * (1 + p.a) * n
  let sig_fors = slh_slice(sig, n, fors_sz)
  let sig_ht = slh_slice(sig, n + fors_sz, sig.length() - n - fors_sz)
  let adrs = adrs_new()
  adrs_set_tree(adrs, i_tree)
  adrs_set_type_and_clear(adrs, slh_fors_tree)
  adrs_set_keypair(adrs, i_leaf)
  let pk_fors = slh_fors_pk_from_sig(p, pk_seed, sig_fors, md, adrs)
  slh_ht_verify(p, pk_seed, pk_root, pk_fors, sig_ht, i_tree, i_leaf)
}

// ==================== pre-hash (HashSLH-DSA) ====================

///| HashSLH-DSA signed-message format (FIPS 205 §10):
///| M' = 0x01 || octet(|ctx|) || ctx || OID(PH) || PH(M). Reuses the
///| ML-DSA pre-hash selectors (`DsaPrehash`).
fn slh_format_prehash(msg : Bytes, ctx : Bytes, ph : DsaPrehash) -> Bytes {
  concat_all([
    Bytes::make(1, b'\x01'),
    Bytes::make(1, ctx.length().to_byte()),
    ctx,
    dsa_prehash_oid(ph),
    dsa_prehash_digest(ph, msg),
  ])
}

// ==================== public API ====================

///|
/// SLH-DSA key generation (FIPS 205 Algorithm 18), deterministic in the
/// three n-byte seeds (SK.seed, SK.prf, PK.seed). Returns (pk, sk).
pub fn slh_keygen(
  params : SlhParams,
  sk_seed : Bytes,
  sk_prf : Bytes,
  pk_seed : Bytes,
) -> (Bytes, Bytes) {
  slh_keygen_internal(params, sk_seed, sk_prf, pk_seed)
}

///|
/// SLH-DSA deterministic pure signing (FIPS 205 Algorithms 22/19 with
/// opt_rand = PK.seed). `ctx` is the context string (at most 255 bytes).
pub fn slh_sign(
  params : SlhParams,
  sk : Bytes,
  msg : Bytes,
  ctx : Bytes,
) -> Bytes {
  if ctx.length() > 255 {
    abort("slh_dsa sign: context too long")
  }
  slh_sign_internal(params, sk, msg, None, Some(ctx))
}

///|
/// SLH-DSA hedged pure signing: `rnd` is the optional additional
/// randomness (opt_rand); pass 32 fresh bytes in production use.
pub fn slh_sign_hedged(
  params : SlhParams,
  sk : Bytes,
  msg : Bytes,
  ctx : Bytes,
  rnd : Bytes,
) -> Bytes {
  if ctx.length() > 255 {
    abort("slh_dsa sign: context too long")
  }
  slh_sign_internal(params, sk, msg, Some(rnd), Some(ctx))
}

///|
/// SLH-DSA pure verification (FIPS 205 Algorithms 24/20).
pub fn slh_verify(
  params : SlhParams,
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if ctx.length() > 255 {
    return false
  }
  slh_verify_internal(params, pk, msg, sig, Some(ctx))
}

///|
/// HashSLH-DSA deterministic signing (FIPS 205 §10): the message is
/// pre-hashed with `ph` and OID-tagged inside M' before signing.
pub fn slh_sign_prehash(
  params : SlhParams,
  sk : Bytes,
  msg : Bytes,
  ctx : Bytes,
  ph : DsaPrehash,
) -> Bytes {
  if ctx.length() > 255 {
    abort("slh_dsa sign: context too long")
  }
  slh_sign_internal(params, sk, slh_format_prehash(msg, ctx, ph), None, None)
}

///|
/// HashSLH-DSA hedged signing. See `slh_sign_prehash`.
pub fn slh_sign_prehash_hedged(
  params : SlhParams,
  sk : Bytes,
  msg : Bytes,
  ctx : Bytes,
  ph : DsaPrehash,
  rnd : Bytes,
) -> Bytes {
  if ctx.length() > 255 {
    abort("slh_dsa sign: context too long")
  }
  slh_sign_internal(params, sk, slh_format_prehash(msg, ctx, ph), Some(rnd), None)
}

///|
/// HashSLH-DSA verification. See `slh_sign_prehash`.
pub fn slh_verify_prehash(
  params : SlhParams,
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
  ctx : Bytes,
  ph : DsaPrehash,
) -> Bool {
  if ctx.length() > 255 {
    return false
  }
  slh_verify_internal(params, pk, slh_format_prehash(msg, ctx, ph), sig, None)
}

///|
/// SLH-DSA signing over a raw M' (Algorithm 19 with no context
/// formatting) — the internal/message-interface entry point.
pub fn slh_sign_raw(params : SlhParams, sk : Bytes, mpr : Bytes) -> Bytes {
  slh_sign_internal(params, sk, mpr, None, None)
}

///|
/// SLH-DSA hedged signing over a raw M'. See `slh_sign_raw`.
pub fn slh_sign_raw_hedged(
  params : SlhParams,
  sk : Bytes,
  mpr : Bytes,
  rnd : Bytes,
) -> Bytes {
  slh_sign_internal(params, sk, mpr, Some(rnd), None)
}

///|
/// SLH-DSA verification over a raw M' (Algorithm 20). See `slh_sign_raw`.
pub fn slh_verify_raw(
  params : SlhParams,
  pk : Bytes,
  mpr : Bytes,
  sig : Bytes,
) -> Bool {
  slh_verify_internal(params, pk, mpr, sig, None)
}
