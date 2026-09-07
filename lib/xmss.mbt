/// XMSS / XMSS^MT eXtended Merkle Signatures (RFC 8391).
///
/// STATEFUL hash-based signatures (WOTS+ one-time keys under a Merkle
/// tree; XMSS^MT stacks d layers of height tree_height). Ported 1:1
/// from the official reference implementation (github.com/XMSS/
/// xmss-reference, CC0, by the RFC authors) and verified against its
/// deterministic KATs: WOTS+ pk/sign/leaf, XMSS and XMSS^MT keygen +
/// byte-exact signatures + verification, covering SHA2 (n=24/32/64),
/// SHAKE128 and SHAKE256 instantiations (v0.47.0).
///
/// Hash interface (reference `core_hash`): SHA2 truncates SHA-256 to
/// 24 bytes for n=24; SHAKE variants squeeze n bytes. Every call is
/// prefixed with a big-endian domain tag of `pad` bytes (4 when
/// n=24, else n): F=0, H=1, message-hash=2, PRF=3, PRF_keygen=4.
///
/// Public keys are [root || PUB_SEED] (2n bytes) without the OID
/// prefix; parameters travel out-of-band like in the reference core
/// API. `xmss_sign` consumes the current leaf index and advances it.

///|
pub struct XmssParams {
  // 0 = SHA2, 1 = SHAKE128, 2 = SHAKE256
  func : Int
  n : Int
  pad : Int
  log_w : Int
  w : Int
  len1 : Int
  len2 : Int
  wlen : Int
  wots_sig_bytes : Int
  full_height : Int
  tree_height : Int
  d : Int
  index_bytes : Int
  sig_bytes : Int
  pk_bytes : Int
}

///|
/// Build a parameter set. `func`: 0 SHA2 / 1 SHAKE128 / 2 SHAKE256;
/// `n` in {24, 32, 64} (n=24 only with SHA2/SHAKE256 per RFC);
/// `full_height` = `tree_height` * `d`; d=1 is plain XMSS.
pub fn xmss_params(
  func : Int,
  n : Int,
  full_height : Int,
  tree_height : Int,
  d : Int,
) -> XmssParams {
  if func < 0 || func > 2 {
    abort("xmss_params: func must be 0/1/2")
  }
  if n != 24 && n != 32 && n != 64 {
    abort("xmss_params: n must be 24/32/64")
  }
  if d < 1 || tree_height < 1 || tree_height * d != full_height {
    abort("xmss_params: need full_height = tree_height * d, d >= 1")
  }
  if full_height > 30 {
    abort("xmss_params: full_height > 30 unsupported (Int index)")
  }
  let pad = if n == 24 { 4 } else { n }
  let len1 = 8 * n / 4 // w = 16 -> log_w = 4
  let len2 = 3
  let wlen = len1 + len2
  let index_bytes = if d == 1 { 4 } else { (full_height + 7) / 8 }
  XmssParams::{
    func,
    n,
    pad,
    log_w: 4,
    w: 16,
    len1,
    len2,
    wlen,
    wots_sig_bytes: wlen * n,
    full_height,
    tree_height,
    d,
    index_bytes,
    sig_bytes: index_bytes + n + d * (wlen * n) + full_height * n,
    pk_bytes: 2 * n,
  }
}

// ==================== low-level helpers ====================

///|
fn xm_ull(v : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  let mut x = v
  for i = len - 1; i >= 0; i = i - 1 {
    out[i] = (x & 0xff).to_byte()
    x = x >> 8
  }
  Bytes::from_array(out)
}

///|
fn xm_to_ull(b : Bytes, off : Int, len : Int) -> Int {
  let mut v = 0
  for i in 0..<len {
    v = (v << 8) | b[off + i].to_int()
  }
  v
}

///|
fn xm_xor(a : Bytes, b : Bytes) -> Bytes {
  let n = a.length()
  let out = Array::make(n, b'\x00')
  for i in 0..<n {
    out[i] = (a[i].to_int() ^ b[i].to_int()).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// core_hash of the reference: the domain-selected n-byte hash.
fn xcore_hash(p : XmssParams, input : Bytes) -> Bytes {
  match p.func {
    0 =>
      if p.n == 64 {
        sha512(input)
      } else if p.n == 24 {
        bytes_sub(sha256(input), 0, 24)
      } else {
        sha256(input)
      }
    1 => shake_128(input, p.n)
    _ => shake_256(input, p.n)
  }
}

///|
fn xm_addr_bytes(addr : Array[UInt]) -> Bytes {
  let out = Array::make(32, (0).to_byte())
  for i in 0..<8 {
    let v = addr[i]
    out[4 * i] = ((v >> 24) & 0xFFU).to_byte()
    out[4 * i + 1] = ((v >> 16) & 0xFFU).to_byte()
    out[4 * i + 2] = ((v >> 8) & 0xFFU).to_byte()
    out[4 * i + 3] = (v & 0xFFU).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn xm_prf(p : XmssParams, key : Bytes, in32 : Bytes) -> Bytes {
  xcore_hash(p, concat_all([xm_ull(3, p.pad), key, in32]))
}

///|
fn xm_prf_keygen(p : XmssParams, key : Bytes, input : Bytes) -> Bytes {
  xcore_hash(p, concat_all([xm_ull(4, p.pad), key, input]))
}

// address field setters (indices per RFC 8391 / the reference)

///|
fn xm_set_layer(addr : Array[UInt], v : Int) -> Unit {
  addr[0] = v.reinterpret_as_uint()
}

///|
fn xm_set_tree(addr : Array[UInt], v : Int) -> Unit {
  addr[1] = 0U
  addr[2] = v.reinterpret_as_uint()
}

///|
fn xm_set_type(addr : Array[UInt], v : Int) -> Unit {
  addr[3] = v.reinterpret_as_uint()
}

///|
fn xm_set_ots(addr : Array[UInt], v : Int) -> Unit {
  addr[4] = v.reinterpret_as_uint()
}

///|
fn xm_set_chain(addr : Array[UInt], v : Int) -> Unit {
  addr[5] = v.reinterpret_as_uint()
}

///|
fn xm_set_hash(addr : Array[UInt], v : Int) -> Unit {
  addr[6] = v.reinterpret_as_uint()
}

///|
fn xm_set_keymask(addr : Array[UInt], v : Int) -> Unit {
  addr[7] = v.reinterpret_as_uint()
}

///|
fn xm_set_ltree(addr : Array[UInt], v : Int) -> Unit {
  addr[4] = v.reinterpret_as_uint()
}

///|
fn xm_set_tree_height(addr : Array[UInt], v : Int) -> Unit {
  addr[5] = v.reinterpret_as_uint()
}

///|
fn xm_set_tree_index(addr : Array[UInt], v : Int) -> Unit {
  addr[6] = v.reinterpret_as_uint()
}

///|
fn xm_new_addr() -> Array[UInt] {
  Array::make(8, 0U)
}

///|
/// Tweakable hash over one n-byte input (Winternitz chain function).
fn thash_f(
  p : XmssParams,
  input : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  xm_set_keymask(addr, 0)
  let key = xm_prf(p, pub_seed, xm_addr_bytes(addr))
  xm_set_keymask(addr, 1)
  let mask = xm_prf(p, pub_seed, xm_addr_bytes(addr))
  xcore_hash(p, concat_all([xm_ull(0, p.pad), key, xm_xor(input, mask)]))
}

///|
/// Tweakable hash over a 2n-byte input (L-tree / hash-tree nodes).
fn thash_h(
  p : XmssParams,
  input : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  xm_set_keymask(addr, 0)
  let key = xm_prf(p, pub_seed, xm_addr_bytes(addr))
  xm_set_keymask(addr, 1)
  let mask0 = xm_prf(p, pub_seed, xm_addr_bytes(addr))
  xm_set_keymask(addr, 2)
  let mask1 = xm_prf(p, pub_seed, xm_addr_bytes(addr))
  let masked = concat_all([
    xm_xor(bytes_sub(input, 0, p.n), mask0),
    xm_xor(bytes_sub(input, p.n, p.n), mask1),
  ])
  xcore_hash(p, concat_all([xm_ull(1, p.pad), key, masked]))
}

// ==================== WOTS+ ====================

///|
fn xm_base_w(p : XmssParams, input : Bytes, out_len : Int) -> Array[Int] {
  let output = Array::make(out_len, 0)
  let mut in_idx = 0
  let mut total = 0
  let mut bits = 0
  for consumed in 0..<out_len {
    if bits == 0 {
      total = input[in_idx].to_int()
      in_idx = in_idx + 1
      bits = bits + 8
    }
    bits = bits - p.log_w
    output[consumed] = (total >> bits) & (p.w - 1)
  }
  output
}

///|
fn xm_chain_lengths(p : XmssParams, msg : Bytes) -> Array[Int] {
  let lengths = xm_base_w(p, msg, p.len1)
  let mut csum = 0
  for i in 0..<p.len1 {
    csum = csum + p.w - 1 - lengths[i]
  }
  let sh = 8 - p.len2 * p.log_w % 8
  csum = csum << sh
  let csum_bytes = xm_ull(csum, (p.len2 * p.log_w + 7) / 8)
  let rest = xm_base_w(p, csum_bytes, p.len2)
  for i in 0..<p.len2 {
    lengths.push(rest[i])
  }
  lengths
}

///|
fn xm_expand_seed(
  p : XmssParams,
  sk_seed : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Array[Bytes] {
  xm_set_hash(addr, 0)
  xm_set_keymask(addr, 0)
  let out = Array::make(p.wlen, Bytes::make(p.n, b'\x00'))
  for i in 0..<p.wlen {
    xm_set_chain(addr, i)
    let buf = concat_all([pub_seed, xm_addr_bytes(addr)])
    out[i] = xm_prf_keygen(p, sk_seed, buf)
  }
  out
}

///|
fn xm_gen_chain(
  p : XmssParams,
  value0 : Bytes,
  start : Int,
  steps : Int,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  let mut value = value0
  let stop = if start + steps < p.w { start + steps } else { p.w }
  for i in start..<stop {
    xm_set_hash(addr, i)
    value = thash_f(p, value, pub_seed, addr)
  }
  value
}

///|
/// WOTS+ public key from the secret seed (reference wots_pkgen).
/// `addr` must carry the right layer/tree/ots fields.
pub fn xmss_wots_pkgen(
  p : XmssParams,
  sk_seed : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  let seeds = xm_expand_seed(p, sk_seed, pub_seed, addr)
  let parts = Array::make(p.wlen, Bytes::make(p.n, b'\x00'))
  for i in 0..<p.wlen {
    xm_set_chain(addr, i)
    parts[i] = xm_gen_chain(p, seeds[i], 0, p.w - 1, pub_seed, addr)
  }
  concat_all(parts)
}

///|
/// WOTS+ signature of an n-byte message (reference wots_sign).
pub fn xmss_wots_sign(
  p : XmssParams,
  sk_seed : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
  msg : Bytes,
) -> Bytes {
  let lengths = xm_chain_lengths(p, msg)
  let seeds = xm_expand_seed(p, sk_seed, pub_seed, addr)
  let parts = Array::make(p.wlen, Bytes::make(p.n, b'\x00'))
  for i in 0..<p.wlen {
    xm_set_chain(addr, i)
    parts[i] = xm_gen_chain(p, seeds[i], 0, lengths[i], pub_seed, addr)
  }
  concat_all(parts)
}

///|
/// WOTS+ public key candidate from a signature (reference
/// wots_pk_from_sig): completes each chain to w-1.
pub fn xmss_wots_pk_from_sig(
  p : XmssParams,
  sig : Bytes,
  msg : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  let lengths = xm_chain_lengths(p, msg)
  let parts = Array::make(p.wlen, Bytes::make(p.n, b'\x00'))
  for i in 0..<p.wlen {
    xm_set_chain(addr, i)
    parts[i] = xm_gen_chain(
      p,
      bytes_sub(sig, i * p.n, p.n),
      lengths[i],
      p.w - 1 - lengths[i],
      pub_seed,
      addr,
    )
  }
  concat_all(parts)
}

// ==================== trees ====================

///|
/// L-tree: compress a WOTS+ public key to a single leaf node.
fn xm_l_tree(
  p : XmssParams,
  wots_pk : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  let pk = Array::make(p.wlen, Bytes::make(p.n, b'\x00'))
  for i in 0..<p.wlen {
    pk[i] = bytes_sub(wots_pk, i * p.n, p.n)
  }
  let mut l = p.wlen
  let mut height = 0
  xm_set_tree_height(addr, height)
  while l > 1 {
    let parents = l >> 1
    for i in 0..<parents {
      xm_set_tree_index(addr, i)
      let pair = concat_all([pk[2 * i], pk[2 * i + 1]])
      pk[i] = thash_h(p, pair, pub_seed, addr)
    }
    if (l & 1) == 1 {
      pk[l >> 1] = pk[l - 1]
      l = (l >> 1) + 1
    } else {
      l = l >> 1
    }
    height = height + 1
    xm_set_tree_height(addr, height)
  }
  pk[0]
}

///|
/// Leaf computation: WOTS pkgen followed by the L-tree
/// (reference gen_leaf_wots).
pub fn xmss_gen_leaf_wots(
  p : XmssParams,
  sk_seed : Bytes,
  pub_seed : Bytes,
  ltree_addr : Array[UInt],
  ots_addr : Array[UInt],
) -> Bytes {
  let pk = xmss_wots_pkgen(p, sk_seed, pub_seed, ots_addr)
  xm_l_tree(p, pk, pub_seed, ltree_addr)
}

///|
/// Stack-based treehash: computes the subtree root and the auth path
/// for leaf `leaf_idx` (reference treehash).
fn xm_treehash(
  p : XmssParams,
  sk_seed : Bytes,
  pub_seed : Bytes,
  leaf_idx : Int,
  subtree_addr : Array[UInt],
) -> (Bytes, Bytes) {
  let stack = Array::make(p.tree_height + 1, Bytes::make(p.n, b'\x00'))
  let heights = Array::make(p.tree_height + 1, 0)
  let auth = Array::make(p.tree_height, Bytes::make(p.n, b'\x00'))
  let mut offset = 0
  let ots_addr = xm_new_addr()
  let ltree_addr = xm_new_addr()
  let node_addr = xm_new_addr()
  for a in [ots_addr, ltree_addr, node_addr] {
    a[0] = subtree_addr[0]
    a[1] = subtree_addr[1]
    a[2] = subtree_addr[2]
  }
  xm_set_type(ots_addr, 0)
  xm_set_type(ltree_addr, 1)
  xm_set_type(node_addr, 2)
  let leaves = 1 << p.tree_height
  for idx in 0..<leaves {
    xm_set_ltree(ltree_addr, idx)
    xm_set_ots(ots_addr, idx)
    stack[offset] = xmss_gen_leaf_wots(
      p, sk_seed, pub_seed, ltree_addr, ots_addr,
    )
    offset = offset + 1
    heights[offset - 1] = 0
    if (leaf_idx ^ 1) == idx {
      auth[0] = stack[offset - 1]
    }
    while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
      let tree_idx = idx >> (heights[offset - 1] + 1)
      xm_set_tree_height(node_addr, heights[offset - 1])
      xm_set_tree_index(node_addr, tree_idx)
      let pair = concat_all([stack[offset - 2], stack[offset - 1]])
      stack[offset - 2] = thash_h(p, pair, pub_seed, node_addr)
      offset = offset - 1
      heights[offset - 1] = heights[offset - 1] + 1
      if ((leaf_idx >> heights[offset - 1]) ^ 1) == tree_idx {
        auth[heights[offset - 1]] = stack[offset - 1]
      }
    }
  }
  (stack[0], concat_all(auth))
}

///|
/// Recompute the subtree root from a leaf and its auth path
/// (reference compute_root).
fn xm_compute_root(
  p : XmssParams,
  leaf : Bytes,
  leafidx0 : Int,
  auth_path : Bytes,
  pub_seed : Bytes,
  addr : Array[UInt],
) -> Bytes {
  let mut leafidx = leafidx0
  let left = if (leafidx & 1) == 1 {
    bytes_sub(auth_path, 0, p.n)
  } else {
    leaf
  }
  let right = if (leafidx & 1) == 1 {
    leaf
  } else {
    bytes_sub(auth_path, 0, p.n)
  }
  let mut buf0 = left
  let mut buf1 = right
  for i in 0..<(p.tree_height - 1) {
    xm_set_tree_height(addr, i)
    leafidx = leafidx >> 1
    xm_set_tree_index(addr, leafidx)
    let next = bytes_sub(auth_path, (i + 1) * p.n, p.n)
    let pair = concat_all([buf0, buf1])
    if (leafidx & 1) == 1 {
      buf1 = thash_h(p, pair, pub_seed, addr)
      buf0 = next
    } else {
      buf0 = thash_h(p, pair, pub_seed, addr)
      buf1 = next
    }
  }
  xm_set_tree_height(addr, p.tree_height - 1)
  leafidx = leafidx >> 1
  xm_set_tree_index(addr, leafidx)
  thash_h(p, concat_all([buf0, buf1]), pub_seed, addr)
}

// ==================== XMSS / XMSS^MT ====================

///|
/// An XMSS/XMSS^MT secret key (stateful: the leaf index advances on
/// every signature).
pub struct XmssPrivateKey {
  params : XmssParams
  mut idx : Int
  sk_seed : Bytes
  sk_prf : Bytes
  pub_root : Bytes
  pub_seed : Bytes
}

///|
/// Deterministic key generation from a 3n-byte seed
/// [SK_SEED || SK_PRF || PUB_SEED] (reference
/// xmssmt_core_seed_keypair). Computes the top-tree root.
pub fn xmss_keygen_from_seed(p : XmssParams, seed : Bytes) -> XmssPrivateKey {
  if seed.length() != 3 * p.n {
    abort("xmss_keygen_from_seed: seed must be 3*n bytes")
  }
  let sk_seed = bytes_sub(seed, 0, p.n)
  let sk_prf = bytes_sub(seed, p.n, p.n)
  let pub_seed = bytes_sub(seed, 2 * p.n, p.n)
  let top = xm_new_addr()
  xm_set_layer(top, p.d - 1)
  let root = xm_treehash(p, sk_seed, pub_seed, 0, top).0
  XmssPrivateKey::{
    params: p,
    idx: 0,
    sk_seed,
    sk_prf,
    pub_root: root,
    pub_seed,
  }
}

///|
/// Set the leaf index (state handling / interoperability testing).
pub fn xmss_set_index(sk : XmssPrivateKey, idx : Int) -> Unit {
  if idx < 0 || idx >= 1 << sk.params.full_height {
    abort("xmss_set_index: out of range")
  }
  sk.idx = idx
}

///|
/// The public key [root || PUB_SEED] (2n bytes, no OID prefix).
pub fn xmss_public_key(sk : XmssPrivateKey) -> Bytes {
  concat_all([sk.pub_root, sk.pub_seed])
}

///|
/// Sign with the current leaf index and advance it. Signature layout:
/// idx_bytes || R || (wots_sig || auth_path) per layer.
pub fn xmss_sign(sk : XmssPrivateKey, msg : Bytes) -> Bytes {
  let p = sk.params
  let idx = sk.idx
  if idx >= (1 << p.full_height) - 1 {
    abort("xmss_sign: key exhausted (stateful scheme — re-key)")
  }
  sk.idx = idx + 1
  let r = xm_prf(p, sk.sk_prf, xm_ull(idx, 32))
  let mhash = xcore_hash(
    p,
    concat_all([xm_ull(2, p.pad), r, sk.pub_root, xm_ull(idx, p.n), msg]),
  )
  let parts = [xm_ull(idx, p.index_bytes), r]
  let mut root = mhash
  let mut cur = idx
  for i in 0..<p.d {
    let idx_leaf = cur & ((1 << p.tree_height) - 1)
    cur = cur >> p.tree_height
    let addr = xm_new_addr()
    xm_set_layer(addr, i)
    xm_set_tree(addr, cur)
    xm_set_ots(addr, idx_leaf)
    xm_set_type(addr, 0)
    parts.push(xmss_wots_sign(p, sk.sk_seed, sk.pub_seed, addr, root))
    let th = xm_treehash(p, sk.sk_seed, sk.pub_seed, idx_leaf, addr)
    parts.push(th.1)
    root = th.0
  }
  concat_all(parts)
}

///|
/// Verify an XMSS/XMSS^MT signature (reference xmssmt_core_sign_open).
pub fn xmss_verify(
  p : XmssParams,
  pk : Bytes,
  msg : Bytes,
  sig : Bytes,
) -> Bool {
  if pk.length() != p.pk_bytes || sig.length() != p.sig_bytes {
    return false
  }
  let pub_root = bytes_sub(pk, 0, p.n)
  let pub_seed = bytes_sub(pk, p.n, p.n)
  let idx0 = xm_to_ull(sig, 0, p.index_bytes)
  let r = bytes_sub(sig, p.index_bytes, p.n)
  let mut off = p.index_bytes + p.n
  let mut root = xcore_hash(
    p,
    concat_all([xm_ull(2, p.pad), r, pub_root, xm_ull(idx0, p.n), msg]),
  )
  let mut cur = idx0
  let ots_addr = xm_new_addr()
  let ltree_addr = xm_new_addr()
  let node_addr = xm_new_addr()
  xm_set_type(ots_addr, 0)
  xm_set_type(ltree_addr, 1)
  xm_set_type(node_addr, 2)
  for i in 0..<p.d {
    let idx_leaf = cur & ((1 << p.tree_height) - 1)
    cur = cur >> p.tree_height
    for a in [ots_addr, ltree_addr, node_addr] {
      xm_set_layer(a, i)
      xm_set_tree(a, cur)
    }
    xm_set_ots(ots_addr, idx_leaf)
    let wots_pk = xmss_wots_pk_from_sig(
      p,
      bytes_sub(sig, off, p.wots_sig_bytes),
      root,
      pub_seed,
      ots_addr,
    )
    off = off + p.wots_sig_bytes
    xm_set_ltree(ltree_addr, idx_leaf)
    let leaf = xm_l_tree(p, wots_pk, pub_seed, ltree_addr)
    root = xm_compute_root(
      p,
      leaf,
      idx_leaf,
      bytes_sub(sig, off, p.tree_height * p.n),
      pub_seed,
      node_addr,
    )
    off = off + p.tree_height * p.n
  }
  bytes_equal(root, pub_root)
}
