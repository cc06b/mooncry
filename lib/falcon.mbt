// Falcon-512 public API (verification for now; keygen/sign land in
// M4/M5). Signature layout follows PQClean: sig[0] = 0x39 header,
// sig[1..41) = 40-byte nonce, sig[41..] = comp-encoded s2. Public key:
// pk[0] = 0x09 header, pk[1..] = modq-encoded h.

///|
/// Falcon-512 public key size in bytes (header + 512*14/8).
pub let falcon512_pk_bytes : Int = 897

///|
/// Falcon-512 secret key size in bytes.
pub let falcon512_sk_bytes : Int = 1281

///|
/// Falcon-512 maximum (padded) signature size in bytes.
pub let falcon512_sig_bytes : Int = 666

///|
/// Verify a Falcon-512 signature. `sig` may be the compact variable
/// length form or the padded form (trailing zero bytes).
pub fn falcon512_verify(pk : Bytes, sig : Bytes, msg : Bytes) -> Bool {
  falcon_verify(pk, sig, msg, 9)
}

///|
/// Verify a Falcon signature for the given logn (9 = Falcon-512,
/// 10 = Falcon-1024).
pub fn falcon_verify(pk : Bytes, sig : Bytes, msg : Bytes, logn : Int) -> Bool {
  let n = 1 << logn
  let pk_len = 1 + (n * 14 + 7) / 8
  let nonce_len = 40
  if pk.length() != pk_len {
    return false
  }
  if pk[0].to_int() != logn {
    return false
  }
  let pk_body = Array::make(pk_len - 1, (0).to_byte())
  for i = 1; i < pk_len; i = i + 1 {
    pk_body[i - 1] = pk[i]
  }
  let h = falcon_modq_decode(Bytes::from_array(pk_body), logn)
  if h.length() != n {
    return false
  }
  falcon_to_ntt_monty(h, logn)
  let sig_len = sig.length()
  if sig_len == 0 {
    return false
  }
  if sig[0].to_int() != 0x30 + logn {
    return false
  }
  if sig_len < 1 + nonce_len {
    return false
  }
  let sig_body = Array::make(sig_len - 1 - nonce_len, (0).to_byte())
  for i = 0; i < sig_body.length(); i = i + 1 {
    sig_body[i] = sig[1 + nonce_len + i]
  }
  let body = Bytes::from_array(sig_body)
  let s2 = falcon_comp_decode(body, logn)
  if s2.length() != n {
    return false
  }
  // consumed-length check: re-encode must reproduce the body prefix,
  // and any remaining bytes must be zero (padded form).
  let enc = falcon_comp_encode(s2, logn)
  if enc.length() > body.length() {
    return false
  }
  for i = 0; i < enc.length(); i = i + 1 {
    if enc[i] != body[i] {
      return false
    }
  }
  for i = enc.length(); i < body.length(); i = i + 1 {
    if body[i].to_int() != 0 {
      return false
    }
  }
  let nonce = Array::make(nonce_len, (0).to_byte())
  for i = 0; i < nonce_len; i = i + 1 {
    nonce[i] = sig[1 + i]
  }
  let hm = falcon_hash_to_point(Bytes::from_array(nonce), msg, logn)
  falcon_verify_raw(hm, s2, h, logn)
}

///|
/// Reproduce the deterministic test RNG used by the C vector harness:
/// randombytes(buf, n) = SHAKE256(16 * 0xA5 || u64le(counter)), with a
/// per-stream counter starting at 0.
pub struct FalconTestRng {
  x : FalconXof
  mut ctr : UInt64
}

///|
pub fn falcon_test_rng_init() -> FalconTestRng {
  { x: falcon_xof_init(), ctr: 0UL, }
}

///|
pub fn falcon_test_rng_bytes(r : FalconTestRng, n : Int) -> Bytes {
  let seed = Array::make(24, (0xA5).to_byte())
  let c = r.ctr
  for i = 0; i < 8; i = i + 1 {
    seed[16 + i] = ((c >> (i * 8)) & 0xFFUL).to_byte()
  }
  r.ctr = r.ctr + 1UL
  let x = falcon_xof_init()
  falcon_xof_inject(x, Bytes::from_array(seed))
  falcon_xof_extract(x, n)
}

///|
/// Falcon-512 keypair from an explicit 48-byte seed (the seed feeds
/// SHAKE256 exactly as PQClean's crypto_sign_keypair does with the
/// output of randombytes).
pub fn falcon512_keypair_from_seed(seed : Bytes) -> (Bytes, Bytes) {
  let x = falcon_xof_init()
  falcon_xof_inject(x, seed)
  let _ = falcon_xof_extract(x, 0) // flip
  let (f, g, big_f, h) = falcon_keygen(x, 9)
  let n = 512
  // pk = 0x09 || modq_encode(h)
  let pk_arr : Array[Byte] = [(0x09).to_byte()]
  let pk_body = falcon_modq_encode(h, 9)
  for i = 0; i < pk_body.length(); i = i + 1 {
    pk_arr.push(pk_body[i])
  }
  // sk = 0x59 || trim_i8(f, max_fg_bits) || trim_i8(g) || trim_i8(F, max_FG_bits)
  let sk_arr : Array[Byte] = [(0x59).to_byte()]
  let ef = falcon_trim_encode(f, 9, falcon_max_fg_bits[9])
  let eg = falcon_trim_encode(g, 9, falcon_max_fg_bits[9])
  let eF = falcon_trim_encode(big_f, 9, falcon_max_FG_bits[9])
  for part in [ef, eg, eF] {
    for i = 0; i < part.length(); i = i + 1 {
      sk_arr.push(part[i])
    }
  }
  ignore(n)
  (Bytes::from_array(pk_arr), Bytes::from_array(sk_arr))
}
