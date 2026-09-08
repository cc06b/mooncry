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
