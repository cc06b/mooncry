// ============================================================
// Ed25519ctx and Ed25519ph (RFC 8032 §5.1, §7.2, §7.3).
// Domain-separated variants of Ed25519: the dom2(F, C) prefix is
// prepended to both hash inputs. Ed25519ph additionally pre-hashes
// the message with SHA-512. Reuses the ed_* field/point helpers from
// ed25519.mbt.
// ============================================================

///|
/// dom2(F, C) = "SigEd25519 no Ed25519 collisions" || F || len(C) || C
fn ed25519_dom2(flag : Int, ctx : Bytes) -> Bytes {
  let prefix = b"SigEd25519 no Ed25519 collisions"
  let flags = Bytes::from_array([flag.to_byte(), ctx.length().to_byte()][:])
  concat_all([prefix, flags, ctx])
}

///|
/// EdDSA sign with a domain prefix: r = H(dom || prefix || M') mod L,
/// k = H(dom || R || A || M') mod L, S = r + k*a mod L.
fn ed25519_sign_dom(seed : Bytes, message : Bytes, dom : Bytes) -> Bytes {
  let h = sha512(seed)
  let a_bytes = ed_clamp(ed_slice(h, 0, 32))
  let a = ed_le_to_int(a_bytes)
  let prefix = ed_slice(h, 32, 32)
  let pk = ed_encode(ed_scalar_mult(a, ed_base))
  let r_hash = sha512(concat_all([dom, prefix, message]))
  let r = ed_le_to_int(r_hash) % ed_l
  let r_enc = ed_encode(ed_scalar_mult(r, ed_base))
  let k = ed_le_to_int(sha512(concat_all([dom, r_enc, pk, message]))) % ed_l
  let s = (r + k * a % ed_l) % ed_l
  concat_bytes(r_enc, ed_int_to_le(s, 32))
}

///|
/// EdDSA verify with a domain prefix
fn ed25519_verify_dom(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
  dom : Bytes,
) -> Bool {
  if public_key.length() != 32 || sig.length() != 64 {
    return false
  }
  let r_enc = ed_slice(sig, 0, 32)
  let s_enc = ed_slice(sig, 32, 32)
  let s = ed_le_to_int(s_enc)
  if s >= ed_l {
    return false
  }
  let a = match ed_decode(public_key) {
    Some(p) => p
    None => return false
  }
  let r = match ed_decode(r_enc) {
    Some(p) => p
    None => return false
  }
  let k = ed_le_to_int(sha512(concat_all([dom, r_enc, public_key, message]))) %
    ed_l
  let lhs = ed_scalar_mult(s, ed_base)
  let rhs = ed_point_add(r, ed_scalar_mult(k, a))
  bytes_equal(ed_encode(lhs), ed_encode(rhs))
}

///|
/// Ed25519ctx sign (RFC 8032 §8.2): Ed25519 with a non-empty context
/// string (1..255 bytes) bound into the signature.
pub fn ed25519ctx_sign(seed : Bytes, message : Bytes, ctx : Bytes) -> Bytes {
  if seed.length() != 32 {
    abort("ed25519ctx_sign: seed must be 32 bytes")
  }
  if ctx.length() < 1 || ctx.length() > 255 {
    abort("ed25519ctx_sign: ctx must be 1..255 bytes")
  }
  ed25519_sign_dom(seed, message, ed25519_dom2(0, ctx))
}

///|
/// Ed25519ctx verify. Returns false unless the signature is valid for
/// the same context string used at signing.
pub fn ed25519ctx_verify(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if ctx.length() < 1 || ctx.length() > 255 {
    return false
  }
  ed25519_verify_dom(public_key, message, sig, ed25519_dom2(0, ctx))
}

///|
/// Ed25519ph sign (RFC 8032 §8.3): pre-hashes the message with
/// SHA-512 before signing (phflag = 1). `ctx` may be empty (0..255
/// bytes).
pub fn ed25519ph_sign(seed : Bytes, message : Bytes, ctx : Bytes) -> Bytes {
  if seed.length() != 32 {
    abort("ed25519ph_sign: seed must be 32 bytes")
  }
  if ctx.length() > 255 {
    abort("ed25519ph_sign: ctx must be at most 255 bytes")
  }
  ed25519ph_sign_hashed(seed, sha512(message), ctx)
}

///|
/// Ed25519ph sign over an already-computed SHA-512 message digest
/// (32-byte input is NOT pre-hashed again).
pub fn ed25519ph_sign_hashed(
  seed : Bytes,
  ph_hash : Bytes,
  ctx : Bytes,
) -> Bytes {
  if seed.length() != 32 {
    abort("ed25519ph_sign_hashed: seed must be 32 bytes")
  }
  if ph_hash.length() != 64 {
    abort("ed25519ph_sign_hashed: PH(M) must be a 64-byte SHA-512 digest")
  }
  if ctx.length() > 255 {
    abort("ed25519ph_sign_hashed: ctx must be at most 255 bytes")
  }
  ed25519_sign_dom(seed, ph_hash, ed25519_dom2(1, ctx))
}

///|
/// Ed25519ph verify: hashes the message with SHA-512 first, then
/// verifies with phflag = 1. `ctx` must match the signing context.
pub fn ed25519ph_verify(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if ctx.length() > 255 {
    return false
  }
  ed25519ph_verify_hashed(public_key, sha512(message), sig, ctx)
}

///|
/// Ed25519ph verify over an already-computed SHA-512 message digest.
pub fn ed25519ph_verify_hashed(
  public_key : Bytes,
  ph_hash : Bytes,
  sig : Bytes,
  ctx : Bytes,
) -> Bool {
  if ph_hash.length() != 64 || ctx.length() > 255 {
    return false
  }
  ed25519_verify_dom(public_key, ph_hash, sig, ed25519_dom2(1, ctx))
}
