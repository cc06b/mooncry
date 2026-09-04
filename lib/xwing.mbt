// ============================================================
// X-Wing: hybrid post-quantum KEM (draft-connolly-cfrg-xwing-kem),
// combining ML-KEM-768 with X25519. v0.35.0.
//
// Key sizes: pk 1216 B (ML-KEM ek 1184 || X25519 pk 32), sk 32 B seed,
// ciphertext 1120 B (ML-KEM ct 1088 || X25519 ct 32), shared secret 32 B.
// The decapsulation key expands deterministically from the 32-byte seed
// (SHAKE256(seed, 96) supplies ML-KEM d/z and the X25519 scalar).
// ============================================================

///|
fn xwing_label() -> Bytes {
  b"\x5c\x2e\x2f\x2f\x5e\x5c" // "\./" "/^\"
}

///|
fn xwing_expand(sk : Bytes) -> (Bytes, Bytes, Bytes, Bytes) {
  let expanded = shake_256(sk, 96)
  let d = bytes_sub(expanded, 0, 32)
  let z = bytes_sub(expanded, 32, 32)
  let (pk_m, sk_m) = ml_kem_768_keygen(d, z)
  let sk_x = bytes_sub(expanded, 64, 32)
  let pk_x = x25519_public_key(sk_x)
  (sk_m, sk_x, pk_m, pk_x)
}

///|
fn xwing_combiner(
  ss_m : Bytes,
  ss_x : Bytes,
  ct_x : Bytes,
  pk_x : Bytes,
) -> Bytes {
  sha3_256(concat_all([ss_m, ss_x, ct_x, pk_x, xwing_label()]))
}

///|
/// X-Wing key generation (derandomized): expands the 32-byte seed into
/// the ML-KEM-768 and X25519 components. Returns (pk, sk) where pk is
/// 1216 bytes and sk is the 32-byte seed itself. v0.35.0.
pub fn xwing_keygen(seed : Bytes) -> (Bytes, Bytes) {
  if seed.length() != 32 {
    abort("xwing_keygen: seed must be 32 bytes")
  }
  let (sk_m, sk_x, pk_m, pk_x) = xwing_expand(seed)
  let _ = sk_m
  let _ = sk_x
  (concat_bytes(pk_m, pk_x), seed)
}

///|
/// X-Wing encapsulation (derandomized in the 64-byte `eseed`:
/// eseed[0:32] is the ML-KEM encapsulation randomness, eseed[32:64] the
/// X25519 ephemeral scalar). Returns (ss, ct). v0.35.0.
pub fn xwing_encaps(pk : Bytes, eseed : Bytes) -> (Bytes, Bytes) {
  if pk.length() != 1216 {
    abort("xwing_encaps: pk must be 1216 bytes")
  }
  if eseed.length() != 64 {
    abort("xwing_encaps: eseed must be 64 bytes")
  }
  let pk_m = bytes_sub(pk, 0, 1184)
  let pk_x = bytes_sub(pk, 1184, 32)
  let ek_x = bytes_sub(eseed, 32, 32)
  let ct_x = x25519_public_key(ek_x)
  let ss_x = x25519(ek_x, pk_x)
  let (ss_m, ct_m) = ml_kem_768_encaps(pk_m, bytes_sub(eseed, 0, 32))
  (xwing_combiner(ss_m, ss_x, ct_x, pk_x), concat_bytes(ct_m, ct_x))
}

///|
/// X-Wing decapsulation: recovers the shared secret from ct with the
/// 32-byte seed. Invalid ciphertexts do not fail — as with ML-KEM, a
/// different (implicit) shared secret is produced. v0.35.0.
pub fn xwing_decaps(ct : Bytes, sk : Bytes) -> Bytes {
  if ct.length() != 1120 {
    abort("xwing_decaps: ct must be 1120 bytes")
  }
  if sk.length() != 32 {
    abort("xwing_decaps: sk must be 32 bytes")
  }
  let (sk_m, sk_x, _, pk_x) = xwing_expand(sk)
  let ct_m = bytes_sub(ct, 0, 1088)
  let ct_x = bytes_sub(ct, 1088, 32)
  let ss_m = ml_kem_768_decaps(sk_m, ct_m)
  let ss_x = x25519(sk_x, ct_x)
  xwing_combiner(ss_m, ss_x, ct_x, pk_x)
}
