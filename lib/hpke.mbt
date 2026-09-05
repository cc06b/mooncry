// ============================================================
// HPKE: Hybrid Public Key Encryption (RFC 9180). v0.37.0.
//
// Supported KEMs: DHKEM(X25519, HKDF-SHA256) = 0x0020 and
// DHKEM(X448, HKDF-SHA512) = 0x0021. KDFs: HKDF-SHA256/SHA512.
// AEADs: AES-128-GCM (0x0001), AES-256-GCM (0x0002),
// ChaCha20Poly1305 (0x0003). Modes: base (0), psk (1), auth (2),
// auth+psk (3). The setup functions take the ephemeral IKM explicitly
// (derandomized) so tests are deterministic — pass 32/56 fresh random
// bytes in production use.
// ============================================================

///|
/// HPKE cipher suite selector (RFC 9180 §7). v0.37.0.
pub struct HpkeSuite {
  kem_id : Int
  kdf_id : Int
  aead_id : Int
}

///|
/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
pub let hpke_x25519_hkdf_sha256_aes128gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x20,
  kdf_id: 1,
  aead_id: 1,
}

///|
/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM.
pub let hpke_x25519_hkdf_sha256_aes256gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x20,
  kdf_id: 1,
  aead_id: 2,
}

///|
/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305.
pub let hpke_x25519_hkdf_sha256_chacha20poly1305 : HpkeSuite = HpkeSuite::{
  kem_id: 0x20,
  kdf_id: 1,
  aead_id: 3,
}

///|

///|
/// DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
pub let hpke_p256_hkdf_sha256_aes128gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x10,
  kdf_id: 1,
  aead_id: 1,
}

///|
/// DHKEM(P-256, HKDF-SHA256) + HKDF-SHA512 + AES-128-GCM.
pub let hpke_p256_hkdf_sha512_aes128gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x10,
  kdf_id: 3,
  aead_id: 1,
}

///|
/// DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305.
pub let hpke_p256_hkdf_sha256_chacha20poly1305 : HpkeSuite = HpkeSuite::{
  kem_id: 0x10,
  kdf_id: 1,
  aead_id: 3,
}

///|

///|

///|
/// DHKEM(P-384, HKDF-SHA384) + HKDF-SHA384 + AES-256-GCM.
pub let hpke_p384_hkdf_sha384_aes256gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x11,
  kdf_id: 2,
  aead_id: 2,
}

///|
/// DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM.
pub let hpke_p521_hkdf_sha512_aes256gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x12,
  kdf_id: 3,
  aead_id: 2,
}

///|
/// DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + AES-128-GCM.
pub let hpke_x448_hkdf_sha512_aes128gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x21,
  kdf_id: 3,
  aead_id: 1,
}

///|
/// DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM.
pub let hpke_x448_hkdf_sha512_aes256gcm : HpkeSuite = HpkeSuite::{
  kem_id: 0x21,
  kdf_id: 3,
  aead_id: 2,
}

///|
/// DHKEM(X448, HKDF-SHA512) + HKDF-SHA512 + ChaCha20Poly1305.
pub let hpke_x448_hkdf_sha512_chacha20poly1305 : HpkeSuite = HpkeSuite::{
  kem_id: 0x21,
  kdf_id: 3,
  aead_id: 3,
}

// ==================== suite parameters ====================

///|
fn hpke_kem_params(s : HpkeSuite) -> (Int, Int) {
  // (Nsecret=Npk=Nsk, ) per KEM
  match s.kem_id {
    0x10 => (32, 32) // Nsecret, Nsk for P-256
    0x11 => (48, 48) // Nsecret, Nsk for P-384
    0x12 => (64, 66) // Nsecret, Nsk for P-521
    0x20 => (32, 32) // Nsecret, Nsk for X25519
    0x21 => (64, 56) // Nsecret, Nsk for X448
    _ => abort("hpke: unsupported kem_id")
  }
}

///|
fn hpke_kdf_nh(s : HpkeSuite) -> Int {
  match s.kdf_id {
    1 => 32
    2 => 48
    3 => 64
    _ => abort("hpke: unsupported kdf_id")
  }
}

///|
fn hpke_aead_params(s : HpkeSuite) -> (Int, Int) {
  // (Nk, Nn)
  match s.aead_id {
    1 => (16, 12)
    2 => (32, 12)
    3 => (32, 12)
    _ => abort("hpke: unsupported aead_id")
  }
}

// ==================== KDF primitives ====================

///|
// The KEM's associated KDF is fixed by kem_id and can differ from the
// ciphersuite KDF (RFC 9180: e.g. DHKEM(P-256, HKDF-SHA256) inside a
// HKDF-SHA512 ciphersuite).
fn hpke_kem_kdf_id(s : HpkeSuite) -> Int {
  match s.kem_id {
    0x10 => 1
    0x11 => 2
    0x12 => 3
    0x20 => 1
    0x21 => 3
    _ => abort("hpke: unsupported kem_id")
  }
}

///|
fn hpke_hkdf_extract(kdf_id : Int, salt : Bytes, ikm : Bytes) -> Bytes {
  match kdf_id {
    1 => hkdf_extract(salt, ikm)
    2 => hkdf_sha384_extract(salt, ikm)
    3 => hkdf_sha512_extract(salt, ikm)
    _ => abort("hpke: unsupported kdf_id")
  }
}

///|
fn hpke_hkdf_expand(
  kdf_id : Int,
  prk : Bytes,
  info : Bytes,
  len : Int,
) -> Bytes {
  let h = match kdf_id {
    1 => hmac_sha256
    2 => hmac_sha384
    3 => hmac_sha512
    _ => abort("hpke: unsupported kdf_id")
  }
  let mut okm = b""
  let mut t = b""
  let mut i = 1
  while okm.length() < len && i <= 255 {
    t = h(prk, concat_all([t, info, Bytes::make(1, i.to_byte())]))
    okm = concat_bytes(okm, t)
    i = i + 1
  }
  Bytes::from_array(okm.to_array()[0:len])
}

///|
fn hpke_i2osp(x : Int, len : Int) -> Bytes {
  let out = Array::make(len, b'\x00')
  let mut v = x
  let mut i = len - 1
  while i >= 0 {
    out[i] = (v % 256).to_byte()
    v = v / 256
    i = i - 1
  }
  Bytes::from_array(out[:])
}

///|
fn hpke_labeled_suite_id(s : HpkeSuite, kem_only : Bool) -> Bytes {
  if kem_only {
    concat_all([b"KEM", hpke_i2osp(s.kem_id, 2)])
  } else {
    concat_all([
      b"HPKE",
      hpke_i2osp(s.kem_id, 2),
      hpke_i2osp(s.kdf_id, 2),
      hpke_i2osp(s.aead_id, 2),
    ])
  }
}

///|
fn hpke_labeled_extract(
  s : HpkeSuite,
  kem_only : Bool,
  salt : Bytes,
  label : Bytes,
  ikm : Bytes,
) -> Bytes {
  hpke_hkdf_extract(
    if kem_only {
      hpke_kem_kdf_id(s)
    } else {
      s.kdf_id
    },
    salt,
    concat_all([b"HPKE-v1", hpke_labeled_suite_id(s, kem_only), label, ikm]),
  )
}

///|
fn hpke_labeled_expand(
  s : HpkeSuite,
  kem_only : Bool,
  prk : Bytes,
  label : Bytes,
  info : Bytes,
  len : Int,
) -> Bytes {
  hpke_hkdf_expand(
    if kem_only {
      hpke_kem_kdf_id(s)
    } else {
      s.kdf_id
    },
    prk,
    concat_all([
      hpke_i2osp(len, 2),
      b"HPKE-v1",
      hpke_labeled_suite_id(s, kem_only),
      label,
      info,
    ]),
    len,
  )
}

// ==================== DHKEM ====================

///|
/// HPKE DeriveKeyPair (RFC 9180 §5.1): deterministic from `ikm`
let hpke_p384_curve : EcCurve = {
  p: @bigint.BigInt::from_string(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    radix=16,
  ),
  n: @bigint.BigInt::from_string(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    radix=16,
  ),
  b: @bigint.BigInt::from_string(
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    radix=16,
  ),
  a_minus3: true,
  gx: @bigint.BigInt::from_string(
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    radix=16,
  ),
  gy: @bigint.BigInt::from_string(
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    radix=16,
  ),
}

///|
fn hpke_p384_point_serialize(
  pt_x : @bigint.BigInt,
  pt_y : @bigint.BigInt,
) -> Bytes {
  concat_all([b"\x04", rsa_i2osp(pt_x, 48), rsa_i2osp(pt_y, 48)])
}

///|
fn hpke_p384_point_deserialize(pk : Bytes) -> (BigInt, BigInt) {
  if pk.length() != 97 || pk[0] != b'\x04' {
    abort("hpke: invalid P-384 public key encoding")
  }
  (rsa_os2ip(bytes_sub(pk, 1, 48)), rsa_os2ip(bytes_sub(pk, 49, 48)))
}

///|
let hpke_p521_curve : EcCurve = {
  p: @bigint.BigInt::from_string(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    radix=16,
  ),
  n: @bigint.BigInt::from_string(
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    radix=16,
  ),
  b: @bigint.BigInt::from_string(
    "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    radix=16,
  ),
  a_minus3: true,
  gx: @bigint.BigInt::from_string(
    "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    radix=16,
  ),
  gy: @bigint.BigInt::from_string(
    "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
    radix=16,
  ),
}

///|
fn hpke_p521_point_serialize(
  pt_x : @bigint.BigInt,
  pt_y : @bigint.BigInt,
) -> Bytes {
  concat_all([b"\x04", rsa_i2osp(pt_x, 66), rsa_i2osp(pt_y, 66)])
}

///|
fn hpke_p521_point_deserialize(pk : Bytes) -> (BigInt, BigInt) {
  if pk.length() != 133 || pk[0] != b'\x04' {
    abort("hpke: invalid P-521 public key encoding")
  }
  (rsa_os2ip(bytes_sub(pk, 1, 66)), rsa_os2ip(bytes_sub(pk, 67, 66)))
}

///|
fn hpke_p256_point_serialize(
  pt_x : @bigint.BigInt,
  pt_y : @bigint.BigInt,
) -> Bytes {
  concat_all([b"\x04", rsa_i2osp(pt_x, 32), rsa_i2osp(pt_y, 32)])
}

///|
fn hpke_p256_point_deserialize(pk : Bytes) -> (BigInt, BigInt) {
  if pk.length() != 65 || pk[0] != b'\x04' {
    abort("hpke: invalid P-256 public key encoding")
  }
  (rsa_os2ip(bytes_sub(pk, 1, 32)), rsa_os2ip(bytes_sub(pk, 33, 32)))
}

///|
/// (Nsk bytes). Returns (pk, sk). v0.37.0.
pub fn hpke_derive_key_pair(s : HpkeSuite, ikm : Bytes) -> (Bytes, Bytes) {
  let (_, nsk) = hpke_kem_params(s)
  let dkp_prk = hpke_labeled_extract(s, true, b"", b"dkp_prk", ikm)
  if s.kem_id == 0x11 {
    // rejection sampling over the P-384 group order (bitmask 0xFF)
    let order = hpke_p384_curve.n
    let mut counter = 0
    let mut sk_int = @bigint.BigInt::from_int(0)
    while true {
      if counter > 255 {
        abort("hpke: DeriveKeyPair rejection sampling failed")
      }
      let cand = hpke_labeled_expand(
        s,
        true,
        dkp_prk,
        b"candidate",
        hpke_i2osp(counter, 1),
        48,
      )
      let cand_int = rsa_os2ip(cand)
      if cand_int > 0 && cand_int < order {
        sk_int = cand_int
        break
      }
      counter = counter + 1
    }
    let sk = rsa_i2osp(sk_int, 48)
    let pt = ec_scalar_mult(
      hpke_p384_curve,
      sk_int,
      ec_g_point(hpke_p384_curve),
    )
    (hpke_p384_point_serialize(pt.x, pt.y), sk)
  } else if s.kem_id == 0x12 {
    // rejection sampling over the P-521 group order (bitmask 0x01)
    let order = hpke_p521_curve.n
    let mut counter = 0
    let mut sk_int = @bigint.BigInt::from_int(0)
    while true {
      if counter > 255 {
        abort("hpke: DeriveKeyPair rejection sampling failed")
      }
      let cand = hpke_labeled_expand(
        s,
        true,
        dkp_prk,
        b"candidate",
        hpke_i2osp(counter, 1),
        66,
      ).to_array()
      cand[0] = cand[0] & 0x01
      let cand_int = rsa_os2ip(Bytes::from_array(cand))
      if cand_int > 0 && cand_int < order {
        sk_int = cand_int
        break
      }
      counter = counter + 1
    }
    let sk = rsa_i2osp(sk_int, 66)
    let pt = ec_scalar_mult(
      hpke_p521_curve,
      sk_int,
      ec_g_point(hpke_p521_curve),
    )
    (hpke_p521_point_serialize(pt.x, pt.y), sk)
  } else if s.kem_id == 0x10 {
    // rejection sampling over the P-256 group order (RFC 9180 section 7.1.3)
    let order = p256_curve.n
    let mut counter = 0
    let mut sk_int = @bigint.BigInt::from_int(0)
    while true {
      if counter > 255 {
        abort("hpke: DeriveKeyPair rejection sampling failed")
      }
      let cand = hpke_labeled_expand(
        s,
        true,
        dkp_prk,
        b"candidate",
        hpke_i2osp(counter, 1),
        32,
      )
      // bitmask for P-256 is 0xFF: the first byte stays unchanged
      let cand_int = rsa_os2ip(cand)
      if cand_int > 0 && cand_int < order {
        sk_int = cand_int
        break
      }
      counter = counter + 1
    }
    let sk = rsa_i2osp(sk_int, 32)
    let pt = ec_scalar_mult(p256_curve, sk_int, ec_g_point(p256_curve))
    (hpke_p256_point_serialize(pt.x, pt.y), sk)
  } else {
    let sk = hpke_labeled_expand(s, true, dkp_prk, b"sk", b"", nsk)
    let pk = match s.kem_id {
      0x20 => x25519_public_key(sk)
      0x21 => x448_public_key(sk)
      _ => abort("hpke: unsupported kem_id")
    }
    (pk, sk)
  }
}

///|
fn hpke_dh(s : HpkeSuite, scalar : Bytes, point : Bytes) -> Bytes {
  match s.kem_id {
    0x11 => {
      let (px, py) = hpke_p384_point_deserialize(point)
      let pt = ec_scalar_mult(hpke_p384_curve, rsa_os2ip(scalar), EcPoint::{
        x: px,
        y: py,
        inf: false,
      })
      rsa_i2osp(pt.x, 48)
    }
    0x12 => {
      let (px, py) = hpke_p521_point_deserialize(point)
      let pt = ec_scalar_mult(hpke_p521_curve, rsa_os2ip(scalar), EcPoint::{
        x: px,
        y: py,
        inf: false,
      })
      rsa_i2osp(pt.x, 66)
    }
    0x10 => {
      let (px, py) = hpke_p256_point_deserialize(point)
      let pt = ec_scalar_mult(p256_curve, rsa_os2ip(scalar), EcPoint::{
        x: px,
        y: py,
        inf: false,
      })
      rsa_i2osp(pt.x, 32)
    }
    0x20 => x25519(scalar, point)
    0x21 => x448(scalar, point)
    _ => abort("hpke: unsupported kem_id")
  }
}

///|
fn hpke_extract_and_expand(
  s : HpkeSuite,
  dh : Bytes,
  kem_context : Bytes,
) -> Bytes {
  let (nsecret, _) = hpke_kem_params(s)
  let eae_prk = hpke_labeled_extract(s, true, b"", b"eae_prk", dh)
  hpke_labeled_expand(s, true, eae_prk, b"shared_secret", kem_context, nsecret)
}

///|
/// HPKE Encap (derandomized: `ikm_e` supplies the ephemeral key
/// material). Returns (shared_secret, enc). v0.37.0.
pub fn hpke_encap(s : HpkeSuite, pk_r : Bytes, ikm_e : Bytes) -> (Bytes, Bytes) {
  let (pk_e, sk_e) = hpke_derive_key_pair(s, ikm_e)
  let dh = hpke_dh(s, sk_e, pk_r)
  let kem_context = concat_bytes(pk_e, pk_r)
  (hpke_extract_and_expand(s, dh, kem_context), pk_e)
}

///|
/// HPKE Decap. v0.37.0.
pub fn hpke_decap(
  s : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  pk_r : Bytes,
) -> Bytes {
  let dh = hpke_dh(s, sk_r, enc)
  hpke_extract_and_expand(s, dh, concat_bytes(enc, pk_r))
}

///|
/// HPKE AuthEncap (derandomized). v0.37.0.
pub fn hpke_auth_encap(
  s : HpkeSuite,
  pk_r : Bytes,
  sk_s : Bytes,
  ikm_e : Bytes,
) -> (Bytes, Bytes) {
  let (pk_e, sk_e) = hpke_derive_key_pair(s, ikm_e)
  let dh = hpke_dh(s, sk_e, pk_r)
  let dh2 = hpke_dh(s, sk_s, pk_r)
  let pk_s = match s.kem_id {
    0x11 => {
      let pt = ec_scalar_mult(
        hpke_p384_curve,
        rsa_os2ip(sk_s),
        ec_g_point(hpke_p384_curve),
      )
      hpke_p384_point_serialize(pt.x, pt.y)
    }
    0x12 => {
      let pt = ec_scalar_mult(
        hpke_p521_curve,
        rsa_os2ip(sk_s),
        ec_g_point(hpke_p521_curve),
      )
      hpke_p521_point_serialize(pt.x, pt.y)
    }
    0x10 => {
      let pt = ec_scalar_mult(
        p256_curve,
        rsa_os2ip(sk_s),
        ec_g_point(p256_curve),
      )
      hpke_p256_point_serialize(pt.x, pt.y)
    }
    0x20 => x25519_public_key(sk_s)
    0x21 => x448_public_key(sk_s)
    _ => abort("hpke: unsupported kem_id")
  }
  let kem_context = concat_all([pk_e, pk_r, pk_s])
  (hpke_extract_and_expand(s, concat_bytes(dh, dh2), kem_context), pk_e)
}

///|
/// HPKE AuthDecap. v0.37.0.
pub fn hpke_auth_decap(
  s : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  pk_r : Bytes,
  pk_s : Bytes,
) -> Bytes {
  let dh = hpke_dh(s, sk_r, enc)
  let dh2 = hpke_dh(s, sk_r, pk_s)
  let kem_context = concat_all([enc, pk_r, pk_s])
  hpke_extract_and_expand(s, concat_bytes(dh, dh2), kem_context)
}

// ==================== key schedule ====================

///|
/// HPKE encryption context: key, base nonce, exporter secret and the
/// sequence counter. Create with `hpke_setup_s` / `hpke_setup_r`. v0.37.0.
pub struct HpkeContext {
  suite : HpkeSuite
  key : Bytes
  base_nonce : Bytes
  exporter_secret : Bytes
  mut seq : Int64
}

///|
fn hpke_key_schedule(
  s : HpkeSuite,
  mode : Int,
  shared_secret : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> HpkeContext {
  let psk_id_hash = hpke_labeled_extract(s, false, b"", b"psk_id_hash", psk_id)
  let info_hash = hpke_labeled_extract(s, false, b"", b"info_hash", info)
  let ks_context = concat_all([
    Bytes::make(1, mode.to_byte()),
    psk_id_hash,
    info_hash,
  ])
  let secret = hpke_labeled_extract(s, false, shared_secret, b"secret", psk)
  let (nk, nn) = hpke_aead_params(s)
  let key = hpke_labeled_expand(s, false, secret, b"key", ks_context, nk)
  let base_nonce = hpke_labeled_expand(
    s, false, secret, b"base_nonce", ks_context, nn,
  )
  let exporter_secret = hpke_labeled_expand(
    s,
    false,
    secret,
    b"exp",
    ks_context,
    hpke_kdf_nh(s),
  )
  HpkeContext::{ suite: s, key, base_nonce, exporter_secret, seq: 0L, }
}

///|
/// HPKE sender setup (RFC 9180 §5.1): mode 0 = base, 1 = psk, 2 = auth,
/// 3 = auth+psk. For base/auth pass `psk`/`psk_id` empty; for
/// base/psk pass `sk_s`/`pk_s` empty (they are unused). Returns
/// (enc, context). v0.37.0.
pub fn hpke_setup_s(
  s : HpkeSuite,
  mode : Int,
  pk_r : Bytes,
  ikm_e : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
  sk_s : Bytes,
) -> (Bytes, HpkeContext) {
  let (shared_secret, enc) = if mode == 2 || mode == 3 {
    hpke_auth_encap(s, pk_r, sk_s, ikm_e)
  } else {
    hpke_encap(s, pk_r, ikm_e)
  }
  (enc, hpke_key_schedule(s, mode, shared_secret, info, psk, psk_id))
}

///|
/// HPKE receiver setup. `pk_r` is the receiver public key; `pk_s` the
/// sender public key (auth modes only). Returns the context. v0.37.0.
pub fn hpke_setup_r(
  s : HpkeSuite,
  mode : Int,
  sk_r : Bytes,
  pk_r : Bytes,
  enc : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
  pk_s : Bytes,
) -> HpkeContext {
  let shared_secret = if mode == 2 || mode == 3 {
    hpke_auth_decap(s, enc, sk_r, pk_r, pk_s)
  } else {
    hpke_decap(s, enc, sk_r, pk_r)
  }
  hpke_key_schedule(s, mode, shared_secret, info, psk, psk_id)
}

// ==================== AEAD context operations ====================

///|
fn hpke_compute_nonce(ctx : HpkeContext) -> Bytes {
  let (_, nn) = hpke_aead_params(ctx.suite)
  let seq_bytes = Array::make(nn, b'\x00')
  let mut v = ctx.seq
  let mut i = nn - 1
  while i >= 0 {
    seq_bytes[i] = (v & 0xFFL).to_int().to_byte()
    v = v >> 8
    i = i - 1
  }
  let out = Array::make(nn, b'\x00')
  for i in 0..<nn {
    out[i] = (ctx.base_nonce[i].to_int() ^ seq_bytes[i].to_int()).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// HPKE Seal (RFC 9180 §5.2): encrypts `pt` under the context's key
/// and current sequence number, then increments the counter. v0.37.0.
pub fn hpke_seal(ctx : HpkeContext, aad : Bytes, pt : Bytes) -> Bytes {
  let nonce = hpke_compute_nonce(ctx)
  ctx.seq = ctx.seq + 1L
  match ctx.suite.aead_id {
    1 => {
      let (ct, tag) = aes_gcm_encrypt(pt, ctx.key, nonce, aad)
      concat_bytes(ct, tag)
    }
    2 => {
      let (ct, tag) = aes_gcm_encrypt(pt, ctx.key, nonce, aad)
      concat_bytes(ct, tag)
    }
    3 => chacha20_poly1305_encrypt(ctx.key, nonce, aad, pt)
    _ => abort("hpke: unsupported aead_id")
  }
}

///|
/// HPKE Open: decrypts and authenticates `ct`; `None` on tag mismatch.
/// Increments the sequence counter either way. v0.37.0.
pub fn hpke_open(ctx : HpkeContext, aad : Bytes, ct : Bytes) -> Bytes? {
  let nonce = hpke_compute_nonce(ctx)
  ctx.seq = ctx.seq + 1L
  match ctx.suite.aead_id {
    1 => {
      if ct.length() < 16 {
        return None
      }
      let body = Bytes::from_array(ct.to_array()[0:ct.length() - 16])
      let tag = Bytes::from_array(ct.to_array()[ct.length() - 16:])
      match aes_gcm_decrypt(body, ctx.key, nonce, aad, tag) {
        (pt, true) => Some(pt)
        (_, false) => None
      }
    }
    2 => {
      if ct.length() < 16 {
        return None
      }
      let body = Bytes::from_array(ct.to_array()[0:ct.length() - 16])
      let tag = Bytes::from_array(ct.to_array()[ct.length() - 16:])
      match aes_gcm_decrypt(body, ctx.key, nonce, aad, tag) {
        (pt, true) => Some(pt)
        (_, false) => None
      }
    }
    3 =>
      if ct.length() < 16 {
        None
      } else {
        let body = Bytes::from_array(ct.to_array()[0:ct.length() - 16])
        let tag = Bytes::from_array(ct.to_array()[ct.length() - 16:])
        let otk = chacha20_poly1305_otk(ctx.key, nonce)
        let expected = poly1305(otk, poly1305_mac_data(aad, body))
        if bytes_equal(expected, tag) {
          Some(chacha20_xor(body, ctx.key, nonce, 1U))
        } else {
          None
        }
      }
    _ => abort("hpke: unsupported aead_id")
  }
}

///|
/// HPKE Export (RFC 9180 §5.3). v0.37.0.
pub fn hpke_export(
  ctx : HpkeContext,
  exporter_context : Bytes,
  len : Int,
) -> Bytes {
  hpke_labeled_expand(
    ctx.suite,
    false,
    ctx.exporter_secret,
    b"sec",
    exporter_context,
    len,
  )
}

// TEMP-NO: whitebox test — sequence-number carry (RFC 9180 A.1 seq 255/256).

///|
test "hpke seq carry 255->256 (whitebox)" {
  let suite = hpke_x25519_hkdf_sha256_aes128gcm
  let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e")
  let ikm_e = hex_to_bytes(
    "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
  )
  let pk_r = hex_to_bytes(
    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
  )
  let (enc, ctx_s) = hpke_setup_s(suite, 0, pk_r, ikm_e, info, b"", b"", b"")
  let _ = enc
  ctx_s.seq = 255L
  let ct255 = hpke_seal(
    ctx_s,
    hex_to_bytes("436f756e742d323535"),
    hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
  )
  assert_true(
    bytes_equal(
      ct255,
      hex_to_bytes(
        "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac" +
        "38d71c9e0a",
      ),
    ),
  )
  // nonce carry into byte 10: seq 256
  let ct256 = hpke_seal(
    ctx_s,
    hex_to_bytes("436f756e742d323536"),
    hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
  )
  assert_true(
    bytes_equal(
      ct256,
      hex_to_bytes(
        "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba" +
        "483a2df9f2",
      ),
    ),
  )
}
