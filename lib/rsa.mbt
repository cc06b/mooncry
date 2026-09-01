// ==================== RSA (RFC 8017: PKCS1-v1.5, OAEP, PSS) ====================
// Uses MoonBit core `@bigint` for modular exponentiation. SHA-256 based
// (OAEP MGF1-SHA256, PSS MGF1-SHA256, PKCS1-v1.5 sign over SHA-256).
// Verified against pycryptodome (Crypto.PublicKey.RSA + PKCS1_v1_5/OAEP +
// pkcs1_15/pss).
//
// No RNG: encryption (PKCS1-v1.5 padding PS, OAEP seed, PSS salt) takes
// caller-supplied randomness — obtain it from a CSPRNG. Decryption, sign
// verification, and PKCS1-v1.5 signing are deterministic.

// SHA-256 DigestInfo prefix (RFC 8017 §9.2): SEQUENCE { SEQUENCE { OID, NULL },
// OCTET STRING(32) } — 19 bytes, then the 32-byte hash.

///|
let rsa_digestinfo_sha256 : Bytes = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

///|
/// SHA-1 DigestInfo prefix (RFC 8017 §9.2 note 1)
let rsa_digestinfo_sha1 : Bytes = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

///|
/// SHA-384 DigestInfo prefix (RFC 8017 §9.2 note 1)
let rsa_digestinfo_sha384 : Bytes = b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"

///|
/// SHA-512 DigestInfo prefix (RFC 8017 §9.2 note 1)
let rsa_digestinfo_sha512 : Bytes = b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"

///|
/// Hash choice for the `_with` RSA signature variants (v0.22.0). The plain
/// (non-`_with`) functions are fixed to SHA-256 for compatibility.
pub enum RsaHash {
  Sha1
  Sha256
  Sha384
  Sha512
}

///|
/// All supported hash variants of the `_with` RSA signature API.
pub let rsa_hash_variants : Array[RsaHash] = [
  RsaHash::Sha1,
  RsaHash::Sha256,
  RsaHash::Sha384,
  RsaHash::Sha512,
]

///|
/// SHA-1 selector for the `_with` RSA signature API (enum constructors are
/// not visible to blackbox `*_test.mbt` files, so variants are exported as
/// constants).
pub let rsa_hash_sha1 : RsaHash = RsaHash::Sha1

///|
/// SHA-256 selector for the `_with` RSA signature API.
pub let rsa_hash_sha256 : RsaHash = RsaHash::Sha256

///|
/// SHA-384 selector for the `_with` RSA signature API.
pub let rsa_hash_sha384 : RsaHash = RsaHash::Sha384

///|
/// SHA-512 selector for the `_with` RSA signature API.
pub let rsa_hash_sha512 : RsaHash = RsaHash::Sha512

///|
fn rsa_hash_len(hash : RsaHash) -> Int {
  match hash {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn rsa_hash_apply(hash : RsaHash, data : Bytes) -> Bytes {
  match hash {
    Sha1 => sha1(data)
    Sha256 => sha256(data)
    Sha384 => sha384(data)
    Sha512 => sha512(data)
  }
}

///|
fn rsa_digestinfo(hash : RsaHash) -> Bytes {
  match hash {
    Sha1 => rsa_digestinfo_sha1
    Sha256 => rsa_digestinfo_sha256
    Sha384 => rsa_digestinfo_sha384
    Sha512 => rsa_digestinfo_sha512
  }
}

///|
fn rsa_os2ip(bytes : Bytes) -> @bigint.BigInt {
  @bigint.BigInt::from_octets(bytes)
}

///|
fn rsa_i2osp(x : @bigint.BigInt, length : Int) -> Bytes {
  x.to_octets(length~)
}

///|
fn rsa_ep(
  m : @bigint.BigInt,
  n : @bigint.BigInt,
  e : @bigint.BigInt,
) -> @bigint.BigInt {
  m.pow(e, modulus=n)
}

///|
fn rsa_dp(
  c : @bigint.BigInt,
  n : @bigint.BigInt,
  d : @bigint.BigInt,
) -> @bigint.BigInt {
  c.pow(d, modulus=n)
}

///|
/// RSA private-key operation via CRT (RFC 8017 §5.1.2): two half-width
/// exponentiations (mod p, mod q) instead of one full-width (mod n) —
/// ~3.5-4x faster on typical keys since BigInt mul is super-linear.
fn rsa_dp_crt(
  c : @bigint.BigInt,
  p : @bigint.BigInt,
  q : @bigint.BigInt,
  dp : @bigint.BigInt,
  dq : @bigint.BigInt,
  qinv : @bigint.BigInt,
) -> @bigint.BigInt {
  let m1 = c.pow(dp, modulus=p)
  let m2 = c.pow(dq, modulus=q)
  // h = qInv * (m1 - m2) mod p ; keep non-negative (BigInt % of a negative
  // operand returns negative in MoonBit).
  let h = (m1 + p - m2) % p * qinv % p
  m2 + q * h
}

///|
/// Bit length of an OS2IP-encoded (big-endian, possibly zero-padded)
/// integer. Replaces an old `to_string(radix=2)` trick that allocated a
/// ~k-byte string per call.
fn rsa_bit_len(bytes : Bytes) -> Int {
  let len = bytes.length()
  let mut i = 0
  while i < len && bytes[i] == b'\x00' {
    i = i + 1
  }
  if i == len {
    return 0
  }
  let mut v = bytes[i].to_int()
  let mut bits = 0
  while v > 0 {
    bits = bits + 1
    v = v >> 1
  }
  8 * (len - i - 1) + bits
}

///|
/// MGF1 (RFC 8017 §B.2.1) with a configurable hash: produces `length` mask
/// bytes from a seed by concatenating H(seed || counter) for counter =
/// 0,1,2,...
fn rsa_mgf1(hash : RsaHash, seed : Bytes, length : Int) -> Bytes {
  let h_len = rsa_hash_len(hash)
  let out = Array::make(length, b'\x00')
  let mut off = 0
  let mut counter = 0
  while off < length {
    let ctr_bytes = Array::make(4, b'\x00')
    ctr_bytes[0] = ((counter >> 24) & 0xFF).to_byte()
    ctr_bytes[1] = ((counter >> 16) & 0xFF).to_byte()
    ctr_bytes[2] = ((counter >> 8) & 0xFF).to_byte()
    ctr_bytes[3] = (counter & 0xFF).to_byte()
    let block = rsa_hash_apply(
      hash,
      concat_bytes(seed, Bytes::from_array(ctr_bytes[:])),
    )
    let take = if length - off < h_len { length - off } else { h_len }
    for j in 0..<take {
      out[off + j] = block[j]
    }
    off = off + take
    counter = counter + 1
  }
  Bytes::from_array(out[:])
}

///|
fn rsa_xor_bytes(a : Array[Byte], b : Bytes, a_off : Int, len : Int) -> Unit {
  for i in 0..<len {
    a[a_off + i] = (a[a_off + i].to_int() ^ b[i].to_int()).to_byte()
  }
}

// ==================== PKCS1-v1.5 (RFC 8017 §7.2 / §8.2) ====================

///|
/// RSAES-PKCS1-v1.5 encrypt. `rand_ps` must be `k - message.length() - 3`
/// nonzero random bytes (caller's CSPRNG output). Returns the k-byte
/// ciphertext.
pub fn rsa_pkcs1_v15_encrypt(
  message : Bytes,
  n : Bytes,
  e : Bytes,
  rand_ps : Bytes,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  if rand_ps.length() != k - message.length() - 3 {
    abort("rsa_pkcs1_v15_encrypt: rand_ps length must be k - msglen - 3")
  }
  // EM = 0x00 || 0x02 || PS || 0x00 || M
  let em = Array::make(k, b'\x00')
  em[0] = b'\x00'
  em[1] = b'\x02'
  for i in 0..<rand_ps.length() {
    em[2 + i] = rand_ps[i]
  }
  em[2 + rand_ps.length()] = b'\x00'
  for i in 0..<message.length() {
    em[3 + rand_ps.length() + i] = message[i]
  }
  let m = rsa_os2ip(Bytes::from_array(em[:]))
  let c = rsa_ep(m, nn, ee)
  rsa_i2osp(c, k)
}

///|
/// Unpad a PKCS1-v1.5 encoded message EM = 0x00 || 0x02 || PS || 0x00 || M.
fn rsa_pkcs1_v15_unpad(em : Bytes, k : Int) -> Bytes {
  if em[0] != b'\x00' || em[1] != b'\x02' {
    abort("rsa_pkcs1_v15 decrypt: invalid padding")
  }
  // PS is nonzero; find the 0x00 separator.
  let mut sep = 2
  while sep < k && em[sep] != b'\x00' {
    sep = sep + 1
  }
  if sep < 2 + 8 || sep >= k {
    abort(
      "rsa_pkcs1_v15 decrypt: invalid padding (no separator or PS too short)",
    )
  }
  let msg_len = k - sep - 1
  let out = Array::make(msg_len, b'\x00')
  for i in 0..<msg_len {
    out[i] = em[sep + 1 + i]
  }
  Bytes::from_array(out[:])
}

///|
/// RSAES-PKCS1-v1.5 decrypt. Returns the recovered message. Aborts if the
/// ciphertext length != modulus length or the padding is malformed.
pub fn rsa_pkcs1_v15_decrypt(ct : Bytes, n : Bytes, d : Bytes) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  if ct.length() != k {
    abort("rsa_pkcs1_v15_decrypt: ciphertext length must equal modulus length")
  }
  let c = rsa_os2ip(ct)
  let m = rsa_dp(c, nn, dd)
  let em = rsa_i2osp(m, k)
  rsa_pkcs1_v15_unpad(em, k)
}

///|
/// RSAES-PKCS1-v1.5 decrypt with the CRT private key (p, q, dP, dQ, qInv)
/// instead of (n, d) — ~3.5-4x faster. The modulus is n = p*q; its byte
/// length is p.length() + q.length(). Same behavior as `rsa_pkcs1_v15_decrypt`.
pub fn rsa_pkcs1_v15_decrypt_crt(
  ct : Bytes,
  p : Bytes,
  q : Bytes,
  dp : Bytes,
  dq : Bytes,
  qinv : Bytes,
) -> Bytes {
  let k = p.length() + q.length()
  if ct.length() != k {
    abort(
      "rsa_pkcs1_v15_decrypt_crt: ciphertext length must equal modulus length",
    )
  }
  let c = rsa_os2ip(ct)
  let m = rsa_dp_crt(
    c,
    rsa_os2ip(p),
    rsa_os2ip(q),
    rsa_os2ip(dp),
    rsa_os2ip(dq),
    rsa_os2ip(qinv),
  )
  let em = rsa_i2osp(m, k)
  rsa_pkcs1_v15_unpad(em, k)
}

///|
/// Build the PKCS1-v1.5 encoded message for SHA-256:
/// EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo || H.
fn rsa_pkcs1_v15_sign_em(message : Bytes, k : Int, hash : RsaHash) -> Bytes {
  // T = DigestInfo || H
  let h = rsa_hash_apply(hash, message)
  let di = rsa_digestinfo(hash)
  let t_len = di.length() + h.length()
  if k < t_len + 11 {
    abort("rsa_pkcs1_v15 sign: modulus too small for the chosen hash")
  }
  let em = Array::make(k, b'\x00')
  em[0] = b'\x00'
  em[1] = b'\x01'
  let ps_len = k - t_len - 3
  for i in 0..<ps_len {
    em[2 + i] = b'\xff'
  }
  em[2 + ps_len] = b'\x00'
  for i in 0..<di.length() {
    em[3 + ps_len + i] = di[i]
  }
  for i in 0..<h.length() {
    em[3 + ps_len + di.length() + i] = h[i]
  }
  Bytes::from_array(em[:])
}

///|
/// RSASSA-PKCS1-v1.5 sign (SHA-256). Deterministic. `n`/`d` are the modulus
/// and private-exponent octets. Returns the k-byte signature.
pub fn rsa_pkcs1_v15_sign(message : Bytes, n : Bytes, d : Bytes) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let em = rsa_pkcs1_v15_sign_em(message, k, RsaHash::Sha256)
  let m = rsa_os2ip(em)
  let s = rsa_dp(m, nn, dd)
  rsa_i2osp(s, k)
}

///|
/// RSASSA-PKCS1-v1.5 sign (SHA-256) with the CRT private key (p, q, dP, dQ,
/// qInv) — ~3.5-4x faster. Deterministic and byte-identical to
/// `rsa_pkcs1_v15_sign` for the same key.
pub fn rsa_pkcs1_v15_sign_crt(
  message : Bytes,
  p : Bytes,
  q : Bytes,
  dp : Bytes,
  dq : Bytes,
  qinv : Bytes,
) -> Bytes {
  let k = p.length() + q.length()
  let em = rsa_pkcs1_v15_sign_em(message, k, RsaHash::Sha256)
  let m = rsa_os2ip(em)
  let s = rsa_dp_crt(
    m,
    rsa_os2ip(p),
    rsa_os2ip(q),
    rsa_os2ip(dp),
    rsa_os2ip(dq),
    rsa_os2ip(qinv),
  )
  rsa_i2osp(s, k)
}

///|
/// RSASSA-PKCS1-v1.5 verify (SHA-256). Returns true iff the signature is
/// valid for `message` under the public key (n, e). Constant-time-ish is not
/// guaranteed; this is a verification path (not secret-dependent).
pub fn rsa_pkcs1_v15_verify(
  message : Bytes,
  sig : Bytes,
  n : Bytes,
  e : Bytes,
) -> Bool {
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  if sig.length() != k {
    return false
  }
  let s = rsa_os2ip(sig)
  let m = rsa_ep(s, nn, ee)
  let em = rsa_i2osp(m, k)
  // Reconstruct expected EM.
  let h_len = rsa_hash_len(RsaHash::Sha256)
  let t_len = rsa_digestinfo(RsaHash::Sha256).length() + h_len
  if k < t_len + 11 {
    return false
  }
  let expected = rsa_pkcs1_v15_sign_em(message, k, RsaHash::Sha256)
  bytes_equal(em, expected)
}

///|
/// RSASSA-PKCS1-v1.5 sign with a caller-chosen hash (v0.22.0; SHA-1,
/// SHA-256, SHA-384 or SHA-512 DigestInfo per RFC 8017 §9.2).
/// Deterministic.
pub fn rsa_pkcs1_v15_sign_with(
  message : Bytes,
  n : Bytes,
  d : Bytes,
  hash : RsaHash,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let em = rsa_pkcs1_v15_sign_em(message, k, hash)
  let m = rsa_os2ip(em)
  let s = rsa_dp(m, nn, dd)
  rsa_i2osp(s, k)
}

///|
/// RSASSA-PKCS1-v1.5 verify with a caller-chosen hash (v0.22.0).
pub fn rsa_pkcs1_v15_verify_with(
  message : Bytes,
  sig : Bytes,
  n : Bytes,
  e : Bytes,
  hash : RsaHash,
) -> Bool {
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  if sig.length() != k {
    return false
  }
  let t_len = rsa_digestinfo(hash).length() + rsa_hash_len(hash)
  if k < t_len + 11 {
    return false
  }
  let s = rsa_os2ip(sig)
  let m = rsa_ep(s, nn, ee)
  let em = rsa_i2osp(m, k)
  let expected = rsa_pkcs1_v15_sign_em(message, k, hash)
  bytes_equal(em, expected)
}

// ==================== RSA-OAEP (RFC 8017 §7.1) ====================

///|
/// Build the OAEP encoded message EM = 0x00 || maskedSeed || maskedDB with
/// a caller-chosen hash (also used for MGF1).
fn rsa_oaep_encrypt_em(
  message : Bytes,
  k : Int,
  seed : Bytes,
  label : Bytes,
  hash : RsaHash,
) -> Bytes {
  let h_len = rsa_hash_len(hash)
  if k < message.length() + 2 * h_len + 2 {
    abort("rsa_oaep encrypt: message too long for modulus")
  }
  let l_hash = rsa_hash_apply(hash, label)
  // DB = lHash || PS(0x00...) || 0x01 || M
  let db_len = k - h_len - 1
  let db = Array::make(db_len, b'\x00')
  for i in 0..<h_len {
    db[i] = l_hash[i]
  }
  let ps_len = db_len - h_len - 1 - message.length()
  db[h_len + ps_len] = b'\x01'
  for i in 0..<message.length() {
    db[h_len + ps_len + 1 + i] = message[i]
  }
  // dbMask = MGF1(seed, db_len); maskedDB = DB xor dbMask
  let db_mask = rsa_mgf1(hash, seed, db_len)
  rsa_xor_bytes(db, db_mask, 0, db_len)
  // seedMask = MGF1(maskedDB, h_len); maskedSeed = seed xor seedMask
  let masked_db = Bytes::from_array(db[:])
  let seed_mask = rsa_mgf1(hash, masked_db, h_len)
  let masked_seed = Array::make(h_len, b'\x00')
  for i in 0..<h_len {
    masked_seed[i] = (seed[i].to_int() ^ seed_mask[i].to_int()).to_byte()
  }
  // EM = 0x00 || maskedSeed || maskedDB
  let em = Array::make(k, b'\x00')
  em[0] = b'\x00'
  for i in 0..<h_len {
    em[1 + i] = masked_seed[i]
  }
  for i in 0..<db_len {
    em[1 + h_len + i] = masked_db[i]
  }
  Bytes::from_array(em[:])
}

///|
/// RSAES-OAEP encrypt (SHA-256, MGF1-SHA256). `seed` must be 32 random bytes
/// (caller's CSPRNG). `label` is hashed into lHash (use b"" for the common
/// case). Returns the k-byte ciphertext.
pub fn rsa_oaep_encrypt(
  message : Bytes,
  n : Bytes,
  e : Bytes,
  seed : Bytes,
  label : Bytes,
) -> Bytes {
  if seed.length() != 32 {
    abort("rsa_oaep_encrypt: seed must be 32 bytes (SHA-256)")
  }
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  let em = rsa_oaep_encrypt_em(message, k, seed, label, RsaHash::Sha256)
  let m = rsa_os2ip(em)
  let c = rsa_ep(m, nn, ee)
  rsa_i2osp(c, k)
}

///|
/// RSAES-OAEP encrypt with a caller-chosen hash (v0.23.0; SHA-1, SHA-256,
/// SHA-384 or SHA-512) for both lHash and MGF1. `seed` must be exactly
/// `rsa_hash_len(hash)` random bytes from the caller's CSPRNG. Note:
/// SHA-512 needs a modulus of at least 2048 bits (k >= 2*hLen + 2 + |M|).
pub fn rsa_oaep_encrypt_with(
  message : Bytes,
  n : Bytes,
  e : Bytes,
  seed : Bytes,
  label : Bytes,
  hash : RsaHash,
) -> Bytes {
  if seed.length() != rsa_hash_len(hash) {
    abort("rsa_oaep_encrypt_with: seed length must match the hash output size")
  }
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  let em = rsa_oaep_encrypt_em(message, k, seed, label, hash)
  let m = rsa_os2ip(em)
  let c = rsa_ep(m, nn, ee)
  rsa_i2osp(c, k)
}

///|
/// Unpad an OAEP encoded message EM = Y || maskedSeed || maskedDB
/// (SHA-256, MGF1-SHA256).
fn rsa_oaep_unpad(em : Bytes, k : Int, label : Bytes, hash : RsaHash) -> Bytes {
  let h_len = rsa_hash_len(hash)
  let l_hash = rsa_hash_apply(hash, label)
  let masked_seed = Array::make(h_len, b'\x00')
  for i in 0..<h_len {
    masked_seed[i] = em[1 + i]
  }
  let db_len = k - h_len - 1
  let masked_db = Array::make(db_len, b'\x00')
  for i in 0..<db_len {
    masked_db[i] = em[1 + h_len + i]
  }
  // seedMask = MGF1(maskedDB, h_len); seed = maskedSeed xor seedMask
  let seed_mask = rsa_mgf1(hash, Bytes::from_array(masked_db[:]), h_len)
  let seed = Array::make(h_len, b'\x00')
  for i in 0..<h_len {
    seed[i] = (masked_seed[i].to_int() ^ seed_mask[i].to_int()).to_byte()
  }
  // dbMask = MGF1(seed, db_len); DB = maskedDB xor dbMask
  let db_mask = rsa_mgf1(hash, Bytes::from_array(seed[:]), db_len)
  rsa_xor_bytes(masked_db, db_mask, 0, db_len)
  // DB = lHash' || PS || 0x01 || M
  for i in 0..<h_len {
    if masked_db[i] != l_hash[i] {
      abort("rsa_oaep decrypt: lHash mismatch (decryption error)")
    }
  }
  let mut idx = h_len
  while idx < db_len && masked_db[idx] == b'\x00' {
    idx = idx + 1
  }
  if idx >= db_len || masked_db[idx] != b'\x01' {
    abort("rsa_oaep decrypt: invalid padding")
  }
  idx = idx + 1
  let msg_len = db_len - idx
  let out = Array::make(msg_len, b'\x00')
  for i in 0..<msg_len {
    out[i] = masked_db[idx + i]
  }
  Bytes::from_array(out[:])
}

///|
/// RSAES-OAEP decrypt (SHA-256, MGF1-SHA256). Returns the recovered message;
/// aborts on length/padding errors (do not rely on the abort message for
/// distinguishing failure causes in a security context).
pub fn rsa_oaep_decrypt(
  ct : Bytes,
  n : Bytes,
  d : Bytes,
  label : Bytes,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let h_len = 32
  if ct.length() != k || k < 2 * h_len + 2 {
    abort("rsa_oaep_decrypt: invalid ciphertext length")
  }
  let c = rsa_os2ip(ct)
  let m = rsa_dp(c, nn, dd)
  let em = rsa_i2osp(m, k)
  rsa_oaep_unpad(em, k, label, RsaHash::Sha256)
}

///|
/// RSAES-OAEP decrypt with a caller-chosen hash (v0.23.0); must match the
/// encryptor's hash and MGF1 choice. Returns the recovered message; aborts
/// on length/padding errors.
pub fn rsa_oaep_decrypt_with(
  ct : Bytes,
  n : Bytes,
  d : Bytes,
  label : Bytes,
  hash : RsaHash,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let h_len = rsa_hash_len(hash)
  if ct.length() != k || k < 2 * h_len + 2 {
    abort("rsa_oaep_decrypt_with: invalid ciphertext length")
  }
  let c = rsa_os2ip(ct)
  let m = rsa_dp(c, nn, dd)
  let em = rsa_i2osp(m, k)
  rsa_oaep_unpad(em, k, label, hash)
}

///|
/// RSAES-OAEP decrypt (SHA-256) with the CRT private key (p, q, dP, dQ,
/// qInv) — ~3.5-4x faster. The modulus is n = p*q; its byte length is
/// p.length() + q.length(). Same behavior as `rsa_oaep_decrypt`.
pub fn rsa_oaep_decrypt_crt(
  ct : Bytes,
  p : Bytes,
  q : Bytes,
  dp : Bytes,
  dq : Bytes,
  qinv : Bytes,
  label : Bytes,
) -> Bytes {
  let k = p.length() + q.length()
  let h_len = 32
  if ct.length() != k || k < 2 * h_len + 2 {
    abort("rsa_oaep_decrypt_crt: invalid ciphertext length")
  }
  let c = rsa_os2ip(ct)
  let m = rsa_dp_crt(
    c,
    rsa_os2ip(p),
    rsa_os2ip(q),
    rsa_os2ip(dp),
    rsa_os2ip(dq),
    rsa_os2ip(qinv),
  )
  let em = rsa_i2osp(m, k)
  rsa_oaep_unpad(em, k, label, RsaHash::Sha256)
}

// ==================== RSASSA-PSS (RFC 8017 §8.1, SHA-256) ====================

///|
/// Build the PSS encoded message (SHA-256, MGF1-SHA256, RFC 8017 §9.1.1).
fn rsa_pss_encode_em(
  message : Bytes,
  salt : Bytes,
  em_len : Int,
  em_bits : Int,
  hash : RsaHash,
) -> Bytes {
  let s_len = salt.length()
  let h_len = rsa_hash_len(hash)
  if em_len < h_len + s_len + 2 {
    abort("rsa_pss sign: modulus too small for salt")
  }
  let m_hash = rsa_hash_apply(hash, message)
  // M' = (0x00 * 8) || mHash || salt ; H = Hash(M')
  let mp = Array::make(8 + h_len + s_len, b'\x00')
  for i in 0..<h_len {
    mp[8 + i] = m_hash[i]
  }
  for i in 0..<s_len {
    mp[8 + h_len + i] = salt[i]
  }
  let h = rsa_hash_apply(hash, Bytes::from_array(mp[:]))
  // DB = PS(0x00 * (em_len - s_len - h_len - 1)) || 0x01 || salt
  let db_len = em_len - h_len - 1
  let db = Array::make(db_len, b'\x00')
  db[db_len - s_len - 1] = b'\x01'
  for i in 0..<s_len {
    db[db_len - s_len + i] = salt[i]
  }
  // dbMask = MGF1(H, db_len); maskedDB = DB xor dbMask
  let db_mask = rsa_mgf1(hash, h, db_len)
  rsa_xor_bytes(db, db_mask, 0, db_len)
  // Set the leftmost (8*em_len - em_bits) bits of maskedDB[0] to 0.
  let bits_to_clear = 8 * em_len - em_bits
  if bits_to_clear > 0 {
    db[0] = (db[0].to_int() & (0xFF >> bits_to_clear)).to_byte()
  }
  // EM = maskedDB || H || 0xbc
  let em = Array::make(em_len, b'\x00')
  for i in 0..<db_len {
    em[i] = db[i]
  }
  for i in 0..<h_len {
    em[db_len + i] = h[i]
  }
  em[em_len - 1] = b'\xbc'
  Bytes::from_array(em[:])
}

///|
/// RSASSA-PSS sign (SHA-256, MGF1-SHA256). `salt` is the caller-supplied
/// random salt (any length; 32 is typical). Returns the k-byte signature.
pub fn rsa_pss_sign(
  message : Bytes,
  n : Bytes,
  d : Bytes,
  salt : Bytes,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let em_bits = rsa_bit_len(n) - 1 // RFC 8017: emBits = modBits - 1
  let em = rsa_pss_encode_em(message, salt, k, em_bits, RsaHash::Sha256)
  let m = rsa_os2ip(em)
  let s = rsa_dp(m, nn, dd)
  rsa_i2osp(s, k)
}

///|
/// RSASSA-PSS sign (SHA-256) with the CRT private key (p, q, dP, dQ, qInv)
/// — ~3.5-4x faster. Deterministic and byte-identical to `rsa_pss_sign`
/// for the same key and salt.
pub fn rsa_pss_sign_crt(
  message : Bytes,
  p : Bytes,
  q : Bytes,
  dp : Bytes,
  dq : Bytes,
  qinv : Bytes,
  salt : Bytes,
) -> Bytes {
  let k = p.length() + q.length()
  let pp = rsa_os2ip(p)
  let qq = rsa_os2ip(q)
  let n_bytes = rsa_i2osp(pp * qq, k)
  let em_bits = rsa_bit_len(n_bytes) - 1 // RFC 8017: emBits = modBits - 1
  let em = rsa_pss_encode_em(message, salt, k, em_bits, RsaHash::Sha256)
  let m = rsa_os2ip(em)
  let s = rsa_dp_crt(m, pp, qq, rsa_os2ip(dp), rsa_os2ip(dq), rsa_os2ip(qinv))
  rsa_i2osp(s, k)
}

///|
/// Generic PSS verification over an already-decoded EM (shared by the
/// fixed-SHA-256 and `_with` paths).
fn rsa_pss_verify_em(
  message : Bytes,
  em : Bytes,
  em_len : Int,
  em_bits : Int,
  salt_len : Int,
  hash : RsaHash,
) -> Bool {
  let h_len = rsa_hash_len(hash)
  if em_len < h_len + salt_len + 2 {
    return false
  }
  let bits_to_clear = 8 * em_len - em_bits
  if bits_to_clear > 0 &&
    (em[0].to_int() & ((0xFF << (8 - bits_to_clear)) & 0xFF)) != 0 {
    return false
  }
  if em[em_len - 1] != b'\xbc' {
    return false
  }
  let db_len = em_len - h_len - 1
  let masked_db = Array::make(db_len, b'\x00')
  for i in 0..<db_len {
    masked_db[i] = em[i]
  }
  let h = Array::make(h_len, b'\x00')
  for i in 0..<h_len {
    h[i] = em[db_len + i]
  }
  // dbMask = MGF1(H, db_len); DB = maskedDB xor dbMask
  let db_mask = rsa_mgf1(hash, Bytes::from_array(h[:]), db_len)
  rsa_xor_bytes(masked_db, db_mask, 0, db_len)
  if bits_to_clear > 0 {
    masked_db[0] = (masked_db[0].to_int() & (0xFF >> bits_to_clear)).to_byte()
  }
  // DB = PS(0x00..) || 0x01 || salt
  let mut idx = 0
  while idx < db_len - salt_len - 1 && masked_db[idx] == b'\x00' {
    idx = idx + 1
  }
  if idx >= db_len || masked_db[idx] != b'\x01' {
    return false
  }
  idx = idx + 1
  let salt_start = idx
  // M' = (0x00*8) || mHash || salt ; H' = Hash(M')
  let m_hash = rsa_hash_apply(hash, message)
  let mp = Array::make(8 + h_len + salt_len, b'\x00')
  for i in 0..<h_len {
    mp[8 + i] = m_hash[i]
  }
  for i in 0..<salt_len {
    mp[8 + h_len + i] = masked_db[salt_start + i]
  }
  let h_prime = rsa_hash_apply(hash, Bytes::from_array(mp[:]))
  bytes_equal(Bytes::from_array(h[:]), h_prime)
}

///|
/// RSASSA-PSS verify (SHA-256, MGF1-SHA256). `salt_len` is the expected salt
/// length. Returns true iff the signature is valid.
pub fn rsa_pss_verify(
  message : Bytes,
  sig : Bytes,
  n : Bytes,
  e : Bytes,
  salt_len : Int,
) -> Bool {
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  let h_len = 32
  let em_bits = rsa_bit_len(n) - 1 // RFC 8017: emBits = modBits - 1
  let em_len = k
  if sig.length() != k || em_len < h_len + salt_len + 2 {
    return false
  }
  let s = rsa_os2ip(sig)
  let m = rsa_ep(s, nn, ee)
  let em = rsa_i2osp(m, em_len)
  rsa_pss_verify_em(message, em, em_len, em_bits, salt_len, RsaHash::Sha256)
}

// ==================== multi-hash signature API (v0.22.0) ====================

///|
/// RSASSA-PSS sign with a caller-chosen hash (SHA-1, SHA-256, SHA-384 or
/// SHA-512) for both the message hash and MGF1, per RFC 8017 §8.1.
/// `salt` is caller-supplied (any length; the hash output size is typical).
pub fn rsa_pss_sign_with(
  message : Bytes,
  n : Bytes,
  d : Bytes,
  salt : Bytes,
  hash : RsaHash,
) -> Bytes {
  let nn = rsa_os2ip(n)
  let dd = rsa_os2ip(d)
  let k = n.length()
  let em_bits = rsa_bit_len(n) - 1 // RFC 8017: emBits = modBits - 1
  let em = rsa_pss_encode_em(message, salt, k, em_bits, hash)
  let m = rsa_os2ip(em)
  let s = rsa_dp(m, nn, dd)
  rsa_i2osp(s, k)
}

///|
/// RSASSA-PSS verify with a caller-chosen hash (must match the signer's
/// hash and MGF1 choice). `salt_len` is the expected salt length.
pub fn rsa_pss_verify_with(
  message : Bytes,
  sig : Bytes,
  n : Bytes,
  e : Bytes,
  salt_len : Int,
  hash : RsaHash,
) -> Bool {
  let nn = rsa_os2ip(n)
  let ee = rsa_os2ip(e)
  let k = n.length()
  let h_len = rsa_hash_len(hash)
  let em_bits = rsa_bit_len(n) - 1 // RFC 8017: emBits = modBits - 1
  let em_len = k
  if sig.length() != k || em_len < h_len + salt_len + 2 {
    return false
  }
  let s = rsa_os2ip(sig)
  let m = rsa_ep(s, nn, ee)
  let em = rsa_i2osp(m, em_len)
  rsa_pss_verify_em(message, em, em_len, em_bits, salt_len, hash)
}
