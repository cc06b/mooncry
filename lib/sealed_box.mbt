// ==================== Sealed Box (composite AEAD envelope) ====================
// A self-contained authenticated-encryption envelope composing HKDF-SHA256
// (key derivation) + AES-256-GCM (AEAD). Demonstrates how the primitives
// compose into a real protocol.
//
// Wire format:  version(1) || nonce(12) || ciphertext || tag(16)
//   - version = 0x01
//   - key      = HKDF-SHA256(salt=ctx, ikm=master_key, info="mooncry-sealedbox/v1", 32)
//   - nonce must be unique per (master_key, message); never reuse a (key, nonce).
//
// The master key may be any length >= 16 bytes; it is stretched to a 32-byte
// AES-256 key by HKDF. `nonce` must be 12 bytes.

///|
let sealed_box_info : Bytes = b"mooncry-sealedbox/v1"

///|
/// Seal `plaintext` into a versioned envelope. Returns the envelope bytes.
/// `nonce` must be 12 bytes; `master_key` >= 16 bytes; both abort otherwise.
pub fn sealed_box_seal(
  master_key : Bytes,
  nonce : Bytes,
  plaintext : Bytes,
  aad : Bytes,
  context : Bytes,
) -> Bytes {
  if master_key.length() < 16 {
    abort("sealed_box_seal: master_key must be >= 16 bytes")
  }
  if nonce.length() != 12 {
    abort("sealed_box_seal: nonce must be 12 bytes")
  }
  let key = hkdf_sha256(context, master_key, sealed_box_info, 32)
  let (ct, tag) = aes_gcm_encrypt(plaintext, key, nonce, aad)
  // version(1) || nonce(12) || ct || tag(16)
  let total = 1 + 12 + ct.length() + 16
  let env = Array::make(total, b'\x00')
  env[0] = b'\x01'
  for i in 0..<12 {
    env[1 + i] = nonce[i]
  }
  for i in 0..<ct.length() {
    env[13 + i] = ct[i]
  }
  for i in 0..<16 {
    env[13 + ct.length() + i] = tag[i]
  }
  Bytes::from_array(env[:])
}

///|
/// Open a sealed-box envelope. Returns `Ok(plaintext)` if the version is
/// supported and the GCM tag verifies, `Err(msg)` otherwise.
pub fn sealed_box_open(
  master_key : Bytes,
  envelope : Bytes,
  aad : Bytes,
  context : Bytes,
) -> Result[Bytes, String] {
  if envelope.length() < 1 + 12 + 16 {
    return Err("sealed_box_open: envelope too short")
  }
  if envelope[0] != b'\x01' {
    return Err("sealed_box_open: unsupported version")
  }
  let nonce = Array::make(12, b'\x00')
  for i in 0..<12 {
    nonce[i] = envelope[1 + i]
  }
  let ct_len = envelope.length() - 1 - 12 - 16
  let ct = Array::make(ct_len, b'\x00')
  for i in 0..<ct_len {
    ct[i] = envelope[13 + i]
  }
  let tag = Array::make(16, b'\x00')
  for i in 0..<16 {
    tag[i] = envelope[13 + ct_len + i]
  }
  let key = hkdf_sha256(context, master_key, sealed_box_info, 32)
  let (pt, ok) = aes_gcm_decrypt(
    Bytes::from_array(ct[:]),
    key,
    Bytes::from_array(nonce[:]),
    aad,
    Bytes::from_array(tag[:]),
  )
  if ok {
    Ok(pt)
  } else {
    Err("sealed_box_open: authentication failed")
  }
}
