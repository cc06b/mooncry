///|
/// GMAC (NIST SP 800-38D): the authentication-only specialization of
/// AES-GCM — GHASH over the AAD with an empty plaintext, using the
/// same 96-bit IV and key rules as `aes_gcm_encrypt`.

///|
/// Compute the 16-byte GMAC tag for `aad` under `key` and 12-byte
/// `iv`. Equivalent to the tag of AES-GCM encrypting an empty
/// plaintext with the same AAD.
pub fn gmac(key : Bytes, iv : Bytes, aad : Bytes) -> Bytes {
  let (_, tag) = aes_gcm_encrypt(b"", key, iv, aad)
  tag
}

///|
/// Verify a 16-byte GMAC tag in constant time
pub fn gmac_verify(key : Bytes, iv : Bytes, aad : Bytes, tag : Bytes) -> Bool {
  bytes_equal(gmac(key, iv, aad), tag)
}

///|
/// GMAC with an IV of ANY length (SP 800-38D §8.2.1, v0.24.0). 12-byte IVs
/// take the fast path (`gmac`); other lengths derive J0 via GHASH. Equal
/// to the AES-GCM tag of an empty plaintext with the same key/iv/aad.
/// Avoid empty IVs (valid per spec but strongly discouraged).
pub fn gmac_iv(key : Bytes, iv : Bytes, aad : Bytes) -> Bytes {
  let st = gmac_new_iv(key, iv)
  gmac_update(st, aad)
  gmac_finalize(st)
}

///|
/// Verify a 16-byte tag produced by `gmac_iv` in constant time.
pub fn gmac_iv_verify(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  tag : Bytes,
) -> Bool {
  bytes_equal(gmac_iv(key, iv, aad), tag)
}
