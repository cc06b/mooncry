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
