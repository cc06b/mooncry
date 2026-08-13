// ============================================================
// Keccak-256 (original Keccak submission, pre-FIPS-202 padding).
// The hash used by Ethereum. Same Keccak-f[1600] sponge as SHA-3,
// differing only in the domain-separation byte (0x01 vs SHA-3's 0x06).
// Reuses the streaming hasher from sha3_stream.mbt.
// ============================================================

///|
/// Compute Keccak-256 (legacy Keccak with 0x01 multi-rate padding, as
/// used by Ethereum), 32-byte digest. Note this is NOT SHA3-256
/// (FIPS 202) — the two differ in the domain byte and thus produce
/// unrelated digests for the same input.
pub fn keccak_256(data : Bytes) -> Bytes {
  let hasher = sha3_new(136, 32, 0x01)
  sha3_update(hasher, data)
  sha3_finalize(hasher)
}
