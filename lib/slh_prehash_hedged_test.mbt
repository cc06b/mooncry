// ==================== HashSLH-DSA verify + the three hedged signers ====================
//
// These four public entry points had no test at all, while their siblings were
// covered by official/ACVP known-answer vectors:
//
//   slh_verify_prehash      the verification half of HashSLH-DSA (FIPS 205 §10).
//                           slh_sign_prehash was vector-checked 12 times, so a
//                           wrong M' = 0x01||octet(|ctx|)||ctx||OID||PH(M) on the
//                           *verify* side would have shipped unnoticed: sign and
//                           verify would agree with each other and disagree with
//                           everybody else.
//   slh_sign_hedged         pure signing with caller randomness (opt_rand)
//   slh_sign_prehash_hedged HashSLH-DSA with caller randomness
//   slh_sign_raw_hedged     raw-M' signing with caller randomness
//
// The anchor is a spec-level identity rather than a fresh vector set:
// slh_sign_internal uses opt_rand = PK.seed when no randomness is given (that
// is what "deterministic" means here), so feeding PK.seed to a *hedged* signer
// must reproduce the deterministic signature byte for byte. The deterministic
// signers are the ones pinned by the ACVP vectors, which ties the hedged paths
// to external authority instead of only to each other.
//
// COST NOTE: SLH-DSA is the slowest family in this library — one 128s signature
// measures ~1.3s here and verification costs about the same, because both walk
// the hypertree. These two tests add ~88s to the release suite (~2min -> ~3m53s
// for 1165 tests), so the matrix is deliberately minimal and every entry earns
// its place: 3 prehash algorithms (SHA2, SHA3 and an XOF — the three shapes the
// OID table distinguishes) instead of all 12, 2 parameter sets instead of 4,
// and *all* the negative cases, because those are verify-only. Signatures are
// reused across assertions rather than regenerated. Trimming further would mean
// dropping a property, not a duplicate.

///|
/// The ACVP seeds from the SLH-DSA-SHA2-128s keyGen vector, so the 128-level
/// keys here are the official ones. n = 16 for every 128-level parameter set.
fn slhph_seeds16() -> (Bytes, Bytes, Bytes) {
  (
    hex_to_bytes("173D04C938C1C36BF289C3C022D04B14"),
    hex_to_bytes("63AE23C41AA546DA589774AC20B745C4"),
    hex_to_bytes("0D794777914C99766827F0F09CA972BE"),
  )
}

///|
/// Deterministic seeds of length `n`. SLH-DSA's n is 16/24/32 for the 128/192/
/// 256 security levels; it is passed explicitly because `SlhParams` is opaque
/// outside the package. `slh_keygen` does not validate seed lengths (it reads
/// out of bounds instead), so a wrong n here would trap rather than report —
/// `slhph_key` checks the resulting key sizes to keep that visible.
fn slhph_seed(n : Int, tag : Int) -> Bytes {
  let a = Array::make(n, b'\x00')
  for i in 0..<n {
    a[i] = ((i * 31 + tag * 7 + 13) & 0xFF).to_byte()
  }
  Bytes::from_array(a)
}

///|
fn slhph_key(p : SlhParams, n : Int) -> (Bytes, Bytes) {
  let (pk, sk) = slh_keygen(
    p,
    slhph_seed(n, 1),
    slhph_seed(n, 2),
    slhph_seed(n, 3),
  )
  // assert_* carries an error type and so cannot be used in a plain fn; this is
  // a test fixture and a wrong n is a bug in the test, so abort is fine
  if pk.length() != 2 * n || sk.length() != 4 * n {
    abort("slhph_key: wrong n for this parameter set")
  }
  (pk, sk)
}

///|
/// PK.seed is the first half of the public key (pk = PK.seed || PK.root), and it
/// is exactly what the deterministic signers use as opt_rand.
fn slhph_pk_seed(pk : Bytes) -> Bytes {
  let n = pk.length() / 2
  let a = Array::make(n, b'\x00')
  for i in 0..<n {
    a[i] = pk[i]
  }
  Bytes::from_array(a)
}

///|
test "slh-prehash-verify" {
  let (s1, s2, s3) = slhph_seeds16()
  let msg = b"hash-slh-dsa message"
  let ctx = b"slh-ctx"
  let p = slh_sha2_128s
  let (pk, sk) = slh_keygen(p, s1, s2, s3)
  // ---- four prehash algorithms round-trip: SHA-256 and SHA-512 (SHA2 family,
  // two digest widths), SHA3-512, SHAKE256 (the two XOFs, which the spec sizes
  // differently: 32 bytes for SHAKE128 and 64 for SHAKE256)
  let phs = [
    dsa_prehash_sha2_256, dsa_prehash_sha2_512, dsa_prehash_sha3_512, dsa_prehash_shake256,
  ]
  // the SHA-256 signature (phs[0]) is kept for every negative below, so each
  // algorithm is signed exactly once
  let mut s256 = b""
  for i in 0..<phs.length() {
    let sig = slh_sign_prehash(p, sk, msg, ctx, phs[i])
    assert_true(
      slh_verify_prehash(p, pk, msg, sig, ctx, phs[i]),
      msg="verify_prehash rejected its own signature",
    )
    if i == 0 {
      s256 = sig
    }
  }
  // ---- every input is bound into the verification (verify-only, so cheap) --
  assert_false(
    slh_verify_prehash(
      p, pk, b"hash-slh-dsa messagf", s256, ctx, dsa_prehash_sha2_256,
    ),
    msg="verify_prehash accepted a changed message",
  )
  assert_false(
    slh_verify_prehash(p, pk, msg, s256, b"other", dsa_prehash_sha2_256),
    msg="verify_prehash accepted a changed context",
  )
  // a HashSLH-DSA signature is neither a pure signature over the message ...
  assert_false(
    slh_verify(p, pk, msg, s256, ctx),
    msg="prehash signature verified as a pure signature",
  )
  // ... nor a raw-M' signature over it
  assert_false(
    slh_verify_raw(p, pk, msg, s256),
    msg="prehash signature verified as a raw-M' signature",
  )
  // ---- the OID/digest pairing: a signature under one algorithm must not
  // verify under another. Explicit pairs rather than enum equality inside the
  // loop (the codebase has no precedent for comparing ADT values).
  for
    other in [
      dsa_prehash_sha2_224, dsa_prehash_sha3_256, dsa_prehash_shake128, dsa_prehash_sha2_512_256,
    ] {
    assert_false(
      slh_verify_prehash(p, pk, msg, s256, ctx, other),
      msg="verify_prehash accepted a different prehash algorithm",
    )
  }
  // ---- tampered signature, wrong key, malformed lengths ------------------
  let flipped = s256.to_array()
  flipped[flipped.length() - 1] = (flipped[flipped.length() - 1].to_int() ^ 1).to_byte()
  assert_false(
    slh_verify_prehash(
      p,
      pk,
      msg,
      Bytes::from_array(flipped),
      ctx,
      dsa_prehash_sha2_256,
    ),
    msg="verify_prehash accepted a flipped signature byte",
  )
  let (pk2, _) = slh_keygen(p, s3, s2, s1)
  assert_false(
    slh_verify_prehash(p, pk2, msg, s256, ctx, dsa_prehash_sha2_256),
    msg="verify_prehash accepted a different public key",
  )
  for
    bad in [
      b"",
      Bytes::make(1, b'\x00'),
      Bytes::make(s256.length() - 1, b'\x00'),
      Bytes::make(s256.length() + 1, b'\x00'),
    ] {
    assert_false(
      slh_verify_prehash(p, pk, msg, bad, ctx, dsa_prehash_sha2_256),
      msg="verify_prehash accepted a malformed signature",
    )
  }
  // ---- context boundaries: 0 and 255 verify, 256 is false (never a trap) --
  let sig_empty = slh_sign_prehash(p, sk, msg, b"", dsa_prehash_sha2_256)
  assert_true(
    slh_verify_prehash(p, pk, msg, sig_empty, b"", dsa_prehash_sha2_256),
    msg="empty context round trip",
  )
  let ctx255 = Bytes::make(255, b'\x41')
  let sig255 = slh_sign_prehash(p, sk, msg, ctx255, dsa_prehash_sha2_256)
  assert_true(
    slh_verify_prehash(p, pk, msg, sig255, ctx255, dsa_prehash_sha2_256),
    msg="255-byte context round trip",
  )
  assert_false(
    slh_verify_prehash(
      p,
      pk,
      msg,
      sig255,
      Bytes::make(256, b'\x41'),
      dsa_prehash_sha2_256,
    ),
    msg="verify_prehash did not reject an over-long context",
  )
  // ---- one SHAKE parameter set, so both hash families inside SLH are hit --
  let (spk, ssk) = slh_keygen(slh_shake_128s, s2, s3, s1)
  let ssig = slh_sign_prehash(
    slh_shake_128s, ssk, msg, ctx, dsa_prehash_shake256,
  )
  assert_true(
    slh_verify_prehash(
      slh_shake_128s, spk, msg, ssig, ctx, dsa_prehash_shake256,
    ),
    msg="SHAKE-128s prehash round trip",
  )
  assert_false(
    slh_verify_prehash(
      slh_shake_128s, spk, msg, ssig, ctx, dsa_prehash_shake128,
    ),
    msg="SHAKE-128s accepted the wrong SHAKE width",
  )
  // and a signature made under other parameters must not verify here
  assert_false(
    slh_verify_prehash(
      slh_shake_128s, spk, msg, s256, ctx, dsa_prehash_sha2_256,
    ),
    msg="a SHA2-128s signature verified under SHAKE-128s",
  )
}

///|
test "slh-hedged-signers" {
  let msg = b"hedged message"
  let ctx = b"hedged-ctx"
  let mpr = b"raw M-prime bytes, not a formatted context"
  // ---- hedged with PK.seed must reproduce the deterministic signature ----
  // All three hedged signers on one set: the identity is about how opt_rand is
  // plumbed, which does not depend on the parameter set. A second set (192s,
  // n = 24) carries just the pure signer, to show the identity is not an
  // artefact of n = 16 -- at half the signing cost of the 256-level sets.
  let p = slh_sha2_128s
  let (pk, sk) = slhph_key(p, 16)
  let pk_seed = slhph_pk_seed(pk)
  assert_true(
    bytes_equal(
      slh_sign_hedged(p, sk, msg, ctx, pk_seed),
      slh_sign(p, sk, msg, ctx),
    ),
    msg="hedged(pk_seed) != deterministic pure signature",
  )
  assert_true(
    bytes_equal(
      slh_sign_prehash_hedged(p, sk, msg, ctx, dsa_prehash_sha2_256, pk_seed),
      slh_sign_prehash(p, sk, msg, ctx, dsa_prehash_sha2_256),
    ),
    msg="hedged(pk_seed) != deterministic prehash signature",
  )
  assert_true(
    bytes_equal(
      slh_sign_raw_hedged(p, sk, mpr, pk_seed),
      slh_sign_raw(p, sk, mpr),
    ),
    msg="hedged(pk_seed) != deterministic raw signature",
  )
  let (wpk, wsk) = slhph_key(slh_sha2_192s, 24)
  assert_true(
    bytes_equal(
      slh_sign_hedged(slh_sha2_192s, wsk, msg, ctx, slhph_pk_seed(wpk)),
      slh_sign(slh_sha2_192s, wsk, msg, ctx),
    ),
    msg="hedged(pk_seed) != deterministic at n = 24",
  )
  // ---- fresh randomness: differs from deterministic, still verifies ------
  let r = rb_rng(0x534C48484544UL)
  let rnd1 = rb_bytes(r, 16)
  let rnd2 = rb_bytes(r, 16)
  let det = slh_sign(p, sk, msg, ctx)
  let h1 = slh_sign_hedged(p, sk, msg, ctx, rnd1)
  let h2 = slh_sign_hedged(p, sk, msg, ctx, rnd2)
  assert_true(
    bytes_equal(h1, slh_sign_hedged(p, sk, msg, ctx, rnd1)),
    msg="hedged signing is not deterministic in rnd",
  )
  assert_false(
    bytes_equal(h1, det),
    msg="hedged(rnd) equalled the deterministic signature",
  )
  assert_false(
    bytes_equal(h1, h2),
    msg="two different rnd gave the same signature",
  )
  assert_true(
    slh_verify(p, pk, msg, h1, ctx),
    msg="hedged signature does not verify",
  )
  assert_true(
    slh_verify(p, pk, msg, h2, ctx),
    msg="second hedged signature does not verify",
  )
  // the same three properties for the prehash and raw hedged signers
  let ph1 = slh_sign_prehash_hedged(p, sk, msg, ctx, dsa_prehash_sha2_256, rnd1)
  let ph2 = slh_sign_prehash_hedged(p, sk, msg, ctx, dsa_prehash_sha2_256, rnd2)
  assert_false(bytes_equal(ph1, ph2), msg="prehash hedged ignored rnd")
  assert_true(
    slh_verify_prehash(p, pk, msg, ph1, ctx, dsa_prehash_sha2_256),
    msg="prehash hedged signature does not verify under verify_prehash",
  )
  assert_true(
    slh_verify_prehash(p, pk, msg, ph2, ctx, dsa_prehash_sha2_256),
    msg="second prehash hedged signature does not verify",
  )
  let rw1 = slh_sign_raw_hedged(p, sk, mpr, rnd1)
  let rw2 = slh_sign_raw_hedged(p, sk, mpr, rnd2)
  assert_false(bytes_equal(rw1, rw2), msg="raw hedged ignored rnd")
  assert_true(
    slh_verify_raw(p, pk, mpr, rw1),
    msg="raw hedged signature does not verify",
  )
  assert_true(
    slh_verify_raw(p, pk, mpr, rw2),
    msg="second raw hedged signature does not verify",
  )
  // a hedged raw signature over M' is not a signature over the message
  assert_false(
    slh_verify(p, pk, mpr, rw1, b""),
    msg="raw M' signature verified as pure",
  )
}
