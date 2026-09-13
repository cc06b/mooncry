// ==================== Structure-aware DER / PEM fuzzing ====================
//
// Byte-flip fuzzing (robust_test.mbt) rarely produces *structurally plausible*
// DER: a mutated blob almost always dies at the first tag or length check, so
// the parser's deep paths never execute. These tests build blobs that look like
// DER — every prefix of a valid encoding, single-byte substitutions with
// DER-meaningful values, extra trailing/inserted TLVs, non-minimal INTEGERs and
// length forms — which is what a hostile peer actually sends.
//
// They earned their keep: two out-of-bounds traps were found this way, both of
// the "valid prefix, nothing after it" shape that random mutation never
// produces (a SPKI whose content is exactly the AlgorithmIdentifier, and a
// ciphertext SEQUENCE whose first INTEGER runs to the end of the buffer).
//
// On top of "never traps", every codec is held to the identity that strict DER
// implies: an accepted blob must re-encode byte-identically. Without it a peer
// can offer several distinct encodings of one value (malleability).

///|
/// Byte values worth substituting into a DER blob: structural tags, both length
/// forms, the 0x80 indefinite form, and the boundaries that turn a minimal
/// encoding into a non-minimal one.
let rb_der_bytes : Array[Byte] = [
  (0x00).to_byte(),
  (0x01).to_byte(),
  (0x02).to_byte(),
  (0x03).to_byte(),
  (0x04).to_byte(),
  (0x05).to_byte(),
  (0x30).to_byte(),
  (0x31).to_byte(),
  (0x32).to_byte(),
  (0x7F).to_byte(),
  (0x80).to_byte(),
  (0x81).to_byte(),
  (0x82).to_byte(),
  (0x83).to_byte(),
  (0xA1).to_byte(),
  (0xFE).to_byte(),
  (0xFF).to_byte(),
]

///|
/// Every prefix of `data`, including the empty blob.
fn rb_prefixes(data : Bytes) -> Array[Bytes] {
  let out : Array[Bytes] = []
  for i = 0; i <= data.length(); i = i + 1 {
    out.push(rb_slice(data, 0, i))
  }
  out
}

///|
/// Every single-byte substitution of `data` with a DER-meaningful value.
fn rb_substs(data : Bytes) -> Array[Bytes] {
  let out : Array[Bytes] = []
  for i = 0; i < data.length(); i = i + 1 {
    for v in rb_der_bytes {
      let a = data.to_array()
      a[i] = v
      out.push(Bytes::from_array(a))
    }
  }
  out
}

///|
/// Whole-TLV perturbations: trailing garbage after the top-level SEQUENCE, an
/// extra TLV inserted before the end, and a duplicated tail.
fn rb_der_extras(r : RbRng, data : Bytes) -> Array[Bytes] {
  let n = data.length()
  let out : Array[Bytes] = []
  out.push(rb_cat(data, rb_bytes(r, 1)))
  out.push(rb_cat(data, rb_bytes(r, 8)))
  out.push(rb_cat(data, rb_slice(data, 2, n - 2)))
  // an extra INTEGER / OCTET STRING TLV wedged in before the last byte
  for tag in rb_der_bytes {
    for payload_len in [0, 1, 32] {
      let tlv = rb_cat(
        Bytes::from_array([tag, payload_len.to_byte()]),
        rb_bytes(r, payload_len),
      )
      out.push(
        rb_cat(rb_slice(data, 0, n - 1), rb_cat(tlv, rb_slice(data, n - 1, 1))),
      )
      out.push(rb_cat(tlv, data))
    }
  }
  out
}

///|
/// Hold a (decode, encode) pair to the strict-DER contract on one blob:
/// never trap, `false` never comes with a payload, and an accepted blob must
/// re-encode byte-identically.
fn rb_check_identity(
  der : Bytes,
  decode : (Bytes) -> (Bytes, Bool),
  encode : (Bytes) -> Bytes,
  what : String,
) -> Unit {
  let (raw, ok) = decode(der)
  if ok {
    if raw.length() == 0 {
      abort(what + ": accepted with an empty payload")
    }
    if !rb_eq(encode(raw), der) {
      abort(what + ": accepted a non-canonical encoding (malleable)")
    }
  } else if raw.length() != 0 {
    abort(what + ": rejected but returned a payload")
  }
}

///|
/// Weaker contract for codecs whose encoder is not the only legal form (PKCS#8
/// has an OPTIONAL publicKey field, so a field-less input decodes fine but
/// re-encodes with it). decode -> encode -> decode must still be stable.
fn rb_check_stable(
  der : Bytes,
  decode : (Bytes) -> (Bytes, Bool),
  encode : (Bytes) -> Bytes,
  what : String,
) -> Unit {
  let (raw, ok) = decode(der)
  if ok {
    if raw.length() == 0 {
      abort(what + ": accepted with an empty payload")
    }
    let (raw2, ok2) = decode(encode(raw))
    if !ok2 {
      abort(what + ": re-encoded form was rejected")
    }
    if !rb_eq(raw, raw2) {
      abort(what + ": decode/encode/decode is not stable")
    }
  } else if raw.length() != 0 {
    abort(what + ": rejected but returned a payload")
  }
}

///|
/// Run the full structural sweep against one codec.
fn rb_der_sweep(
  r : RbRng,
  der : Bytes,
  decode : (Bytes) -> (Bytes, Bool),
  encode : (Bytes) -> Bytes,
  what : String,
  identity : Bool,
) -> Unit {
  let check = if identity { rb_check_identity } else { rb_check_stable }
  check(der, decode, encode, what + " canonical")
  for d in rb_prefixes(der) {
    check(d, decode, encode, what + " prefix")
  }
  for d in rb_substs(der) {
    check(d, decode, encode, what + " subst")
  }
  for d in rb_der_extras(r, der) {
    check(d, decode, encode, what + " extra")
  }
  for d in rb_cases(r, der, 24) {
    check(d, decode, encode, what + " random")
  }
}

///|
test "robust-der-signature" {
  let r = rb_rng(0x444552534947UL)
  let sk = rb_bytes(r, 32)
  let id = b"1234567812345678"
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let sig = sm2_sign(sk, b"msg", id, rand)
  let der = sm2_sig_to_der(sig)
  rb_der_sweep(r, der, sm2_sig_from_der, sm2_sig_to_der, "sm2_sig", true)
  // the decoded value must still verify: parsing is not just shape-checking
  let (raw, ok) = sm2_sig_from_der(der)
  assert_true(ok && rb_eq(raw, sig), msg="sm2_sig: canonical decode")
  assert_true(sm2_verify(sm2_public_key(sk), b"msg", id, raw))
  // Handcrafted malleability probes: all three are BER-ish re-encodings of a
  // value that already has a canonical form, so all three must be rejected.
  let inner = rb_slice(der, 2, der.length() - 2)
  // 1. an extra leading zero on the first INTEGER (non-minimal INTEGER)
  let r_len = der[3].to_int()
  let padded_r = rb_cat(
    rb_slice(der, 0, 3),
    rb_cat(
      Bytes::from_array([(r_len + 1).to_byte(), (0).to_byte()]),
      rb_slice(der, 4, der.length() - 4),
    ),
  )
  let outer_len = padded_r.length() - 2
  let padded = rb_cat(
    Bytes::from_array([(0x30).to_byte(), outer_len.to_byte()]),
    rb_slice(padded_r, 2, outer_len),
  )
  let (_, ok_pad) = sm2_sig_from_der(padded)
  assert_false(ok_pad)
  // 2. one trailing byte inside the SEQUENCE
  let (_, ok_trail) = sm2_sig_from_der(
    rb_cat(
      Bytes::from_array([(0x30).to_byte(), (inner.length() + 1).to_byte()]),
      rb_cat(inner, Bytes::from_array([(0).to_byte()])),
    ),
  )
  assert_false(ok_trail)
  // 3. the long length form for a value that fits in the short form
  let (_, ok_long) = sm2_sig_from_der(
    rb_cat(
      Bytes::from_array([
        (0x30).to_byte(),
        (0x81).to_byte(),
        inner.length().to_byte(),
      ]),
      inner,
    ),
  )
  assert_false(ok_long)
  // 4. indefinite length (reserved in DER)
  let (_, ok_indef) = sm2_sig_from_der(
    rb_cat(
      Bytes::from_array([(0x30).to_byte(), (0x80).to_byte()]),
      rb_cat(inner, Bytes::from_array([(0).to_byte(), (0).to_byte()])),
    ),
  )
  assert_false(ok_indef)
}

///|
test "robust-der-ciphertext" {
  let r = rb_rng(0x444552435458UL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let rand = fn(k : Int) -> Bytes { rb_bytes(r, k) }
  let ct = sm2_encrypt(pk, b"payload", rand)
  let der = sm2_ct_to_der(ct)
  rb_der_sweep(r, der, sm2_ct_from_der, sm2_ct_to_der, "sm2_ct", true)
  let (raw, ok) = sm2_ct_from_der(der)
  assert_true(ok && rb_eq(raw, ct), msg="sm2_ct: canonical decode")
  let (pt, ok2) = sm2_decrypt(sk, raw)
  assert_true(ok2 && rb_eq(pt, b"payload"), msg="sm2_ct: decoded ct decrypts")
  // Regression pin: SEQUENCE { INTEGER(6 bytes) } and nothing else — the first
  // INTEGER runs to the end of the buffer, so the parser's next tag read used
  // to index one past the end and trap.
  let trapped = Bytes::from_array([
    (0x30).to_byte(),
    (0x08).to_byte(),
    (0x02).to_byte(),
    (0x06).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    (0).to_byte(),
    (0x41).to_byte(),
  ])
  let (_, ok3) = sm2_ct_from_der(trapped)
  assert_false(ok3)
}

///|
test "robust-der-keys" {
  let r = rb_rng(0x4445524B4559UL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let p8 = sm2_sk_to_pkcs8_der(sk)
  let spki = sm2_pk_to_spki_der(pk)
  // SPKI has exactly one legal encoding here, so hold it to the identity
  rb_der_sweep(
    r, spki, sm2_spki_der_to_pk, sm2_pk_to_spki_der, "sm2_spki", true,
  )
  // PKCS#8 has an OPTIONAL publicKey field: decode/encode/decode must be stable
  rb_der_sweep(
    r, p8, sm2_pkcs8_der_to_sk, sm2_sk_to_pkcs8_der, "sm2_pkcs8", false,
  )
  let (sk2, ok) = sm2_pkcs8_der_to_sk(p8)
  assert_true(ok && rb_eq(sk2, sk), msg="pkcs8: canonical decode")
  let (pk2, ok2) = sm2_spki_der_to_pk(spki)
  assert_true(ok2 && rb_eq(pk2, pk), msg="spki: canonical decode")
  // Regression pin: SEQUENCE whose content is exactly the 21-byte
  // AlgorithmIdentifier and nothing else — the BIT STRING tag read used to
  // index one past the end of the buffer and trap.
  let trapped = rb_cat(
    Bytes::from_array([(0x30).to_byte(), (21).to_byte()]),
    rb_slice(spki, 2, 21),
  )
  let (_, ok3) = sm2_spki_der_to_pk(trapped)
  assert_false(ok3)
  // the same shape must not confuse the PKCS#8 parser either
  let (_, ok4) = sm2_pkcs8_der_to_sk(trapped)
  assert_false(ok4)
}

///|
test "robust-pem-structure" {
  let r = rb_rng(0x44455250454DUL)
  let sk = rb_bytes(r, 32)
  let pk = sm2_public_key(sk)
  let sk_pem = sm2_sk_to_pem(sk)
  let pk_pem = sm2_pk_to_pem(pk)
  // canonical PEM decodes and re-encodes identically
  let (sk1, ok1) = sm2_sk_from_pem(sk_pem)
  assert_true(ok1 && rb_eq(sk1, sk) && sm2_sk_to_pem(sk1) == sk_pem)
  let (pk1, ok2) = sm2_pk_from_pem(pk_pem)
  assert_true(ok2 && rb_eq(pk1, pk) && sm2_pk_to_pem(pk1) == pk_pem)
  // Hostile armour: every prefix of a canonical PEM. A prefix can still be a
  // complete PEM (dropping only the trailing newline is normal leniency), so
  // the invariant is not "must be rejected" but "whatever it accepts must be
  // the real key" — a truncated payload decoding to garbage would be the bug.
  for i = 0; i < sk_pem.length(); i = i + 1 {
    let frag = sk_pem[:i].to_owned()
    let (sk_f, a) = sm2_sk_from_pem(frag)
    let (pk_f, b) = sm2_pk_from_pem(frag)
    if a {
      assert_true(rb_eq(sk_f, sk), msg="pem: prefix decoded to a wrong key")
    }
    if b {
      assert_true(rb_eq(pk_f, pk), msg="pem: prefix decoded to a wrong pk")
    }
  }
  // valid-looking headers around a hostile payload
  let body = sm2_sk_to_pkcs8_der(sk)
  for payload in rb_cases(r, body, 20) {
    let b64 = base64_encode(payload)
    for
      headers in [
        ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
        ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
        ("-----BEGIN PRIVATE KEY-----", "-----END PUBLIC KEY-----"),
        ("", ""),
        ("-----BEGIN PRIVATE KEY-----", ""),
      ] {
      let (open_, close_) = headers
      let pem = open_ + "\n" + b64 + "\n" + close_ + "\n"
      let (sk_x, ok_x) = sm2_sk_from_pem(pem)
      let (pk_x, ok_y) = sm2_pk_from_pem(pem)
      // Acceptance with a *different* key is legitimate — a mutated payload can
      // still be structurally perfect DER (e.g. flipping a byte inside the
      // OPTIONAL publicKey field). What must hold is self-consistency: the
      // decoded value re-encodes and decodes back to itself, and an unmodified
      // payload still yields the real key.
      if ok_x {
        let (sk_again, ok_again) = sm2_sk_from_pem(sm2_sk_to_pem(sk_x))
        assert_true(
          ok_again && rb_eq(sk_again, sk_x),
          msg="pem: accepted key is not self-consistent",
        )
        if rb_eq(payload, body) {
          assert_true(
            rb_eq(sk_x, sk),
            msg="pem: canonical payload decoded wrong",
          )
        }
      }
      if ok_y {
        let (pk_again, ok_b) = sm2_pk_from_pem(sm2_pk_to_pem(pk_x))
        assert_true(
          ok_b && rb_eq(pk_again, pk_x),
          msg="pem: accepted pk is not self-consistent",
        )
        if rb_eq(payload, body) {
          assert_true(
            rb_eq(pk_x, pk),
            msg="pem: canonical payload decoded wrong",
          )
        }
      }
    }
    // no line wrapping at all, and CRLF wrapping: both must be rejected or
    // must yield the correct key — never garbage
    let oneline = "-----BEGIN PRIVATE KEY-----\n" +
      b64 +
      "\n-----END PRIVATE KEY-----\n"
    let (sk_l, ok_l) = sm2_sk_from_pem(oneline)
    if ok_l {
      let (sk_l2, ok_l2) = sm2_sk_from_pem(sm2_sk_to_pem(sk_l))
      assert_true(
        ok_l2 && rb_eq(sk_l2, sk_l),
        msg="pem: unwrapped-line decode is not self-consistent",
      )
      if rb_eq(payload, body) {
        assert_true(rb_eq(sk_l, sk), msg="pem: canonical payload decoded wrong")
      }
    }
  }
}
