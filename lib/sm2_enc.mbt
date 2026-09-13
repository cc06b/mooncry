// SM2 public-key encryption (GB/T 32918.4-2017).
// Ciphertext layout (raw form): C1 || C3 || C2 where
//   C1 = 0x04 || x1 || y1 (65 bytes, the ephemeral point kG),
//   C3 = SM3(x2 || M || y2) (32 bytes, integrity),
//   C2 = M xor KDF(x2 || y2, |M|),
// with (x2, y2) = k * P (recipient key) on decrypt d * C1.
// DER helpers convert to/from the openssl/ASN.1 form
// SEQUENCE { INTEGER x1, INTEGER y1, OCTET STRING C3, OCTET STRING C2 }.
// Oracle: python reference cross-proven via openssl pkeyutl SM2 decrypt
// (GB/T 32918.5 example key, fixed k) — see _sm2_enc_oracle.py.

///|
/// SM3-based counter KDF (GB/T 32918.4 §5.4.3): t = SM3(z||ct) for ct=1..
/// Returns klen bytes; caller must reject an all-zero output.
fn sm2_kdf(z : Bytes, klen : Int) -> Bytes {
  let out = Array::make(klen, (0).to_byte())
  let mut produced = 0
  let mut ct = 1
  while produced < klen {
    let ctb = Array::make(4, (0).to_byte())
    ctb[0] = ((ct >> 24) & 0xFF).to_byte()
    ctb[1] = ((ct >> 16) & 0xFF).to_byte()
    ctb[2] = ((ct >> 8) & 0xFF).to_byte()
    ctb[3] = (ct & 0xFF).to_byte()
    let mut acc = z
    acc = concat_bytes(acc, Bytes::from_array(ctb[:]))
    let h = sm3(acc)
    let take = if produced + 32 <= klen { 32 } else { klen - produced }
    for i in 0..<take {
      out[produced + i] = h[i]
    }
    produced = produced + take
    ct = ct + 1
  }
  Bytes::from_array(out[:])
}

///|
fn sm2_all_zero(b : Bytes) -> Bool {
  for i in 0..<b.length() {
    if b[i] != (0).to_byte() {
      return false
    }
  }
  true
}

///|
fn sm2_parse_point(pk : Bytes) -> (@bigint.BigInt, @bigint.BigInt) {
  guard pk.length() == 65 && pk[0] == (4).to_byte() else {
    abort("sm2 encryption: public key must be uncompressed 0x04||x||y")
  }
  let x = ec_be_to_int(ec_slice(pk, 1, 32))
  let y = ec_be_to_int(ec_slice(pk, 33, 32))
  guard sm2_on_curve(x, y) else {
    abort("sm2 encryption: public key off curve")
  }
  (x, y)
}

///|
/// Encrypt with an explicit nonce k (32-byte big-endian, 1 <= k <= n-1).
/// Returns raw C1||C3||C2. Aborts on degenerate k (all-zero KDF output).
pub fn sm2_encrypt_with_k(pk : Bytes, msg : Bytes, k : Bytes) -> Bytes {
  guard k.length() == 32 else {
    abort("sm2_encrypt_with_k: k must be 32 bytes")
  }
  guard msg.length() > 0 else { abort("sm2_encrypt_with_k: empty message") }
  let kx = ec_be_to_int(k)
  let one = @bigint.BigInt::from_int(1)
  guard kx >= one && kx <= sm2_curve.n - one else {
    abort("sm2_encrypt_with_k: k out of range [1, n-1]")
  }
  let (px, py) = sm2_parse_point(pk)
  let c1pt = ec_scalar_mult(sm2_curve, kx, ec_g_point(sm2_curve))
  let shared = ec_scalar_mult(sm2_curve, kx, EcPoint::{
    x: px,
    y: py,
    inf: false,
  })
  let x2 = ec_int_to_be(shared.x, 32)
  let y2 = ec_int_to_be(shared.y, 32)
  let z = concat_bytes(x2, y2)
  let t = sm2_kdf(z, msg.length())
  guard !sm2_all_zero(t) else {
    abort("sm2_encrypt_with_k: degenerate k (KDF output all zero)")
  }
  let c2 = Array::make(msg.length(), (0).to_byte())
  for i in 0..<msg.length() {
    c2[i] = (msg[i].to_int() ^ t[i].to_int()).to_byte()
  }
  let mut m_acc = x2
  m_acc = concat_bytes(m_acc, msg)
  m_acc = concat_bytes(m_acc, y2)
  let c3 = sm3(m_acc)
  let c1 = Array::make(65, (0).to_byte())
  c1[0] = (4).to_byte()
  let c1x = ec_int_to_be(c1pt.x, 32)
  let c1y = ec_int_to_be(c1pt.y, 32)
  for i in 0..<32 {
    c1[1 + i] = c1x[i]
    c1[33 + i] = c1y[i]
  }
  let mut out = Bytes::from_array(c1[:])
  out = concat_bytes(out, c3)
  out = concat_bytes(out, Bytes::from_array(c2[:]))
  out
}

///|
/// Encrypt with fresh randomness: `rand(32)` supplies the ephemeral k.
/// SECURITY: k must be unique per ciphertext under the same recipient key —
/// KDF-stream reuse turns C2 into a two-time pad. Degenerate draws retry.
pub fn sm2_encrypt(pk : Bytes, msg : Bytes, rand : (Int) -> Bytes) -> Bytes {
  guard msg.length() > 0 else { abort("sm2_encrypt: empty message") }
  let one = @bigint.BigInt::from_int(1)
  let (px, py) = sm2_parse_point(pk)
  let mut tries = 0
  let mut done = false
  let mut result = b""
  while !done {
    guard tries < 100 else { abort("sm2_encrypt: too many degenerate k draws") }
    tries = tries + 1
    let kx = ec_be_to_int(rand(32))
    if kx >= one && kx <= sm2_curve.n - one {
      let c1pt = ec_scalar_mult(sm2_curve, kx, ec_g_point(sm2_curve))
      let shared = ec_scalar_mult(sm2_curve, kx, EcPoint::{
        x: px,
        y: py,
        inf: false,
      })
      let x2 = ec_int_to_be(shared.x, 32)
      let y2 = ec_int_to_be(shared.y, 32)
      let t = sm2_kdf(concat_bytes(x2, y2), msg.length())
      if !sm2_all_zero(t) {
        let c2 = Array::make(msg.length(), (0).to_byte())
        for i in 0..<msg.length() {
          c2[i] = (msg[i].to_int() ^ t[i].to_int()).to_byte()
        }
        let mut m_acc = x2
        m_acc = concat_bytes(m_acc, msg)
        m_acc = concat_bytes(m_acc, y2)
        let c3 = sm3(m_acc)
        let c1 = Array::make(65, (0).to_byte())
        c1[0] = (4).to_byte()
        let c1x = ec_int_to_be(c1pt.x, 32)
        let c1y = ec_int_to_be(c1pt.y, 32)
        for i in 0..<32 {
          c1[1 + i] = c1x[i]
          c1[33 + i] = c1y[i]
        }
        let mut out = Bytes::from_array(c1[:])
        out = concat_bytes(out, c3)
        out = concat_bytes(out, Bytes::from_array(c2[:]))
        result = out
        done = true
      }
    }
  }
  result
}

///|
/// Decrypt raw C1||C3||C2 with a 32-byte secret key. Returns (b"", false)
/// on any malformed input or C3 mismatch (corruption, tampering, or wrong
/// key) — same convention as aes_gcm_decrypt. Aborts only on a wrong-length
/// secret key (caller error).
pub fn sm2_decrypt(sk : Bytes, ct : Bytes) -> (Bytes, Bool) {
  guard sk.length() == 32 else { abort("sm2_decrypt: sk must be 32 bytes") }
  if ct.length() < 65 + 32 + 1 {
    return (b"", false)
  }
  let d = ec_be_to_int(sk)
  let c1 = ec_slice(ct, 0, 65)
  if c1[0] != (4).to_byte() {
    return (b"", false)
  }
  let x1 = ec_be_to_int(ec_slice(c1, 1, 32))
  let y1 = ec_be_to_int(ec_slice(c1, 33, 32))
  if !sm2_on_curve(x1, y1) {
    return (b"", false)
  }
  let shared = ec_scalar_mult(sm2_curve, d, EcPoint::{
    x: x1,
    y: y1,
    inf: false,
  })
  if shared.inf {
    return (b"", false)
  }
  let x2 = ec_int_to_be(shared.x, 32)
  let y2 = ec_int_to_be(shared.y, 32)
  let c3 = ec_slice(ct, 65, 32)
  let c2 = ec_slice(ct, 97, ct.length() - 97)
  let t = sm2_kdf(concat_bytes(x2, y2), c2.length())
  if sm2_all_zero(t) {
    return (b"", false)
  }
  let msg = Array::make(c2.length(), (0).to_byte())
  for i in 0..<c2.length() {
    msg[i] = (c2[i].to_int() ^ t[i].to_int()).to_byte()
  }
  let mut m_acc = x2
  m_acc = concat_bytes(m_acc, Bytes::from_array(msg[:]))
  m_acc = concat_bytes(m_acc, y2)
  if !bytes_equal(sm3(m_acc), c3) {
    return (b"", false)
  }
  (Bytes::from_array(msg[:]), true)
}

// ==================== DER interop (openssl ASN.1 form) ====================

///|
fn sm2_der_len(n : Int) -> Array[Byte] {
  if n < 0x80 {
    [n.to_byte()]
  } else if n < 0x100 {
    [(0x81).to_byte(), n.to_byte()]
  } else {
    [(0x82).to_byte(), ((n >> 8) & 0xFF).to_byte(), (n & 0xFF).to_byte()]
  }
}

///|
fn sm2_der_tlv(tag : Int, val : Array[Byte]) -> Array[Byte] {
  let out : Array[Byte] = []
  out.push(tag.to_byte())
  for b in sm2_der_len(val.length()) {
    out.push(b)
  }
  for b in val {
    out.push(b)
  }
  out
}

///|
fn sm2_der_int_bytes(v : Bytes) -> Array[Byte] {
  // strip leading zeros, keep one if the top bit is set
  let mut start = 0
  while start < v.length() - 1 && v[start] == (0).to_byte() {
    start = start + 1
  }
  let body : Array[Byte] = []
  if v[start].to_int() >= 0x80 {
    body.push((0).to_byte())
  }
  for i in start..<v.length() {
    body.push(v[i])
  }
  sm2_der_tlv(2, body)
}

///|
/// Read a DER `INTEGER` at `pos` into a right-aligned `width`-byte big-endian
/// value. Returns (value, next_pos), or (b"", -1) on any malformed input.
///
/// Strict in the two ways that matter for a parser fed by peers:
///   * every read is bounds-checked (`sm2_der_byte` / `sm2_der_read_len`), so a
///     truncated TLV cannot index past the end of the buffer;
///   * the encoding must be minimal (X.690 DER): a leading 0x00 is accepted
///     only as the sign pad of a value whose top bit is set. Without that a
///     peer can offer several distinct encodings of the same integer
///     (malleability), and re-encoding a decoded value would not round-trip.
///
/// INTEGER zero is accepted here (it is minimally encoded as 02 01 00);
/// whether zero is *meaningful* is the caller's business (sm2_verify rejects
/// r < 1, sm2_decrypt rejects a point that is not on the curve).
fn sm2_der_int(der : Bytes, pos : Int, width : Int) -> (Bytes, Int) {
  let bad = (b"", -1)
  if sm2_der_byte(der, pos) != 2 {
    return bad
  }
  let (lv, p) = sm2_der_read_len(der, pos + 1)
  if lv < 1 || lv > width + 1 || p + lv > der.length() {
    return bad
  }
  let vend = p + lv
  if lv == 1 && sm2_der_byte(der, p) == 0 {
    return (Bytes::make(width, (0).to_byte()), vend)
  }
  let mut vs = p
  let padded = sm2_der_byte(der, vs) == 0
  if padded {
    // a sign pad must be needed by the value that follows it
    if sm2_der_byte(der, vs + 1) < 0x80 {
      return bad
    }
    vs = vs + 1
  } else if sm2_der_byte(der, vs) >= 0x80 {
    // top bit set with no pad: a negative INTEGER, invalid for these fields
    return bad
  }
  let vlen = vend - vs
  if vlen < 1 || vlen > width {
    return bad
  }
  let out = Array::make(width, (0).to_byte())
  for i in 0..<vlen {
    out[width - vlen + i] = der[vs + i]
  }
  (Bytes::from_array(out), vend)
}

///|
/// Encode a raw C1||C3||C2 ciphertext into the openssl/ASN.1 DER form
/// SEQUENCE { INTEGER x1, INTEGER y1, OCTET STRING C3, OCTET STRING C2 }.
pub fn sm2_ct_to_der(ct : Bytes) -> Bytes {
  guard ct.length() >= 98 && ct[0] == (4).to_byte() else {
    abort("sm2_ct_to_der: not a raw C1||C3||C2 ciphertext")
  }
  let x1 = ec_slice(ct, 1, 32)
  let y1 = ec_slice(ct, 33, 32)
  let c3 = ec_slice(ct, 65, 32)
  let c2 = ec_slice(ct, 97, ct.length() - 97)
  let body : Array[Byte] = []
  for b in sm2_der_int_bytes(x1) {
    body.push(b)
  }
  for b in sm2_der_int_bytes(y1) {
    body.push(b)
  }
  let c3a = Array::make(32, (0).to_byte())
  for i in 0..<32 {
    c3a[i] = c3[i]
  }
  for b in sm2_der_tlv(4, c3a) {
    body.push(b)
  }
  let c2a = Array::make(c2.length(), (0).to_byte())
  for i in 0..<c2.length() {
    c2a[i] = c2[i]
  }
  for b in sm2_der_tlv(4, c2a) {
    body.push(b)
  }
  Bytes::from_array(sm2_der_tlv(0x30, body)[:])
}

///|
/// Decode the openssl/ASN.1 DER form back to raw C1||C3||C2.
/// Returns (b"", false) on malformed input (strict length checks).
pub fn sm2_ct_from_der(der : Bytes) -> (Bytes, Bool) {
  let fail = (b"", false)
  if der.length() < 10 || der[0] != (0x30).to_byte() {
    return fail
  }
  let (total, pos0) = sm2_der_read_len(der, 1)
  if total < 0 || pos0 + total != der.length() {
    return fail
  }
  let end = der.length()
  // INTEGER x1, INTEGER y1
  let (x1, pos1) = sm2_der_int(der, pos0, 32)
  if pos1 < 0 {
    return fail
  }
  let (y1, pos2) = sm2_der_int(der, pos1, 32)
  if pos2 < 0 {
    return fail
  }
  // OCTET STRING C3 (32 bytes)
  if sm2_der_byte(der, pos2) != 4 {
    return fail
  }
  let (l3, pos3) = sm2_der_read_len(der, pos2 + 1)
  if l3 != 32 || pos3 + 32 > end {
    return fail
  }
  let c3 = ec_slice(der, pos3, 32)
  let pos4 = pos3 + 32
  // OCTET STRING C2 (>= 1 byte, running exactly to the end: no trailing data)
  if sm2_der_byte(der, pos4) != 4 {
    return fail
  }
  let (l2, pos5) = sm2_der_read_len(der, pos4 + 1)
  if l2 < 1 || pos5 + l2 != end {
    return fail
  }
  let out : Array[Byte] = [(4).to_byte()]
  for b in x1 {
    out.push(b)
  }
  for b in y1 {
    out.push(b)
  }
  for b in c3 {
    out.push(b)
  }
  for i in 0..<l2 {
    out.push(der[pos5 + i])
  }
  (Bytes::from_array(out), true)
}

///|
/// Encode a raw r||s signature (64 bytes) into DER
/// SEQUENCE { INTEGER r, INTEGER s } (the openssl/ASN.1 signature form).
pub fn sm2_sig_to_der(sig : Bytes) -> Bytes {
  guard sig.length() == 64 else {
    abort("sm2_sig_to_der: raw signature must be 64 bytes")
  }
  let r = ec_slice(sig, 0, 32)
  let s = ec_slice(sig, 32, 32)
  let body : Array[Byte] = []
  for b in sm2_der_int_bytes(r) {
    body.push(b)
  }
  for b in sm2_der_int_bytes(s) {
    body.push(b)
  }
  Bytes::from_array(sm2_der_tlv(0x30, body)[:])
}

///|
/// Decode DER SEQUENCE { INTEGER r, INTEGER s } back to raw r||s (64 bytes).
/// Returns (b"", false) on malformed input (strict length/order checks).
pub fn sm2_sig_from_der(der : Bytes) -> (Bytes, Bool) {
  let fail = (b"", false)
  if der.length() < 8 || der[0] != (0x30).to_byte() {
    return fail
  }
  let (total, pos0) = sm2_der_read_len(der, 1)
  if total < 0 || pos0 + total != der.length() {
    return fail
  }
  let (r, pos1) = sm2_der_int(der, pos0, 32)
  if pos1 < 0 {
    return fail
  }
  let (sv, pos2) = sm2_der_int(der, pos1, 32)
  if pos2 < 0 {
    return fail
  }
  // No trailing bytes inside the SEQUENCE: a lax parser would accept several
  // distinct encodings of one signature (malleability).
  if pos2 != der.length() {
    return fail
  }
  (concat_bytes(r, sv), true)
}

// ==================== SM2 sealed envelope (GM/T 0009 style) ====================

///|
/// Seal a message for an SM2 recipient: a fresh SM4 key + IV are encrypted
/// to the recipient (raw C1||C3||C2, fixed 125 bytes for the 28-byte
/// payload), then the message is SM4-GCM encrypted under them.
/// Layout: enc_key(125) || iv(12) || ciphertext || tag(16).
/// `rand` supplies 16 bytes for the SM4 key, then 12 for the IV, then 32
/// for each SM2 nonce k draw — all must be cryptographically fresh.
pub fn sm2_seal(pk : Bytes, msg : Bytes, rand : (Int) -> Bytes) -> Bytes {
  let sm4_key = rand(16)
  let iv = rand(12)
  let mut payload = sm4_key
  payload = concat_bytes(payload, iv)
  let enc_key = sm2_encrypt(pk, payload, rand)
  let (ct, tag) = sm4_gcm_encrypt(msg, sm4_key, iv, b"")
  let mut out = enc_key
  out = concat_bytes(out, iv)
  out = concat_bytes(out, ct)
  out = concat_bytes(out, tag)
  out
}

///|
/// Open a sealed envelope. Returns (b"", false) on malformed input, failed
/// SM2 decryption, or GCM tag mismatch.
pub fn sm2_open(sk : Bytes, envelope : Bytes) -> (Bytes, Bool) {
  // 125 (enc key) + 12 (iv) + 16 (tag) = 153 bytes of overhead minimum
  if envelope.length() < 153 {
    return (b"", false)
  }
  let enc_key = ec_slice(envelope, 0, 125)
  let iv = ec_slice(envelope, 125, 12)
  let ct_len = envelope.length() - 153
  let ct = ec_slice(envelope, 137, ct_len)
  let tag = ec_slice(envelope, 137 + ct_len, 16)
  let (payload, ok) = sm2_decrypt(sk, enc_key)
  if !ok || payload.length() != 28 {
    return (b"", false)
  }
  let sm4_key = ec_slice(payload, 0, 16)
  let (pt, ok2) = sm4_gcm_decrypt(ct, sm4_key, iv, b"", tag)
  if !ok2 {
    return (b"", false)
  }
  (pt, true)
}
