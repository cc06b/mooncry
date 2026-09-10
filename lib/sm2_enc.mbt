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
  let mut pos = 1
  // outer length
  let l0 = der[pos].to_int()
  pos = pos + 1
  let total = if l0 < 0x80 {
    l0
  } else if l0 == 0x81 {
    let v = der[pos].to_int()
    pos = pos + 1
    v
  } else if l0 == 0x82 {
    let v = (der[pos].to_int() << 8) | der[pos + 1].to_int()
    pos = pos + 2
    v
  } else {
    return fail
  }
  if pos + total != der.length() {
    return fail
  }
  let end = der.length()
  // INTEGER x1
  if der[pos] != (2).to_byte() {
    return fail
  }
  pos = pos + 1
  let lx = der[pos].to_int()
  pos = pos + 1
  if lx > 33 || pos + lx > end {
    return fail
  }
  let mut xs = pos
  pos = pos + lx
  while xs < pos - 1 && der[xs] == (0).to_byte() {
    xs = xs + 1
  }
  let xlen = pos - xs
  if xlen > 32 {
    return fail
  }
  let x1 = Array::make(32, (0).to_byte())
  for i in 0..<xlen {
    x1[32 - xlen + i] = der[xs + i]
  }
  // INTEGER y1
  if der[pos] != (2).to_byte() {
    return fail
  }
  pos = pos + 1
  let ly = der[pos].to_int()
  pos = pos + 1
  if ly > 33 || pos + ly > end {
    return fail
  }
  let mut ys = pos
  pos = pos + ly
  while ys < pos - 1 && der[ys] == (0).to_byte() {
    ys = ys + 1
  }
  let ylen = pos - ys
  if ylen > 32 {
    return fail
  }
  let y1 = Array::make(32, (0).to_byte())
  for i in 0..<ylen {
    y1[32 - ylen + i] = der[ys + i]
  }
  // OCTET STRING C3
  if der[pos] != (4).to_byte() {
    return fail
  }
  pos = pos + 1
  let l3 = der[pos].to_int()
  pos = pos + 1
  if l3 != 32 || pos + 32 > end {
    return fail
  }
  let c3 = Array::make(32, (0).to_byte())
  for i in 0..<32 {
    c3[i] = der[pos + i]
  }
  pos = pos + 32
  // OCTET STRING C2
  if der[pos] != (4).to_byte() {
    return fail
  }
  pos = pos + 1
  let l2b = der[pos].to_int()
  pos = pos + 1
  let l2 = if l2b < 0x80 {
    l2b
  } else if l2b == 0x81 {
    let v = der[pos].to_int()
    pos = pos + 1
    v
  } else if l2b == 0x82 {
    let v = (der[pos].to_int() << 8) | der[pos + 1].to_int()
    pos = pos + 2
    v
  } else {
    return fail
  }
  if pos + l2 != end || l2 < 1 {
    return fail
  }
  let out : Array[Byte] = []
  out.push((4).to_byte())
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
    out.push(der[pos + i])
  }
  (Bytes::from_array(out[:]), true)
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
  let mut pos = 1
  let l0 = der[pos].to_int()
  pos = pos + 1
  let total = if l0 < 0x80 {
    l0
  } else if l0 == 0x81 {
    let v = der[pos].to_int()
    pos = pos + 1
    v
  } else {
    return fail
  }
  if pos + total != der.length() {
    return fail
  }
  let out = Array::make(64, (0).to_byte())
  for half in 0..<2 {
    if pos >= der.length() || der[pos] != (2).to_byte() {
      return fail
    }
    pos = pos + 1
    let lv = der[pos].to_int()
    pos = pos + 1
    if lv < 1 || lv > 33 || pos + lv > der.length() {
      return fail
    }
    let mut vs = pos
    let vend = pos + lv
    pos = vend
    // strip a single leading zero pad
    if vs < vend - 1 && der[vs] == (0).to_byte() {
      vs = vs + 1
    }
    let vlen = vend - vs
    if vlen > 32 {
      return fail
    }
    if der[vs].to_int() >= 0x80 && vlen == lv && lv <= 32 {
      // high bit set without padding -> negative INTEGER, invalid here
      return fail
    }
    for i in 0..<vlen {
      out[half * 32 + 32 - vlen + i] = der[vs + i]
    }
  }
  (Bytes::from_array(out[:]), true)
}
