// SM2 key serialization: PKCS#8 private key and SPKI public key, in DER and
// PEM. Byte-identical to openssl's encodings (verified against PEMs that
// openssl generated/consumed in the GB/T 32918.5 example interop run).
// OIDs: id-ecPublicKey 1.2.840.10045.2.1, sm2p256v1 1.2.156.10197.1.301.

///|
fn sm2_oid_ecpub() -> Array[Byte] {
  [
    (0x06).to_byte(),
    (0x07).to_byte(),
    (0x2A).to_byte(),
    (0x86).to_byte(),
    (0x48).to_byte(),
    (0xCE).to_byte(),
    (0x3D).to_byte(),
    (0x02).to_byte(),
    (0x01).to_byte(),
  ]
}

///|
fn sm2_oid_curve() -> Array[Byte] {
  [
    (0x06).to_byte(),
    (0x08).to_byte(),
    (0x2A).to_byte(),
    (0x81).to_byte(),
    (0x1C).to_byte(),
    (0xCF).to_byte(),
    (0x55).to_byte(),
    (0x01).to_byte(),
    (0x82).to_byte(),
    (0x2D).to_byte(),
  ]
}

///|
fn sm2_algid() -> Array[Byte] {
  let body : Array[Byte] = []
  for b in sm2_oid_ecpub() {
    body.push(b)
  }
  for b in sm2_oid_curve() {
    body.push(b)
  }
  sm2_der_tlv(0x30, body)
}

///|
/// Encode a 32-byte secret key as PKCS#8 DER (PrivateKeyInfo wrapping
/// ECPrivateKey with the public key included, as openssl does).
pub fn sm2_sk_to_pkcs8_der(sk : Bytes) -> Bytes {
  guard sk.length() == 32 else {
    abort("sm2_sk_to_pkcs8_der: sk must be 32 bytes")
  }
  let pk = sm2_public_key(sk)
  let ska = Array::make(32, (0).to_byte())
  for i in 0..<32 {
    ska[i] = sk[i]
  }
  let bitstr = sm2_der_tlv(
    3,
    {
      let a : Array[Byte] = []
      a.push((0).to_byte())
      for i in 0..<65 {
        a.push(pk[i])
      }
      a
    },
  )
  let a1 = sm2_der_tlv(0xA1, bitstr)
  let inner : Array[Byte] = []
  for b in sm2_der_tlv(2, [(1).to_byte()]) {
    inner.push(b)
  }
  for b in sm2_der_tlv(4, ska) {
    inner.push(b)
  }
  for b in a1 {
    inner.push(b)
  }
  let body : Array[Byte] = []
  for b in sm2_der_tlv(2, [(0).to_byte()]) {
    body.push(b)
  }
  for b in sm2_algid() {
    body.push(b)
  }
  for b in sm2_der_tlv(4, sm2_der_tlv(0x30, inner)) {
    body.push(b)
  }
  Bytes::from_array(sm2_der_tlv(0x30, body)[:])
}

///|
/// Encode the 65-byte uncompressed public key as SPKI DER.
pub fn sm2_pk_to_spki_der(pk : Bytes) -> Bytes {
  guard pk.length() == 65 && pk[0] == (4).to_byte() else {
    abort("sm2_pk_to_spki_der: pk must be uncompressed 0x04||x||y")
  }
  let bits : Array[Byte] = []
  bits.push((0).to_byte())
  for i in 0..<65 {
    bits.push(pk[i])
  }
  let body : Array[Byte] = []
  for b in sm2_algid() {
    body.push(b)
  }
  for b in sm2_der_tlv(3, bits) {
    body.push(b)
  }
  Bytes::from_array(sm2_der_tlv(0x30, body)[:])
}

///|
/// Read a DER length at `pos`; returns (len, next_pos) or (-1, pos) on
/// invalid/reserved forms. Indefinite and multi-byte (>2) lengths rejected.
fn sm2_der_read_len(der : Bytes, pos : Int) -> (Int, Int) {
  if pos >= der.length() {
    return (-1, pos)
  }
  let b0 = der[pos].to_int()
  if b0 < 0x80 {
    return (b0, pos + 1)
  }
  let nbytes = b0 & 0x7F
  if nbytes == 0 || nbytes > 2 || pos + 1 + nbytes > der.length() {
    return (-1, pos)
  }
  let mut v = 0
  for i in 0..<nbytes {
    v = (v << 8) | der[pos + 1 + i].to_int()
  }
  (v, pos + 1 + nbytes)
}

///|
/// Match a byte sequence at pos; returns the advanced pos or -1.
fn sm2_der_expect(der : Bytes, pos : Int, want : Array[Byte]) -> Int {
  if pos < 0 || pos + want.length() > der.length() {
    return -1
  }
  for i in 0..<want.length() {
    if der[pos + i] != want[i] {
      return -1
    }
  }
  pos + want.length()
}

///|
/// Decode PKCS#8 DER (SM2) to the 32-byte secret key. Strict: exact OIDs,
/// exact structure, no trailing bytes. (b"", false) on any mismatch.
pub fn sm2_pkcs8_der_to_sk(der : Bytes) -> (Bytes, Bool) {
  let fail = (b"", false)
  if der.length() < 20 || der[0] != (0x30).to_byte() {
    return fail
  }
  let (outer_len, p1) = sm2_der_read_len(der, 1)
  if outer_len < 0 || p1 + outer_len != der.length() {
    return fail
  }
  // version INTEGER 0
  let p2 = sm2_der_expect(der, p1, [(2).to_byte(), (1).to_byte(), (0).to_byte()])
  if p2 < 0 {
    return fail
  }
  // algorithm identifier
  let p3 = sm2_der_expect(der, p2, sm2_algid())
  if p3 < 0 {
    return fail
  }
  // outer OCTET STRING wrapping the ECPrivateKey SEQUENCE
  if der[p3] != (4).to_byte() {
    return fail
  }
  let (oct_len, p4) = sm2_der_read_len(der, p3 + 1)
  if oct_len < 0 || p4 + oct_len != der.length() {
    return fail
  }
  if der[p4] != (0x30).to_byte() {
    return fail
  }
  let (inner_len, p5) = sm2_der_read_len(der, p4 + 1)
  if inner_len < 0 || p5 + inner_len != p4 + oct_len {
    return fail
  }
  // ECPrivateKey version INTEGER 1
  let p6 = sm2_der_expect(der, p5, [(2).to_byte(), (1).to_byte(), (1).to_byte()])
  if p6 < 0 {
    return fail
  }
  // privateKey OCTET STRING (32)
  if der[p6] != (4).to_byte() {
    return fail
  }
  let (sk_len, p7) = sm2_der_read_len(der, p6 + 1)
  if sk_len != 32 || p7 + 32 > der.length() {
    return fail
  }
  let sk = ec_slice(der, p7, 32)
  // optional [1] publicKey — if present, must be BIT STRING(00||04||x||y)
  let p8 = p7 + 32
  if p8 < p5 + inner_len {
    if der[p8] != (0xA1).to_byte() {
      return fail
    }
    let (a1_len, p9) = sm2_der_read_len(der, p8 + 1)
    if a1_len < 0 || p9 + a1_len != p5 + inner_len {
      return fail
    }
    if der[p9] != (3).to_byte() {
      return fail
    }
    let (bs_len, p10) = sm2_der_read_len(der, p9 + 1)
    if bs_len != 66 || p10 + 66 != p9 + a1_len {
      return fail
    }
    if der[p10] != (0).to_byte() || der[p10 + 1] != (4).to_byte() {
      return fail
    }
  }
  (sk, true)
}

///|
/// Decode SPKI DER (SM2) to the 65-byte uncompressed public key.
pub fn sm2_spki_der_to_pk(der : Bytes) -> (Bytes, Bool) {
  let fail = (b"", false)
  if der.length() < 20 || der[0] != (0x30).to_byte() {
    return fail
  }
  let (outer_len, p1) = sm2_der_read_len(der, 1)
  if outer_len < 0 || p1 + outer_len != der.length() {
    return fail
  }
  let p2 = sm2_der_expect(der, p1, sm2_algid())
  if p2 < 0 {
    return fail
  }
  if der[p2] != (3).to_byte() {
    return fail
  }
  let (bs_len, p3) = sm2_der_read_len(der, p2 + 1)
  if bs_len != 66 || p3 + 66 != der.length() {
    return fail
  }
  if der[p3] != (0).to_byte() || der[p3 + 1] != (4).to_byte() {
    return fail
  }
  (ec_slice(der, p3 + 1, 65), true)
}

///|
fn sm2_pem_wrap(b64 : String, header : String) -> String {
  let chars : Array[Char] = []
  for c in b64.iter() {
    chars.push(c)
  }
  let mut out = "-----BEGIN " + header + "-----\n"
  let mut i = 0
  while i < chars.length() {
    let line : Array[Char] = []
    while i < chars.length() && line.length() < 64 {
      line.push(chars[i])
      i = i + 1
    }
    out = out + String::from_array(line[:]) + "\n"
  }
  out + "-----END " + header + "-----\n"
}

///|
fn sm2_b64_char(c : Char) -> Bool {
  let code = c.to_int()
  (code >= 65 && code <= 90) ||
  (code >= 97 && code <= 122) ||
  (code >= 48 && code <= 57) ||
  code == 43 ||
  code == 47 ||
  code == 61
}

///|
/// Extract and decode the base64 body of a PEM block. Whitespace inside the
/// body is ignored; the first '-' after the body must start the END marker.
fn sm2_pem_unwrap(pem : String, header : String) -> (Bytes, Bool) {
  let begin = "-----BEGIN " + header + "-----"
  let endm = "-----END " + header + "-----"
  // state machine over chars: 0 seeking BEGIN, 1 collecting body, 2 done
  let bchars : Array[Char] = []
  for c in begin.iter() {
    bchars.push(c)
  }
  let echars : Array[Char] = []
  for c in endm.iter() {
    echars.push(c)
  }
  let all : Array[Char] = []
  for c in pem.iter() {
    all.push(c)
  }
  let mut state = 0
  let mut mi = 0
  let body : Array[Char] = []
  for i in 0..<all.length() {
    if state == 0 {
      if all[i] == bchars[mi] {
        mi = mi + 1
        if mi == bchars.length() {
          state = 1
          mi = 0
        }
      } else {
        mi = if all[i] == bchars[0] { 1 } else { 0 }
      }
    } else if state == 1 {
      if sm2_b64_char(all[i]) {
        body.push(all[i])
      } else if all[i] == '-' {
        state = 2 // END marker begins; this '-' IS echars[0]
        mi = 1
      } else if !(all[i] == '\n' || all[i] == '\r' || all[i] == ' ') {
        return (b"", false)
      }
    } else if state == 2 {
      // verify END marker chars in order
      if all[i] != echars[mi] {
        return (b"", false)
      }
      mi = mi + 1
      if mi == echars.length() {
        state = 3
      }
    }
    // state 3: trailing content after the END marker is ignored
  }
  if state != 3 {
    return (b"", false)
  }
  let decoded = base64_decode(String::from_array(body[:]))
  if decoded.length() == 0 {
    return (b"", false)
  }
  (decoded, true)
}

///|
/// PEM-encode a secret key (PKCS#8, "PRIVATE KEY", 64-char lines).
pub fn sm2_sk_to_pem(sk : Bytes) -> String {
  sm2_pem_wrap(base64_encode(sm2_sk_to_pkcs8_der(sk)), "PRIVATE KEY")
}

///|
/// Parse a PKCS#8 "PRIVATE KEY" PEM; strict (see sm2_pkcs8_der_to_sk).
pub fn sm2_sk_from_pem(pem : String) -> (Bytes, Bool) {
  let (der, ok) = sm2_pem_unwrap(pem, "PRIVATE KEY")
  if !ok {
    return (b"", false)
  }
  sm2_pkcs8_der_to_sk(der)
}

///|
/// PEM-encode a public key (SPKI, "PUBLIC KEY", 64-char lines).
pub fn sm2_pk_to_pem(pk : Bytes) -> String {
  sm2_pem_wrap(base64_encode(sm2_pk_to_spki_der(pk)), "PUBLIC KEY")
}

///|
/// Parse an SPKI "PUBLIC KEY" PEM; strict (see sm2_spki_der_to_pk).
pub fn sm2_pk_from_pem(pem : String) -> (Bytes, Bool) {
  let (der, ok) = sm2_pem_unwrap(pem, "PUBLIC KEY")
  if !ok {
    return (b"", false)
  }
  sm2_spki_der_to_pk(der)
}
