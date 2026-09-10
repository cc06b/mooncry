// SM2 encryption vectors: python reference with the GB/T 32918.5 example
// key and fixed k, cross-proven by openssl pkeyutl SM2 decrypt of the DER
// form (see agent_box/_sm2_enc_oracle.py). Message: "encryption standard".

///|
fn sm2e_msg() -> Bytes {
  b"encryption standard"
}

///|
fn sm2e_k() -> Bytes {
  hex_to_bytes(
    "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
  )
}

///|
fn sm2e_ct_hex() -> String {
  "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa"
}

///|
test "sm2-encrypt-fixed-k-oracle" {
  let ct = sm2_encrypt_with_k(sm2_ex_pk(), sm2e_msg(), sm2e_k())
  inspect(
    bytes_to_hex(ct),
    content="0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa",
  )
  // decrypt with the GB example secret key must recover the message
  let (pt, ok) = sm2_decrypt(sm2_ex_sk(), ct)
  inspect(ok, content="true")
  inspect(bytes_equal(pt, sm2e_msg()), content="true")
}

///|
test "sm2-encrypt-random-roundtrip" {
  for seed in 1..<=3 {
    let ska = Array::make(32, (0).to_byte())
    ska[31] = (seed * 13 + 5).to_byte()
    ska[30] = (seed * 29 + 1).to_byte()
    let sk = Bytes::from_array(ska[:])
    let pk = sm2_public_key(sk)
    let msg = Bytes::make(seed * 23 + 10, (0x41 + seed).to_byte())
    let ct = sm2_encrypt(pk, msg, sm2_test_rand(seed * 5))
    let (pt, ok) = sm2_decrypt(sk, ct)
    inspect(ok, content="true")
    inspect(bytes_equal(pt, msg), content="true")
    // wrong key: C3 check must fail (false, not abort)
    let oth = Array::make(32, (0).to_byte())
    oth[31] = (99).to_byte()
    let (_, ok2) = sm2_decrypt(Bytes::from_array(oth[:]), ct)
    inspect(ok2, content="false")
  }
}

///|
test "sm2-decrypt-rejects" {
  let ct = hex_to_bytes(sm2e_ct_hex())
  // flipped C2 byte -> C3 mismatch
  let bad = Array::make(ct.length(), (0).to_byte())
  for i in 0..<ct.length() {
    bad[i] = ct[i]
  }
  bad[100] = (bad[100].to_int() ^ 1).to_byte()
  let (_, ok1) = sm2_decrypt(sm2_ex_sk(), Bytes::from_array(bad[:]))
  inspect(ok1, content="false")
  // flipped C3 byte
  bad[70] = (bad[70].to_int() ^ 2).to_byte()
  bad[100] = ct[100]
  let (_, ok2) = sm2_decrypt(sm2_ex_sk(), Bytes::from_array(bad[:]))
  inspect(ok2, content="false")
  // bad C1 prefix
  bad[70] = ct[70]
  bad[0] = (5).to_byte()
  let (_, ok3) = sm2_decrypt(sm2_ex_sk(), Bytes::from_array(bad[:]))
  inspect(ok3, content="false")
  // off-curve C1 (x+1)
  bad[0] = (4).to_byte()
  bad[32] = (bad[32].to_int() + 1).to_byte()
  let (_, ok4) = sm2_decrypt(sm2_ex_sk(), Bytes::from_array(bad[:]))
  inspect(ok4, content="false")
  // too short
  let (_, ok5) = sm2_decrypt(sm2_ex_sk(), Bytes::make(96, (0).to_byte()))
  inspect(ok5, content="false")
}

///|
test "sm2-der-interop" {
  // The DER below is byte-identical to the ciphertext python produced and
  // openssl pkeyutl decrypted (gb_ct.der in the oracle run).
  let der = hex_to_bytes(
    "307c022004ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73022100e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0042059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766041321886ca989ca9c7d58087307ca93092d651efa",
  )
  let (raw, ok) = sm2_ct_from_der(der)
  inspect(ok, content="true")
  inspect(bytes_to_hex(raw), content=sm2e_ct_hex())
  // raw -> DER must reproduce the openssl-compatible encoding exactly
  inspect(
    bytes_to_hex(sm2_ct_to_der(raw)),
    content="307c022004ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73022100e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0042059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766041321886ca989ca9c7d58087307ca93092d651efa",
  )
  // decrypt via the DER path
  let (pt, ok2) = sm2_decrypt(sm2_ex_sk(), raw)
  inspect(ok2, content="true")
  inspect(bytes_equal(pt, sm2e_msg()), content="true")
  // malformed DER rejected
  let (_, bad) = sm2_ct_from_der(Bytes::make(20, (0x30).to_byte()))
  inspect(bad, content="false")
}
