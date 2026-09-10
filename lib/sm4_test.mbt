///|
fn sm4_hex16(s : String) -> Bytes {
  hex_to_bytes(s)
}

///|
test "sm4-gb-official-vector" {
  // GB/T 32907-2016 Appendix A Example 1
  let key = sm4_hex16("0123456789abcdeffedcba9876543210")
  let pt = sm4_hex16("0123456789abcdeffedcba9876543210")
  inspect(
    bytes_to_hex(sm4_encrypt(key, pt)),
    content="681edf34d206965e86b3e94f536e4246",
  )
  inspect(
    bytes_to_hex(sm4_decrypt(key, sm4_encrypt(key, pt))),
    content="0123456789abcdeffedcba9876543210",
  )
}

///|
test "sm4-gb-official-1e6-iterations" {
  // GB/T 32907-2016 Appendix A Example 2: encrypt the result 1,000,000 times
  let key = sm4_hex16("0123456789abcdeffedcba9876543210")
  let rk = sm4_expand_key(key)
  let mut block = sm4_hex16("0123456789abcdeffedcba9876543210")
  for _ in 0..<1000000 {
    block = sm4_encrypt_block(rk, block, 0)
  }
  inspect(bytes_to_hex(block), content="595298c7c6fd271f0402f804c33d3f66")
}

///|
test "sm4-extra-oracle-vectors" {
  // Cross-checked against openssl (cryptography package) SM4-ECB: all-zero
  // edge case plus three structured key/plaintext pairs; decrypt must invert.
  let ks = [
    "00000000000000000000000000000000", "0d32577ca1c6eb10355a7fa4c9ee1338", "688db2d7fc21466b90b5daff24496e93",
    "c3e80d32577ca1c6eb10355a7fa4c9ee",
  ]
  let ps = [
    "00000000000000000000000000000000", "073c71a6db10457aafe4194e83b8ed22", "4e83b8ed22578cc1f62b6095caff3469",
    "95caff34699ed3083d72a7dc11467bb0",
  ]
  let cs = [
    "9f1f7bff6f5511384d9430531e538fd3", "2ba7d73204cf1c9155f0d0b8230b0c9e", "d5a5f7784f990ac43f99d80a96fc1c67",
    "8f48c791a6d75bd89ecc596b4e4765a8",
  ]
  for i in 0..<4 {
    let key = sm4_hex16(ks[i])
    let pt = sm4_hex16(ps[i])
    let ct = sm4_encrypt(key, pt)
    inspect(bytes_to_hex(ct), content=cs[i])
    inspect(bytes_equal(sm4_decrypt(key, ct), pt), content="true")
  }
}
