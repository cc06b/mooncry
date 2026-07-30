// ==================== Phase-3 benchmarks: Argon2 / ECDSA / AES-SIV / AES-KW ====================
// Run with: moon bench. Throughput/timing of the algorithms added in
// 0.9.0–0.13.0 on representative inputs.

///|
fn p3_bench_input(len : Int) -> Bytes {
  let arr = Array::make(len, b'\x00')
  for i in 0..<len {
    arr[i] = (i % 251).to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "bench argon2id (t=1 m=64 p=1 hash=16)" (it : @bench.T) {
  it.bench(fn() { it.keep(argon2id(b"password", b"somesalt", 1, 64, 1, 16)) })
}

///|
test "bench ecdsa_p256_sign" (it : @bench.T) {
  let d = p3_bench_input(32)
  let msg = p3_bench_input(64)
  it.bench(fn() { it.keep(ecdsa_p256_sign(d, msg)) })
}

///|
test "bench ecdsa_p256_verify" (it : @bench.T) {
  let d = p3_bench_input(32)
  let q = ecdsa_p256_public_key(d)
  let msg = p3_bench_input(64)
  let sig = ecdsa_p256_sign(d, msg)
  it.bench(fn() { it.keep(ecdsa_p256_verify(q, msg, sig)) })
}

///|
test "bench aes_siv_encrypt 1KiB (AES-256, 1 AD)" (it : @bench.T) {
  let key = p3_bench_input(64)
  let pt = p3_bench_input(1024)
  let ads : Array[Bytes] = [b"associated data"]
  it.bench(fn() { it.keep(aes_siv_encrypt(key, pt, ads)) })
}

///|
test "bench aes_kw_wrap 32B (AES-128)" (it : @bench.T) {
  let kek = p3_bench_input(16)
  let data = p3_bench_input(32)
  it.bench(fn() { it.keep(aes_kw_wrap(kek, data)) })
}

///|
test "bench scrypt N=16 r=1 p=1 dk=16" (it : @bench.T) {
  it.bench(fn() { it.keep(scrypt(b"password", b"salt", 16, 1, 1, 16)) })
}
