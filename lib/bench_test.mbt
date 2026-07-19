// ============================================================
// mooncry benchmarks — run with: moon bench
// Measures throughput of the core hash / cipher / encoding
// primitives. Inputs are deterministic non-zero patterns so the
// optimizer cannot fold the workload away.
// ============================================================

///|
/// Build a deterministic non-zero input of the given length
fn bench_input(len : Int) -> Bytes {
  let buf = Array::make(len, b'\x00')
  for i in 0..<len {
    buf[i] = ((i * 7 + 13) & 0xFF).to_byte()
  }
  Bytes::from_array(buf[:])
}

///|
test "bench sha256 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha256(data)) })
}

///|
test "bench sha512 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha512(data)) })
}

///|
test "bench md5 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(md5(data)) })
}

///|
test "bench hmac_sha256 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  it.bench(fn() { it.keep(hmac_sha256(key, data)) })
}

///|
test "bench aes_cbc_encrypt 1KiB (AES-256)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let iv = bench_input(16)
  it.bench(fn() { it.keep(aes_encrypt_cbc(data, key, iv)) })
}

///|
test "bench aes_gcm_encrypt 1KiB (AES-256)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let iv = bench_input(12)
  let aad = bench_input(16)
  it.bench(fn() {
    let (ct, tag) = aes_gcm_encrypt(data, key, iv, aad)
    it.keep(ct)
    it.keep(tag)
  })
}

///|
test "bench chacha20_xor 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let nonce = bench_input(12)
  it.bench(fn() { it.keep(chacha20_xor(data, key, nonce, 0U)) })
}

///|
test "bench base64_encode 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(base64_encode(data)) })
}

///|
test "bench bytes_to_hex 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(bytes_to_hex(data)) })
}

///|
test "bench sha256 streaming 1KiB (1-byte chunks)" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() {
    let h = sha256_new()
    for i in 0..<data.length() {
      sha256_update(h, Bytes::make(1, data[i]))
    }
    it.keep(sha256_finalize(h))
  })
}

///|
test "bench sha224 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha224(data)) })
}

///|
test "bench sha384 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha384(data)) })
}

///|
test "bench hmac_sha512 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(64)
  it.bench(fn() { it.keep(hmac_sha512(key, data)) })
}

///|
test "bench pbkdf2_sha256 iter=100 dklen=32" (it : @bench.T) {
  it.bench(fn() { it.keep(pbkdf2_hmac_sha256(b"password", b"salt", 100, 32)) })
}

///|
test "bench hkdf_sha256 L=256" (it : @bench.T) {
  it.bench(fn() { it.keep(hkdf_sha256(b"salt", bench_input(64), b"info", 256)) })
}
