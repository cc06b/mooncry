// ==================== Phase-2 benchmarks: new algorithms ====================
// Run with: moon bench
// Throughput of the algorithms added in this phase on 1 KiB inputs.

///|
fn phase2_bench_input(len : Int) -> Bytes {
  let arr = Array::make(len, b'\x00')
  for i in 0..<len {
    arr[i] = (i % 251).to_byte()
  }
  Bytes::from_array(arr[:])
}

///|
test "bench hmac_sha3_256 1KiB" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  let key = phase2_bench_input(32)
  it.bench(fn() { it.keep(hmac_sha3_256(key, data)) })
}

///|
test "bench hmac_sha3_512 1KiB" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  let key = phase2_bench_input(32)
  it.bench(fn() { it.keep(hmac_sha3_512(key, data)) })
}

///|
test "bench cmac_aes 1KiB (AES-128)" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  let key = phase2_bench_input(16)
  it.bench(fn() { it.keep(cmac_aes(data, key)) })
}

///|
test "bench crc32 1KiB" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  it.bench(fn() { it.keep(crc32(data)) })
}

///|
test "bench crc32c 1KiB" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  it.bench(fn() { it.keep(crc32c(data)) })
}

///|
test "bench siphash_2_4 1KiB" (it : @bench.T) {
  let data = phase2_bench_input(1024)
  let key = phase2_bench_input(16)
  it.bench(fn() { it.keep(siphash_2_4(key, data)) })
}

///|
test "bench sealed_box_seal 1KiB" (it : @bench.T) {
  let pt = phase2_bench_input(1024)
  let key = phase2_bench_input(32)
  let nonce = Bytes::make(12, b'\x00')
  it.bench(fn() { it.keep(sealed_box_seal(key, nonce, pt, b"", b"ctx")) })
}
