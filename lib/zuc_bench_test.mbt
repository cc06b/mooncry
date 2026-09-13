// ==================== ZUC benchmarks ====================
//
// Throughput numbers for the ZUC family at 1 KiB, so the cost of the LFSR-based
// design can be compared against the library's other stream ciphers
// (`bench chacha20_xor 1KiB`) and against AES-CTR.

///|
test "bench zuc_xor 1KiB (ZUC-128 stream)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(16)
  let iv = bench_input(16)
  it.bench(fn() { it.keep(zuc_xor(key, iv, data)) })
}

///|
test "bench zuc_eea3 1KiB (128-EEA3)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(16)
  it.bench(fn() { it.keep(zuc_eea3_encrypt(key, 0U, 1, 0, 8192, data)) })
}

///|
test "bench zuc_eia3 1KiB (128-EIA3 MAC)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(16)
  it.bench(fn() { it.keep(zuc_eia3_mac(key, 0U, 1, 0, 8192, data)) })
}

///|
test "bench zuc256_xor 1KiB (ZUC-256 stream)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let iv = bench_input(23)
  it.bench(fn() { it.keep(zuc256_xor(key, iv, data)) })
}

///|
test "bench zuc256_mac 1KiB (128-bit tag)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let iv = bench_input(23)
  it.bench(fn() { it.keep(zuc256_mac(key, iv, 128, 8192, data)) })
}
