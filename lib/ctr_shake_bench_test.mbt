// ==================== AES-CTR + SHAKE benchmarks ====================

///|
test "bench aes_ctr 1KiB (AES-256)" (it : @bench.T) {
  let data = bench_input(1024)
  let key = bench_input(32)
  let iv = bench_input(16)
  it.bench(fn() { it.keep(aes_ctr(data, key, iv)) })
}

///|
test "bench shake_128 1KiB (out=32)" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(shake_128(data, 32)) })
}

///|
test "bench shake_256 1KiB (out=64)" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(shake_256(data, 64)) })
}
