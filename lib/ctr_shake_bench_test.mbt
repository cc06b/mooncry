// ==================== AES-CTR + SHAKE benchmarks ====================

///|
test "bench aes_ctr 4KB (AES-256)" (it : @bench.T) {
  let data = bench_input(4096)
  let key = bench_input(32)
  let iv = bench_input(16)
  it.bench(fn() { it.keep(aes_ctr(data, key, iv)) })
}

///|
test "bench shake_128 4KB (out=32)" (it : @bench.T) {
  let data = bench_input(4096)
  it.bench(fn() { it.keep(shake_128(data, 32)) })
}

///|
test "bench shake_256 4KB (out=64)" (it : @bench.T) {
  let data = bench_input(4096)
  it.bench(fn() { it.keep(shake_256(data, 64)) })
}
