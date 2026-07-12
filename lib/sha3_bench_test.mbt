// ==================== SHA-3 benchmarks ====================

///|
test "bench sha3_256 4KB" (it : @bench.T) {
  let data = bench_input(4096)
  it.bench(fn() { it.keep(sha3_256(data)) })
}

///|
test "bench sha3_512 4KB" (it : @bench.T) {
  let data = bench_input(4096)
  it.bench(fn() { it.keep(sha3_512(data)) })
}
