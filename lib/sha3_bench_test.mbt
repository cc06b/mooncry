// ==================== SHA-3 benchmarks ====================

///|
test "bench sha3_256 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha3_256(data)) })
}

///|
test "bench sha3_512 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(sha3_512(data)) })
}
