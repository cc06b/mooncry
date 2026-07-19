///|
test "bench blake2b 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(blake2b(data, 64)) })
}

///|
test "bench blake3 1KiB" (it : @bench.T) {
  let data = bench_input(1024)
  it.bench(fn() { it.keep(blake3(data)) })
}
