///|
test "bench blake2b 1KiB" (it : @bench.T) {
  let data = Bytes::make(1024, b'')
  it.bench(fn() {
    let _ = blake2b(data, 64)
    it.keep(data)
  })
}
