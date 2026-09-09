// Falcon benchmarks (512): keygen, sign, verify.

///|
fn falcon_bench_keys() -> (Bytes, Bytes) {
  let r = falcon_test_rng_init()
  let seed = falcon_test_rng_bytes(r, 48)
  falcon512_keypair_from_seed(seed)
}

///|
fn falcon_bench_msg() -> Bytes {
  let a : Array[Byte] = []
  for i = 0; i < 64; i = i + 1 {
    a.push(((i * 31) & 0xFF).to_byte())
  }
  Bytes::from_array(a)
}

///|
fn falcon_bench_rand() -> (Int) -> Bytes {
  let r = falcon_test_rng_init()
  falcon_test_rng_set_ctr(r, 3UL)
  fn(k : Int) -> Bytes { falcon_test_rng_bytes(r, k) }
}

///|
test "bench falcon512 keygen" (it : @bench.T) {
  it.bench(fn() {
    let r = falcon_test_rng_init()
    let seed = falcon_test_rng_bytes(r, 48)
    it.keep(falcon512_keypair_from_seed(seed))
  })
}

///|
test "bench falcon512 sign" (it : @bench.T) {
  let (_, sk) = falcon_bench_keys()
  let msg = falcon_bench_msg()
  it.bench(fn() { it.keep(falcon512_sign(sk, msg, falcon_bench_rand())) })
}

///|
test "bench falcon512 verify" (it : @bench.T) {
  let (pk, sk) = falcon_bench_keys()
  let msg = falcon_bench_msg()
  let sig = falcon512_sign(sk, msg, falcon_bench_rand())
  it.bench(fn() { it.keep(falcon512_verify(pk, sig, msg)) })
}
