///|
fn main {
  @username/cryptoult.run_all_tests()
  println("")
  @username/cryptoult.bench_sha256()
  println("")
  @username/cryptoult.bench_aes128()
}
