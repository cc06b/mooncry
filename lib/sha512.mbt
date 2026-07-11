// ==================== SHA-512 (FIPS 180-4) ====================

///|
/// SHA-512 constants — first 80 primes' cube-root fractional parts
let sha512_k : Array[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn sha512_sig0(x : UInt64) -> UInt64 {
  rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
}

///|
fn sha512_sig1(x : UInt64) -> UInt64 {
  rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)
}

///|
fn sha512_cap_sig0(x : UInt64) -> UInt64 {
  rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)
}

///|
fn sha512_cap_sig1(x : UInt64) -> UInt64 {
  rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)
}

///|
fn sha512_ch(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ ((0xFFFFFFFFFFFFFFFFUL ^ x) & z)
}

///|
fn sha512_maj(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
fn read_u64_be(data : Bytes, offset : Int) -> UInt64 {
  (data[offset].to_uint64() << 56) |
  (data[offset + 1].to_uint64() << 48) |
  (data[offset + 2].to_uint64() << 40) |
  (data[offset + 3].to_uint64() << 32) |
  (data[offset + 4].to_uint64() << 24) |
  (data[offset + 5].to_uint64() << 16) |
  (data[offset + 6].to_uint64() << 8) |
  data[offset + 7].to_uint64()
}

///|
fn write_u64_be(arr : Array[Byte], offset : Int, val : UInt64) -> Unit {
  arr[offset] = ((val >> 56) & 0xFFUL).to_byte()
  arr[offset + 1] = ((val >> 48) & 0xFFUL).to_byte()
  arr[offset + 2] = ((val >> 40) & 0xFFUL).to_byte()
  arr[offset + 3] = ((val >> 32) & 0xFFUL).to_byte()
  arr[offset + 4] = ((val >> 24) & 0xFFUL).to_byte()
  arr[offset + 5] = ((val >> 16) & 0xFFUL).to_byte()
  arr[offset + 6] = ((val >> 8) & 0xFFUL).to_byte()
  arr[offset + 7] = (val & 0xFFUL).to_byte()
}

///|
fn sha512_process_block(state : Array[UInt64], block : Array[UInt64]) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  let w = Array::make(80, 0UL)
  for i in 0..<=15 {
    w[i] = block[i]
  }
  for i in 16..<=79 {
    w[i] = sha512_sig1(w[i - 2]) + w[i - 7] + sha512_sig0(w[i - 15]) + w[i - 16]
  }
  for i in 0..<=79 {
    let t1 = h + sha512_cap_sig1(e) + sha512_ch(e, f, g) + sha512_k[i] + w[i]
    let t2 = sha512_cap_sig0(a) + sha512_maj(a, b, c)
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
/// Compute SHA-512 (FIPS 180-4), 64-byte digest. Delegates to the streaming hasher.
pub fn sha512(data : Bytes) -> Bytes {
  let hasher = sha512_new()
  sha512_update(hasher, data)
  sha512_finalize(hasher)
}
