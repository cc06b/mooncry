// Falcon M5a tests: prng (Salsa20), Gaussian sampler, fpr floor/trunc/
// sqrt/expm_p63 vs dumps from the official C reference.

///|
fn m5a_seed() -> Bytes {
  let a = Array::make(48, (0).to_byte())
  for i = 0; i < 48; i = i + 1 {
    a[i] = ((i * 11 + 5) & 0xFF).to_byte()
  }
  Bytes::from_array(a)
}

///|
fn m5a_fresh_prng() -> FalconPrng {
  let x = falcon_xof_init()
  falcon_xof_inject(x, m5a_seed())
  let _ = falcon_xof_extract(x, 0)
  falcon_prng_init(x)
}

///|
test "falcon-m5a-prng" {
  let p = m5a_fresh_prng()
  // u8 draws
  let e8 : Array[Int] = [
    6, 173, 76, 134, 187, 204, 188, 172, 166, 227, 187, 195, 215, 167, 82, 118,
  ]
  let mut ok2 = true
  for i = 0; i < 16; i = i + 1 {
    if prng_get_u8(p) != e8[i] {
      ok2 = false
    }
  }
  let e64 : Array[UInt64] = [
    0x8b6bf2c1ec49b22fUL, 0xa72e1a2c0cfda39bUL, 0xddf72d4dc07b57e0UL, 0xd545ea4290d0ab9aUL,
  ]
  for i = 0; i < 4; i = i + 1 {
    if prng_get_u64(p) != e64[i] {
      ok2 = false
    }
  }
  let e8b : Array[Int] = [196, 97, 183, 204, 45, 47, 224, 147]
  for i = 0; i < 8; i = i + 1 {
    if prng_get_u8(p) != e8b[i] {
      ok2 = false
    }
  }
  inspect(ok2, content="true")
  // buffer layout check via hex compare
  let expbuf = "06ad4c86bbccbcaca6e3bbc3d7a752762fb249ecc1f26b8b9ba3fd0c2c1a2ea7"
  let p2 = m5a_fresh_prng()
  let mut got = ""
  let digits : Array[String] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  for i = 0; i < 32; i = i + 1 {
    let v = p2.buf[i].to_int()
    got = got + digits[(v >> 4) & 15] + digits[v & 15]
  }
  inspect(got, content=expbuf)
}

///|
test "falcon-m5a-gaussian0" {
  let p = m5a_fresh_prng()
  let e : Array[Int] = [0, 0, 0, 0, 2, 2, 1, 5, 0, 0, 3, 0, 5, 3, 0, 0]
  let mut ok = true
  for i = 0; i < 16; i = i + 1 {
    if falcon_gaussian0_sampler(p) != e[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m5a-sampler" {
  let p = m5a_fresh_prng()
  let ctx = falcon_sampler_ctx_make(
    p,
    4608433670533905013UL.reinterpret_as_double(),
  )
  let e : Array[Int] = [-1, -2, -2, 0, -2, -1, -1, 0, 0, 0, -1, 2, 4, 3, -4, -1]
  let mut ok = true
  for i = 0; i < 16; i = i + 1 {
    let mu = (i * 37 % 500 - 250).to_double() / 100.0
    if falcon_sampler(ctx, mu, 4573606369665796042UL.reinterpret_as_double()) !=
      e[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m5a-floor-trunc" {
  let vals : Array[Double] = [
    -2.7, 2.7, -0.3, 0.3, 1000000000000000000.0, -1000000000000000000.0, 0.0, 12345.67,
  ]
  let ef : Array[Int64] = [
    -3L, 2L, -1L, 0L, 1000000000000000000L, -1000000000000000000L, 0L, 12345L,
  ]
  let et : Array[Int64] = [
    -2L, 2L, 0L, 0L, 1000000000000000000L, -1000000000000000000L, 0L, 12345L,
  ]
  let mut ok = true
  for i = 0; i < 8; i = i + 1 {
    if fp_floor(vals[i]) != ef[i] {
      ok = false
    }
    if fp_trunc(vals[i]) != et[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m5a-sqrt" {
  let pos : Array[Double] = [0.0, 1.0, 2.0, 4.0, 123456789.0, 1.0 / 1024.0]
  let es : Array[UInt64] = [
    0x0000000000000000UL, 0x3ff0000000000000UL, 0x3ff6a09e667f3bcdUL, 0x4000000000000000UL,
    0x40c5b38e373b76feUL, 0x3fa0000000000000UL,
  ]
  let mut ok = true
  for i = 0; i < 6; i = i + 1 {
    if fp_sqrt(pos[i]).reinterpret_as_uint64() != es[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m5a-expm" {
  let log2 = 4604418534313441775UL.reinterpret_as_double()
  let ccs = 4573606369665796042UL.reinterpret_as_double() *
    4608433670533905013UL.reinterpret_as_double()
  let ee : Array[UInt64] = [
    0x00fca463a8885988UL, 0x00ec36d1e2c703c3UL, 0x00dcdab77dc7183bUL, 0x00ce7e4c4242e4d7UL,
    0x00c110effabb7b6aUL, 0x00b4831734095a29UL, 0x00a8c6393e54e1c8UL, 0x009dccbf59a104a7UL,
  ]
  let mut ok = true
  for i = 0; i < 8; i = i + 1 {
    let x = (i * 97).to_double() * (log2 / 1000.0)
    if fp_expm_p63(x, ccs) != ee[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}
