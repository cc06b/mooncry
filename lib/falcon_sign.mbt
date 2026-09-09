// Falcon M5a: signing randomness layer — the Salsa20-based prng
// (rng.c), the discrete Gaussian sampler (sign.c gaussian0_sampler /
// BerExp / sampler), and the fpr extensions it needs (floor/trunc/
// sqrt/expm_p63/FPR packing from fpr.h/fpr.c). Faithful ports;
// verified against dumps from the official C reference.

///|
/// PRNG state: 48-byte key + 8-byte counter (state.d), 512-byte
/// output buffer, read pointer. Mirrors rng.c including the AVX2-style
/// 4-way interleaved buffer layout.
pub struct FalconPrng {
  st : Array[Byte] // 56 bytes: key(48) || counter(8, LE)
  buf : Array[Byte] // 512 bytes
  mut ptr : Int
}

///|
fn prng_refill(p : FalconPrng) -> Unit {
  // CW = "expa" "nd 3" "2-by" "te k" (little-endian u32)
  let cw0 = 0x61707865L
  let cw1 = 0x3320646EL
  let cw2 = 0x79622D32L
  let cw3 = 0x6B206574L
  let m32 = 0xFFFFFFFFL
  let mut cc = 0UL
  for i = 0; i < 8; i = i + 1 {
    cc = cc | (p.st[48 + i].to_uint64() << (i * 8))
  }
  // key words w[0..12) from st[0..48), LE
  let kw = Array::make(12, 0L)
  for i = 0; i < 12; i = i + 1 {
    let mut w = 0L
    for b = 0; b < 4; b = b + 1 {
      w = w | (p.st[i * 4 + b].to_int64() << (b * 8))
    }
    kw[i] = w
  }
  for u = 0; u < 8; u = u + 1 {
    let state = Array::make(16, 0L)
    state[0] = cw0
    state[1] = cw1
    state[2] = cw2
    state[3] = cw3
    for i = 0; i < 12; i = i + 1 {
      state[4 + i] = kw[i]
    }
    let ccl = u32bits(cc & 0xFFFFFFFFUL)
    let cch = u32bits(cc >> 32)
    state[14] = state[14] ^ ccl
    state[15] = state[15] ^ cch
    for _i = 0; _i < 10; _i = _i + 1 {
      qround(state, 0, 4, 8, 12)
      qround(state, 1, 5, 9, 13)
      qround(state, 2, 6, 10, 14)
      qround(state, 3, 7, 11, 15)
      qround(state, 0, 5, 10, 15)
      qround(state, 1, 6, 11, 12)
      qround(state, 2, 7, 8, 13)
      qround(state, 3, 4, 9, 14)
    }
    state[0] = (state[0] + cw0) & m32
    state[1] = (state[1] + cw1) & m32
    state[2] = (state[2] + cw2) & m32
    state[3] = (state[3] + cw3) & m32
    for v = 4; v < 14; v = v + 1 {
      state[v] = (state[v] + kw[v - 4]) & m32
    }
    state[14] = (state[14] + (kw[10] ^ ccl)) & m32
    state[15] = (state[15] + (kw[11] ^ cch)) & m32
    cc = cc + 1UL
    for v = 0; v < 16; v = v + 1 {
      let sv = state[v]
      p.buf[(u << 2) + (v << 5)] = (sv & 0xFFL).to_int().to_byte()
      p.buf[(u << 2) + (v << 5) + 1] = ((sv >> 8) & 0xFFL).to_int().to_byte()
      p.buf[(u << 2) + (v << 5) + 2] = ((sv >> 16) & 0xFFL).to_int().to_byte()
      p.buf[(u << 2) + (v << 5) + 3] = ((sv >> 24) & 0xFFL).to_int().to_byte()
    }
  }
  for i = 0; i < 8; i = i + 1 {
    p.st[48 + i] = ((cc >> (i * 8)) & 0xFFUL).to_byte()
  }
  p.ptr = 0
}

///|
/// Salsa quarter-round, exact C macro order (a+=b first), u32 words
/// held masked in Int64.
fn qround(s : Array[Int64], a : Int, b : Int, c : Int, d : Int) -> Unit {
  let m = 0xFFFFFFFFL
  s[a] = (s[a] + s[b]) & m
  s[d] = fp_rotl32(s[d] ^ s[a], 16)
  s[c] = (s[c] + s[d]) & m
  s[b] = fp_rotl32(s[b] ^ s[c], 12)
  s[a] = (s[a] + s[b]) & m
  s[d] = fp_rotl32(s[d] ^ s[a], 8)
  s[c] = (s[c] + s[d]) & m
  s[b] = fp_rotl32(s[b] ^ s[c], 7)
}

///|
/// 32-bit left rotate on a masked u32-in-Int64.
fn fp_rotl32(x : Int64, n : Int) -> Int64 {
  let m = 0xFFFFFFFFL
  let xm = x & m
  ((xm << n) | (xm >> (32 - n))) & m
}

///|
/// Initialize the prng from a flipped XOF (extracts 56 bytes).
pub fn falcon_prng_init(x : FalconXof) -> FalconPrng {
  let tmp = falcon_xof_extract(x, 56)
  let st = Array::make(56, (0).to_byte())
  for i = 0; i < 56; i = i + 1 {
    st[i] = tmp[i]
  }
  // C: d64[6] = d32[12] + (d32[13] << 32) — identity on LE bytes; no-op.
  let p : FalconPrng = { st, buf: Array::make(512, (0).to_byte()), ptr: 0, }
  prng_refill(p)
  p
}

///|
/// Get a little-endian u64 (refill when fewer than 9 bytes remain).
pub fn prng_get_u64(p : FalconPrng) -> UInt64 {
  let mut u = p.ptr
  if u >= 512 - 9 {
    prng_refill(p)
    u = 0
  }
  p.ptr = u + 8
  let mut r = 0UL
  for i = 0; i < 8; i = i + 1 {
    r = r | (p.buf[u + i].to_uint64() << (i * 8))
  }
  r
}

///|
/// Get one byte (refill exactly when the buffer is exhausted).
pub fn prng_get_u8(p : FalconPrng) -> Int {
  let v = p.buf[p.ptr].to_int()
  p.ptr = p.ptr + 1
  if p.ptr == 512 {
    prng_refill(p)
  }
  v
}

// ---------------------------------------------------------------------------
// fpr extensions (fpr.h bit tricks)
// ---------------------------------------------------------------------------

///|
/// FPR(s, e, m): pack sign/exponent/scaled-mantissa (m in [2^54,2^55))
/// into an f64, with round-to-nearest-even on the dropped 2 bits.
fn fpr_pack(sgn : Int, e0 : Int, m0 : UInt64) -> Double {
  let e = e0 + 1076
  let mut m = m0
  if e < 0 {
    m = 0UL
  }
  let t2 = m >> 54
  let mut ee = e
  if t2 == 0UL {
    ee = 0
  }
  let mut x = ((sgn.to_uint64() << 63) | (m >> 2)) +
    ((ee.to_int64() & 0xFFFFFFFFL).reinterpret_as_uint64() << 52)
  let f = ((m & 7UL) >> 0).reinterpret_as_int64().to_int()
  x = x + ((0xC8 >> f) & 1).to_uint64()
  x.reinterpret_as_double()
}

///|
/// floor(x) as Int64 (bit-exact port of fpr_floor).
pub fn fp_floor(x : Double) -> Int64 {
  let xb = x.reinterpret_as_uint64()
  let e = ((xb >> 52) & 0x7FFUL).reinterpret_as_int64().to_int()
  let t = xb >> 63
  let mut xi = (((xb << 10) | (1UL << 62)) & 0x7FFFFFFFFFFFFFFFUL).reinterpret_as_int64()
  let ti = t.reinterpret_as_int64()
  xi = (xi ^ (0L - ti)) + ti
  let cc = 1085 - e
  // arithmetic shift by (cc & 63); cc&63 in 0..63
  let sh = cc & 63
  xi = xi >> sh
  // if the true shift was >= 64: xi = 0 (t=0) or -1 (t=1)
  if 63 - cc < 0 {
    xi = 0L - ti
  }
  xi
}

///|
/// trunc(x) as Int64 (bit-exact port of fpr_trunc).
pub fn fp_trunc(x : Double) -> Int64 {
  let xb = x.reinterpret_as_uint64()
  let e = ((xb >> 52) & 0x7FFUL).reinterpret_as_int64().to_int()
  let mut xu = (xb << 10) | (1UL << 62)
  xu = xu & 0x7FFFFFFFFFFFFFFFUL
  let cc = 1085 - e
  xu = xu >> (cc & 63)
  if cc - 64 >= 0 {
    xu = 0UL
  }
  let t = xb >> 63
  let ti = t.reinterpret_as_int64()
  let xui = xu.reinterpret_as_int64()
  (xui ^ (0L - ti)) + ti
}

///|
/// sqrt(x) for x >= 0 (bit-exact port of fpr_sqrt).
pub fn fp_sqrt(x : Double) -> Double {
  let xb = x.reinterpret_as_uint64()
  let mut xu = (xb & 0xFFFFFFFFFFFFFUL) | (1UL << 52)
  let ex = ((xb >> 52) & 0x7FFUL).reinterpret_as_int64().to_int()
  let mut e = ex - 1023
  if (e & 1) != 0 {
    xu = xu + xu
  }
  e = e >> 1
  xu = xu << 1
  let mut q = 0UL
  let mut s = 0UL
  let mut r = 1UL << 53
  for _i = 0; _i < 54; _i = _i + 1 {
    let t = s + r
    // b = ((xu - t) >> 63) - 1 : all-ones if xu >= t
    let b = if xu >= t { 0xFFFFFFFFFFFFFFFFUL } else { 0UL }
    s = s + ((r << 1) & b)
    xu = xu - (t & b)
    q = q + (r & b)
    xu = xu << 1
    r = r >> 1
  }
  q = q << 1
  if xu != 0UL {
    q = q | 1UL
  }
  e = e - 54
  if (ex.to_int64() + 0x7FFL) >> 11 != 0L {
    // keep q
    q = q
  } else {
    q = 0UL
  }
  fpr_pack(0, e, q)
}

///|
/// 2^63 * exp(-x) for 0 <= x < log(2) (raykzhao polynomial, C table).
pub fn fp_expm_p63(x : Double, ccs : Double) -> UInt64 {
  let z0f = fp_trunc(x * 9223372036854775808.0)
  let z = z0f.reinterpret_as_uint64() << 1
  let mut y = falcon_expm_c[0]
  for u = 1; u < 13; u = u + 1 {
    let c = mulhi64(z, y)
    y = falcon_expm_c[u] - c
  }
  let z1f = fp_trunc(ccs * 9223372036854775808.0)
  let z1 = z1f.reinterpret_as_uint64() << 1
  mulhi64(z1, y)
}

///|
/// High 64 bits of a 64x64 product (schoolbook on 32-bit halves).
fn mulhi64(xx : UInt64, yy : UInt64) -> UInt64 {
  let z0 = xx & 0xFFFFFFFFUL
  let z1 = xx >> 32
  let y0 = yy & 0xFFFFFFFFUL
  let y1 = yy >> 32
  let a = z0 * y1 + ((z0 * y0) >> 32)
  let b = z1 * y0
  let mut c = (a >> 32) + (b >> 32)
  c = c + (((a & 0xFFFFFFFFUL) + (b & 0xFFFFFFFFUL)) >> 32)
  c + z1 * y1
}

// ---------------------------------------------------------------------------
// Gaussian sampler (sign.c)
// ---------------------------------------------------------------------------

///|
/// gaussian0_sampler: half-normal draw over the dist table.
pub fn falcon_gaussian0_sampler(p : FalconPrng) -> Int {
  let lo = prng_get_u64(p)
  let hi = prng_get_u8(p)
  let v0 = u32bits(lo & 0xFFFFFFUL).to_int()
  let v1 = u32bits((lo >> 24) & 0xFFFFFFUL).to_int()
  let v2 = u32bits((lo >> 48) | (hi.to_uint64() << 16)).to_int()
  let mut z = 0
  for u = 0; u < 54; u = u + 3 {
    let w0 = falcon_g0_dist[u + 2]
    let w1 = falcon_g0_dist[u + 1]
    let w2 = falcon_g0_dist[u + 0]
    let mut cc = if v0 < w0 { 1 } else { 0 }
    cc = if v1 - w1 - cc < 0 { 1 } else { 0 }
    cc = if v2 - w2 - cc < 0 { 1 } else { 0 }
    z = z + cc
  }
  z
}

///|
/// BerExp: Bernoulli(exp(-x)) via the expm_p63 fixed-point stream.
fn falcon_ber_exp(p : FalconPrng, x : Double, ccs : Double) -> Int {
  let mut s = fp_trunc(x * fp_inv_log2_val()).to_int()
  let r = x - s.to_double() * fp_log2_val()
  let mut sw = s
  if 63 - sw < 0 {
    sw = 63
  }
  s = sw
  let ez = ((fp_expm_p63(r, ccs) << 1) - 1UL) >> s
  let mut i = 64
  let mut w = 0
  let mut done = false
  while done == false {
    i = i - 8
    w = prng_get_u8(p) - ((ez >> i) & 0xFFUL).reinterpret_as_int64().to_int()
    if w != 0 || i <= 0 {
      done = true
    }
  }
  if w < 0 {
    1
  } else {
    0
  }
}

///|
/// sampler_context equivalent: prng + sigma_min.
pub struct FalconSamplerCtx {
  p : FalconPrng
  sigma_min : Double
}

///|
/// Discrete Gaussian sampler with mean mu, inverse sigma isigma.
pub fn falcon_sampler(
  ctx : FalconSamplerCtx,
  mu : Double,
  isigma : Double,
) -> Int {
  let s = fp_floor(mu).to_int()
  let r = mu - s.to_double()
  let dss = fp_half(isigma * isigma)
  let ccs = isigma * ctx.sigma_min
  let mut out = 0
  let mut done = false
  while done == false {
    let z0 = falcon_gaussian0_sampler(ctx.p)
    let b = prng_get_u8(ctx.p) & 1
    let z = b + ((b << 1) - 1) * z0
    let dz = z.to_double() - r
    let mut xv = dz * dz * dss
    let z0d = (z0 * z0).to_double()
    xv = xv - z0d * fp_inv_2sqrsigma0_val()
    if falcon_ber_exp(ctx.p, xv, ccs) != 0 {
      out = s + z
      done = true
    }
  }
  out
}

///|
/// f64 constant accessors (bit patterns from the CONSTS dump).
fn fp_log2_val() -> Double {
  4604418534313441775UL.reinterpret_as_double()
}

///|
fn fp_inv_log2_val() -> Double {
  4609176140021203710UL.reinterpret_as_double()
}

///|
fn fp_inv_2sqrsigma0_val() -> Double {
  4594603506513722306UL.reinterpret_as_double()
}

///|
/// Low-32-bit pattern of a UInt64 as a non-negative Int64.
fn u32bits(x : UInt64) -> Int64 {
  (x & 0xFFFFFFFFUL).reinterpret_as_int64() & 0xFFFFFFFFL
}

///|
/// Build a sampler context (prng + sigma_min for the target logn).
pub fn falcon_sampler_ctx_make(
  p : FalconPrng,
  sigma_min : Double,
) -> FalconSamplerCtx {
  { p, sigma_min, }
}
