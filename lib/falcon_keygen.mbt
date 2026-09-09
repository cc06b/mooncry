// Falcon M4a: keygen randomness layer — RNG u64 extraction, the
// discrete Gaussian sampler (mkgauss), and small-polynomial helpers.
// Faithful port of PQClean keygen.c (get_rng_u64, mkgauss,
// poly_small_mkgauss/sqnorm/to_fp). Byte-exact vs C dumps.

///|
/// Extract a little-endian u64 from the (already flipped) XOF.
fn falcon_get_rng_u64(x : FalconXof) -> UInt64 {
  let b = falcon_xof_extract(x, 8)
  let mut r = 0UL
  for i = 7; i >= 0; i = i - 1 {
    r = (r << 8) | b[i].to_uint64()
  }
  r
}

///|
/// One discrete Gaussian sample (sigma = 1.17*sqrt(q/(2N)), N=1024;
/// for logn < 10 it sums 2^(10-logn) independent draws).
pub fn falcon_mkgauss(rng : FalconXof, logn : Int) -> Int {
  let g = 1 << (10 - logn)
  let mut val = 0
  for _u = 0; _u < g; _u = _u + 1 {
    let mut r = falcon_get_rng_u64(rng)
    let neg = r >> 63
    r = r & 0x7FFFFFFFFFFFFFFFUL
    // (r - t) >> 63 on unsigned == borrow flag == (r < t)
    let mut f = if r < falcon_gauss_tab[0] { 1 } else { 0 }
    let mut v = 0
    let mut r2 = falcon_get_rng_u64(rng)
    r2 = r2 & 0x7FFFFFFFFFFFFFFFUL
    for k = 1; k < 27; k = k + 1 {
      let t = if r2 >= falcon_gauss_tab[k] { 1 } else { 0 }
      v = v | (k & (0 - (t & (f ^ 1))))
      f = f | t
    }
    let negi = neg.to_int()
    let vv = (v ^ (0 - negi)) + negi
    val = val + vv
  }
  val
}

///|
/// Sample a small polynomial: n Gaussian coefficients in [-127,127]
/// with coefficient-sum parity forced odd (last coefficient resampled
/// until (mod2 ^ s&1) == 1).
fn falcon_poly_small_mkgauss(
  rng : FalconXof,
  f : Array[Int],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let mut mod2 = 0
  for u = 0; u < n; u = u + 1 {
    let mut s = falcon_mkgauss(rng, logn)
    while s < -127 || s > 127 {
      s = falcon_mkgauss(rng, logn)
    }
    if u == n - 1 {
      while (mod2 ^ (s & 1)) == 0 {
        s = falcon_mkgauss(rng, logn)
        while s < -127 || s > 127 {
          s = falcon_mkgauss(rng, logn)
        }
      }
    } else {
      mod2 = mod2 ^ (s & 1)
    }
    f[u] = s
  }
}

///|
/// Squared norm of a small polynomial, with the C u32 saturation
/// semantics expressed exactly via Int64.
fn falcon_poly_small_sqnorm(f : Array[Int], logn : Int) -> Int {
  let n = 1 << logn
  let mut s = 0L
  for u = 0; u < n; u = u + 1 {
    let z = f[u].to_int64()
    s = s + z * z
  }
  if s >= 2147483648L {
    0x7FFFFFFF
  } else {
    s.to_int()
  }
}

///|
/// Small ints -> f64 array.
fn falcon_poly_small_to_fp(
  x : Array[Double],
  f : Array[Int],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    x[u] = fp_of(f[u])
  }
}
