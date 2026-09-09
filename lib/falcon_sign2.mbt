// Falcon M5b: the signing path — complete_private (G from f,g,F),
// ffSampling_fft_dyntree, do_sign_dyn, and the falcon512_sign API.
// Faithful port of PQClean sign.c / vrfy.c / pqclean.c. The C pointer
// aliasing between b00..b11/t0/t1/g00/g01/g11 regions is reproduced
// with explicit arrays; regions whose mutations are never read again
// by the parent are safely localized (verified against the C flow).

///|
/// G = g*F/f mod q, normalized to ±q/2, must fit ±127. Returns false
/// if f is not invertible or G is out of range.
fn falcon_complete_private(
  big_g : Array[Int],
  f : Array[Int],
  g : Array[Int],
  big_f : Array[Int],
  logn : Int,
) -> Bool {
  let n = 1 << logn
  let t1 = Array::make(n, 0)
  let t2 = Array::make(n, 0)
  for u = 0; u < n; u = u + 1 {
    t1[u] = mq_conv_small(g[u])
    t2[u] = mq_conv_small(big_f[u])
  }
  falcon_mq_ntt(t1, logn)
  falcon_mq_ntt(t2, logn)
  // t1 <- monty form then pointwise t1*t2
  for u = 0; u < n; u = u + 1 {
    t1[u] = mq_montymul(t1[u], falcon_r2)
  }
  for u = 0; u < n; u = u + 1 {
    t1[u] = mq_montymul(t1[u], t2[u])
  }
  for u = 0; u < n; u = u + 1 {
    t2[u] = mq_conv_small(f[u])
  }
  falcon_mq_ntt(t2, logn)
  for u = 0; u < n; u = u + 1 {
    if t2[u] == 0 {
      return false
    }
    t1[u] = falcon_mq_div(t1[u], t2[u])
  }
  falcon_mq_intt(t1, logn)
  for u = 0; u < n; u = u + 1 {
    let mut w = t1[u]
    if w >= falcon_q >> 1 {
      w = w - falcon_q
    }
    if w < -127 || w > 127 {
      return false
    }
    big_g[u] = w
  }
  true
}

///|
pub let fp_invsqrt2 : Double = 4604544271217802189UL.reinterpret_as_double()

///|
pub let fp_invsqrt8 : Double = 4600040671590431693UL.reinterpret_as_double()

///|
fn fpr_inv_sigma_at(logn : Int) -> Double {
  falcon_sigma_inv_bits[logn].reinterpret_as_double()
}

///|
/// ffSampling_fft_dyntree: recursive Gaussian sampling with on-the-fly
/// LDL tree. Arrays are level-sized (n = 1<<logn); halves are passed as
/// fresh copies at recursion (parent never re-reads mutated regions).
fn ff_sampling_dyntree(
  ctx : FalconSamplerCtx,
  t0 : Array[Double],
  t1 : Array[Double],
  g00 : Array[Double],
  g01 : Array[Double],
  g11 : Array[Double],
  orig_logn : Int,
  logn : Int,
) -> Unit {
  if logn == 0 {
    let leaf = fp_sqrt(g00[0]) * fpr_inv_sigma_at(orig_logn)
    t0[0] = falcon_sampler(ctx, t0[0], leaf).to_double()
    t1[0] = falcon_sampler(ctx, t1[0], leaf).to_double()
    return
  }
  let n = 1 << logn
  let hn = n >> 1
  // in-place LDL: g01 <- conj(mu), g11 <- d11 (g00 read-only)
  falcon_poly_LDL_fft(g00, g01, g11, logn)
  // split g00 and g11
  let g00a = Array::make(hn, 0.0)
  let g00b = Array::make(hn, 0.0)
  falcon_poly_split_fft(g00a, g00b, g00, logn)
  let g11a = Array::make(hn, 0.0)
  let g11b = Array::make(hn, 0.0)
  falcon_poly_split_fft(g11a, g11b, g11, logn)
  // packed g01 = [g00a | g11a]
  let pg01 = Array::make(n, 0.0)
  for i = 0; i < hn; i = i + 1 {
    pg01[i] = g00a[i]
    pg01[i + hn] = g11a[i]
  }
  // z1 = split(t1)
  let z1a = Array::make(hn, 0.0)
  let z1b = Array::make(hn, 0.0)
  falcon_poly_split_fft(z1a, z1b, t1, logn)
  // child 1: (g11a, g11b, packed-hi = g11a-copy)
  let g11a_hi = Array::make(hn, 0.0)
  for i = 0; i < hn; i = i + 1 {
    g11a_hi[i] = pg01[i + hn]
  }
  ff_sampling_dyntree(ctx, z1a, z1b, g11a, g11b, g11a_hi, orig_logn, logn - 1)
  // merge z1
  let mz1 = Array::make(n, 0.0)
  falcon_poly_merge_fft(mz1, z1a, z1b, logn)
  // z1diff = t1 - mz1 ; t1 = mz1
  let z1d = Array::make(n, 0.0)
  for i = 0; i < n; i = i + 1 {
    z1d[i] = t1[i]
  }
  falcon_poly_sub(z1d, mz1, logn)
  for i = 0; i < n; i = i + 1 {
    t1[i] = mz1[i]
  }
  // tmp = g01copy * z1d  (g01copy = pre-LDL g01 — C copies it before
  // the recursion; our g01 array still holds the ORIGINAL values? No:
  // poly_LDL_fft mutated g01 in place. C: memcpy(tmp, g01, n) happens
  // AFTER the LDL+packing? — C order: LDL; split g00; split g11;
  // memcpy(tmp, g01); pack g01. So tmp = g01 AFTER LDL (= conj(mu)).
  let tmpm = Array::make(n, 0.0)
  for i = 0; i < n; i = i + 1 {
    tmpm[i] = g01[i]
  }
  falcon_poly_mul_fft(tmpm, z1d, logn)
  falcon_poly_add(t0, tmpm, logn)
  // z0 = split(t0)
  let z0a = Array::make(hn, 0.0)
  let z0b = Array::make(hn, 0.0)
  falcon_poly_split_fft(z0a, z0b, t0, logn)
  // child 2: (g00a, g00b, packed-lo = g00a copy)
  let pg_lo = Array::make(hn, 0.0)
  for i = 0; i < hn; i = i + 1 {
    pg_lo[i] = pg01[i]
  }
  ff_sampling_dyntree(ctx, z0a, z0b, g00a, g00b, pg_lo, orig_logn, logn - 1)
  falcon_poly_merge_fft(t0, z0a, z0b, logn)
}

///|
/// do_sign_dyn: one signing attempt. Returns -1 on rejection, else the
/// squared norm seed... C returns 0/−1 with s2 output; we return true
/// and fill s2.
fn falcon_do_sign_dyn(
  ctx : FalconSamplerCtx,
  s2 : Array[Int],
  f : Array[Int],
  g : Array[Int],
  big_f : Array[Int],
  big_g : Array[Int],
  hm : Array[Int],
  logn : Int,
) -> Bool {
  let n = 1 << logn
  let b00 = Array::make(n, 0.0)
  let b01 = Array::make(n, 0.0)
  let b10 = Array::make(n, 0.0)
  let b11 = Array::make(n, 0.0)
  smallints_to_fpr(b01, f, logn)
  smallints_to_fpr(b00, g, logn)
  smallints_to_fpr(b11, big_f, logn)
  smallints_to_fpr(b10, big_g, logn)
  falcon_fft(b01, logn)
  falcon_fft(b00, logn)
  falcon_fft(b11, logn)
  falcon_fft(b10, logn)
  falcon_poly_neg(b01, logn)
  falcon_poly_neg(b11, logn)
  // Gram matrix
  let t0 = Array::make(n, 0.0)
  let t1 = Array::make(n, 0.0)
  for i = 0; i < n; i = i + 1 {
    t0[i] = b01[i]
  }
  falcon_poly_mulselfadj_fft(t0, logn)
  for i = 0; i < n; i = i + 1 {
    t1[i] = b00[i]
  }
  falcon_poly_muladj_fft(t1, b10, logn)
  falcon_poly_mulselfadj_fft(b00, logn)
  falcon_poly_add(b00, t0, logn) // g00
  for i = 0; i < n; i = i + 1 {
    t0[i] = b01[i]
  }
  falcon_poly_muladj_fft(b01, b11, logn)
  falcon_poly_add(b01, t1, logn) // g01
  falcon_poly_mulselfadj_fft(b10, logn)
  for i = 0; i < n; i = i + 1 {
    t1[i] = b11[i]
  }
  falcon_poly_mulselfadj_fft(t1, logn)
  falcon_poly_add(b10, t1, logn) // g11
  let g00 = b00
  let g01 = b01
  let g11 = b10
  // C's t0 region ends the Gram phase holding a SECOND raw copy of
  // -FFT(f) (the mulselfadj result was consumed by g00 and then
  // overwritten); b01 is reassigned to that raw copy for the hm
  // transform phase.
  let b01r = Array::make(n, 0.0)
  smallints_to_fpr(b01r, f, logn)
  falcon_fft(b01r, logn)
  falcon_poly_neg(b01r, logn)
  // t0/t1 = FFT(hm) based targets
  let c0 = Array::make(n, 0.0)
  let c1 = Array::make(n, 0.0)
  for u = 0; u < n; u = u + 1 {
    c0[u] = hm[u].to_double()
    c1[u] = 0.0
  }
  falcon_fft(c0, logn)
  let ni = falcon_inv_q_val()
  for i = 0; i < n; i = i + 1 {
    c1[i] = c0[i]
  }
  // C: b01 is REASSIGNED to the mulselfadj(original b01) region here:
  // the hm transform multiplies by f*adj(f), NOT by the Gram g01.
  falcon_poly_mul_fft(c1, b01r, logn)
  falcon_poly_mulconst(c1, 0.0 - ni, logn)
  falcon_poly_mul_fft(c0, b11, logn)
  falcon_poly_mulconst(c0, ni, logn)
  // dyntree sampling: t0 arg = c0 (ni*hm*b11), t1 arg = c1
  let z0 = Array::make(n, 0.0)
  let z1 = Array::make(n, 0.0)
  ff_sampling_dyntree(ctx, c0, c1, g00, g01, g11, logn, logn)
  for i = 0; i < n; i = i + 1 {
    z0[i] = c0[i]
    z1[i] = c1[i]
  }
  // phase 2: rebuild B from f,g,F,G (fresh)
  let p2b00 = Array::make(n, 0.0)
  let p2b01 = Array::make(n, 0.0)
  let p2b10 = Array::make(n, 0.0)
  let p2b11 = Array::make(n, 0.0)
  smallints_to_fpr(p2b01, f, logn)
  smallints_to_fpr(p2b00, g, logn)
  smallints_to_fpr(p2b11, big_f, logn)
  smallints_to_fpr(p2b10, big_g, logn)
  falcon_fft(p2b01, logn)
  falcon_fft(p2b00, logn)
  falcon_fft(p2b11, logn)
  falcon_fft(p2b10, logn)
  falcon_poly_neg(p2b01, logn)
  falcon_poly_neg(p2b11, logn)
  let tx = Array::make(n, 0.0)
  let ty = Array::make(n, 0.0)
  for i = 0; i < n; i = i + 1 {
    tx[i] = z0[i]
    ty[i] = z1[i]
  }
  falcon_poly_mul_fft(tx, p2b00, logn)
  falcon_poly_mul_fft(ty, p2b10, logn)
  falcon_poly_add(tx, ty, logn)
  for i = 0; i < n; i = i + 1 {
    ty[i] = z0[i]
  }
  falcon_poly_mul_fft(ty, p2b01, logn)
  let u0 = tx
  falcon_poly_mul_fft(z1, p2b11, logn)
  falcon_poly_add(z1, ty, logn)
  falcon_ifft(u0, logn)
  falcon_ifft(z1, logn)
  // s1 = hm - rint(u0); sqn accumulation
  let mut sqn = 0L
  let s1tmp = Array::make(n, 0)
  for u = 0; u < n; u = u + 1 {
    let z = hm[u] - fp_rint(u0[u]).to_int()
    let zi = z.to_int64()
    sqn = sqn + zi * zi
    s1tmp[u] = z
  }
  let s2tmp = Array::make(n, 0)
  for u = 0; u < n; u = u + 1 {
    s2tmp[u] = 0 - fp_rint(z1[u]).to_int()
  }
  if falcon_is_short_half(sqn, s2tmp, logn) {
    for u = 0; u < n; u = u + 1 {
      s2[u] = s2tmp[u]
    }
    ignore(s1tmp)
    true
  } else {
    false
  }
}

///|
fn falcon_inv_q_val() -> Double {
  4545632735260551042UL.reinterpret_as_double()
}

///|
/// is_short_half: sqn (from s1) + sum(s2^2) <= l2bound (exact Int64).
fn falcon_is_short_half(sqn0 : Int64, s2 : Array[Int], logn : Int) -> Bool {
  let n = 1 << logn
  let mut sqn = sqn0
  for u = 0; u < n; u = u + 1 {
    let z = s2[u].to_int64()
    sqn = sqn + z * z
  }
  sqn <= falcon_l2bound[logn].to_int64()
}

///|
fn smallints_to_fpr(r : Array[Double], t : Array[Int], logn : Int) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    r[u] = t[u].to_double()
  }
}
