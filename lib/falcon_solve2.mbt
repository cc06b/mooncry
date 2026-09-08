// Falcon M4c (part 2): binary depth0 level, the solve_NTRU orchestrator,
// and the keygen rejection loop. Port of PQClean keygen.c.

///|
pub fn solve_ntru_depth0(
  logn : Int,
  f : Array[Int],
  g : Array[Int],
  tmp : Array[Int],
) -> Bool {
  let n = 1 << logn
  let hn = n >> 1
  let p = falcon_primes_p[0]
  let p0i = modp_ninv31(p)
  let r2 = modp_r2(p, p0i)
  let fp = 0
  let gp = hn
  let ft = 2 * hn
  let gt = ft + n
  let gm = gt + n
  let igm = gm + n
  modp_mkgm2_slice(tmp, gm, tmp, igm, logn, falcon_primes_g[0], p, p0i)
  for u = 0; u < hn; u = u + 1 {
    let one_f : Array[Int] = [tmp[fp + u]]
    let one_g : Array[Int] = [tmp[gp + u]]
    tmp[fp + u] = modp_set(zint_one_to_plain(one_f), p)
    tmp[gp + u] = modp_set(zint_one_to_plain(one_g), p)
  }
  modp_ntt2_ext(tmp, fp, 1, tmp, gm, logn - 1, p, p0i)
  modp_ntt2_ext(tmp, gp, 1, tmp, gm, logn - 1, p, p0i)
  for u = 0; u < n; u = u + 1 {
    tmp[ft + u] = modp_set(f[u], p)
    tmp[gt + u] = modp_set(g[u], p)
  }
  modp_ntt2_ext(tmp, ft, 1, tmp, gm, logn, p, p0i)
  modp_ntt2_ext(tmp, gt, 1, tmp, gm, logn, p, p0i)
  for u = 0; u < n; u = u + 2 {
    let ft_a = tmp[ft + u]
    let ft_b = tmp[ft + u + 1]
    let gt_a = tmp[gt + u]
    let gt_b = tmp[gt + u + 1]
    let mfp = modp_montymul(tmp[fp + (u >> 1)], r2, p, p0i)
    let mgp = modp_montymul(tmp[gp + (u >> 1)], r2, p, p0i)
    tmp[ft + u] = modp_montymul(gt_b, mfp, p, p0i)
    tmp[ft + u + 1] = modp_montymul(gt_a, mfp, p, p0i)
    tmp[gt + u] = modp_montymul(ft_b, mgp, p, p0i)
    tmp[gt + u + 1] = modp_montymul(ft_a, mgp, p, p0i)
  }
  modp_intt2_ext(tmp, ft, 1, tmp, igm, logn, p, p0i)
  modp_intt2_ext(tmp, gt, 1, tmp, igm, logn, p, p0i)
  copy_words(tmp, ft, 0, 2 * n)
  let t1 = 2 * n
  let t2 = 3 * n
  let t3 = 4 * n
  let t4 = 5 * n
  let t5 = 6 * n
  modp_mkgm2_slice(tmp, t1, tmp, t2, logn, falcon_primes_g[0], p, p0i)
  modp_ntt2_ext(tmp, 0, 1, tmp, t1, logn, p, p0i)
  modp_ntt2_ext(tmp, n, 1, tmp, t1, logn, p, p0i)
  tmp[t4] = modp_set(f[0], p)
  tmp[t5] = tmp[t4]
  for u = 1; u < n; u = u + 1 {
    tmp[t4 + u] = modp_set(f[u], p)
    tmp[t5 + n - u] = modp_set(0 - f[u], p)
  }
  modp_ntt2_ext(tmp, t4, 1, tmp, t1, logn, p, p0i)
  modp_ntt2_ext(tmp, t5, 1, tmp, t1, logn, p, p0i)
  for u = 0; u < n; u = u + 1 {
    let w = modp_montymul(tmp[t5 + u], r2, p, p0i)
    tmp[t2 + u] = modp_montymul(w, tmp[u], p, p0i)
    tmp[t3 + u] = modp_montymul(w, tmp[t4 + u], p, p0i)
  }
  tmp[t4] = modp_set(g[0], p)
  tmp[t5] = tmp[t4]
  for u = 1; u < n; u = u + 1 {
    tmp[t4 + u] = modp_set(g[u], p)
    tmp[t5 + n - u] = modp_set(0 - g[u], p)
  }
  modp_ntt2_ext(tmp, t4, 1, tmp, t1, logn, p, p0i)
  modp_ntt2_ext(tmp, t5, 1, tmp, t1, logn, p, p0i)
  for u = 0; u < n; u = u + 1 {
    let w = modp_montymul(tmp[t5 + u], r2, p, p0i)
    tmp[t2 + u] = modp_add(tmp[t2 + u], modp_montymul(w, tmp[n + u], p, p0i), p)
    tmp[t3 + u] = modp_add(
      tmp[t3 + u],
      modp_montymul(w, tmp[t4 + u], p, p0i),
      p,
    )
  }
  modp_mkgm2_slice(tmp, t1, tmp, t4, logn, falcon_primes_g[0], p, p0i)
  modp_intt2_ext(tmp, t2, 1, tmp, t4, logn, p, p0i)
  modp_intt2_ext(tmp, t3, 1, tmp, t4, logn, p, p0i)
  for u = 0; u < n; u = u + 1 {
    tmp[t1 + u] = modp_norm(tmp[t2 + u], p)
    tmp[t2 + u] = modp_norm(tmp[t3 + u], p)
  }
  let rt3 = Array::make(n, 0.0)
  for u = 0; u < n; u = u + 1 {
    rt3[u] = tmp[t2 + u].to_double()
  }
  falcon_fft(rt3, logn)
  let rt2 = Array::make(hn, 0.0)
  for u = 0; u < hn; u = u + 1 {
    rt2[u] = rt3[u]
  }
  let rt3b = Array::make(n, 0.0)
  for u = 0; u < n; u = u + 1 {
    rt3b[u] = tmp[t1 + u].to_double()
  }
  falcon_fft(rt3b, logn)
  falcon_poly_div_autoadj_fft(rt3b, rt2, logn)
  falcon_ifft(rt3b, logn)
  for u = 0; u < n; u = u + 1 {
    tmp[t1 + u] = modp_set(fp_rint(rt3b[u]).to_int(), p)
  }
  modp_mkgm2_slice(tmp, t2, tmp, t3, logn, falcon_primes_g[0], p, p0i)
  for u = 0; u < n; u = u + 1 {
    tmp[t4 + u] = modp_set(f[u], p)
    tmp[t5 + u] = modp_set(g[u], p)
  }
  modp_ntt2_ext(tmp, t1, 1, tmp, t2, logn, p, p0i)
  modp_ntt2_ext(tmp, t4, 1, tmp, t2, logn, p, p0i)
  modp_ntt2_ext(tmp, t5, 1, tmp, t2, logn, p, p0i)
  for u = 0; u < n; u = u + 1 {
    let kw = modp_montymul(tmp[t1 + u], r2, p, p0i)
    tmp[u] = modp_sub(tmp[u], modp_montymul(kw, tmp[t4 + u], p, p0i), p)
    tmp[n + u] = modp_sub(tmp[n + u], modp_montymul(kw, tmp[t5 + u], p, p0i), p)
  }
  modp_intt2_ext(tmp, 0, 1, tmp, t3, logn, p, p0i)
  modp_intt2_ext(tmp, n, 1, tmp, t3, logn, p, p0i)
  for u = 0; u < n; u = u + 1 {
    tmp[u] = modp_norm(tmp[u], p)
    tmp[n + u] = modp_norm(tmp[n + u], p)
  }
  true
}

///|
/// Full solve_NTRU: F,G (one signed limb per coefficient) land in
/// tmp[0..n) and tmp[n..2n); the big-int outputs go to big_f/big_g.
pub fn solve_ntru(
  logn : Int,
  big_f : Array[Int],
  big_g : Array[Int],
  f : Array[Int],
  g : Array[Int],
  lim : Int,
  tmp : Array[Int],
) -> Bool {
  let n = 1 << logn
  if solve_ntru_deepest_at(logn, f, g, tmp) == false {
    return false
  }
  if logn <= 2 {
    let mut depth = logn
    while depth > 0 {
      depth = depth - 1
      if solve_ntru_intermediate(logn, f, g, depth, tmp) == false {
        return false
      }
    }
  } else {
    let mut depth = logn
    while depth > 2 {
      depth = depth - 1
      if solve_ntru_intermediate(logn, f, g, depth, tmp) == false {
        return false
      }
    }
    if solve_ntru_depth1(logn, f, g, tmp) == false {
      return false
    }
    if solve_ntru_depth0(logn, f, g, tmp) == false {
      return false
    }
  }
  if poly_big_to_small(big_f, tmp, 0, lim, logn) == false {
    return false
  }
  if poly_big_to_small(big_g, tmp, n, lim, logn) == false {
    return false
  }
  // final check: f*G - g*F == q mod phi mod PRIMES[0]
  let gt = 0
  let ft = n
  let g2 = 2 * n
  let ft2 = 3 * n
  let gm = 4 * n
  let p = falcon_primes_p[0]
  let p0i = modp_ninv31(p)
  modp_mkgm2_slice(tmp, gm, tmp, gt, logn, falcon_primes_g[0], p, p0i)
  for u = 0; u < n; u = u + 1 {
    tmp[gt + u] = modp_set(big_g[u], p)
    tmp[ft + u] = modp_set(f[u], p)
    tmp[g2 + u] = modp_set(g[u], p)
    tmp[ft2 + u] = modp_set(big_f[u], p)
  }
  modp_ntt2_ext(tmp, ft, 1, tmp, gm, logn, p, p0i)
  modp_ntt2_ext(tmp, g2, 1, tmp, gm, logn, p, p0i)
  modp_ntt2_ext(tmp, ft2, 1, tmp, gm, logn, p, p0i)
  modp_ntt2_ext(tmp, gt, 1, tmp, gm, logn, p, p0i)
  let r = modp_montymul(12289, 1, p, p0i)
  for u = 0; u < n; u = u + 1 {
    let z = modp_sub(
      modp_montymul(tmp[ft + u], tmp[gt + u], p, p0i),
      modp_montymul(tmp[g2 + u], tmp[ft2 + u], p, p0i),
      p,
    )
    if z != r {
      return false
    }
  }
  true
}

///|
/// keygen: rejection loop producing f, g (small), F (large) and h.
/// rng must be flipped and ready for extraction (matches the C flow:
/// SHAKE256 seeded with the 48-byte seed).
pub fn falcon_keygen(
  rng : FalconXof,
  logn : Int,
) -> (Array[Int], Array[Int], Array[Int], Array[Int]) {
  let n = 1 << logn
  let q_f = 12289.0
  let bnorm_max = fp_bnorm_max_bits.reinterpret_as_double()
  let tmp = Array::make(40 * n + 4096, 0)
  let f = Array::make(n, 0)
  let g = Array::make(n, 0)
  let big_f = Array::make(n, 0)
  let big_g = Array::make(n, 0)
  let h = Array::make(n, 0)
  while true {
    falcon_poly_small_mkgauss(rng, f, logn)
    falcon_poly_small_mkgauss(rng, g, logn)
    let lim = 1 << (falcon_max_fg_bits[logn] - 1)
    let mut ok = true
    for u = 0; u < n; u = u + 1 {
      if f[u] >= lim || f[u] <= 0 - lim || g[u] >= lim || g[u] <= 0 - lim {
        ok = false
        break
      }
    }
    if ok == false {
      continue
    }
    let normf = falcon_poly_small_sqnorm(f, logn)
    let normg = falcon_poly_small_sqnorm(g, logn)
    if normf.to_int64() + normg.to_int64() >= 16823L {
      continue
    }
    let rt1 = Array::make(n, 0.0)
    let rt2 = Array::make(n, 0.0)
    let rt3 = Array::make(n >> 1, 0.0)
    falcon_poly_small_to_fp(rt1, f, logn)
    falcon_poly_small_to_fp(rt2, g, logn)
    falcon_fft(rt1, logn)
    falcon_fft(rt2, logn)
    falcon_poly_invnorm2_fft(rt3, rt1, rt2, logn)
    falcon_poly_adj_fft(rt1, logn)
    falcon_poly_adj_fft(rt2, logn)
    falcon_poly_mulconst(rt1, q_f, logn)
    falcon_poly_mulconst(rt2, q_f, logn)
    falcon_poly_mul_autoadj_fft(rt1, rt3, logn)
    falcon_poly_mul_autoadj_fft(rt2, rt3, logn)
    falcon_ifft(rt1, logn)
    falcon_ifft(rt2, logn)
    let mut bnorm = 0.0
    for u = 0; u < n; u = u + 1 {
      bnorm = bnorm + rt1[u] * rt1[u]
      bnorm = bnorm + rt2[u] * rt2[u]
    }
    if bnorm >= bnorm_max {
      continue
    }
    if falcon_compute_public(h, f, g, logn) == false {
      continue
    }
    let lim2 = (1 << (falcon_max_FG_bits[logn] - 1)) - 1
    if solve_ntru(logn, big_f, big_g, f, g, lim2, tmp) == false {
      continue
    }
    break
  }
  (f, g, big_f, h)
}
