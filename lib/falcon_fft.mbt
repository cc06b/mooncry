// Falcon M2: f64 FFT over X^N+1 and the polynomial operations built on
// it. Faithful port of PQClean falcon clean fft.c. `fpr` is Double here;
// the C reference stores f64 bit patterns in uint64 and does the same
// IEEE ops. Verified bit-exact against dumps from the official C code.

///|
/// gm table entry as Double (bit pattern -> f64).
fn fgm(k : Int) -> Double {
  falcon_gm_tab[k].reinterpret_as_double()
}

///|
/// fpr_half: divide by 2 via exponent decrement, with the C zero
/// special case (bit trick, not x*0.5 — keeps subnormal behaviour).
fn fp_half(x : Double) -> Double {
  let b = x.reinterpret_as_uint64() - (1UL << 52)
  let t = (((b >> 52) & 0x7FFUL) + 1UL) >> 11
  (b & (t - 1UL)).reinterpret_as_double()
}

///|
/// FFT: n reals (coefficients mod X^n+1) -> half-complex bit-reversed
/// representation (Re in slots 0..hn-1, Im in slots hn..n-1). In place.
pub fn falcon_fft(f : Array[Double], logn : Int) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  let mut t = hn
  let mut m = 2
  for _u = 1; _u < logn; _u = _u + 1 {
    let ht = t >> 1
    let hm = m >> 1
    let mut j1 = 0
    for i1 = 0; i1 < hm; i1 = i1 + 1 {
      let j2 = j1 + ht
      let s_re = fgm((m + i1) << 1)
      let s_im = fgm(((m + i1) << 1) + 1)
      for j = j1; j < j2; j = j + 1 {
        let x_re = f[j]
        let x_im = f[j + hn]
        let y_re = f[j + ht]
        let y_im = f[j + ht + hn]
        // y *= s
        let yr = y_re * s_re - y_im * s_im
        let yi = y_re * s_im + y_im * s_re
        f[j] = x_re + yr
        f[j + hn] = x_im + yi
        f[j + ht] = x_re - yr
        f[j + ht + hn] = x_im - yi
      }
      j1 = j1 + t
    }
    t = ht
    m = m << 1
  }
}

///|
/// iFFT: inverse of falcon_fft, scaled by 1/n. In place.
pub fn falcon_ifft(f : Array[Double], logn : Int) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  let mut t = 1
  let mut m = n
  for u = logn; u > 1; u = u - 1 {
    let hm = m >> 1
    let dt = t << 1
    let mut i1 = 0
    let mut j1 = 0
    while j1 < hn {
      let j2 = j1 + t
      let s_re = fgm((hm + i1) << 1)
      let s_im = 0.0 - fgm(((hm + i1) << 1) + 1)
      for j = j1; j < j2; j = j + 1 {
        let x_re = f[j]
        let x_im = f[j + hn]
        let y_re = f[j + t]
        let y_im = f[j + t + hn]
        f[j] = x_re + y_re
        f[j + hn] = x_im + y_im
        let dr = x_re - y_re
        let di = x_im - y_im
        f[j + t] = dr * s_re - di * s_im
        f[j + t + hn] = dr * s_im + di * s_re
      }
      i1 = i1 + 1
      j1 = j1 + dt
    }
    t = dt
    m = hm
  }
  if logn > 0 {
    let ni = falcon_p2_tab[logn].reinterpret_as_double()
    for u = 0; u < n; u = u + 1 {
      f[u] = f[u] * ni
    }
  }
}

///|
/// a += b (coefficient or FFT domain).
pub fn falcon_poly_add(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    a[u] = a[u] + b[u]
  }
}

///|
/// a -= b.
pub fn falcon_poly_sub(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    a[u] = a[u] - b[u]
  }
}

///|
/// a = -a.
pub fn falcon_poly_neg(a : Array[Double], logn : Int) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    a[u] = 0.0 - a[u]
  }
}

///|
/// Conjugate in FFT domain (negate imaginary halves).
pub fn falcon_poly_adj_fft(a : Array[Double], logn : Int) -> Unit {
  let n = 1 << logn
  for u = n >> 1; u < n; u = u + 1 {
    a[u] = 0.0 - a[u]
  }
}

///|
/// Complex pointwise multiply in FFT domain: a *= b.
pub fn falcon_poly_mul_fft(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ar = a[u]
    let ai = a[u + hn]
    let br = b[u]
    let bi = b[u + hn]
    a[u] = ar * br - ai * bi
    a[u + hn] = ar * bi + ai * br
  }
}

///|
/// a *= conj(b) in FFT domain.
pub fn falcon_poly_muladj_fft(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ar = a[u]
    let ai = a[u + hn]
    let br = b[u]
    let bi = 0.0 - b[u + hn]
    a[u] = ar * br - ai * bi
    a[u + hn] = ar * bi + ai * br
  }
}

///|
/// a *= conj(a): real slots get |a|^2, imaginary slots zeroed.
pub fn falcon_poly_mulselfadj_fft(a : Array[Double], logn : Int) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ar = a[u]
    let ai = a[u + hn]
    a[u] = ar * ar + ai * ai
    a[u + hn] = 0.0
  }
}

///|
/// a *= x (all slots).
pub fn falcon_poly_mulconst(a : Array[Double], x : Double, logn : Int) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    a[u] = a[u] * x
  }
}

///|
/// Complex pointwise divide in FFT domain: a /= b.
pub fn falcon_poly_div_fft(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ar = a[u]
    let ai = a[u + hn]
    let br = b[u]
    let bi = b[u + hn]
    let m = 1.0 / (br * br + bi * bi)
    let br2 = br * m
    let bi2 = (0.0 - bi) * m
    a[u] = ar * br2 - ai * bi2
    a[u + hn] = ar * bi2 + ai * br2
  }
}

///|
/// d[u] = 1 / (|a|^2 + |b|^2) per complex slot (real output in low half).
pub fn falcon_poly_invnorm2_fft(
  d : Array[Double],
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ar = a[u]
    let ai = a[u + hn]
    let br = b[u]
    let bi = b[u + hn]
    d[u] = 1.0 / (ar * ar + ai * ai + (br * br + bi * bi))
  }
}

///|
/// d = F*conj(f) + G*conj(g) in FFT domain.
pub fn falcon_poly_add_muladj_fft(
  d : Array[Double],
  big_f : Array[Double],
  big_g : Array[Double],
  f : Array[Double],
  g : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let fr = big_f[u]
    let fi = big_f[u + hn]
    let gr = big_g[u]
    let gi = big_g[u + hn]
    let f_r = f[u]
    let f_i = 0.0 - f[u + hn]
    let g_r = g[u]
    let g_i = 0.0 - g[u + hn]
    let ar = fr * f_r - fi * f_i
    let ai = fr * f_i + fi * f_r
    let br = gr * g_r - gi * g_i
    let bi = gr * g_i + gi * g_r
    d[u] = ar + br
    d[u + hn] = ai + bi
  }
}

///|
/// a *= b where b is auto-adjoint (real slots only).
pub fn falcon_poly_mul_autoadj_fft(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let bu = b[u]
    a[u] = a[u] * bu
    a[u + hn] = a[u + hn] * bu
  }
}

///|
/// a /= b where b is auto-adjoint (real slots only).
pub fn falcon_poly_div_autoadj_fft(
  a : Array[Double],
  b : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let ib = 1.0 / b[u]
    a[u] = a[u] * ib
    a[u + hn] = a[u + hn] * ib
  }
}

///|
/// In-place LDL decomposition of a 2x2 Gram matrix in FFT domain.
pub fn falcon_poly_LDL_fft(
  g00 : Array[Double],
  g01 : Array[Double],
  g11 : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let a_r = g00[u]
    let a_i = g00[u + hn]
    let b_r = g01[u]
    let b_i = g01[u + hn]
    // mu = g01 / g00
    let m = 1.0 / (a_r * a_r + a_i * a_i)
    let a2r = a_r * m
    let a2i = (0.0 - a_i) * m
    let mu_r = b_r * a2r - b_i * a2i
    let mu_i = b_r * a2i + b_i * a2r
    // g01 = mu * conj(g01)
    let p_r = mu_r * b_r - mu_i * (0.0 - b_i)
    let p_i = mu_r * (0.0 - b_i) + mu_i * b_r
    g11[u] = g11[u] - p_r
    g11[u + hn] = g11[u + hn] - p_i
    g01[u] = mu_r
    g01[u + hn] = 0.0 - mu_i
  }
}

///|
/// Non-destructive LDL step: d11 = g11 - mu*conj(g01), l10 = conj(mu).
pub fn falcon_poly_LDLmv_fft(
  d11 : Array[Double],
  l10 : Array[Double],
  g00 : Array[Double],
  g01 : Array[Double],
  g11 : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  for u = 0; u < hn; u = u + 1 {
    let a_r = g00[u]
    let a_i = g00[u + hn]
    let b_r = g01[u]
    let b_i = g01[u + hn]
    let m = 1.0 / (a_r * a_r + a_i * a_i)
    let a2r = a_r * m
    let a2i = (0.0 - a_i) * m
    let mu_r = b_r * a2r - b_i * a2i
    let mu_i = b_r * a2i + b_i * a2r
    let p_r = mu_r * b_r - mu_i * (0.0 - b_i)
    let p_i = mu_r * (0.0 - b_i) + mu_i * b_r
    d11[u] = g11[u] - p_r
    d11[u + hn] = g11[u + hn] - p_i
    l10[u] = mu_r
    l10[u + hn] = 0.0 - mu_i
  }
}

///|
/// Split an FFT-domain polynomial into its even/odd halves (f0, f1).
pub fn falcon_poly_split_fft(
  f0 : Array[Double],
  f1 : Array[Double],
  f : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  let qn = hn >> 1
  f0[0] = f[0]
  f1[0] = f[hn]
  for u = 0; u < qn; u = u + 1 {
    let a_r = f[u << 1]
    let a_i = f[(u << 1) + hn]
    let b_r = f[(u << 1) + 1]
    let b_i = f[(u << 1) + 1 + hn]
    let tr = a_r + b_r
    let ti = a_i + b_i
    f0[u] = fp_half(tr)
    f0[u + qn] = fp_half(ti)
    let dr = a_r - b_r
    let di = a_i - b_i
    let sr = fgm((u + hn) << 1)
    let si = 0.0 - fgm(((u + hn) << 1) + 1)
    let mr = dr * sr - di * si
    let mi = dr * si + di * sr
    f1[u] = fp_half(mr)
    f1[u + qn] = fp_half(mi)
  }
}

///|
/// Merge two FFT-domain half polynomials into f (inverse of split).
pub fn falcon_poly_merge_fft(
  f : Array[Double],
  f0 : Array[Double],
  f1 : Array[Double],
  logn : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  let qn = hn >> 1
  f[0] = f0[0]
  f[hn] = f1[0]
  for u = 0; u < qn; u = u + 1 {
    let a_r = f0[u]
    let a_i = f0[u + qn]
    let sr = fgm((u + hn) << 1)
    let si = fgm(((u + hn) << 1) + 1)
    let b_r = f1[u] * sr - f1[u + qn] * si
    let b_i = f1[u] * si + f1[u + qn] * sr
    f[u << 1] = a_r + b_r
    f[(u << 1) + hn] = a_i + b_i
    f[(u << 1) + 1] = a_r - b_r
    f[(u << 1) + 1 + hn] = a_i - b_i
  }
}

///|
/// Integer -> fpr (exact for |i| < 2^53).
pub fn fp_of(i : Int) -> Double {
  i.to_double()
}
