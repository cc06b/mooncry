// Falcon M4c (part 1): strided mod-p NTT, offset zint wrappers, CRT
// rebuild, and the big-polynomial helpers used by the solve_NTRU tree.
// Faithful port of PQClean keygen.c (poly_big_to_fp/to_small,
// poly_sub_scaled{,_ntt}, zint_rebuild_CRT, modp_{NTT,iNTT}2_ext).

///|
/// 2^31 as f64 (fpr_ptwo31).
let fp_two31 : Double = 2147483648.0

///|
/// Strided forward NTT mod p (elements at a[off + i*stride]).
fn modp_ntt2_ext(
  a : Array[Int],
  off : Int,
  stride : Int,
  gm : Array[Int],
  gm_off : Int,
  logn : Int,
  p : Int,
  p0i : Int,
) -> Unit {
  if logn == 0 {
    return
  }
  let n = 1 << logn
  let mut t = n
  let mut m = 1
  while m < n {
    let ht = t >> 1
    let mut v1 = 0
    for u = 0; u < m; u = u + 1 {
      let s = gm[gm_off + m + u]
      for v = 0; v < ht; v = v + 1 {
        let i1 = off + (v1 + v) * stride
        let i2 = off + (v1 + v + ht) * stride
        let x = a[i1]
        let y = modp_montymul(a[i2], s, p, p0i)
        a[i1] = modp_add(x, y, p)
        a[i2] = modp_sub(x, y, p)
      }
      v1 = v1 + t
    }
    t = ht
    m = m << 1
  }
}

///|
/// Strided inverse NTT mod p.
fn modp_intt2_ext(
  a : Array[Int],
  off : Int,
  stride : Int,
  igm : Array[Int],
  igm_off : Int,
  logn : Int,
  p : Int,
  p0i : Int,
) -> Unit {
  if logn == 0 {
    return
  }
  let n = 1 << logn
  let mut t = 1
  let mut m = n
  while m > 1 {
    let hm = m >> 1
    let dt = t << 1
    let mut v1 = 0
    for u = 0; u < hm; u = u + 1 {
      let s = igm[igm_off + hm + u]
      for v = 0; v < t; v = v + 1 {
        let i1 = off + (v1 + v) * stride
        let i2 = off + (v1 + v + t) * stride
        let x = a[i1]
        let y = a[i2]
        a[i1] = modp_add(x, y, p)
        a[i2] = modp_montymul(modp_sub(x, y, p), s, p, p0i)
      }
      v1 = v1 + dt
    }
    t = dt
    m = hm
  }
  let ni = 1 << (31 - logn)
  for k = 0; k < n; k = k + 1 {
    let i = off + k * stride
    a[i] = modp_montymul(a[i], ni, p, p0i)
  }
}

///|
/// zint_mod_small_unsigned over a slice d[doff .. doff+dlen).
fn zint_mod_small_unsigned_at(
  d : Array[Int],
  doff : Int,
  dlen : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
) -> Int {
  let mut x = 0
  let mut u = dlen
  while u > 0 {
    u = u - 1
    x = modp_montymul(x, r2, p, p0i)
    let mut w = d[doff + u] - p
    if w < 0 {
      w = w + p
    }
    x = modp_add(x, w, p)
  }
  x
}

///|
/// zint_mod_small_signed over a slice.
fn zint_mod_small_signed_at(
  d : Array[Int],
  doff : Int,
  dlen : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
  rx : Int,
) -> Int {
  if dlen == 0 {
    return 0
  }
  let mut z = zint_mod_small_unsigned_at(d, doff, dlen, p, p0i, r2)
  if d[doff + dlen - 1] >> 30 != 0 {
    z = modp_sub(z, rx, p)
  }
  z
}

///|
/// x[xoff..) += y[0..len) * s; carry written to x[xoff+len].
fn zint_add_mul_small_at(
  x : Array[Int],
  xoff : Int,
  y : Array[Int],
  len : Int,
  s : Int,
) -> Unit {
  let mut cc = 0
  for u = 0; u < len; u = u + 1 {
    let z = y[u].to_int64() * s.to_int64() +
      x[xoff + u].to_int64() +
      cc.to_int64()
    x[xoff + u] = (z & 0x7FFFFFFFL).to_int()
    cc = (z >> 31).to_int()
  }
  x[xoff + len] = cc
}

///|
/// zint_norm_zero over a slice.
fn zint_norm_zero_at(
  x : Array[Int],
  xoff : Int,
  p : Array[Int],
  len : Int,
) -> Unit {
  let mut r = 0
  let mut bb = 0
  let mut u = len
  while u > 0 {
    u = u - 1
    let wx = x[xoff + u]
    let wp = ((p[u] >> 1) & fp_mask31) | (bb << 30)
    bb = p[u] & 1
    // lock-on-first-difference semantics (see zint_norm_zero note)
    if r == 0 {
      if wx > wp {
        r = -1
      } else if wx < wp {
        r = 1
      }
    }
  }
  // conditional subtract in place
  if r == -1 {
    let mut cc = 0
    for i = 0; i < len; i = i + 1 {
      let w = x[xoff + i] - p[i] - cc
      x[xoff + i] = w & fp_mask31
      cc = if w < 0 { 1 } else { 0 }
    }
  }
}

///|
/// Big-limb polynomial (flen limbs per coefficient, stride fstride) ->
/// f64 array of 2^logn coefficients.
fn poly_big_to_fp(
  d : Array[Double],
  f : Array[Int],
  foff : Int,
  flen : Int,
  fstride : Int,
  logn : Int,
) -> Unit {
  let n = 1 << logn
  if flen == 0 {
    for u = 0; u < n; u = u + 1 {
      d[u] = 0.0
    }
    return
  }
  let mut fpos = foff
  for u = 0; u < n; u = u + 1 {
    // limbs are CONTIGUOUS within a coefficient; fstride steps between
    // coefficients (C: f += fstride per u, f[v] per limb)
    let neg = f[fpos + flen - 1] >> 30 != 0
    let xm = if neg { fp_mask31 } else { 0 }
    let mut cc = if neg { 1 } else { 0 }
    let mut x = 0.0
    let mut fsc = 1.0
    for v = 0; v < flen; v = v + 1 {
      let fv = f[fpos + v]
      let w64 = ((fv ^ xm) + cc).to_int64() & 0xFFFFFFFFL
      cc = (w64 >> 31).to_int()
      let mut w = (w64 & 0x7FFFFFFFL).to_int()
      if neg {
        w = 0 - w
      }
      x = x + w.to_double() * fsc
      fsc = fsc * fp_two31
    }
    d[u] = x
    fpos = fpos + fstride
  }
}

///|
/// One-limb-per-coefficient big -> int8 with range check; false if any
/// coefficient exceeds ±lim.
fn poly_big_to_small(
  d : Array[Int],
  s : Array[Int],
  soff : Int,
  lim : Int,
  logn : Int,
) -> Bool {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    let one : Array[Int] = [s[soff + u]]
    let z = zint_one_to_plain(one)
    if z < 0 - lim || z > lim {
      return false
    }
    d[u] = z
  }
  true
}

///|
/// F -= (X^k-scaled) f * k[u] with negacyclic wrap (direct method).
fn poly_sub_scaled(
  big_f : Array[Int],
  foff : Int,
  flen : Int,
  fstride : Int,
  small_f : Array[Int],
  soff : Int,
  small_len : Int,
  small_stride : Int,
  k : Array[Int],
  sch : Int,
  scl : Int,
  logn : Int,
) -> Unit {
  let n = 1 << logn
  for u = 0; u < n; u = u + 1 {
    let mut kf = 0 - k[u]
    let mut xoff = foff + u * fstride
    let mut yoff = soff
    for v = 0; v < n; v = v + 1 {
      zint_add_scaled_slice(
        big_f, xoff, flen, small_f, yoff, small_len, small_stride, kf, sch, scl,
      )
      if u + v == n - 1 {
        xoff = foff
        kf = 0 - kf
      } else {
        xoff = xoff + fstride // C: x += Fstride, NOT Flen
      }
      yoff = yoff + small_stride
    }
  }
}

///|
/// zint_add_scaled_mul_small over slices x[xoff..) += y[yoff..)*k<<sc.
fn zint_add_scaled_slice(
  x : Array[Int],
  xoff : Int,
  xlen : Int,
  y : Array[Int],
  yoff : Int,
  ylen : Int,
  _ystride : Int,
  k : Int,
  sch : Int,
  scl : Int,
) -> Unit {
  if ylen == 0 {
    return
  }
  let ytop = y[yoff + ylen - 1]
  let ysign = if ytop >> 30 != 0 { fp_mask31 } else { 0 }
  let mut tw = 0
  let mut cc = 0L
  for u = sch; u < xlen; u = u + 1 {
    let v = u - sch
    let mut wy = ysign
    if v < ylen {
      wy = y[yoff + v] // limbs contiguous within a coefficient
    }
    let wys = ((wy << scl) & fp_mask31) | tw
    tw = (wy >> (31 - scl)) & fp_mask31
    let z = wys.to_int64() * k.to_int64() + x[xoff + u].to_int64() + cc
    x[xoff + u] = (z & 0x7FFFFFFFL).to_int()
    cc = z >> 31
  }
}

///|
/// NTT-accelerated poly_sub_scaled: computes k*f in RNS over tlen
/// primes, CRT-rebuilds, then subtracts with scaling.
/// tmp layout: gm(n) | igm(n) | fk(n*tlen) | t1(n), tlen = flen+1.
fn poly_sub_scaled_ntt(
  big_f : Array[Int],
  foff : Int,
  flen : Int,
  fstride : Int,
  small_f : Array[Int],
  soff : Int,
  small_len : Int,
  small_stride : Int,
  k : Array[Int],
  sch : Int,
  scl : Int,
  logn : Int,
  tmp : Array[Int],
) -> Unit {
  let n = 1 << logn
  let tlen = small_len + 1
  let gm_off = 0
  let igm_off = n
  let fk_off = 2 * n
  let t1_off = fk_off + n * tlen
  for u = 0; u < tlen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let rx = modp_rx(small_len, p, p0i, r2) // C: Rx uses flen = SMALL poly limbs
    modp_mkgm2_slice(
      tmp,
      gm_off,
      tmp,
      igm_off,
      logn,
      falcon_primes_g[u],
      p,
      p0i,
    )
    for v = 0; v < n; v = v + 1 {
      tmp[t1_off + v] = modp_set(k[v], p)
    }
    modp_ntt2_ext(tmp, t1_off, 1, tmp, gm_off, logn, p, p0i)
    let mut yoff = soff
    for v = 0; v < n; v = v + 1 {
      tmp[fk_off + u + v * tlen] = zint_mod_small_signed_at(
        small_f, yoff, small_len, p, p0i, r2, rx,
      )
      yoff = yoff + small_stride
    }
    modp_ntt2_ext(tmp, fk_off + u, tlen, tmp, gm_off, logn, p, p0i)
    for v = 0; v < n; v = v + 1 {
      let ix = fk_off + u + v * tlen
      let inner = modp_montymul(tmp[t1_off + v], tmp[ix], p, p0i)
      tmp[ix] = modp_montymul(inner, r2, p, p0i)
    }
    modp_intt2_ext(tmp, fk_off + u, tlen, tmp, igm_off, logn, p, p0i)
  }
  // CRT rebuild: fk holds n polys of tlen limbs (stride tlen); t1 is scratch
  zint_rebuild_crt_from(tmp, fk_off, tlen, tlen, n, t1_off)
  let mut xoff = foff
  let mut yoff2 = fk_off
  for _u = 0; _u < n; _u = _u + 1 {
    zint_sub_scaled_slice(big_f, xoff, flen, tmp, yoff2, tlen, sch, scl)
    xoff = xoff + fstride
    yoff2 = yoff2 + tlen
  }
}

///|
/// mkgm2 writing gm/igm into slices of one array.
fn modp_mkgm2_slice(
  gm : Array[Int],
  gm_off : Int,
  igm : Array[Int],
  igm_off : Int,
  logn : Int,
  g0 : Int,
  p : Int,
  p0i : Int,
) -> Unit {
  let n = 1 << logn
  let r2 = modp_r2(p, p0i)
  let mut g = modp_montymul(g0, r2, p, p0i)
  for _k = logn; _k < 10; _k = _k + 1 {
    g = modp_montymul(g, g, p, p0i)
  }
  let ig = modp_div(r2, g, p, p0i, modp_r(p))
  let k = 10 - logn
  let mut x1 = modp_r(p)
  let mut x2 = modp_r(p)
  for u = 0; u < n; u = u + 1 {
    let v = falcon_rev10[u << k]
    gm[gm_off + v] = x1
    igm[igm_off + v] = x2
    x1 = modp_montymul(x1, g, p, p0i)
    x2 = modp_montymul(x2, ig, p, p0i)
  }
}

///|
/// CRT rebuild over a region of one array (xx at xxoff, stride xstride).
fn zint_rebuild_crt_from(
  xx : Array[Int],
  xxoff : Int,
  xlen : Int,
  xstride : Int,
  num : Int,
  tmp_off : Int,
) -> Unit {
  // tmp region must hold xlen limbs; use a dedicated copy to keep the
  // flat-array tmp semantics of zint_rebuild_crt.
  let tmp = Array::make(xlen + num, 0)
  xx[xxoff] = xx[xxoff] // no-op to keep offsets explicit
  tmp[0] = falcon_primes_p[0]
  for u = 1; u < xlen; u = u + 1 {
    let p = falcon_primes_p[u]
    let s = falcon_primes_s[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let mut xoff = xxoff
    for _v = 0; _v < num; _v = _v + 1 {
      let xp = xx[xoff + u]
      let xq = zint_mod_small_unsigned_at(xx, xoff, u, p, p0i, r2)
      let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i)
      zint_add_mul_small_at(xx, xoff, tmp, u, xr)
      xoff = xoff + xstride
    }
    tmp[u] = zint_mul_small(tmp, u, p)
  }
  let mut xoff = xxoff
  for _u = 0; _u < num; _u = _u + 1 {
    zint_norm_zero_at(xx, xoff, tmp, xlen)
    xoff = xoff + xstride
  }
  ignore(tmp_off)
}

///|
/// zint_sub_scaled over slices.
fn zint_sub_scaled_slice(
  x : Array[Int],
  xoff : Int,
  xlen : Int,
  y : Array[Int],
  yoff : Int,
  ylen : Int,
  sch : Int,
  scl : Int,
) -> Unit {
  if ylen == 0 {
    return
  }
  let ysign = if y[yoff + ylen - 1] >> 30 != 0 { fp_mask31 } else { 0 }
  let mut tw = 0
  let mut cc = 0
  for u = sch; u < xlen; u = u + 1 {
    let v = u - sch
    let mut wy = ysign
    if v < ylen {
      wy = y[yoff + v]
    }
    let wys = ((wy << scl) & fp_mask31) | tw
    tw = (wy >> (31 - scl)) & fp_mask31
    let w = x[xoff + u] - wys - cc
    x[xoff + u] = w & fp_mask31
    cc = if w < 0 { 1 } else { 0 }
  }
}

// ---------------------------------------------------------------------------
// make_fg: resultants of f and g with X^(N/2^depth)+1, computed over
// depth levels via the small-prime RNS + mod-p NTT machinery.
// ---------------------------------------------------------------------------

///|
fn fold_rec_res_at(
  t1 : Array[Int],
  t1_off : Int,
  dst : Array[Int],
  dst_off : Int,
  tlen : Int,
  hn : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
) -> Unit {
  for v = 0; v < hn; v = v + 1 {
    let w0 = t1[t1_off + (v << 1)]
    let w1 = t1[t1_off + (v << 1) + 1]
    dst[dst_off + v * tlen] = modp_montymul(
      modp_montymul(w0, w1, p, p0i),
      r2,
      p,
      p0i,
    )
  }
}
