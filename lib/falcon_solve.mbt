// Falcon M4c: solve_NTRU tree (intermediate / binary depth1 / depth0),
// the solve_NTRU orchestrator, and the keygen loop. Faithful port of
// PQClean keygen.c. C's pointer aliasing between u32 and fpr views is
// reproduced with separate Int / Double arrays and explicit copies at
// the memmove points (identical data flow, no shared-memory hazards).

///|
let fp_bnorm_max_bits : UInt64 = 4670353323383631276UL

///|
/// fpr_rint: round-to-nearest-even, exact bit-level port (fpr.h).
fn fp_rint(x : Double) -> Int64 {
  let xb = x.reinterpret_as_uint64()
  let mut m = ((xb << 10) | (1UL << 62)) & 0x7FFFFFFFFFFFFFFFUL
  let exp11 = (xb >> 52) & 0x7FFUL
  let e = 1085L - exp11.reinterpret_as_int64()
  if e >= 64L {
    m = 0UL
  }
  let ee = (e & 63L).to_int()
  let d = m << (63 - ee)
  let d64 = d.reinterpret_as_int64()
  let top3 = ((d64 >> 61) & 7L).to_int()
  // sticky: any of bits 0..60 of d set (== C's dd != 0)
  let sticky = if (d64 & ((1L << 61) - 1L)) != 0L { 1 } else { 0 }
  let f = top3 | sticky
  m = (m >> ee) + ((0xC8 >> f) & 1).to_uint64()
  let s = (xb >> 63).reinterpret_as_int64()
  let mi = m.reinterpret_as_int64()
  (mi ^ (0L - s)) + s
}

///|
/// f64 constant bit patterns from fpr.h (programmatic copies).
let fp_ptwo31m1 : Double = 4746794007244308480UL.reinterpret_as_double()

///|
let fp_mtwo31m1 : Double = 13970166044099084288UL.reinterpret_as_double()

///|
let fp_ptwo63m1 : Double = 4890909195324358656UL.reinterpret_as_double()

///|
let fp_mtwo63m1 : Double = 14114281232179134464UL.reinterpret_as_double()

// ---------------------------------------------------------------------------
// make_fg with a base offset into a flat tmp array
// ---------------------------------------------------------------------------

///|
fn make_fg_step_at(
  data : Array[Int],
  base : Int,
  logn : Int,
  depth : Int,
  in_ntt : Int,
  out_ntt : Int,
) -> Unit {
  let n = 1 << logn
  let hn = n >> 1
  let slen = falcon_max_bl_small[depth]
  let tlen = falcon_max_bl_small[depth + 1]
  let fd = base
  let gd = base + hn * tlen
  let fs = base + 2 * hn * tlen
  let gs = fs + n * slen
  let gm = gs + n * slen
  let igm = gm + n
  let t1 = igm + n
  // memmove(fs, data+base, 2*n*slen)
  let cnt = 2 * n * slen
  let buf = Array::make(cnt, 0)
  for i = 0; i < cnt; i = i + 1 {
    buf[i] = data[base + i]
  }
  for i = 0; i < cnt; i = i + 1 {
    data[fs + i] = buf[i]
  }
  for u = 0; u < slen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    modp_mkgm2_slice(data, gm, data, igm, logn, falcon_primes_g[u], p, p0i)
    for v = 0; v < n; v = v + 1 {
      data[t1 + v] = data[fs + u + v * slen]
    }
    if in_ntt == 0 {
      modp_ntt2_ext(data, t1, 1, data, gm, logn, p, p0i)
    }
    fold_rec_res_at(data, t1, data, fd + u, tlen, hn, p, p0i, r2)
    if in_ntt != 0 {
      modp_intt2_ext(data, fs + u, slen, data, igm, logn, p, p0i)
    }
    for v = 0; v < n; v = v + 1 {
      data[t1 + v] = data[gs + u + v * slen]
    }
    if in_ntt == 0 {
      modp_ntt2_ext(data, t1, 1, data, gm, logn, p, p0i)
    }
    fold_rec_res_at(data, t1, data, gd + u, tlen, hn, p, p0i, r2)
    if in_ntt != 0 {
      modp_intt2_ext(data, gs + u, slen, data, igm, logn, p, p0i)
    }
    if out_ntt == 0 {
      modp_intt2_ext(data, fd + u, tlen, data, igm, logn - 1, p, p0i)
      modp_intt2_ext(data, gd + u, tlen, data, igm, logn - 1, p, p0i)
    }
  }
  zint_rebuild_crt_at(data, fs, slen, slen, n, 1)
  zint_rebuild_crt_at(data, gs, slen, slen, n, 1)
  for u = slen; u < tlen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let rx = modp_rx(slen, p, p0i, r2)
    modp_mkgm2_slice(data, gm, data, igm, logn, falcon_primes_g[u], p, p0i)
    for v = 0; v < n; v = v + 1 {
      data[t1 + v] = zint_mod_small_signed_at(
        data,
        fs + v * slen,
        slen,
        p,
        p0i,
        r2,
        rx,
      )
    }
    modp_ntt2_ext(data, t1, 1, data, gm, logn, p, p0i)
    fold_rec_res_at(data, t1, data, fd + u, tlen, hn, p, p0i, r2)
    for v = 0; v < n; v = v + 1 {
      data[t1 + v] = zint_mod_small_signed_at(
        data,
        gs + v * slen,
        slen,
        p,
        p0i,
        r2,
        rx,
      )
    }
    modp_ntt2_ext(data, t1, 1, data, gm, logn, p, p0i)
    fold_rec_res_at(data, t1, data, gd + u, tlen, hn, p, p0i, r2)
    if out_ntt == 0 {
      modp_intt2_ext(data, fd + u, tlen, data, igm, logn - 1, p, p0i)
      modp_intt2_ext(data, gd + u, tlen, data, igm, logn - 1, p, p0i)
    }
  }
}

///|
fn make_fg_at(
  data : Array[Int],
  base : Int,
  f : Array[Int],
  g : Array[Int],
  logn : Int,
  depth : Int,
  out_ntt : Int,
) -> Unit {
  let n = 1 << logn
  let ft = base
  let gt = base + n
  let p0 = falcon_primes_p[0]
  for u = 0; u < n; u = u + 1 {
    data[ft + u] = modp_set(f[u], p0)
    data[gt + u] = modp_set(g[u], p0)
  }
  if depth == 0 && out_ntt != 0 {
    let p = falcon_primes_p[0]
    let p0i = modp_ninv31(p)
    let gm = gt + n
    let igm = gm + n
    modp_mkgm2_slice(data, gm, data, igm, logn, falcon_primes_g[0], p, p0i)
    modp_ntt2_ext(data, ft, 1, data, gm, logn, p, p0i)
    modp_ntt2_ext(data, gt, 1, data, gm, logn, p, p0i)
    return
  }
  if depth == 0 {
    return
  }
  if depth == 1 {
    make_fg_step_at(data, base, logn, 0, 0, out_ntt)
    return
  }
  make_fg_step_at(data, base, logn, 0, 0, 1)
  for d = 1; d + 1 < depth; d = d + 1 {
    make_fg_step_at(data, base, logn - d, d, 1, 1)
  }
  make_fg_step_at(data, base, logn - depth + 1, depth - 1, 1, out_ntt)
}

///|
/// CRT rebuild over a region with its own scratch (no aliasing).
fn zint_rebuild_crt_at(
  xx : Array[Int],
  xxoff : Int,
  xlen : Int,
  xstride : Int,
  num : Int,
  normalize_signed : Int,
) -> Unit {
  let tmp = Array::make(xlen, 0)
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
  if normalize_signed != 0 {
    let mut xoff = xxoff
    for _u = 0; _u < num; _u = _u + 1 {
      zint_norm_zero_at(xx, xoff, tmp, xlen)
      xoff = xoff + xstride
    }
  }
}

// ---------------------------------------------------------------------------
// solve_NTRU levels
// ---------------------------------------------------------------------------

///|
fn solve_ntru_deepest_at(
  logn_top : Int,
  f : Array[Int],
  g : Array[Int],
  tmp : Array[Int],
) -> Bool {
  let len = falcon_max_bl_small[logn_top]
  let fp_off = 2 * len
  // C: make_fg(fp, ...) — base is the fp region itself; its final
  // fd/gd output lands exactly on fp/gp.
  make_fg_at(tmp, fp_off, f, g, logn_top, logn_top, 0)
  zint_rebuild_crt_at(tmp, fp_off, len, len, 2, 0)
  let fp = Array::make(len, 0)
  let gp = Array::make(len, 0)
  let out_f = Array::make(len, 0)
  let out_g = Array::make(len, 0)
  for i = 0; i < len; i = i + 1 {
    fp[i] = tmp[fp_off + i]
    gp[i] = tmp[fp_off + len + i]
  }
  if zint_bezout(out_g, out_f, fp, gp, len) == 0 {
    return false
  }
  for i = 0; i < len; i = i + 1 {
    tmp[i] = out_f[i]
    tmp[len + i] = out_g[i]
  }
  let q = 12289
  if zint_mul_small(tmp, len, q) != 0 {
    return false
  }
  let gslice = Array::make(len, 0)
  for i = 0; i < len; i = i + 1 {
    gslice[i] = tmp[len + i]
  }
  if zint_mul_small(gslice, len, q) != 0 {
    return false
  }
  for i = 0; i < len; i = i + 1 {
    tmp[len + i] = gslice[i]
  }
  true
}

///|
fn solve_ntru_intermediate(
  logn_top : Int,
  f : Array[Int],
  g : Array[Int],
  depth : Int,
  tmp : Array[Int],
) -> Bool {
  let logn = logn_top - depth
  let n = 1 << logn
  let hn = n >> 1
  let slen = falcon_max_bl_small[depth]
  let dlen = falcon_max_bl_small[depth + 1]
  let llen = falcon_max_bl_large[depth]
  // phase A: make_fg into tmp[ft0..]
  let ft0 = 2 * hn * dlen
  make_fg_at(tmp, ft0, f, g, logn_top, depth, 1)
  // relocate: ft/gt copy at 2*n*llen, Fd/Gd copy after
  let ft = 2 * n * llen
  let gt = ft + n * slen
  let fd_off = gt + n * slen
  let gd_off = fd_off + hn * dlen
  copy_words(tmp, ft0, ft, 2 * n * slen)
  copy_words(tmp, 0, fd_off, 2 * hn * dlen)
  let ft_off = 0
  let gt_off = n * llen
  // reduce Fd/Gd mod primes[0..llen) into Ft/Gt (stride llen, hn coeffs)
  for u = 0; u < llen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let rx = modp_rx(dlen, p, p0i, r2)
    for v = 0; v < hn; v = v + 1 {
      tmp[ft_off + u + v * llen] = zint_mod_small_signed_at(
        tmp,
        fd_off + v * dlen,
        dlen,
        p,
        p0i,
        r2,
        rx,
      )
      tmp[gt_off + u + v * llen] = zint_mod_small_signed_at(
        tmp,
        gd_off + v * dlen,
        dlen,
        p,
        p0i,
        r2,
        rx,
      )
    }
  }
  // per-prime lifting
  let gm = fd_off // t1 region (Fd is dead)
  for u = 0; u < llen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    if u == slen {
      zint_rebuild_crt_at(tmp, ft, slen, slen, n, 1)
      zint_rebuild_crt_at(tmp, gt, slen, slen, n, 1)
    }
    let igm = gm + n
    let fx = igm + n
    let gx = fx + n
    let fp = gx + n
    let gp = fp + hn
    modp_mkgm2_slice(tmp, gm, tmp, igm, logn, falcon_primes_g[u], p, p0i)
    if u < slen {
      for v = 0; v < n; v = v + 1 {
        tmp[fx + v] = tmp[ft + u + v * slen]
        tmp[gx + v] = tmp[gt + u + v * slen]
      }
      modp_intt2_ext(tmp, ft + u, slen, tmp, igm, logn, p, p0i)
      modp_intt2_ext(tmp, gt + u, slen, tmp, igm, logn, p, p0i)
    } else {
      let rx = modp_rx(slen, p, p0i, r2)
      for v = 0; v < n; v = v + 1 {
        tmp[fx + v] = zint_mod_small_signed_at(
          tmp,
          ft + v * slen,
          slen,
          p,
          p0i,
          r2,
          rx,
        )
        tmp[gx + v] = zint_mod_small_signed_at(
          tmp,
          gt + v * slen,
          slen,
          p,
          p0i,
          r2,
          rx,
        )
      }
      modp_ntt2_ext(tmp, fx, 1, tmp, gm, logn, p, p0i)
      modp_ntt2_ext(tmp, gx, 1, tmp, gm, logn, p, p0i)
    }
    for v = 0; v < hn; v = v + 1 {
      tmp[fp + v] = tmp[ft_off + u + v * llen]
      tmp[gp + v] = tmp[gt_off + u + v * llen]
    }
    modp_ntt2_ext(tmp, fp, 1, tmp, gm, logn - 1, p, p0i)
    modp_ntt2_ext(tmp, gp, 1, tmp, gm, logn - 1, p, p0i)
    for v = 0; v < hn; v = v + 1 {
      let x0 = ft_off + u + (v << 1) * llen
      let y0 = gt_off + u + (v << 1) * llen
      let ft_a = tmp[fx + (v << 1)]
      let ft_b = tmp[fx + (v << 1) + 1]
      let gt_a = tmp[gx + (v << 1)]
      let gt_b = tmp[gx + (v << 1) + 1]
      let mfp = modp_montymul(tmp[fp + v], r2, p, p0i)
      let mgp = modp_montymul(tmp[gp + v], r2, p, p0i)
      tmp[x0] = modp_montymul(gt_b, mfp, p, p0i)
      tmp[x0 + llen] = modp_montymul(gt_a, mfp, p, p0i)
      tmp[y0] = modp_montymul(ft_b, mgp, p, p0i)
      tmp[y0 + llen] = modp_montymul(ft_a, mgp, p, p0i)
    }
    modp_intt2_ext(tmp, ft_off + u, llen, tmp, igm, logn, p, p0i)
    modp_intt2_ext(tmp, gt_off + u, llen, tmp, igm, logn, p, p0i)
  }
  zint_rebuild_crt_at(tmp, ft_off, llen, llen, n, 1)
  zint_rebuild_crt_at(tmp, gt_off, llen, llen, n, 1)
  // f64 reduction phase (separate Double arrays; C aliases them into tmp)
  let rt3 = Array::make(n, 0.0)
  let rt4 = Array::make(n, 0.0)
  let rt5 = Array::make(hn, 0.0)
  let rt1 = Array::make(n, 0.0)
  let rt2 = Array::make(n, 0.0)
  let k = Array::make(n, 0)
  let t1s = n * (slen + 4) // scratch for sub_scaled_ntt (>= n*(slen+3))
  let scratch = Array::make(t1s, 0)
  let rlen0 = if slen > 10 { 10 } else { slen }
  poly_big_to_fp(rt3, tmp, ft + slen - rlen0, rlen0, slen, logn)
  poly_big_to_fp(rt4, tmp, gt + slen - rlen0, rlen0, slen, logn)
  let scale_fg = 31 * (slen - rlen0)
  let minbl_fg = falcon_bitlength_avg[depth] - 6 * falcon_bitlength_std[depth]
  let maxbl_fg = falcon_bitlength_avg[depth] + 6 * falcon_bitlength_std[depth]
  falcon_fft(rt3, logn)
  falcon_fft(rt4, logn)
  falcon_poly_invnorm2_fft(rt5, rt3, rt4, logn)
  falcon_poly_adj_fft(rt3, logn)
  falcon_poly_adj_fft(rt4, logn)
  let mut fglen = llen
  let mut maxbl_fg2 = 31 * llen
  let mut scale_k = maxbl_fg2 - minbl_fg
  while true {
    let rlen = if fglen > 10 { 10 } else { fglen }
    let scale_fgp = 31 * (fglen - rlen)
    poly_big_to_fp(rt1, tmp, ft_off + fglen - rlen, rlen, llen, logn)
    poly_big_to_fp(rt2, tmp, gt_off + fglen - rlen, rlen, llen, logn)
    falcon_fft(rt1, logn)
    falcon_fft(rt2, logn)
    falcon_poly_mul_fft(rt1, rt3, logn)
    falcon_poly_mul_fft(rt2, rt4, logn)
    falcon_poly_add(rt2, rt1, logn)
    falcon_poly_mul_autoadj_fft(rt2, rt5, logn)
    falcon_ifft(rt2, logn)
    let mut dc = scale_k - scale_fgp + scale_fg
    let mut pt = 0.0
    if dc < 0 {
      dc = 0 - dc
      pt = 2.0
    } else {
      pt = 0.5
    }
    let mut pdc = 1.0
    while dc != 0 {
      if (dc & 1) != 0 {
        pdc = pdc * pt
      }
      dc = dc >> 1
      pt = pt * pt
    }
    for u = 0; u < n; u = u + 1 {
      let xv = rt2[u] * pdc
      if xv <= fp_mtwo31m1 || xv >= fp_ptwo31m1 {
        return false
      }
      k[u] = fp_rint(xv).to_int()
    }
    let sch = scale_k / 31
    let scl = scale_k % 31
    if depth <= 4 {
      poly_sub_scaled_ntt(
        tmp, ft_off, fglen, llen, tmp, ft, slen, slen, k, sch, scl, logn, scratch,
      )
      poly_sub_scaled_ntt(
        tmp, gt_off, fglen, llen, tmp, gt, slen, slen, k, sch, scl, logn, scratch,
      )
    } else {
      poly_sub_scaled(
        tmp, ft_off, fglen, llen, tmp, ft, slen, slen, k, sch, scl, logn,
      )
      poly_sub_scaled(
        tmp, gt_off, fglen, llen, tmp, gt, slen, slen, k, sch, scl, logn,
      )
    }
    let new_maxbl = scale_k + maxbl_fg + 10
    if new_maxbl < maxbl_fg2 {
      maxbl_fg2 = new_maxbl
      if fglen * 31 >= maxbl_fg2 + 31 {
        fglen = fglen - 1
      }
    }
    if scale_k <= 0 {
      break
    }
    scale_k = scale_k - 25
    if scale_k < 0 {
      scale_k = 0
    }
  }
  if fglen < slen {
    for u = 0; u < 2 * n; u = u + 1 {
      let base = if u < n { ft_off + u * llen } else { gt_off + (u - n) * llen }
      let sw = if tmp[base + fglen - 1] >> 30 != 0 { fp_mask31 } else { 0 }
      for v = fglen; v < slen; v = v + 1 {
        tmp[base + v] = sw
      }
    }
  }
  // compact from stride llen to stride slen (2n polys)
  for u = 0; u < 2 * n; u = u + 1 {
    let row = Array::make(slen, 0)
    for v = 0; v < slen; v = v + 1 {
      row[v] = tmp[u * llen + v]
    }
    for v = 0; v < slen; v = v + 1 {
      tmp[u * slen + v] = row[v]
    }
  }
  true
}

///|
fn copy_words(a : Array[Int], src : Int, dst : Int, cnt : Int) -> Unit {
  let buf = Array::make(cnt, 0)
  for i = 0; i < cnt; i = i + 1 {
    buf[i] = a[src + i]
  }
  for i = 0; i < cnt; i = i + 1 {
    a[dst + i] = buf[i]
  }
}

///|
fn solve_ntru_depth1(
  logn_top : Int,
  f : Array[Int],
  g : Array[Int],
  tmp : Array[Int],
) -> Bool {
  let n_top = 1 << logn_top
  let logn = logn_top - 1
  let n = 1 << logn
  let hn = n >> 1
  let slen = falcon_max_bl_small[1]
  let dlen = falcon_max_bl_small[2]
  let llen = falcon_max_bl_large[1]
  let fd_off = 0
  let gd_off = dlen * hn
  let ft_off = 2 * dlen * hn
  let gt_off = ft_off + n * llen
  // reduce Fd/Gd mod primes[0..llen)
  for u = 0; u < llen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let rx = modp_rx(dlen, p, p0i, r2)
    for v = 0; v < hn; v = v + 1 {
      tmp[ft_off + u + v * llen] = zint_mod_small_signed_at(
        tmp,
        fd_off + v * dlen,
        dlen,
        p,
        p0i,
        r2,
        rx,
      )
      tmp[gt_off + u + v * llen] = zint_mod_small_signed_at(
        tmp,
        gd_off + v * dlen,
        dlen,
        p,
        p0i,
        r2,
        rx,
      )
    }
  }
  // relocate Ft/Gt to the front
  copy_words(tmp, ft_off, 0, llen * n)
  copy_words(tmp, gt_off, llen * n, llen * n)
  let big_ft = 0
  let big_gt = llen * n
  let ft = big_gt + llen * n
  let gt = ft + slen * n
  let t1 = gt + slen * n
  for u = 0; u < llen; u = u + 1 {
    let p = falcon_primes_p[u]
    let p0i = modp_ninv31(p)
    let r2 = modp_r2(p, p0i)
    let gm = t1
    let igm0 = gm + n_top
    let fx0 = igm0 + n
    let gx0 = fx0 + n_top
    modp_mkgm2_slice(tmp, gm, tmp, igm0, logn_top, falcon_primes_g[u], p, p0i)
    for v = 0; v < n_top; v = v + 1 {
      tmp[fx0 + v] = modp_set(f[v], p)
      tmp[gx0 + v] = modp_set(g[v], p)
    }
    modp_ntt2_ext(tmp, fx0, 1, tmp, gm, logn_top, p, p0i)
    modp_ntt2_ext(tmp, gx0, 1, tmp, gm, logn_top, p, p0i)
    for e = logn_top; e > logn; e = e - 1 {
      modp_poly_rec_res_at(tmp, fx0, e, p, p0i, r2)
      modp_poly_rec_res_at(tmp, gx0, e, p, p0i, r2)
    }
    // relocation dance (exact C memmove sequence)
    copy_words(tmp, igm0, gm + n, n)
    let igm = gm + n
    copy_words(tmp, fx0, igm + n, n)
    let fx = igm + n
    copy_words(tmp, gx0, fx + n, n)
    let gx = fx + n
    let fp = gx + n
    let gp = fp + hn
    for v = 0; v < hn; v = v + 1 {
      tmp[fp + v] = tmp[big_ft + u + v * llen]
      tmp[gp + v] = tmp[big_gt + u + v * llen]
    }
    modp_ntt2_ext(tmp, fp, 1, tmp, gm, logn - 1, p, p0i)
    modp_ntt2_ext(tmp, gp, 1, tmp, gm, logn - 1, p, p0i)
    for v = 0; v < hn; v = v + 1 {
      let x = big_ft + u + (v << 1) * llen
      let y = big_gt + u + (v << 1) * llen
      let ft_a = tmp[fx + (v << 1)]
      let ft_b = tmp[fx + (v << 1) + 1]
      let gt_a = tmp[gx + (v << 1)]
      let gt_b = tmp[gx + (v << 1) + 1]
      let mfp = modp_montymul(tmp[fp + v], r2, p, p0i)
      let mgp = modp_montymul(tmp[gp + v], r2, p, p0i)
      tmp[x] = modp_montymul(gt_b, mfp, p, p0i)
      tmp[x + llen] = modp_montymul(gt_a, mfp, p, p0i)
      tmp[y] = modp_montymul(ft_b, mgp, p, p0i)
      tmp[y + llen] = modp_montymul(ft_a, mgp, p, p0i)
    }
    modp_intt2_ext(tmp, big_ft + u, llen, tmp, igm, logn, p, p0i)
    modp_intt2_ext(tmp, big_gt + u, llen, tmp, igm, logn, p, p0i)
    if u < slen {
      modp_intt2_ext(tmp, fx, 1, tmp, igm, logn, p, p0i)
      modp_intt2_ext(tmp, gx, 1, tmp, igm, logn, p, p0i)
      for v = 0; v < n; v = v + 1 {
        tmp[ft + u + v * slen] = tmp[fx + v]
        tmp[gt + u + v * slen] = tmp[gx + v]
      }
    }
  }
  zint_rebuild_crt_at(tmp, big_ft, llen, llen, n << 1, 1)
  zint_rebuild_crt_at(tmp, ft, slen, slen, n << 1, 1)
  let rt1 = Array::make(n, 0.0)
  let rt2 = Array::make(n, 0.0)
  poly_big_to_fp(rt1, tmp, big_ft, llen, llen, logn)
  poly_big_to_fp(rt2, tmp, big_gt, llen, llen, logn)
  copy_words(tmp, ft, 0, 2 * slen * n)
  let sft = 0
  let sgt = slen * n
  let rt3 = Array::make(n, 0.0)
  let rt4 = Array::make(n, 0.0)
  poly_big_to_fp(rt3, tmp, sft, slen, slen, logn)
  poly_big_to_fp(rt4, tmp, sgt, slen, slen, logn)
  falcon_fft(rt1, logn)
  falcon_fft(rt2, logn)
  falcon_fft(rt3, logn)
  falcon_fft(rt4, logn)
  let rt5 = Array::make(n, 0.0)
  let rt6 = Array::make(hn, 0.0)
  falcon_poly_add_muladj_fft(rt5, rt1, rt2, rt3, rt4, logn)
  falcon_poly_invnorm2_fft(rt6, rt3, rt4, logn)
  falcon_poly_mul_autoadj_fft(rt5, rt6, logn)
  falcon_ifft(rt5, logn)
  for u = 0; u < n; u = u + 1 {
    let z = rt5[u]
    if z >= fp_ptwo63m1 || z <= fp_mtwo63m1 {
      return false
    }
    rt5[u] = fp_rint(z).to_double()
  }
  falcon_fft(rt5, logn)
  falcon_poly_mul_fft(rt3, rt5, logn)
  falcon_poly_mul_fft(rt4, rt5, logn)
  falcon_poly_sub(rt1, rt3, logn)
  falcon_poly_sub(rt2, rt4, logn)
  falcon_ifft(rt1, logn)
  falcon_ifft(rt2, logn)
  for u = 0; u < n; u = u + 1 {
    tmp[u] = fp_rint(rt1[u]).to_int()
    tmp[n + u] = fp_rint(rt2[u]).to_int()
  }
  true
}

///|
fn modp_poly_rec_res_at(
  f : Array[Int],
  off : Int,
  logn : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
) -> Unit {
  let hn = 1 << (logn - 1)
  for u = 0; u < hn; u = u + 1 {
    let w0 = f[off + (u << 1)]
    let w1 = f[off + (u << 1) + 1]
    f[off + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i)
  }
}
