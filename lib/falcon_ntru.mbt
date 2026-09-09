// Falcon M4b: small-prime modular layer (modp_*), mod-p NTT, and the
// 31-bit-limb signed bignum layer (zint_*) used by solve_NTRU.
// Faithful port of PQClean keygen.c lines ~630-2010. All u32 wrap
// idioms are reproduced with explicit masks; the C '>>31' on unsigned
// becomes a comparison against 2^31 on our non-negative Int values.

///|
let fp_2_31 : Int = 0x80000000

///|
let fp_mask31 : Int = 0x7FFFFFFF

// ---------------------------------------------------------------------------
// modp layer (modulus p < 2^31, values kept in [0, 2^31))
// ---------------------------------------------------------------------------

///|
fn modp_set(x : Int, p : Int) -> Int {
  let mut w = x
  if w < 0 {
    w = w + p
  }
  w
}

///|
pub fn modp_norm(x : Int, p : Int) -> Int {
  let half = (p + 1) >> 1
  if x >= half {
    x - p
  } else {
    x
  }
}

///|
/// -1/p mod 2^31 (Newton iteration, u32-wrap faithful via masks).
pub fn modp_ninv31(p : Int) -> Int {
  let p64 = p.to_int64()
  let mut y = (2L - p64) & 0xFFFFFFFFL
  for _i = 0; _i < 4; _i = _i + 1 {
    let t = (2L - ((p64 * y) & 0xFFFFFFFFL)) & 0xFFFFFFFFL
    y = (y * t) & 0xFFFFFFFFL
  }
  // C returns (0x7FFFFFFF & -y): the NEGATIVE inverse
  ((0L - y) & 0x7FFFFFFFL).to_int()
}

///|
pub fn modp_r(p : Int) -> Int {
  fp_2_31 - p
}

///|
pub fn modp_add(a : Int, b : Int, p : Int) -> Int {
  let mut d = a + b - p
  if d < 0 {
    d = d + p
  }
  d
}

///|
pub fn modp_sub(a : Int, b : Int, p : Int) -> Int {
  let mut d = a - b
  if d < 0 {
    d = d + p
  }
  d
}

///|
/// Montgomery multiply mod p (R = 2^31). a, b, p < 2^31.
pub fn modp_montymul(a : Int, b : Int, p : Int, p0i : Int) -> Int {
  let z = a.to_int64() * b.to_int64()
  let w = ((z * p0i.to_int64()) & 0x7FFFFFFFL) * p.to_int64()
  let d64 = ((z + w) >> 31).to_int() - p
  let mut d = d64
  if d < 0 {
    d = d + p
  }
  d
}

///|
/// R2 = 2^62 mod p in Montgomery domain.
pub fn modp_r2(p : Int, p0i : Int) -> Int {
  let mut z = modp_r(p)
  z = modp_add(z, z, p)
  for _i = 0; _i < 5; _i = _i + 1 {
    z = modp_montymul(z, z, p, p0i)
  }
  // (z + (p & -(z & 1))) >> 1 — u32 logical shift; t may reach 2^32-1
  let t = z.to_int64() + (if (z & 1) != 0 { p.to_int64() } else { 0L })
  ((t >> 1) & 0x7FFFFFFFL).to_int()
}

///|
/// R^x mod p in Montgomery domain (x >= 1).
pub fn modp_rx(x0 : Int, p : Int, p0i : Int, r2 : Int) -> Int {
  let x = x0 - 1
  let mut r = r2
  let mut z = modp_r(p)
  let mut i = 0
  while 1 << i <= x {
    if (x & (1 << i)) != 0 {
      z = modp_montymul(z, r, p, p0i)
    }
    r = modp_montymul(r, r, p, p0i)
    i = i + 1
  }
  z
}

///|
/// a / b mod p (Montgomery, exponentiation by p-2).
pub fn modp_div(a : Int, b : Int, p : Int, p0i : Int, rr : Int) -> Int {
  let e = p - 2
  let mut z = rr
  for i = 30; i >= 0; i = i - 1 {
    z = modp_montymul(z, z, p, p0i)
    let z2 = modp_montymul(z, b, p, p0i)
    if (e & (1 << i)) != 0 {
      z = z2
    }
  }
  z = modp_montymul(z, 1, p, p0i)
  modp_montymul(a, z, p, p0i)
}

///|
/// Build gm/igm tables for the mod-p NTT at degree 2^logn.
pub fn modp_mkgm2(
  gm : Array[Int],
  igm : Array[Int],
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
    gm[v] = x1
    igm[v] = x2
    x1 = modp_montymul(x1, g, p, p0i)
    x2 = modp_montymul(x2, ig, p, p0i)
  }
}

///|
/// Forward negacyclic-ish NTT mod p (gm from modp_mkgm2).
pub fn modp_ntt2(
  a : Array[Int],
  gm : Array[Int],
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
      let s = gm[m + u]
      for v = 0; v < ht; v = v + 1 {
        let x = a[v1 + v]
        let y = modp_montymul(a[v1 + v + ht], s, p, p0i)
        a[v1 + v] = modp_add(x, y, p)
        a[v1 + v + ht] = modp_sub(x, y, p)
      }
      v1 = v1 + t
    }
    t = ht
    m = m << 1
  }
}

///|
/// Inverse NTT mod p with 1/n scaling.
pub fn modp_intt2(
  a : Array[Int],
  igm : Array[Int],
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
      let s = igm[hm + u]
      for v = 0; v < t; v = v + 1 {
        let x = a[v1 + v]
        let y = a[v1 + v + t]
        a[v1 + v] = modp_add(x, y, p)
        a[v1 + v + t] = modp_montymul(modp_sub(x, y, p), s, p, p0i)
      }
      v1 = v1 + dt
    }
    t = dt
    m = hm
  }
  let ni = 1 << (31 - logn)
  for k = 0; k < n; k = k + 1 {
    a[k] = modp_montymul(a[k], ni, p, p0i)
  }
}

///|
/// One resultant-folding step: f[u] = f[2u]*f[2u+1] (Montgomery).
pub fn modp_poly_rec_res(
  f : Array[Int],
  logn : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
) -> Unit {
  let hn = 1 << (logn - 1)
  for u = 0; u < hn; u = u + 1 {
    let w0 = f[u << 1]
    let w1 = f[(u << 1) + 1]
    f[u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i)
  }
}

// ---------------------------------------------------------------------------
// zint layer: signed bignums as little-endian 31-bit limbs (Int values,
// each limb in [0, 2^31); arrays may carry one extra top limb).
// ---------------------------------------------------------------------------

///|
/// a -= b if ctl != 0; returns the borrow flag (0/1).
pub fn zint_sub(a : Array[Int], b : Array[Int], len : Int, ctl : Int) -> Int {
  let mut cc = 0
  for u = 0; u < len; u = u + 1 {
    let aw = a[u]
    if ctl != 0 {
      let w = aw - b[u] - cc
      a[u] = w & fp_mask31
      cc = if w < 0 { 1 } else { 0 }
    } else {
      cc = 0
    }
  }
  cc
}

///|
/// m *= x in place; returns the overflow carry.
pub fn zint_mul_small(m : Array[Int], mlen : Int, x : Int) -> Int {
  let mut cc = 0
  for u = 0; u < mlen; u = u + 1 {
    let z = m[u].to_int64() * x.to_int64() + cc.to_int64()
    m[u] = (z & 0x7FFFFFFFL).to_int()
    cc = (z >> 31).to_int()
  }
  cc
}

///|
/// d mod p for an unsigned (non-negative limb) bignum, Montgomery out.
pub fn zint_mod_small_unsigned(
  d : Array[Int],
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
    let mut w = d[u] - p
    if w < 0 {
      w = w + p
    }
    x = modp_add(x, w, p)
  }
  x
}

///|
/// Signed variant: subtracts Rx when the top limb has bit 30 set.
pub fn zint_mod_small_signed(
  d : Array[Int],
  dlen : Int,
  p : Int,
  p0i : Int,
  r2 : Int,
  rx : Int,
) -> Int {
  if dlen == 0 {
    return 0
  }
  let mut z = zint_mod_small_unsigned(d, dlen, p, p0i, r2)
  if d[dlen - 1] >> 30 != 0 {
    z = modp_sub(z, rx, p)
  }
  z
}

///|
/// x += y*s in place; writes the final carry to x[len].
pub fn zint_add_mul_small(
  x : Array[Int],
  y : Array[Int],
  len : Int,
  s : Int,
) -> Unit {
  let mut cc = 0
  for u = 0; u < len; u = u + 1 {
    let z = y[u].to_int64() * s.to_int64() + x[u].to_int64() + cc.to_int64()
    x[u] = (z & 0x7FFFFFFFL).to_int()
    cc = (z >> 31).to_int()
  }
  x[len] = cc
}

///|
/// Reduce x modulo the bignum p in place (conditional subtract chosen
/// by the lexicographic comparison x >= p).
pub fn zint_norm_zero(x : Array[Int], p : Array[Int], len : Int) -> Unit {
  let mut r = 0
  let mut bb = 0
  let mut u = len
  while u > 0 {
    u = u - 1
    let wx = x[u]
    let wp = ((p[u] >> 1) & fp_mask31) | (bb << 30)
    bb = p[u] & 1
    // C: r |= cc & ((r&1)-1) locks r once odd; the first differing
    // limb from the top decides: wx > wp -> subtract (C r = all ones),
    // wx < wp -> never subtract (C r = 1, r>>31 = 0).
    if r == 0 {
      if wx > wp {
        r = -1
      } else if wx < wp {
        r = 1
      }
    }
  }
  ignore(zint_sub(x, p, len, if r == -1 { 1 } else { 0 }))
}

///|
/// Conditional negate (two's complement over 31-bit limbs).
pub fn zint_negate(a : Array[Int], len : Int, ctl : Int) -> Unit {
  let mut cc = ctl
  let m = if ctl != 0 { fp_mask31 } else { 0 }
  for u = 0; u < len; u = u + 1 {
    let aw = (a[u] ^ m) + cc
    a[u] = aw & fp_mask31
    cc = (aw >> 31) & 1
  }
}

///|
/// (a,b) <- (xa*a + xb*b, ya*a + yb*b) over 31-bit limbs; result kept
/// non-negative via conditional negate. Returns nega | (negb << 1).
fn zint_co_reduce(
  a : Array[Int],
  b : Array[Int],
  len : Int,
  xa : Int64,
  xb : Int64,
  ya : Int64,
  yb : Int64,
) -> Int {
  let mut cca = 0L
  let mut ccb = 0L
  for u = 0; u < len; u = u + 1 {
    let wa = a[u].to_int64()
    let wb = b[u].to_int64()
    let za = wa * xa + wb * xb + cca
    let zb = wa * ya + wb * yb + ccb
    if u > 0 {
      a[u - 1] = (za & 0x7FFFFFFFL).to_int()
      b[u - 1] = (zb & 0x7FFFFFFFL).to_int()
    }
    cca = za >> 31
    ccb = zb >> 31
  }
  a[len - 1] = cca.to_int()
  b[len - 1] = ccb.to_int()
  let nega = if cca < 0L { 1 } else { 0 }
  let negb = if ccb < 0L { 1 } else { 0 }
  zint_negate(a, len, nega)
  zint_negate(b, len, negb)
  nega | (negb << 1)
}

///|
fn zint_finish_mod(
  a : Array[Int],
  len : Int,
  m : Array[Int],
  neg : Int,
) -> Unit {
  let mut cc = 0
  for u = 0; u < len; u = u + 1 {
    let w = a[u] - m[u] - cc
    cc = if w < 0 { 1 } else { 0 }
  }
  let do_xor = neg != 0
  let do_sub = neg != 0 || cc == 0
  let mut cc2 = if neg != 0 { 1 } else { 0 }
  for u = 0; u < len; u = u + 1 {
    let mut mw = m[u]
    if do_xor {
      mw = mw ^ fp_mask31
    }
    if do_sub == false {
      mw = 0
    }
    let aw = a[u] - mw - cc2
    a[u] = aw & fp_mask31
    cc2 = if aw < 0 { 1 } else { 0 }
  }
}

///|
/// co_reduce followed by reduction modulo m.
fn zint_co_reduce_mod(
  a : Array[Int],
  b : Array[Int],
  m : Array[Int],
  len : Int,
  m0i : Int,
  xa : Int64,
  xb : Int64,
  ya : Int64,
  yb : Int64,
) -> Unit {
  let mut cca = 0L
  let mut ccb = 0L
  let xa32 = xa & 0xFFFFFFFFL
  let xb32 = xb & 0xFFFFFFFFL
  let sum0 = (a[0].to_int64() * xa32 + b[0].to_int64() * xb32) & 0xFFFFFFFFL
  let fa = (sum0 * m0i.to_int64()) & 0x7FFFFFFFL
  let ya32 = ya & 0xFFFFFFFFL
  let yb32 = yb & 0xFFFFFFFFL
  let sum1 = (a[0].to_int64() * ya32 + b[0].to_int64() * yb32) & 0xFFFFFFFFL
  let fb = (sum1 * m0i.to_int64()) & 0x7FFFFFFFL
  for u = 0; u < len; u = u + 1 {
    let wa = a[u].to_int64()
    let wb = b[u].to_int64()
    let za = wa * xa + wb * xb + m[u].to_int64() * fa + cca
    let zb = wa * ya + wb * yb + m[u].to_int64() * fb + ccb
    if u > 0 {
      a[u - 1] = (za & 0x7FFFFFFFL).to_int()
      b[u - 1] = (zb & 0x7FFFFFFFL).to_int()
    }
    cca = za >> 31
    ccb = zb >> 31
  }
  a[len - 1] = cca.to_int()
  b[len - 1] = ccb.to_int()
  zint_finish_mod(a, len, m, if cca < 0L { 1 } else { 0 })
  zint_finish_mod(b, len, m, if ccb < 0L { 1 } else { 0 })
}

///|
/// Binary-GCD Bezout: u*x + v*y = gcd(x,y); returns nonzero iff the
/// gcd is 1 and both x[0], y[0] are odd.
pub fn zint_bezout(
  u : Array[Int],
  v : Array[Int],
  x : Array[Int],
  y : Array[Int],
  len : Int,
) -> Int {
  if len == 0 {
    return 0
  }
  let u1 = Array::make(len, 0)
  let v1 = Array::make(len, 0)
  let a = Array::make(len, 0)
  let b = Array::make(len, 0)
  let x0i = modp_ninv31(x[0])
  let y0i = modp_ninv31(y[0])
  for i = 0; i < len; i = i + 1 {
    a[i] = x[i]
    b[i] = y[i]
    u1[i] = y[i]
    v1[i] = x[i]
    v[i] = 0
  }
  u[0] = 1
  for i = 1; i < len; i = i + 1 {
    u[i] = 0
  }
  v1[0] = v1[0] - 1
  let mut num = 62 * len + 30
  while num >= 30 {
    // top two limbs of a and b (a0/a1 = top/second, 0 if absent)
    let mut c0 = -1
    let mut c1 = -1
    let mut a0 = 0
    let mut a1 = 0
    let mut b0 = 0
    let mut b1 = 0
    let mut j = len
    while j > 0 {
      j = j - 1
      let aw = a[j]
      let bw = b[j]
      if c0 != 0 {
        a0 = aw
        b0 = bw
      }
      if c1 != 0 {
        a1 = aw
        b1 = bw
      }
      c1 = c0
      // limbs < 2^31, but the sum can reach 2^32-2: compare in Int64
      // (wasm Int is 32-bit and would wrap negative)
      let t = (aw | bw).to_int64() + 0x7FFFFFFFL
      let bit = if t >= 0x80000000L { 1 } else { 0 }
      c0 = c0 & (bit - 1)
    }
    if c1 != 0 {
      a1 = a1 | a0
      b1 = b1 | b0
      a0 = 0
      b0 = 0
    }
    let mut a_hi = (a0.to_int64() << 31) + a1.to_int64()
    let mut b_hi = (b0.to_int64() << 31) + b1.to_int64()
    let mut a_lo = a[0].to_int64()
    let mut b_lo = b[0].to_int64()
    let mut pa = 1L
    let mut pb = 0L
    let mut qa = 0L
    let mut qb = 1L
    for i = 0; i < 31; i = i + 1 {
      let rz = b_hi - a_hi
      let xor1 = (a_hi ^ b_hi) & (a_hi ^ rz)
      let rt = if (rz ^ xor1) < 0L { 1 } else { 0 }
      let oa = ((a_lo >> i) & 1L).to_int()
      let ob = ((b_lo >> i) & 1L).to_int()
      let cab = oa & ob & rt
      let cba = oa & ob & (1 - rt)
      let ca = cab | (1 - oa)
      if cab != 0 {
        a_lo = a_lo - b_lo
        a_hi = a_hi - b_hi
        pa = pa - qa
        pb = pb - qb
      }
      if cba != 0 {
        b_lo = b_lo - a_lo
        b_hi = b_hi - a_hi
        qa = qa - pa
        qb = qb - pb
      }
      if ca == 0 {
        // cA=0: double a_lo/pa/pb, halve b_hi
        a_lo = a_lo + a_lo
        pa = pa + pa
        pb = pb + pb
        b_hi = b_hi >> 1
      } else {
        // cA=1: halve a_hi, double b_lo/qa/qb
        a_hi = a_hi >> 1
        b_lo = b_lo + b_lo
        qa = qa + qa
        qb = qb + qb
      }
    }
    let r = zint_co_reduce(a, b, len, pa, pb, qa, qb)
    if (r & 1) != 0 {
      pa = 0L - pa
      pb = 0L - pb
    }
    if r >> 1 != 0 {
      qa = 0L - qa
      qb = 0L - qb
    }
    zint_co_reduce_mod(u, u1, y, len, y0i, pa, pb, qa, qb)
    zint_co_reduce_mod(v, v1, x, len, x0i, pa, pb, qa, qb)
    num = num - 30
  }
  let mut rc = a[0] ^ 1
  for j = 1; j < len; j = j + 1 {
    rc = rc | a[j]
  }
  // C returns (1 - ((rc | -rc) >> 31)) & x[0] & y[0] on u32 rc:
  // nonzero only when rc == 0, i.e. a == exactly 1.
  if rc == 0 {
    x[0] & y[0] & 1
  } else {
    0
  }
}

///|
/// x += (y * k) << (sch*31 + scl) with sign extension of y.
pub fn zint_add_scaled_mul_small(
  x : Array[Int],
  xlen : Int,
  y : Array[Int],
  ylen : Int,
  k : Int,
  sch : Int,
  scl : Int,
) -> Unit {
  if ylen == 0 {
    return
  }
  let ysign = if y[ylen - 1] >> 30 != 0 { fp_mask31 } else { 0 }
  let mut tw = 0
  let mut cc = 0L
  for u = sch; u < xlen; u = u + 1 {
    let v = u - sch
    let mut wy = ysign
    if v < ylen {
      wy = y[v]
    }
    let wys = ((wy << scl) & fp_mask31) | tw
    tw = (wy >> (31 - scl)) & fp_mask31
    let z = wys.to_int64() * k.to_int64() + x[u].to_int64() + cc
    x[u] = (z & 0x7FFFFFFFL).to_int()
    cc = z >> 31
  }
}

///|
/// x -= y << (sch*31 + scl) with sign extension of y.
pub fn zint_sub_scaled(
  x : Array[Int],
  xlen : Int,
  y : Array[Int],
  ylen : Int,
  sch : Int,
  scl : Int,
) -> Unit {
  if ylen == 0 {
    return
  }
  let ysign = if y[ylen - 1] >> 30 != 0 { fp_mask31 } else { 0 }
  let mut tw = 0
  let mut cc = 0
  for u = sch; u < xlen; u = u + 1 {
    let v = u - sch
    let mut wy = ysign
    if v < ylen {
      wy = y[v]
    }
    let wys = ((wy << scl) & fp_mask31) | tw
    tw = (wy >> (31 - scl)) & fp_mask31
    let w = x[u] - wys - cc
    x[u] = w & fp_mask31
    cc = if w < 0 { 1 } else { 0 }
  }
}

///|
/// Interpret a one-limb zint as a plain signed int.
pub fn zint_one_to_plain(x : Array[Int]) -> Int {
  let w = x[0]
  // Two compatible representations: C stores u32 two's-complement whose
  // low 31 bits carry the magnitude with bit30 as sign; our pipeline
  // keeps native signed Ints. Only non-negative words with bit30 set
  // need the fold; already-negative words pass through unchanged.
  if w >= 0 && (w & 0x40000000) != 0 {
    w - fp_2_31
  } else {
    w
  }
}
