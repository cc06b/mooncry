// Falcon M3: verification path. Faithful port of PQClean falcon clean
// vrfy.c (mod-q Montgomery NTT + verify_raw + is_short) and the
// do_verify glue from pqclean.c. Verified against official signatures
// produced by the C reference (see falcon_m3_test.mbt).

///|
let falcon_q : Int = 12289

///|
let falcon_q0i : Int = 12287

///|
let falcon_r_mont : Int = 4091

///|
let falcon_r2 : Int = 10952

///|
/// Montgomery multiply mod q (16-bit window, wrapping Int32 like C u32).
fn mq_montymul(x : Int, y : Int) -> Int {
  let z = x * y
  let w = ((z * falcon_q0i) & 0xFFFF) * falcon_q
  let mut zr = (z + w) >> 16
  zr = zr - falcon_q
  zr = zr + (falcon_q & (zr >> 31))
  zr
}

///|
fn mq_add(x : Int, y : Int) -> Int {
  let mut d = x + y - falcon_q
  d = d + (falcon_q & (d >> 31))
  d
}

///|
fn mq_sub(x : Int, y : Int) -> Int {
  let mut d = x - y
  d = d + (falcon_q & (d >> 31))
  d
}

///|
fn mq_rshift1(x : Int) -> Int {
  let xx = x + (falcon_q & (0 - (x & 1)))
  xx >> 1
}

///|
/// Forward NTT (negacyclic, bit-reversal-free ordering per GMb table).
pub fn falcon_mq_ntt(a : Array[Int], logn : Int) -> Unit {
  let n = 1 << logn
  let mut t = n
  let mut m = 1
  while m < n {
    let ht = t >> 1
    let mut j1 = 0
    for i = 0; i < m; i = i + 1 {
      let s = falcon_GMb[m + i]
      let j2 = j1 + ht
      for j = j1; j < j2; j = j + 1 {
        let u = a[j]
        let v = mq_montymul(a[j + ht], s)
        a[j] = mq_add(u, v)
        a[j + ht] = mq_sub(u, v)
      }
      j1 = j1 + t
    }
    t = ht
    m = m << 1
  }
}

///|
/// Inverse NTT with final 1/n scaling.
pub fn falcon_mq_intt(a : Array[Int], logn : Int) -> Unit {
  let n = 1 << logn
  let mut t = 1
  let mut m = n
  while m > 1 {
    let hm = m >> 1
    let dt = t << 1
    let mut j1 = 0
    for i = 0; i < hm; i = i + 1 {
      let j2 = j1 + t
      let s = falcon_iGMb[hm + i]
      for j = j1; j < j2; j = j + 1 {
        let u = a[j]
        let v = a[j + t]
        a[j] = mq_add(u, v)
        let w = mq_sub(u, v)
        a[j + t] = mq_montymul(w, s)
      }
      j1 = j1 + dt
    }
    t = dt
    m = hm
  }
  let mut ni = falcon_r_mont
  let mut mm = n
  while mm > 1 {
    ni = mq_rshift1(ni)
    mm = mm >> 1
  }
  for u = 0; u < n; u = u + 1 {
    a[u] = mq_montymul(a[u], ni)
  }
}

///|
/// h -> NTT(h) * R2 (public key to Montgomery NTT domain).
pub fn falcon_to_ntt_monty(h : Array[Int], logn : Int) -> Unit {
  falcon_mq_ntt(h, logn)
  for u = 0; u < 1 << logn; u = u + 1 {
    h[u] = mq_montymul(h[u], falcon_r2)
  }
}

///|
/// L2 norm bound check on the (-s1, s2) pair, saturating like the C u32
/// accumulation.
pub fn falcon_is_short(s1 : Array[Int], s2 : Array[Int], logn : Int) -> Bool {
  let n = 1 << logn
  let mut s = 0L
  for u = 0; u < n; u = u + 1 {
    let z1 = s1[u].to_int64()
    s = s + z1 * z1
    let z2 = s2[u].to_int64()
    s = s + z2 * z2
  }
  s <= falcon_l2bound[logn].to_int64()
}

///|
/// verify_raw: reconstruct -s1 = s2*h - c0 (mod phi, mod q), normalize
/// to [-q/2, q/2], then is_short(-s1, s2).
pub fn falcon_verify_raw(
  c0 : Array[Int],
  s2 : Array[Int],
  h : Array[Int],
  logn : Int,
) -> Bool {
  let n = 1 << logn
  let tt = Array::make(n, 0)
  // reduce s2 mod q into [0, q-1]
  for u = 0; u < n; u = u + 1 {
    let mut w = s2[u]
    w = w + (falcon_q & (w >> 31))
    tt[u] = w
  }
  falcon_mq_ntt(tt, logn)
  for u = 0; u < n; u = u + 1 {
    tt[u] = mq_montymul(tt[u], h[u])
  }
  falcon_mq_intt(tt, logn)
  for u = 0; u < n; u = u + 1 {
    tt[u] = mq_sub(tt[u], c0[u])
  }
  // normalize into [-q/2, q/2]
  for u = 0; u < n; u = u + 1 {
    let mut w = tt[u]
    w = w - (falcon_q & (((falcon_q >> 1) - w) >> 31))
    tt[u] = w
  }
  falcon_is_short(tt, s2, logn)
}
