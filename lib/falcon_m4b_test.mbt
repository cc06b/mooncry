// Falcon M4b tests: modp layer, mod-p NTT, and zint bignum layer vs
// dumps from the official PQClean C reference (falcon_m4b_vectors.txt).

///|
test "falcon-m4b-modp-consts" {
  inspect(modp_ninv31(falcon_primes_p[5]), content="2147352575")
  inspect(
    modp_r2(falcon_primes_p[5], modp_ninv31(falcon_primes_p[5])),
    content="786425",
  )
  inspect(modp_r(falcon_primes_p[5]), content="131071")
  inspect(modp_ninv31(falcon_primes_p[0]), content="2042615807")
  let p = falcon_primes_p[5]
  let p0i = modp_ninv31(p)
  let r2 = modp_r2(p, p0i)
  inspect(modp_rx(3, p, p0i, r2), content="4587479")
  inspect(modp_rx(17, p, p0i, r2), content="1075840476")
  inspect(modp_rx(100, p, p0i, r2), content="351392628")
}

///|
test "falcon-m4b-modp-ops" {
  let exp_ops : Array[Int] = [
    8888888, 2140932823, 218266831, 688562623, 1234567, 17777776, 2134513069, 873067324,
    688562623, 2469134, 26666664, 2128093315, 1964401479, 688562623, 3703701, 35555552,
    2121673561, 1344916719, 688562623, 4938268, 44444440, 2115253807, 1161965621,
    688562623, 6172835, 53333328, 2108834053, 1415548185, 688562623, 7407402, 62222216,
    2102414299, 2105664411, 688562623, 8641969, 71111104, 2095994545, 1084961722,
    688562623, 9876536, 79999992, 2089574791, 500792695, 688562623, 11111103, 88888880,
    2083155037, 353157330, 688562623, 12345670, 97777768, 2076735283, 642055627,
    688562623, 13580237, 106666656, 2070315529, 1367487586, 688562623, 14814804,
  ]
  let p = falcon_primes_p[5]
  let p0i = modp_ninv31(p)
  let got : Array[Int] = []
  for i = 1; i <= 12; i = i + 1 {
    let a = i * 1234567 % p
    let b = i * 7654321 % p
    got.push(modp_add(a, b, p))
    got.push(modp_sub(a, b, p))
    got.push(modp_montymul(a, b, p, p0i))
    got.push(modp_div(a, b, p, p0i, modp_r(p)))
    got.push(modp_norm(a, p))
  }
  let mut ok = got.length() == exp_ops.length()
  for i = 0; i < got.length(); i = i + 1 {
    if got[i] != exp_ops[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m4b-ntt2" {
  let exp_gm : Array[Int] = [
    131071, 809189909, 1363578287, 1363381681, 693150862, 494996176, 511773136, 659596686,
    1548644950, 1123031297, 1693078890, 972419764, 549501128, 637292556, 1260826735,
    1356620673,
  ]
  let exp_igm : Array[Int] = [
    131071, 1338162668, 783970896, 783774290, 1487755891, 1635579441, 1652356401,
    1454201715, 790731904, 886525842, 1510060021, 1597851449, 1174932813, 454273687,
    1024321280, 598707627,
  ]
  let exp_ntt : Array[Int] = [
    1752553145, 1914508733, 939811730, 1172243522, 1796386895, 1402924554, 459633657,
    569856430, 806471390, 484245263, 1237436457, 1910048006, 289935408, 377916615,
    1513926064, 550922923,
  ]
  let p = falcon_primes_p[5]
  let p0i = modp_ninv31(p)
  let gm = Array::make(16, 0)
  let igm = Array::make(16, 0)
  modp_mkgm2(gm, igm, 4, falcon_primes_g[5], p, p0i)
  let mut ok = true
  for i = 0; i < 16; i = i + 1 {
    if gm[i] != exp_gm[i] || igm[i] != exp_igm[i] {
      ok = false
    }
  }
  let a = Array::make(16, 0)
  let asave = Array::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    a[i] = (i * 37 + 11) % p
    asave[i] = a[i]
  }
  modp_ntt2(a, gm, 4, p, p0i)
  for i = 0; i < 16; i = i + 1 {
    if a[i] != exp_ntt[i] {
      ok = false
    }
  }
  modp_intt2(a, igm, 4, p, p0i)
  for i = 0; i < 16; i = i + 1 {
    if a[i] != asave[i] {
      ok = false
    }
  }
  let r = Array::make(16, 0)
  for i = 0; i < 16; i = i + 1 {
    r[i] = (i * 53 + 7) % p
  }
  let r2 = modp_r2(p, p0i)
  for lg = 4; lg >= 1; lg = lg - 1 {
    modp_poly_rec_res(r, lg, p, p0i, r2)
  }
  if r[0] != 28278973 {
    ok = false
  }
  inspect(ok, content="true")
}

///|
test "falcon-m4b-zint-basics" {
  let e_zsub : Array[Int] = [36984441, 2147483630, 11214]
  let e_zsub0 : Array[Int] = [305419896, 2147483632, 43981]
  let e_zmuls : Array[Int] = [1574813880, 2147287883, 542957789]
  let e_zaddmul : Array[Int] = [36983441, 2107, 32778215, 0]
  let e_zneg : Array[Int] = [1842063752, 15, 2147439666]
  let e_znorm : Array[Int] = [131055, 2147483632, 1073741824]
  let x : Array[Int] = [0x12345678, 0x7FFFFFF0, 0x0000ABCD]
  let y : Array[Int] = [0x0FFFFFFF, 0x00000002, 0x00007FFF]
  let mut ok = true
  let z = Array::make(3, 0)
  for i = 0; i < 3; i = i + 1 {
    z[i] = x[i]
  }
  if zint_sub(z, y, 3, 1) != 0 {
    ok = false
  }
  for i = 0; i < 3; i = i + 1 {
    if z[i] != e_zsub[i] {
      ok = false
    }
  }
  for i = 0; i < 3; i = i + 1 {
    z[i] = x[i]
  }
  if zint_sub(z, y, 3, 0) != 0 {
    ok = false
  }
  for i = 0; i < 3; i = i + 1 {
    if z[i] != e_zsub0[i] {
      ok = false
    }
  }
  for i = 0; i < 3; i = i + 1 {
    z[i] = x[i]
  }
  if zint_mul_small(z, 3, 12345) != 0 {
    ok = false
  }
  for i = 0; i < 3; i = i + 1 {
    if z[i] != e_zmuls[i] {
      ok = false
    }
  }
  let p = falcon_primes_p[5]
  let p0i = modp_ninv31(p)
  let r2 = modp_r2(p, p0i)
  if zint_mod_small_unsigned(x, 3, p, p0i, r2) != 534225878 {
    ok = false
  }
  if zint_mod_small_signed(x, 3, p, p0i, r2, modp_rx(3, p, p0i, r2)) !=
    534225878 {
    ok = false
  }
  let z4 = Array::make(4, 0)
  for i = 0; i < 3; i = i + 1 {
    z4[i] = x[i]
  }
  zint_add_mul_small(z4, y, 3, 999)
  for i = 0; i < 4; i = i + 1 {
    if z4[i] != e_zaddmul[i] {
      ok = false
    }
  }
  for i = 0; i < 3; i = i + 1 {
    z[i] = x[i]
  }
  zint_negate(z, 3, 1)
  for i = 0; i < 3; i = i + 1 {
    if z[i] != e_zneg[i] {
      ok = false
    }
  }
  let m : Array[Int] = [p, 0, 0]
  let w : Array[Int] = [0x7FFFFFF0, 0x7FFFFFF0, 0x40000000]
  zint_norm_zero(w, m, 3)
  for i = 0; i < 3; i = i + 1 {
    if w[i] != e_znorm[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m4b-zint-bezout" {
  let e_bezu : Array[Int] = [1804479205, 0]
  let e_bezv : Array[Int] = [1631630408, 1]
  let bx : Array[Int] = [123456789, 3]
  let by : Array[Int] = [987654321, 1]
  let bu = Array::make(2, 0)
  let bv = Array::make(2, 0)
  let rc = zint_bezout(bu, bv, bx, by, 2)
  inspect(rc, content="1")
  let mut ok = true
  for i = 0; i < 2; i = i + 1 {
    if bu[i] != e_bezu[i] || bv[i] != e_bezv[i] {
      ok = false
    }
  }
  inspect(ok, content="true")
}

///|
test "falcon-m4b-zint-scaled" {
  let e_addsc : Array[Int] = [1, 2, 31, 2147426112, 4, 6]
  let e_subsc : Array[Int] = [1, 2, 7, 2147475432, 4, 6]
  let sx : Array[Int] = [1, 2, 3, 4, 5, 6]
  let sy : Array[Int] = [0x70000000, 0x6FFFFFFF, 0x100]
  zint_add_scaled_mul_small(sx, 6, sy, 3, -7, 1, 5)
  let sz : Array[Int] = [1, 2, 3, 4, 5, 6]
  zint_sub_scaled(sz, 6, sy, 3, 1, 5)
  let mut ok = true
  for i = 0; i < 6; i = i + 1 {
    if sx[i] != e_addsc[i] || sz[i] != e_subsc[i] {
      ok = false
    }
  }
  let one : Array[Int] = [0x7FFFFFFF]
  if zint_one_to_plain(one) != -1 {
    ok = false
  }
  inspect(ok, content="true")
}
