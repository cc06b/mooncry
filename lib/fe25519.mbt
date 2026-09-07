/// Curve25519 field arithmetic — radix 2^25.5, ten signed Int64 limbs
/// (donna/ref10 style). Value = sum f[i] * 2^S[i], S[i] = ceil(51*i/2),
/// limb widths alternate 26/25 bits. Negative intermediates are legal:
/// carries use arithmetic shift (floor semantics), exactly like the
/// Python prototype this was ported from (v0.45.0 perf: replaces the
/// generic BigInt ladder, ~10x faster).
///
/// Multiplication coefficients are DERIVED at init from the shift table
/// (never hand-copied): the direct term (i+j<10) scales by
/// 2^(S[i]+S[j]-S[i+j]) in {1,2}; the wrap term (i+j>=10) additionally
/// uses 2^255 = 19 mod p, giving {19,38}.

///|
let fe25519_s : Array[Int] = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]

///|
let fe25519_w : Array[Int] = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25]

///|
let fe25519_m : Array[Int64] = [
  0x3FFFFFFL, 0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL, 0x3FFFFFFL,
  0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL,
]

///|
/// Bias limbs = the limb decomposition of p = 2^255-19 (fe_sub).
let fe25519_pbias : Array[Int64] = [
  0x3FFFFEDL, 0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL, 0x3FFFFFFL,
  0x1FFFFFFL, 0x3FFFFFFL, 0x1FFFFFFL,
]

///|
/// mul coefficients: coef[i*10+j].
let fe25519_coef : Array[Int64] = {
  let t = Array::make(100, 1L)
  for i in 0..<10 {
    for j in 0..<10 {
      if i + j < 10 {
        let d = fe25519_s[i] + fe25519_s[j] - fe25519_s[i + j]
        t[i * 10 + j] = 1L << d
      } else {
        // S[10] = 255; 2^255 = 19 (mod p)
        let d = fe25519_s[i] + fe25519_s[j] - fe25519_s[i + j - 10] - 255
        t[i * 10 + j] = 19L * (1L << d)
      }
    }
  }
  t
}

///|
/// Carry-normalize in place: limbs to [0, 2^w), limb 9 wraps with x19.
fn fe_carry(h : Array[Int64]) -> Array[Int64] {
  for i in 0..<9 {
    let c = h[i] >> fe25519_w[i]
    h[i] = h[i] - (c << fe25519_w[i])
    h[i + 1] = h[i + 1] + c
  }
  let c9 = h[9] >> 25
  h[9] = h[9] - (c9 << 25)
  h[0] = h[0] + 19L * c9
  let c0 = h[0] >> 26
  h[0] = h[0] - (c0 << 26)
  h[1] = h[1] + c0
  h
}

///|
fn fe_zero() -> Array[Int64] {
  Array::make(10, 0L)
}

///|
fn fe_one() -> Array[Int64] {
  let f = Array::make(10, 0L)
  f[0] = 1L
  f
}

///|
fn fe_mul(f : Array[Int64], g : Array[Int64]) -> Array[Int64] {
  let r = Array::make(10, 0L)
  for i in 0..<10 {
    let fi = f[i]
    if fi == 0L {
      continue
    }
    for j in 0..<10 {
      let k = i + j
      let prod = fe25519_coef[i * 10 + j] * fi * g[j]
      if k < 10 {
        r[k] = r[k] + prod
      } else {
        r[k - 10] = r[k - 10] + prod
      }
    }
  }
  fe_carry(r)
}

///|
fn fe_sqr(f : Array[Int64]) -> Array[Int64] {
  fe_mul(f, f)
}

///|
fn fe_add(f : Array[Int64], g : Array[Int64]) -> Array[Int64] {
  let r = Array::make(10, 0L)
  for i in 0..<10 {
    r[i] = f[i] + g[i]
  }
  fe_carry(r)
}

///|
fn fe_sub(f : Array[Int64], g : Array[Int64]) -> Array[Int64] {
  let r = Array::make(10, 0L)
  for i in 0..<10 {
    r[i] = f[i] + fe25519_pbias[i] - g[i]
  }
  fe_carry(r)
}

///|
fn fe_mula24(f : Array[Int64]) -> Array[Int64] {
  let r = Array::make(10, 0L)
  for i in 0..<10 {
    r[i] = f[i] * 121665L
  }
  fe_carry(r)
}

///|
/// Bit patterns of the fixed exponents, computed once at init:
/// p-2 (inversion) and (p+3)/8 (sqrt for p = 5 mod 8).
let fe_pm2_bits : Array[Bool] = {
  let e = ed_p - @bigint.BigInt::from_int(2)
  let str = e.to_string(radix=2)
  let t = Array::make(str.length(), false)
  for i in 0..<str.length() {
    t[i] = str[i] == '1'
  }
  t
}

///|
let fe_p38_bits : Array[Bool] = {
  let e = (ed_p + @bigint.BigInt::from_int(3)) / @bigint.BigInt::from_int(8)
  let str = e.to_string(radix=2)
  let t = Array::make(str.length(), false)
  for i in 0..<str.length() {
    t[i] = str[i] == '1'
  }
  t
}

///|
/// z^e for a precomputed MSB-first bit pattern (square-and-multiply).
fn fe_pow_bits(z : Array[Int64], bits : Array[Bool]) -> Array[Int64] {
  let mut r = fe_one()
  for b in bits {
    r = fe_sqr(r)
    if b {
      r = fe_mul(r, z)
    }
  }
  r
}

///|
/// f^(p-2): field inversion.
fn fe_invert(z : Array[Int64]) -> Array[Int64] {
  fe_pow_bits(z, fe_pm2_bits)
}

///|
/// Candidate square root z^((p+3)/8) (p = 5 mod 8).
fn fe_sqrt_cand(z : Array[Int64]) -> Array[Int64] {
  fe_pow_bits(z, fe_p38_bits)
}

///|
/// sqrt(-1) = 2^((p-1)/4) in limbs (computed once at init).
let fe_sqrt_m1 : Array[Int64] = {
  let i_exp = (ed_p - @bigint.BigInt::from_int(1)) / @bigint.BigInt::from_int(4)
  fe_fromint_big(ed_two.pow(i_exp, modulus=ed_p))
}

///|
/// BigInt -> limbs (canonical, non-negative).
fn fe_fromint_big(v : @bigint.BigInt) -> Array[Int64] {
  let m = (v % ed_p + ed_p) % ed_p
  let f = Array::make(10, 0L)
  for i in 0..<10 {
    let limb = (m >> fe25519_s[i]) & @bigint.BigInt::from_int64(fe25519_m[i])
    f[i] = limb.to_int64()
  }
  f
}

///|
fn fe_neg(f : Array[Int64]) -> Array[Int64] {
  fe_sub(fe_zero(), f)
}

///|
/// Decode a 32-byte little-endian u-coordinate (top bit masked per
/// RFC 7748) into limbs.
fn fe_frombytes(s : Bytes) -> Array[Int64] {
  let arr = s.to_array()
  arr[31] = (arr[31].to_int() & 127).to_byte()
  let v = ed_le_to_int(Bytes::from_array(arr))
  let f = Array::make(10, 0L)
  for i in 0..<10 {
    let limb = (v >> fe25519_s[i]) & @bigint.BigInt::from_int64(fe25519_m[i])
    f[i] = limb.to_int64()
  }
  f
}

///|
/// Canonical 32-byte little-endian encoding.
fn fe_tobytes(h : Array[Int64]) -> Bytes {
  let mut v = @bigint.BigInt::from_int(0)
  for i in 0..<10 {
    v = v +
      @bigint.BigInt::from_int64(h[i]) *
      (@bigint.BigInt::from_int(1) << fe25519_s[i])
  }
  let canonical = v % ed_p
  ed_int_to_le(canonical, 32)
}

///|
/// X25519 Montgomery ladder on native limbs (RFC 7748 §5, a24 = 121665).
fn x25519_ladder(k_bytes : Bytes, u_bytes : Bytes) -> Bytes {
  let x1 = fe_frombytes(u_bytes)
  let mut x2 = fe_one()
  let mut z2 = fe_zero()
  let mut x3 = fe_frombytes(u_bytes)
  let mut z3 = fe_one()
  let mut swap = 0
  for pos = 254; pos >= 0; pos = pos - 1 {
    // bit straight from the clamped scalar bytes (no BigInt per bit)
    let kt = (k_bytes[pos / 8].to_int() >> (pos & 7)) & 1
    swap = swap ^ kt
    if swap == 1 {
      let t = x2
      x2 = x3
      x3 = t
      let t2 = z2
      z2 = z3
      z3 = t2
    }
    swap = kt
    let a = fe_add(x2, z2)
    let aa = fe_sqr(a)
    let b = fe_sub(x2, z2)
    let bb = fe_sqr(b)
    let e = fe_sub(aa, bb)
    let c = fe_add(x3, z3)
    let d = fe_sub(x3, z3)
    let da = fe_mul(d, a)
    let cb = fe_mul(c, b)
    x3 = fe_sqr(fe_add(da, cb))
    z3 = fe_mul(x1, fe_sqr(fe_sub(da, cb)))
    x2 = fe_mul(aa, bb)
    z2 = fe_mul(e, fe_add(aa, fe_mula24(e)))
  }
  if swap == 1 {
    let t = x2
    x2 = x3
    x3 = t
    let t2 = z2
    z2 = z3
    z3 = t2
  }
  fe_tobytes(fe_mul(x2, fe_invert(z2)))
}
