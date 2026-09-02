// ==================== X448 (RFC 7748) ====================
// X448 Diffie-Hellman over curve448 (Montgomery form), 448-bit security.
// Montgomery ladder on the u-coordinate per RFC 7748 §5. Verified against
// the official RFC 7748 §5.2/§6.1 test vectors (incl. the single-iteration
// K=u=5 vector).
//
// Note: the ladder here uses a plain (non-constant-time) conditional swap;
// the library's asymmetric operations are not side-channel hardened (see
// the README security notes).

///|
let x448_p : @bigint.BigInt = @bigint.BigInt::from_string(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  radix=16,
)

///|
let x448_a24 : @bigint.BigInt = @bigint.BigInt::from_uint64(39081UL)

///|
let x448_zero : @bigint.BigInt = @bigint.BigInt::from_uint64(0UL)

///|
let x448_one : @bigint.BigInt = @bigint.BigInt::from_uint64(1UL)

///|
let x448_two : @bigint.BigInt = @bigint.BigInt::from_uint64(2UL)

///|
fn x448_add(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + b) % x448_p
}

///|
fn x448_sub(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  (a + x448_p - b) % x448_p
}

///|
fn x448_mul(a : @bigint.BigInt, b : @bigint.BigInt) -> @bigint.BigInt {
  a * b % x448_p
}

///|
fn x448_sqr(a : @bigint.BigInt) -> @bigint.BigInt {
  a * a % x448_p
}

///|
fn x448_le_to_int(b : Bytes) -> @bigint.BigInt {
  let n = b.length()
  let rev = Array::make(n, b'\x00')
  for i in 0..<n {
    rev[i] = b[n - 1 - i]
  }
  @bigint.BigInt::from_octets(Bytes::from_array(rev[:]))
}

///|
fn x448_int_to_le(x : @bigint.BigInt) -> Bytes {
  let be = x.to_octets(length=56)
  let rev = Array::make(56, b'\x00')
  for i in 0..<56 {
    rev[i] = be[55 - i]
  }
  Bytes::from_array(rev[:])
}

///|
/// RFC 7748 §5 clamping for X448: clear the two least significant bits of
/// the first byte and set the most significant bit of the last byte.
fn x448_clamp(k : Bytes) -> Array[Byte] {
  if k.length() != 56 {
    abort("x448: scalar must be 56 bytes")
  }
  let arr = Array::make(56, b'\x00')
  for i in 0..<56 {
    arr[i] = k[i]
  }
  arr[0] = (arr[0].to_int() & 252).to_byte()
  arr[55] = (arr[55].to_int() | 128).to_byte()
  arr
}

///|
/// The X448 ladder (RFC 7748 §5). `k_le` is the clamped little-endian
/// scalar bytes; `u` the decoded u-coordinate.
fn x448_ladder(k_le : Array[Byte], u : @bigint.BigInt) -> @bigint.BigInt {
  let x1 = u
  let mut x2 = x448_one
  let mut z2 = x448_zero
  let mut x3 = u
  let mut z3 = x448_one
  let mut swap = 0
  for tt in 0..<448 {
    let t = 447 - tt
    let k_t = (k_le[t / 8].to_int() >> (t % 8)) & 1
    swap = swap ^ k_t
    if swap == 1 {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
    swap = k_t
    let aa_ = x448_add(x2, z2)
    let aaa = x448_sqr(aa_)
    let bb_ = x448_sub(x2, z2)
    let bbb = x448_sqr(bb_)
    let ee = x448_sub(aaa, bbb)
    let cc = x448_add(x3, z3)
    let dd = x448_sub(x3, z3)
    let da = x448_mul(dd, aa_)
    let cb = x448_mul(cc, bb_)
    x3 = x448_sqr(x448_add(da, cb))
    z3 = x448_mul(x1, x448_sqr(x448_sub(da, cb)))
    x2 = x448_mul(aaa, bbb)
    z2 = x448_mul(ee, x448_add(aaa, x448_mul(x448_a24, ee)))
  }
  if swap == 1 {
    let tx = x2
    x2 = x3
    x3 = tx
    let tz = z2
    z2 = z3
    z3 = tz
  }
  x448_mul(x2, z2.pow(x448_p - x448_two, modulus=x448_p))
}

///|
/// X448 scalar multiplication (RFC 7748): 56-byte scalar and 56-byte
/// u-coordinate in, 56-byte u-coordinate out (little-endian). The u
/// coordinate is decoded as a little-endian integer mod p (any high bits
/// beyond 448 are impossible for a 56-byte input).
pub fn x448(scalar : Bytes, u : Bytes) -> Bytes {
  if u.length() != 56 {
    abort("x448: u-coordinate must be 56 bytes")
  }
  let k_le = x448_clamp(scalar)
  let u_int = x448_le_to_int(u) % x448_p
  x448_int_to_le(x448_ladder(k_le, u_int))
}

///|
/// Derive the X448 public key (u = scalar * base point u=5).
pub fn x448_public_key(private_key : Bytes) -> Bytes {
  let base = Array::make(56, b'\x00')
  base[0] = b'\x05'
  x448(private_key, Bytes::from_array(base[:]))
}
