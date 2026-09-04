// ============================================================
// TurboSHAKE128/256 + KangarooTwelve KT128/KT256 (RFC 9861). v0.36.0.
//
// TurboSHAKE = Keccak-p[1600, 12] sponge (the last 12 rounds of
// Keccak-f), rate 168 (TSHAKE128) / 136 (TSHAKE256), with the domain
// byte D (0x01..0x7F) appended to the message in lieu of the first
// pad10*1 bit. KangarooTwelve is the Sakura tree hash over TurboSHAKE
// with 8192-byte chunks.
// ============================================================

///|
fn turbosha_x(rate : Int, data : Bytes, d_byte : Byte, out_len : Int) -> Bytes {
  let st = Array::make(25, 0UL)
  let mlen = data.length() + 1 // message + domain byte
  let blocks = (mlen + rate - 1) / rate
  let padded_len = blocks * rate
  for blk in 0..<blocks {
    let start = blk * rate
    let end = if start + rate < mlen { start + rate } else { mlen }
    for i in start..<end {
      let j = i - start
      let bv = if i < data.length() { data[i] } else { d_byte }
      st[j / 8] = st[j / 8] ^ (bv.to_uint64() << (j % 8 * 8))
    }
    if blk == blocks - 1 {
      let pos = padded_len - 1 - start
      st[pos / 8] = st[pos / 8] ^ (0x80UL << (pos % 8 * 8))
    }
    keccak_f_from(st, 12)
  }
  let out = Array::make(out_len, b'\x00')
  let mut got = 0
  while got < out_len {
    let take = if rate < out_len - got { rate } else { out_len - got }
    for i in 0..<take {
      let lane = st[i / 8]
      out[got + i] = ((lane >> (i % 8 * 8)) & 0xFFUL).to_byte()
    }
    got = got + take
    if got < out_len {
      keccak_f_from(st, 12)
    }
  }
  Bytes::from_array(out[:])
}

///|
/// TurboSHAKE128 (RFC 9861 §2): Keccak-p[1600,12] sponge, rate 168.
/// `d` is the domain separation byte (0x01..0x7F). v0.36.0.
pub fn turbo_shake_128(data : Bytes, d : Byte, out_len : Int) -> Bytes {
  turbosha_x(168, data, d, out_len)
}

///|
/// TurboSHAKE256 (RFC 9861 §2): Keccak-p[1600,12] sponge, rate 136.
/// v0.36.0.
pub fn turbo_shake_256(data : Bytes, d : Byte, out_len : Int) -> Bytes {
  turbosha_x(136, data, d, out_len)
}

///|
/// RFC 9861 §3.3 length_encode(x): big-endian bytes of x followed by
/// their count (length_encode(0) = `00`, length_encode(12) = `0C 01`).
fn kt_length_encode(x : Int) -> Bytes {
  let digits : Array[Byte] = []
  let mut v = x
  while v > 0 {
    digits.push((v % 256).to_byte())
    v = v / 256
  }
  let n = digits.length()
  let out = Array::make(n + 1, b'\x00')
  for i in 0..<n {
    out[i] = digits[n - 1 - i]
  }
  out[n] = n.to_byte()
  Bytes::from_array(out[:])
}

///|
fn kt_core(rate : Int, cv_len : Int, m : Bytes, c : Bytes, l : Int) -> Bytes {
  let s = concat_all([m, c, kt_length_encode(c.length())])
  if s.length() <= 8192 {
    turbosha_x(rate, s, b'\x07', l)
  } else {
    let n = (s.length() + 8191) / 8192
    let parts : Array[Bytes] = [
      bytes_sub(s, 0, 8192),
      b"\x03\x00\x00\x00\x00\x00\x00\x00",
    ]
    for i in 1..<n {
      let start = i * 8192
      let len = if 8192 < s.length() - start {
        8192
      } else {
        s.length() - start
      }
      parts.push(turbosha_x(rate, bytes_sub(s, start, len), b'\x0B', cv_len))
    }
    parts.push(kt_length_encode(n - 1))
    parts.push(b"\xFF\xFF")
    turbosha_x(rate, concat_all(parts), b'\x06', l)
  }
}

///|
/// KangarooTwelve KT128 (RFC 9861 §3.2): tree hash over TurboSHAKE128
/// with 8192-byte chunks and 32-byte chaining values. `m` is the
/// message, `c` the customization string, `l` the output length. v0.36.0.
pub fn kangaroo_twelve_128(m : Bytes, c : Bytes, l : Int) -> Bytes {
  kt_core(168, 32, m, c, l)
}

///|
/// KangarooTwelve KT256 (RFC 9861 §3.4): tree hash over TurboSHAKE256
/// with 64-byte chaining values. v0.36.0.
pub fn kangaroo_twelve_256(m : Bytes, c : Bytes, l : Int) -> Bytes {
  kt_core(136, 64, m, c, l)
}
