// ============================================================
// cSHAKE128/256 and KMAC128/256/KMACXOF (NIST SP 800-185).
// Built on the Keccak-f[1600] sponge from sha3_stream.mbt with the
// SP 800-185 helper functions left_encode / right_encode /
// encode_string / bytepad.
// ============================================================

///|
/// Concatenate an array of Bytes into one fresh Bytes
fn sp185_concat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out = Array::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  Bytes::from_array(out[:])
}

///|
/// Number of bytes needed to represent x (at least 1)
fn sp185_int_len(x : Int) -> Int {
  if x == 0 {
    return 1
  }
  let mut v = x
  let mut n = 0
  while v > 0 {
    n = n + 1
    v = v / 256
  }
  n
}

///|
/// SP 800-185 left_encode(x): minimal big-endian encoding of x
/// prefixed with its byte length
fn sp185_left_encode(x : Int) -> Bytes {
  let n = sp185_int_len(x)
  let out = Array::make(n + 1, b'\x00')
  out[0] = n.to_byte()
  let mut v = x
  let mut i = n
  while i > 0 {
    out[i] = (v & 255).to_byte()
    v = v / 256
    i = i - 1
  }
  Bytes::from_array(out[:])
}

///|
/// SP 800-185 right_encode(x): minimal big-endian encoding of x
/// suffixed with its byte length
fn sp185_right_encode(x : Int) -> Bytes {
  let n = sp185_int_len(x)
  let out = Array::make(n + 1, b'\x00')
  let mut v = x
  let mut i = n - 1
  while i >= 0 {
    out[i] = (v & 255).to_byte()
    v = v / 256
    i = i - 1
  }
  out[n] = n.to_byte()
  Bytes::from_array(out[:])
}

///|
/// SP 800-185 encode_string(s): left_encode of the bit length, then s
fn sp185_encode_string(s : Bytes) -> Bytes {
  sp185_concat([sp185_left_encode(s.length() * 8), s])
}

///|
/// SP 800-185 bytepad(x, w): left_encode(w) || x, zero-padded so the
/// total length is a multiple of w
fn sp185_bytepad(x : Bytes, w : Int) -> Bytes {
  let head = sp185_left_encode(w)
  let pad = (w - (head.length() + x.length()) % w) % w
  let zeros = Bytes::from_array(Array::make(pad, b'\x00')[:])
  sp185_concat([head, x, zeros])
}

///|
/// cSHAKE sponge core (SP 800-185 §3). When both N and S are empty the
/// construction is defined to be identical to the corresponding SHAKE
/// XOF (domain 0x1F); otherwise the input is prefixed with
/// bytepad(encode_string(N) || encode_string(S), rate) and the sponge
/// uses domain 0x04.
fn cshake_core(
  rate : Int,
  data : Bytes,
  n : Bytes,
  s : Bytes,
  out_len : Int,
) -> Bytes {
  if out_len < 1 {
    abort("cshake: out_len must be at least 1")
  }
  let has_custom = n.length() > 0 || s.length() > 0
  let domain = if has_custom { 0x04 } else { 0x1F }
  let hasher = sha3_new(rate, out_len, domain)
  if has_custom {
    let prefix = sp185_bytepad(
      sp185_concat([sp185_encode_string(n), sp185_encode_string(s)]),
      rate,
    )
    sha3_update(hasher, prefix)
  }
  sha3_update(hasher, data)
  sha3_finalize(hasher)
}

///|
/// Compute cSHAKE128 (NIST SP 800-185), variable-length output.
/// `n` is the function-name string N, `s` the customization string S.
/// With N = S = "" this is exactly SHAKE128.
pub fn cshake_128(data : Bytes, n : Bytes, s : Bytes, out_len : Int) -> Bytes {
  cshake_core(168, data, n, s, out_len)
}

///|
/// Compute cSHAKE256 (NIST SP 800-185), variable-length output.
/// With N = S = "" this is exactly SHAKE256.
pub fn cshake_256(data : Bytes, n : Bytes, s : Bytes, out_len : Int) -> Bytes {
  cshake_core(136, data, n, s, out_len)
}

///|
/// KMAC core (SP 800-185 §4): newX = bytepad(encode_string(K), rate)
/// || X || right_encode(L), hashed with cSHAKE under N = "KMAC".
/// For the XOF variants L is encoded as 0 (right_encode(0)).
fn kmac_core(
  rate : Int,
  key : Bytes,
  data : Bytes,
  s : Bytes,
  out_len : Int,
  xof : Bool,
) -> Bytes {
  let tail = if xof {
    sp185_right_encode(0)
  } else {
    sp185_right_encode(out_len * 8)
  }
  let new_x = sp185_concat([
    sp185_bytepad(sp185_encode_string(key), rate),
    data,
    tail,
  ])
  cshake_core(rate, new_x, b"KMAC", s, out_len)
}

///|
/// Compute KMAC128 (NIST SP 800-185), fixed-length MAC. `key` must be
/// at least 16 bytes (128-bit security), `s` is the customization
/// string S, `out_len` the tag length in bytes.
pub fn kmac_128(key : Bytes, data : Bytes, s : Bytes, out_len : Int) -> Bytes {
  if key.length() < 16 {
    abort("kmac_128: key must be at least 16 bytes (128 bits)")
  }
  kmac_core(168, key, data, s, out_len, false)
}

///|
/// Compute KMAC256 (NIST SP 800-185), fixed-length MAC. `key` must be
/// at least 32 bytes (256-bit security), `s` is the customization
/// string S, `out_len` the tag length in bytes.
pub fn kmac_256(key : Bytes, data : Bytes, s : Bytes, out_len : Int) -> Bytes {
  if key.length() < 32 {
    abort("kmac_256: key must be at least 32 bytes (256 bits)")
  }
  kmac_core(136, key, data, s, out_len, false)
}

///|
/// Compute KMACXOF128 (NIST SP 800-185), variable-length output
/// variant of KMAC128 (right_encode(0) instead of the requested
/// length). `key` must be at least 16 bytes.
pub fn kmac_xof_128(
  key : Bytes,
  data : Bytes,
  s : Bytes,
  out_len : Int,
) -> Bytes {
  if key.length() < 16 {
    abort("kmac_xof_128: key must be at least 16 bytes (128 bits)")
  }
  kmac_core(168, key, data, s, out_len, true)
}

///|
/// Compute KMACXOF256 (NIST SP 800-185), variable-length output
/// variant of KMAC256. `key` must be at least 32 bytes.
pub fn kmac_xof_256(
  key : Bytes,
  data : Bytes,
  s : Bytes,
  out_len : Int,
) -> Bytes {
  if key.length() < 32 {
    abort("kmac_xof_256: key must be at least 32 bytes (256 bits)")
  }
  kmac_core(136, key, data, s, out_len, true)
}
