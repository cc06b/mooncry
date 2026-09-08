// ==================== scrypt (RFC 7914) ====================
// Memory-hard password-based KDF. Composes PBKDF2-HMAC-SHA256 (already in the
// library) with the Salsa20/8 core + scryptBlockMix + scryptROMix.
// Verified against Python `hashlib.scrypt`.
//
// Parameters: N (CPU/memory cost, power of 2), r (block size), p (parallelism),
// dkLen (output length). Work factor ~ N * r * p. Avoid N > ~16384 in tests
// (memory + time).

///|
fn rotl32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn scrypt_read_u32_le(data : Bytes, offset : Int) -> UInt {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn scrypt_write_u32_le(out : Array[Byte], offset : Int, v : UInt) -> Unit {
  out[offset] = (v & 0xFFU).to_byte()
  out[offset + 1] = ((v >> 8) & 0xFFU).to_byte()
  out[offset + 2] = ((v >> 16) & 0xFFU).to_byte()
  out[offset + 3] = ((v >> 24) & 0xFFU).to_byte()
}

///|
/// Salsa20 quarter-round. Mutates the word array in place.
fn salsa20_qr(x : Array[UInt], a : Int, b : Int, c : Int, d : Int) -> Unit {
  x[b] = x[b] ^ rotl32(x[a] + x[d], 7)
  x[c] = x[c] ^ rotl32(x[b] + x[a], 9)
  x[d] = x[d] ^ rotl32(x[c] + x[b], 13)
  x[a] = x[a] ^ rotl32(x[d] + x[c], 18)
}

///|
/// The Salsa20/8 core on a 16-word block, in place (v0.52.0 perf:
/// word-oriented pipeline, no Bytes conversions per block).
fn salsa20_8_words(x : Array[UInt]) -> Unit {
  let orig = Array::make(16, 0U)
  for i in 0..<16 {
    orig[i] = x[i]
  }
  for _ in 0..<4 {
    // columnround
    salsa20_qr(x, 0, 4, 8, 12)
    salsa20_qr(x, 5, 9, 13, 1)
    salsa20_qr(x, 10, 14, 2, 6)
    salsa20_qr(x, 15, 3, 7, 11)
    // rowround
    salsa20_qr(x, 0, 1, 2, 3)
    salsa20_qr(x, 5, 6, 7, 4)
    salsa20_qr(x, 10, 11, 8, 9)
    salsa20_qr(x, 15, 12, 13, 14)
  }
  for i in 0..<16 {
    x[i] = x[i] + orig[i]
  }
}

///|
/// scryptBlockMix(r, B) on words: b holds 2r blocks of 16 words.
fn scrypt_block_mix_words(r : Int, b : Array[UInt]) -> Array[UInt] {
  let n_blocks = 2 * r
  let x = Array::make(16, 0U)
  for i in 0..<16 {
    x[i] = b[(n_blocks - 1) * 16 + i]
  }
  let y = Array::make(n_blocks * 16, 0U)
  for i in 0..<n_blocks {
    for j in 0..<16 {
      x[j] = x[j] ^ b[i * 16 + j]
    }
    salsa20_8_words(x)
    for j in 0..<16 {
      y[i * 16 + j] = x[j]
    }
  }
  // interleave: even blocks then odd
  let out = Array::make(n_blocks * 16, 0U)
  let mut pos = 0
  let mut k = 0
  while k < n_blocks {
    for j in 0..<16 {
      out[pos + j] = y[k * 16 + j]
    }
    pos = pos + 16
    k = k + 2
  }
  k = 1
  while k < n_blocks {
    for j in 0..<16 {
      out[pos + j] = y[k * 16 + j]
    }
    pos = pos + 16
    k = k + 2
  }
  out
}

///|
/// scryptROMix(r, B, N) on words: b holds 2r*16 words; V is one flat
/// N * 2r * 16-word table (single allocation). Integerify = the first
/// word of the last 64-byte block (little-endian low 32 bits suffice:
/// N is a power of two <= 2^31).
fn scrypt_ro_mix_words(r : Int, b : Array[UInt], n : Int) -> Array[UInt] {
  let blen = 2 * r * 16
  let v = Array::make(n * blen, 0U)
  let mut x = b
  for i in 0..<n {
    for j in 0..<blen {
      v[i * blen + j] = x[j]
    }
    x = scrypt_block_mix_words(r, x)
  }
  for _ in 0..<n {
    let j = (x[(2 * r - 1) * 16] % n.reinterpret_as_uint()).reinterpret_as_int()
    let base = j * blen
    for t in 0..<blen {
      x[t] = x[t] ^ v[base + t]
    }
    x = scrypt_block_mix_words(r, x)
  }
  x
}

///|
/// scrypt (RFC 7914) password-based KDF. `n` (cost, power of two), `r` (block
/// size), `p` (parallelism), `dklen` (output bytes). Aborts on bad params
/// (n not power of two, or 128*r*n/p overflow). Work ~ n*r*p.
pub fn scrypt(
  password : Bytes,
  salt : Bytes,
  n : Int,
  r : Int,
  p : Int,
  dklen : Int,
) -> Bytes {
  if n <= 1 || (n & (n - 1)) != 0 {
    abort("scrypt: N must be a power of two > 1")
  }
  if r <= 0 || p <= 0 || dklen <= 0 {
    abort("scrypt: r, p, dklen must be positive")
  }
  let block_len = 128 * r
  // B0 = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r) — p blocks of 128r bytes.
  let b0 = pbkdf2_hmac_sha256(password, salt, 1, p * block_len)
  // ROMix each block independently.
  let result = Array::make(p * block_len, b'\x00')
  let mut i = 0
  while i < p {
    let start = i * block_len
    let block = Array::make(block_len, b'\x00')
    for k in 0..<block_len {
      block[k] = b0[start + k]
    }
    let block_b = Bytes::from_array(block[:])
    let nwords = block_len / 4
    let words = Array::make(nwords, 0U)
    for k in 0..<nwords {
      words[k] = scrypt_read_u32_le(block_b, k * 4)
    }
    let mixed_w = scrypt_ro_mix_words(r, words, n)
    for k in 0..<nwords {
      scrypt_write_u32_le(result, start + k * 4, mixed_w[k])
    }
    i = i + 1
  }
  // DK = PBKDF2-HMAC-SHA256(P, B, 1, dklen)
  pbkdf2_hmac_sha256(password, Bytes::from_array(result[:]), 1, dklen)
}
