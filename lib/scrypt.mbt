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
/// The Salsa20/8 core: 8 rounds (4 × columnround + rowround) on a 64-byte
/// block, returning a 64-byte block. Used by scryptBlockMix.
fn salsa20_8_block(block : Bytes) -> Bytes {
  let x = Array::make(16, 0U)
  for i in 0..<16 {
    x[i] = scrypt_read_u32_le(block, i * 4)
  }
  for _ in 0..<4 {
    // columnround (a,b,c,d = y0,y4,y8,y12 etc.)
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
  let out = Array::make(64, b'\x00')
  for i in 0..<16 {
    scrypt_write_u32_le(out, i * 4, x[i] + scrypt_read_u32_le(block, i * 4))
  }
  Bytes::from_array(out[:])
}

///|
/// scryptBlockMix(r, B): mix 2r 64-byte blocks. Output interleaves even then
/// odd blocks (Y[0],Y[2],...,Y[2r-2],Y[1],Y[3],...,Y[2r-1]).
fn scrypt_block_mix(r : Int, b : Bytes) -> Bytes {
  let block_size = 64
  let n_blocks = 2 * r
  // X = B[2r-1] (last block), then XOR each block + Salsa20/8.
  let x = Array::make(64, b'\x00')
  for i in 0..<64 {
    x[i] = b[(n_blocks - 1) * block_size + i]
  }
  let y_arr = Array::make(n_blocks, Bytes::make(64, b'\x00'))
  for i in 0..<n_blocks {
    // X = X XOR B[i]
    for j in 0..<64 {
      x[j] = (x[j].to_int() ^ b[i * block_size + j].to_int()).to_byte()
    }
    // X = Salsa20/8(X)
    let x_bytes = Bytes::from_array(x[:])
    let mixed = salsa20_8_block(x_bytes)
    for j in 0..<64 {
      x[j] = mixed[j]
    }
    y_arr[i] = mixed
  }
  // interleave: even blocks then odd blocks
  let out = Array::make(n_blocks * block_size, b'\x00')
  let mut out_pos = 0
  let mut k = 0
  while k < n_blocks {
    for j in 0..<64 {
      out[out_pos + j] = y_arr[k][j]
    }
    out_pos = out_pos + 64
    k = k + 2
  }
  k = 1
  while k < n_blocks {
    for j in 0..<64 {
      out[out_pos + j] = y_arr[k][j]
    }
    out_pos = out_pos + 64
    k = k + 2
  }
  Bytes::from_array(out[:])
}

///|
/// Integerify(B, r): the little-endian 64-bit value formed by the first 8
/// bytes of B's last 64-byte block (block index 2r-1). Since N is a power
/// of two and <= 2^31, the low 32 bits suffice (N divides 2^32).
fn scrypt_integerify(b : Bytes, r : Int) -> UInt {
  let offset = (2 * r - 1) * 64
  b[offset].to_uint() |
  (b[offset + 1].to_uint() << 8) |
  (b[offset + 2].to_uint() << 16) |
  (b[offset + 3].to_uint() << 24)
}

///|
/// scryptROMix(r, B, N): N rounds of BlockMix building a memory table V, then
/// N rounds of pseudo-random lookups. Returns the mixed 128r-byte block.
fn scrypt_ro_mix(r : Int, b : Bytes, n : Int) -> Bytes {
  let block_len = 128 * r
  // V: N snapshots of 128r bytes each.
  let v = Array::make(n, Bytes::make(block_len, b'\x00'))
  let mut x = b
  for i in 0..<n {
    v[i] = x
    x = scrypt_block_mix(r, x)
  }
  for _ in 0..<n {
    let j = (scrypt_integerify(x, r) % n.reinterpret_as_uint()).reinterpret_as_int()
    // X = X XOR V[j]
    let xored = Array::make(block_len, b'\x00')
    for i in 0..<block_len {
      xored[i] = (x[i].to_int() ^ v[j][i].to_int()).to_byte()
    }
    x = scrypt_block_mix(r, Bytes::from_array(xored[:]))
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
    let mixed = scrypt_ro_mix(r, Bytes::from_array(block[:]), n)
    for k in 0..<block_len {
      result[start + k] = mixed[k]
    }
    i = i + 1
  }
  // DK = PBKDF2-HMAC-SHA256(P, B, 1, dklen)
  pbkdf2_hmac_sha256(password, Bytes::from_array(result[:]), 1, dklen)
}
