// ==================== AES-CMAC (NIST SP 800-38B) ====================
// Reuses the AES block cipher (`encrypt_block` / `aes_key_expansion`).
// 128-bit keys verified against the NIST SP 800-38B Appendix D.1 vectors.

///|
fn cmac_shift_left(block : Bytes) -> Bytes {
  // Shift a 16-byte (big-endian) block left by one bit. Process from the
  // least-significant byte (index 15) upward so the carry flows toward the
  // most-significant byte; the top bit of block[0] is the overflow (lost).
  let out = Array::make(16, b'\x00')
  let mut carry = 0
  let mut i = 15
  while i >= 0 {
    let b = block[i].to_int()
    out[i] = (((b << 1) | carry) & 0xFF).to_byte()
    carry = (b >> 7) & 1
    i = i - 1
  }
  Bytes::from_array(out[:])
}

///|
fn cmac_gen_subkeys(key : Bytes) -> (Bytes, Bytes) {
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)
  let zero = Bytes::from_array(Array::make(16, b'\x00')[:])
  let l = encrypt_block(zero, round_keys, nr)
  // K1 = (L << 1) xor (Rb if MSB(L) == 1)
  let k1 = cmac_shift_left(l)
  let k1 = if (l[0].to_int() & 0x80) != 0 {
    let rb = Array::make(16, b'\x00')
    rb[15] = b'\x87'
    xor_bytes(k1, Bytes::from_array(rb[:]))
  } else {
    k1
  }
  // K2 = (K1 << 1) xor (Rb if MSB(K1) == 1)
  let k2 = cmac_shift_left(k1)
  let k2 = if (k1[0].to_int() & 0x80) != 0 {
    let rb = Array::make(16, b'\x00')
    rb[15] = b'\x87'
    xor_bytes(k2, Bytes::from_array(rb[:]))
  } else {
    k2
  }
  (k1, k2)
}

///|
/// AES-CMAC (NIST SP 800-38B). Returns the 16-byte MAC. `key` may be 16,
/// 192, or 256 bits. Wrong key length aborts.
pub fn cmac_aes(data : Bytes, key : Bytes) -> Bytes {
  if key.length() != 16 && key.length() != 24 && key.length() != 32 {
    abort("cmac_aes: key length must be 16, 24, or 32 bytes")
  }
  let nr = if key.length() == 16 {
    10
  } else if key.length() == 24 {
    12
  } else {
    14
  }
  let round_keys = aes_key_expansion(key)
  let (k1, k2) = cmac_gen_subkeys(key)

  let len = data.length()
  let num_full = len / 16
  let last_partial = len % 16
  // If the message is empty or the last block is partial, the final block is
  // padded (0x80 followed by zeros) and XORed with K2; otherwise the final
  // full block is XORed with K1.
  let last_is_full = if len == 0 { false } else { last_partial == 0 }

  let num_blocks = if last_is_full { num_full } else { num_full + 1 }

  let mut c = Bytes::from_array(Array::make(16, b'\x00')[:])
  for i in 0..<num_blocks {
    let offset = i * 16
    let is_last = i == num_blocks - 1
    let block = if is_last {
      if last_is_full {
        let arr = Array::make(16, b'\x00')
        for j in 0..<16 {
          arr[j] = data[offset + j]
        }
        xor_bytes(Bytes::from_array(arr[:]), k1)
      } else {
        // pad: copy remaining bytes, append 0x80, then zeros.
        let arr = Array::make(16, b'\x00')
        let rem = len - offset
        for j in 0..<rem {
          arr[j] = data[offset + j]
        }
        arr[rem] = b'\x80'
        xor_bytes(Bytes::from_array(arr[:]), k2)
      }
    } else {
      let arr = Array::make(16, b'\x00')
      for j in 0..<16 {
        arr[j] = data[offset + j]
      }
      Bytes::from_array(arr[:])
    }
    let xored = xor_bytes(c, block)
    c = encrypt_block(xored, round_keys, nr)
  }
  c
}
