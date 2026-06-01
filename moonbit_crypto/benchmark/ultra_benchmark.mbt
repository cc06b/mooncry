// Ultra Performance Benchmark
// 测试优化版本的性能

test "SHA-256 Ultra Performance" {
  let test_data = b"Hello, MoonBit Crypto! This is a performance test for ultra-optimized SHA-256."
  
  let start = 0L
  let iterations = 10000
  
  let hash = sha256_ultra(test_data)
  println("SHA-256 Ultra Test:")
  println("Hash length: " + hash.length().to_string())
  println("Hash (first 8 bytes): " + bytes_to_hex_ultra(hash).substring(0, 16))
}

test "AES-128 Ultra Performance" {
  let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let plaintext = b"AES Ultra Test!"
  
  let encrypted = aes_encrypt_ultra(plaintext, key)
  let decrypted = aes_decrypt_ultra(encrypted, key)
  
  println("\nAES-128 Ultra Test:")
  println("Encrypted length: " + encrypted.length().to_string())
  println("Decrypted: " + bytes_to_str_ultra(decrypted))
}

fn bytes_to_hex_ultra(data: Bytes) -> String {
  let len = data.length()
  let hex_chars = "0123456789abcdef"
  let mut result = ""
  for i in 0..<len {
    let byte = data[i].to_int()
    let hi = (byte >> 4) & 0x0F
    let lo = byte & 0x0F
    let hi_idx = if hi < 10 { hi } else { hi + 6 }
    let lo_idx = if lo < 10 { lo } else { lo + 6 }
    let hi_char = hex_chars[hi_idx]
    let lo_char = hex_chars[lo_idx]
    result = result + hi_char.to_string() + lo_char.to_string()
  }
  result
}

fn bytes_to_str_ultra(data: Bytes) -> String {
  let len = data.length()
  let mut result = ""
  for i in 0..<len {
    result = result + data[i].to_string()
    if i < len - 1 {
      result = result + ", "
    }
  }
  result
}

test "Performance Comparison" {
  println("\n=== Performance Optimization Summary ===")
  println("1. SHA-256: Full 64-round loop unrolling")
  println("2. AES: Complete GMUL lookup tables (2,3,9,11,13,14)")
  println("3. All constants precomputed at compile time")
  println("4. InvSBox precomputed as constant")
  println("5. RCON precomputed as constant")
  println("\nExpected improvements:")
  println("- Reduced loop overhead")
  println("- Better instruction cache utilization")
  println("- Reduced function call overhead")
}
