// MoonBit Crypto 性能基准测试
// 用于测试和比较不同加密算法实现的性能

import lib/ultra_optimized.*
import lib/simd_crypto.*
import lib/aes_ultra.*

// 测试数据生成
fn generate_test_data(size: Int) -> Bytes {
  let arr = Array::make(size, b'A')
  Bytes::from_array(arr[:])
}

// SHA-256 性能测试
test "SHA-256 Ultra 性能测试" {
  let data = generate_test_data(1024)
  let iterations = 1000
  
  println("=== SHA-256 Ultra 性能测试 ===")
  println("测试数据大小: " + data.length().to_string() + " bytes")
  println("迭代次数: " + iterations.to_string())
  
  // 预热
  let _ = sha256_ultra(data)
  
  // 测试
  let hash = sha256_ultra(data)
  println("哈希结果 (前16字节): " + bytes_to_hex_test(hash).substring(0, 32))
  println()
}

// SHA-256 SIMD 性能测试
test "SHA-256 SIMD 性能测试" {
  let data = generate_test_data(1024)
  
  println("=== SHA-256 SIMD 性能测试 ===")
  println("测试数据大小: " + data.length().to_string() + " bytes")
  
  // 预热
  let _ = sha256_simd(data)
  
  // 测试
  let hash = sha256_simd(data)
  println("哈希结果 (前16字节): " + bytes_to_hex_test(hash).substring(0, 32))
  println()
}

// AES 性能测试
test "AES-128 性能测试" {
  let key = Bytes::from_array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c][:])
  let plaintext = generate_test_data(256)
  
  println("=== AES-128 性能测试 ===")
  println("明文大小: " + plaintext.length().to_string() + " bytes")
  
  // 预热
  let _ = aes_encrypt_ultra(plaintext, key)
  
  // 加密测试
  let encrypted = aes_encrypt_ultra(plaintext, key)
  println("加密后大小: " + encrypted.length().to_string() + " bytes")
  
  // 解密测试
  let decrypted = aes_decrypt_ultra(encrypted, key)
  println("解密后大小: " + decrypted.length().to_string() + " bytes")
  println()
}

// 综合测试
test "综合功能验证" {
  println("=== 综合功能验证 ===")
  
  // 测试SHA-256一致性
  let test_str = Bytes::from_string("Hello, MoonBit Crypto!")
  let hash1 = sha256_ultra(test_str)
  let hash2 = sha256_simd(test_str)
  
  let hash1_hex = bytes_to_hex_test(hash1)
  let hash2_hex = bytes_to_hex_test(hash2)
  
  println("SHA-256一致性检查: " + (if hash1_hex == hash2_hex then "通过" else "失败"))
  
  // 测试AES加解密一致性
  let key = Bytes::from_array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c][:])
  let test_data = Bytes::from_string("This is a test message for AES encryption!")
  
  let encrypted = aes_encrypt_ultra(test_data, key)
  let decrypted = aes_decrypt_ultra(encrypted, key)
  
  let decrypted_str = bytes_to_string_test(decrypted)
  let original_str = bytes_to_string_test(test_data)
  
  println("AES加解密一致性检查: " + (if decrypted_str == original_str then "通过" else "失败"))
  println()
}

fn bytes_to_hex_test(data: Bytes) -> String {
  let len = data.length()
  let hex_chars = "0123456789abcdef"
  let mut result = ""
  for i in 0..<len {
    let byte = data[i].to_int()
    let hi = (byte >> 4) & 0x0F
    let lo = byte & 0x0F
    result = result + hex_chars[hi].to_string() + hex_chars[lo].to_string()
  }
  result
}

fn bytes_to_string_test(data: Bytes) -> String {
  let len = data.length()
  let mut result = ""
  for i in 0..<len {
    result = result + data[i].to_char().to_string()
  }
  result
}
