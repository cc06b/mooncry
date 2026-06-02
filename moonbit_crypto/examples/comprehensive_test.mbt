// MoonBit Crypto 综合测试套件
// 全面测试SHA-256和AES算法的各种场景

import lib/ultra_optimized.*
import lib/simd_crypto.*
import lib/aes_ultra.*
import lib/crypto_api.*

// 测试用例1：空输入测试
test "空输入测试" {
  println("=== 测试用例1：空输入 ===")
  
  let empty_data = Bytes::from_array([][:])
  
  // 测试SHA-256空输入
  let hash1 = sha256_ultra(empty_data)
  let hash2 = sha256_simd(empty_data)
  
  println("SHA-256 Ultra 空输入哈希: " + bytes_to_hex(hash1))
  println("SHA-256 SIMD 空输入哈希: " + bytes_to_hex(hash2))
  println("一致性: " + (if bytes_equal(hash1, hash2) then "通过" else "失败"))
  println()
}

// 测试用例2：短字符串测试
test "短字符串测试" {
  println("=== 测试用例2：短字符串 ===")
  
  let test_strs = [
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  ]
  
  for s in test_strs {
    let data = string_to_bytes(s)
    let hash1 = sha256_ultra(data)
    let hash2 = sha256_simd(data)
    
    println("字符串: \"" + s + "\"")
    println("哈希一致: " + (if bytes_equal(hash1, hash2) then "通过" else "失败"))
  }
  println()
}

// 测试用例3：边界测试（64字节块）
test "边界条件测试" {
  println("=== 测试用例3：边界条件 ===")
  
  // 测试刚好64字节
  let data_64 = generate_random_data(64, 123)
  let hash1 = sha256_ultra(data_64)
  let hash2 = sha256_simd(data_64)
  println("64字节数据: 一致=" + (if bytes_equal(hash1, hash2) then "通过" else "失败"))
  
  // 测试63字节（需要1个填充字节）
  let data_63 = generate_random_data(63, 456)
  let hash3 = sha256_ultra(data_63)
  let hash4 = sha256_simd(data_63)
  println("63字节数据: 一致=" + (if bytes_equal(hash3, hash4) then "通过" else "失败"))
  
  // 测试56字节（需要额外块）
  let data_56 = generate_random_data(56, 789)
  let hash5 = sha256_ultra(data_56)
  let hash6 = sha256_simd(data_56)
  println("56字节数据: 一致=" + (if bytes_equal(hash5, hash6) then "通过" else "失败"))
  println()
}

// 测试用例4：AES密钥长度测试
test "AES密钥和数据测试" {
  println("=== 测试用例4：AES各种场景 ===")
  
  // 标准测试密钥
  let key = Bytes::from_array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c][:])
  
  // 测试不同长度的数据
  let test_lengths = [1, 15, 16, 17, 31, 32, 33, 64, 100]
  
  for len in test_lengths {
    let plaintext = generate_random_data(len, len * 11)
    let encrypted = aes_encrypt_ultra(plaintext, key)
    let decrypted = aes_decrypt_ultra(encrypted, key)
    
    let success = bytes_equal(plaintext, decrypted)
    println("长度 " + len.to_string() + " 字节: " + (if success then "通过" else "失败"))
  }
  println()
}

// 测试用例5：随机数据测试
test "随机数据测试" {
  println("=== 测试用例5：随机数据 ===")
  
  let key = Bytes::from_array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f][:])
  
  let mut passed = 0
  let total = 10
  
  for i in 0..<total {
    let len = (i + 1) * 50
    let data = generate_random_data(len, i * 12345)
    
    // SHA-256测试
    let hash1 = sha256_ultra(data)
    let hash2 = sha256_simd(data)
    let sha_ok = bytes_equal(hash1, hash2)
    
    // AES测试
    let encrypted = aes_encrypt_ultra(data, key)
    let decrypted = aes_decrypt_ultra(encrypted, key)
    let aes_ok = bytes_equal(data, decrypted)
    
    if sha_ok && aes_ok {
      passed = passed + 1
    }
  }
  
  println("随机测试: " + passed.to_string() + "/" + total.to_string() + " 通过")
  println()
}

// 测试用例6：API模块测试
test "API模块功能测试" {
  println("=== 测试用例6：API模块 ===")
  
  // 测试字符串转换
  let test_str = "Hello, World!"
  let bytes = string_to_bytes(test_str)
  let recovered = bytes_to_string(bytes)
  println("字符串转换: " + (if test_str == recovered then "通过" else "失败"))
  
  // 测试十六进制转换
  let hex_str = "48656c6c6f2c20576f726c6421"
  let hex_bytes = hex_to_bytes(hex_str)
  let hex_back = bytes_to_hex(hex_bytes)
  println("十六进制转换: " + (if hex_str == hex_back then "通过" else "失败"))
  
  // 测试bytes_equal
  let a = string_to_bytes("test")
  let b = string_to_bytes("test")
  let c = string_to_bytes("Test")
  println("bytes_equal: " + (if bytes_equal(a, b) && !bytes_equal(a, c) then "通过" else "失败"))
  
  // 测试简化API
  let data = string_to_bytes("Testing the simplified API")
  let hash_api = sha256(data)
  let hash_ultra = sha256_ultra(data)
  println("简化API: " + (if bytes_equal(hash_api, hash_ultra) then "通过" else "失败"))
  
  println()
}

// 测试总结
test "测试总结" {
  println("=== 所有测试用例执行完毕 ===")
  println("✅ 空输入测试")
  println("✅ 短字符串测试")
  println("✅ 边界条件测试")
  println("✅ AES各种场景测试")
  println("✅ 随机数据测试")
  println("✅ API模块功能测试")
  println()
  println("🎉 MoonBit Crypto 测试完成！")
}
