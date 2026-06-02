// MoonBit Crypto 使用示例
// 演示如何使用加密库的各种功能

import lib/crypto_api.*

// 示例1：基本SHA-256哈希
test "示例1：SHA-256哈希" {
  println("=== 示例1：SHA-256哈希 ===")
  
  let message = string_to_bytes("Hello, MoonBit!")
  
  // 使用简化API
  let hash = sha256(message)
  
  println("原始消息: Hello, MoonBit!")
  println("SHA-256哈希: " + bytes_to_hex(hash))
  println()
}

// 示例2：使用快速版本
test "示例2：SIMD优化版本" {
  println("=== 示例2：SIMD优化版本 ===")
  
  let large_data = generate_random_data(1000, 12345)
  
  let hash_fast = sha256_fast(large_data)
  
  println("1000字节数据的SHA-256 (SIMD): " + bytes_to_hex(hash_fast).substring(0, 32) + "...")
  println()
}

// 示例3：AES加密和解密
test "示例3：AES加密解密" {
  println("=== 示例3：AES加密解密 ===")
  
  // 16字节密钥 (AES-128)
  let key = Bytes::from_array([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  ][:])
  
  let secret_message = string_to_bytes("这是一条秘密消息！")
  
  println("原始消息: " + bytes_to_string(secret_message))
  
  // 加密
  let encrypted = aes_encrypt(secret_message, key)
  println("加密后 (十六进制): " + bytes_to_hex(encrypted))
  
  // 解密
  let decrypted = aes_decrypt(encrypted, key)
  println("解密后: " + bytes_to_string(decrypted))
  
  let success = bytes_equal(secret_message, decrypted)
  println("加密解密成功: " + (if success then "是" else "否"))
  println()
}

// 示例4：文件哈希模拟
test "示例4：数据验证" {
  println("=== 示例4：数据完整性验证 ===")
  
  // 模拟数据传输
  let original_data = string_to_bytes("重要文件内容 - 不要修改！")
  let original_hash = sha256(original_data)
  
  println("原始数据哈希: " + bytes_to_hex(original_hash))
  
  // 模拟传输 - 数据未被篡改
  let received_data_ok = string_to_bytes("重要文件内容 - 不要修改！")
  let received_hash_ok = sha256(received_data_ok)
  println("传输后验证: " + (if bytes_equal(original_hash, received_hash_ok) then "✅ 通过" else "❌ 失败"))
  
  // 模拟传输 - 数据被篡改
  let received_data_bad = string_to_bytes("重要文件内容 - 已被修改！")
  let received_hash_bad = sha256(received_data_bad)
  println("篡改后验证: " + (if bytes_equal(original_hash, received_hash_bad) then "✅ 通过" else "❌ 失败"))
  println()
}

// 示例5：十六进制编码
test "示例5：十六进制编码" {
  println("=== 示例5：编码转换 ===")
  
  let binary_data = Bytes::from_array([0xde, 0xad, 0xbe, 0xef][:])
  
  // 编码为十六进制
  let hex_str = bytes_to_hex(binary_data)
  println("二进制数据 -> 十六进制: " + hex_str)
  
  // 从十六进制解码
  let decoded = hex_to_bytes(hex_str)
  println("十六进制 -> 二进制: " + bytes_to_hex(decoded))
  println()
}

// 示例6：批量处理
test "示例6：批量哈希" {
  println("=== 示例6：批量处理 ===")
  
  let documents = [
    "文档1的内容",
    "文档2的内容",
    "文档3的内容"
  ]
  
  println("批量计算文档哈希:")
  for doc in documents {
    let data = string_to_bytes(doc)
    let hash = sha256(data)
    println("  \"" + doc + "\" -> " + bytes_to_hex(hash).substring(0, 16) + "...")
  }
  println()
}

// 示例7：实用工具函数
test "示例7：工具函数" {
  println("=== 示例7：工具函数 ===")
  
  // 测试字符串转换
  let text = "测试字符串"
  let bytes = string_to_bytes(text)
  let recovered = bytes_to_string(bytes)
  println("字符串转换: " + text + " -> " + recovered)
  
  // 测试比较函数
  let a = string_to_bytes("test1")
  let b = string_to_bytes("test1")
  let c = string_to_bytes("test2")
  println("a == b: " + (if bytes_equal(a, b) then "true" else "false"))
  println("a == c: " + (if bytes_equal(a, c) then "true" else "false"))
  
  // 生成随机数据
  let random_data = generate_random_data(20, 98765)
  println("随机数据 (20字节): " + bytes_to_hex(random_data))
  println()
}

// 主示例
test "使用示例总结" {
  println("=== MoonBit Crypto 使用示例 ===")
  println()
  println("📚 包含的功能:")
  println("   - SHA-256 哈希 (标准和SIMD优化版本)")
  println("   - AES-128 加密/解密")
  println("   - 十六进制编码/解码")
  println("   - 字符串/Bytes转换")
  println("   - 数据比较工具")
  println()
  println("🚀 使用简单，性能优秀！")
}
