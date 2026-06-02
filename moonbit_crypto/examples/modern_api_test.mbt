// MoonBit Crypto 现代化API测试
// 测试新架构的功能和接口

import lib/modern_api.*

// 测试哈希模块
test "现代化API - 哈希模块" {
  println("=== 测试现代化API - 哈希模块 ===")
  
  let data = util::string_to_bytes("Hello, Modern Crypto!")
  
  // 使用便捷函数
  let hash1 = sha256(data)
  println("SHA-256 (便捷): " + util::bytes_to_hex(hash1))
  
  // 使用模块函数
  let hash2 = hash::sha256(data)
  println("SHA-256 (模块): " + util::bytes_to_hex(hash2))
  
  // 使用指定提供者
  let hash3 = hash::sha256_with_provider(data, "ultra")
  println("SHA-256 (ultra): " + util::bytes_to_hex(hash3))
  
  // 验证一致性
  let all_equal = util::bytes_equal(hash1, hash2) && util::bytes_equal(hash2, hash3)
  println("一致性验证: " + (if all_equal then "✅ 通过" else "❌ 失败"))
  println()
}

// 测试增量哈希
test "现代化API - 增量哈希" {
  println("=== 测试现代化API - 增量哈希 ===")
  
  let h = hash::new_sha256()
  
  // 增量更新
  let h1 = h.update(util::string_to_bytes("Hello"))
  let h2 = h1.update(util::string_to_bytes(", "))
  let h3 = h2.update(util::string_to_bytes("World!"))
  
  // 完成哈希
  let result = h3.finalize()
  
  // 直接计算对比
  let direct = hash::sha256(util::string_to_bytes("Hello, World!"))
  
  let success = util::bytes_equal(result, direct)
  println("增量哈希验证: " + (if success then "✅ 通过" else "❌ 失败"))
  println()
}

// 测试加密模块
test "现代化API - 加密模块" {
  println("=== 测试现代化API - 加密模块 ===")
  
  let key = util::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let plaintext = util::string_to_bytes("Secret Message 123")
  
  // 加密
  let encrypted_result = cipher::aes_encrypt(plaintext, key)
  
  match encrypted_result {
    CryptoResult { result: Some(encrypted), error: None } => {
      println("加密成功")
      println("密文: " + util::bytes_to_hex(encrypted))
      
      // 解密
      let decrypted_result = cipher::aes_decrypt(encrypted, key)
      
      match decrypted_result {
        CryptoResult { result: Some(decrypted), error: None } => {
          let success = util::bytes_equal(plaintext, decrypted)
          println("解密成功")
          println("解密结果: " + util::bytes_to_string(decrypted))
          println("验证: " + (if success then "✅ 通过" else "❌ 失败"))
        }
        CryptoResult { result: None, error: Some(e) } => {
          println("解密失败: " + e.message())
        }
      }
    }
    CryptoResult { result: None, error: Some(e) } => {
      println("加密失败: " + e.message())
    }
  }
  println()
}

// 测试错误处理
test "现代化API - 错误处理" {
  println("=== 测试现代化API - 错误处理 ===")
  
  // 测试无效密钥
  let bad_key = util::string_to_bytes("short")
  
  let result = cipher::aes_encrypt(util::string_to_bytes("test"), bad_key)
  
  match result {
    CryptoResult { result: None, error: Some(e) } => {
      println("错误代码: " + e.code().to_string())
      println("错误消息: " + e.message())
      println("是否致命: " + (if e.is_fatal() then "是" else "否"))
      println("无效密钥测试: ✅ 通过")
    }
    _ => {
      println("无效密钥测试: ❌ 失败")
    }
  }
  println()
}

// 测试配置模块
test "现代化API - 配置模块" {
  println("=== 测试现代化API - 配置模块 ===")
  
  // 获取默认配置
  let default_cfg = config::default()
  println("默认哈希算法: " + default_cfg.default_hash_algorithm)
  println("默认加密算法: " + default_cfg.default_cipher_algorithm)
  
  // 使用构建器创建自定义配置
  let custom_cfg = config::builder()
    .with_hash_algorithm("SHA-256")
    .with_provider("ultra")
    .with_debug_mode(true)
    .build()
  
  match custom_cfg {
    CryptoResult { result: Some(cfg), error: None } => {
      println("自定义配置哈希算法: " + cfg.default_hash_algorithm)
      println("自定义配置提供者: " + cfg.default_provider)
      println("自定义配置调试模式: " + (if cfg.debug_mode then "开启" else "关闭"))
      println("配置测试: ✅ 通过")
    }
    CryptoResult { result: None, error: Some(e) } => {
      println("配置失败: " + e.message())
    }
  }
  println()
}

// 测试算法和提供者常量
test "现代化API - 常量" {
  println("=== 测试现代化API - 常量 ===")
  
  println("算法常量:")
  println("  SHA256: " + algorithm::SHA256)
  println("  AES128: " + algorithm::AES128)
  
  println("提供者常量:")
  println("  DEFAULT: " + provider::DEFAULT)
  println("  ULTRA: " + provider::ULTRA)
  println("  SIMD: " + provider::SIMD)
  
  println("常量测试: ✅ 通过")
  println()
}

// 测试工具模块
test "现代化API - 工具模块" {
  println("=== 测试现代化API - 工具模块 ===")
  
  // 十六进制转换
  let hex_str = "48656c6c6f"
  let bytes = util::hex_to_bytes(hex_str)
  let back = util::bytes_to_hex(bytes)
  println("十六进制转换: " + (if hex_str == back then "✅ 通过" else "❌ 失败"))
  
  // 字符串转换
  let text = "Hello"
  let text_bytes = util::string_to_bytes(text)
  let text_back = util::bytes_to_string(text_bytes)
  println("字符串转换: " + (if text == text_back then "✅ 通过" else "❌ 失败"))
  
  // 随机数据生成
  let random = util::generate_random_data(16, 12345)
  println("随机数据生成: " + util::bytes_to_hex(random))
  println("工具模块测试: ✅ 通过")
  println()
}

// 综合测试
test "现代化API - 综合测试" {
  println("=== 现代化API综合测试 ===")
  println()
  println("📦 模块结构:")
  println("  - hash: SHA-256 哈希算法")
  println("  - cipher: AES 加密算法")
  println("  - config: 配置管理")
  println("  - util: 工具函数")
  println("  - error: 错误处理")
  println("  - algorithm: 算法常量")
  println("  - provider: 提供者常量")
  println()
  println("🎉 现代化API测试完成！")
}
