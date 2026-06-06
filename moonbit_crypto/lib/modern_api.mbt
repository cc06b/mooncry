// MoonBit Crypto 现代化API入口
// 提供简洁、类型安全的加密库接口

import crypto_interface.*
import crypto_error.*
import crypto_config.*
import provider.provider_manager.*
import hash.sha256_provider.*
import cipher.aes_provider.*
import crypto_api.*
import sha256_mega.*

// 哈希模块
pub module hash {
  // 计算SHA-256哈希
  pub fn sha256(data: Bytes) -> Bytes {
    SHA256::new().hash(data)
  }
  
  // 计算SHA-256哈希（指定提供者）
  pub fn sha256_with_provider(data: Bytes, provider: String) -> Bytes {
    SHA256::with_provider(provider).hash(data)
  }
  
  // 创建SHA-256增量哈希器
  pub fn new_sha256() -> SHA256 {
    SHA256::new()
  }
  
  // 创建SHA-256增量哈希器（指定提供者）
  pub fn new_sha256_with_provider(provider: String) -> SHA256 {
    SHA256::with_provider(provider)
  }
  
  // 获取支持的哈希算法列表
  pub fn supported_algorithms() -> Array[String] {
    ProviderManager::list_hash_algorithms()
  }
}

// 加密模块
pub module cipher {
  // AES加密
  pub fn aes_encrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
    aes_provider::aes_encrypt(data, key)
  }
  
  // AES解密
  pub fn aes_decrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
    aes_provider::aes_decrypt(data, key)
  }
  
  // AES加密（指定提供者）
  pub fn aes_encrypt_with_provider(data: Bytes, key: Bytes, provider: String) -> CryptoResult[Bytes] {
    aes_provider::aes_encrypt_with_provider(data, key, provider)
  }
  
  // AES解密（指定提供者）
  pub fn aes_decrypt_with_provider(data: Bytes, key: Bytes, provider: String) -> CryptoResult[Bytes] {
    aes_provider::aes_decrypt_with_provider(data, key, provider)
  }
  
  // 创建AES实例
  pub fn new_aes(key: Bytes) -> CryptoResult[AES] {
    AES::new(key)
  }
  
  // 获取支持的加密算法列表
  pub fn supported_algorithms() -> Array[String] {
    ["AES-128"]
  }
}

// 配置模块
pub module config {
  // 获取默认配置
  pub fn default() -> CryptoConfig {
    default_config()
  }
  
  // 创建配置构建器
  pub fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
  }
  
  // 获取全局配置
  pub fn global() -> CryptoConfig {
    GlobalConfig::get()
  }
  
  // 设置全局配置
  pub fn set_global(config: CryptoConfig) {
    GlobalConfig::set(config)
  }
  
  // 重置全局配置
  pub fn reset_global() {
    GlobalConfig::reset()
  }
  
  // 获取算法配置
  pub fn get_algorithm_config(name: String) -> CryptoResult[AlgorithmConfig] {
    crypto_config::get_algorithm_config(name)
  }
}

// 工具模块
pub module util {
  // 十六进制转Bytes
  pub fn hex_to_bytes(hex: String) -> Bytes {
    crypto_api::hex_to_bytes(hex)
  }
  
  // Bytes转十六进制
  pub fn bytes_to_hex(data: Bytes) -> String {
    crypto_api::bytes_to_hex(data)
  }
  
  // 字符串转Bytes
  pub fn string_to_bytes(s: String) -> Bytes {
    crypto_api::string_to_bytes(s)
  }
  
  // Bytes转字符串
  pub fn bytes_to_string(data: Bytes) -> String {
    crypto_api::bytes_to_string(data)
  }
  
  // 比较两个Bytes是否相等
  pub fn bytes_equal(a: Bytes, b: Bytes) -> Bool {
    crypto_api::bytes_equal(a, b)
  }
  
  // 生成随机测试数据
  pub fn generate_random_data(size: Int, seed: Int) -> Bytes {
    crypto_api::generate_random_data(size, seed)
  }
}

// 错误处理模块
pub module error {
  // 创建成功结果
  pub fn ok[T](value: T) -> CryptoResult[T] {
    CryptoResult::ok(value)
  }
  
  // 创建错误结果
  pub fn err[T](error: CryptoError) -> CryptoResult[T] {
    CryptoResult::err(error)
  }
  
  // 获取错误消息
  pub fn message(error: CryptoError) -> String {
    error.message()
  }
  
  // 获取错误代码
  pub fn code(error: CryptoError) -> Int {
    error.code()
  }
  
  // 判断是否为致命错误
  pub fn is_fatal(error: CryptoError) -> Bool {
    error.is_fatal()
  }
  
  // 验证密钥长度
  pub fn validate_key_length(key: Bytes, expected_length: Int) -> CryptoResult[Bytes] {
    crypto_error::validate_key_length(key, expected_length)
  }
  
  // 验证最小长度
  pub fn validate_min_length(data: Bytes, min_length: Int) -> CryptoResult[Bytes] {
    crypto_error::validate_min_length(data, min_length)
  }
}

// 算法常量
pub module algorithm {
  pub static SHA256: String = "SHA-256"
  pub static AES128: String = "AES-128"
  pub static HMAC_SHA256: String = "HMAC-SHA256"
}

// 提供者常量
pub module provider {
  pub static DEFAULT: String = "default"
  pub static ULTRA: String = "ultra"
  pub static SIMD: String = "simd"
  pub static FALLBACK: String = "fallback"
}

// 便捷函数（保持向后兼容）
pub fn sha256(data: Bytes) -> Bytes {
  hash::sha256(data)
}

pub fn aes_encrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
  cipher::aes_encrypt(data, key)
}

pub fn aes_decrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
  cipher::aes_decrypt(data, key)
}
