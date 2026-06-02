// MoonBit Crypto 配置模块
// 现代化配置管理体系

import crypto_error.*

// 全局配置
pub struct CryptoConfig {
  // 默认哈希算法
  default_hash_algorithm: String,
  
  // 默认对称加密算法
  default_cipher_algorithm: String,
  
  // 默认算法提供者
  default_provider: String,
  
  // 是否启用调试模式
  debug_mode: Bool,
  
  // 是否启用性能统计
  enable_performance_stats: Bool,
  
  // 是否启用缓存
  enable_cache: Bool,
  
  // 缓存大小限制（字节）
  cache_size_limit: Int,
  
  // 最大数据处理大小（字节）
  max_data_size: Int,
  
  // 是否验证输入
  validate_input: Bool,
}

// 配置构建器
pub struct ConfigBuilder {
  config: CryptoConfig,
}

// 默认配置
pub fn default_config() -> CryptoConfig {
  CryptoConfig {
    default_hash_algorithm: "SHA-256",
    default_cipher_algorithm: "AES-128",
    default_provider: "ultra",
    debug_mode: false,
    enable_performance_stats: false,
    enable_cache: true,
    cache_size_limit: 1024 * 1024,
    max_data_size: 100 * 1024 * 1024,
    validate_input: true,
  }
}

// 配置构建器实现
impl ConfigBuilder {
  // 创建构建器
  pub fn new() -> ConfigBuilder {
    ConfigBuilder { config: default_config() }
  }
  
  // 设置默认哈希算法
  pub fn with_hash_algorithm(self, name: String) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, default_hash_algorithm: name } }
  }
  
  // 设置默认加密算法
  pub fn with_cipher_algorithm(self, name: String) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, default_cipher_algorithm: name } }
  }
  
  // 设置默认提供者
  pub fn with_provider(self, name: String) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, default_provider: name } }
  }
  
  // 启用调试模式
  pub fn with_debug_mode(self, enabled: Bool) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, debug_mode: enabled } }
  }
  
  // 启用性能统计
  pub fn with_performance_stats(self, enabled: Bool) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, enable_performance_stats: enabled } }
  }
  
  // 启用缓存
  pub fn with_cache(self, enabled: Bool) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, enable_cache: enabled } }
  }
  
  // 设置缓存大小限制
  pub fn with_cache_limit(self, bytes: Int) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, cache_size_limit: bytes } }
  }
  
  // 设置最大数据大小
  pub fn with_max_data_size(self, bytes: Int) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, max_data_size: bytes } }
  }
  
  // 设置输入验证
  pub fn with_input_validation(self, enabled: Bool) -> ConfigBuilder {
    ConfigBuilder { config: { ..self.config, validate_input: enabled } }
  }
  
  // 构建配置
  pub fn build(self) -> CryptoResult[CryptoConfig] {
    // 验证配置
    if self.config.max_data_size < 0 {
      return CryptoResult::err(InvalidArgument("max_data_size 不能为负数"))
    }
    if self.config.cache_size_limit < 0 {
      return CryptoResult::err(InvalidArgument("cache_size_limit 不能为负数"))
    }
    CryptoResult::ok(self.config)
  }
}

// 全局配置实例
pub struct GlobalConfig {
  private static instance: Option[CryptoConfig] = None
  
  // 获取全局配置
  pub static fn get() -> CryptoConfig {
    match GlobalConfig.instance {
      Some(config) => config,
      None => {
        let config = default_config()
        GlobalConfig.instance = Some(config)
        config
      }
    }
  }
  
  // 设置全局配置
  pub static fn set(config: CryptoConfig) {
    GlobalConfig.instance = Some(config)
  }
  
  // 重置为默认配置
  pub static fn reset() {
    GlobalConfig.instance = None
  }
}

// 算法配置
pub struct AlgorithmConfig {
  name: String,
  key_size: Int,
  block_size: Int,
  iv_size: Int,
  output_size: Int,
}

// 获取算法配置
pub fn get_algorithm_config(name: String) -> CryptoResult[AlgorithmConfig] {
  match name {
    "SHA-256" => CryptoResult::ok(AlgorithmConfig {
      name: "SHA-256",
      key_size: 0,
      block_size: 64,
      iv_size: 0,
      output_size: 32,
    }),
    "AES-128" => CryptoResult::ok(AlgorithmConfig {
      name: "AES-128",
      key_size: 16,
      block_size: 16,
      iv_size: 16,
      output_size: 0,
    }),
    _ => CryptoResult::err(AlgorithmNotSupported(name)),
  }
}

// 支持的算法列表
pub fn supported_algorithms() -> Array[String] {
  ["SHA-256", "AES-128"]
}

// 支持的提供者列表
pub fn supported_providers() -> Array[String] {
  ["default", "ultra", "simd", "fallback"]
}
