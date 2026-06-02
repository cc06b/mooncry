// 算法提供者管理器
// 现代化架构 - 提供者模式实现

import crypto_interface.*
import crypto_error.*
import crypto_config.*
import hash::sha256_provider.*
import cipher::aes_provider.*

// 哈希算法提供者工厂
pub struct HashProviderFactory {
  // 注册的提供者
  providers: Array[(String, fn() -> HashAlgorithm)],
}

// 加密算法提供者工厂
pub struct CipherProviderFactory {
  providers: Array[(String, fn(Bytes) -> SymmetricCipher)],
}

// 全局提供者管理器
pub struct ProviderManager {
  private static hash_factory: HashProviderFactory = HashProviderFactory { providers: [] }
  private static cipher_factory: CipherProviderFactory = CipherProviderFactory { providers: [] }
  private static initialized: Bool = false
  
  // 初始化所有提供者
  pub static fn initialize() {
    if ProviderManager.initialized {
      return
    }
    
    // 注册哈希提供者
    ProviderManager.register_hash_provider("SHA-256", fn() -> HashAlgorithm { SHA256::new() })
    ProviderManager.register_hash_provider("SHA-256-ULTRA", fn() -> HashAlgorithm { SHA256::with_provider("ultra") })
    ProviderManager.register_hash_provider("SHA-256-SIMD", fn() -> HashAlgorithm { SHA256::with_provider("simd") })
    
    // 注册加密提供者
    ProviderManager.initialized = true
  }
  
  // 注册哈希提供者
  pub static fn register_hash_provider(name: String, factory: fn() -> HashAlgorithm) {
    ProviderManager.hash_factory.providers = ProviderManager.hash_factory.providers.append((name, factory))
  }
  
  // 获取哈希提供者
  pub static fn get_hash_provider(name: String) -> CryptoResult[HashAlgorithm] {
    if !ProviderManager.initialized {
      ProviderManager.initialize()
    }
    
    for (provider_name, factory) in ProviderManager.hash_factory.providers {
      if provider_name == name {
        return CryptoResult::ok(factory())
      }
    }
    
    CryptoResult::err(AlgorithmNotSupported(name))
  }
  
  // 获取默认哈希提供者
  pub static fn get_default_hash_provider() -> HashAlgorithm {
    match ProviderManager.get_hash_provider(GlobalConfig::get().default_hash_algorithm) {
      CryptoResult { result: Some(provider), error: None } => provider,
      _ => SHA256::new(),
    }
  }
  
  // 获取所有注册的哈希算法
  pub static fn list_hash_algorithms() -> Array[String] {
    if !ProviderManager.initialized {
      ProviderManager.initialize()
    }
    
    ProviderManager.hash_factory.providers.map(fn((name, _)) => name)
  }
  
  // 创建AES加密器
  pub static fn create_aes(key: Bytes) -> CryptoResult[AES] {
    AES::new(key)
  }
  
  // 创建AES加密器（指定提供者）
  pub static fn create_aes_with_provider(key: Bytes, provider: String) -> CryptoResult[AES] {
    AES::with_provider(key, provider)
  }
  
  // 获取所有支持的提供者
  pub static fn list_providers() -> Array[String] {
    ["default", "ultra", "simd", "fallback"]
  }
}

// 便捷函数
pub fn create_hash(algorithm: String) -> CryptoResult[HashAlgorithm] {
  ProviderManager::get_hash_provider(algorithm)
}

pub fn create_default_hash() -> HashAlgorithm {
  ProviderManager::get_default_hash_provider()
}

pub fn create_cipher(algorithm: String, key: Bytes) -> CryptoResult[SymmetricCipher] {
  match algorithm {
    "AES-128" => {
      match AES::new(key) {
        CryptoResult { result: Some(aes), error: None } => CryptoResult::ok(aes),
        CryptoResult { result: None, error: Some(e) } => CryptoResult::err(e),
      }
    }
    _ => CryptoResult::err(AlgorithmNotSupported(algorithm)),
  }
}
