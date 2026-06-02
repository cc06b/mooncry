// AES 算法提供者
// 现代化架构 - 基于接口的实现

import crypto_interface.*
import crypto_error.*
import crypto_config.*
import aes_ultra.*

// AES 算法实现
pub struct AES {
  key: Bytes,
  key_size: Int,
  rounds: Int,
  provider: String,
}

// AES 静态工厂方法
impl AES {
  // 创建新实例（使用默认提供者）
  pub fn new(key: Bytes) -> CryptoResult[AES] {
    AES::with_provider(key, GlobalConfig::get().default_provider)
  }
  
  // 使用指定提供者创建实例
  pub fn with_provider(key: Bytes, provider: String) -> CryptoResult[AES] {
    let len = key.length()
    
    if len != 16 {
      return CryptoResult::err(InvalidKeyLength(len, 16))
    }
    
    CryptoResult::ok(AES {
      key: key,
      key_size: len,
      rounds: 10,
      provider: provider,
    })
  }
  
  // 获取支持的提供者列表
  pub fn supported_providers() -> Array[String] {
    ["ultra", "default"]
  }
  
  // 获取轮数
  pub fn get_rounds(self) -> Int {
    self.rounds
  }
}

// 实现 SymmetricCipher 接口
impl SymmetricCipher for AES {
  pub fn name(self) -> String {
    "AES-128"
  }
  
  pub fn key_length(self) -> Int {
    16
  }
  
  pub fn block_size(self) -> Int {
    16
  }
  
  pub fn encrypt(self, plaintext: Bytes, key: Bytes) -> Bytes {
    match self.provider {
      "ultra" => aes_encrypt_ultra(plaintext, key),
      _ => aes_encrypt_ultra(plaintext, key),
    }
  }
  
  pub fn decrypt(self, ciphertext: Bytes, key: Bytes) -> Bytes {
    match self.provider {
      "ultra" => aes_decrypt_ultra(ciphertext, key),
      _ => aes_decrypt_ultra(ciphertext, key),
    }
  }
}

// AES 便捷函数
pub fn aes_encrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
  match AES::new(key) {
    CryptoResult { result: Some(aes), error: None } => {
      CryptoResult::ok(aes.encrypt(data, key))
    }
    CryptoResult { result: None, error: Some(e) } => {
      CryptoResult::err(e)
    }
  }
}

pub fn aes_decrypt(data: Bytes, key: Bytes) -> CryptoResult[Bytes] {
  match AES::new(key) {
    CryptoResult { result: Some(aes), error: None } => {
      CryptoResult::ok(aes.decrypt(data, key))
    }
    CryptoResult { result: None, error: Some(e) } => {
      CryptoResult::err(e)
    }
  }
}

pub fn aes_encrypt_with_provider(data: Bytes, key: Bytes, provider: String) -> CryptoResult[Bytes] {
  match AES::with_provider(key, provider) {
    CryptoResult { result: Some(aes), error: None } => {
      CryptoResult::ok(aes.encrypt(data, key))
    }
    CryptoResult { result: None, error: Some(e) } => {
      CryptoResult::err(e)
    }
  }
}

pub fn aes_decrypt_with_provider(data: Bytes, key: Bytes, provider: String) -> CryptoResult[Bytes] {
  match AES::with_provider(key, provider) {
    CryptoResult { result: Some(aes), error: None } => {
      CryptoResult::ok(aes.decrypt(data, key))
    }
    CryptoResult { result: None, error: Some(e) } => {
      CryptoResult::err(e)
    }
  }
}
