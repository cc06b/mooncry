// MoonBit Crypto 核心接口定义
// 现代化架构 - 基于接口的设计模式

// 哈希算法接口
pub trait HashAlgorithm {
  // 获取算法名称
  pub fn name(self) -> String
  
  // 获取输出长度（字节）
  pub fn output_length(self) -> Int
  
  // 计算哈希值
  pub fn hash(self, data: Bytes) -> Bytes
  
  // 增量哈希更新
  pub fn update(self, data: Bytes) -> Self
  
  // 完成增量哈希并获取结果
  pub fn finalize(self) -> Bytes
}

// 对称加密算法接口
pub trait SymmetricCipher {
  // 获取算法名称
  pub fn name(self) -> String
  
  // 获取密钥长度（字节）
  pub fn key_length(self) -> Int
  
  // 获取块大小（字节）
  pub fn block_size(self) -> Int
  
  // 加密数据
  pub fn encrypt(self, plaintext: Bytes, key: Bytes) -> Bytes
  
  // 解密数据
  pub fn decrypt(self, ciphertext: Bytes, key: Bytes) -> Bytes
}

// 消息认证码接口
pub trait MACAlgorithm {
  // 获取算法名称
  pub fn name(self) -> String
  
  // 获取输出长度
  pub fn output_length(self) -> Int
  
  // 计算 MAC
  pub fn compute(self, data: Bytes, key: Bytes) -> Bytes
  
  // 验证 MAC
  pub fn verify(self, data: Bytes, key: Bytes, mac: Bytes) -> Bool
}

// 密钥派生接口
pub trait KeyDerivation {
  // 获取算法名称
  pub fn name(self) -> String
  
  // 派生密钥
  pub fn derive(self, password: Bytes, salt: Bytes, iterations: Int, length: Int) -> Bytes
}

// 随机数生成器接口
pub trait RandomGenerator {
  // 生成随机字节
  pub fn generate(self, length: Int) -> Bytes
  
  // 生成范围内的随机整数
  pub fn generate_range(self, min: Int, max: Int) -> Int
  
  // 重新播种
  pub fn reseed(self, seed: Bytes) -> Self
}

// 加密上下文（用于保持状态）
pub struct CryptoContext {
  hash_algorithm: String,
  cipher_algorithm: String,
  provider: String,
}

// 算法参数配置
pub struct AlgorithmParams {
  hash_name: String,
  cipher_name: String,
  key_size: Int,
  block_size: Int,
  padding: String,
  mode: String,
}

// 算法标识常量
pub struct AlgorithmID {
  // SHA 系列
  pub static SHA256: String = "SHA-256"
  pub static SHA384: String = "SHA-384"
  pub static SHA512: String = "SHA-512"
  
  // AES 系列
  pub static AES128: String = "AES-128"
  pub static AES192: String = "AES-192"
  pub static AES256: String = "AES-256"
  
  // HMAC 系列
  pub static HMAC_SHA256: String = "HMAC-SHA256"
  
  // PBKDF2
  pub static PBKDF2: String = "PBKDF2"
}

// 加密结果包装
pub struct CryptoResult<T> {
  result: Option[T],
  error: Option[CryptoError],
}

// 算法提供者类型
pub type ProviderType = String

// 提供者标识
pub struct ProviderID {
  pub static DEFAULT: String = "default"
  pub static ULTRA: String = "ultra"
  pub static SIMD: String = "simd"
  pub static FALLBACK: String = "fallback"
}
