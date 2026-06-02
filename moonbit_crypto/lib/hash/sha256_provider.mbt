// SHA-256 算法提供者
// 现代化架构 - 基于接口的实现

import crypto_interface.*
import crypto_error.*
import crypto_config.*
import ultra_optimized.*
import simd_crypto.*

// SHA-256 算法实现
pub struct SHA256 {
  state: Array[UInt32],
  buffer: Array[UInt8],
  buffer_len: Int,
  total_len: UInt64,
  provider: String,
}

// SHA-256 静态工厂方法
impl SHA256 {
  // 创建新实例（使用默认提供者）
  pub fn new() -> SHA256 {
    SHA256::with_provider(GlobalConfig::get().default_provider)
  }
  
  // 使用指定提供者创建实例
  pub fn with_provider(provider: String) -> SHA256 {
    SHA256 {
      state: Array::make(8, 0U),
      buffer: Array::make(64, 0U8),
      buffer_len: 0,
      total_len: 0U64,
      provider: provider,
    }
  }
  
  // 重置状态
  pub fn reset(self) -> SHA256 {
    SHA256 {
      state: Array::make(8, 0U),
      buffer: Array::make(64, 0U8),
      buffer_len: 0,
      total_len: 0U64,
      provider: self.provider,
    }
  }
  
  // 获取支持的提供者列表
  pub fn supported_providers() -> Array[String] {
    ["ultra", "simd", "default"]
  }
}

// 实现 HashAlgorithm 接口
impl HashAlgorithm for SHA256 {
  pub fn name(self) -> String {
    "SHA-256"
  }
  
  pub fn output_length(self) -> Int {
    32
  }
  
  pub fn hash(self, data: Bytes) -> Bytes {
    let hash = match self.provider {
      "ultra" => sha256_ultra(data),
      "simd" => sha256_simd(data),
      _ => sha256_ultra(data),
    }
    hash
  }
  
  pub fn update(self, data: Bytes) -> SHA256 {
    let len = data.length()
    let mut new_total_len = self.total_len + len.to_uint64()
    let mut new_buffer_len = self.buffer_len
    let mut new_buffer = self.buffer[:]
    let mut new_state = self.state[:]
    
    let mut data_pos = 0
    let remaining = 64 - self.buffer_len
    
    if self.buffer_len > 0 && len >= remaining {
      for i in 0..<remaining {
        new_buffer[self.buffer_len + i] = data[i].to_uint8()
      }
      new_buffer_len = 64
      data_pos = remaining
      
      new_state = SHA256::process_block(new_buffer, new_state)
      new_buffer_len = 0
    }
    
    while data_pos + 64 <= len {
      let block = Array::make(64, 0U8)
      for i in 0..<64 {
        block[i] = data[data_pos + i].to_uint8()
      }
      new_state = SHA256::process_block(block, new_state)
      data_pos = data_pos + 64
    }
    
    while data_pos < len {
      new_buffer[new_buffer_len] = data[data_pos].to_uint8()
      new_buffer_len = new_buffer_len + 1
      data_pos = data_pos + 1
    }
    
    SHA256 {
      state: new_state,
      buffer: new_buffer,
      buffer_len: new_buffer_len,
      total_len: new_total_len,
      provider: self.provider,
    }
  }
  
  pub fn finalize(self) -> Bytes {
    let mut final_buffer = self.buffer[:]
    let mut final_state = self.state[:]
    
    final_buffer[self.buffer_len] = 0x80U8
    
    if self.buffer_len >= 56 {
      for i in (self.buffer_len + 1)..<64 {
        final_buffer[i] = 0U8
      }
      final_state = SHA256::process_block(final_buffer, final_state)
      final_buffer = Array::make(64, 0U8)
    }
    
    for i in (self.buffer_len + 1)..<56 {
      final_buffer[i] = 0U8
    }
    
    let bit_len = self.total_len * 8
    for i in 0..<8 {
      final_buffer[56 + i] = ((bit_len >> ((7 - i) * 8)) & 0xFF).to_uint8()
    }
    
    final_state = SHA256::process_block(final_buffer, final_state)
    
    let result = Array::make(32, 0U8)
    for i in 0..<8 {
      let word = final_state[i]
      result[i * 4] = ((word >> 24) & 0xFF).to_uint8()
      result[i * 4 + 1] = ((word >> 16) & 0xFF).to_uint8()
      result[i * 4 + 2] = ((word >> 8) & 0xFF).to_uint8()
      result[i * 4 + 3] = (word & 0xFF).to_uint8()
    }
    
    Bytes::from_array(result[:])
  }
}

// SHA-256 内部实现
impl SHA256 {
  // 处理单个块
  fn process_block(block: Array[UInt8], state: Array[UInt32]) -> Array[UInt32] {
    let mut w = Array::make(64, 0U)
    
    for i in 0..<16 {
      w[i] = 
        (block[i * 4].to_uint32() << 24) |
        (block[i * 4 + 1].to_uint32() << 16) |
        (block[i * 4 + 2].to_uint32() << 8) |
        block[i * 4 + 3].to_uint32()
    }
    
    for i in 16..<64 {
      let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3)
      let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }
    
    let mut a = state[0]
    let mut b = state[1]
    let mut c = state[2]
    let mut d = state[3]
    let mut e = state[4]
    let mut f = state[5]
    let mut g = state[6]
    let mut h = state[7]
    
    let k = SHA256::get_constants()
    
    for i in 0..<64 {
      let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
      let ch = (e & f) ^ ((!e) & g)
      let temp1 = h + s1 + ch + k[i] + w[i]
      let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let temp2 = s0 + maj
      
      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
    }
    
    [
      state[0] + a,
      state[1] + b,
      state[2] + c,
      state[3] + d,
      state[4] + e,
      state[5] + f,
      state[6] + g,
      state[7] + h,
    ]
  }
  
  // 获取常量
  fn get_constants() -> Array[UInt32] {
    [
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
      0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
      0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
      0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
      0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
      0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
      0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    ]
  }
}

// SHA-256 便捷函数
pub fn sha256(data: Bytes) -> Bytes {
  SHA256::new().hash(data)
}

pub fn sha256_with_provider(data: Bytes, provider: String) -> Bytes {
  SHA256::with_provider(provider).hash(data)
}
