// MoonBit Crypto 统一 API 模块
// 提供简洁易用的加密库接口

import ultra_optimized.*
import aes_ultra.*
import simd_crypto.*

// SHA-256 哈希函数（使用 ultra 优化版本）
pub fn sha256(data: Bytes) -> Bytes {
  sha256_ultra(data)
}

// SHA-256 哈希函数（使用 SIMD 优化版本）
pub fn sha256_fast(data: Bytes) -> Bytes {
  sha256_simd(data)
}

// AES-128 加密函数
pub fn aes_encrypt(data: Bytes, key: Bytes) -> Bytes {
  aes_encrypt_ultra(data, key)
}

// AES-128 解密函数
pub fn aes_decrypt(data: Bytes, key: Bytes) -> Bytes {
  aes_decrypt_ultra(data, key)
}

// 十六进制字符串转换为 Bytes
pub fn hex_to_bytes(hex: String) -> Bytes {
  let len = hex.length()
  let arr = Array::make(len / 2, b'\x00')
  for i in 0..<(len / 2) {
    let hi = hex_char_to_int(hex[i * 2])
    let lo = hex_char_to_int(hex[i * 2 + 1])
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(arr[:])
}

// Bytes 转换为十六进制字符串
pub fn bytes_to_hex(data: Bytes) -> String {
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

fn hex_char_to_int(c: Char) -> Int {
  let code = c.to_int()
  if code >= '0'.to_int() && code <= '9'.to_int() {
    return code - '0'.to_int()
  }
  if code >= 'a'.to_int() && code <= 'f'.to_int() {
    return code - 'a'.to_int() + 10
  }
  if code >= 'A'.to_int() && code <= 'F'.to_int() {
    return code - 'A'.to_int() + 10
  }
  0
}

// 字符串到 Bytes 转换
pub fn string_to_bytes(s: String) -> Bytes {
  let len = s.length()
  let arr = Array::make(len, b'\x00')
  for i in 0..<len {
    arr[i] = s[i].to_byte()
  }
  Bytes::from_array(arr[:])
}

// Bytes 到字符串转换
pub fn bytes_to_string(data: Bytes) -> String {
  let len = data.length()
  let mut result = ""
  for i in 0..<len {
    result = result + data[i].to_char().to_string()
  }
  result
}

// 生成随机测试数据（伪随机）
pub fn generate_random_data(size: Int, seed: Int) -> Bytes {
  let arr = Array::make(size, b'\x00')
  let mut s = seed
  for i in 0..<size {
    s = (s * 1103515245 + 12345) & 0x7FFFFFFF
    arr[i] = (s & 0xFF).to_byte()
  }
  Bytes::from_array(arr[:])
}

// 比较两个Bytes是否相等
pub fn bytes_equal(a: Bytes, b: Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}
