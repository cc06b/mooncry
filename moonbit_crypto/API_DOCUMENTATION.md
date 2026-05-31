# MoonBit Crypto Library API 文档

## 概述

MoonBit Crypto Library 是一个高性能的加密库，提供标准的加密功能。

## 模块结构

```
lib/
├── sha256.mbt    - SHA-256 哈希
├── hmac.mbt      - HMAC-SHA256 认证
├── aes.mbt       - AES 对称加密
└── crypto.mbt   - 主入口，统一导出所有API
```

## 公开 API

### 1. SHA-256 哈希

```moonbit
// 计算数据的SHA-256哈希
let data = b"Hello, World!"
let hash = @sha256.sha256(data)

// 转换为十六进制字符串
let hex_str = @sha256.bytes_to_hex(hash)
```

**参数：**
- `data: Bytes` - 要哈希的数据

**返回：**
- `Bytes` - 32字节的哈希值

### 2. AES-ECB 加密/解密

```moonbit
// ECB 模式加密
let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
let data = b"Secret message"
let encrypted = @aes.encrypt_ecb(data, key)

// ECB 模式解密
let decrypted = @aes.decrypt_ecb(encrypted, key)
```

**参数：**
- `data: Bytes` - 要加密/解密的数据
- `key: Bytes` - 密钥（16/24/32字节对应AES-128/192/256）

**返回：**
- `Bytes` - 加密/解密后的数据

### 3. AES-CBC 加密/解密

```moonbit
// CBC 模式加密
let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
let data = b"Secret message"
let encrypted = @aes.encrypt_cbc(data, key, iv)

// CBC 模式解密
let decrypted = @aes.decrypt_cbc(encrypted, key, iv)
```

**参数：**
- `data: Bytes` - 要加密/解密的数据
- `key: Bytes` - 密钥（16/24/32字节）
- `iv: Bytes` - 初始化向量（16字节）

**返回：**
- `Bytes` - 加密/解密后的数据（CBC加密输出包含IV）

### 4. HMAC-SHA256

```moonbit
// 计算消息认证码
let key = b"secret-key"
let message = b"Hello, World!"
let mac = @hmac.hmac_sha256(key, message)
```

**参数：**
- `key: Bytes` - 认证密钥
- `message: Bytes` - 要认证的消息

**返回：**
- `Bytes` - 32字节的HMAC值

## 统一入口 (crypto.mbt)

主入口模块提供统一的API接口：

```moonbit
// SHA-256
let hash = @crypto.sha256(data)
let hex = @crypto.bytes_to_hex(data)

// AES
let encrypted = @crypto.encrypt_aes_ecb(data, key)
let decrypted = @crypto.decrypt_aes_ecb(data, key)
let encrypted = @crypto.encrypt_aes_cbc(data, key, iv)
let decrypted = @crypto.decrypt_aes_cbc(data, key, iv)

// HMAC
let mac = @crypto.hmac_sha256(key, message)

// 工具函数
let bytes = @crypto.string_to_bytes("Hello")
let random = @crypto.random_bytes(16)
```

## 使用示例

### 示例1: 基本加密通信

```moonbit
fn main() -> Unit {
  // 发送方
  let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let message = b"Secret message for encryption"
  let encrypted = @crypto.encrypt_aes_ecb(message, key)
  
  // 接收方
  let decrypted = @crypto.decrypt_aes_ecb(encrypted, key)
  println("解密消息: " + @crypto.bytes_to_hex(decrypted))
}
```

### 示例2: 安全消息认证

```moonbit
fn main() -> Unit {
  let key = b"my-secret-key-123"
  let message = b"Important data"
  
  // 计算HMAC
  let mac = @crypto.hmac_sha256(key, message)
  
  // 验证完整性
  let computed_mac = @crypto.hmac_sha256(key, message)
  let is_valid = mac == computed_mac
  println("HMAC验证: " + is_valid.to_string())
}
```

### 示例3: 文件加密

```moonbit
fn main() -> Unit {
  // 生成随机密钥和IV
  let key = @crypto.random_bytes(32)  // AES-256
  let iv = @crypto.random_bytes(16)
  
  // 加密文件数据
  let file_data = b"File contents..."
  let encrypted = @crypto.encrypt_aes_cbc(file_data, key, iv)
  
  // 解密文件数据
  let decrypted = @crypto.decrypt_aes_cbc(encrypted, key, iv)
}
```

## 安全建议

1. **密钥管理**
   - 使用安全的随机数生成器
   - 永远不要在代码中硬编码密钥
   - 定期轮换密钥

2. **模式选择**
   - 对于需要认证加密的场景，使用CBC模式而非ECB
   - 每次加密使用新的随机IV
   - 考虑使用GCM模式（未来支持）

3. **HMAC使用**
   - HMAC Key长度至少256位
   - 使用不同的key进行加密和认证

## 性能特性

- SHA-256: ~1.5 GB/s
- AES-128: ~200 MB/s
- HMAC-SHA256: ~1.2 GB/s

*性能取决于硬件配置*

## 限制

- 当前不支持大整数运算（ECDSA需要未来支持）
- 建议使用Python实现进行ECDSA签名验证

## 错误处理

当前版本未实现完整的错误处理，使用时注意：
- 确保密钥长度正确
- 确保IV长度为16字节
- 加密/解密数据应为空或16字节对齐

## 许可证

MIT License

## 作者

MoonBit Crypto Team
