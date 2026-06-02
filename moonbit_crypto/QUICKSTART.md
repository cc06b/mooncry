# MoonBit Crypto 快速入门指南

## 简介

MoonBit Crypto 是一个用 MoonBit 语言编写的高性能加密库，提供 SHA-256 哈希算法和 AES-128 加密算法。

## 功能特性

- 🚀 **高性能**：循环展开、查找表优化、SIMD思想
- 🔒 **安全**：标准密码学算法实现
- 📦 **易用**：简洁的API设计
- 🛠️ **工具丰富**：十六进制编码、字符串转换等

## 安装

将 `moonbit_crypto` 文件夹复制到你的项目中。

## 快速开始

### SHA-256 哈希

```moonbit
import lib/crypto_api.*

let message = string_to_bytes("Hello, World!")
let hash = sha256(message)
println("SHA-256: " + bytes_to_hex(hash))
```

### AES 加密/解密

```moonbit
import lib/crypto_api.*

// 16字节密钥
let key = Bytes::from_array([
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
][:])

let plaintext = string_to_bytes("Secret message")

// 加密
let encrypted = aes_encrypt(plaintext, key)

// 解密
let decrypted = aes_decrypt(encrypted, key)
```

### 使用 SIMD 优化版本

```moonbit
import lib/crypto_api.*

let data = generate_random_data(10000, 12345)
let hash_fast = sha256_fast(data)
```

## 模块说明

- `lib/ultra_optimized.mbt` - SHA-256 完全优化版本
- `lib/simd_crypto.mbt` - SHA-256 SIMD思想优化版本  
- `lib/aes_ultra.mbt` - AES-128 优化实现
- `lib/crypto_api.mbt` - 统一API接口

## 示例

查看 `examples/` 目录获取更多使用示例：

- `comprehensive_test.mbt` - 全面测试套件
- `usage_examples.mbt` - 使用示例

## 测试

运行示例和测试来验证功能：

```bash
cd moonbit_crypto
moon test
```

## 性能优化

本库包含多项性能优化：
- 循环展开
- 查找表优化
- 内存复用
- 寄存器变量重用

## 注意事项

- AES密钥长度必须为16字节（AES-128）
- 生产环境使用前请进行充分测试
- 密钥管理请遵循安全最佳实践
