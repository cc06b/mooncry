# MoonBit Crypto Library - 快速参考指南

## 📦 项目概览

**MoonBit Crypto Library** - MoonBit语言实现的加密算法库

### 核心功能
- ✅ SHA-256 哈希
- ✅ HMAC-SHA256 认证
- ✅ AES-128/192/256 (ECB/CBC模式)
- ✅ PKCS7 填充
- 🔄 性能优化进行中

---

## 🚀 快速开始

### 1. 基本使用

```moonbit
// 导入加密库
// (假设库已编译或在同一模块)

// SHA-256 哈希
let data = Bytes::from_string("Hello, World!")
let hash = sha256(data)

// AES 加密
let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
let encrypted = encrypt_aes_ecb(data, key)
let decrypted = decrypt_aes_ecb(encrypted, key)

// HMAC 认证
let hmac = hmac_sha256(key, data)
```

### 2. 性能测试

```bash
# SHA-256 测试
moon run benchmark/sha256_test.mbt

# AES 测试
moon run benchmark/aes_test.mbt

# Python 对比测试
python benchmark/sha256_python.py
```

---

## 📊 性能数据速查

### 当前性能

| 算法 | 吞吐量 (16KB) | vs Python | vs C |
|------|-------------|-----------|------|
| SHA-256 | ~2.9 MB/s | 13x | 136x |
| AES-128 | ~0.34 MB/s | 1.1x | 6000x |

### 性能目标

| 阶段 | SHA-256 | AES-128 | 预期提升 |
|------|---------|---------|---------|
| 当前 | 2.9 MB/s | 0.34 MB/s | 基准 |
| 1-2周 | 5 MB/s | 3 MB/s | 1.7x |
| 1-2月 | 30 MB/s | 50 MB/s | 10x |
| 长期 | 200 MB/s | 200 MB/s | 50x |

---

## 📁 文件结构

```
moonbit_crypto/
├── lib/                          # 核心库
│   ├── crypto.mbt               # 主入口
│   ├── sha256.mbt               # SHA-256
│   ├── aes.mbt                  # AES
│   └── hmac.mbt                 # HMAC
├── cmd/main/
│   └── main.mbt                 # 测试程序
├── benchmark/                    # 性能测试
│   ├── sha256_test.mbt         # SHA-256测试
│   ├── aes_test.mbt            # AES测试
│   ├── sha256_python.py        # Python对比
│   └── PERFORMANCE_REPORT.md   # 完整报告
├── API_DOCUMENTATION.md         # API文档
├── PERFORMANCE_SUMMARY.md        # 优化总结
└── README.md                    # 项目说明
```

---

## 🔧 API 参考

### SHA-256

```moonbit
// 计算哈希
fn sha256(data: Bytes) -> Bytes

// 字节转十六进制
fn bytes_to_hex(data: Bytes) -> String

// 示例
let data = Bytes::from_string("test")
let hash = sha256(data)
let hex = bytes_to_hex(hash)
// hex = "9f86d08..."
```

### AES

```moonbit
// AES-128 ECB 加密/解密
fn encrypt_aes_ecb(data: Bytes, key: Bytes) -> Bytes
fn decrypt_aes_ecb(data: Bytes, key: Bytes) -> Bytes

// AES-128 CBC 加密/解密
fn encrypt_aes_cbc(data: Bytes, key: Bytes, iv: Bytes) -> Bytes
fn decrypt_aes_cbc(data: Bytes, key: Bytes, iv: Bytes) -> Bytes

// AES-256 (使用32字节密钥)
fn encrypt_aes_256_ecb(data: Bytes, key: Bytes) -> Bytes

// 示例
let key = b"\x00\x01\x02...\x0f"  // 16字节
let iv = b"\x10\x11\x12...\x1f"   // 16字节

let encrypted = encrypt_aes_cbc(data, key, iv)
let decrypted = decrypt_aes_cbc(encrypted, key, iv)
```

### HMAC

```moonbit
// HMAC-SHA256
fn hmac_sha256(key: Bytes, message: Bytes) -> Bytes

// 示例
let key = b"\x00\x01\x02...\x0f"
let message = Bytes::from_string("Hello")
let mac = hmac_sha256(key, message)
```

---

## ⚡ 性能优化技巧

### 1. 批量处理

```moonbit
// 优化前：多次调用
for item in items {
  let hash = sha256(item)  // 每次调用都初始化
}

// 优化后：批量处理
let hashes = items.map(sha256)  // 批量处理
```

### 2. 密钥缓存

```moonbit
// 优化前：每次加密都扩展密钥
for chunk in chunks {
  encrypt(chunk, key)  // 每次都 key_expansion
}

// 优化后：预扩展密钥
let expanded_key = key_expansion_128(key)
for chunk in chunks {
  encrypt_with_expanded_key(chunk, expanded_key)
}
```

### 3. 预分配缓冲区

```moonbit
// 优化前：每次创建新数组
fn process(data) {
  let result = Array::make(len, b'\x00')  // 每次分配
  // ...
}

// 优化后：复用缓冲区
let buffer = Array::make(max_size, b'\x00')
fn process_with_buffer(data, buffer) {
  // 复用 buffer
}
```

### 4. 避免小函数调用

```moonbit
// 优化前：函数调用开销
fn mix_columns(state) {
  for j in 0..<4 {
    state[0][j] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3
    // ...
  }
}

// 优化后：内联
// 将 gmul2, gmul3 查表内联到主循环
```

---

## 🎯 使用场景建议

### 适合使用 MoonBit Crypto

✅ **推荐场景**
- 签名验证（速度要求不高）
- 配置加密
- 开发原型
- 教学演示

⚠️ **谨慎使用**
- 高性能服务器
- 大量数据处理
- 低延迟要求

❌ **不推荐**
- 高频交易
- 大文件加密
- 实时通信加密

### 推荐架构

```moonbit
// 混合方案
module CryptoService {
  
  // MoonBit 业务逻辑
  fn encrypt_user_data(data: UserData) -> EncryptedData {
    let key = derive_key(user_password)
    let encrypted = encrypt_aes_cbc(data, key, iv)  // MoonBit
    EncryptedData::{ encrypted, key_id }
  }
  
  // FFI 调用高性能库
  @extern("libcrypto", "SHA256")
  fn sha256_fast(data: Bytes) -> Bytes
  
  // 或者使用Web Crypto API
  @javascript("window.crypto.subtle")
  fn subtle_sha256(data: Bytes) -> Bytes
}
```

---

## 🔍 调试技巧

### 1. 验证结果

```moonbit
// 使用已知测试向量验证
let test_data = b"abc"
let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
let hash = sha256(test_data)
let hex = bytes_to_hex(hash)

if hex != expected {
  println("错误: " + hex)
}
```

### 2. 性能分析

```bash
# 使用 PowerShell 测量
Measure-Command { moon run your_script.mbt }

# 使用 Unix time
time moon run your_script.mbt
```

### 3. 常见错误

```moonbit
// ❌ 错误：密钥长度不对
let key = b"\x01\x02\x03"  // 只有3字节

// ✅ 正确：AES-128需要16字节
let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

// ❌ 错误：数据未填充
let data = b"\x01\x02\x03"  // 不是16的倍数

// ✅ 正确：自动PKCS7填充
let encrypted = encrypt_aes_ecb(data, key)  // 自动填充
```

---

## 📚 学习资源

### 相关文档

- **[API_DOCUMENTATION.md](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/API_DOCUMENTATION.md)** - 完整API文档
- **[PERFORMANCE_SUMMARY.md](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/PERFORMANCE_SUMMARY.md)** - 性能优化总结
- **[benchmark/COMPLETE_PERFORMANCE_REPORT.md](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/benchmark/COMPLETE_PERFORMANCE_REPORT.md)** - 详细测试报告

### 参考资料

- **NIST FIPS 180-4** - SHA-256标准
- **NIST FIPS 197** - AES标准
- **RFC 2104** - HMAC标准
- **MoonBit官网** - https://www.moonbitlang.com

---

## 🤝 贡献指南

### 发现Bug

1. 创建最小复现示例
2. 测试向量验证
3. 提交Issue

### 性能优化

1. 先测试基准性能
2. 应用优化
3. 验证正确性
4. 测量提升
5. 提交PR

### 文档改进

1. 修正错误
2. 添加示例
3. 完善API文档

---

## 📞 联系方式

- **GitHub**: https://github.com/你的用户名/moonbit_crypto
- **问题反馈**: 提交 GitHub Issue
- **讨论**: GitHub Discussions

---

## ✅ 检查清单

开始使用前，确认以下内容：

- [ ] 已安装 MoonBit SDK
- [ ] 了解基本API用法
- [ ] 知道性能限制
- [ ] 选择合适的加密场景
- [ ] 准备好性能优化策略

---

**最后更新**: 2026-05-24  
**版本**: 1.0.0  
**状态**: 活跃开发中 🚀
