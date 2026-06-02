# MoonBit Crypto

高性能 MoonBit 加密库，支持 SHA-256 哈希算法和 AES-128 加密算法。

## 特性

- 🚀 **高性能**：循环展开、查找表优化、SIMD思想
- 🔒 **安全**：标准密码学算法实现
- 📦 **易用**：简洁的 API 设计
- 🛠️ **工具丰富**：十六进制编码、字符串转换等
- 📚 **文档完善**：完整的示例和文档

## 快速开始

### SHA-256 哈希

```moonbit
import lib/crypto_api.*

let message = string_to_bytes("Hello, MoonBit!")
let hash = sha256(message)
println("SHA-256: " + bytes_to_hex(hash))
```

### AES 加密/解密

```moonbit
import lib/crypto_api.*

let key = Bytes::from_array([
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
][:])

let encrypted = aes_encrypt(string_to_bytes("Secret"), key)
let decrypted = aes_decrypt(encrypted, key)
```

## 模块说明

- `lib/ultra_optimized.mbt` - SHA-256 完全优化版本
- `lib/simd_crypto.mbt` - SHA-256 SIMD思想优化版本
- `lib/aes_ultra.mbt` - AES-128 优化实现
- `lib/crypto_api.mbt` - 统一 API 接口

## 文档

- [QUICKSTART.md](QUICKSTART.md) - 快速入门指南
- [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) - 项目总结
- [SECURITY.md](SECURITY.md) - 安全注意事项

## 示例

查看 `examples/` 目录获取完整的使用示例：

- `comprehensive_test.mbt` - 综合测试套件
- `usage_examples.mbt` - 使用示例

## 性能优化

- SHA-256：完全循环展开、寄存器重用
- AES：GMUL 查找表、内存复用
- 整体：缓存友好、减少内存分配

## 测试

```bash
cd moonbit_crypto
moon test
```

## 安全提示

- 生产环境使用前请进行安全审计
- 妥善管理密钥，不要硬编码
- 本库未针对侧信道攻击防护
- 仅供学习和研究使用

## 项目结构

```
moonbit_crypto/
├── lib/                    # 核心库
├── benchmark/              # 性能测试
├── examples/               # 示例代码
├── *.md                    # 文档
└── moon.mod.json           # 配置
```

## 优化历史

20次有价值的优化提交，涵盖性能、文档、测试等方面。

## 许可证

仅供学习和研究使用。
