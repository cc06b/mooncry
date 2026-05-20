# 金融级 C/S 架构系统

一个高性能、高安全性的客户端/服务器架构系统，专为金融级应用设计。

## 核心特性

### 🔐 安全性

- **TLS 1.3 加密通信**：使用最新的 TLS 协议保护网络传输
- **JWT 身份认证**：基于 JWT 的无状态认证机制
- **AES-256-CBC 数据加密**：C语言实现的高性能加密算法
- **HMAC-SHA256 完整性校验**：确保数据未被篡改
- **Nonce 防重放攻击**：防止请求被恶意重放
- **请求限流**：保护服务器免受暴力攻击

### ⚡ 高性能

- **C 语言实现加密算法**：编译为原生动态库，性能远超纯 Python 实现
- **异步 I/O 架构**：基于 Python asyncio 的高效并发处理
- **多平台支持**：Windows、Linux、macOS 全平台兼容

### 🏗️ 架构设计

```
solo/
├── config/              # 配置文件
│   └── config.py
├── server/              # 服务端
│   └── server.py        # 异步服务器，支持 TLS
├── client/              # 客户端（待实现）
├── crypto/              # 加密模块（核心！）
│   ├── include/         # 头文件
│   │   └── financial_crypto.h
│   ├── src/             # C 语言源码
│   │   ├── sha256.c     # SHA-256 哈希
│   │   ├── hmac.c       # HMAC-SHA256
│   │   ├── aes256.c     # AES-256-CBC 加密
│   │   └── utils.c      # 工具函数
│   ├── __init__.py      # Python 绑定
│   ├── build.py         # 构建脚本
│   └── CMakeLists.txt   # CMake 构建配置
├── utils/               # 工具模块
│   ├── security.py      # 安全管理器（支持双方案）
│   └── logger.py        # 日志模块
├── examples/            # 示例代码
│   └── test_crypto.py   # 加密库测试
├── requirements.txt
└── README.md
```

## 快速开始

### 环境要求

- Python 3.8+
- CMake 3.10+
- 支持 C99 的编译器（GCC、Clang、MSVC）

### 安装依赖

```bash
pip install -r requirements.txt
```

### 构建加密库

#### 方法 1：使用构建脚本（推荐）

```bash
cd crypto
python build.py
```

#### 方法 2：手动使用 CMake

```bash
cd crypto
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

构建完成后，动态库会自动复制到 `crypto/lib/` 目录。

### 运行测试

```bash
cd examples
python test_crypto.py
```

## 加密模块使用

### Python API 示例

```python
from crypto import (
    sha256,
    hmac_sha256,
    aes_256_cbc_encrypt,
    aes_256_cbc_decrypt,
    generate_random_bytes,
    encrypt_text_to_base64,
    decrypt_from_base64
)

# SHA-256 哈希
hash_result = sha256(b"Hello World")
print(hash_result.hex())

# HMAC-SHA256
hmac_result = hmac_sha256(b"secret-key", b"data")

# AES-256-CBC 加密
key = generate_random_bytes(32)
iv = generate_random_bytes(16)
ciphertext = aes_256_cbc_encrypt(key, iv, b"sensitive data")
plaintext = aes_256_cbc_decrypt(key, iv, ciphertext)

# Base64 便捷加密
encrypted = encrypt_text_to_base64(key, "秘密信息")
decrypted = decrypt_from_base64(key, encrypted)
```

### C 语言 API 示例

```c
#include "financial_crypto.h"

// SHA-256 哈希
uint8_t hash[SHA256_DIGEST_SIZE];
size_t hash_len = SHA256_DIGEST_SIZE;
sha256_hash(data, data_len, hash, &hash_len);

// AES-256-CBC 加密
uint8_t key[32], iv[16];
// ... 初始化 key 和 iv ...
uint8_t ciphertext[MAX_SIZE];
size_t ciphertext_len = MAX_SIZE;
aes_256_cbc_encrypt(key, 32, iv, 16, plaintext, plaintext_len, 
                     ciphertext, &ciphertext_len);
```

## 启动服务器

```bash
# 首先需要准备 TLS 证书（开发环境可以使用自签名证书）
mkdir -p certs
# 使用 openssl 生成自签名证书...

# 启动服务器
cd server
python server.py
```

## 安全说明

### 生产环境部署建议

1. **替换默认密钥**：修改 `config/config.py` 中的 `JWT_SECRET_KEY`
2. **使用正规 CA 签名证书**：不要在生产环境使用自签名证书
3. **配置安全的 TLS 参数**：仅使用安全的加密套件
4. **定期更新依赖**：保持所有依赖库为最新版本
5. **启用审计日志**：所有操作都会被记录

### 加密算法说明

- **SHA-256**：用于数据完整性校验和哈希
- **HMAC-SHA256**：用于消息认证
- **AES-256-CBC**：用于数据加密，使用 PKCS#7 填充
- **加密库隔离**：C语言编译为动态库，算法源码不直接暴露

## 性能优势

相比纯 Python 实现的加密库，本系统的优势：

- **SHA-256**：约 5-10 倍性能提升
- **HMAC-SHA256**：约 3-8 倍性能提升  
- **AES-256**：约 10-20 倍性能提升
- **内存效率**：更节省内存占用

## 备用方案

如果无法编译 C 语言加密库，系统会自动降级使用 Python 的 `cryptography` 库作为备用方案，功能完全兼容，仅性能有所下降。

## 许可证

本项目仅供学习和研究使用。

## 联系方式

如有问题或建议，欢迎提交 Issue。
