# 金融级 C/S 架构系统 - 代码架构

## 📁 完整目录结构

```
solo/
├── config/                          # 配置模块
│   └── config.py                    # 配置文件
├── crypto/                          # 🔐 加密模块（核心）
│   ├── include/                     # C 头文件
│   │   └── financial_crypto.h       # 加密库 API 定义
│   ├── src/                         # C 源文件
│   │   ├── sha256.c                 # SHA-256 哈希算法
│   │   ├── hmac.c                   # HMAC-SHA256 实现
│   │   ├── aes256.c                 # AES-256-CBC 加密/解密
│   │   └── utils.c                  # 工具函数（随机数）
│   ├── __init__.py                  # Python 绑定（ctypes）
│   ├── CMakeLists.txt               # CMake 构建配置
│   └── build.py                     # Python 构建脚本
├── server/                          # 🚀 服务器模块
│   └── server.py                    # 异步 TLS 服务器
├── utils/                           # 🛠️ 工具模块
│   ├── logger.py                    # 日志记录器
│   └── security.py                  # 安全管理器
├── examples/                        # 📝 示例
│   └── test_crypto.py               # 加密库测试
├── requirements.txt                 # Python 依赖
├── README.md                        # 项目文档
├── TEST_PLAN.md                     # 测试计划
├── TEST_REPORT.md                   # 测试报告
├── GIT_SETUP.md                     # Git 设置指南
├── QUICK_GIT.md                     # Git 快速开始
├── run_tests.py                     # 测试脚本
├── validate.py                      # 验证脚本
├── init_git.bat                     # Git 初始化脚本（Windows）
├── init_git.ps1                     # Git 初始化脚本（PowerShell）
├── quick_verify.sh                  # 快速验证脚本
└── .gitignore                       # Git 忽略配置
```

---

## 🏗️ 架构概览

### 分层架构

```
┌─────────────────────────────────────────┐
│        Application Layer                │
│  ┌──────────────────────────────────┐  │
│  │  Server (TLS, AsyncIO)          │  │
│  │  Examples / Test                │  │
│  └──────────────────────────────────┘  │
├─────────────────────────────────────────┤
│        Security Layer                   │
│  ┌──────────────────────────────────┐  │
│  │  Security Manager               │  │
│  │  Logger                         │  │
│  └──────────────────────────────────┘  │
├─────────────────────────────────────────┤
│        Crypto Layer                     │
│  ┌──────────────────────────────────┐  │
│  │  Python Bindings (ctypes)        │  │
│  ├──────────────────────────────────┤  │
│  │  Native C Library (高性能)       │  │
│  │  - SHA-256, HMAC, AES-256       │  │
│  └──────────────────────────────────┘  │
├─────────────────────────────────────────┤
│        Configuration Layer              │
│  ┌──────────────────────────────────┐  │
│  │  Config Manager                 │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 📦 模块详细说明

### 1. 🔐 Crypto 模块（加密核心）

**目录：** `crypto/`

#### 文件说明

| 文件 | 功能 | 行数 |
|------|------|------|
| [financial_crypto.h](file:///c:/Users/leo/Documents/GitHub/solo/crypto/include/financial_crypto.h) | 加密库 API 定义，错误码枚举 | 57 行 |
| [sha256.c](file:///c:/Users/leo/Documents/GitHub/solo/crypto/src/sha256.c) | SHA-256 哈希算法实现（NIST标准） | 167 行 |
| [hmac.c](file:///c:/Users/leo/Documents/GitHub/solo/crypto/src/hmac.c) | HMAC-SHA256 消息认证码实现 | 78 行 |
| [aes256.c](file:///c:/Users/leo/Documents/GitHub/solo/crypto/src/aes256.c) | AES-256-CBC 加密/解密 + PKCS#7 | 359 行 |
| [utils.c](file:///c:/Users/leo/Documents/GitHub/solo/crypto/src/utils.c) | 跨平台随机数生成（Windows / Linux） | 78 行 |
| [__init__.py](file:///c:/Users/leo/Documents/GitHub/solo/crypto/__init__.py) | Python ctypes 绑定 + 双方案支持 | 326 行 |
| [CMakeLists.txt](file:///c:/Users/leo/Documents/GitHub/solo/crypto/CMakeLists.txt) | CMake 构建配置（动态/静态库） | 43 行 |
| [build.py](file:///c:/Users/leo/Documents/GitHub/solo/crypto/build.py) | Python 自动构建脚本 | 95 行 |

#### 核心 API 函数

```c
// SHA-256 哈希
CryptoResult sha256_hash(const uint8_t* data, size_t data_len,
                         uint8_t* output, size_t* output_len);

// HMAC-SHA256
CryptoResult hmac_sha256(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t* output, size_t* output_len);

// AES-256-CBC 加密/解密
CryptoResult aes_256_cbc_encrypt(...)
CryptoResult aes_256_cbc_decrypt(...)

// 随机数生成
CryptoResult generate_random_bytes(uint8_t* buffer, size_t length);
```

#### 特点

- ✅ 纯 C 语言实现，无外部依赖
- ✅ 性能远高于纯 Python
- ✅ 双方案支持（原生库 + Python 备用）
- ✅ 跨平台（Windows / Linux / macOS）
- ✅ 可编译为动态库 (.dll/.so/.dylib) 或静态库

---

### 2. 🚀 Server 模块（服务器）

**目录：** `server/`

#### 文件说明

| 文件 | 功能 | 行数 |
|------|------|------|
| [server.py](file:///c:/Users/leo/Documents/GitHub/solo/server/server.py) | 异步 TLS 1.3 加密服务器 | 203 行 |

#### 核心功能

1. **异步架构** - 基于 asyncio，支持高并发
2. **TLS 1.3 加密** - 安全传输层
3. **JWT 认证** - 无状态身份验证
4. **Nonce 防重放** - 防止请求重放攻击
5. **限流保护** - 防止暴力攻击
6. **消息序列化** - JSON + 签名
7. **审计日志** - 完整操作记录

#### 请求处理流程

```
客户端
  ↓
TLS 连接
  ↓
用户认证 (JWT)
  ↓
Nonce 验证 (防重放)
  ↓
限流检查
  ↓
签名验证 (HMAC)
  ↓
业务处理
  ↓
响应加密
  ↓
客户端
```

---

### 3. 🛠️ Utils 模块（工具）

**目录：** `utils/`

#### 文件说明

| 文件 | 功能 | 行数 |
|------|------|------|
| [security.py](file:///c:/Users/leo/Documents/GitHub/solo/utils/security.py) | 安全管理器（双方案加密支持） | 160 行 |
| [logger.py](file:///c:/Users/leo/Documents/GitHub/solo/utils/logger.py) | 日志记录器（文件 + 控制台） | 39 行 |

#### Security Manager 功能

- ✅ SHA-256 哈希
- ✅ HMAC-SHA256 消息认证
- ✅ AES-256-CBC 加密/解密
- ✅ JWT 生成/验证
- ✅ Nonce 生成/验证
- ✅ 限流控制
- ✅ 安全比较（防时序攻击）
- ✅ 自动降级（原生库 -> Python）

---

### 4. ⚙️ Config 模块（配置）

**目录：** `config/`

#### 文件说明

| 文件 | 功能 | 行数 |
|------|------|------|
| [config.py](file:///c:/Users/leo/Documents/GitHub/solo/config/config.py) | 配置管理器（支持环境变量） | 29 行 |

#### 配置项

- JWT 密钥和过期时间
- TLS 证书路径
- 服务器地址和端口
- 限流阈值
- Nonce 过期时间

---

### 5. 📝 Examples 模块（示例）

**目录：** `examples/`

#### 文件说明

| 文件 | 功能 | 行数 |
|------|------|------|
| [test_crypto.py](file:///c:/Users/leo/Documents/GitHub/solo/examples/test_crypto.py) | 加密库完整测试套件 | 130 行 |

#### 测试覆盖

- SHA-256 哈希测试
- HMAC-SHA256 测试
- 随机数生成测试
- AES-256-CBC 加密/解密测试
- Base64 编码加密测试
- Security Manager 功能测试
- Nonce 验证测试

---

## 🔗 模块依赖关系

```
┌─────────────────────────────────────────┐
│          Server                         │
│         /     \                         │
│        ↓       ↓                        │
│  Security      Logger                  │
│     │           │                       │
│     └─────┬─────┘                       │
│           ↓                             │
│      Config                             │
│           │                             │
│           ↓                             │
├─────────────────────────────────────────┤
│        Crypto                           │
│    (C 原生库或 Python 备用)            │
└─────────────────────────────────────────┘
```

---

## 🎯 核心设计特点

### 1. 双方案加密架构

```
Crypto API 调用
    ↓
[有原生库？] → 是 → 使用 C 原生库（高性能）
    ↓ 否
使用 Python cryptography 库（备用）
```

### 2. 分层安全设计

- **传输层** - TLS 1.3
- **认证层** - JWT + HMAC
- **数据层** - AES-256
- **防重放** - Nonce + 时间窗口
- **应用层** - 限流 + 审计

### 3. 性能优化

- C 语言核心算法
- 异步非阻塞 I/O
- 内存安全管理
- 编译优化支持

### 4. 跨平台兼容

- 支持 Windows / Linux / macOS
- 统一的 API 接口
- 自动适应平台特性

---

## 📊 代码统计

| 语言 | 文件数 | 代码行数 |
|------|--------|----------|
| C | 5 | ~680 行 |
| Python | 9 | ~1300 行 |
| Markdown (文档) | 7 | ~2000 行 |
| CMake/Shell | 3 | ~150 行 |
| **总计** | **25** | **~4130 行** |

---

## 🚀 快速开始

### 加密模块使用

```python
from crypto import (
    sha256,
    hmac_sha256,
    aes_256_cbc_encrypt,
    aes_256_cbc_decrypt,
    generate_random_bytes
)

# SHA-256 哈希
hash_val = sha256(b"Hello World")

# AES-256 加密
key = generate_random_bytes(32)
iv = generate_random_bytes(16)
ciphertext = aes_256_cbc_encrypt(key, iv, b"Secret data")
```

### 安全管理器使用

```python
from utils.security import security_manager

# JWT 认证
token = security_manager.generate_jwt("user123")
payload = security_manager.verify_jwt(token)

# 加密
encrypted = security_manager.encrypt_data("Secret message")
decrypted = security_manager.decrypt_data(encrypted)
```

### 服务器启动

```bash
# 1. 生成 TLS 证书
mkdir certs
openssl genrsa -out certs/server.key 2048
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes

# 2. 启动服务器
cd server
python server.py
```

---

## 🔐 安全特性概览

| 特性 | 实现 | 说明 |
|------|------|------|
| 传输加密 | TLS 1.3 | 证书验证 |
| 身份认证 | JWT | 过期机制 |
| 数据加密 | AES-256-CBC | PKCS#7 填充 |
| 完整性 | HMAC-SHA256 | 消息认证 |
| 防重放 | Nonce + TTL | 单次使用 |
| 防暴力 | 请求限流 | 时间窗口 |
| 时序攻击 | 安全比较 | 恒定时间 |
| 审计 | 日志记录 | 操作追踪 |

---

## 📚 相关文档

- [README.md](file:///c:/Users/leo/Documents/GitHub/solo/README.md) - 项目介绍
- [TEST_PLAN.md](file:///c:/Users/leo/Documents/GitHub/solo/TEST_PLAN.md) - 测试计划
- [TEST_REPORT.md](file:///c:/Users/leo/Documents/GitHub/solo/TEST_REPORT.md) - 测试报告
- [GIT_SETUP.md](file:///c:/Users/leo/Documents/GitHub/solo/GIT_SETUP.md) - Git 指南
