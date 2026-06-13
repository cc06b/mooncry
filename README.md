# Solo — 金融级 C/S 架构 + MoonBit 加密加速

一个高性能、高安全性的客户端/服务器架构系统，专为金融级应用设计。
底层加密算法由 **MoonBit** 实现并优化，提供可验证的高性能加密原语。

---

## 架构总览

```
┌────────────────────────────────────────────────────┐
│                  Solo (根项目)                      │
│  Apache License 2.0                                │
├────────────────────────────────────────────────────┤
│                                                    │
│  ┌── C/S 架构层 (验证 & 测试) ────────────────┐   │
│  │                                               │   │
│  │   config/        配置 (config.py)            │   │
│  │   crypto/        C 加密库 (SHA-256, AES, HMAC)│   │
│  │     ├─ src/      C 实现                       │   │
│  │     ├─ include/  头文件                       │   │
│  │     └─ build.py  编译脚本                     │   │
│  │   server/        异步服务器 (TLS 1.3)         │   │
│  │   utils/         日志 & 安全工具              │   │
│  │   examples/      测试脚本 & 用例              │   │
│  └───────────────────────────────────────────────┘   │
│                                                    │
│  ┌── MoonBit 加密加速层 ─────────────────────────┐  │
│  │                                               │   │
│  │   cryptoult/     精简版 (SHA-256, 已验证)    │   │
│  │     └─ cryptoult.mbt                         │   │
│  │                                               │   │
│  │   moonbit_crypto/ 完整版 (模块化提供者)        │   │
│  │     ├─ lib/     核心算法与接口                │   │
│  │     ├─ benchmark/ 性能基准测试                │   │
│  │     ├─ examples/ API 使用示例                 │   │
│  │     └─ cmd/main/ 入口 & 测试                  │   │
│  └───────────────────────────────────────────────┘   │
│                                                    │
└────────────────────────────────────────────────────┘
```

| 层 | 职责 | 语言 | 核心文件 |
|---|------|------|---------|
| **C/S 架构** | 验证测试、协议通信、业务集成 | Python + C | `crypto/src/`, `server/server.py`, `examples/` |
| **MoonBit 加密加速** | 加密原语实现与性能优化 | MoonBit / WebAssembly | `cryptoult/`, `moonbit_crypto/lib/` |

---

## 核心特性

### 🔐 C/S 架构层（验证与测试）

- **TLS 1.3 加密通信**：使用最新的 TLS 协议保护网络传输
- **C 语言加密库**：编译为原生动态库，性能远超纯 Python 实现
  - `aes256.c` — AES-256-CBC 加解密
  - `sha256.c` — SHA-256 哈希
  - `hmac.c` — HMAC-SHA256 完整性校验
- **Python 异步服务器**：基于 `asyncio` 的高并发架构
- **请求限流 & 防重放**：保护服务器免受暴力攻击
- **标准测试向量**：所有加密算法通过 FIPS / NIST 标准向量验证

### ⚡ MoonBit 加密加速层

- **SHA-256**：完整 64 轮展开，滚动缓冲优化
- **AES-128**：轮密钥扩展内联，S-box 查表优化
- **HMAC**：基于 SHA-256 的消息认证码
- **模块化提供者模式**：统一 `crypto_interface.mbt` + 可插拔算法提供者
- **SIMD 友好设计**：数据布局便于未来向量化扩展
- **交叉验证**：与 C 实现双向校验一致性

---

## 快速开始

### 依赖

- Python 3.8+
- CMake 3.10+（用于编译 C 加密库）
- MoonBit toolchain（用于加密加速层，可选）

### 运行 C/S 层

```bash
# 构建 C 加密库
cd crypto
python build.py
cd ..

# 启动服务器
python server/server.py

# 运行测试
python examples/test_crypto.py
python examples/performance_test.py
```

### 运行 MoonBit 加密加速层

```bash
# cryptoult (精简版, SHA-256)
cd cryptoult
moon run cmd/main

# moonbit_crypto (完整版, 含 AES/HMAC/提供者模式)
cd moonbit_crypto
moon run cmd/main
```

### 验证标准测试向量

```bash
# cryptoult 中的 run_sha256_tests() 自动验证:
#  - sha256("")        = e3b0c442...852b855
#  - sha256("a")       = ca978112...fee48bb
#  - sha256("abc")     = ba7816bf...20015ad
#  - sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
#                      = 248d6a61...db06c1
```

---

## 项目结构

```
solo/
├── LICENSE                 # Apache License 2.0 (项目级)
├── README.md               # 本文件
│
├── config/                 # 配置模块
│   └── config.py
│
├── crypto/                 # C 加密库 (参考实现)
│   ├── CMakeLists.txt
│   ├── build.py
│   ├── include/
│   │   └── financial_crypto.h
│   └── src/
│       ├── aes256.c
│       ├── sha256.c
│       ├── hmac.c
│       └── utils.c
│
├── server/                 # 异步服务器
│   └── server.py
│
├── utils/                  # 工具模块
│   ├── logger.py
│   └── security.py
│
├── examples/               # 测试脚本 & 使用示例
│   ├── test_crypto.py
│   ├── performance_test.py
│   ├── lightweight_test.py
│   ├── auto_stress_test.py
│   ├── stress_test_server.py
│   └── stress_test_client.py
│
├── cryptoult/              # MoonBit 精简版加密库
│   ├── moon.mod
│   ├── moon.pkg
│   ├── cryptoult.mbt       # SHA-256 核心实现 (已验证)
│   ├── cryptoult_test.mbt
│   ├── cryptoult_wbtest.mbt
│   └── cmd/main/main.mbt   # 测试入口
│
└── moonbit_crypto/         # MoonBit 完整版加密库
    ├── moon.mod
    ├── moon.pkg
    ├── lib/                # 核心实现 (SHA-256, AES, 提供者)
    │   ├── crypto_*.mbt
    │   ├── sha256_mega.mbt
    │   ├── aes_ultra.mbt
    │   ├── simd_crypto.mbt
    │   ├── crypto_config.mbt
    │   ├── crypto_error.mbt
    │   ├── crypto_interface.mbt
    │   ├── crypto_api.mbt
    │   ├── provider/provider_manager.mbt
    │   ├── cipher/aes_provider.mbt
    │   └── hash/sha256_provider.mbt
    ├── benchmark/          # 性能基准测试
    ├── examples/           # API 使用示例
    └── cmd/main/           # 入口 & 测试运行器
```

---

## 开发工作流

1. **算法开发** → 在 `cryptoult/` 或 `moonbit_crypto/` 中实现 MoonBit 算法
2. **标准向量验证** → 使用 `run_sha256_tests()` 等函数验证
3. **性能基准** → 使用 `bench_sha256()` 与 C/参考实现对比
4. **集成到 C/S 层** → 通过 Python FFI 或独立微服务调用 MoonBit 编译产物

---

## License

Copyright © 2026 Solo Crypto Contributors

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) for details.
