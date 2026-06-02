// MoonBit Crypto 现代化架构配置
// 高性能加密库 - SHA-256 和 AES-128

name = "moonbit/crypto"

version = "1.0.0"

readme = "README.md"

repository = "https://github.com/cc06b/mooncry"

license = "Apache-2.0"

keywords = ["crypto", "hash", "aes", "sha256", "encryption"]

description = "高性能 MoonBit 加密库，支持 SHA-256 哈希算法和 AES-128 对称加密算法"

import {
  "moonbitlang/x@0.4.43",
}

// 模块结构说明:
// - lib/crypto_interface.mbt    : 核心接口定义
// - lib/crypto_error.mbt         : 错误处理模块
// - lib/crypto_config.mbt        : 配置管理模块
// - lib/hash/sha256_provider.mbt : SHA-256 算法提供者
// - lib/cipher/aes_provider.mbt  : AES 算法提供者
// - lib/provider/provider_manager.mbt : 提供者管理器
// - lib/modern_api.mbt           : 现代化API入口
// - lib/crypto_api.mbt           : 传统API（保持兼容）
// - lib/ultra_optimized.mbt      : SHA-256 极致优化版本
// - lib/simd_crypto.mbt          : SHA-256 SIMD优化版本
// - lib/aes_ultra.mbt            : AES 极致优化版本
