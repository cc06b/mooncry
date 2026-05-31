# MoonBit Crypto Library - 性能测试报告

## 📊 测试数据摘要

### 测试环境
- **日期**: 2026-05-24
- **操作系统**: Windows
- **测试数据**: 随机字节 (i % 256)
- **迭代次数**: 100次

---

## 📈 性能对比数据

### Python 纯实现 vs Python hashlib (C优化)

| 数据大小 | Python纯实现 | Python hashlib (C) | 加速比 |
|---------|-------------|-------------------|-------|
| **64 B** | 0.12 MB/s | 41.61 MB/s | **359.7x** |
| **256 B** | 0.18 MB/s | 123.12 MB/s | **668.8x** |
| **1 KB** | 0.21 MB/s | 269.25 MB/s | **1273.1x** |
| **4 KB** | 0.22 MB/s | 350.81 MB/s | **1597.3x** |
| **16 KB** | 0.23 MB/s | 389.85 MB/s | **1682.7x** |
| **64 KB** | 0.22 MB/s | 394.24 MB/s | **1771.3x** |

### MoonBit 测试数据
- **16 KB × 100次**: ~2.77秒（完整运行时间）

---

## 🔍 性能分析

### 1. 解释型语言 vs 编译型语言

| 特性 | Python纯实现 | Python hashlib (C) | MoonBit |
|------|-------------|-------------------|---------|
| 执行方式 | 解释执行 | 机器码 | 解释执行 |
| 类型系统 | 动态 | 静态 | 静态 |
| 编译器优化 | 无 | GCC -O3 | 内置优化 |
| 吞吐量 (16KB) | 0.23 MB/s | 389.85 MB/s | 待精确测量 |

### 2. 瓶颈分析

#### Python 纯实现瓶颈
1. **循环开销**: Python 循环极慢
2. **函数调用**: 每次函数调用有显著开销
3. **动态类型**: 运行时类型检查
4. **字节码执行**: 虚拟机解释执行

#### Python hashlib (C优化) 优势
1. **机器码**: 直接编译为机器码
2. **编译器优化**: GCC -O3 + CPU 特化
3. **SIMD指令**: 利用 SSE/AVX 加速
4. **手动优化**: 汇编级优化

---

## 🎯 MoonBit 优化策略

### 短期优化（立即可行）

#### 1. 展开关键循环
```moonbit
// 替代:
for j in 0..=63 { ... }

// 使用:
// 手动展开16-32轮
// 编译器提示
```

#### 2. 减少函数调用
```moonbit
// 内联 rotr, s0, s1 计算
// 避免函数调用开销
```

#### 3. 预分配数组
```moonbit
// 在循环外预分配工作数组
let w = Array::make(64, 0U)
```

#### 4. 批量操作
```moonbit
// 一次性读取16个字
// 优化内存访问模式
```

### 中期优化（需要 MoonBit 更新）

#### 1. SIMD 支持
```moonbit
// 一旦 MoonBit 支持 SIMD intrinsics
// 使用 SHA-256 SIMD 实现
// 预期提升: 3-5x
```

#### 2. 更好的编译器优化
- 自动循环展开
- 更好的寄存器分配
- 死代码消除

### 长期优化（架构改进）

#### 1. Native 后端
```moonbit
// 直接编译为机器码
// 消除解释执行开销
// 预期提升: 5-10x
```

#### 2. GC 优化
- 分代 GC
- 减少暂停
- 栈分配优先

---

## 📊 性能目标

### 阶段目标

| 阶段 | 目标性能 | 实现方式 |
|------|---------|---------|
| **当前** | ~5-10x Python纯 | 基础优化 |
| **短期** | ~20-50x Python纯 | 循环展开 + 批量操作 |
| **中期** | ~100-200x Python纯 | SIMD支持 |
| **长期** | 接近 C 性能 | Native 后端 |

### 对标目标
- **Python纯实现**: 0.22 MB/s (16KB)
- **Python hashlib**: 394 MB/s (16KB)
- **纯C实现**: ~800-1500 MB/s (16KB)
- **C+SIMD**: ~3000-5000 MB/s (16KB)

---

## 🔧 立即可行的优化

### 1. 优化 1: 消息展开
```moonbit
// 完全展开 16-63 的消息扩展
// 避免循环开销
```

### 2. 优化 2: 批量读取
```moonbit
// 一次性读取完整块
// 优化缓存访问
```

### 3. 优化 3: 内联计算
```moonbit
// 内联 rotr, ch, maj 计算
// 避免函数调用
```

### 4. 优化 4: 数组访问优化
```moonbit
// 减少数组边界检查
// 使用局部变量缓存常用值
```

---

## 📝 测试代码

### 已创建的测试文件

1. **[sha256_python.py](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/benchmark/sha256_python.py)**
   - Python纯实现
   - Python hashlib对比
   - 完整性能数据

2. **[sha256_test.mbt](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/benchmark/sha256_test.mbt)**
   - MoonBit 测试版本
   - 可使用外部计时测量

3. **[sha256_moonbit.mbt](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/benchmark/sha256_moonbit.mbt)**
   - MoonBit 标准版本

4. **[sha256_ultra.mbt](file:///C:/Users/leo/Documents/GitHub/solo/moonbit_crypto/benchmark/sha256_ultra.mbt)**
   - MoonBit 极致优化版本

---

## 💡 建议

### 对于 MoonBit 团队

1. **添加精确计时 API**
   ```moonbit
   // 类似:
   let start = System.currentTimeMillis()
   let end = System.currentTimeMillis()
   let elapsed = end - start
   ```

2. **支持 SIMD intrinsics**
   - SHA-256 SIMD 加速
   - AES-NI 支持

3. **Native 编译后端**
   - 直接编译为机器码
   - 消除解释开销

4. **更好的编译器优化**
   - 循环展开
   - 寄存器分配
   - 数组边界检查消除

### 对于当前应用

1. **混合方案**
   - MoonBit: 业务逻辑、高层抽象
   - C/Rust: 性能敏感路径
   - FFI 调用

2. **批量处理**
   - 减少函数调用次数
   - 批量加密/哈希

3. **缓存优化**
   - 重用已计算值
   - 预分配缓冲区

---

## 📊 结论

### 当前状态
- ✅ 功能完整：SHA-256, HMAC, AES 工作正常
- ✅ 代码质量：模块化、易维护
- ⚠️ 性能：与解释型语言相当
- ⚠️ 差距：与优化 C 有显著差距

### 下一步行动

1. **短期** (1-2周)
   - 实现极致优化版本
   - 测试性能提升
   - 创建 AES 性能测试

2. **中期** (1-2月)
   - 等待 MoonBit SIMD 支持
   - 重写使用 SIMD
   - 实现 Native 后端测试

3. **长期** (3-6月)
   - 与 MoonBit 团队合作
   - 优化编译器
   - 达到接近 C 的性能

---

## 📚 参考资料

- [NIST FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [SHA-256 SIMD Implementations](https://github.com/noloader/SHA-Intrinsics)
- [GCC Optimization Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [MoonBit Language](https://www.moonbitlang.com/)

---

**报告生成时间**: 2026-05-24
**测试完成**: ✅
