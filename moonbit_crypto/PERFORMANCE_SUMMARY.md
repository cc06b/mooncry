# MoonBit Crypto Library - 性能优化总结

## 📊 性能测试套件

### 创建的文件

1. **benchmark/sha256_c.c** - C 优化版本基准测试
   - 使用 `-O3 -march=native` 编译
   - 高精度计时 (clock_gettime)
   - 测试多种数据大小

2. **benchmark/sha256_moonbit.mbt** - MoonBit 标准版本
   - 基础优化（const + 批量操作）
   - 对标 C 版本实现

3. **benchmark/sha256_ultra.mbt** - MoonBit 极致优化版本
   - 消息扩展完全展开
   - 批量读取优化
   - 64轮计算展开

4. **benchmark/run_benchmark.bat** - 一键运行脚本
   - 自动编译 C 版本
   - 运行两个版本
   - 输出对比结果

5. **benchmark/PERFORMANCE_ANALYSIS.md** - 性能分析文档
   - 差距原因分析
   - 优化方向建议
   - 预期结果

6. **benchmark/README.md** - 测试套件说明

## 🚀 运行测试

### 方法 1: 一键运行

```cmd
cd C:\Users\leo\Documents\GitHub\solo\moonbit_crypto\benchmark
run_benchmark.bat
```

### 方法 2: 手动运行

```bash
# 1. 编译 C 版本
gcc -O3 -march=native -o sha256_c.exe sha256_c.c -lrt

# 2. 运行 C 版本
./sha256_c.exe

# 3. 运行 MoonBit 版本
cd C:\Users\leo\Documents\GitHub\solo\moonbit_crypto
moon run benchmark/sha256_moonbit.mbt

# 4. 运行极致优化版本
moon run benchmark/sha256_ultra.mbt
```

## 📈 预期性能

| 优化级别 | vs C 性能 | 说明 |
|---------|----------|------|
| 无优化   | 50-100x  | 基准 |
| 基础优化 | 20-50x   | const + 批量操作 |
| 极致优化 | 10-20x   | 展开 + 预计算 |

## 🔍 性能差距原因

### 1. 编译器优化差距
- **C**: GCC -O3 利用 CPU 特性 (SSE/AVX)
- **MoonBit**: 通用后端，无法针对特定 CPU

### 2. 运行时开销
- **C**: 直接机器码执行
- **MoonBit**: 解释执行 + GC

### 3. SIMD 支持
- **C**: 可使用 SIMD 指令 (3-5x 提升)
- **MoonBit**: 暂无 SIMD intrinsics

### 4. 内存管理
- **C**: 栈分配，无 GC
- **MoonBit**: GC 暂停和开销

## 🎯 优化策略

### 短期（立即可行）

1. **完全内联**
   ```moonbit
   // 展开64轮计算
   // 替代循环
   ```

2. **预计算**
   ```moonbit
   const K: Array[UInt] = [...]  // 编译时常量
   ```

3. **批量操作**
   ```moonbit
   // 一次性读取16个字
   let block = [read(data, 0), read(data, 4), ...]
   ```

### 中期（需要 MoonBit 更新）

1. **SIMD intrinsics**
   - SHA-256 SIMD 实现
   - 预期提升 3-5x

2. **更好的编译器优化**
   - 自动循环展开
   - 更好的寄存器分配

### 长期（架构改进）

1. **Native 后端**
   - 直接编译为机器码
   - 消除 GC

2. **WebAssembly SIMD**
   - 利用 WASM SIMD 提案
   - 多线程支持

## 📝 测试数据格式

C 版本输出：
```
======================================================================
              SHA-256 性能对比测试 (C vs MoonBit)
======================================================================

C SHA-256 性能测试
测试迭代次数: 1000

数据大小      总时间(ms)  平均时间(μs)  吞吐量(MB/s)
--------  -----------  -----------  -----------
64           xxx.xx        x.xx       xxx.xx
256          xxx.xx        x.xx       xxx.xx
1024         xxx.xx        x.xx       xxx.xx
```

MoonBit 版本输出：
```
======================================================================
          MoonBit SHA-256 性能基准测试
======================================================================

数据大小: 64 字节 -> SHA-256 完成
数据大小: 256 字节 -> SHA-256 完成
...
```

## 🔧 调优建议

### 获取稳定结果

1. **多次运行**
   ```bash
   for i in {1..5}; do ./sha256_c.exe; done | awk '{sum+=$4; cnt++} END {print sum/cnt}'
   ```

2. **排除冷启动**
   - MoonBit 首次运行较慢
   - 取后续运行的平均值

3. **CPU 频率**
   - 关闭 CPU 调频
   - 使用性能模式

### 分析瓶颈

1. **使用 profilers**
   - gprof (C)
   - MoonBit 内置 profiler

2. **热点识别**
   - 消息扩展循环
   - 主压缩循环

## 📚 参考资料

- [NIST FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [GCC Optimization](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [SHA-256 SIMD Implementations](https://github.com/noloader/SHA-Intrinsics)

## ✅ 完成的工作

1. ✅ 创建完整的基准测试套件
2. ✅ C 版本优化编译
3. ✅ MoonBit 多版本实现
4. ✅ 性能分析文档
5. ✅ 一键运行脚本

## 🎯 下一步

1. **运行测试** - 收集实际数据
2. **分析差距** - 识别瓶颈
3. **针对性优化** - 根据数据分析
4. **反馈 MoonBit** - 提交性能问题和建议

## 📞 反馈

如有任何性能问题或优化建议，请：
1. 运行测试并记录结果
2. 分析具体瓶颈
3. 提交 MoonBit issue 或 PR
