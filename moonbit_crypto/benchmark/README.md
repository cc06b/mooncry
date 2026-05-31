# MoonBit Crypto Library - 性能基准测试

本目录包含 SHA-256 的性能基准测试，用于对比 C 和 MoonBit 实现的性能差异。

## 文件说明

- `sha256_c.c` - C 优化版本（使用 -O3 编译）
- `sha256_moonbit.mbt` - MoonBit 标准版本
- `sha256_ultra.mbt` - MoonBit 极致优化版本
- `run_benchmark.bat` - Windows 一键运行脚本
- `PERFORMANCE_ANALYSIS.md` - 性能分析文档

## 快速开始

### Windows

双击运行 `run_benchmark.bat` 或在命令行执行：

```cmd
cd C:\Users\leo\Documents\GitHub\solo\moonbit_crypto\benchmark
run_benchmark.bat
```

### 单独运行 C 版本

```bash
gcc -O3 -march=native -o sha256_c.exe sha256_c.c -lrt
./sha256_c.exe
```

### 单独运行 MoonBit 版本

```bash
cd C:\Users\leo\Documents\GitHub\solo\moonbit_crypto
moon run benchmark/sha256_moonbit.mbt
```

### 运行极致优化版本

```bash
moon run benchmark/sha256_ultra.mbt
```

## 测试配置

```c
// C 版本配置
int iterations = 1000;
int sizes[] = {64, 256, 1024, 4096, 16384, 65536, 262144};
```

```moonbit
// MoonBit 版本配置
let iterations = 1000
let sizes = [64, 256, 1024, 4096, 16384, 65536, 262144]
```

## 预期结果

| 数据大小 | C 吞吐量 | MoonBit 吞吐量 | 差距 |
|---------|---------|----------------|------|
| 64 B    | ~200 MB/s | ~10 MB/s    | ~20x |
| 1 KB    | ~500 MB/s | ~40 MB/s    | ~12x |
| 16 KB   | ~800 MB/s | ~120 MB/s   | ~7x  |
| 256 KB  | ~1 GB/s   | ~200 MB/s   | ~5x  |

## 性能差距原因

1. **编译器优化**: C 使用 -O3 和 CPU 特定优化
2. **SIMD**: C 可使用 SSE/AVX，MoonBit 暂无
3. **GC**: MoonBit 有垃圾回收开销
4. **边界检查**: MoonBit 可能添加安全检查

## 进一步优化

查看 `PERFORMANCE_ANALYSIS.md` 了解详细的优化策略和未来方向。

## 注意事项

- MoonBit 当前版本未提供精确计时 API
- C 版本使用 `clock_gettime()` 获取纳秒精度
- 建议多次运行取平均值以获得稳定结果
