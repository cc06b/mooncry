#!/usr/bin/env python3
"""
性能基准测试 - 对比优化效果
"""

import os
import time
import hashlib


def benchmark_aes_vs_hashlib():
    """AES vs hashlib 性能对比"""
    print("=" * 80)
    print("AES 性能测试（对比 hashlib 的 SHA256）")
    print("=" * 80)
    
    # 使用优化版本的 AES
    from optimized_crypto import OptimizedAES
    
    key = b'0123456789abcdef'
    iv = b'0123456789abcdef'
    data_sizes = [64, 256, 1024, 4096]
    
    aes = OptimizedAES(key, 'CBC')
    
    print(f"\n{'数据大小':<12} {'AES吞吐量':<18} {'SHA256吞吐量':<18} {'AES延迟(μs)':<15} {'SHA256延迟(μs)':<15}")
    print("-" * 80)
    
    for size in data_sizes:
        data = os.urandom(size)
        iterations = max(100, 10000 // size)
        
        # AES 测试
        start = time.time()
        for _ in range(iterations):
            encrypted = aes.encrypt(data, iv)
        aes_elapsed = time.time() - start
        aes_throughput = (size * iterations) / (1024 * 1024 * aes_elapsed)
        aes_latency = (aes_elapsed / iterations) * 1000000
        
        # SHA256 测试 (使用优化的实现)
        from optimized_crypto import OptimizedSHA256
        sha256 = OptimizedSHA256()
        
        start = time.time()
        for _ in range(iterations):
            hash_result = sha256.sha256(data)
        sha_elapsed = time.time() - start
        sha_throughput = (size * iterations) / (1024 * 1024 * sha_elapsed)
        sha_latency = (sha_elapsed / iterations) * 1000000
        
        print(f"{size:<12} {aes_throughput:<18.2f} {sha_throughput:<18.2f} {aes_latency:<15.2f} {sha_latency:<15.2f}")
    
    print()


def benchmark_optimization_techniques():
    """展示优化技术效果"""
    print("=" * 80)
    print("优化技术分析")
    print("=" * 80)
    
    print("\n1. AES 优化技术:")
    print("   - T-table 查表加速")
    print("   - 批量块处理")
    print("   - 减少中间变量分配")
    print("   - 预计算轮密钥")
    
    print("\n2. SHA-256 优化技术:")
    print("   - 预计算 K 常量数组")
    print("   - 批量块处理")
    print("   - 减少函数调用开销")
    print("   - 内联位操作")
    
    print("\n3. ECDSA 优化技术:")
    print("   - 窗口化标量乘法")
    print("   - Jacobian 坐标转换")
    print("   - 预计算常用值")


def run_complete_benchmark():
    """完整的性能基准测试"""
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 25 + "加密库性能基准测试" + " " * 25 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    # 优化技术分析
    benchmark_optimization_techniques()
    print()
    
    # 性能测试
    benchmark_aes_vs_hashlib()
    
    # 理论性能分析
    print("=" * 80)
    print("理论性能分析")
    print("=" * 80)
    
    print("\nPython 实现（当前）:")
    print("   - SHA-256:     ~1-5 MB/s (单线程)")
    print("   - AES-128:     ~0.1-1 MB/s (单线程)")
    print("   - HMAC-SHA256: ~0.5-3 MB/s (单线程)")
    
    print("\nMoonBit 实现（预期）:")
    print("   - SHA-256:     ~50-200 MB/s (单线程)")
    print("   - AES-128:     ~10-50 MB/s (单线程)")
    print("   - HMAC-SHA256: ~30-100 MB/s (单线程)")
    
    print("\nMoonBit + SIMD 优化（理论）:")
    print("   - SHA-256:     ~500-2000 MB/s")
    print("   - AES-128:     ~100-500 MB/s")
    print("   - HMAC-SHA256: ~300-1500 MB/s")
    
    print("\nMoonBit + ASM 优化（理论上限）:")
    print("   - SHA-256:     ~2000-10000 MB/s")
    print("   - AES-128:     ~500-3000 MB/s")
    print("   - HMAC-SHA256: ~1500-8000 MB/s")
    
    print()
    print("=" * 80)
    print("🎉 性能基准测试完成！")
    print("=" * 80)


if __name__ == '__main__':
    run_complete_benchmark()
