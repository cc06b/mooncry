#!/usr/bin/env python3
"""
SHA-256 性能对比测试 - Python版本
用于对比 MoonBit 实现
"""

import time
import struct
import hashlib

# 常量定义
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sha256_python(data):
    """Python 纯实现的 SHA-256（对比用）"""
    state = H_INIT.copy()

    original_len = len(data)
    bit_len = original_len * 8
    pad_len = 64 - ((original_len + 9) % 64)
    final_len = original_len + 9 + pad_len

    padded = bytearray(final_len)
    padded[:original_len] = data
    padded[original_len] = 0x80

    padded[final_len-8:final_len] = struct.pack('>Q', bit_len)

    for block_idx in range(final_len // 64):
        offset = block_idx * 64
        block = [struct.unpack('>I', padded[offset + i*4 : offset + (i+1)*4])[0] for i in range(16)]

        w = [0] * 64
        for i in range(16):
            w[i] = block[i]

        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (s0 + w[i-7] + s1 + w[i-16]) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = state

        for j in range(64):
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((0xFFFFFFFF ^ e) & g)
            temp1 = (h + s1 + ch + K[j] + w[j]) & 0xFFFFFFFF
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        state[0] = (state[0] + a) & 0xFFFFFFFF
        state[1] = (state[1] + b) & 0xFFFFFFFF
        state[2] = (state[2] + c) & 0xFFFFFFFF
        state[3] = (state[3] + d) & 0xFFFFFFFF
        state[4] = (state[4] + e) & 0xFFFFFFFF
        state[5] = (state[5] + f) & 0xFFFFFFFF
        state[6] = (state[6] + g) & 0xFFFFFFFF
        state[7] = (state[7] + h) & 0xFFFFFFFF

    result = b''
    for val in state:
        result += struct.pack('>I', val)

    return result

def sha256_native(data):
    """使用 Python 的 hashlib（C优化版本）"""
    return hashlib.sha256(data).digest()

def benchmark():
    print("=" * 70)
    print("             Python SHA-256 性能基准测试")
    print("=" * 70)
    print()

    iterations = 100
    sizes = [64, 256, 1024, 4096, 16384, 65536]

    print(f"配置:")
    print(f"  - 迭代次数: {iterations}")
    print(f"  - 数据大小: {sizes}")
    print()
    print("-" * 70)

    for size in sizes:
        data = bytes([i % 256 for i in range(size)])

        print(f"\n数据大小: {size} 字节")

        # Python 纯实现
        start = time.perf_counter()
        for _ in range(iterations):
            hash_py = sha256_python(data)
        elapsed_py = time.perf_counter() - start

        # 原生 C 实现 (hashlib)
        start = time.perf_counter()
        for _ in range(iterations):
            hash_native = sha256_native(data)
        elapsed_native = time.perf_counter() - start

        # 计算吞吐量 (MB/s)
        total_data = size * iterations / (1024 * 1024)
        throughput_py = total_data / elapsed_py if elapsed_py > 0 else 0
        throughput_native = total_data / elapsed_native if elapsed_native > 0 else 0

        print(f"  Python 纯实现:")
        print(f"    总时间: {elapsed_py*1000:.2f} ms")
        print(f"    平均时间: {(elapsed_py*1000000)/iterations:.2f} μs/次")
        print(f"    吞吐量: {throughput_py:.2f} MB/s")

        print(f"  hashlib (C优化):")
        print(f"    总时间: {elapsed_native*1000:.2f} ms")
        print(f"    平均时间: {(elapsed_native*1000000)/iterations:.2f} μs/次")
        print(f"    吞吐量: {throughput_native:.2f} MB/s")

        print(f"  加速比: {elapsed_py/elapsed_native:.1f}x")

    print()
    print("=" * 70)
    print("测试完成!")
    print("=" * 70)

if __name__ == "__main__":
    benchmark()
