#!/usr/bin/env python3
"""
性能测试脚本
测试加密系统性能和资源消耗
"""

import time
import sys
import os
import gc
import platform
import psutil

try:
    import threading
    import asyncio
    HAS_ASYNCIO = True
except ImportError:
    HAS_ASYNCIO = False

class PerformanceTester:
    """性能测试器"""
    
    def __init__(self):
        self.results = {}
        self.process = psutil.Process(os.getpid())
        
    def format_time(self, seconds):
        """格式化时间"""
        if seconds < 0.001:
            return f"{seconds * 1000000:.2f} 微秒"
        elif seconds < 1:
            return f"{seconds * 1000:.2f} 毫秒"
        else:
            return f"{seconds:.2f} 秒"
    
    def get_memory_usage(self):
        """获取内存使用"""
        mem_info = self.process.memory_info()
        return mem_info.rss / 1024 / 1024  # MB
    
    def get_cpu_usage(self):
        """获取CPU使用率"""
        return self.process.cpu_percent(interval=0.1)
    
    def test_sha256(self, iterations=10000):
        """测试 SHA-256 性能"""
        from crypto import sha256
        
        test_data = b"Financial transaction data for testing performance" * 10
        
        gc.collect()
        mem_before = self.get_memory_usage()
        
        start_time = time.time()
        for _ in range(iterations):
            result = sha256(test_data)
        end_time = time.time()
        
        gc.collect()
        mem_after = self.get_memory_usage()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['sha256'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
            'memory_used': mem_after - mem_before
        }
        
        return self.results['sha256']
    
    def test_hmac(self, iterations=10000):
        """测试 HMAC-SHA256 性能"""
        from crypto import hmac_sha256
        
        key = b"secret-key-for-hmac-testing-12345678"
        test_data = b"Message data for HMAC authentication test" * 10
        
        gc.collect()
        
        start_time = time.time()
        for _ in range(iterations):
            result = hmac_sha256(key, test_data)
        end_time = time.time()
        
        gc.collect()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['hmac'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
        }
        
        return self.results['hmac']
    
    def test_aes_encrypt(self, iterations=10000):
        """测试 AES-256-CBC 加密性能"""
        from crypto import aes_256_cbc_encrypt, generate_random_bytes
        
        key = generate_random_bytes(32)
        iv = generate_random_bytes(16)
        plaintext = b"Sensitive financial data requiring encryption" * 20
        
        gc.collect()
        
        start_time = time.time()
        for _ in range(iterations):
            ciphertext = aes_256_cbc_encrypt(key, iv, plaintext)
        end_time = time.time()
        
        gc.collect()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['aes_encrypt'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
        }
        
        return self.results['aes_encrypt']
    
    def test_aes_decrypt(self, iterations=10000):
        """测试 AES-256-CBC 解密性能"""
        from crypto import aes_256_cbc_encrypt, aes_256_cbc_decrypt, generate_random_bytes
        
        key = generate_random_bytes(32)
        iv = generate_random_bytes(16)
        plaintext = b"Sensitive financial data requiring encryption" * 20
        
        ciphertext = aes_256_cbc_encrypt(key, iv, plaintext)
        
        gc.collect()
        
        start_time = time.time()
        for _ in range(iterations):
            result = aes_256_cbc_decrypt(key, iv, ciphertext)
        end_time = time.time()
        
        gc.collect()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['aes_decrypt'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
        }
        
        return self.results['aes_decrypt']
    
    def test_random_bytes(self, iterations=100000):
        """测试随机数生成性能"""
        from crypto import generate_random_bytes
        
        gc.collect()
        
        start_time = time.time()
        for _ in range(iterations):
            result = generate_random_bytes(32)
        end_time = time.time()
        
        gc.collect()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['random_bytes'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
        }
        
        return self.results['random_bytes']
    
    def test_jwt(self, iterations=1000):
        """测试 JWT 性能"""
        from utils.security import security_manager
        
        gc.collect()
        
        start_time = time.time()
        for _ in range(iterations):
            token = security_manager.generate_jwt("user123", ["read", "write"])
            payload = security_manager.verify_jwt(token)
        end_time = time.time()
        
        gc.collect()
        
        elapsed = end_time - start_time
        per_op = elapsed / iterations
        
        self.results['jwt'] = {
            'iterations': iterations,
            'total_time': elapsed,
            'per_operation': per_op,
            'ops_per_second': iterations / elapsed,
        }
        
        return self.results['jwt']
    
    def estimate_concurrency(self):
        """估算并发能力"""
        
        # 基于测试结果估算
        results = self.results
        
        # 计算单个请求的总处理时间
        # 假设一个典型请求需要：
        # 1. JWT 验证 (~0.5ms)
        # 2. HMAC 验证 (~0.1ms)
        # 3. AES 解密 (~0.2ms)
        # 4. 业务处理 (~1ms)
        # 5. AES 加密 (~0.2ms)
        # 6. HMAC 生成 (~0.1ms)
        # 总计约 2.1ms
        
        avg_request_time = 0.0021  # 2.1ms
        
        # 如果有实际测试数据，使用实测值
        if 'jwt' in results and 'hmac' in results and 'aes_decrypt' in results:
            avg_request_time = (
                results['jwt']['per_operation'] +
                results['hmac']['per_operation'] +
                results['aes_decrypt']['per_operation'] +
                0.001  # 业务处理时间
            )
        
        # 2核4G服务器参数
        cpu_cores = 2
        memory_gb = 4
        memory_mb = memory_gb * 1024
        
        # 每个连接估算内存使用
        # - Python asyncio: ~50KB per connection
        # - Request buffer: ~10KB
        # - Response buffer: ~10KB
        # - Security context: ~5KB
        # 总计约 75KB per connection
        memory_per_connection = 0.075  # MB
        
        # CPU估算
        # 单核每秒最大请求数
        max_requests_per_core = 1 / avg_request_time
        
        # 考虑异步IO，CPU利用率通常在 30-70%
        cpu_utilization = 0.5
        
        # 内存限制的最大连接数
        max_by_memory = memory_mb / memory_per_connection
        
        # CPU限制的最大连接数
        max_by_cpu = (max_requests_per_core * cpu_cores * cpu_utilization)
        
        # 取较小值，并考虑一些余量
        max_concurrent = min(max_by_memory, max_by_cpu) * 0.8
        
        return {
            'cpu_cores': cpu_cores,
            'memory_gb': memory_gb,
            'avg_request_time_ms': avg_request_time * 1000,
            'max_requests_per_core': max_requests_per_core,
            'max_by_memory': max_by_memory,
            'max_by_cpu': max_by_cpu,
            'estimated_max_concurrent': max_concurrent,
            'estimated_max_rps': max_concurrent / avg_request_time,
        }
    
    def run_all_tests(self):
        """运行所有测试"""
        print("=" * 70)
        print("金融级 C/S 架构系统 - 性能测试")
        print("=" * 70)
        
        print(f"\n测试环境:")
        print(f"  操作系统: {platform.system()} {platform.release()}")
        print(f"  Python: {platform.python_version()}")
        print(f"  CPU: {platform.processor()}")
        print(f"  当前进程内存: {self.get_memory_usage():.2f} MB")
        
        print("\n" + "=" * 70)
        print("开始性能测试...")
        print("=" * 70)
        
        # SHA-256 测试
        print("\n[1/6] 测试 SHA-256 哈希...")
        result = self.test_sha256(10000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        # HMAC 测试
        print("\n[2/6] 测试 HMAC-SHA256...")
        result = self.test_hmac(10000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        # AES 加密测试
        print("\n[3/6] 测试 AES-256-CBC 加密...")
        result = self.test_aes_encrypt(10000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        # AES 解密测试
        print("\n[4/6] 测试 AES-256-CBC 解密...")
        result = self.test_aes_decrypt(10000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        # 随机数测试
        print("\n[5/6] 测试随机数生成...")
        result = self.test_random_bytes(100000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        # JWT 测试
        print("\n[6/6] 测试 JWT 生成和验证...")
        result = self.test_jwt(1000)
        print(f"  总耗时: {self.format_time(result['total_time'])}")
        print(f"  单次操作: {self.format_time(result['per_operation'])}")
        print(f"  每秒操作数: {result['ops_per_second']:,.0f}")
        
        print("\n" + "=" * 70)
        print("性能测试完成！")
        print("=" * 70)
        
        return self.results
    
    def generate_report(self):
        """生成性能分析报告"""
        estimate = self.estimate_concurrency()
        
        print("\n" + "=" * 70)
        print("2核4G 服务器性能预估")
        print("=" * 70)
        
        print(f"\n服务器配置:")
        print(f"  CPU 核心数: {estimate['cpu_cores']} 核")
        print(f"  内存大小: {estimate['memory_gb']} GB")
        
        print(f"\n性能指标:")
        print(f"  单个请求平均处理时间: {estimate['avg_request_time_ms']:.2f} ms")
        print(f"  单核每秒最大请求数: {estimate['max_requests_per_core']:,.0f} req/s")
        
        print(f"\n并发能力分析:")
        print(f"  内存限制最大连接数: {estimate['max_by_memory']:,.0f}")
        print(f"  CPU限制最大连接数: {estimate['max_by_cpu']:,.0f}")
        print(f"  实际最大并发连接数: {estimate['estimated_max_concurrent']:,.0f}")
        print(f"  预估最大吞吐量: {estimate['estimated_max_rps']:,.0f} req/s")
        
        print("\n" + "=" * 70)
        print("建议")
        print("=" * 70)
        
        if estimate['estimated_max_concurrent'] >= 1000:
            print("✅ 系统性能优秀，可支持高并发场景（如高频交易）")
        elif estimate['estimated_max_concurrent'] >= 500:
            print("⚠️  系统性能良好，可支持中等并发场景")
        elif estimate['estimated_max_concurrent'] >= 200:
            print("⚠️  系统性能一般，建议优化或增加资源")
        else:
            print("❌ 系统性能不足，建议增加服务器资源")
        
        print("\n优化建议:")
        print("1. 使用原生C加密库可提升 5-20 倍性能")
        print("2. 考虑使用负载均衡扩展到多台服务器")
        print("3. 对非关键路径使用缓存减少加密次数")
        print("4. 使用连接池复用资源")
        
        return estimate

def main():
    """主函数"""
    tester = PerformanceTester()
    
    try:
        tester.run_all_tests()
        tester.generate_report()
    except ImportError as e:
        print(f"\n错误: 缺少必要的模块 - {e}")
        print("\n请先安装依赖:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
