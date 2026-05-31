#!/usr/bin/env python3
"""
自动化压测脚本
进行多层次压力测试
"""

import sys
import os
import time
import json
import subprocess
import asyncio
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.stress_test_client import StressTester

class AutoStressTest:
    """自动化压测"""
    
    def __init__(self):
        self.all_results = []
        
    async def test_concurrent_level(self, level, num_clients, requests_per_client):
        """测试不同并发级别"""
        print(f"\n{'=' * 70}")
        print(f"测试 Level {level} - 并发数: {num_clients}")
        print('=' * 70)
        
        tester = StressTester('127.0.0.1', 8443)
        tester.start_time = time.time()
        
        await tester.run_test(num_clients, requests_per_client)
        
        tester.end_time = time.time()
        
        # 收集结果
        result = {
            'level': level,
            'num_clients': num_clients,
            'total_requests': num_clients * requests_per_client,
            'successes': tester.successes,
            'errors': tester.errors,
            'total_time': tester.end_time - tester.start_time,
        }
        
        if len(tester.results.get('latencies', [])) > 0:
            latencies = tester.results['latencies']
            latencies.sort()
            result['avg_latency'] = sum(latencies) / len(latencies)
            result['p50'] = latencies[int(len(latencies) * 0.5)]
            result['p95'] = latencies[int(len(latencies) * 0.95)]
            result['p99'] = latencies[int(len(latencies) * 0.99)]
        
        self.all_results.append(result)
        
        return result
        
    async def run_all_tests(self):
        """运行所有测试"""
        print("=" * 70)
        print("金融级 C/S 架构系统 - 自动化压测")
        print("=" * 70)
        
        # 定义测试级别
        test_levels = [
            (1, 50, 10),    # Level 1: 50并发
            (2, 100, 10),   # Level 2: 100并发
            (3, 200, 10),   # Level 3: 200并发
            (4, 500, 5),    # Level 4: 500并发
            (5, 1000, 3),   # Level 5: 1000并发
            (6, 1500, 2),   # Level 6: 1500并发
        ]
        
        print(f"\n测试配置:")
        print(f"  测试级别: {len(test_levels)}")
        print(f"  范围: 50 - 1500 并发")
        print(f"  每级别等待: 5秒")
        
        for level, num_clients, requests in test_levels:
            print(f"\n等待 5 秒后开始...")
            await asyncio.sleep(5)
            
            await self.test_concurrent_level(level, num_clients, requests)
        
        # 打印汇总报告
        self.print_summary()
        
    def print_summary(self):
        """打印汇总报告"""
        print("\n" + "=" * 70)
        print("压测汇总报告")
        print("=" * 70)
        
        print(f"\n{'Level':<8} {'Concurrency':<12} {'QPS':<10} {'Avg(ms)':<10} {'P50(ms)':<10} {'P95(ms)':<10} {'P99(ms)':<10}")
        print("-" * 70)
        
        for result in self.all_results:
            qps = result['successes'] / result['total_time'] if result['total_time'] > 0 else 0
            print(f"{result['level']:<8} {result['num_clients']:<12} {qps:<10.0f} "
                  f"{result.get('avg_latency', 0) * 1000:<10.2f} "
                  f"{result.get('p50', 0) * 1000:<10.2f} "
                  f"{result.get('p95', 0) * 1000:<10.2f} "
                  f"{result.get('p99', 0) * 1000:<10.2f}")
        
        print("\n" + "=" * 70)
        
        # 保存报告
        self.save_report()
    
    def save_report(self):
        """保存汇总报告"""
        report = {
            'test_date': datetime.utcnow().isoformat(),
            'results': self.all_results
        }
        
        filename = "auto_stress_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n报告已保存到: {filename}")

def main():
    """主函数"""
    print("=" * 70)
    print("自动化压测启动")
    print("=" * 70)
    print("\n注意:")
    print("1. 请确保先启动压测服务器 (另一个终端):")
    print("   python examples/stress_test_server.py")
    print("\n2. 按 Ctrl+C 可中断测试")
    
    try:
        input("\n按 Enter 键开始...")
    except KeyboardInterrupt:
        print("\n测试取消")
        return
        
    auto_test = AutoStressTest()
    try:
        asyncio.run(auto_test.run_all_tests())
    except KeyboardInterrupt:
        print("\n\n测试被中断")
        if auto_test.all_results:
            auto_test.print_summary()

if __name__ == '__main__':
    main()
