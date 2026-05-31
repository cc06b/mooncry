#!/usr/bin/env python3
"""
压测客户端
用于压力测试
"""

import asyncio
import socket
import ssl
import json
import time
import os
import sys
import random
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class StressTester:
    """压力测试器"""
    
    def __init__(self, host='127.0.0.1', port=8443, use_tls=False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.results = defaultdict(list)
        self.errors = 0
        self.successes = 0
        self.start_time = None
        self.end_time = None
        
    async def single_request(self, client_id):
        """单个请求"""
        start_time = time.time()
        
        try:
            # 创建连接
            reader, writer = await asyncio.open_connection(
                self.host,
                self.port
            )
            
            # 准备请求
            request_data = {
                'action': 'ping',
                'client_id': client_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            request = json.dumps(request_data).encode('utf-8')
            
            # 发送请求
            writer.write(request)
            await writer.drain()
            
            # 接收响应
            response_data = await reader.read(4096)
            
            # 关闭连接
            writer.close()
            await writer.wait_closed()
            
            # 记录结果
            elapsed = time.time() - start_time
            self.results['latencies'].append(elapsed)
            self.successes += 1
            return (True, elapsed)
            
        except Exception as e:
            elapsed = time.time() - start_time
            self.errors += 1
            self.results['errors'].append(str(e))
            return (False, elapsed)
    
    async def worker(self, client_id, num_requests):
        """工作线程"""
        for i in range(num_requests):
            await self.single_request(f"{client_id}-{i}")
            await asyncio.sleep(0.0001)  # 微小的延迟，避免拥塞
    
    async def run_test(self, num_clients, requests_per_client):
        """运行测试"""
        print("=" * 70)
        print("压力测试")
        print("=" * 70)
        print(f"\n测试参数:")
        print(f"  客户端数量: {num_clients}")
        print(f"  每客户端请求数: {requests_per_client}")
        print(f"  总请求数: {num_clients * requests_per_client}")
        print(f"  目标服务器: {self.host}:{self.port}")
        
        # 启动计时器
        self.start_time = time.time()
        
        # 创建并启动工作线程
        print(f"\n开始测试 ({datetime.now()})...")
        tasks = []
        for i in range(num_clients):
            task = asyncio.create_task(
                self.worker(f"client-{i}", requests_per_client)
            )
            tasks.append(task)
        
        # 等待所有任务完成
        await asyncio.gather(*tasks)
        
        self.end_time = time.time()
        
        # 生成报告
        print("\n测试完成!")
        print("=" * 70)
        
        self.print_report()
    
    def print_report(self):
        """打印测试报告"""
        total_time = self.end_time - self.start_time
        total_requests = self.successes + self.errors
        total_latencies = len(self.results.get('latencies', []))
        
        print(f"\n测试报告:")
        print("-" * 70)
        print(f"总耗时: {total_time:.2f} 秒")
        print(f"总请求数: {total_requests}")
        print(f"成功请求: {self.successes}")
        print(f"失败请求: {self.errors}")
        print(f"成功率: {(self.successes / total_requests * 100):.2f}%" if total_requests > 0 else "0%")
        
        if total_latencies > 0:
            latencies = self.results['latencies']
            latencies.sort()
            
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            p50 = latencies[int(len(latencies) * 0.5)]
            p95 = latencies[int(len(latencies) * 0.95)]
            p99 = latencies[int(len(latencies) * 0.99)]
            
            print(f"\n延迟统计:")
            print(f"  平均: {avg_latency * 1000:.2f} ms")
            print(f"  最小: {min_latency * 1000:.2f} ms")
            print(f"  最大: {max_latency * 1000:.2f} ms")
            print(f"  P50: {p50 * 1000:.2f} ms")
            print(f"  P95: {p95 * 1000:.2f} ms")
            print(f"  P99: {p99 * 1000:.2f} ms")
        
        if total_time > 0:
            qps = total_requests / total_time
            print(f"\n吞吐量:")
            print(f"  QPS: {qps:.2f} req/s")
        
        if self.errors > 0:
            print(f"\n错误统计 (前5个):")
            for i, error in enumerate(self.results.get('errors', [])[:5]):
                print(f"  {i + 1}. {error}")
        
        print("\n" + "=" * 70)
    
    def save_report(self, filename="stress_test_report.json"):
        """保存报告"""
        report = {
            'test_date': datetime.utcnow().isoformat(),
            'host': self.host,
            'port': self.port,
            'total_time': self.end_time - self.start_time if self.end_time else 0,
            'total_requests': self.successes + self.errors,
            'successes': self.successes,
            'errors': self.errors,
            'latencies': self.results.get('latencies', [])
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n报告已保存到: {filename}")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='压力测试')
    parser.add_argument('--host', default='127.0.0.1', help='服务器地址')
    parser.add_argument('--port', type=int, default=8443, help='服务器端口')
    parser.add_argument('--clients', type=int, default=100, help='并发客户端数')
    parser.add_argument('--requests', type=int, default=10, help='每客户端请求数')
    parser.add_argument('--save', action='store_true', help='保存报告')
    
    args = parser.parse_args()
    
    tester = StressTester(host=args.host, port=args.port)
    
    try:
        asyncio.run(tester.run_test(args.clients, args.requests))
        
        if args.save:
            tester.save_report()
            
    except KeyboardInterrupt:
        print("\n\n测试被中断.")
        if tester.start_time:
            tester.end_time = time.time()
            tester.print_report()

if __name__ == '__main__':
    main()
