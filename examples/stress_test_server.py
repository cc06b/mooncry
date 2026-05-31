#!/usr/bin/env python3
"""
简化的压测服务器
用于压力测试
"""

import asyncio
import socket
import ssl
import json
import time
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.security import security_manager

class MockServer:
    """模拟服务器，用于压测"""
    
    def __init__(self, host='0.0.0.0', port=8443, use_tls=False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.request_count = 0
        self.start_time = None
        
    async def handle_client(self, reader, writer):
        """处理客户端连接"""
        client_id = id(writer)
        
        try:
            # 读取请求
            data = await reader.read(4096)
            if not data:
                return
            
            self.request_count += 1
            
            # 模拟处理时间
            await asyncio.sleep(0.002)
            
            # 返回简单响应
            response = {
                'status': 'success',
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': client_id
            }
            
            response_data = json.dumps(response).encode('utf-8')
            
            writer.write(response_data)
            await writer.drain()
            
        except Exception as e:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def start(self):
        """启动服务器"""
        self.start_time = time.time()
        print(f"[Server] 压测服务器启动在 {self.host}:{self.port}")
        
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        print(f"[Server] 监听中...")
        print(f"[Server] 按 Ctrl+C 停止")
        
        async with server:
            await server.serve_forever()
    
    def get_stats(self):
        """获取统计信息"""
        elapsed = 0
        if self.start_time:
            elapsed = time.time() - self.start_time
        
        return {
            'total_requests': self.request_count,
            'elapsed_seconds': elapsed,
            'qps': self.request_count / elapsed if elapsed > 0 else 0
        }

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='压测服务器')
    parser.add_argument('--host', default='0.0.0.0', help='监听地址')
    parser.add_argument('--port', type=int, default=8443, help='监听端口')
    args = parser.parse_args()
    
    server = MockServer(host=args.host, port=args.port)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[Server] 正在停止...")
        stats = server.get_stats()
        print(f"[Server] 总请求: {stats['total_requests']}")
        print(f"[Server] 总耗时: {stats['elapsed_seconds']:.2f}s")
        print(f"[Server] QPS: {stats['qps']:.0f}")

if __name__ == '__main__':
    main()
