import asyncio
import ssl
import json
import struct
from typing import Dict, Optional
from utils.security import security_manager
from utils.logger import setup_logger, log_transaction
from config.config import Config

class FinancialServer:
    def __init__(self):
        self.logger = setup_logger('financial_server')
        self.clients: Dict[str, asyncio.StreamWriter] = {}
        self.user_credentials = {
            'user1': 'password123',
            'user2': 'password456'
        }
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_id = None
        user_id = None
        authenticated = False
        
        try:
            addr = writer.get_extra_info('peername')
            self.logger.info(f'新连接来自 {addr}')
            
            while True:
                data = await self.read_message(reader)
                if not data:
                    break
                
                message = security_manager.deserialize_message(data)
                client_id = message.get('client_id', f'{addr[0]}:{addr[1]}')
                
                if not security_manager.check_rate_limit(client_id):
                    response = {
                        'status': 'error',
                        'message': '请求过于频繁，请稍后再试'
                    }
                    await self.send_message(writer, response)
                    continue
                
                if not authenticated:
                    result = await self.handle_authentication(message, writer)
                    if result.get('authenticated'):
                        authenticated = True
                        user_id = result.get('user_id')
                        self.clients[user_id] = writer
                        self.logger.info(f'用户 {user_id} 已认证')
                else:
                    response = await self.handle_request(message, user_id)
                    await self.send_message(writer, response)
                    
        except Exception as e:
            self.logger.error(f'客户端连接错误: {str(e)}')
        finally:
            if user_id and user_id in self.clients:
                del self.clients[user_id]
            writer.close()
            await writer.wait_closed()
            self.logger.info(f'连接已关闭: {addr}')
    
    async def handle_authentication(self, message: dict, writer: asyncio.StreamWriter) -> dict:
        try:
            if message.get('type') == 'login':
                username = message.get('username')
                password = message.get('password')
                
                if username in self.user_credentials and self.user_credentials[username] == password:
                    token = security_manager.generate_jwt(username, ['read', 'write'])
                    response = {
                        'status': 'success',
                        'authenticated': True,
                        'user_id': username,
                        'token': token
                    }
                    log_transaction(self.logger, 'login', username, {}, True)
                else:
                    response = {
                        'status': 'error',
                        'authenticated': False,
                        'message': '用户名或密码错误'
                    }
                    log_transaction(self.logger, 'login', username, {}, False)
                
                await self.send_message(writer, response)
                return response
            
            return {'authenticated': False}
        except Exception as e:
            self.logger.error(f'认证错误: {str(e)}')
            return {'authenticated': False}
    
    async def handle_request(self, message: dict, user_id: str) -> dict:
        try:
            request_type = message.get('type')
            
            if request_type == 'transfer':
                return await self.handle_transfer(message, user_id)
            elif request_type == 'balance':
                return await self.handle_balance(message, user_id)
            elif request_type == 'logout':
                return await self.handle_logout(user_id)
            else:
                return {
                    'status': 'error',
                    'message': '未知的请求类型'
                }
        except Exception as e:
            self.logger.error(f'请求处理错误: {str(e)}')
            return {
                'status': 'error',
                'message': '服务器内部错误'
            }
    
    async def handle_transfer(self, message: dict, user_id: str) -> dict:
        amount = message.get('amount')
        to_account = message.get('to_account')
        
        log_transaction(self.logger, 'transfer', user_id, 
                       {'amount': amount, 'to_account': to_account}, True)
        
        return {
            'status': 'success',
            'message': f'转账成功: {amount} 到 {to_account}',
            'transaction_id': security_manager.hash_data(f'{user_id}{amount}{to_account}')
        }
    
    async def handle_balance(self, message: dict, user_id: str) -> dict:
        log_transaction(self.logger, 'balance_query', user_id, {}, True)
        
        return {
            'status': 'success',
            'balance': 10000.00,
            'currency': 'CNY'
        }
    
    async def handle_logout(self, user_id: str) -> dict:
        log_transaction(self.logger, 'logout', user_id, {}, True)
        
        return {
            'status': 'success',
            'message': '已登出'
        }
    
    async def read_message(self, reader: asyncio.StreamReader) -> Optional[str]:
        try:
            header_data = await reader.readexactly(4)
            message_length = struct.unpack('!I', header_data)[0]
            
            if message_length > Config.MAX_REQUEST_SIZE:
                raise Exception('消息过大')
            
            message_data = await reader.readexactly(message_length)
            return message_data.decode('utf-8')
        except asyncio.IncompleteReadError:
            return None
        except Exception as e:
            self.logger.error(f'读取消息错误: {str(e)}')
            return None
    
    async def send_message(self, writer: asyncio.StreamWriter, message: dict):
        try:
            message_str = security_manager.serialize_message(message)
            message_data = message_str.encode('utf-8')
            header = struct.pack('!I', len(message_data))
            
            writer.write(header + message_data)
            await writer.drain()
        except Exception as e:
            self.logger.error(f'发送消息错误: {str(e)}')
    
    def create_ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
        context.load_cert_chain(
            certfile=Config.TLS_CERT_PATH,
            keyfile=Config.TLS_KEY_PATH
        )
        context.verify_mode = ssl.CERT_NONE
        return context
    
    async def start(self):
        ssl_context = self.create_ssl_context()
        
        server = await asyncio.start_server(
            self.handle_client,
            Config.SERVER_HOST,
            Config.SERVER_PORT,
            ssl=ssl_context
        )
        
        addr = server.sockets[0].getsockname()
        self.logger.info(f'金融服务器启动在 {addr}')
        
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    server = FinancialServer()
    asyncio.run(server.start())
