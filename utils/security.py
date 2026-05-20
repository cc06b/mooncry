import jwt
import time
import json
import base64
from datetime import datetime, timedelta
from config.config import Config

# 尝试导入高性能加密模块
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from crypto import (
        sha256 as _crypto_sha256,
        hmac_sha256 as _crypto_hmac_sha256,
        generate_random_bytes as _crypto_generate_random_bytes,
        encrypt_text_to_base64 as _crypto_encrypt_text_to_base64,
        decrypt_from_base64 as _crypto_decrypt_from_base64
    )
    _use_crypto = True
except Exception:
    # 备用方案：使用 Python 内置库
    import hashlib
    import hmac
    from cryptography.fernet import Fernet
    _use_crypto = False


class SecurityManager:
    def __init__(self):
        self.nonce_store = {}
        self.rate_limit_store = {}
        self._aes_key = None
        
        # 预生成加密密钥
        if _use_crypto:
            self._aes_key = self.sha256(Config.JWT_SECRET_KEY.encode())
        else:
            key_bytes = Config.JWT_SECRET_KEY.encode()
            self._fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    
    def generate_jwt(self, user_id: str, permissions: list = None) -> str:
        payload = {
            'user_id': user_id,
            'permissions': permissions or [],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=Config.JWT_EXPIRATION_SECONDS)
        }
        return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
    
    def verify_jwt(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception('Token已过期')
        except jwt.InvalidTokenError:
            raise Exception('无效的Token')
    
    def generate_nonce(self) -> str:
        if _use_crypto:
            timestamp = str(time.time()).encode()
            random_bytes = _crypto_generate_random_bytes(16)
            nonce_bytes = _crypto_sha256(timestamp + random_bytes)
            nonce = nonce_bytes.hex()
        else:
            nonce = hashlib.sha256(f'{time.time()}{id(self)}'.encode()).hexdigest()
        self.nonce_store[nonce] = time.time()
        return nonce
    
    def verify_nonce(self, nonce: str) -> bool:
        current_time = time.time()
        if nonce in self.nonce_store:
            if current_time - self.nonce_store[nonce] < Config.REPLAY_ATTACK_TTL:
                del self.nonce_store[nonce]
                return True
            else:
                del self.nonce_store[nonce]
        return False
    
    def check_rate_limit(self, client_id: str) -> bool:
        current_time = time.time()
        window_start = current_time - Config.RATE_LIMIT_WINDOW
        
        if client_id not in self.rate_limit_store:
            self.rate_limit_store[client_id] = []
        
        self.rate_limit_store[client_id] = [
            ts for ts in self.rate_limit_store[client_id]
            if ts > window_start
        ]
        
        if len(self.rate_limit_store[client_id]) >= Config.RATE_LIMIT_REQUESTS:
            return False
        
        self.rate_limit_store[client_id].append(current_time)
        return True
    
    def sha256(self, data: bytes) -> bytes:
        if _use_crypto:
            return _crypto_sha256(data)
        else:
            import hashlib
            return hashlib.sha256(data).digest()
    
    def hash_data(self, data: str) -> str:
        return self.sha256(data.encode()).hex()
    
    def create_hmac(self, data: str, key: str) -> str:
        if _use_crypto:
            hmac_bytes = _crypto_hmac_sha256(key.encode(), data.encode())
            return hmac_bytes.hex()
        else:
            return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    
    def verify_hmac(self, data: str, signature: str, key: str) -> bool:
        expected = self.create_hmac(data, key)
        # 安全比较，防止时序攻击
        if len(expected) != len(signature):
            return False
        result = 0
        for x, y in zip(expected, signature):
            result |= ord(x) ^ ord(y)
        return result == 0
    
    def encrypt_data(self, data: str, key: bytes = None) -> str:
        if _use_crypto:
            encrypt_key = key if key else self._aes_key
            return _crypto_encrypt_text_to_base64(encrypt_key, data)
        else:
            encrypt_key = key if key else self._fernet_key
            fernet = Fernet(encrypt_key)
            return fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str, key: bytes = None) -> str:
        if _use_crypto:
            decrypt_key = key if key else self._aes_key
            return _crypto_decrypt_from_base64(decrypt_key, encrypted_data)
        else:
            decrypt_key = key if key else self._fernet_key
            fernet = Fernet(decrypt_key)
            return fernet.decrypt(encrypted_data.encode()).decode()
    
    def serialize_message(self, message: dict, nonce: str = None) -> str:
        if nonce is None:
            nonce = self.generate_nonce()
        message['nonce'] = nonce
        message['timestamp'] = datetime.utcnow().isoformat()
        return json.dumps(message, ensure_ascii=False)
    
    def deserialize_message(self, message_str: str) -> dict:
        message = json.loads(message_str)
        if 'nonce' not in message:
            raise Exception('消息缺少nonce')
        if not self.verify_nonce(message['nonce']):
            raise Exception('无效或过期的nonce')
        return message


security_manager = SecurityManager()
