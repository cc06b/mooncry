import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # 服务端配置
    SERVER_HOST = os.getenv('SERVER_HOST', '0.0.0.0')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 8443))
    
    # TLS/SSL 配置
    TLS_CERT_PATH = os.getenv('TLS_CERT_PATH', 'certs/server.crt')
    TLS_KEY_PATH = os.getenv('TLS_KEY_PATH', 'certs/server.key')
    TLS_CA_CERT_PATH = os.getenv('TLS_CA_CERT_PATH', 'certs/ca.crt')
    
    # JWT 配置
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_SECONDS = 3600  # 1小时
    
    # 安全配置
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # 秒
    REPLAY_ATTACK_TTL = 300  # 5分钟
    
    # 日志配置
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/app.log')
