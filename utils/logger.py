import logging
import os
from config.config import Config

def setup_logger(name: str = 'financial_system') -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, Config.LOG_LEVEL))
    
    if not logger.handlers:
        os.makedirs(os.path.dirname(Config.LOG_FILE), exist_ok=True)
        
        file_handler = logging.FileHandler(Config.LOG_FILE, encoding='utf-8')
        file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

def log_transaction(logger: logging.Logger, transaction_type: str, user_id: str, 
                   details: dict, success: bool = True):
    log_msg = f"Transaction: {transaction_type} | User: {user_id} | Success: {success}"
    if details:
        log_msg += f" | Details: {details}"
    
    if success:
        logger.info(log_msg)
    else:
        logger.error(log_msg)
