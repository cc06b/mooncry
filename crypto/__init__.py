"""
Financial Crypto Module
高性能金融级加密模块
"""

import os
import sys
import base64

# 模块状态
use_native = False
_native_lib = None
_error_msg = None

def _load_native_library():
    """尝试加载原生加密库"""
    global use_native, _native_lib, _error_msg
    
    # 查找动态库名称
    if sys.platform.startswith('win'):
        lib_name = 'financial_crypto.dll'
    elif sys.platform.startswith('darwin'):
        lib_name = 'libfinancial_crypto.dylib'
    else:
        lib_name = 'libfinancial_crypto.so'
    
    # 查找动态库路径
    lib_path = None
    possible_paths = [
        os.path.join(os.path.dirname(__file__), 'build', 'lib', lib_name),
        os.path.join(os.path.dirname(__file__), 'lib', lib_name),
        os.path.join(os.path.dirname(__file__), lib_name),
        lib_name,
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            lib_path = path
            break
    
    if lib_path is None:
        _error_msg = f"Could not find {lib_name}. Please build the library first."
        return False
    
    # 加载动态库
    try:
        import ctypes
        from ctypes import c_uint8, c_size_t, c_int, c_char_p, POINTER, byref
        
        _native_lib = ctypes.CDLL(lib_path)
        
        # 定义返回值和参数类型
        _native_lib.sha256_hash.restype = c_int
        _native_lib.sha256_hash.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_size_t)]
        
        _native_lib.hmac_sha256.restype = c_int
        _native_lib.hmac_sha256.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_size_t)]
        
        _native_lib.aes_256_cbc_encrypt.restype = c_int
        _native_lib.aes_256_cbc_encrypt.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_size_t)]
        
        _native_lib.aes_256_cbc_decrypt.restype = c_int
        _native_lib.aes_256_cbc_decrypt.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_size_t)]
        
        _native_lib.generate_random_bytes.restype = c_int
        _native_lib.generate_random_bytes.argtypes = [POINTER(c_uint8), c_size_t]
        
        _native_lib.crypto_result_to_string.restype = c_char_p
        _native_lib.crypto_result_to_string.argtypes = [c_int]
        
        use_native = True
        return True
        
    except Exception as e:
        _error_msg = f"Failed to load {lib_name}: {e}"
        return False

# 尝试加载原生库
_load_native_library()

def sha256(data: bytes) -> bytes:
    """
    SHA-256 哈希函数
    
    Args:
        data: 要哈希的数据
        
    Returns:
        哈希结果 (32 bytes)
    """
    if not use_native:
        import hashlib
        return hashlib.sha256(data).digest()
    
    import ctypes
    from ctypes import c_uint8, c_size_t, byref
    
    output_len = c_size_t(32)
    output = (c_uint8 * 32)()
    
    result = _native_lib.sha256_hash(
        (c_uint8 * len(data))(*data),
        c_size_t(len(data)),
        output,
        byref(output_len)
    )
    
    if result != 0:
        error_msg = _native_lib.crypto_result_to_string(result).decode('utf-8')
        raise Exception(f"SHA-256 error: {error_msg}")
    
    return bytes(output)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    HMAC-SHA256 消息认证码
    
    Args:
        key: 密钥
        data: 要认证的数据
        
    Returns:
        HMAC 结果 (32 bytes)
    """
    if not use_native:
        import hmac
        import hashlib
        return hmac.new(key, data, hashlib.sha256).digest()
    
    import ctypes
    from ctypes import c_uint8, c_size_t, byref
    
    output_len = c_size_t(32)
    output = (c_uint8 * 32)()
    
    result = _native_lib.hmac_sha256(
        (c_uint8 * len(key))(*key),
        c_size_t(len(key)),
        (c_uint8 * len(data))(*data),
        c_size_t(len(data)),
        output,
        byref(output_len)
    )
    
    if result != 0:
        error_msg = _native_lib.crypto_result_to_string(result).decode('utf-8')
        raise Exception(f"HMAC-SHA256 error: {error_msg}")
    
    return bytes(output)

def aes_256_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC 加密
    
    Args:
        key: 32字节密钥
        iv: 16字节初始化向量
        plaintext: 明文
        
    Returns:
        密文 (包含PKCS#7填充)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long for AES-256")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long")
    
    if not use_native:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # PKCS#7 padding
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len]) * pad_len
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    
    import ctypes
    from ctypes import c_uint8, c_size_t, byref
    
    output_len = c_size_t(len(plaintext) + 16)
    output = (c_uint8 * (len(plaintext) + 16))()
    
    result = _native_lib.aes_256_cbc_encrypt(
        (c_uint8 * 32)(*key),
        c_size_t(32),
        (c_uint8 * 16)(*iv),
        c_size_t(16),
        (c_uint8 * len(plaintext))(*plaintext),
        c_size_t(len(plaintext)),
        output,
        byref(output_len)
    )
    
    if result != 0:
        error_msg = _native_lib.crypto_result_to_string(result).decode('utf-8')
        raise Exception(f"AES-256-CBC encryption error: {error_msg}")
    
    return bytes(output[:output_len.value])

def aes_256_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-256-CBC 解密
    
    Args:
        key: 32字节密钥
        iv: 16字节初始化向量
        ciphertext: 密文
        
    Returns:
        明文
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long for AES-256")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long")
    
    if not use_native:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        pad_len = padded[-1]
        return padded[:-pad_len]
    
    import ctypes
    from ctypes import c_uint8, c_size_t, byref
    
    output_len = c_size_t(len(ciphertext))
    output = (c_uint8 * len(ciphertext))()
    
    result = _native_lib.aes_256_cbc_decrypt(
        (c_uint8 * 32)(*key),
        c_size_t(32),
        (c_uint8 * 16)(*iv),
        c_size_t(16),
        (c_uint8 * len(ciphertext))(*ciphertext),
        c_size_t(len(ciphertext)),
        output,
        byref(output_len)
    
    if result != 0:
        error_msg = _native_lib.crypto_result_to_string(result).decode('utf-8')
        raise Exception(f"AES-256-CBC decryption error: {error_msg}")
    
    return bytes(output[:output_len.value])

def generate_random_bytes(length: int) -> bytes:
    """
    生成随机字节
    
    Args:
        length: 要生成的字节数
        
    Returns:
        随机字节
    """
    if not use_native:
        import secrets
        return secrets.token_bytes(length)
    
    import ctypes
    from ctypes import c_uint8, c_size_t, byref
    
    output = (c_uint8 * length)()
    
    result = _native_lib.generate_random_bytes(output, c_size_t(length))
    
    if result != 0:
        error_msg = _native_lib.crypto_result_to_string(result).decode('utf-8')
        raise Exception(f"Random bytes generation error: {error_msg}")
    
    return bytes(output)

def encrypt_text_to_base64(key: bytes, plaintext: str) -> str:
    """
    加密文本并返回Base64编码的密文
    
    Args:
        key: 32字节密钥
        plaintext: 要加密的文本
        
    Returns:
        Base64编码的密文 (包含IV)
    """
    iv = generate_random_bytes(16)
    ciphertext = aes_256_cbc_encrypt(key, iv, plaintext.encode('utf-8'))
    combined = iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_from_base64(key: bytes, encrypted_base64: str) -> str:
    """
    解密Base64编码的密文
    
    Args:
        key: 32字节密钥
        encrypted_base64: Base64编码的密文 (包含IV)
        
    Returns:
        解密后的文本
    """
    combined = base64.b64decode(encrypted_base64)
    if len(combined) < 16:
        raise ValueError("Invalid encrypted data")
    
    iv = combined[:16]
    ciphertext = combined[16:]
    plaintext = aes_256_cbc_decrypt(key, iv, ciphertext)
    return plaintext.decode('utf-8')

__all__ = [
    'sha256',
    'hmac_sha256',
    'aes_256_cbc_encrypt',
    'aes_256_cbc_decrypt',
    'generate_random_bytes',
    'encrypt_text_to_base64',
    'decrypt_from_base64'
]
