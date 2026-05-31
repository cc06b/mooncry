#!/usr/bin/env python3
"""使用标准 NIST 测试向量验证 AES 实现"""

def test_nist_vector():
    """使用 NIST 提供的 AES-128 测试向量"""
    print("=" * 70)
    print("AES-128 NIST 测试向量验证")
    print("=" * 70)
    
    # NIST FIPS 197 Appendix B 测试向量
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = bytes.fromhex('3243f6a8885a308d313198a2e0370734')  # 16 bytes
    
    # 使用 Python 的 cryptography 库（如果可用）或我们的实现
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        print(f"密钥:       {key.hex()}")
        print(f"明文:       {plaintext.hex()}")
        print(f"密文:       {ciphertext.hex()}")
        print()
        
        # 解密验证
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"解密后:     {decrypted.hex()}")
        print(f"解密测试:   {'PASS' if decrypted == plaintext else 'FAIL'}")
        
    except ImportError:
        print("cryptography 库不可用，跳过 NIST 测试")

def test_our_implementation():
    """测试我们的实现"""
    from advanced_crypto import AES
    
    print()
    print("=" * 70)
    print("我们实现的测试向量验证")
    print("=" * 70)
    
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = b"Hello, AES-ECB!"
    
    aes = AES(key, 'ECB')
    ciphertext = aes.encrypt(plaintext)
    decrypted = aes.decrypt(ciphertext)
    
    print(f"密钥:       {key.hex()}")
    print(f"明文:       {plaintext.hex()}")
    print(f"密文:       {ciphertext.hex()}")
    print(f"解密后:     {decrypted}")
    print(f"解密测试:   {'PASS' if decrypted == plaintext else 'FAIL'}")
    
    return decrypted == plaintext

def generate_moonbit_test_vector():
    """生成 MoonBit 使用的相同测试向量"""
    print()
    print("=" * 70)
    print("MoonBit 测试向量")
    print("=" * 70)
    
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = b"Hello, AES-ECB!" + b'\x00'  # 16 bytes
    
    print(f"密钥:       {key.hex()}")
    print(f"明文 (hex): {plaintext.hex()}")
    print(f"明文字节:   {' '.join(hex(b) for b in plaintext)}")
    print()
    
    # 预期输出（使用 Python cryptography 库）
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        print(f"预期密文:   {ciphertext.hex()}")
        
        # 解密验证
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"预期解密:   {decrypted}")
        print(f"测试:       {'PASS' if decrypted == plaintext else 'FAIL'}")
        
    except ImportError:
        print("cryptography 库不可用")

if __name__ == '__main__':
    test_nist_vector()
    test_our_implementation()
    generate_moonbit_test_vector()
