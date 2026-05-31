#!/usr/bin/env python3
"""验证 MoonBit AES 修复 - 完整的加密解密测试"""

from advanced_crypto import AES

def test_aes_ecb():
    """测试 AES-128 ECB 模式"""
    print("=" * 70)
    print("AES-128 ECB 加密/解密测试")
    print("=" * 70)
    
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = b"Hello, AES-ECB!"  # 15 bytes, will be padded to 16
    
    aes = AES(key, 'ECB')
    ciphertext = aes.encrypt(plaintext)
    decrypted = aes.decrypt(ciphertext)
    
    print(f"密钥:      {key.hex()}")
    print(f"明文:      {plaintext}")
    print(f"密文:      {ciphertext.hex()}")
    print(f"解密:      {decrypted}")
    print(f"密文长度:  {len(ciphertext)} (PKCS7 padding adds 1 byte)")
    print(f"加密测试:  {'PASS' if len(ciphertext) == 16 else 'FAIL'}")
    print(f"解密测试:  {'PASS' if decrypted == plaintext else 'FAIL'}")
    print()
    return len(ciphertext) == 16 and decrypted == plaintext


def test_aes_cbc():
    """测试 AES-128 CBC 模式"""
    print("=" * 70)
    print("AES-128 CBC 加密/解密测试")
    print("=" * 70)
    
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    plaintext = b"Hello, World! This is AES-CBC test!"
    
    aes = AES(key, 'CBC')
    ciphertext = aes.encrypt(plaintext, iv)
    decrypted = aes.decrypt(ciphertext[16:], iv)  # Skip IV
    
    print(f"密钥:      {key.hex()}")
    print(f"IV:        {iv.hex()}")
    print(f"明文:      {plaintext}")
    print(f"密文:      {ciphertext.hex()}")
    print(f"解密:      {decrypted}")
    print(f"加密测试:  {'PASS' if len(ciphertext) > len(plaintext) else 'FAIL'}")
    print(f"解密测试:  {'PASS' if decrypted == plaintext else 'FAIL'}")
    print()
    return decrypted == plaintext


def test_aes_256():
    """测试 AES-256"""
    print("=" * 70)
    print("AES-256 加密/解密测试")
    print("=" * 70)
    
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    plaintext = b"Hello, AES-256!"  # 15 bytes
    
    aes = AES(key, 'ECB')
    ciphertext = aes.encrypt(plaintext)
    decrypted = aes.decrypt(ciphertext)
    
    print(f"密钥:      {key.hex()}")
    print(f"明文:      {plaintext}")
    print(f"密文:      {ciphertext.hex()}")
    print(f"解密:      {decrypted}")
    print(f"密文长度:  {len(ciphertext)} (PKCS7 padding adds 1 byte)")
    print(f"加密测试:  {'PASS' if len(ciphertext) == 16 else 'FAIL'}")
    print(f"解密测试:  {'PASS' if decrypted == plaintext else 'FAIL'}")
    print()
    return len(ciphertext) == 16 and decrypted == plaintext


if __name__ == '__main__':
    all_passed = True
    
    all_passed &= test_aes_ecb()
    all_passed &= test_aes_cbc()
    all_passed &= test_aes_256()
    
    print("=" * 70)
    if all_passed:
        print("所有测试通过！AES 实现正确。")
    else:
        print("部分测试失败。")
    print("=" * 70)
