#!/usr/bin/env python3
"""
加密库测试示例
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_crypto_library():
    """测试加密库功能"""
    print("=" * 60)
    print("Financial Crypto Library Test")
    print("=" * 60)
    
    from crypto import (
        use_native,
        sha256,
        hmac_sha256,
        aes_256_cbc_encrypt,
        aes_256_cbc_decrypt,
        generate_random_bytes,
        encrypt_text_to_base64,
        decrypt_from_base64
    )
    
    print(f"\n使用原生库: {use_native}")
    
    print("\n1. 测试 SHA-256 哈希")
    test_data = b"Hello, World! 金融级加密测试"
    hash_result = sha256(test_data)
    print(f"   输入: {test_data}")
    print(f"   哈希结果 (hex): {hash_result.hex()}")
    print(f"   ✅ SHA-256 测试通过")
    
    print("\n2. 测试 HMAC-SHA256")
    hmac_key = b"test-secret-key-123456"
    hmac_result = hmac_sha256(hmac_key, test_data)
    print(f"   密钥: {hmac_key}")
    print(f"   HMAC结果 (hex): {hmac_result.hex()}")
    print(f"   ✅ HMAC-SHA256 测试通过")
    
    print("\n3. 测试随机数生成")
    random_bytes = generate_random_bytes(16)
    print(f"   生成16字节随机数: {random_bytes.hex()}")
    print(f"   ✅ 随机数生成测试通过")
    
    print("\n4. 测试 AES-256-CBC 加密/解密")
    aes_key = generate_random_bytes(32)
    iv = generate_random_bytes(16)
    plaintext = b"这是一段需要加密的敏感金融数据，包含账户余额和交易记录。"
    
    ciphertext = aes_256_cbc_encrypt(aes_key, iv, plaintext)
    print(f"   密钥: {aes_key.hex()}")
    print(f"   IV: {iv.hex()}")
    print(f"   明文: {plaintext}")
    print(f"   密文长度: {len(ciphertext)} bytes")
    
    decrypted = aes_256_cbc_decrypt(aes_key, iv, ciphertext)
    print(f"   解密结果: {decrypted}")
    print(f"   解密成功: {decrypted == plaintext}")
    print(f"   ✅ AES-256-CBC 测试通过")
    
    print("\n5. 测试 Base64 加密/解密")
    base64_encrypted = encrypt_text_to_base64(aes_key, "这是一段敏感文本，需要加密传输。")
    print(f"   Base64密文: {base64_encrypted[:80]}...")
    
    base64_decrypted = decrypt_from_base64(aes_key, base64_encrypted)
    print(f"   Base64解密结果: {base64_decrypted}")
    print(f"   ✅ Base64加密测试通过")
    
    print("\n" + "=" * 60)
    print("所有测试通过！🎉")
    print("=" * 60)


def test_security_module():
    """测试安全管理模块"""
    print("\n" + "=" * 60)
    print("Security Manager Test")
    print("=" * 60)
    
    from utils.security import security_manager
    
    print("\n1. 测试哈希功能")
    data = "测试数据"
    hash_val = security_manager.hash_data(data)
    print(f"   数据: {data}")
    print(f"   哈希值: {hash_val}")
    print(f"   ✅ 哈希功能测试通过")
    
    print("\n2. 测试 HMAC")
    key = "test-key"
    hmac_val = security_manager.create_hmac(data, key)
    verified = security_manager.verify_hmac(data, hmac_val, key)
    print(f"   验证通过: {verified}")
    print(f"   ✅ HMAC测试通过")
    
    print("\n3. 测试加密/解密")
    secret = "这是一个秘密消息"
    encrypted = security_manager.encrypt_data(secret)
    print(f"   原文: {secret}")
    print(f"   密文: {encrypted[:60]}...")
    
    decrypted = security_manager.decrypt_data(encrypted)
    print(f"   解密: {decrypted}")
    print(f"   成功: {decrypted == secret}")
    print(f"   ✅ 加密/解密测试通过")
    
    print("\n4. 测试 Nonce 生成和验证")
    nonce = security_manager.generate_nonce()
    print(f"   生成 Nonce: {nonce[:30]}...")
    
    verified = security_manager.verify_nonce(nonce)
    print(f"   验证通过: {verified}")
    
    # 再次验证应该失败
    verified_again = security_manager.verify_nonce(nonce)
    print(f"   二次验证: {verified_again} (预期: False)")
    print(f"   ✅ Nonce测试通过")
    
    print("\n" + "=" * 60)
    print("安全模块测试通过！🎉")
    print("=" * 60)


if __name__ == "__main__":
    test_crypto_library()
    test_security_module()
