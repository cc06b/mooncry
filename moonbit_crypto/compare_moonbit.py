#!/usr/bin/env python3
"""详细对比 MoonBit 输出"""

from advanced_crypto import AES

def main():
    print("=" * 70)
    print("MoonBit AES 测试详细对比")
    print("=" * 70)
    
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    
    # MoonBit 使用的明文（16字节，最后一个字节是 0x00）
    moonbit_plaintext = bytes([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x41,
                              0x45, 0x53, 0x2d, 0x45, 0x43, 0x42, 0x21, 0x00])
    
    # 正确的 15 字节明文（无 padding）
    correct_plaintext = b"Hello, AES-ECB!"
    
    print("测试 1: MoonBit 使用的明文（16字节）")
    print(f"  明文: {moonbit_plaintext}")
    print(f"  长度: {len(moonbit_plaintext)}")
    
    aes = AES(key, 'ECB')
    ciphertext = aes.encrypt(moonbit_plaintext)
    decrypted = aes.decrypt(ciphertext)
    
    print(f"  密文: {ciphertext.hex()}")
    print(f"  解密: {decrypted}")
    print(f"  测试: {'PASS' if decrypted == moonbit_plaintext else 'FAIL'}")
    
    print()
    print("测试 2: 正确的明文（15字节）")
    print(f"  明文: {correct_plaintext}")
    print(f"  长度: {len(correct_plaintext)}")
    
    ciphertext2 = aes.encrypt(correct_plaintext)
    decrypted2 = aes.decrypt(ciphertext2)
    
    print(f"  密文: {ciphertext2.hex()}")
    print(f"  解密: {decrypted2}")
    print(f"  测试: {'PASS' if decrypted2 == correct_plaintext else 'FAIL'}")
    
    print()
    print("MoonBit 报告的加密结果:")
    print("  Encrypted (ECB): 00000000060606060f0f0f0fd3d3d3d324242424cbcbcbcb5252525216161616")
    print()
    print("我们的预期结果（15字节明文）:")
    print(f"  Encrypted (ECB): {ciphertext2.hex()}")
    print()
    print("我们的结果（16字节明文）:")
    print(f"  Encrypted (ECB): {ciphertext.hex()}")
    
    # 检查 MoonBit 第一个块的输出
    print()
    print("MoonBit 第一个块 (前16字节): 00000000060606060f0f0f0fd3d3d3d3")
    print(f"我们 16字节输入的密文:       {ciphertext[:16].hex()}")
    print(f"我们 15字节输入的密文:       {ciphertext2[:16].hex()}")

if __name__ == '__main__':
    main()
