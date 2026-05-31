#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\Users\leo\Documents\GitHub\solo\moonbit_crypto')
from advanced_crypto import AES

key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
plaintext = b'Hello, AES-ECB!'  # 14 bytes
plaintext_bytes = plaintext + b'\x00' * (16 - len(plaintext))  # Pad to 16 bytes

print(f"Key (hex): {key.hex()}")
print(f"Plaintext (bytes): {plaintext}")
print(f"Plaintext (hex): {plaintext_bytes.hex()}")
print(f"Plaintext length: {len(plaintext_bytes)} bytes")

aes = AES(key, 'ECB')
ciphertext = aes.encrypt(plaintext_bytes)
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Ciphertext length: {len(ciphertext)} bytes")

decrypted = aes.decrypt(ciphertext)
print(f"Decrypted (hex): {decrypted.hex()}")
print(f"Decrypted (bytes): {decrypted}")
print(f"Decrypted length: {len(decrypted)} bytes")

print(f"\nEncryption test: {'PASS' if len(ciphertext) == 16 else 'FAIL'}")
print(f"Decryption test: {'PASS' if decrypted == plaintext_bytes else 'FAIL'}")

# Also test CBC
print("\n--- CBC Mode Test ---")
iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
plaintext_cbc = b'Hello, World! This is AES-CBC test!'
aes_cbc = AES(key, 'CBC')
ciphertext_cbc = aes_cbc.encrypt(plaintext_cbc, iv)
print(f"Plaintext: {plaintext_cbc}")
print(f"Ciphertext (hex): {ciphertext_cbc.hex()}")
print(f"Ciphertext length: {len(ciphertext_cbc)} bytes")

decrypted_cbc = aes_cbc.decrypt(ciphertext_cbc[16:], iv)  # Skip IV
print(f"Decrypted: {decrypted_cbc}")
print(f"CBC Decryption test: {'PASS' if decrypted_cbc == plaintext_cbc else 'FAIL'}")
