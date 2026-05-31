#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\Users\leo\Documents\GitHub\solo\moonbit_crypto')
from advanced_crypto import AES

key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
plaintext = b'Hello, AES-ECB!'
plaintext_bytes = plaintext + b'\x00' * (16 - len(plaintext))

print(f"Key (hex): {key.hex()}")
print(f"Plaintext (hex): {plaintext_bytes.hex()}")
print(f"Plaintext (bytes): {plaintext_bytes}")

aes = AES(key, 'ECB')

# Encrypt
ciphertext = aes.encrypt(plaintext_bytes)
print(f"\nPython ECB Encrypt:")
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Ciphertext length: {len(ciphertext)} bytes")

# Decrypt
decrypted = aes.decrypt(ciphertext)
print(f"\nPython ECB Decrypt:")
print(f"Decrypted (hex): {decrypted.hex()}")
print(f"Decrypted (bytes): {decrypted}")

# Now compare with a known test vector
# NIST AES-128 test vector (simplified)
test_key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
test_plaintext = bytes.fromhex('48656c6c6f2c204145532d4543422100')
aes_test = AES(test_key, 'ECB')
test_ciphertext = aes_test.encrypt(test_plaintext)
print(f"\nTest with explicit hex input:")
print(f"Test plaintext (hex): {test_plaintext.hex()}")
print(f"Test ciphertext (hex): {test_ciphertext.hex()}")
print(f"Test decrypted (hex): {aes_test.decrypt(test_ciphertext).hex()}")
