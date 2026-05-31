#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\Users\leo\Documents\GitHub\solo\moonbit_crypto')
from advanced_crypto import AES

# Test AES-128 ECB
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
plaintext = bytes.fromhex('48656c6c6f2c204145532d4543422100')

print("=== AES-128 ECB Test ===")
print(f"Key: {key.hex()}")
print(f"Plaintext: {plaintext.hex()}")
print(f"Plaintext (bytes): {plaintext}")

aes = AES(key, 'ECB')
ciphertext = aes.encrypt(plaintext)
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Ciphertext length: {len(ciphertext)}")

decrypted = aes.decrypt(ciphertext)
print(f"Decrypted: {decrypted.hex()}")
print(f"Decrypted (bytes): {decrypted}")
print(f"Match: {decrypted == plaintext}")

# Verify with NIST test vector (if available)
# From FIPS 197 Appendix B
print("\n=== Verify with known vector ===")
print("Note: NIST vector uses different key/plaintext")
