#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\Users\leo\Documents\GitHub\solo\moonbit_crypto')
from advanced_crypto import AES

key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
aes = AES(key, 'ECB')

print("Round Keys (first 4 words each round):")
for i in range(11):
    words = aes.round_keys[i*4:(i+1)*4]
    hex_words = [''.join(f'{b:02x}' for b in w) for w in words]
    print(f"Round {i}: {hex_words}")
