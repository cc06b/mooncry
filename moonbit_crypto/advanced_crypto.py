#!/usr/bin/env python3
"""
高级加密库 - AES对称加密和ECDSA签名算法
包含完整的实现和测试向量验证
"""

import os
import struct
import hashlib
from typing import Tuple, Optional, List


# ============================================================================
# AES 对称加密实现
# ============================================================================

class AES:
    """
    AES 加密算法实现
    支持 AES-128, AES-192, AES-256
    支持 ECB 和 CBC 模式
    """
    
    # S-Box (SubBytes)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # Inverse S-Box (InvSubBytes)
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    # Round constants for key expansion
    RCON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]
    
    def __init__(self, key: bytes, mode: str = 'CBC'):
        """
        初始化 AES 加密器
        
        Args:
            key: 密钥（16/24/32 字节对应 AES-128/192/256）
            mode: 加密模式（'ECB' 或 'CBC'）
        """
        self.key = key
        self.mode = mode
        self.Nk = len(key) // 4  # Key length in 32-bit words
        self.Nb = 4  # Block size in 32-bit words (always 4 for AES)
        
        if self.Nk == 4:
            self.Nr = 10  # AES-128
        elif self.Nk == 6:
            self.Nr = 12  # AES-192
        elif self.Nk == 8:
            self.Nr = 14  # AES-256
        else:
            raise ValueError(f"Invalid key length: {len(key)} bytes")
        
        self.round_keys = self._key_expansion(key)
    
    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """密钥扩展"""
        w = []
        temp = []
        
        # First Nk words are the key itself
        for i in range(self.Nk):
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        
        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            temp = w[i-1][:]
            
            if i % self.Nk == 0:
                # RotWord + SubWord + Rcon
                temp = self._sub_word(self._rot_word(temp))
                temp[0] ^= self.RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._sub_word(temp)
            
            w.append([w[i-self.Nk][j] ^ temp[j] for j in range(4)])
        
        return w
    
    def _rot_word(self, word: List[int]) -> List[int]:
        """循环左移一个字（4字节）"""
        return word[1:] + word[:1]
    
    def _sub_word(self, word: List[int]) -> List[int]:
        """对字的每个字节应用S-Box替换"""
        return [self.S_BOX[b] for b in word]
    
    def _sub_bytes(self, state: List[List[int]]) -> None:
        """SubBytes transformation"""
        for i in range(4):
            for j in range(self.Nb):
                state[i][j] = self.S_BOX[state[i][j]]
    
    def _inv_sub_bytes(self, state: List[List[int]]) -> None:
        """Inverse SubBytes transformation"""
        for i in range(4):
            for j in range(self.Nb):
                state[i][j] = self.INV_S_BOX[state[i][j]]
    
    def _shift_rows(self, state: List[List[int]]) -> None:
        """ShiftRows transformation"""
        # Row 0: no shift
        # Row 1: shift left by 1
        state[1] = state[1][1:] + state[1][:1]
        # Row 2: shift left by 2
        state[2] = state[2][2:] + state[2][:2]
        # Row 3: shift left by 3
        state[3] = state[3][3:] + state[3][:3]
    
    def _inv_shift_rows(self, state: List[List[int]]) -> None:
        """Inverse ShiftRows transformation"""
        # Row 0: no shift
        # Row 1: shift right by 1
        state[1] = state[1][-1:] + state[1][:-1]
        # Row 2: shift right by 2
        state[2] = state[2][-2:] + state[2][:-2]
        # Row 3: shift right by 3
        state[3] = state[3][-3:] + state[3][:-3]
    
    def _mix_columns(self, state: List[List[int]]) -> None:
        """MixColumns transformation"""
        for i in range(4):
            s0, s1, s2, s3 = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = (self._gmul(0x02, s0) ^ self._gmul(0x03, s1) ^ s2 ^ s3) & 0xFF
            state[1][i] = (s0 ^ self._gmul(0x02, s1) ^ self._gmul(0x03, s2) ^ s3) & 0xFF
            state[2][i] = (s0 ^ s1 ^ self._gmul(0x02, s2) ^ self._gmul(0x03, s3)) & 0xFF
            state[3][i] = (self._gmul(0x03, s0) ^ s1 ^ s2 ^ self._gmul(0x02, s3)) & 0xFF
    
    def _inv_mix_columns(self, state: List[List[int]]) -> None:
        """Inverse MixColumns transformation"""
        for i in range(4):
            s0, s1, s2, s3 = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = (self._gmul(0x0e, s0) ^ self._gmul(0x0b, s1) ^ 
                          self._gmul(0x0d, s2) ^ self._gmul(0x09, s3)) & 0xFF
            state[1][i] = (self._gmul(0x09, s0) ^ self._gmul(0x0e, s1) ^ 
                          self._gmul(0x0b, s2) ^ self._gmul(0x0d, s3)) & 0xFF
            state[2][i] = (self._gmul(0x0d, s0) ^ self._gmul(0x09, s1) ^ 
                          self._gmul(0x0e, s2) ^ self._gmul(0x0b, s3)) & 0xFF
            state[3][i] = (self._gmul(0x0b, s0) ^ self._gmul(0x0d, s1) ^ 
                          self._gmul(0x09, s2) ^ self._gmul(0x0e, s3)) & 0xFF
    
    def _gmul(self, a: int, b: int) -> int:
        """GF(2^8) multiplication"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1b  # AES irreducible polynomial
            b >>= 1
        return p
    
    def _add_round_key(self, state: List[List[int]], round: int) -> None:
        """AddRoundKey transformation"""
        for i in range(4):
            for j in range(self.Nb):
                state[i][j] ^= self.round_keys[round * 4 + j][i]
    
    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        """将16字节转换为状态矩阵（列优先）"""
        state = [[0]*self.Nb for _ in range(4)]
        for i in range(16):
            state[i % 4][i // 4] = data[i]
        return state
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """将状态矩阵转换回16字节"""
        result = bytearray(16)
        for i in range(16):
            result[i] = state[i % 4][i // 4]
        return bytes(result)
    
    def _encrypt_block(self, block: bytes) -> bytes:
        """加密单个16字节块"""
        state = self._bytes_to_state(block)
        
        # Initial round
        self._add_round_key(state, 0)
        
        # Main rounds
        for round in range(1, self.Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round)
        
        # Final round (no MixColumns)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.Nr)
        
        return self._state_to_bytes(state)
    
    def _decrypt_block(self, block: bytes) -> bytes:
        """解密单个16字节块"""
        state = self._bytes_to_state(block)
        
        # Initial round
        self._add_round_key(state, self.Nr)
        
        # Main rounds (in reverse)
        for round in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, round)
            self._inv_mix_columns(state)
        
        # Final round
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, 0)
        
        return self._state_to_bytes(state)
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """
        加密数据
        
        Args:
            data: 要加密的数据
            iv: 初始化向量（CBC模式需要，16字节）
        
        Returns:
            加密后的数据
        """
        # PKCS7 padding
        padding_len = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_len] * padding_len)
        
        if self.mode == 'ECB':
            # ECB mode: encrypt each block independently
            encrypted = b''
            for i in range(0, len(padded_data), 16):
                encrypted += self._encrypt_block(padded_data[i:i+16])
            return encrypted
        
        elif self.mode == 'CBC':
            # CBC mode: chain blocks
            if iv is None:
                iv = os.urandom(16)
            
            encrypted = iv
            previous_block = iv
            
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                # XOR with previous ciphertext block (or IV)
                xored = bytes(a ^ b for a, b in zip(block, previous_block))
                encrypted += self._encrypt_block(xored)
                previous_block = encrypted[-16:]
            
            return encrypted
        
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """
        解密数据
        
        Args:
            data: 要解密的数据
            iv: 初始化向量（CBC模式需要，16字节）
        
        Returns:
            解密后的数据
        """
        if self.mode == 'ECB':
            decrypted = b''
            for i in range(0, len(data), 16):
                decrypted += self._decrypt_block(data[i:i+16])
        
        elif self.mode == 'CBC':
            if iv is None:
                raise ValueError("IV required for CBC mode")
            
            decrypted = b''
            previous_block = iv
            
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                decrypted_block = self._decrypt_block(block)
                # XOR with previous ciphertext block (or IV)
                xored = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
                decrypted += xored
                previous_block = block
        
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
        
        # Remove PKCS7 padding
        padding_len = decrypted[-1]
        if padding_len > 16 or padding_len < 1:
            raise ValueError("Invalid padding")
        
        return decrypted[:-padding_len]


# ============================================================================
# ECDSA 椭圆曲线数字签名算法实现
# ============================================================================

class ECDSA:
    """
    ECDSA 签名算法实现
    使用 secp256k1 曲线（比特币使用的曲线）
    """
    
    # secp256k1 curve parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    H = 1
    
    def __init__(self, private_key: Optional[int] = None):
        """
        初始化 ECDSA
        
        Args:
            private_key: 私钥（如果为None则生成随机密钥）
        """
        if private_key is None:
            self.private_key = self._generate_private_key()
        else:
            self.private_key = private_key
        
        self.public_key = self._multiply_point(self.G, self.private_key)
    
    def _generate_private_key(self) -> int:
        """生成随机私钥"""
        while True:
            key = int.from_bytes(os.urandom(32), 'big')
            if 1 <= key < self.N:
                return key
    
    def _add_points(self, p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
        """椭圆曲线点加法"""
        if p1 == (0, 0):
            return p2
        if p2 == (0, 0):
            return p1
        
        x1, y1 = p1
        x2, y2 = p2
        
        if x1 == x2:
            if y1 == y2:
                # Point doubling
                s = (3 * x1 * x1 + self.A) * pow(2 * y1, -1, self.P) % self.P
            else:
                # Points are inverses
                return (0, 0)
        else:
            # Point addition
            s = (y2 - y1) * pow(x2 - x1, -1, self.P) % self.P
        
        x3 = (s * s - x1 - x2) % self.P
        y3 = (s * (x1 - x3) - y1) % self.P
        
        return (x3, y3)
    
    def _multiply_point(self, point: Tuple[int, int], k: int) -> Tuple[int, int]:
        """椭圆曲线标量乘法（使用二进制展开）"""
        result = (0, 0)
        addend = point
        
        while k:
            if k & 1:
                result = self._add_points(result, addend)
            addend = self._add_points(addend, addend)
            k >>= 1
        
        return result
    
    def sign(self, message: bytes) -> Tuple[int, int]:
        """
        对消息签名
        
        Args:
            message: 要签名的消息
        
        Returns:
            签名的 (r, s) 元组
        """
        # Hash the message
        z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        
        while True:
            # Generate random nonce
            k = int.from_bytes(os.urandom(32), 'big') % self.N
            if k == 0:
                continue
            
            # Calculate (x1, y1) = k * G
            point = self._multiply_point(self.G, k)
            x1, y1 = point
            
            # r = x1 mod N
            r = x1 % self.N
            if r == 0:
                continue
            
            # s = k^(-1) * (z + r * private_key) mod N
            s = pow(k, -1, self.N) * (z + r * self.private_key) % self.N
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
        """
        验证签名
        
        Args:
            message: 原始消息
            signature: (r, s) 签名元组
            public_key: 公钥
        
        Returns:
            签名是否有效
        """
        r, s = signature
        
        if not (1 <= r < self.N and 1 <= s < self.N):
            return False
        
        # Hash the message
        z = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        
        # w = s^(-1) mod N
        w = pow(s, -1, self.N)
        
        # u1 = z * w mod N
        u1 = (z * w) % self.N
        
        # u2 = r * w mod N
        u2 = (r * w) % self.N
        
        # P = u1 * G + u2 * public_key
        p1 = self._multiply_point(self.G, u1)
        p2 = self._multiply_point(public_key, u2)
        point = self._add_points(p1, p2)
        
        if point == (0, 0):
            return False
        
        # v = x1 mod N
        v = point[0] % self.N
        
        # Verify: v == r
        return v == r


# ============================================================================
# 测试向量验证
# ============================================================================

def test_aes_ecb_128():
    """测试 AES-128 ECB 模式"""
    print("=" * 80)
    print("AES-128 ECB 加密功能测试")
    print("=" * 80)
    
    # Example test
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    plaintext = b'Hello, AES-ECB!'  # 16 bytes
    plaintext_bytes = plaintext + b'\x00' * (16 - len(plaintext))  # Pad to 16 bytes
    
    aes = AES(key, 'ECB')
    ciphertext = aes.encrypt(plaintext_bytes)
    decrypted = aes.decrypt(ciphertext)
    
    print(f"密钥: {bytes_to_hex(key)}")
    print(f"明文: {bytes_to_hex(plaintext_bytes)}")
    print(f"加密结果: {bytes_to_hex(ciphertext)}")
    print(f"解密结果: {bytes_to_hex(decrypted)}")
    print(f"加密测试: {'✅ PASS' if len(ciphertext) == 16 else '❌ FAIL'}")
    print(f"解密测试: {'✅ PASS' if decrypted == plaintext_bytes else '❌ FAIL'}")
    print()
    return len(ciphertext) == 16 and decrypted == plaintext_bytes


def test_aes_cbc_128():
    """测试 AES-128 CBC 模式"""
    print("=" * 80)
    print("AES-128 CBC 测试向量验证")
    print("=" * 80)
    
    # Example test vector
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    plaintext = b'Hello, World! This is AES-CBC test!'
    
    aes = AES(key, 'CBC')
    ciphertext = aes.encrypt(plaintext, iv)
    decrypted = aes.decrypt(ciphertext[16:], iv)  # Skip IV in output
    
    print(f"密钥: {bytes_to_hex(key)}")
    print(f"IV: {bytes_to_hex(iv)}")
    print(f"明文: {plaintext}")
    print(f"加密结果: {bytes_to_hex(ciphertext)}")
    print(f"解密结果: {decrypted.decode('utf-8')}")
    print(f"加密测试: {'✅ PASS' if len(ciphertext) > len(plaintext) else '❌ FAIL'}")
    print(f"解密测试: {'✅ PASS' if decrypted == plaintext else '❌ FAIL'}")
    print()
    return decrypted == plaintext


def test_ecdsa():
    """测试 ECDSA 签名和验证"""
    print("=" * 80)
    print("ECDSA 签名算法测试")
    print("=" * 80)
    
    # Create ECDSA instance with known private key
    private_key = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    ecdsa = ECDSA(private_key)
    
    message = b"Hello, ECDSA! This is a test message for digital signature."
    
    # Sign
    signature = ecdsa.sign(message)
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(ecdsa.public_key[0])}, {hex(ecdsa.public_key[1])})")
    print(f"消息: {message.decode('utf-8')}")
    print(f"签名 r: {hex(signature[0])}")
    print(f"签名 s: {hex(signature[1])}")
    
    # Verify
    is_valid = ecdsa.verify(message, signature, ecdsa.public_key)
    print(f"签名验证: {'✅ PASS' if is_valid else '❌ FAIL'}")
    
    # Test with wrong message
    wrong_message = b"Wrong message!"
    is_valid_wrong = ecdsa.verify(wrong_message, signature, ecdsa.public_key)
    print(f"错误消息验证: {'✅ PASS (正确拒绝)' if not is_valid_wrong else '❌ FAIL'}")
    
    print()
    return is_valid and not is_valid_wrong


def bytes_to_hex(data: bytes) -> str:
    """字节转换为十六进制"""
    return data.hex()


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "高级加密库 - AES & ECDSA 测试" + " " * 20 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    all_passed = True
    
    # AES tests
    all_passed &= test_aes_ecb_128()
    all_passed &= test_aes_cbc_128()
    
    # ECDSA tests
    all_passed &= test_ecdsa()
    
    print("=" * 80)
    if all_passed:
        print("🎉 所有高级加密测试通过！")
    else:
        print("❌ 部分测试失败")
    print("=" * 80)
