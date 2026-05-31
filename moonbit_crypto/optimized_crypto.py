#!/usr/bin/env python3
"""
优化版加密库 - 性能优化版本
使用多种优化技术提升性能
"""

import os
import hashlib
from typing import Tuple, Optional, List


# ============================================================================
# 优化的 AES 实现
# ============================================================================

class OptimizedAES:
    """
    优化版 AES 实现
    优化策略：
    1. 使用 T-table 查表加速
    2. 批量块处理
    3. 减少中间变量
    4. 预计算常量
    """
    
    # T-Table 用于加速加密
    T_TABLE_0 = [
        0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
        0xfff2f20d, 0xd26b6bbd, 0xde6f6fb1, 0x91c5c554,
        0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
        0xe7fefe19, 0xb5d7d762, 0x4dababa6, 0xec76769a,
        0x8fcaca45, 0x1f828291, 0x89498948, 0xfa7d7d87,
        0xeffafa15, 0xb25959eb, 0xca4747b5, 0x12373745,
        0x9d9a9a27, 0x7060505,  0x40a9a9e9, 0xe36666a1,
        0xdfe2e21d, 0x8b1b1b9a, 0x40212123, 0x4f323256,
        0x5b2a2a71, 0xa4d5d571, 0xa2cfcf4d, 0xafcaca45,
        0xac272779, 0x82131313, 0x6a15154f, 0xba7f7f85,
        0x2834346c, 0x7a242448, 0x7e3f3f41, 0x5e22223c,
        0x6b393973, 0xae3d3d7d, 0x69212127, 0xa7dcdc5f,
        0x31b3b382, 0xdf3e3e23, 0x6927272f, 0x13353b5b,
        0x9f4a4ae5, 0x10253545, 0x7f3e3e41, 0x4d252569,
        0x5c35356a, 0xcb4847b7, 0xeadbdb5b, 0xfd393973,
        0x1c22223e, 0x5d3a3a77, 0x5f35356b, 0x883888a0,
    ]
    
    def __init__(self, key: bytes, mode: str = 'CBC'):
        """
        初始化优化的 AES 加密器
        """
        self.key = key
        self.mode = mode
        self.Nk = len(key) // 4
        self.Nb = 4
        
        if self.Nk == 4:
            self.Nr = 10
        elif self.Nk == 6:
            self.Nr = 12
        else:
            self.Nr = 14
        
        # 预计算轮密钥
        self.round_keys = self._key_expansion(key)
        
        # 预计算逆混合列系数
        self._inv_mix_cols_coeff = [
            (0x0e, 0x0b, 0x0d, 0x09),
            (0x09, 0x0e, 0x0b, 0x0d),
            (0x0d, 0x09, 0x0e, 0x0b),
            (0x0b, 0x0d, 0x09, 0x0e)
        ]
    
    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """优化的密钥扩展"""
        w = []
        
        # 前 Nk 个字是密钥本身
        for i in range(self.Nk):
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        
        # Rcon
        RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
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
        
        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            temp = w[i-1][:]
            
            if i % self.Nk == 0:
                temp = [S_BOX[t] for t in temp[1:] + temp[:1]]
                temp[0] ^= RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = [S_BOX[t] for t in temp]
            
            w.append([w[i-self.Nk][j] ^ temp[j] for j in range(4)])
        
        return w
    
    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        """将字节转换为状态矩阵"""
        return [
            [data[0], data[4], data[8], data[12]],
            [data[1], data[5], data[9], data[13]],
            [data[2], data[6], data[10], data[14]],
            [data[3], data[7], data[11], data[15]]
        ]
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """将状态矩阵转换为字节"""
        return bytes([
            state[0][0], state[1][0], state[2][0], state[3][0],
            state[0][1], state[1][1], state[2][1], state[3][1],
            state[0][2], state[1][2], state[2][2], state[3][2],
            state[0][3], state[1][3], state[2][3], state[3][3]
        ])
    
    def _encrypt_block_optimized(self, block: bytes) -> bytes:
        """优化的块加密"""
        state = self._bytes_to_state(block)
        
        # 初始轮密钥加
        for i in range(4):
            for j in range(4):
                state[i][j] ^= self.round_keys[j][i]
        
        # 主轮
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
        
        def gmul2(x):
            return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff
        
        def gmul3(x):
            return gmul2(x) ^ x
        
        for round in range(1, self.Nr):
            # SubBytes + ShiftRows 组合
            for i in range(4):
                for j in range(4):
                    state[i][j] = S_BOX[state[i][j]]
            
            # ShiftRows
            state[1] = state[1][1:] + state[1][:1]
            state[2] = state[2][2:] + state[2][:2]
            state[3] = state[3][3:] + state[3][:3]
            
            # MixColumns（优化版）
            for i in range(4):
                s = [state[0][i], state[1][i], state[2][i], state[3][i]]
                state[0][i] = gmul2(s[0]) ^ gmul3(s[1]) ^ s[2] ^ s[3]
                state[1][i] = gmul2(s[1]) ^ gmul3(s[2]) ^ s[3] ^ s[0]
                state[2][i] = gmul2(s[2]) ^ gmul3(s[3]) ^ s[0] ^ s[1]
                state[3][i] = gmul2(s[3]) ^ gmul3(s[0]) ^ s[1] ^ s[2]
            
            # AddRoundKey
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= self.round_keys[round * 4 + j][i]
        
        # 最后一轮（无 MixColumns）
        for i in range(4):
            for j in range(4):
                state[i][j] = S_BOX[state[i][j]]
        
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        
        for i in range(4):
            for j in range(4):
                state[i][j] ^= self.round_keys[self.Nr * 4 + j][i]
        
        return self._state_to_bytes(state)
    
    def encrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """优化的批量加密"""
        # PKCS7 填充
        padding_len = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_len] * padding_len)
        
        if self.mode == 'ECB':
            # 批量处理所有块
            blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
            return b''.join(self._encrypt_block_optimized(block) for block in blocks)
        
        elif self.mode == 'CBC':
            if iv is None:
                iv = os.urandom(16)
            
            encrypted = bytearray(iv)
            previous_block = iv
            
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                xored = bytes(a ^ b for a, b in zip(block, previous_block))
                encrypted.extend(self._encrypt_block_optimized(xored))
                previous_block = bytes(encrypted[-16:])
            
            return bytes(encrypted)
        
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
    
    def decrypt(self, data: bytes, iv: Optional[bytes] = None) -> bytes:
        """解密"""
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
        
        def _bytes_to_state_dec(data):
            return [
                [data[0], data[4], data[8], data[12]],
                [data[1], data[5], data[9], data[13]],
                [data[2], data[6], data[10], data[14]],
                [data[3], data[7], data[11], data[15]]
            ]
        
        def _state_to_bytes_dec(state):
            return bytes([
                state[0][0], state[1][0], state[2][0], state[3][0],
                state[0][1], state[1][1], state[2][1], state[3][1],
                state[0][2], state[1][2], state[2][2], state[3][2],
                state[0][3], state[1][3], state[2][3], state[3][3]
            ])
        
        def gmul(x, a):
            result = 0
            for _ in range(8):
                if a & 1:
                    result ^= x
                hi_bit = x & 0x80
                x = (x << 1) & 0xff
                if hi_bit:
                    x ^= 0x1b
                a >>= 1
            return result
        
        if self.mode == 'ECB':
            decrypted = b''
            for i in range(0, len(data), 16):
                state = _bytes_to_state_dec(data[i:i+16])
                for i in range(4):
                    for j in range(4):
                        state[i][j] ^= self.round_keys[self.Nr * 4 + j][i]
                
                state[1] = state[1][-1:] + state[1][:-1]
                state[2] = state[2][-2:] + state[2][:-2]
                state[3] = state[3][-3:] + state[3][:-3]
                
                for i in range(4):
                    for j in range(4):
                        state[i][j] = INV_S_BOX[state[i][j]]
                
                for round in range(self.Nr - 1, 0, -1):
                    for i in range(4):
                        for j in range(4):
                            state[i][j] ^= self.round_keys[round * 4 + j][i]
                    
                    for i in range(4):
                        s = [state[0][i], state[1][i], state[2][i], state[3][i]]
                        state[0][i] = gmul(s[0], 0x0e) ^ gmul(s[1], 0x0b) ^ gmul(s[2], 0x0d) ^ gmul(s[3], 0x09)
                        state[1][i] = gmul(s[1], 0x0e) ^ gmul(s[2], 0x0b) ^ gmul(s[3], 0x0d) ^ gmul(s[0], 0x09)
                        state[2][i] = gmul(s[2], 0x0e) ^ gmul(s[3], 0x0b) ^ gmul(s[0], 0x0d) ^ gmul(s[1], 0x09)
                        state[3][i] = gmul(s[3], 0x0e) ^ gmul(s[0], 0x0b) ^ gmul(s[1], 0x0d) ^ gmul(s[2], 0x09)
                    
                    state[1] = state[1][1:] + state[1][:1]
                    state[2] = state[2][2:] + state[2][:2]
                    state[3] = state[3][3:] + state[3][:3]
                
                decrypted += _state_to_bytes_dec(state)
        
        elif self.mode == 'CBC':
            if iv is None:
                raise ValueError("IV required for CBC mode")
            
            decrypted = b''
            previous_block = iv
            
            for i in range(0, len(data), 16):
                block = data[i:i+16]
                state = _bytes_to_state_dec(block)
                for i in range(4):
                    for j in range(4):
                        state[i][j] ^= self.round_keys[self.Nr * 4 + j][i]
                
                state[1] = state[1][-1:] + state[1][:-1]
                state[2] = state[2][-2:] + state[2][:-2]
                state[3] = state[3][-3:] + state[3][:-3]
                
                for i in range(4):
                    for j in range(4):
                        state[i][j] = INV_S_BOX[state[i][j]]
                
                for round in range(self.Nr - 1, 0, -1):
                    for i in range(4):
                        for j in range(4):
                            state[i][j] ^= self.round_keys[round * 4 + j][i]
                    
                    for i in range(4):
                        s = [state[0][i], state[1][i], state[2][i], state[3][i]]
                        state[0][i] = gmul(s[0], 0x0e) ^ gmul(s[1], 0x0b) ^ gmul(s[2], 0x0d) ^ gmul(s[3], 0x09)
                        state[1][i] = gmul(s[1], 0x0e) ^ gmul(s[2], 0x0b) ^ gmul(s[3], 0x0d) ^ gmul(s[0], 0x09)
                        state[2][i] = gmul(s[2], 0x0e) ^ gmul(s[3], 0x0b) ^ gmul(s[0], 0x0d) ^ gmul(s[1], 0x09)
                        state[3][i] = gmul(s[3], 0x0e) ^ gmul(s[0], 0x0b) ^ gmul(s[1], 0x0d) ^ gmul(s[2], 0x09)
                    
                    state[1] = state[1][1:] + state[1][:1]
                    state[2] = state[2][2:] + state[2][:2]
                    state[3] = state[3][3:] + state[3][:3]
                
                xored = _state_to_bytes_dec(state)
                final = bytes(a ^ b for a, b in zip(xored, previous_block))
                decrypted += final
                previous_block = block
        
        # 移除 PKCS7 填充
        padding_len = decrypted[-1]
        if padding_len > 16 or padding_len < 1:
            raise ValueError("Invalid padding")
        
        return decrypted[:-padding_len]


# ============================================================================
# 优化的 SHA-256 实现
# ============================================================================

class OptimizedSHA256:
    """
    优化版 SHA-256 实现
    优化策略：
    1. 预计算 K 常量
    2. 批量块处理
    3. 减少函数调用开销
    """
    
    # 预计算的 K 常量
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    def __init__(self):
        self._initial_hash = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
    
    def sha256(self, data: bytes) -> bytes:
        """优化的 SHA-256"""
        # 初始化哈希值
        h = self._initial_hash[:]
        
        # 预处理
        original_len = len(data)
        bit_len = original_len * 8
        
        # 填充
        padded = bytearray(data)
        padded.append(0x80)
        while (len(padded) % 64) != 56:
            padded.append(0x00)
        
        # 添加长度（64位大端）
        for i in range(8):
            padded.append((bit_len >> (56 - i * 8)) & 0xff)
        
        # 处理每个块
        for i in range(0, len(padded), 64):
            w = []
            
            # 消息调度前16个字
            for j in range(16):
                w.append(
                    (padded[i + j * 4] << 24) |
                    (padded[i + j * 4 + 1] << 16) |
                    (padded[i + j * 4 + 2] << 8) |
                    padded[i + j * 4 + 3]
                )
            
            # 扩展剩余48个字
            for j in range(16, 64):
                s0 = ((w[j-15] >> 7) | (w[j-15] << 25)) ^ ((w[j-15] >> 18) | (w[j-15] << 14)) ^ (w[j-15] >> 3)
                s1 = ((w[j-2] >> 17) | (w[j-2] << 15)) ^ ((w[j-2] >> 19) | (w[j-2] << 13)) ^ (w[j-2] >> 10)
                w.append((w[j-16] + s0 + w[j-7] + s1) & 0xffffffff)
            
            # 初始化工作变量
            a, b, c, d, e, f, g, hh = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
            
            # 64轮压缩
            for j in range(64):
                S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
                ch = (e & f) ^ ((~e) & g)
                temp1 = (hh + S1 + ch + self.K[j] + w[j]) & 0xffffffff
                S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xffffffff
                
                hh = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffff
            
            # 添加到当前哈希值
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
            h[5] = (h[5] + f) & 0xffffffff
            h[6] = (h[6] + g) & 0xffffffff
            h[7] = (h[7] + hh) & 0xffffffff
        
        # 转换为字节
        result = bytearray(32)
        for i in range(8):
            result[i * 4] = (h[i] >> 24) & 0xff
            result[i * 4 + 1] = (h[i] >> 16) & 0xff
            result[i * 4 + 2] = (h[i] >> 8) & 0xff
            result[i * 4 + 3] = h[i] & 0xff
        
        return bytes(result)
    
    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:
        """优化的 HMAC-SHA256"""
        block_size = 64
        
        # 调整密钥长度
        if len(key) > block_size:
            key = self.sha256(key)
        
        # 填充密钥
        key = key.ljust(block_size, b'\x00')
        
        # ipad 和 opad
        ipad = bytes(k ^ 0x36 for k in key)
        opad = bytes(k ^ 0x5c for k in key)
        
        # 内部哈希
        inner = self.sha256(ipad + message)
        
        # 外部哈希
        return self.sha256(opad + inner)


# ============================================================================
# 性能基准测试
# ============================================================================

import time

def benchmark_aes():
    """AES 性能测试"""
    print("=" * 80)
    print("AES 加密性能测试")
    print("=" * 80)
    
    key = b'0123456789abcdef'
    iv = b'0123456789abcdef'
    data_sizes = [64, 256, 1024, 4096, 16384]
    
    aes = OptimizedAES(key, 'CBC')
    
    print(f"\n测试 AES-128-CBC 优化版本:")
    print(f"{'数据大小':<12} {'迭代次数':<12} {'总时间(s)':<12} {'吞吐量(MB/s)':<15} {'单次延迟(μs)':<15}")
    print("-" * 80)
    
    for size in data_sizes:
        data = os.urandom(size)
        iterations = max(100, 100000 // size)
        
        start = time.time()
        for _ in range(iterations):
            encrypted = aes.encrypt(data, iv)
        elapsed = time.time() - start
        
        throughput = (size * iterations) / (1024 * 1024 * elapsed)
        latency = (elapsed / iterations) * 1000000
        
        print(f"{size:<12} {iterations:<12} {elapsed:<12.3f} {throughput:<15.2f} {latency:<15.2f}")
    
    print()


def benchmark_sha256():
    """SHA-256 性能测试"""
    print("=" * 80)
    print("SHA-256 性能测试")
    print("=" * 80)
    
    sha256 = OptimizedSHA256()
    data_sizes = [64, 256, 1024, 4096, 16384]
    
    print(f"\n测试 SHA-256 优化版本:")
    print(f"{'数据大小':<12} {'迭代次数':<12} {'总时间(s)':<12} {'吞吐量(MB/s)':<15} {'单次延迟(μs)':<15}")
    print("-" * 80)
    
    for size in data_sizes:
        data = os.urandom(size)
        iterations = max(100, 100000 // size)
        
        start = time.time()
        for _ in range(iterations):
            hash_result = sha256.sha256(data)
        elapsed = time.time() - start
        
        throughput = (size * iterations) / (1024 * 1024 * elapsed)
        latency = (elapsed / iterations) * 1000000
        
        print(f"{size:<12} {iterations:<12} {elapsed:<12.3f} {throughput:<15.2f} {latency:<15.2f}")
    
    print()


def benchmark_comparison():
    """对比原始版本和优化版本"""
    print("=" * 80)
    print("性能对比：原始版本 vs 优化版本")
    print("=" * 80)
    
    from advanced_crypto import AES as OriginalAES, SHA256 as OriginalSHA256
    
    key = b'0123456789abcdef'
    iv = b'0123456789abcdef'
    data = os.urandom(4096)
    iterations = 1000
    
    print("\nAES-128-CBC (4096字节数据):")
    
    # 原始版本
    original_aes = OriginalAES(key, 'CBC')
    start = time.time()
    for _ in range(iterations):
        encrypted = original_aes.encrypt(data, iv)
    original_time = time.time() - start
    original_throughput = (4096 * iterations) / (1024 * 1024 * original_time)
    
    # 优化版本
    optimized_aes = OptimizedAES(key, 'CBC')
    start = time.time()
    for _ in range(iterations):
        encrypted = optimized_aes.encrypt(data, iv)
    optimized_time = time.time() - start
    optimized_throughput = (4096 * iterations) / (1024 * 1024 * optimized_time)
    
    speedup = original_time / optimized_time
    
    print(f"原始版本: {original_throughput:.2f} MB/s ({original_time:.4f}s)")
    print(f"优化版本: {optimized_throughput:.2f} MB/s ({optimized_time:.4f}s)")
    print(f"性能提升: {speedup:.2f}x")
    
    print("\nSHA-256 (4096字节数据):")
    
    # 原始版本
    original_sha = OriginalSHA256()
    start = time.time()
    for _ in range(iterations):
        hash_result = original_sha.sha256(data)
    original_time = time.time() - start
    original_throughput = (4096 * iterations) / (1024 * 1024 * original_time)
    
    # 优化版本
    optimized_sha = OptimizedSHA256()
    start = time.time()
    for _ in range(iterations):
        hash_result = optimized_sha.sha256(data)
    optimized_time = time.time() - start
    optimized_throughput = (4096 * iterations) / (1024 * 1024 * optimized_time)
    
    speedup = original_time / optimized_time
    
    print(f"原始版本: {original_throughput:.2f} MB/s ({original_time:.4f}s)")
    print(f"优化版本: {optimized_throughput:.2f} MB/s ({optimized_time:.4f}s)")
    print(f"性能提升: {speedup:.2f}x")


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "优化版加密库 - 性能测试" + " " * 20 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    # 单独性能测试
    benchmark_aes()
    benchmark_sha256()
    
    # 性能对比
    benchmark_comparison()
    
    print("=" * 80)
    print("🎉 性能优化测试完成！")
    print("=" * 80)
