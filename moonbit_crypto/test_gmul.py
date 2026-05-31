#!/usr/bin/env python3
"""测试 gmul 函数"""

def gmul(a, b):
    p = 0
    aa = a
    bb = b
    for _ in range(8):
        if (bb & 1) != 0:
            p = p ^ aa
        hi_bit = aa & 0x80
        aa = (aa << 1) & 0xFF
        if hi_bit != 0:
            aa = aa ^ 0x1b
        bb = bb >> 1
    return p

def test_gmul():
    print("gmul 函数测试")
    print("-" * 50)
    
    # 测试一些已知的 gmul 结果
    test_cases = [
        # (a, b, expected)
        (0x02, 0x01, 0x02),  # 2 * 1 = 2
        (0x02, 0x02, 0x04),  # 2 * 2 = 4
        (0x02, 0x03, 0x06),  # 2 * 3 = 6
        (0x03, 0x01, 0x03),  # 3 * 1 = 3
        (0x03, 0x02, 0x06),  # 3 * 2 = 6
        (0x03, 0x03, 0x07),  # 3 * 3 = 9 (in GF, it's 0x07)
        (0x01, 0xff, 0xff),  # 1 * 255 = 255
        (0x02, 0xff, 0x1d),   # 2 * 255 = 510 = 0x1fe -> reduce = 0x1d
        (0x0e, 0x01, 0x0e),
        (0x0b, 0x01, 0x0b),
        (0x0d, 0x01, 0x0d),
        (0x09, 0x01, 0x09),
    ]
    
    for a, b, expected in test_cases:
        result = gmul(a, b)
        status = "OK" if result == expected else "FAIL"
        print(f"  gmul(0x{a:02x}, 0x{b:02x}) = 0x{result:02x} (expected 0x{expected:02x}) [{status}]")

def test_mix_columns():
    """测试 mix_columns"""
    print()
    print("mix_columns 测试")
    print("-" * 50)
    
    # 已知测试向量
    state = [
        [0xd4, 0xbf, 0x5d, 0x30],
        [0xe0, 0xb4, 0x5e, 0xa0],
        [0x27, 0x96, 0x6d, 0xeb],
        [0x6c, 0x90, 0x02, 0x4a]
    ]
    
    print("输入 state:")
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in state[i]]}")
    
    # 应用 mix_columns
    def gmul(a, b):
        p = 0
        aa = a
        bb = b
        for _ in range(8):
            if (bb & 1) != 0:
                p = p ^ aa
            hi_bit = aa & 0x80
            aa = (aa << 1) & 0xFF
            if hi_bit != 0:
                aa = aa ^ 0x1b
            bb = bb >> 1
        return p
    
    for j in range(4):
        s0, s1, s2, s3 = state[0][j], state[1][j], state[2][j], state[3][j]
        state[0][j] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3
        state[1][j] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3
        state[2][j] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3)
        state[3][j] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3)
    
    print("输出 state:")
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in state[i]]}")
    
    # 预期输出 (来自 AES 标准)
    expected = [
        [0x04, 0x66, 0x81, 0xe5],
        [0xe5, 0x9a, 0x7a, 0x4c],
        [0x31, 0xe8, 0xfe, 0x1d],
        [0xc6, 0x41, 0x82, 0x5c]
    ]
    
    print("预期 state:")
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in expected[i]]}")
    
    match = all(state[i][j] == expected[i][j] for i in range(4) for j in range(4))
    print(f"测试结果: {'PASS' if match else 'FAIL'}")

if __name__ == '__main__':
    test_gmul()
    test_mix_columns()
