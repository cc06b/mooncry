#!/usr/bin/env python3
"""正确的 ShiftRows 实现测试"""

def bytes_to_state(data):
    """将16字节转换为状态矩阵（列优先）"""
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def state_to_bytes(state):
    """将状态矩阵转换回16字节"""
    result = bytearray(16)
    for i in range(16):
        result[i] = state[i % 4][i // 4]
    return bytes(result)

def shift_rows_correct(state):
    """正确的 ShiftRows 实现（来自 advanced_crypto.py）"""
    # Row 0: no shift
    # Row 1: shift left by 1
    state[1] = state[1][1:] + state[1][:1]
    # Row 2: shift left by 2
    state[2] = state[2][2:] + state[2][:2]
    # Row 3: shift left by 3
    state[3] = state[3][3:] + state[3][:3]

def shift_rows_current(state):
    """当前 MoonBit 的实现"""
    t = 0
    t = state[1][3]
    state[1][3] = state[1][2]
    state[1][2] = state[1][1]
    state[1][1] = state[1][0]
    state[1][0] = t
    
    t = state[2][0]
    state[2][0] = state[2][2]
    state[2][2] = t
    t = state[2][1]
    state[2][1] = state[2][3]
    state[2][3] = t
    
    t = state[3][0]
    state[3][0] = state[3][3]
    state[3][3] = state[3][2]
    state[3][2] = state[3][1]
    state[3][1] = t

def test_shift_rows():
    """测试 ShiftRows"""
    print("=" * 70)
    print("ShiftRows 实现对比")
    print("=" * 70)
    
    test_data = b"Hello, AES-ECB!X"
    state1 = bytes_to_state(test_data)
    state2 = bytes_to_state(test_data)
    
    print("\n初始状态:")
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in state1[i]]}")
    
    print("\n--- 正确实现 ---")
    shift_rows_correct(state1)
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in state1[i]]}")
    
    print("\n--- 当前实现 ---")
    shift_rows_current(state2)
    for i in range(4):
        print(f"  Row {i}: {[hex(x) for x in state2[i]]}")
    
    # 对比结果
    match = all(state1[i][j] == state2[i][j] for i in range(4) for j in range(4))
    print(f"\n结果是否一致: {'YES' if match else 'NO'}")

if __name__ == '__main__':
    test_shift_rows()
