#!/usr/bin/env python3

def bytes_to_state(data):
    """Convert bytes to state matrix (row-major)"""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state

def state_to_bytes(state):
    """Convert state matrix to bytes"""
    result = bytearray(16)
    for i in range(16):
        result[i] = state[i % 4][i // 4]
    return bytes(result)

# Test with 16 bytes
data = bytes.fromhex('48656c6c6f2c204145532d4543422100')
print(f"Original data: {data.hex()}")

state = bytes_to_state(data)
print("\nState matrix (row-major):")
for row in range(4):
    print(f"  Row {row}: {state[row][0]:02x} {state[row][1]:02x} {state[row][2]:02x} {state[row][3]:02x}")

recovered = state_to_bytes(state)
print(f"\nRecovered data: {recovered.hex()}")
print(f"Match: {data == recovered}")

# Print in column-major format
print("\nState matrix (column-major view):")
for col in range(4):
    print(f"  Col {col}: {state[0][col]:02x} {state[1][col]:02x} {state[2][col]:02x} {state[3][col]:02x}")
