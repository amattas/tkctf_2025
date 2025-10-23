#!/usr/bin/env python3
import sys

def bin2c(data):
    """Convert binary data to C hex array format like xxd -i"""
    output = []
    for i, byte in enumerate(data):
        if i % 12 == 0:
            if i > 0:
                output.append("\n")
        output.append(f"0x{byte:02x}, ")

    # Remove trailing comma and space
    result = ''.join(output).rstrip(', ')
    return result

if __name__ == '__main__':
    data = sys.stdin.buffer.read()
    print(bin2c(data))
