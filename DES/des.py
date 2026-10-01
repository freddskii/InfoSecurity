"""
DES (Data Encryption Standard) - Manual Implementation
Built for academic / university coursework demonstration.
No external cryptographic libraries used.
"""

import os

# =====================================================================
# 1. PERMUTATION & SUBSTITUTION TABLES
# =====================================================================

# Initial Permutation (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP / Inverse IP)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Table (E)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation P
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# Permuted Choice 1 (PC-1) - Key schedule
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2 (PC-2) - Subkey compression
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Shift schedule for 16 rounds
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-boxes (S1 to S8)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


# =====================================================================
# 2. HELPER FUNCTIONS: BIT & PERMUTATION
# =====================================================================

def bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of bits (0s and 1s)."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits back to bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def permute(bits: list, table: list) -> list:
    """Permute a bit list using a 1-indexed permutation table."""
    return [bits[pos - 1] for pos in table]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))


# =====================================================================
# 3. KEY SCHEDULE & FEISTEL CORE
# =====================================================================

def generate_subkeys(key: bytes) -> list:
    """Generate 16 48-bit subkeys from an 8-byte (64-bit) key."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")
    
    bits = bytes_to_bits(key)
    key56 = permute(bits, PC1)
    C = key56[:28]
    D = key56[28:]
    
    subkeys = []
    for shift in SHIFTS:
        # Circular left shift
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        # PC-2 compression to 48 bits
        subkeys.append(permute(C + D, PC2))
    return subkeys

def feistel_f(R: list, subkey: list) -> list:
    """DES Feistel round function f(R, K)."""
    # 1. Expansion 32 -> 48 bits
    expanded = permute(R, E)
    
    # 2. XOR with round subkey
    xored = [r ^ k for r, k in zip(expanded, subkey)]
    
    # 3. S-box substitution (8 boxes * 6 bits -> 4 bits each)
    s_output = []
    for i in range(8):
        chunk = xored[i * 6 : (i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOXES[i][row][col]
        # Append 4 bits
        s_output.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
        
    # 4. Permutation P
    return permute(s_output, P)

def process_block(block: bytes, subkeys: list) -> bytes:
    """
    Process an 8-byte block using the Feistel network.
    - For encryption: pass subkeys in standard order (K1..K16).
    - For decryption: pass subkeys in reversed order (K16..K1).
    """
    if len(block) != 8:
        raise ValueError("Block must be exactly 8 bytes")
        
    bits = bytes_to_bits(block)
    permuted = permute(bits, IP)
    L = permuted[:32]
    R = permuted[32:]
    
    for k in subkeys:
        f_res = feistel_f(R, k)
        new_R = [l ^ f for l, f in zip(L, f_res)]
        L = R
        R = new_R
        
    # 32-bit swap after round 16 (R16, L16)
    pre_output = R + L
    return bits_to_bytes(permute(pre_output, FP))


# =====================================================================
# 4. PKCS#7 PADDING & UNPADDING
# =====================================================================

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Pad data to a multiple of block_size using PKCS#7."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# =====================================================================
# 5. CBC MODE ENCRYPTION & DECRYPTION
# =====================================================================

def des_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    """
    Encrypt plaintext using DES in CBC mode.
    Returns: IV (8 bytes) + Ciphertext
    """
    if iv is None:
        iv = os.urandom(8)
    elif len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
        
    padded = pkcs7_pad(plaintext)
    subkeys = generate_subkeys(key)
    
    ciphertext = bytearray()
    prev = iv
    
    for i in range(0, len(padded), 8):
        block = padded[i : i + 8]
        xored = xor_bytes(block, prev)
        enc = process_block(xored, subkeys)
        ciphertext.extend(enc)
        prev = enc
        
    return iv + bytes(ciphertext)

def des_cbc_decrypt(payload: bytes, key: bytes) -> bytes:
    """
    Decrypt payload (IV + Ciphertext) using DES in CBC mode.
    Returns: Original plaintext
    """
    if len(payload) < 16 or (len(payload) - 8) % 8 != 0:
        raise ValueError("Payload must contain 8-byte IV followed by 8-byte ciphertext blocks")
        
    iv = payload[:8]
    ciphertext = payload[8:]
    subkeys = generate_subkeys(key)[::-1]  # Reversed for decryption
    
    plaintext = bytearray()
    prev = iv
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i : i + 8]
        dec = process_block(block, subkeys)
        plaintext.extend(xor_bytes(dec, prev))
        prev = block
        
    return pkcs7_unpad(bytes(plaintext))


# =====================================================================
# 6. SELF-TEST
# =====================================================================
if __name__ == "__main__":
    print("--- Running DES Verification Tests ---")
    
    # 1. NIST Test Vector Verification
    # Key: 133457799BBCDFF1, Plaintext: 0123456789ABCDEF -> Ciphertext: 85E813540F0AB405
    test_key = bytes.fromhex("133457799BBCDFF1")
    test_plain = bytes.fromhex("0123456789ABCDEF")
    expected_cipher = "85E813540F0AB405"
    
    subkeys = generate_subkeys(test_key)
    block_cipher = process_block(test_plain, subkeys)
    print(f"Test Vector Key:        {test_key.hex().upper()}")
    print(f"Test Vector Plaintext:  {test_plain.hex().upper()}")
    print(f"Expected Ciphertext:    {expected_cipher}")
    print(f"Calculated Ciphertext:  {block_cipher.hex().upper()}")
    assert block_cipher.hex().upper() == expected_cipher, "Single block test failed!"
    print("[+] Test Vector Check: PASSED")
    
    # Decrypt the block back
    decrypted_block = process_block(block_cipher, subkeys[::-1])
    assert decrypted_block == test_plain, "Single block decrypt failed!"
    print("[+] Single Block Decrypt Check: PASSED")
    
    # 2. CBC Mode Round-Trip Test
    secret_key = b"MyKey123"  # 8 bytes
    messages = [
        b"Hello World!",
        b"A",
        b"Exact 8b",
        b"16 bytes long!!",
        b"DES manual implementation test for InfoSec assignment two-way transmission!"
    ]
    for msg in messages:
        encrypted_payload = des_cbc_encrypt(msg, secret_key)
        decrypted_msg = des_cbc_decrypt(encrypted_payload, secret_key)
        assert decrypted_msg == msg, f"CBC failed on message: {msg}"
    print("[+] CBC Mode & PKCS#7 Round-Trip Checks: ALL PASSED")
    print("All tests completed successfully!")
