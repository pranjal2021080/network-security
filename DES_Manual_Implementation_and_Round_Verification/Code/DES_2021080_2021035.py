#!/usr/bin/env python3
"""
Combined DES Verification for Parts (a), (b), and (c):

For each <plaintext, ciphertext> pair:
  a. Verify that the ciphertext, when decrypted, yields the original plaintext.
  b. Verify that the output of the 1st encryption round equals the output of the 15th decryption round.
  c. Verify that the output of the 14th encryption round equals the output of the 2nd decryption round.

Note: Because of the Feistel structure, decryption round states are "mirrored"
(i.e. their left and right halves are swapped) relative to the encryption round states.
Thus, before comparing a decryption round output to an encryption round output,
the halves of the decryption state must be swapped.
"""

# -----------------------
# DES Permutation Tables
# -----------------------

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

# Final Permutation (IP^-1)
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Table (E) – expands 32 bits to 48 bits.
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

# Permutation (P) used after the S-box substitution.
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

# -------------------------------
# DES S-Boxes (Substitution Boxes)
# There are 8 S-boxes; each is a 4x16 matrix.
# -------------------------------
S_BOX = [
    # S-box 1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S-box 2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S-box 3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S-box 4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S-box 5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S-box 6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S-box 7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S-box 8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# -------------------------------
# Key Schedule Tables
# -------------------------------

# Permuted Choice 1 (PC-1) – from 64 bits to 56 bits.
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

# Permuted Choice 2 (PC-2) – from 56 bits to 48 bits.
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

# Number of left shifts per round.
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# -------------------------------
# Helper Functions
# -------------------------------
def permute(block, table):
    """Permute the input bit-string using the provided table."""
    return ''.join(block[i - 1] for i in table)

def left_shift(bits, n):
    """Perform a circular left shift of the bit-string by n positions."""
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    """XOR two bit strings of equal length."""
    return ''.join('0' if bits1[i] == bits2[i] else '1' for i in range(len(bits1)))

def sbox_substitution(bits):
    """Apply the eight S-boxes on the 48-bit input to yield 32 bits."""
    output = ""
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        # Determine row (from the 1st and 6th bit) and column (middle 4 bits)
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S_BOX[i][row][col]
        output += format(val, '04b')
    return output

def feistel(right, round_key):
    """The DES Feistel (F) function."""
    # 1. Expand right half from 32 to 48 bits.
    expanded_right = permute(right, E)
    # 2. XOR with the round key.
    xored = xor(expanded_right, round_key)
    # 3. Substitute using S-boxes to reduce 48 bits to 32 bits.
    sbox_out = sbox_substitution(xored)
    # 4. Permute the S-box output.
    return permute(sbox_out, P)

def generate_round_keys(key):
    """Generate 16 round keys (each 48 bits) from the 64-bit key."""
    key56 = permute(key, PC1)  # Drop parity bits.
    left, right = key56[:28], key56[28:]
    round_keys = []
    for shift in SHIFT_SCHEDULE:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        combined = left + right
        round_key = permute(combined, PC2)
        round_keys.append(round_key)
    return round_keys

def hex_to_bin(hex_str):
    """Convert a hexadecimal string to a binary string."""
    num_of_bits = len(hex_str) * 4
    return bin(int(hex_str, 16))[2:].zfill(num_of_bits)

def bin_to_hex(bin_str):
    """Convert a binary string to a hexadecimal string."""
    hex_str = hex(int(bin_str, 2))[2:].upper()
    return hex_str.zfill(len(bin_str) // 4)

# -------------------------------
# DES with Round-State Capture
# -------------------------------
def des_encrypt_rounds(plaintext, round_keys):
    """
    Encrypts the 64-bit plaintext and returns a list of 16 intermediate
    round states (each 64 bits) after each round (before the final swap/permutation).
    """
    # Apply Initial Permutation.
    permuted = permute(plaintext, IP)
    L, R = permuted[:32], permuted[32:]
    round_states = []
    for i in range(16):
        temp = R
        R = xor(L, feistel(R, round_keys[i]))
        L = temp
        round_states.append(L + R)
    return round_states

def des_decrypt_rounds(ciphertext, round_keys):
    """
    Decrypts the 64-bit ciphertext and returns a list of 16 intermediate
    round states (each 64 bits) after each decryption round.
    """
    permuted = permute(ciphertext, IP)
    L, R = permuted[:32], permuted[32:]
    round_states = []
    for i in range(16):
        temp = R
        R = xor(L, feistel(R, round_keys[15 - i]))
        L = temp
        round_states.append(L + R)
    return round_states

def des_encrypt(plaintext, round_keys):
    """Standard DES encryption: 16 rounds, final swap, and final permutation."""
    permuted = permute(plaintext, IP)
    L, R = permuted[:32], permuted[32:]
    for i in range(16):
        temp = R
        R = xor(L, feistel(R, round_keys[i]))
        L = temp
    combined = R + L  # Final swap.
    return permute(combined, IP_INV)

def des_decrypt(ciphertext, round_keys):
    """Standard DES decryption: using round keys in reverse order."""
    permuted = permute(ciphertext, IP)
    L, R = permuted[:32], permuted[32:]
    for i in range(16):
        temp = R
        R = xor(L, feistel(R, round_keys[15 - i]))
        L = temp
    combined = R + L
    return permute(combined, IP_INV)

# -------------------------------
# Combined Verification for (a), (b), and (c)
# -------------------------------
if __name__ == "__main__":
    # Define at least three test pairs.
    test_pairs = [
        {"key": "133457799BBCDFF1", "plaintext": "0123456789ABCDEF"},
        {"key": "AABB09182736CCDD", "plaintext": "1234567890ABCDEF"},
        {"key": "FFFFFFFFFFFFFFFF", "plaintext": "0000000000000000"}
    ]
    
    for idx, pair in enumerate(test_pairs, 1):
        print("\n==============================")
        print(f"Test Pair {idx}:")
        print(f"Key:       {pair['key']}")
        print(f"Plaintext: {pair['plaintext']}")
        print("==============================")
        
        # Convert hex strings to binary strings.
        key_bin = hex_to_bin(pair["key"])
        plaintext_bin = hex_to_bin(pair["plaintext"])
        
        # Generate the 16 round keys.
        round_keys = generate_round_keys(key_bin)
        
        # --- Encryption ---
        # Capture intermediate round outputs during encryption.
        enc_round_states = des_encrypt_rounds(plaintext_bin, round_keys)
        # Fully encrypt to get the ciphertext.
        ciphertext_bin = des_encrypt(plaintext_bin, round_keys)
        ciphertext_hex = bin_to_hex(ciphertext_bin)
        print(f"Ciphertext: {ciphertext_hex}")
        
        # --- Decryption ---
        # Capture intermediate round outputs during decryption.
        dec_round_states = des_decrypt_rounds(ciphertext_bin, round_keys)
        # Fully decrypt.
        decrypted_bin = des_decrypt(ciphertext_bin, round_keys)
        decrypted_hex = bin_to_hex(decrypted_bin)
        print(f"Decrypted:  {decrypted_hex}")
        
        # -------------------------------
        # (a) Verify Decryption
        # -------------------------------
        if decrypted_hex == pair["plaintext"]:
            print("Verification (a): SUCCESS - Decrypted text matches the original plaintext.")
        else:
            print("Verification (a): FAILURE - Decrypted text does not match the original plaintext.")
        
        # -------------------------------
        # (b) Verify: 1st Encryption Round == 15th Decryption Round (after swapping halves)
        # -------------------------------
        round1_enc = enc_round_states[0]          # 1st encryption round state.
        round15_dec = dec_round_states[14]          # 15th decryption round state (0-indexed).
        # Because of the Feistel structure, swap halves of the decryption state.
        swapped_round15_dec = round15_dec[32:] + round15_dec[:32]
        
        round1_enc_hex = bin_to_hex(round1_enc)
        swapped_round15_dec_hex = bin_to_hex(swapped_round15_dec)
        print(f"\n1st Encryption Round:          {round1_enc_hex}")
        print(f"15th Decryption Round (swapped): {swapped_round15_dec_hex}")
        
        if round1_enc == swapped_round15_dec:
            print("Verification (b): SUCCESS - 1st encryption round equals 15th decryption round (after swapping).")
        else:
            print("Verification (b): FAILURE - The outputs do not match.")
        
        # -------------------------------
        # (c) Verify: 14th Encryption Round == 2nd Decryption Round (after swapping halves)
        # -------------------------------
        round14_enc = enc_round_states[13]         # 14th encryption round state (index 13).
        round2_dec = dec_round_states[1]             # 2nd decryption round state (index 1).
        swapped_round2_dec = round2_dec[32:] + round2_dec[:32]
        
        round14_enc_hex = bin_to_hex(round14_enc)
        swapped_round2_dec_hex = bin_to_hex(swapped_round2_dec)
        print(f"\n14th Encryption Round:         {round14_enc_hex}")
        print(f"2nd Decryption Round (swapped):  {swapped_round2_dec_hex}")
        
        if round14_enc == swapped_round2_dec:
            print("Verification (c): SUCCESS - 14th encryption round equals 2nd decryption round (after swapping).")
        else:
            print("Verification (c): FAILURE - The outputs do not match.")
