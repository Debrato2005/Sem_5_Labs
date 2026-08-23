# AES-128 implementation from scratch
# No cryptography library used

# ---------------------------------------------------------
# CONSTANT TABLES
# ---------------------------------------------------------

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0] * 256

for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


RCON = [
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]


# ---------------------------------------------------------
# GALOIS FIELD MULTIPLICATION
# ---------------------------------------------------------

def gf_mul(a, b):
    """
    Multiply two bytes in GF(2^8).
    AES uses polynomial:
    x^8 + x^4 + x^3 + x + 1
    represented by 0x11B.
    """

    result = 0

    while b:
        if b & 1:
            result ^= a # ^ means bitwise xor

        high_bit = a & 0x80

        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


# ---------------------------------------------------------
# AES TRANSFORMATIONS
# ---------------------------------------------------------

def sub_bytes(state):
    return [SBOX[x] for x in state]


def inv_sub_bytes(state):
    return [INV_SBOX[x] for x in state]


def shift_rows(state):
    result = state.copy()

    # AES state index = row + 4 * column

    for row in range(4):
        for col in range(4):

            result[row + 4 * col] = \
                state[row + 4 * ((col + row) % 4)]

    return result


def inv_shift_rows(state):
    result = state.copy()

    for row in range(4):
        for col in range(4):

            result[row + 4 * col] = \
                state[row + 4 * ((col - row) % 4)]

    return result


def mix_columns(state):
    result = state.copy()

    for col in range(4):

        i = col * 4

        a0 = state[i]
        a1 = state[i + 1]
        a2 = state[i + 2]
        a3 = state[i + 3]

        result[i] = (
            gf_mul(a0, 2) ^
            gf_mul(a1, 3) ^
            a2 ^
            a3
        )

        result[i + 1] = (
            a0 ^
            gf_mul(a1, 2) ^
            gf_mul(a2, 3) ^
            a3
        )

        result[i + 2] = (
            a0 ^
            a1 ^
            gf_mul(a2, 2) ^
            gf_mul(a3, 3)
        )

        result[i + 3] = (
            gf_mul(a0, 3) ^
            a1 ^
            a2 ^
            gf_mul(a3, 2)
        )

    return result


def inv_mix_columns(state):
    result = state.copy()

    for col in range(4):

        i = col * 4

        a0 = state[i]
        a1 = state[i + 1]
        a2 = state[i + 2]
        a3 = state[i + 3]

        result[i] = (
            gf_mul(a0, 14) ^
            gf_mul(a1, 11) ^
            gf_mul(a2, 13) ^
            gf_mul(a3, 9)
        )

        result[i + 1] = (
            gf_mul(a0, 9) ^
            gf_mul(a1, 14) ^
            gf_mul(a2, 11) ^
            gf_mul(a3, 13)
        )

        result[i + 2] = (
            gf_mul(a0, 13) ^
            gf_mul(a1, 9) ^
            gf_mul(a2, 14) ^
            gf_mul(a3, 11)
        )

        result[i + 3] = (
            gf_mul(a0, 11) ^
            gf_mul(a1, 13) ^
            gf_mul(a2, 9) ^
            gf_mul(a3, 14)
        )

    return result


def add_round_key(state, round_key):
    return [
        state[i] ^ round_key[i]
        for i in range(16)
    ]


# ---------------------------------------------------------
# KEY EXPANSION
# ---------------------------------------------------------

def rotate_word(word):

    return word[1:] + word[:1]


def substitute_word(word):

    return [SBOX[x] for x in word]


def xor_words(a, b):

    return [
        a[i] ^ b[i]
        for i in range(4)
    ]


def expand_key(key):

    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    # First 4 words come directly from original key

    words = [
        list(key[i:i + 4])
        for i in range(0, 16, 4)
    ]

    # AES-128 requires 44 words
    # 4 words × 11 round keys

    for i in range(4, 44):

        temp = words[i - 1].copy()

        if i % 4 == 0:

            temp = rotate_word(temp)

            temp = substitute_word(temp)

            temp[0] ^= RCON[i // 4]

        words.append(
            xor_words(
                words[i - 4],
                temp
            )
        )

    # Convert words into 11 round keys

    round_keys = []

    for round_number in range(11):

        key_bytes = []

        for word in words[
            round_number * 4:
            round_number * 4 + 4
        ]:
            key_bytes.extend(word)

        round_keys.append(key_bytes)

    return round_keys


# ---------------------------------------------------------
# ENCRYPT ONE 128-BIT BLOCK
# ---------------------------------------------------------

def encrypt_block(block, key):

    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    round_keys = expand_key(key)

    state = list(block)

    # -----------------------------
    # Initial round
    # -----------------------------

    state = add_round_key(
        state,
        round_keys[0]
    )

    # -----------------------------
    # Main rounds 1-9
    # -----------------------------

    for round_number in range(1, 10):

        state = sub_bytes(state)

        state = shift_rows(state)

        state = mix_columns(state)

        state = add_round_key(
            state,
            round_keys[round_number]
        )

    # -----------------------------
    # Final round
    # NO MixColumns
    # -----------------------------

    state = sub_bytes(state)

    state = shift_rows(state)

    state = add_round_key(
        state,
        round_keys[10]
    )

    return bytes(state)


# ---------------------------------------------------------
# DECRYPT ONE BLOCK
# ---------------------------------------------------------

def decrypt_block(block, key):

    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    round_keys = expand_key(key)

    state = list(block)

    # Start using last round key

    state = add_round_key(
        state,
        round_keys[10]
    )

    # Rounds 9 -> 1

    for round_number in range(9, 0, -1):

        state = inv_shift_rows(state)

        state = inv_sub_bytes(state)

        state = add_round_key(
            state,
            round_keys[round_number]
        )

        state = inv_mix_columns(state)

    # Final inverse round

    state = inv_shift_rows(state)

    state = inv_sub_bytes(state)

    state = add_round_key(
        state,
        round_keys[0]
    )

    return bytes(state)


# ---------------------------------------------------------
# GENERAL TEXT ENCRYPTION
# ---------------------------------------------------------

def encrypt(text, key_hex):

    # 32 hexadecimal characters -> 16 bytes
    key = bytes.fromhex(key_hex)

    if len(key) != 16:
        raise ValueError(
            "AES-128 key must contain exactly 32 hexadecimal characters"
        )

    data = text.encode()

    # PKCS#7 padding
    pad = 16 - (len(data) % 16)

    data += bytes([pad]) * pad

    ciphertext = b""

    for i in range(0, len(data), 16):

        block = data[i:i + 16]

        ciphertext += encrypt_block(
            block,
            key
        )

    return ciphertext.hex().upper()


def decrypt(ciphertext, key_hex):

    key = bytes.fromhex(key_hex)

    data = bytes.fromhex(ciphertext)

    if len(data) % 16 != 0:
        raise ValueError("Invalid AES ciphertext length")

    plaintext = b""

    for i in range(0, len(data), 16):

        block = data[i:i + 16]

        plaintext += decrypt_block(
            block,
            key
        )

    # Remove PKCS#7 padding

    pad = plaintext[-1]

    if not 1 <= pad <= 16:
        raise ValueError("Invalid padding")

    if plaintext[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")

    return plaintext[:-pad].decode()



message=input("enter message:")
key=input("enter the key:")

ciphertext = encrypt(message, key)

plaintext = decrypt(ciphertext, key)

print("Original  :", message)
print("Encrypted :", ciphertext)
print("Decrypted :", plaintext)

#WRITE A GENERAL PROGRAM FOR ALL AES IE NOT HARDCODED