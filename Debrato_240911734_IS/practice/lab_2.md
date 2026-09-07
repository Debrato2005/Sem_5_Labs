````md
# Symmetric Cryptography — Individual Python Programs

Install dependencies:

```bash
pip install pycryptodome matplotlib
````

---

# 1. Text ↔ Hex Conversion

```python
text = input("Text: ")

data = text.encode()

print("Bytes:", data)
print("Hex  :", data.hex())

hex_data = input("Hex: ")

data = bytes.fromhex(hex_data)

print("Bytes:", data)
print("Text :", data.decode())
```

---

# 2. Generate Random AES / DES / 3DES Keys

```python
from Crypto.Random import get_random_bytes

aes128 = get_random_bytes(16)
aes192 = get_random_bytes(24)
aes256 = get_random_bytes(32)

des = get_random_bytes(8)
des3 = get_random_bytes(24)

print("AES-128:", aes128.hex())
print("AES-192:", aes192.hex())
print("AES-256:", aes256.hex())
print("DES    :", des.hex())
print("3DES   :", des3.hex())
```

---

# 3. AES-128 Encryption / Decryption

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")
key = bytes.fromhex(input("AES-128 key (32 hex characters): "))

if len(key) != 16:
    raise ValueError("AES-128 requires 16 bytes")

cipher = AES.new(key, AES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(key, AES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 4. AES-192 Encryption / Decryption

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")
key = bytes.fromhex(input("AES-192 key (48 hex characters): "))

if len(key) != 24:
    raise ValueError("AES-192 requires 24 bytes")

cipher = AES.new(key, AES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(key, AES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 5. AES-256 Encryption / Decryption

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")
key = bytes.fromhex(input("AES-256 key (64 hex characters): "))

if len(key) != 32:
    raise ValueError("AES-256 requires 32 bytes")

cipher = AES.new(key, AES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(key, AES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 6. Generic AES — Automatically Detect 128 / 192 / 256

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")
key = bytes.fromhex(input("AES key in hex: "))

if len(key) not in (16, 24, 32):
    raise ValueError("AES key must be 16, 24 or 32 bytes")

print("AES size:", len(key) * 8)

cipher = AES.new(key, AES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(key, AES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 7. DES Encryption / Decryption

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")
key = input("8-character DES key: ").encode()

if len(key) != 8:
    raise ValueError("DES requires 8 bytes")

cipher = DES.new(key, DES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), DES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = DES.new(key, DES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 8. DES With Hex Key

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")

key = bytes.fromhex(
    input("DES key (16 hex characters): ")
)

if len(key) != 8:
    raise ValueError("DES requires 8 bytes")

cipher = DES.new(key, DES.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), DES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = DES.new(key, DES.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 9. Triple DES / 3DES

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")

key = bytes.fromhex(
    input("3DES key in hex (32 or 48 hex chars): ")
)

if len(key) not in (16, 24):
    raise ValueError("3DES requires 16 or 24 bytes")

key = DES3.adjust_key_parity(key)

cipher = DES3.new(key, DES3.MODE_ECB)

encrypted = cipher.encrypt(
    pad(text.encode(), DES3.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = DES3.new(key, DES3.MODE_ECB)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES3.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 10. AES ECB Mode

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

cipher = AES.new(
    key,
    AES.MODE_ECB
)

encrypted = cipher.encrypt(
    pad(text, AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_ECB
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 11. AES CBC Mode

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

iv = get_random_bytes(16)

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

encrypted = cipher.encrypt(
    pad(text, AES.block_size)
)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 12. AES CBC With User-Provided IV

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

iv = bytes.fromhex(
    input("IV (32 hex characters): ")
)

if len(iv) != 16:
    raise ValueError("AES IV must be 16 bytes")

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

encrypted = cipher.encrypt(
    pad(text, AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 13. DES CBC Mode

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

text = input("Plaintext: ")

key = input("8-character DES key: ").encode()
iv = input("8-character IV: ").encode()

if len(key) != 8 or len(iv) != 8:
    raise ValueError("DES key and IV must be 8 bytes")

cipher = DES.new(
    key,
    DES.MODE_CBC,
    iv
)

encrypted = cipher.encrypt(
    pad(text.encode(), DES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = DES.new(
    key,
    DES.MODE_CBC,
    iv
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 14. 3DES CBC Mode

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("3DES key in hex: ")
)

key = DES3.adjust_key_parity(key)

iv = get_random_bytes(8)

cipher = DES3.new(
    key,
    DES3.MODE_CBC,
    iv
)

encrypted = cipher.encrypt(
    pad(text, DES3.block_size)
)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = DES3.new(
    key,
    DES3.MODE_CBC,
    iv
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES3.block_size
)

print("Plaintext:", decrypted.decode())
```

---

# 15. AES CFB Mode

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

iv = get_random_bytes(16)

cipher = AES.new(
    key,
    AES.MODE_CFB,
    iv,
    segment_size=128
)

encrypted = cipher.encrypt(text)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_CFB,
    iv,
    segment_size=128
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 16. DES CFB Mode

```python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()
key = input("8-character DES key: ").encode()

iv = get_random_bytes(8)

cipher = DES.new(
    key,
    DES.MODE_CFB,
    iv,
    segment_size=64
)

encrypted = cipher.encrypt(text)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = DES.new(
    key,
    DES.MODE_CFB,
    iv,
    segment_size=64
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 17. AES OFB Mode

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

iv = get_random_bytes(16)

cipher = AES.new(
    key,
    AES.MODE_OFB,
    iv
)

encrypted = cipher.encrypt(text)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_OFB,
    iv
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 18. DES OFB Mode

```python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()
key = input("8-character DES key: ").encode()

iv = get_random_bytes(8)

cipher = DES.new(
    key,
    DES.MODE_OFB,
    iv
)

encrypted = cipher.encrypt(text)

print("IV        :", iv.hex())
print("Ciphertext:", encrypted.hex())

cipher = DES.new(
    key,
    DES.MODE_OFB,
    iv
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 19. AES CTR Mode

```python
from Crypto.Cipher import AES

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

cipher = AES.new(
    key,
    AES.MODE_CTR
)

nonce = cipher.nonce

encrypted = cipher.encrypt(text)

print("Nonce     :", nonce.hex())
print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 20. AES CTR With User-Provided Nonce

```python
from Crypto.Cipher import AES

text = input("Plaintext: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

nonce = bytes.fromhex(
    input("Nonce in hex: ")
)

cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

encrypted = cipher.encrypt(text)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 21. DES CTR Mode

```python
from Crypto.Cipher import DES

text = input("Plaintext: ").encode()
key = input("8-character DES key: ").encode()

cipher = DES.new(
    key,
    DES.MODE_CTR
)

nonce = cipher.nonce

encrypted = cipher.encrypt(text)

print("Nonce     :", nonce.hex())
print("Ciphertext:", encrypted.hex())

cipher = DES.new(
    key,
    DES.MODE_CTR,
    nonce=nonce
)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 22. AES-GCM — Authenticated Encryption

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

text = input("Plaintext: ").encode()

key = get_random_bytes(32)

cipher = AES.new(
    key,
    AES.MODE_GCM
)

ciphertext, tag = cipher.encrypt_and_digest(text)

nonce = cipher.nonce

print("Key       :", key.hex())
print("Nonce     :", nonce.hex())
print("Tag       :", tag.hex())
print("Ciphertext:", ciphertext.hex())

cipher = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = cipher.decrypt_and_verify(
    ciphertext,
    tag
)

print("Plaintext:", plaintext.decode())
```

---

# 23. Encrypt Hexadecimal Data Using DES

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

data = bytes.fromhex(
    input("Data in hex: ")
)

key = bytes.fromhex(
    input("DES key in hex: ")
)

if len(key) != 8:
    raise ValueError("DES requires 8 byte key")

cipher = DES.new(
    key,
    DES.MODE_ECB
)

encrypted = cipher.encrypt(
    pad(data, DES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = DES.new(
    key,
    DES.MODE_ECB
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    DES.block_size
)

print("Decrypted hex :", decrypted.hex())

try:
    print("Decrypted text:", decrypted.decode())
except UnicodeDecodeError:
    pass
```

---

# 24. Encrypt Hexadecimal Data Using AES

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

data = bytes.fromhex(
    input("Data in hex: ")
)

key = bytes.fromhex(
    input("AES key in hex: ")
)

cipher = AES.new(
    key,
    AES.MODE_ECB
)

encrypted = cipher.encrypt(
    pad(data, AES.block_size)
)

print("Ciphertext:", encrypted.hex())

cipher = AES.new(
    key,
    AES.MODE_ECB
)

decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)

print("Decrypted hex:", decrypted.hex())
```

---

# 25. PKCS#7 Padding Demonstration

```python
from Crypto.Util.Padding import pad, unpad

text = input("Text: ").encode()

block_size = int(
    input("Block size in bytes: ")
)

padded = pad(
    text,
    block_size
)

print("Original:", text)
print("Padded  :", padded)
print("Hex     :", padded.hex())

original = unpad(
    padded,
    block_size
)

print("Unpadded:", original)
```

---

# 26. XOR Two Byte Strings

```python
def xor(a, b):
    return bytes(
        x ^ y
        for x, y in zip(a, b)
    )


a = bytes.fromhex(
    input("First hex value : ")
)

b = bytes.fromhex(
    input("Second hex value: ")
)

print("XOR:", xor(a, b).hex())
```

---

# 27. Split Data Into Blocks

```python
def split_blocks(data, block_size):
    return [
        data[i:i + block_size]
        for i in range(0, len(data), block_size)
    ]


text = input("Text: ").encode()
size = int(input("Block size: "))

blocks = split_blocks(
    text,
    size
)

for i, block in enumerate(blocks, 1):
    print(
        f"Block {i}:",
        block,
        block.hex()
    )
```

---

# 28. DES Encryption / Decryption Timing

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from time import perf_counter

text = input("Message: ").encode()
key = input("8-character DES key: ").encode()

data = pad(
    text,
    DES.block_size
)

runs = 10000

start = perf_counter()

for _ in range(runs):
    cipher = DES.new(
        key,
        DES.MODE_ECB
    )

    ciphertext = cipher.encrypt(data)

enc_time = (
    perf_counter() - start
) / runs


start = perf_counter()

for _ in range(runs):
    cipher = DES.new(
        key,
        DES.MODE_ECB
    )

    plaintext = cipher.decrypt(ciphertext)

dec_time = (
    perf_counter() - start
) / runs


print(
    "Encryption:",
    enc_time * 1e6,
    "µs"
)

print(
    "Decryption:",
    dec_time * 1e6,
    "µs"
)
```

---

# 29. AES Encryption / Decryption Timing

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from time import perf_counter

text = input("Message: ").encode()

key = bytes.fromhex(
    input("AES key in hex: ")
)

data = pad(
    text,
    AES.block_size
)

runs = 10000

start = perf_counter()

for _ in range(runs):

    cipher = AES.new(
        key,
        AES.MODE_ECB
    )

    ciphertext = cipher.encrypt(data)

enc_time = (
    perf_counter() - start
) / runs


start = perf_counter()

for _ in range(runs):

    cipher = AES.new(
        key,
        AES.MODE_ECB
    )

    plaintext = cipher.decrypt(ciphertext)

dec_time = (
    perf_counter() - start
) / runs


print(
    "Encryption:",
    enc_time * 1e6,
    "µs"
)

print(
    "Decryption:",
    dec_time * 1e6,
    "µs"
)
```

---

# 30. DES vs AES-256 Performance Comparison

```python
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
from time import perf_counter

message = input("Message: ").encode()

des_key = input(
    "8-character DES key: "
).encode()

aes_key = bytes.fromhex(
    input("AES-256 key in hex: ")
)

runs = 10000


def test(algorithm, key):

    data = pad(
        message,
        algorithm.block_size
    )

    start = perf_counter()

    for _ in range(runs):

        cipher = algorithm.new(
            key,
            algorithm.MODE_ECB
        )

        ciphertext = cipher.encrypt(data)

    enc = (
        perf_counter() - start
    ) / runs


    start = perf_counter()

    for _ in range(runs):

        cipher = algorithm.new(
            key,
            algorithm.MODE_ECB
        )

        cipher.decrypt(ciphertext)

    dec = (
        perf_counter() - start
    ) / runs

    return enc, dec


des_enc, des_dec = test(
    DES,
    des_key
)

aes_enc, aes_dec = test(
    AES,
    aes_key
)

print(
    "DES     :",
    des_enc * 1e6,
    des_dec * 1e6
)

print(
    "AES-256 :",
    aes_enc * 1e6,
    aes_dec * 1e6
)
```

---

# 31. Compare AES-128 / AES-192 / AES-256

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from time import perf_counter

message = input("Message: ").encode()

keys = {
    "AES-128": get_random_bytes(16),
    "AES-192": get_random_bytes(24),
    "AES-256": get_random_bytes(32)
}

runs = 10000

for name, key in keys.items():

    data = pad(
        message,
        AES.block_size
    )

    start = perf_counter()

    for _ in range(runs):

        cipher = AES.new(
            key,
            AES.MODE_ECB
        )

        cipher.encrypt(data)

    time_taken = (
        perf_counter() - start
    ) / runs

    print(
        name,
        f"{time_taken * 1e6:.3f} µs"
    )
```

---

# 32. Compare AES Modes

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from time import perf_counter

message = input("Message: ").encode()
key = get_random_bytes(16)

runs = 5000

modes = [
    "ECB",
    "CBC",
    "CFB",
    "OFB",
    "CTR"
]


def encrypt(mode):

    if mode == "ECB":

        cipher = AES.new(
            key,
            AES.MODE_ECB
        )

        return cipher.encrypt(
            pad(message, AES.block_size)
        )


    if mode == "CBC":

        cipher = AES.new(
            key,
            AES.MODE_CBC,
            get_random_bytes(16)
        )

        return cipher.encrypt(
            pad(message, AES.block_size)
        )


    if mode == "CFB":

        cipher = AES.new(
            key,
            AES.MODE_CFB,
            get_random_bytes(16),
            segment_size=128
        )

        return cipher.encrypt(message)


    if mode == "OFB":

        cipher = AES.new(
            key,
            AES.MODE_OFB,
            get_random_bytes(16)
        )

        return cipher.encrypt(message)


    if mode == "CTR":

        cipher = AES.new(
            key,
            AES.MODE_CTR
        )

        return cipher.encrypt(message)


for mode in modes:

    start = perf_counter()

    for _ in range(runs):
        encrypt(mode)

    average = (
        perf_counter() - start
    ) / runs

    print(
        mode,
        f"{average * 1e6:.3f} µs"
    )
```

---

# 33. Graph AES Mode Performance

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from time import perf_counter
import matplotlib.pyplot as plt

message = b"Performance Testing"

key = get_random_bytes(16)

modes = [
    "ECB",
    "CBC",
    "CFB",
    "OFB",
    "CTR"
]

times = []
runs = 5000


def test(mode):

    start = perf_counter()

    for _ in range(runs):

        if mode == "ECB":

            cipher = AES.new(
                key,
                AES.MODE_ECB
            )

            cipher.encrypt(
                pad(
                    message,
                    AES.block_size
                )
            )


        elif mode == "CBC":

            cipher = AES.new(
                key,
                AES.MODE_CBC,
                get_random_bytes(16)
            )

            cipher.encrypt(
                pad(
                    message,
                    AES.block_size
                )
            )


        elif mode == "CFB":

            cipher = AES.new(
                key,
                AES.MODE_CFB,
                get_random_bytes(16),
                segment_size=128
            )

            cipher.encrypt(message)


        elif mode == "OFB":

            cipher = AES.new(
                key,
                AES.MODE_OFB,
                get_random_bytes(16)
            )

            cipher.encrypt(message)


        elif mode == "CTR":

            cipher = AES.new(
                key,
                AES.MODE_CTR
            )

            cipher.encrypt(message)


    return (
        perf_counter() - start
    ) / runs


for mode in modes:
    times.append(
        test(mode) * 1e6
    )


plt.bar(
    modes,
    times
)

plt.xlabel("Mode")
plt.ylabel("Time (µs)")
plt.title("AES Mode Performance")

plt.show()
```

---

# 34. Compare Performance for Different Message Sizes

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from time import perf_counter

key = get_random_bytes(32)

sizes = [
    16,
    100,
    1000,
    10_000,
    100_000,
    1_000_000
]

for size in sizes:

    data = get_random_bytes(size)

    start = perf_counter()

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        get_random_bytes(16)
    )

    cipher.encrypt(
        pad(data, AES.block_size)
    )

    elapsed = perf_counter() - start

    print(
        size,
        "bytes:",
        elapsed,
        "seconds"
    )
```

---

# 35. AES Throughput in MB/s

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from time import perf_counter

size = int(
    input("Number of bytes: ")
)

data = get_random_bytes(size)
key = get_random_bytes(32)

cipher = AES.new(
    key,
    AES.MODE_CTR
)

start = perf_counter()

cipher.encrypt(data)

elapsed = perf_counter() - start

mb = size / (1024 * 1024)

print(
    "Throughput:",
    mb / elapsed,
    "MB/s"
)
```

---

# 36. Encrypt / Decrypt a File With AES-GCM

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

input_file = input("Input file: ")
encrypted_file = input("Encrypted file: ")
decrypted_file = input("Recovered file: ")

key = get_random_bytes(32)

with open(input_file, "rb") as f:
    data = f.read()


cipher = AES.new(
    key,
    AES.MODE_GCM
)

ciphertext, tag = cipher.encrypt_and_digest(data)

nonce = cipher.nonce


with open(encrypted_file, "wb") as f:
    f.write(ciphertext)


cipher = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = cipher.decrypt_and_verify(
    ciphertext,
    tag
)


with open(decrypted_file, "wb") as f:
    f.write(plaintext)


print("Key  :", key.hex())
print("Nonce:", nonce.hex())
print("Tag  :", tag.hex())
```

---

# 37. AES Avalanche Effect

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def hamming_distance(a, b):

    return sum(
        (x ^ y).bit_count()
        for x, y in zip(a, b)
    )


key = get_random_bytes(16)

text1 = input("First plaintext : ").encode()
text2 = input("Second plaintext: ").encode()


cipher = AES.new(
    key,
    AES.MODE_ECB
)

c1 = cipher.encrypt(
    pad(text1, AES.block_size)
)


cipher = AES.new(
    key,
    AES.MODE_ECB
)

c2 = cipher.encrypt(
    pad(text2, AES.block_size)
)


distance = hamming_distance(
    c1,
    c2
)

total = len(c1) * 8

print(
    "Different bits:",
    distance
)

print(
    "Avalanche:",
    distance / total * 100,
    "%"
)
```

---

# 38. DES Reduced-Key Brute Force Demonstration

This is for a deliberately reduced educational key space: 7 key bytes are known and only the final byte is unknown.

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

plaintext = input("Plaintext: ").encode()

known_prefix = input(
    "Known 7-character key prefix: "
).encode()

if len(known_prefix) != 7:
    raise ValueError(
        "Prefix must be 7 bytes"
    )


secret_last_byte = int(
    input("Secret final byte [0-255]: ")
)

real_key = (
    known_prefix
    + bytes([secret_last_byte])
)


cipher = DES.new(
    real_key,
    DES.MODE_ECB
)

ciphertext = cipher.encrypt(
    pad(
        plaintext,
        DES.block_size
    )
)


print(
    "Ciphertext:",
    ciphertext.hex()
)


for x in range(256):

    candidate = (
        known_prefix
        + bytes([x])
    )

    cipher = DES.new(
        candidate,
        DES.MODE_ECB
    )

    decrypted = cipher.decrypt(
        ciphertext
    )

    try:

        decrypted = unpad(
            decrypted,
            DES.block_size
        )

    except ValueError:

        continue


    if decrypted == plaintext:

        print(
            "Key found:",
            candidate.hex()
        )

        print(
            "Plaintext:",
            decrypted.decode()
        )

        break
```

---

# 39. AES Reduced-Key Brute Force Demonstration

15 bytes known, 1 byte unknown.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

plaintext = input(
    "Plaintext: "
).encode()

prefix = bytes.fromhex(
    input(
        "Known first 15 bytes "
        "(30 hex chars): "
    )
)

if len(prefix) != 15:
    raise ValueError(
        "Exactly 15 bytes required"
    )


unknown = int(
    input(
        "Secret final byte [0-255]: "
    )
)

real_key = (
    prefix
    + bytes([unknown])
)


cipher = AES.new(
    real_key,
    AES.MODE_ECB
)

ciphertext = cipher.encrypt(
    pad(
        plaintext,
        AES.block_size
    )
)


for x in range(256):

    candidate = (
        prefix
        + bytes([x])
    )

    cipher = AES.new(
        candidate,
        AES.MODE_ECB
    )

    result = cipher.decrypt(
        ciphertext
    )

    try:

        result = unpad(
            result,
            AES.block_size
        )

    except ValueError:

        continue


    if result == plaintext:

        print(
            "Key found:",
            candidate.hex()
        )

        print(
            "Plaintext:",
            result.decode()
        )

        break
```

---

# 40. Generic Candidate-Key Generator

```python
from itertools import product


def generate_keys(
    prefix=b"",
    unknown_bytes=1
):

    for values in product(
        range(256),
        repeat=unknown_bytes
    ):

        yield (
            prefix
            + bytes(values)
        )


prefix = bytes.fromhex(
    input("Known prefix in hex: ")
)

unknown = int(
    input(
        "Number of unknown bytes: "
    )
)


for key in generate_keys(
    prefix,
    unknown
):

    print(key.hex())
```

Use only small values such as 1–2 unknown bytes for practical demonstrations.

---

# 41. Key-Space Calculator

```python
bits = int(
    input("Key size in bits: ")
)

possibilities = 2 ** bits

print(
    "Possible keys:",
    possibilities
)
```

Examples:

```text
DES     → 2^56
AES-128 → 2^128
AES-192 → 2^192
AES-256 → 2^256
```

---

# 42. Unknown-Byte Key-Space Calculator

```python
unknown = int(
    input(
        "Unknown bytes: "
    )
)

possibilities = 256 ** unknown

print(
    "Possibilities:",
    possibilities
)

print(
    "Equivalent bits:",
    unknown * 8
)
```

---

# 43. Brute-Force Time Estimator

```python
bits = int(
    input(
        "Key bits: "
    )
)

speed = float(
    input(
        "Keys tested per second: "
    )
)

total_keys = 2 ** bits

seconds = total_keys / speed

years = seconds / (
    60 * 60 * 24 * 365
)

print(
    "Worst case seconds:",
    seconds
)

print(
    "Worst case years:",
    years
)

print(
    "Average case years:",
    years / 2
)
```

---

# 44. Measure Candidate-Key Generation Speed

```python
from itertools import product
from time import perf_counter

unknown_bytes = int(
    input(
        "Unknown bytes: "
    )
)

start = perf_counter()

count = 0

for values in product(
    range(256),
    repeat=unknown_bytes
):

    key = bytes(values)

    count += 1


elapsed = (
    perf_counter() - start
)

print(
    "Candidates:",
    count
)

print(
    "Time:",
    elapsed
)

print(
    "Candidates/sec:",
    count / elapsed
)
```

---

# 45. Verify AES Key Size

```python
key_hex = input(
    "AES key in hex: "
)

key = bytes.fromhex(
    key_hex
)

bits = len(key) * 8

print(
    "Hex characters:",
    len(key_hex)
)

print(
    "Bytes:",
    len(key)
)

print(
    "Bits:",
    bits
)


if bits == 128:
    print("AES-128")

elif bits == 192:
    print("AES-192")

elif bits == 256:
    print("AES-256")

else:
    print("Invalid AES key size")
```

---

# 46. Verify DES / 3DES Key Size

```python
key = bytes.fromhex(
    input(
        "Key in hex: "
    )
)

bits = len(key) * 8

print(
    "Bytes:",
    len(key)
)

print(
    "Bits:",
    bits
)


if len(key) == 8:
    print("DES-sized supplied key")

elif len(key) in (16, 24):
    print("Possible 3DES key")

else:
    print("Invalid DES/3DES key size")
```

---

# Quick Reference

| Algorithm | Block Size |              Supplied Key Size |
| --------- | ---------: | -----------------------------: |
| DES       |    64 bits | 8 bytes, 56 effective key bits |
| 3DES      |    64 bits |                  16 / 24 bytes |
| AES-128   |   128 bits |                       16 bytes |
| AES-192   |   128 bits |                       24 bytes |
| AES-256   |   128 bits |                       32 bytes |

---

# Mode Reference

| Mode | Padding | IV / Nonce                 |
| ---- | ------- | -------------------------- |
| ECB  | Yes     | None                       |
| CBC  | Yes     | IV                         |
| CFB  | No      | IV                         |
| OFB  | No      | IV                         |
| CTR  | No      | Nonce                      |
| GCM  | No      | Nonce + Authentication Tag |

---

# Important Conversion Rule

If a key is written as ordinary characters:

```text
A1B2C3D4
```

and intended literally:

```python
key = "A1B2C3D4".encode()
```

gives:

```text
8 characters = 8 bytes
```

If it is written as hexadecimal:

```text
0123456789ABCDEF0123456789ABCDEF
```

use:

```python
key = bytes.fromhex(
    "0123456789ABCDEF0123456789ABCDEF"
)
```

giving:

```text
32 hex digits
÷ 2
= 16 bytes
= 128 bits
```

---

# Core Imports Worth Remembering

```python
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from time import perf_counter
import matplotlib.pyplot as plt
```

---

# Core Patterns Worth Remembering

## AES

```python
cipher = AES.new(
    key,
    AES.MODE_ECB
)
```

## DES

```python
cipher = DES.new(
    key,
    DES.MODE_ECB
)
```

## 3DES

```python
cipher = DES3.new(
    key,
    DES3.MODE_ECB
)
```

## Encryption

```python
ciphertext = cipher.encrypt(
    plaintext
)
```

## Decryption

```python
plaintext = cipher.decrypt(
    ciphertext
)
```

## Padding

```python
padded = pad(
    plaintext,
    block_size
)

plaintext = unpad(
    padded,
    block_size
)
```

## Text → Bytes

```python
data = text.encode()
```

## Bytes → Text

```python
text = data.decode()
```

## Hex → Bytes

```python
data = bytes.fromhex(
    hex_string
)
```

## Bytes → Hex

```python
hex_string = data.hex()
```

## Random Bytes

```python
value = get_random_bytes(
    number_of_bytes
)
```

```

This keeps each concept as an **independent program** instead of hiding DES, AES, modes, benchmarking, file handling, and reduced-key brute-force demonstrations behind one abstraction.
```
