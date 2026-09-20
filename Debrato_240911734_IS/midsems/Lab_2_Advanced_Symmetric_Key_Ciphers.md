# Lab 2 — Advanced Symmetric Key Ciphers

## Scope from the lab manual

This lab covers **DES, Triple DES, AES-128, AES-192, AES-256, block-cipher modes (ECB/CBC/CFB/OFB/CTR), encryption/decryption timing, and comparison of algorithms/modes**. The lab manual also asks for direct encryption/decryption exercises, timing experiments, multi-message tests, DES-CBC, and AES-CTR.

> Exam strategy: use the compact library-based programs below unless the question explicitly says \\\*\\\*implement AES/DES internals manually\\\*\\\* or \\\*\\\*show round-level steps\\\*\\\*.

\---

# 0\. Install once

Recommended for this lab:

```bash
pip install pycryptodome matplotlib
```

Imports used throughout:

```python
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes
from Crypto.Util import Counter
import time
import matplotlib.pyplot as plt
```

\---

# 1\. Critical facts to remember

## DES

* Block size: **64 bits = 8 bytes**
* Effective key size: **56 bits**
* PyCryptodome DES key input: **8 bytes** (includes parity bits)
* 16 Feistel rounds
* Modes: ECB, CBC, CFB, OFB

## Triple DES (3DES)

* Block size: **8 bytes**
* Key length: commonly **16 or 24 bytes**
* PyCryptodome: `DES3.new(...)`

## AES

* Block size: **128 bits = 16 bytes** for AES-128/192/256
* Key sizes:

  * AES-128 → **16 bytes**
  * AES-192 → **24 bytes**
  * AES-256 → **32 bytes**
* Rounds:

  * AES-128 → 10
  * AES-192 → 12
  * AES-256 → 14

## AES encryption round structure

1. Initial `AddRoundKey`
2. Main rounds: `SubBytes -> ShiftRows -> MixColumns -> AddRoundKey`
3. Final round: `SubBytes -> ShiftRows -> AddRoundKey`

\---

# 2\. Universal helper functions

Use these helpers in most programs.

```python
from Crypto.Util.Padding import pad, unpad

def fix\\\_key(s, n):
    b = s.encode()
    return (b + b'0' \\\* n)\\\[:n]

def show(label, b):
    print(label, b.hex())
```

### Important

`fix\\\_key()` is convenient for exams because it accepts any user input and pads/truncates it to the required key length. For cryptographically correct real systems, use proper key derivation instead.

# KEY + PADDING QUICK RULES

# 1\. Do NOT blindly use fix\_key() for every program.

# 2\. If the question gives an exact key, use that key exactly.

# 3\. Validate key length instead of silently padding/truncating it.

# 

# DES key       = 8 bytes

# AES-128 key   = 16 bytes

# AES-192 key   = 24 bytes

# AES-256 key   = 32 bytes

# 3DES key      = 16 or 24 bytes

# 

# 4\. "No padding" refers to PLAINTEXT padding, NOT key length.

# 5\. ECB/CBC:

# plaintext must be a multiple of block size if no padding is used.

# DES block = 8 bytes, AES block = 16 bytes.

# 6\. CFB/OFB/CTR do not require plaintext padding.

# 

# 7\. ASCII key:

# key = input("Key: ").encode()

# 

# 8\. Hex key:

# key = bytes.fromhex(input("Hex key: "))

# Example: "A1B2C3D4E5F60708" = 8-byte DES key in hex.

# 

# 9\. Only use fix\_key() when arbitrary user input is allowed and resizing

# the key is intentionally part of the program.

# 

# 10\. pad()/unpad() are for MESSAGE data only:

# ct = cipher.encrypt(pad(msg, block\_size))

# pt = unpad(cipher.decrypt(ct), block\_size)

# 

# EXAM RULE:

# Exact key given -> preserve it.

# No padding given -> remove pad/unpad and check block alignment.

\---

# 3\. DES — shortest complete ECB encryption/decryption

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
key = (input("DES key: ").encode() + b'00000000')\\\[:8]

c = DES.new(key, DES.MODE\\\_ECB)
ct = c.encrypt(pad(msg, 8))

pt = DES.new(key, DES.MODE\\\_ECB).decrypt(ct)
pt = unpad(pt, 8)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

Use when question says simply:

* encrypt/decrypt using DES
* verify original plaintext

\---

# 4\. DES-CBC — user-input key + IV

The manual explicitly includes DES in CBC mode.

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
key = (input("Key: ").encode() + b'00000000')\\\[:8]
iv  = (input("IV: ").encode()  + b'00000000')\\\[:8]

ct = DES.new(key, DES.MODE\\\_CBC, iv).encrypt(pad(msg, 8))
pt = unpad(DES.new(key, DES.MODE\\\_CBC, iv).decrypt(ct), 8)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 5\. DES — selectable mode: ECB / CBC / CFB / OFB

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
key = (input("Key: ").encode() + b'00000000')\\\[:8]
mode = input("Mode \\\[ECB/CBC/CFB/OFB]: ").upper()

if mode == "ECB":
    e = DES.new(key, DES.MODE\\\_ECB)
    ct = e.encrypt(pad(msg, 8))
    pt = unpad(DES.new(key, DES.MODE\\\_ECB).decrypt(ct), 8)

else:
    iv = get\\\_random\\\_bytes(8)
    M = getattr(DES, "MODE\\\_" + mode)
    e = DES.new(key, M, iv=iv)

    if mode == "CBC":
        ct = e.encrypt(pad(msg, 8))
        pt = unpad(DES.new(key, M, iv=iv).decrypt(ct), 8)
    else:
        ct = e.encrypt(msg)
        pt = DES.new(key, M, iv=iv).decrypt(ct)

    print("IV:", iv.hex())

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 6\. AES — one generic program for 128 / 192 / 256 bit keys

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]

ct = AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
pt = unpad(AES.new(key, AES.MODE\\\_ECB).decrypt(ct), 16)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

This one program handles:

* AES-128
* AES-192
* AES-256

\---

# 7\. AES-CBC

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]
iv = (input("IV (16 chars): ").encode() + b'0' \\\* 16)\\\[:16]

ct = AES.new(key, AES.MODE\\\_CBC, iv).encrypt(pad(msg, 16))
pt = unpad(AES.new(key, AES.MODE\\\_CBC, iv).decrypt(ct), 16)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 8\. AES-CTR — compact version

The manual explicitly asks for AES in CTR mode with a nonce.

```python
from Crypto.Cipher import AES

msg = input("Message: ").encode()
bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]
nonce = input("Nonce: ").encode()\\\[:8]

ct = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).encrypt(msg)
pt = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).decrypt(ct)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

### Note

In PyCryptodome AES-CTR, the nonce does **not** have to be 16 bytes. A shorter nonce is typical because the remaining bytes are used for the counter.

\---

# 9\. AES — selectable mode: ECB / CBC / CFB / OFB / CTR

This is the most useful single AES program for an unknown exam question.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes

msg = input("Message: ").encode()
bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]
mode = input("Mode \\\[ECB/CBC/CFB/OFB/CTR]: ").upper()

if mode == "ECB":
    ct = AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
    pt = unpad(AES.new(key, AES.MODE\\\_ECB).decrypt(ct), 16)

elif mode == "CTR":
    nonce = get\\\_random\\\_bytes(8)
    ct = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).encrypt(msg)
    pt = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).decrypt(ct)
    print("Nonce:", nonce.hex())

else:
    iv = get\\\_random\\\_bytes(16)
    M = getattr(AES, "MODE\\\_" + mode)

    if mode == "CBC":
        ct = AES.new(key, M, iv=iv).encrypt(pad(msg, 16))
        pt = unpad(AES.new(key, M, iv=iv).decrypt(ct), 16)
    else:
        ct = AES.new(key, M, iv=iv).encrypt(msg)
        pt = AES.new(key, M, iv=iv).decrypt(ct)

    print("IV:", iv.hex())

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 10\. Triple DES (3DES)

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

msg = input("Message: ").encode()
raw = input("3DES key: ").encode()
key = DES3.adjust\\\_key\\\_parity((raw + b'0' \\\* 24)\\\[:24])

ct = DES3.new(key, DES3.MODE\\\_ECB).encrypt(pad(msg, 8))
pt = unpad(DES3.new(key, DES3.MODE\\\_ECB).decrypt(ct), 8)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

### If `ValueError: Triple DES key degenerates to single DES`

The chosen key has repeated structure. Enter a more varied key.

\---

# 11\. Encrypt multiple messages using the same key

The manual asks to encrypt five different messages using the same key.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]

for i in range(int(input("Number of messages: "))):
    msg = input(f"Message {i+1}: ").encode()
    ct = AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
    print(ct.hex())
```

\---

# 12\. Encrypt HEX input directly

Useful when a question provides plaintext blocks in hexadecimal.

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

h = input("Plaintext hex: ")
data = bytes.fromhex(h)
key = bytes.fromhex(input("Key hex (16 hex chars): "))

ct = DES.new(key, DES.MODE\\\_ECB).encrypt(pad(data, 8))
pt = unpad(DES.new(key, DES.MODE\\\_ECB).decrypt(ct), 8)

print("Ciphertext hex:", ct.hex())
print("Recovered hex:", pt.hex())
print("Recovered text:", pt.decode(errors="replace"))
```

\---

# 13\. Encryption/decryption timing — generic helper

```python
import time

def measure(f, \\\*args):
    t = time.perf\\\_counter()
    out = f(\\\*args)
    return out, time.perf\\\_counter() - t
```

\---

# 14\. DES vs AES-256 timing comparison

Directly covers the manual's performance-comparison question.

```python
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes
import time

msg = input("Message: ").encode()
des\\\_key = get\\\_random\\\_bytes(8)
aes\\\_key = get\\\_random\\\_bytes(32)

start = time.perf\\\_counter()
des\\\_ct = DES.new(des\\\_key, DES.MODE\\\_ECB).encrypt(pad(msg, 8))
des\\\_enc = time.perf\\\_counter() - start

start = time.perf\\\_counter()
unpad(DES.new(des\\\_key, DES.MODE\\\_ECB).decrypt(des\\\_ct), 8)
des\\\_dec = time.perf\\\_counter() - start

start = time.perf\\\_counter()
aes\\\_ct = AES.new(aes\\\_key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
aes\\\_enc = time.perf\\\_counter() - start

start = time.perf\\\_counter()
unpad(AES.new(aes\\\_key, AES.MODE\\\_ECB).decrypt(aes\\\_ct), 16)
aes\\\_dec = time.perf\\\_counter() - start

print("DES encrypt:", des\\\_enc)
print("DES decrypt:", des\\\_dec)
print("AES-256 encrypt:", aes\\\_enc)
print("AES-256 decrypt:", aes\\\_dec)
```

### Better timing method

For very small strings, one run is too noisy. Repeat many times:

```python
N = int(input("Iterations: "))
start = time.perf\\\_counter()
for \\\_ in range(N):
    DES.new(des\\\_key, DES.MODE\\\_ECB).encrypt(pad(msg, 8))
print("Average:", (time.perf\\\_counter() - start) / N)
```

\---

# 15\. Compare AES-128 / AES-192 / AES-256 timing

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get\\\_random\\\_bytes
import time

msg = input("Message: ").encode()
N = int(input("Iterations: "))

for bits in (128, 192, 256):
    key = get\\\_random\\\_bytes(bits // 8)
    t = time.perf\\\_counter()
    for \\\_ in range(N):
        AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
    print(bits, (time.perf\\\_counter() - t) / N)
```

\---

# 16\. Compare AES modes by execution time

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get\\\_random\\\_bytes
import time

msg = input("Message: ").encode()
key = get\\\_random\\\_bytes(32)
N = int(input("Iterations: "))

for mode in \\\["ECB", "CBC", "CFB", "OFB", "CTR"]:
    t = time.perf\\\_counter()

    for \\\_ in range(N):
        if mode == "ECB":
            AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
        elif mode == "CTR":
            AES.new(key, AES.MODE\\\_CTR).encrypt(msg)
        else:
            iv = get\\\_random\\\_bytes(16)
            M = getattr(AES, "MODE\\\_" + mode)
            data = pad(msg, 16) if mode == "CBC" else msg
            AES.new(key, M, iv=iv).encrypt(data)

    print(mode, (time.perf\\\_counter() - t) / N)
```

\---

# 17\. Plot execution time graph

The manual explicitly asks for a graph.

```python
import matplotlib.pyplot as plt

names = \\\[]
times = \\\[]

n = int(input("How many results? "))
for \\\_ in range(n):
    names.append(input("Algorithm/mode name: "))
    times.append(float(input("Time: ")))

plt.bar(names, times)
plt.ylabel("Time (seconds)")
plt.xlabel("Algorithm / Mode")
plt.title("Encryption Performance")
plt.show()
```

\---

# 18\. Full DES vs AES mode comparison + plotting

```python
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad
from Crypto.Random import get\\\_random\\\_bytes
import time
import matplotlib.pyplot as plt

msg = input("Message: ").encode()
N = int(input("Iterations: "))

results = {}

# DES ECB
k = get\\\_random\\\_bytes(8)
t = time.perf\\\_counter()
for \\\_ in range(N):
    DES.new(k, DES.MODE\\\_ECB).encrypt(pad(msg, 8))
results\\\["DES-ECB"] = (time.perf\\\_counter() - t) / N

# AES variants
for bits in (128, 192, 256):
    k = get\\\_random\\\_bytes(bits // 8)
    t = time.perf\\\_counter()
    for \\\_ in range(N):
        AES.new(k, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
    results\\\[f"AES-{bits}"] = (time.perf\\\_counter() - t) / N

for k, v in results.items():
    print(k, v)

plt.bar(results.keys(), results.values())
plt.ylabel("Average encryption time (s)")
plt.xticks(rotation=20)
plt.show()
```

\---

# 19\. Read from file -> encrypt -> write ciphertext -> decrypt file

Very useful for scenario-based midsem questions.

## AES file encryption

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

src = input("Input file: ")
enc = input("Encrypted file: ")
out = input("Decrypted file: ")
bits = int(input("AES bits \\\[128/192/256]: "))
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:bits // 8]

with open(src, "rb") as f:
    data = f.read()

ct = AES.new(key, AES.MODE\\\_ECB).encrypt(pad(data, 16))
open(enc, "wb").write(ct)

pt = unpad(AES.new(key, AES.MODE\\\_ECB).decrypt(ct), 16)
open(out, "wb").write(pt)

print("Encrypted:", ct.hex())
print("Recovered:", pt.decode(errors="replace"))
```

\---

# 20\. AES-CBC file encryption — better practical version

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes

src = input("Input file: ")
enc = input("Encrypted output: ")
dec = input("Decrypted output: ")
key = (input("Key: ").encode() + b'0' \\\* 32)\\\[:32]

iv = get\\\_random\\\_bytes(16)
data = open(src, "rb").read()
ct = AES.new(key, AES.MODE\\\_CBC, iv).encrypt(pad(data, 16))
open(enc, "wb").write(iv + ct)

blob = open(enc, "rb").read()
iv, ct = blob\\\[:16], blob\\\[16:]
pt = unpad(AES.new(key, AES.MODE\\\_CBC, iv).decrypt(ct), 16)
open(dec, "wb").write(pt)

print("Done")
```

\---

# 21\. AES round steps — what to write if asked theoretically

For AES-128:

```text
Plaintext (128 bits)
    |
AddRoundKey      <- round key K0
    |
Rounds 1-9:
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey
    |
Round 10:
    SubBytes
    ShiftRows
    AddRoundKey
    |
Ciphertext
```

For AES-192:

* 12 rounds total
* rounds 1–11 are main rounds
* round 12 omits MixColumns

For AES-256:

* 14 rounds total
* rounds 1–13 are main rounds
* round 14 omits MixColumns

\---

# 22\. AES manual core operations — concise implementation backup

Use only if faculty explicitly asks you to demonstrate internals instead of using a library.

## GF(2^8) multiplication

```python
def gmul(a, b):
    r = 0
    while b:
        if b \\\& 1:
            r ^= a
        a = ((a << 1) ^ (0x11B if a \\\& 0x80 else 0)) \\\& 0xFF
        b >>= 1
    return r
```

## ShiftRows

```python
def shift\\\_rows(s):
    return \\\[
        s\\\[0], s\\\[5], s\\\[10], s\\\[15],
        s\\\[4], s\\\[9], s\\\[14], s\\\[3],
        s\\\[8], s\\\[13], s\\\[2], s\\\[7],
        s\\\[12], s\\\[1], s\\\[6], s\\\[11]
    ]
```

## MixColumns

```python
def mix\\\_columns(s):
    out = s\\\[:]
    for i in range(0, 16, 4):
        a = s\\\[i:i+4]
        out\\\[i:i+4] = \\\[
            gmul(a\\\[0],2)^gmul(a\\\[1],3)^a\\\[2]^a\\\[3],
            a\\\[0]^gmul(a\\\[1],2)^gmul(a\\\[2],3)^a\\\[3],
            a\\\[0]^a\\\[1]^gmul(a\\\[2],2)^gmul(a\\\[3],3),
            gmul(a\\\[0],3)^a\\\[1]^a\\\[2]^gmul(a\\\[3],2)
        ]
    return out
```

## AddRoundKey

```python
def add\\\_round\\\_key(s, k):
    return \\\[a ^ b for a, b in zip(s, k)]
```

### Important

A full hand-written AES requires:

* S-box / inverse S-box
* key expansion
* SubBytes
* ShiftRows
* MixColumns
* AddRoundKey
* inverse transformations

That implementation becomes long. For midsem scenario questions, library code is usually the efficient choice unless the question explicitly demands AES internals.

\---

# 23\. DES round — exam explanation

One DES round:

```text
R(i-1) --Expansion 32->48-->
                           XOR round key Ki
                                  |
                              48 bits
                                  |
                           8 S-boxes
                          48 -> 32 bits
                                  |
                             P permutation
                                  |
L(i-1) -------------------------- XOR ---> R(i)

L(i) = R(i-1)
```

Core formulas:

```text
Li = R(i-1)
Ri = L(i-1) XOR F(R(i-1), Ki)
```

After round 16, halves are swapped/recombined and final permutation is applied.

\---

# 24\. Padding — why it is needed

ECB and CBC require plaintext length to be a multiple of the block size.

```python
pad(data, 16)       # AES
pad(data, 8)        # DES / 3DES

unpad(data, 16)
unpad(data, 8)
```

CFB, OFB and CTR behave like stream modes and do not require block padding for arbitrary-length data.

\---

# 25\. ECB vs CBC vs CFB vs OFB vs CTR

|Mode|IV/Nonce|Padding|Main property|
|-|-:|-:|-|
|ECB|No|Yes|Identical plaintext blocks produce identical ciphertext blocks|
|CBC|IV|Yes|Each block depends on previous ciphertext block|
|CFB|IV|No|Block cipher behaves as self-synchronizing stream cipher|
|OFB|IV|No|Generates keystream independent of plaintext/ciphertext|
|CTR|Nonce/counter|No|Encrypts counter values; highly parallelizable|

\---

# 26\. Common mistakes

### Mistake 1 — treating AES key HEX text as raw bytes

If the question gives:

```text
0123456789ABCDEF0123456789ABCDEF
```

this can be interpreted in two different ways:

### As ASCII text

```python
key = input().encode()
```

32 characters = 32 bytes = AES-256.

### As hexadecimal

```python
key = bytes.fromhex(input())
```

32 hex characters = 16 bytes = AES-128.

**Read the question wording carefully.**

The lab manual sometimes labels a 32-character hexadecimal-looking string as AES-128. In that context the intended interpretation is usually **hexadecimal**, therefore use `bytes.fromhex()`.

\---

### Mistake 2 — wrong DES key size

DES API needs exactly **8 bytes**:

```python
key = (input().encode() + b'00000000')\\\[:8]
```

\---

### Mistake 3 — losing IV/nonce

You need the **same IV/nonce** for decryption.

\---

### Mistake 4 — padding CTR/CFB/OFB unnecessarily

Usually not required.

\---

### Mistake 5 — decrypting CBC with a new random IV

Wrong:

```python
AES.new(key, AES.MODE\\\_CBC, get\\\_random\\\_bytes(16)).decrypt(ct)
```

Correct:

```python
iv = get\\\_random\\\_bytes(16)
ct = AES.new(key, AES.MODE\\\_CBC, iv).encrypt(...)
pt = AES.new(key, AES.MODE\\\_CBC, iv).decrypt(ct)
```

\---

# 27\. ASCII key vs HEX key — universal reader

Very useful in an exam because questions vary.

```python
def read\\\_key(prompt="Key: "):
    s = input(prompt).strip()
    kind = input("Key format \\\[text/hex]: ").lower()
    return bytes.fromhex(s) if kind == "hex" else s.encode()
```

Then validate:

```python
key = read\\\_key()
if len(key) not in (16, 24, 32):
    raise ValueError("AES key must be 16, 24 or 32 bytes")
```

\---

# 28\. Universal AES program with text/hex key + mode selection

This is arguably the **single most useful Lab 2 backup program**.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes

msg = input("Message: ").encode()
s = input("Key: ").strip()
key = bytes.fromhex(s) if input("Key format \\\[text/hex]: ").lower() == "hex" else s.encode()

if len(key) not in (16, 24, 32):
    raise ValueError("AES key must be 16/24/32 bytes")

mode = input("Mode \\\[ECB/CBC/CFB/OFB/CTR]: ").upper()

if mode == "ECB":
    ct = AES.new(key, AES.MODE\\\_ECB).encrypt(pad(msg, 16))
    pt = unpad(AES.new(key, AES.MODE\\\_ECB).decrypt(ct), 16)

elif mode == "CTR":
    nonce = get\\\_random\\\_bytes(8)
    ct = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).encrypt(msg)
    pt = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).decrypt(ct)
    print("Nonce:", nonce.hex())

else:
    iv = get\\\_random\\\_bytes(16)
    M = getattr(AES, "MODE\\\_" + mode)
    data = pad(msg, 16) if mode == "CBC" else msg
    ct = AES.new(key, M, iv=iv).encrypt(data)
    out = AES.new(key, M, iv=iv).decrypt(ct)
    pt = unpad(out, 16) if mode == "CBC" else out
    print("IV:", iv.hex())

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 29\. Exam question routing table

|Question wording|Use|
|-|-|
|DES encryption/decryption|Section 3|
|DES CBC|Section 4|
|DES with arbitrary mode|Section 5|
|AES-128 / 192 / 256|Section 6|
|AES CBC|Section 7|
|AES CTR|Section 8|
|AES arbitrary mode|Section 9 or 28|
|Triple DES|Section 10|
|Encrypt multiple messages|Section 11|
|Hexadecimal plaintext block|Section 12|
|DES vs AES performance|Section 14|
|AES key-size performance|Section 15|
|mode comparison|Section 16|
|plot graph|Section 17|
|file encryption|Section 19 / 20|
|explain AES rounds|Section 21|
|implement core AES math|Section 22|
|explain DES round|Section 23|

\---

# 30\. Minimal all-in-one DES/AES/3DES program

If you want only **one file open in the exam**, keep this.

```python
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\\\_random\\\_bytes

alg = input("Algorithm \\\[AES/DES/3DES]: ").upper()
msg = input("Message: ").encode()
mode = input("Mode \\\[ECB/CBC/CFB/OFB/CTR]: ").upper()
raw = input("Key: ").encode()

if alg == "AES":
    bits = int(input("AES bits \\\[128/192/256]: "))
    key = (raw + b'0'\\\*32)\\\[:bits//8]
    B, C = 16, AES
elif alg == "DES":
    key = (raw + b'0'\\\*8)\\\[:8]
    B, C = 8, DES
else:
    key = DES3.adjust\\\_key\\\_parity((raw + b'0'\\\*24)\\\[:24])
    B, C = 8, DES3

if mode == "ECB":
    ct = C.new(key, C.MODE\\\_ECB).encrypt(pad(msg, B))
    pt = unpad(C.new(key, C.MODE\\\_ECB).decrypt(ct), B)

elif mode == "CTR":
    if alg != "AES":
        raise ValueError("Use AES for this compact CTR implementation")
    nonce = get\\\_random\\\_bytes(8)
    ct = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).encrypt(msg)
    pt = AES.new(key, AES.MODE\\\_CTR, nonce=nonce).decrypt(ct)
    print("Nonce:", nonce.hex())

else:
    iv = get\\\_random\\\_bytes(B)
    M = getattr(C, "MODE\\\_" + mode)
    data = pad(msg, B) if mode == "CBC" else msg
    ct = C.new(key, M, iv=iv).encrypt(data)
    out = C.new(key, M, iv=iv).decrypt(ct)
    pt = unpad(out, B) if mode == "CBC" else out
    print("IV:", iv.hex())

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

\---

# 31\. What to say in viva

### Why is AES preferred over DES?

AES supports much larger keys (128/192/256 bits) and DES has only a 56-bit effective key, making DES obsolete for modern security.

### Why does AES have a fixed 128-bit block size even for AES-256?

AES key size changes, but its block size remains 128 bits.

### Why is ECB weak?

Identical plaintext blocks encrypt to identical ciphertext blocks, leaking structural patterns.

### Why does CBC need an IV?

It randomizes the first block so the same plaintext encrypted with the same key does not always start with the same ciphertext.

### Why does CTR not need padding?

CTR produces a keystream and XORs it with plaintext, so arbitrary message lengths are supported.

### Difference between IV and key?

* Key must remain secret.
* IV usually need not remain secret but must satisfy mode-specific uniqueness/randomness requirements.

### Why compare execution times over many iterations?

Single encryption operations are so fast that timer noise may dominate. Averaging many iterations gives more stable results.

### DES key is 64 bits or 56 bits?

DES accepts 64 input bits, but 8 bits are parity bits, so the effective cryptographic key size is 56 bits.

\---

# 32\. Fast checklist before running

```text
\\\[ ] Correct algorithm?
\\\[ ] Correct key byte length?
\\\[ ] Is the key input TEXT or HEX?
\\\[ ] Correct block size? AES=16, DES/3DES=8
\\\[ ] Padding used for ECB/CBC?
\\\[ ] Same IV/nonce reused for decryption?
\\\[ ] Ciphertext printed as .hex()?
\\\[ ] Decrypted output shown?
\\\[ ] Timing asked? use perf\\\_counter()
\\\[ ] Graph asked? store results and plt.bar()
```

\---

# 33\. Recommended files to keep beside this Markdown

If allowed to carry code files, create:

```text
lab2\\\_aes.py
lab2\\\_des.py
lab2\\\_3des.py
lab2\\\_compare.py
lab2\\\_file\\\_crypto.py
```

But this Markdown contains enough code to reconstruct all of them quickly.

