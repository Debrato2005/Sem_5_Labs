# Lab 2 — DES, 3DES, AES and modes of operation

Toolkit module: `toolkit/symmetric.py` (`sym_encrypt/sym_decrypt` for any alg+mode,
`aes_cbc_*`, `aes_gcm_*`, `encrypt_file`, `password_seal`, `cipher_benchmark`, and a
from-scratch AES with `trace=True`). Most blocks use only pycryptodome. The AES round
trace imports the local toolkit, and the optional graph also needs matplotlib.

## 0. Facts you must get right

| | key bytes | block | rounds | notes |
|---|---|---|---|---|
| DES | 8 (56 effective bits + parity) | 8 | 16 Feistel | legacy, brute-forceable |
| 3DES | 16 (K1,K2,K1) or 24 (K1,K2,K3) | 8 | 48 | K1=K2=K3 is refused ("degenerates to single DES") |
| AES-128/192/256 | 16 / 24 / 32 | 16 | 10 / 12 / 14 | final round has no MixColumns |

| Mode | IV / nonce | padding? | notes |
|---|---|---|---|
| ECB | none | yes | same block → same ciphertext (insecure, shows patterns) |
| CBC | IV = block size, random | yes | `C_i = E(P_i ⊕ C_{i−1})`; needs separate integrity (signature/HMAC) |
| CFB / OFB | IV = block size | no | stream-like |
| CTR | nonce (≤ block−1 bytes, AES: 8) | no | counter stream; never reuse nonce+key |
| GCM / EAX | nonce (GCM 12 B) | no | **authenticated**: tamper → `ValueError: MAC check failed` |

**Key input trap.** `"0123456789ABCDEF0123456789ABCDEF"` for AES-128 is **hex** (16 bytes).
`"A1B2C3D4"` for DES is **text** (8 bytes). Decide by the required length (helper below).
Manual traps: the AES-192 key `"FEDCBA9876543210FEDCBA9876543210"` is only 16 bytes as hex
(32 as text) — neither is 24, so state your fix (e.g. use the first 24 text bytes, or pad);
the 3DES key `"1234567890ABCDEF"×3` has K1=K2=K3 → pycryptodome raises `ValueError`
(use a different K2, or explain that it collapses to single DES).

## 1. Key / IV input helper (paste with any block)

<!-- stdin: 0123456789ABCDEF0123456789ABCDEF | A1B2C3D4 -->
```python
def parse_key(text, sizes):
    """Return key bytes of an allowed size: hex if that fits, else UTF-8 text."""
    text = text.strip()
    try:
        b = bytes.fromhex(text)
        if len(b) in sizes:
            return b
    except ValueError:
        pass
    b = text.encode()
    if len(b) not in sizes:
        raise ValueError(f'key must be {sizes} bytes (got {len(b)} as text)')
    return b

print(parse_key(input('AES key: '), (16, 24, 32)).hex())     # -> 16-byte key from hex
print(parse_key(input('DES key: '), (8,)))                   # -> b'A1B2C3D4'
```

## 2. Select the algorithm and a supported mode

<!-- stdin: AES | CBC | 0123456789ABCDEF0123456789ABCDEF | Sensitive Information -->
```python
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ALGS = {'AES': (AES, (16, 24, 32)), 'DES': (DES, (8,)), '3DES': (DES3, (16, 24))}

def parse_key(text, sizes):
    try:
        b = bytes.fromhex(text.strip())
        if len(b) in sizes: return b
    except ValueError: pass
    b = text.strip().encode()
    if len(b) not in sizes: raise ValueError(f'key must be {sizes} bytes')
    return b

def make(mod, key, mode, iv=None):
    m = getattr(mod, 'MODE_' + mode)
    if mode == 'ECB': return mod.new(key, m)
    if mode in ('CBC', 'CFB', 'OFB'): return mod.new(key, m, iv=iv) if iv else mod.new(key, m)
    if mode == 'CTR': return mod.new(key, m, nonce=iv if iv is not None else get_random_bytes(mod.block_size // 2))
    return mod.new(key, m, nonce=iv) if iv else mod.new(key, m)          # GCM / EAX

alg = input('Algorithm (AES/DES/3DES): ').strip().upper()
mode = input('Mode (ECB/CBC/CFB/OFB/CTR/GCM): ').strip().upper()
mod, sizes = ALGS[alg]
if mode == 'GCM' and alg != 'AES': raise ValueError('GCM requires AES in this program')
key = parse_key(input(f'Key {sizes} bytes (text or hex): '), sizes)
msg = input('Message: ').encode()
bs = mod.block_size

c = make(mod, key, mode)
iv = getattr(c, 'iv', None) or getattr(c, 'nonce', None)
if mode in ('ECB', 'CBC'):
    ct = c.encrypt(pad(msg, bs))
elif mode in ('GCM', 'EAX'):
    ct, tag = c.encrypt_and_digest(msg)
else:
    ct = c.encrypt(msg)
print('IV/nonce  :', iv.hex() if iv else '(none)')
print('Ciphertext:', ct.hex())

d = make(mod, key, mode, iv)
if mode in ('ECB', 'CBC'):
    pt = unpad(d.decrypt(ct), bs)
elif mode in ('GCM', 'EAX'):
    pt = d.decrypt_and_verify(ct, tag)          # raises ValueError if tampered
else:
    pt = d.decrypt(ct)
print('Decrypted :', pt.decode())
```

## 3. Manual exercises (short forms)

<!-- stdin: Confidential Data | A1B2C3D4 -->
```python
# Q1  DES-ECB  ("Confidential Data", key "A1B2C3D4")
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
msg, key = input('Message: ').encode(), input('DES key (8 chars): ').encode()
ct = DES.new(key, DES.MODE_ECB).encrypt(pad(msg, 8))
print('Ciphertext:', ct.hex())
print('Decrypted :', unpad(DES.new(key, DES.MODE_ECB).decrypt(ct), 8).decode())
```

<!-- stdin: Secure Communication | A1B2C3D4 | 12345678 -->
```python
# Additional Q4  DES-CBC with given IV ("Secure Communication", key "A1B2C3D4", IV "12345678")
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
msg = input('Message: ').encode()
key, iv = input('Key (8 chars): ').encode(), input('IV (8 chars): ').encode()
if len(key) != 8 or len(iv) != 8: raise ValueError('DES key and IV must be 8 bytes')
ct = DES.new(key, DES.MODE_CBC, iv=iv).encrypt(pad(msg, 8))
print('Ciphertext:', ct.hex())
print('Decrypted :', unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ct), 8).decode())
```

<!-- stdin: Cryptography Lab Exercise | 0123456789ABCDEF0123456789ABCDEF | 0000000000000000 -->
```python
# Additional Q5  AES-CTR with nonce "0000000000000000" (8 bytes as hex)
from Crypto.Cipher import AES
msg = input('Message: ').encode()
key = bytes.fromhex(input('AES-128 key (32 hex): '))
nonce = bytes.fromhex(input('Nonce (16 hex = 8 bytes): '))
ct = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(msg)          # no padding in CTR
print('Ciphertext:', ct.hex())
print('Decrypted :', AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct).decode())
```

<!-- stdin: A1B2C3D4E5F60708 | 54686973206973206120636f6e666964656e7469616c206d657373616765 | 416e64207468697320697320746865207365636f6e6420626c6f636b -->
```python
# Additional Q2  DES on given HEX blocks with key "A1B2C3D4E5F60708" (hex -> 8 bytes)
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
key = bytes.fromhex(input('DES key (16 hex): '))
for i in (1, 2):
    block = bytes.fromhex(input(f'Block{i} hex: '))
    ct = DES.new(key, DES.MODE_ECB).encrypt(pad(block, 8))
    print(f'Block{i} ciphertext:', ct.hex())
    print(f'Block{i} decrypted :', unpad(DES.new(key, DES.MODE_ECB).decrypt(ct), 8).decode())
```

<!-- stdin: Classified Text | 1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF -->
```python
# Q4  Triple DES - the manual's key repeats K1=K2=K3, which pycryptodome refuses.
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
msg = input('Message: ').encode()
key = bytes.fromhex(input('3DES key (32 or 48 hex): '))
try:
    key = DES3.adjust_key_parity(key)
    DES3.new(key, DES3.MODE_ECB)
except ValueError as e:
    print('Key rejected:', e, '-> using K1|K2|K3 with K2 changed for the demo')
    key = DES3.adjust_key_parity(key[:8] + bytes(b ^ 0xFF for b in key[8:16]) + key[16:])
ct = DES3.new(key, DES3.MODE_ECB).encrypt(pad(msg, 8))
print('Ciphertext:', ct.hex())
print('Decrypted :', unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ct), 8).decode())
```

## 4. Show every AES step (Q5: key expansion, initial round, main rounds, final round)

Uses the from-scratch AES in the toolkit (verified against pycryptodome for 128/192/256).
To make it standalone, copy the "AES from scratch" part of `toolkit/symmetric.py`
(`gf_mul` … `aes_encrypt_block`, ~110 lines).

<!-- stdin: Top Secret Data | FEDCBA9876543210FEDCBA98 -->
```python
from toolkit.symmetric import aes_encrypt_block, aes_decrypt_block
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

msg = pad(input('Message: ').encode(), 16)[:16]          # first block shown step by step
key = input('Key (16/24/32 chars; 24 = AES-192): ').encode()
ct = aes_encrypt_block(key, msg, trace=True)              # prints round keys + every step
print('Ciphertext block :', ct.hex())
print('pycryptodome says:', AES.new(key, AES.MODE_ECB).encrypt(msg).hex())
print('Decrypted        :', aes_decrypt_block(key, ct))
```

Theory to write: **SubBytes** (S-box = GF(2⁸) inverse + affine map), **ShiftRows** (row r
rotated left r bytes), **MixColumns** (each column × fixed matrix [2 3 1 1] in GF(2⁸) mod
x⁸+x⁴+x³+x+1), **AddRoundKey** (XOR round key). Key expansion: Nk = 4/6/8 words,
`w[i] = w[i−Nk] ⊕ SubWord(RotWord(w[i−1])) ⊕ Rcon` every Nk words (AES-256 also SubWord at i mod 8 = 4).

<!-- stdin: -->
```python
def gf_mul(a, b):                       # multiplication in GF(2^8), poly 0x11B
    r = 0
    while b:
        if b & 1: r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r

def mix_column(col, m=(2, 3, 1, 1)):    # inverse: m = (14, 11, 13, 9)
    return [gf_mul(col[0], m[-i % 4]) ^ gf_mul(col[1], m[(1 - i) % 4]) ^
            gf_mul(col[2], m[(2 - i) % 4]) ^ gf_mul(col[3], m[(3 - i) % 4]) for i in range(4)]

out = mix_column([0xdb, 0x13, 0x53, 0x45])
print('MixColumns:', bytes(out).hex(), '(expected 8e4da1bc)')
print('InvMix    :', bytes(mix_column(out, (14, 11, 13, 9))).hex())
print('0x57*0x83 =', hex(gf_mul(0x57, 0x83)), '(expected 0xc1)')
```

## 5. Timing comparison (Q3, additional Q1) + optional plot

Read five different messages, then use one key per algorithm across all five. Each trial
creates a new IV or nonce. The table reports encryption and decryption separately for
DES and AES-128/192/256 in ECB, CBC, CFB, OFB and CTR. This covers additional Q1.
For Q3 alone, compare the DES and AES-256 rows for the specified performance message.

<!-- stdin: Performance Testing of Encryption Algorithms | alpha | longer second message | Sensitive Information | fifth message | 20 -->
```python
import time
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

messages = [input(f'Message {i + 1} of 5: ').encode() for i in range(5)]
if len(set(messages)) != 5:
    raise ValueError('Enter five different messages')
reps = int(input('Repetitions per message and mode: '))
if reps < 1:
    raise ValueError('Repetitions must be positive')
results = {}
for name, mod, ks in (('DES', DES, 8), ('AES-128', AES, 16), ('AES-192', AES, 24), ('AES-256', AES, 32)):
    key = get_random_bytes(ks)  # same key for all five messages with this algorithm
    for mode in ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'):
        mode_id = getattr(mod, 'MODE_' + mode)
        rows = []
        for number, msg in enumerate(messages, 1):
            padded = mode in ('ECB', 'CBC')
            data = pad(msg, mod.block_size) if padded else msg
            start = time.perf_counter()
            for _ in range(reps):
                if mode == 'CTR':
                    c = mod.new(key, mode_id, nonce=get_random_bytes(mod.block_size // 2))
                else:
                    c = mod.new(key, mode_id)
                ct = c.encrypt(data)
            enc = (time.perf_counter() - start) / reps
            options = {'nonce': c.nonce} if mode == 'CTR' else ({'iv': c.iv} if mode != 'ECB' else {})
            start = time.perf_counter()
            for _ in range(reps):
                out = mod.new(key, mode_id, **options).decrypt(ct)
                recovered = unpad(out, mod.block_size) if padded else out
            dec = (time.perf_counter() - start) / reps
            assert recovered == msg
            rows.append((enc, dec))
            print(f'{name:8} {mode:3} message {number}: enc {enc * 1e6:.2f} us  dec {dec * 1e6:.2f} us  match=True')
        results[f'{name} {mode}'] = tuple(sum(row[i] for row in rows) / 5 for i in (0, 1))
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    labels = list(results)
    positions = list(range(len(labels)))
    plt.bar([x - 0.2 for x in positions], [results[k][0] * 1e6 for k in labels], 0.4, label='Encrypt')
    plt.bar([x + 0.2 for x in positions], [results[k][1] * 1e6 for k in labels], 0.4, label='Decrypt')
    plt.ylabel('Mean time across five messages (us)')
    plt.xticks(positions, labels, rotation=90)
    plt.legend()
    plt.tight_layout()
    plt.savefig('timing.png')
    print('Graph saved to timing.png')
except ImportError:
    print('matplotlib is absent: table only, graph not generated')
```

Report the measured timings. CPU acceleration, message sizes and cipher setup affect
which result is faster. These short-message measurements include cipher creation and
padding costs. They do not establish a universal speed ranking or a security ranking.
Install the optional matplotlib dependency when the exercise requires the graph.

## 6. File encryption (authenticated)

<!-- stdin: hello file -->
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

open('plain.txt', 'w').write(input('File content: '))
key = get_random_bytes(32)
data = open('plain.txt', 'rb').read()
c = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
ct, tag = c.encrypt_and_digest(data)
open('plain.txt.enc', 'wb').write(c.nonce + tag + ct)          # nonce|tag|ciphertext

blob = open('plain.txt.enc', 'rb').read()
pt = AES.new(key, AES.MODE_GCM, nonce=blob[:12]).decrypt_and_verify(blob[28:], blob[12:28])
print('Recovered:', pt.decode())
```

## 7. Exam checklist (Lab 2)
* Exact key length for the algorithm; say whether you read the key as text or hex.
* CBC/ECB: `pad` before encrypt, `unpad` after decrypt. CTR/CFB/OFB/GCM: no padding.
* Store/print the IV or nonce — decryption needs it; never reuse (key, nonce) in CTR/GCM.
* CBC has no integrity: verify a MAC/signature of the IV and ciphertext **before** decrypting
  (or use GCM). Print both ciphertext (hex) and recovered plaintext.
