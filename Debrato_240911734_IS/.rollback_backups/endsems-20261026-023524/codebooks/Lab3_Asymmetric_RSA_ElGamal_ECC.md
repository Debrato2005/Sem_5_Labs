# Lab 3 — Asymmetric ciphers: RSA, ElGamal, ECC, Diffie–Hellman

Toolkit module: `toolkit/asymmetric.py` (`rsa_*`, `hybrid_encrypt/decrypt`, `elgamal_*`,
`dh_*`, `kdf`, `ecc_generate`, `ecdh`, `ecies_encrypt/decrypt`, `G14_P`).

**Two rules.** Encryption: *receiver's public* encrypts, *receiver's private* decrypts.
Signature (Lab 6): *sender's private* signs, *sender's public* verifies.
Never use `key.encrypt()` / `ElGamal.encrypt()` (removed from pycryptodome).

## 0. Formulas

| Scheme | Key generation | Encrypt | Decrypt |
|---|---|---|---|
| RSA | n=pq, φ=(p−1)(q−1), gcd(e,φ)=1, d=e⁻¹ mod φ | c = mᵉ mod n (0≤m<n) | m = cᵈ mod n |
| ElGamal | prime p, generator g, x∈[1,p−2], y=gˣ mod p | random k: c1=gᵏ, c2=m·yᵏ mod p | s=c1ˣ, m=c2·s⁻¹ mod p |
| DH | public p, g; secrets a, b | A=gᵃ, B=gᵇ | K = Bᵃ = Aᵇ = gᵃᵇ mod p |
| ECC | private d, public Q = d·G | (ECIES) ephemeral k: R=kG, S=kQ, key=H(S) → AES | S = d·R → same key |

RSA-OAEP max plaintext = k − 2·hLen − 2 bytes (RSA-2048 + SHA-256 → 190 bytes). Bigger data →
**hybrid**: AES encrypts data, RSA encrypts the AES key.

## 1. RSA with given n, e, d (numerical, e.g. n=323, e=5, d=173)

Messages larger than n are encrypted in blocks (here 1 byte per block when n is tiny).

<!-- stdin: Cryptographic Protocols | 17 | 19 | 5 -->
```python
from math import gcd
from Crypto.Util.number import isPrime

msg = input('Message: ')
p, q, e = int(input('p: ')), int(input('q: ')), int(input('e: '))
if p == q or not isPrime(p) or not isPrime(q): raise ValueError('Use distinct primes')
n, phi = p * q, (p - 1) * (q - 1)
if not 1 < e < phi or gcd(e, phi) != 1: raise ValueError('gcd(e, phi) must be 1')
d = pow(e, -1, phi)
print(f'n={n} phi={phi} d={d}   public=(n={n}, e={e}) private=(n={n}, d={d})')
size = max(1, (n.bit_length() - 1) // 8)                     # bytes per block, block < n
data = msg.encode()
pieces = [data[i:i + size] for i in range(0, len(data), size)]
blocks = [int.from_bytes(piece, 'big') for piece in pieces]
if any(m >= n for m in blocks): raise ValueError('Modulus is too small for a plaintext block')
ct = [pow(m, e, n) for m in blocks]
print('Ciphertext blocks:', ct)
pt = b''.join(pow(c, d, n).to_bytes(len(piece), 'big') for c, piece in zip(ct, pieces))
print('Decrypted:', pt.decode())
```

## 2. RSA real keys + OAEP + save/load PEM

<!-- stdin: Asymmetric Encryption | 2048 -->
```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

msg = input('Message: ').encode()
key = RSA.generate(int(input('Key bits (2048/3072/4096): ')))
open('private.pem', 'wb').write(key.export_key())               # keep secret
open('public.pem', 'wb').write(key.publickey().export_key())    # distribute
pub = RSA.import_key(open('public.pem', 'rb').read())
priv = RSA.import_key(open('private.pem', 'rb').read())
print('n =', hex(pub.n)[:40], '...  e =', pub.e)
ct = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(msg)          # public encrypts
print('Ciphertext:', ct.hex()[:64], '...')
print('Decrypted :', PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct).decode())
```

## 3. Hybrid RSA + AES (local file encryption and recovery)

The file payload uses AES. RSA wraps the key. This example reads the whole file into
memory and does not send it over a network. Add transport and authenticated key exchange
when the question requires a transfer between hosts.

<!-- stdin: 2000 -->
```python
import os, time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

size_kb = int(input('Test file size in KB: '))
open('file.bin', 'wb').write(os.urandom(size_kb * 1024))
receiver = RSA.generate(2048)

t = time.perf_counter()
data = open('file.bin', 'rb').read()
session = get_random_bytes(32)                                   # AES-256 session key
c = AES.new(session, AES.MODE_GCM, nonce=get_random_bytes(12))
ct, tag = c.encrypt_and_digest(data)
wrapped = PKCS1_OAEP.new(receiver.publickey()).encrypt(session)  # RSA wraps the KEY only
open('file.enc', 'wb').write(len(wrapped).to_bytes(2, 'big') + wrapped + c.nonce + tag + ct)
print(f'encrypt {time.perf_counter() - t:.4f}s')

t = time.perf_counter()
blob = open('file.enc', 'rb').read()
k = int.from_bytes(blob[:2], 'big')
w, nonce, tag2, ct2 = blob[2:2 + k], blob[2 + k:14 + k], blob[14 + k:30 + k], blob[30 + k:]
key = PKCS1_OAEP.new(receiver).decrypt(w)
out = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct2, tag2)
print(f'decrypt {time.perf_counter() - t:.4f}s  identical={out == data}')
```

## 4. ElGamal with given p, g, h(=y), x — CHECK h = gˣ mod p first

Manual additional Q1 gives p=7919, g=2, h=6465, x=2999, but 2²⁹⁹⁹ mod 7919 = **3868**, not 6465:
encrypting with 6465 and decrypting with x=2999 would fail. The program recomputes h from x
and says so. Text is encrypted 1 byte per block when p is small (+1 so a 0 byte never encrypts m=0).

<!-- stdin: Asymmetric Algorithms | 7919 | 2 | 6465 | 2999 -->
```python
import secrets

msg = input('Message: ').encode()
p, g = int(input('p: ')), int(input('g: '))
h, x = int(input('Public h (y): ')), int(input('Private x: '))
if pow(g, x, p) != h:
    print(f'WARNING: g^x mod p = {pow(g, x, p)} != given h={h}; using h = g^x mod p')
    h = pow(g, x, p)
size = max(1, (p.bit_length() - 1) // 8)
ct, lengths = [], []
for i in range(0, len(msg), size):
    piece = msg[i:i + size]
    lengths.append(len(piece))
    m = int.from_bytes(piece, 'big') + 1                # 0 < m < p
    k = secrets.randbelow(p - 3) + 2                              # fresh random k each block
    ct.append((pow(g, k, p), m * pow(h, k, p) % p))
print('Ciphertext (c1, c2):', ct[:4], '...')
out = b''
for (c1, c2), length in zip(ct, lengths):
    m = c2 * pow(pow(c1, x, p), -1, p) % p - 1                    # m = c2 * s^-1 mod p
    out += m.to_bytes(length, 'big')
print('Decrypted:', out.decode())
```

Large keys without given parameters: use the RFC 3526 2048-bit safe prime with g = 2
(`from toolkit.asymmetric import G14_P`) — instant, no prime search. `Crypto.PublicKey.ElGamal.generate(bits, get_random_bytes)` also works but is slow above 1024 bits.

## 5. ECC: key generation (secp256r1) + "encrypt/decrypt" via ECDH + AES-GCM

ECC does not encrypt arbitrary messages directly: derive a shared AES key with ECDH.
This is an ECIES-style hybrid, not mathematical EC-ElGamal point encryption. The manual
asks for "ElGamal using secp256r1" without a message-to-point encoding. State the chosen
interpretation. If point ElGamal is required, its encoding and point operations need a
separate implementation. Do not present this hybrid as that exact construction.

<!-- stdin: Secure Transactions -->
```python
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

def shared_key(my_private, their_public):        # ECDH: d_A * Q_B, hash x-coordinate
    P = their_public.pointQ * my_private.d
    return hashlib.sha256(int(P.x).to_bytes(32, 'big')).digest()

msg = input('Message: ').encode()
receiver = ECC.generate(curve='P-256')            # secp256r1 == P-256 == prime256v1
print('Private d:', hex(receiver.d)[:20], '...  Public Q.x:', hex(receiver.pointQ.x)[:20], '...')
print(receiver.public_key().export_key(format='PEM'))

# sender: ephemeral key + receiver PUBLIC key
eph = ECC.generate(curve='P-256')
c = AES.new(shared_key(eph, receiver.public_key()), AES.MODE_GCM, nonce=get_random_bytes(12))
ct, tag = c.encrypt_and_digest(msg)
packet = (eph.public_key(), c.nonce, ct, tag)                     # send ephemeral PUBLIC key
print('Ciphertext:', ct.hex())

# receiver: own PRIVATE key + ephemeral public key -> same AES key
R, nonce, ct, tag = packet
print('Decrypted :', AES.new(shared_key(receiver, R), AES.MODE_GCM, nonce=nonce)
      .decrypt_and_verify(ct, tag).decode())
```

## 6. Diffie–Hellman key exchange between two peers (+ timing)

<!-- stdin: n -->
```python
import hashlib, secrets, time

G14_P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
            '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
            '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
            '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
if input('Enter your own p and g? (y/n): ').strip().lower() == 'y':
    p, g = int(input('p: ')), int(input('g: '))
else:
    p, g = G14_P, 2                               # RFC 3526 2048-bit group
t = time.perf_counter()
a, b = secrets.randbelow(p - 3) + 2, secrets.randbelow(p - 3) + 2     # private keys
A, B = pow(g, a, p), pow(g, b, p)                                      # public keys (sent)
t_gen = time.perf_counter() - t
t = time.perf_counter()
K1, K2 = pow(B, a, p), pow(A, b, p)
t_ex = time.perf_counter() - t
print('A =', hex(A)[:30], '...\nB =', hex(B)[:30], '...')
print('Shared secrets equal:', K1 == K2)
print('AES key = SHA-256(K):', hashlib.sha256(K1.to_bytes((p.bit_length() + 7) // 8, 'big')).hexdigest())
print(f'keygen {t_gen * 1000:.2f} ms, exchange {t_ex * 1000:.2f} ms')
```

DH alone gives no authentication (man-in-the-middle) — sign A and B (Lab 6) or use RSA
to authenticate the exchange.

## 7. Performance: RSA vs ECC vs ElGamal (key gen / enc / dec)

Enter `1,10` for the manual's small-message comparison or `1024,10240` for 1 MiB and
10 MiB file payloads. Each scheme uses AES-256-GCM for the bulk data. RSA and ElGamal
wrap the session key. ECIES derives it from an ephemeral P-256 exchange.

The ElGamal row uses a finite-field RFC 3526 group. It is a separate comparison with
classical ElGamal, not the manual's ambiguous point-ElGamal wording. Key-generation timing
excludes generation of this fixed group's public parameters. The three parameter sizes
do not imply equal security levels. Packet size includes each scheme's key material,
nonce, tag and ciphertext. DER public keys and the fixed-width ElGamal tuple use different encodings.

<!-- stdin: 1,10 -->
```python
import hashlib, os, secrets, time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
from toolkit.asymmetric import G14_P

sizes = [int(x) for x in input('Payload sizes in KiB (comma separated): ').split(',')]
if not sizes or any(x < 1 for x in sizes):
    raise ValueError('Use positive payload sizes')

def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start

def aes_box(key, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def aes_open(key, packet):
    return AES.new(key, AES.MODE_GCM, nonce=packet[:12]).decrypt_and_verify(packet[28:], packet[12:28])

rsa, rsa_kg = timed(lambda: RSA.generate(2048))
ecc, ecc_kg = timed(lambda: ECC.generate(curve='P-256'))
p, g = G14_P, 2
width = (p.bit_length() + 7) // 8

def elg_keygen():
    x = secrets.randbelow(p - 3) + 2
    return x, pow(g, x, p)

(x, y), elg_kg = timed(elg_keygen)
def point_key(point):
    return hashlib.sha256(int(point.x).to_bytes(32, 'big')).digest()

def rsa_enc(data):
    key = get_random_bytes(32)
    wrapped = PKCS1_OAEP.new(rsa.publickey(), hashAlgo=SHA256).encrypt(key)
    return wrapped + aes_box(key, data)

def rsa_dec(packet):
    width = rsa.size_in_bytes()
    key = PKCS1_OAEP.new(rsa, hashAlgo=SHA256).decrypt(packet[:width])
    return aes_open(key, packet[width:])

def ecc_enc(data):
    eph = ECC.generate(curve='P-256')
    public = eph.public_key().export_key(format='DER')
    return len(public).to_bytes(2, 'big') + public + aes_box(point_key(ecc.pointQ * eph.d), data)

def ecc_dec(packet):
    size = int.from_bytes(packet[:2], 'big')
    eph = ECC.import_key(packet[2:2 + size])
    return aes_open(point_key(eph.pointQ * ecc.d), packet[2 + size:])

def elg_enc(data):
    key = get_random_bytes(32)
    r = secrets.randbelow(p - 3) + 2
    c1 = pow(g, r, p)
    c2 = (int.from_bytes(key, 'big') + 1) * pow(y, r, p) % p
    return c1.to_bytes(width, 'big') + c2.to_bytes(width, 'big') + aes_box(key, data)

def elg_dec(packet):
    c1 = int.from_bytes(packet[:width], 'big')
    c2 = int.from_bytes(packet[width:2 * width], 'big')
    key = (c2 * pow(pow(c1, x, p), -1, p) % p - 1).to_bytes(32, 'big')
    return aes_open(key, packet[2 * width:])

schemes = [
    ('RSA-2048 hybrid', rsa_kg, len(rsa.publickey().export_key('DER')), rsa_enc, rsa_dec),
    ('P-256 ECIES', ecc_kg, len(ecc.public_key().export_key(format='DER')), ecc_enc, ecc_dec),
    ('ElGamal-2048 hybrid', elg_kg, 3 * width, elg_enc, elg_dec),
]
for kib in sizes:
    data = os.urandom(kib * 1024)
    for name, keygen, pub_size, encrypt, decrypt in schemes:
        packet, enc_time = timed(lambda: encrypt(data))
        plain, dec_time = timed(lambda: decrypt(packet))
        assert plain == data
        print(f'{name}: input={len(data)} B keygen={keygen:.4f}s enc={enc_time:.4f}s dec={dec_time:.4f}s '
              f'public={pub_size} B packet={len(packet)} B overhead={len(packet)-len(data)} B match=True')
```

Write the measured values in your report. Key generation is measured once per scheme,
then reused for each payload size. Repeat runs for a stable comparison. Fixed parameter
selection, hybrid encryption and serialization are implementation choices, not official
performance results. Transport and authenticated exchange of public keys need separate code.

## 8. Exam checklist (Lab 3)
* Inputs via `input()`; validate primes (`Crypto.Util.number.isPrime`), gcd(e,φ)=1, 0≤m<n, 0<m<p.
* Use OAEP for RSA encryption; hybrid for anything longer than ~190 bytes.
* ElGamal: new random k for every encryption (reusing k leaks m2 = m1·c2'/c2).
* Print public key, ciphertext and recovered plaintext; for timing questions print a table.
