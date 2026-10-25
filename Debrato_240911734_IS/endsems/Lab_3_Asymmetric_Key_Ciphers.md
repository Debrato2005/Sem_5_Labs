# Lab 3 — Asymmetric Key Ciphers

> Exam-ready reference for the Information Security Lab.
>
> **Rule used throughout:** all message/key/parameter values are taken from user input.  
> Keep the smallest program that matches the wording of the question.

---

## 0. What Lab 3 covers

The lab manual covers:

- RSA
- ElGamal
- ECC
- Diffie–Hellman key exchange
- key generation
- encryption/decryption
- file transfer
- timing/performance comparison
- RSA vs ECC / ElGamal comparisons

The manual also asks for:
- RSA with given `(n,e)` and `(n,d)`
- ElGamal with `(p,g,h)` and private key `x`
- ECC using `secp256r1`
- RSA 2048-bit / ECC secure file transfer
- Diffie–Hellman shared-secret generation
- timing of key generation, encryption and decryption

---

# 1. QUICK FORMULAS

## RSA

```text
n = p*q
phi = (p-1)(q-1)

gcd(e, phi) = 1
d = e^(-1) mod phi

Public key  = (n,e)
Private key = (n,d)

Encryption: c = m^e mod n
Decryption: m = c^d mod n
```

Python:

```python
c = pow(m, e, n)
m = pow(c, d, n)
```

---

## ElGamal

```text
Public parameters: p, g
Private key: x
h = g^x mod p

Public key = (p,g,h)

Choose random k

c1 = g^k mod p
c2 = m * h^k mod p

s = c1^x mod p
m = c2 * s^(-1) mod p
```

Python:

```python
h = pow(g, x, p)
c1 = pow(g, k, p)
c2 = m * pow(h, k, p) % p
m = c2 * pow(pow(c1, x, p), -1, p) % p
```

---

## Diffie–Hellman

```text
Public: p, g

Alice private = a
Bob private   = b

A = g^a mod p
B = g^b mod p

Alice secret = B^a mod p
Bob secret   = A^b mod p
```

Both secrets must be equal.

---

## ECC

```text
Private key = d
Public key  = Q = dG
```

ECC itself is normally used for key exchange/signatures rather than directly encrypting a long message.

For an exam question saying **"encrypt using ECC"**, a practical implementation is:

```text
ECDH -> shared secret -> symmetric key -> AES encryption
```

---

# 2. INSTALLS

If required:

```bash
pip install pycryptodome cryptography
```

Imports vary by program. Do not import everything unless needed.

---

# 3. RSA — GIVEN n, e, d — SHORTEST COMPLETE PROGRAM

Use when the question gives:

```text
public key  = (n,e)
private key = (n,d)
```

Works well for small educational RSA values such as the manual's numerical exercises.

```python
msg = input("Message: ").encode()
n = int(input("n: "))
e = int(input("e: "))
d = int(input("d: "))

if any(b >= n for b in msg):
    raise ValueError("n must be greater than every plaintext byte")

ct = [pow(b, e, n) for b in msg]
pt = bytes(pow(c, d, n) for c in ct)

print("Ciphertext:", ct)
print("Decrypted:", pt.decode())
```

### Why encrypt byte-by-byte?

If:

```python
m = int.from_bytes(msg, "big")
```

then RSA requires:

```text
m < n
```

For a very small `n`, a whole message will usually violate this.

Byte-by-byte encryption avoids that for educational examples when `n > 255`.

---

# 4. RSA — GENERATE KEYS FROM p, q, e

Use when the question asks you to perform RSA key generation mathematically.

```python
from math import gcd

p = int(input("p: "))
q = int(input("q: "))
e = int(input("e: "))
msg = input("Message: ").encode()

n = p*q
phi = (p-1)*(q-1)

if gcd(e, phi) != 1:
    raise ValueError("e must be coprime with phi(n)")

d = pow(e, -1, phi)

if any(b >= n for b in msg):
    raise ValueError("n must be > every plaintext byte")

ct = [pow(b, e, n) for b in msg]
pt = bytes(pow(c, d, n) for c in ct)

print("Public key:", (n, e))
print("Private key:", (n, d))
print("Ciphertext:", ct)
print("Decrypted:", pt.decode())
```

---

# 5. RSA — INTEGER-ONLY NUMERICAL

Use if the plaintext itself is an integer.

```python
m = int(input("Plaintext integer: "))
n = int(input("n: "))
e = int(input("e: "))
d = int(input("d: "))

if not 0 <= m < n:
    raise ValueError("RSA requires 0 <= m < n")

c = pow(m, e, n)
p = pow(c, d, n)

print("Ciphertext:", c)
print("Decrypted:", p)
```

---

# 6. RSA — REAL KEY GENERATION + OAEP

Use when the question says:

- RSA 1024/2048/3072...
- generate public/private keys
- encrypt/decrypt securely
- use a standard implementation

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

bits = int(input("RSA key size: "))
msg = input("Message: ").encode()

key = RSA.generate(bits)
pub = key.publickey()

ct = PKCS1_OAEP.new(pub).encrypt(msg)
pt = PKCS1_OAEP.new(key).decrypt(ct)

print("Public key:\n", pub.export_key().decode())
print("Private key:\n", key.export_key().decode())
print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

### Important

RSA cannot directly encrypt arbitrary large files in one operation.

For RSA-OAEP:

```text
maximum plaintext size depends on RSA key size + hash
```

For files, either:

```text
1. encrypt in RSA-sized chunks
```

or preferably:

```text
2. RSA encrypts an AES key
3. AES encrypts the file
```

That is hybrid encryption.

---

# 7. RSA OAEP — SAVE / LOAD KEYS

```python
from Crypto.PublicKey import RSA

bits = int(input("RSA key size: "))
name = input("Key file prefix: ")

key = RSA.generate(bits)

open(name+"_private.pem", "wb").write(key.export_key())
open(name+"_public.pem", "wb").write(key.publickey().export_key())

print("Keys saved")
```

Load:

```python
from Crypto.PublicKey import RSA

path = input("Key file: ")
key = RSA.import_key(open(path, "rb").read())

print(key)
```

---

# 8. RSA FILE ENCRYPTION — OAEP CHUNKING

Use only if the question explicitly expects the file itself to be encrypted using RSA.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

path = input("Input file: ")
bits = int(input("RSA key size: "))

data = open(path, "rb").read()
key = RSA.generate(bits)

enc = PKCS1_OAEP.new(key, hashAlgo=SHA256)
dec = PKCS1_OAEP.new(key, hashAlgo=SHA256)

k = key.size_in_bytes()
chunk = k - 2*SHA256.digest_size - 2

ct = [enc.encrypt(data[i:i+chunk]) for i in range(0, len(data), chunk)]
pt = b"".join(dec.decrypt(x) for x in ct)

print("Original bytes:", len(data))
print("Encrypted blocks:", len(ct))
print("Recovered correctly:", pt == data)

out = input("Decrypted output file: ")
open(out, "wb").write(pt)
```

---

# 9. RSA FILE TRANSFER — RECOMMENDED HYBRID RSA + AES

Use when the scenario says secure file transfer with RSA.

RSA protects the AES key.  
AES protects the file.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

path = input("Input file: ")
bits = int(input("RSA key size: "))
out = input("Recovered file: ")

data = open(path, "rb").read()

rsa = RSA.generate(bits)
aes_key = get_random_bytes(32)

aes = AES.new(aes_key, AES.MODE_GCM)
ct, tag = aes.encrypt_and_digest(data)

ek = PKCS1_OAEP.new(rsa.publickey()).encrypt(aes_key)

aes_key2 = PKCS1_OAEP.new(rsa).decrypt(ek)
pt = AES.new(aes_key2, AES.MODE_GCM, nonce=aes.nonce).decrypt_and_verify(ct, tag)

open(out, "wb").write(pt)

print("Encrypted AES key:", ek.hex())
print("Recovered correctly:", pt == data)
```

---

# 10. ELGAMAL — GIVEN p, g, h, x

Use when the question gives:

```text
Public key = (p,g,h)
Private key = x
```

```python
from secrets import randbelow

msg = input("Message: ").encode()
p = int(input("p: "))
g = int(input("g: "))
h = int(input("h: "))
x = int(input("Private key x: "))

if pow(g, x, p) != h:
    raise ValueError("h != g^x mod p")
if any(b >= p for b in msg):
    raise ValueError("p must be > every plaintext byte")

ct = []

for m in msg:
    k = randbelow(p-2) + 1
    c1 = pow(g, k, p)
    c2 = m * pow(h, k, p) % p
    ct.append((c1, c2))

pt = bytes(
    c2 * pow(pow(c1, x, p), -1, p) % p
    for c1, c2 in ct
)

print("Ciphertext:", ct)
print("Decrypted:", pt.decode())
```

---

# 11. ELGAMAL — GENERATE PUBLIC KEY FROM p, g, x

```python
from secrets import randbelow

msg = input("Message: ").encode()
p = int(input("Prime p: "))
g = int(input("Generator g: "))
x = int(input("Private key x: "))

h = pow(g, x, p)

if any(b >= p for b in msg):
    raise ValueError("p must be > every plaintext byte")

ct = []

for m in msg:
    k = randbelow(p-2) + 1
    c1 = pow(g, k, p)
    c2 = m * pow(h, k, p) % p
    ct.append((c1, c2))

pt = bytes(
    c2 * pow(pow(c1, x, p), -1, p) % p
    for c1, c2 in ct
)

print("Public key:", (p, g, h))
print("Private key:", x)
print("Ciphertext:", ct)
print("Decrypted:", pt.decode())
```

---

# 12. ELGAMAL — INTEGER-ONLY NUMERICAL

Use for handwritten-style numerical questions.

```python
p = int(input("p: "))
g = int(input("g: "))
x = int(input("Private x: "))
k = int(input("Random k: "))
m = int(input("Plaintext integer: "))

h = pow(g, x, p)

c1 = pow(g, k, p)
c2 = m * pow(h, k, p) % p

s = pow(c1, x, p)
pt = c2 * pow(s, -1, p) % p

print("Public key:", (p, g, h))
print("Ciphertext:", (c1, c2))
print("Decrypted:", pt)
```

---

# 13. DIFFIE–HELLMAN — SHORTEST COMPLETE PROGRAM

Use when the question asks:

- key exchange
- Alice/Bob public values
- shared secret
- verify both shared secrets match

```python
p = int(input("Prime p: "))
g = int(input("Generator g: "))
a = int(input("Alice private key: "))
b = int(input("Bob private key: "))

A = pow(g, a, p)
B = pow(g, b, p)

Ka = pow(B, a, p)
Kb = pow(A, b, p)

print("Alice public:", A)
print("Bob public:", B)
print("Alice secret:", Ka)
print("Bob secret:", Kb)
print("Match:", Ka == Kb)
```

---

# 14. DIFFIE–HELLMAN — WITH TIMING

```python
from time import perf_counter

p = int(input("Prime p: "))
g = int(input("Generator g: "))
a = int(input("Alice private key: "))
b = int(input("Bob private key: "))

t = perf_counter()
A = pow(g, a, p)
B = pow(g, b, p)
keygen = perf_counter() - t

t = perf_counter()
Ka = pow(B, a, p)
Kb = pow(A, b, p)
exchange = perf_counter() - t

print("Alice public:", A)
print("Bob public:", B)
print("Shared secret:", Ka)
print("Match:", Ka == Kb)
print("Public-key generation time:", keygen)
print("Key exchange time:", exchange)
```

---

# 15. ECC — KEY GENERATION + ECDH USING secp256r1

The manual specifically refers to `secp256r1`.

With the `cryptography` package, this curve is:

```python
ec.SECP256R1()
```

Program:

```python
from cryptography.hazmat.primitives.asymmetric import ec

a = ec.generate_private_key(ec.SECP256R1())
b = ec.generate_private_key(ec.SECP256R1())

sa = a.exchange(ec.ECDH(), b.public_key())
sb = b.exchange(ec.ECDH(), a.public_key())

print("Alice shared secret:", sa.hex())
print("Bob shared secret:", sb.hex())
print("Match:", sa == sb)
```

There is no message hardcoded here; the generated keys are deliberately random cryptographic keys.

---

# 16. ECC — DISPLAY PRIVATE + PUBLIC VALUES

```python
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
pub = key.public_key().public_numbers()

print("Private d:", key.private_numbers().private_value)
print("Public x:", pub.x)
print("Public y:", pub.y)
```

---

# 17. ECC "ENCRYPT / DECRYPT MESSAGE" — ECDH + AES-GCM

The manual asks to encrypt/decrypt using ECC but does not define a direct ECC encryption scheme.

A practical answer is:

```text
ECC/ECDH establishes a shared secret
        ↓
derive AES key
        ↓
AES-GCM encrypts message
```

```python
from os import urandom
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

msg = input("Message: ").encode()

sender = ec.generate_private_key(ec.SECP256R1())
receiver = ec.generate_private_key(ec.SECP256R1())

s1 = sender.exchange(ec.ECDH(), receiver.public_key())
s2 = receiver.exchange(ec.ECDH(), sender.public_key())

def derive(s):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecc"
    ).derive(s)

k1 = derive(s1)
k2 = derive(s2)

nonce = urandom(12)
ct = AESGCM(k1).encrypt(nonce, msg, None)
pt = AESGCM(k2).decrypt(nonce, ct, None)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

---

# 18. ECC FILE ENCRYPTION — ECDH + AES-GCM

Use for the manual's file-transfer style question.

```python
from os import urandom
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

path = input("Input file: ")
out = input("Recovered file: ")

data = open(path, "rb").read()

sender = ec.generate_private_key(ec.SECP256R1())
receiver = ec.generate_private_key(ec.SECP256R1())

s1 = sender.exchange(ec.ECDH(), receiver.public_key())
s2 = receiver.exchange(ec.ECDH(), sender.public_key())

def key(s):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file"
    ).derive(s)

nonce = urandom(12)
ct = AESGCM(key(s1)).encrypt(nonce, data, None)
pt = AESGCM(key(s2)).decrypt(nonce, ct, None)

open(out, "wb").write(pt)

print("Encrypted bytes:", len(ct))
print("Recovered correctly:", pt == data)
```

---

# 19. RSA — KEY GENERATION / ENCRYPTION / DECRYPTION TIMING

```python
from time import perf_counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

bits = int(input("RSA key size: "))
msg = input("Message: ").encode()

t = perf_counter()
key = RSA.generate(bits)
kg = perf_counter() - t

t = perf_counter()
ct = PKCS1_OAEP.new(key.publickey()).encrypt(msg)
enc = perf_counter() - t

t = perf_counter()
pt = PKCS1_OAEP.new(key).decrypt(ct)
dec = perf_counter() - t

print("Key generation:", kg)
print("Encryption:", enc)
print("Decryption:", dec)
print("Recovered:", pt.decode())
```

---

# 20. ECC — KEY GENERATION / ECDH TIMING

```python
from time import perf_counter
from cryptography.hazmat.primitives.asymmetric import ec

t = perf_counter()
a = ec.generate_private_key(ec.SECP256R1())
b = ec.generate_private_key(ec.SECP256R1())
kg = perf_counter() - t

t = perf_counter()
s1 = a.exchange(ec.ECDH(), b.public_key())
s2 = b.exchange(ec.ECDH(), a.public_key())
ex = perf_counter() - t

print("Key generation:", kg)
print("Key exchange:", ex)
print("Match:", s1 == s2)
```

---

# 21. ELGAMAL — TIMING

```python
from time import perf_counter
from secrets import randbelow

msg = input("Message: ").encode()
p = int(input("p: "))
g = int(input("g: "))
x = int(input("Private x: "))

t = perf_counter()
h = pow(g, x, p)
kg = perf_counter() - t

t = perf_counter()
ct = []
for m in msg:
    k = randbelow(p-2) + 1
    ct.append((pow(g, k, p), m * pow(h, k, p) % p))
enc = perf_counter() - t

t = perf_counter()
pt = bytes(
    c2 * pow(pow(c1, x, p), -1, p) % p
    for c1, c2 in ct
)
dec = perf_counter() - t

print("Key generation:", kg)
print("Encryption:", enc)
print("Decryption:", dec)
print("Recovered:", pt.decode())
```

---

# 22. CREATE TEST FILE OF USER-SELECTED SIZE

Useful for the manual's 1 MB / 10 MB type experiments.

```python
from os import urandom

size = int(input("File size in MB: "))
path = input("Output file: ")

open(path, "wb").write(urandom(size * 1024 * 1024))

print("Created:", path)
```

The size is supplied by the user, not hardcoded.

---

# 23. FILE TIMING TEMPLATE

Wrap any operation with:

```python
from time import perf_counter

t = perf_counter()

# operation here

elapsed = perf_counter() - t
print("Time:", elapsed, "seconds")
```

For speed:

```python
speed = len(data) / elapsed / (1024*1024)
print("Speed:", speed, "MB/s")
```

---

# 24. RSA vs ECC — WHAT TO WRITE IN OBSERVATION

Use only when the question asks for analysis.

```text
RSA
- Security is based on integer factorization.
- Commonly uses much larger keys than ECC.
- RSA can encrypt only limited-size plaintext directly.
- For large files, hybrid encryption is appropriate.
- RSA is widely used for encryption, signatures and key transport.

ECC
- Security is based on the elliptic-curve discrete logarithm problem.
- Achieves strong security with smaller keys.
- Commonly used for ECDH key exchange and ECDSA signatures.
- For file/message encryption, use an ECC-derived shared key with a symmetric cipher.
```

Do not claim one is always "faster" from theory alone if the question asks for measured performance.  
Print actual timings from your run.

---

# 25. RSA vs ELGAMAL — QUICK COMPARISON

```text
RSA
Encryption:
    c = m^e mod n

Decryption:
    m = c^d mod n

Security basis:
    integer factorization

Ciphertext:
    one main ciphertext value/block


ElGamal
Encryption:
    c1 = g^k mod p
    c2 = m*h^k mod p

Decryption:
    m = c2*(c1^x)^(-1) mod p

Security basis:
    discrete logarithm problem

Ciphertext:
    pair (c1,c2)

Important:
    fresh random k is required for every encryption
```

---

# 26. PUBLIC KEY / PRIVATE KEY — DO NOT MIX THESE UP

```text
RSA
Encrypt  -> public key
Decrypt  -> private key

ElGamal
Encrypt  -> public key (p,g,h)
Decrypt  -> private key x

ECC/ECDH
Each party:
private scalar -> derives public point
private key + other party public key -> shared secret

Diffie-Hellman
private values are NEVER transmitted
public values can be transmitted
```

---

# 27. VERY IMPORTANT: ENCRYPTION vs DIGITAL SIGNATURE

Lab 3 is primarily asymmetric encryption/key exchange.

```text
Encryption:
public key  -> encrypt
private key -> decrypt

Digital signature:
private key -> sign
public key  -> verify
```

Do not reverse the terminology.

---

# 28. EXAM ROUTING TABLE

| Question wording | Use |
|---|---|
| RSA with given `n,e,d` | Section 3 |
| Generate RSA using `p,q,e` | Section 4 |
| RSA numerical integer | Section 5 |
| RSA 2048-bit / standard implementation | Section 6 |
| RSA file transfer | Section 9 |
| Direct RSA file/chunks explicitly requested | Section 8 |
| ElGamal with `p,g,h,x` | Section 10 |
| Generate ElGamal public key | Section 11 |
| ElGamal numerical with chosen `k` | Section 12 |
| Diffie–Hellman shared secret | Section 13 |
| DH with timing | Section 14 |
| ECC key exchange | Section 15 |
| Display ECC key values | Section 16 |
| "Encrypt/decrypt using ECC" | Section 17 |
| ECC secure file transfer | Section 18 |
| Compare performance | Sections 19–23 |
| RSA vs ECC analysis | Section 24 |
| RSA vs ElGamal | Section 25 |

---

# 29. COMMON ERRORS

## Error 1 — trying to encrypt a huge plaintext integer with small RSA `n`

Wrong:

```python
m = int.from_bytes(msg, "big")
c = pow(m, e, n)
```

unless:

```text
m < n
```

For small classroom RSA values, encrypt bytes/characters separately.

---

## Error 2 — RSA directly encrypting a 1 MB file

A normal RSA operation cannot encrypt 1 MB directly.

Use:

```text
RSA + AES hybrid
```

or RSA-sized chunks if the instructor explicitly asks for direct RSA experimentation.

---

## Error 3 — ElGamal message >= p

ElGamal mathematical message values must lie in the permitted modular range.

For byte-wise text:

```text
p > 255
```

is the simple classroom condition.

---

## Error 4 — reusing ElGamal k

`k` should be fresh/random for encryption.

---

## Error 5 — Diffie-Hellman described as encryption

DH is primarily a **key exchange** algorithm.

It derives a shared secret.

---

## Error 6 — saying ECC itself directly encrypts arbitrary files

The lab manual asks for ECC encryption but also states that ECC is primarily used for key exchange.

A defensible implementation is:

```text
ECDH + symmetric encryption
```

---

# 30. MINIMUM FORMULAS TO MEMORIZE

```text
RSA
n = pq
phi = (p-1)(q-1)
d = e^-1 mod phi
c = m^e mod n
m = c^d mod n


ELGAMAL
h = g^x mod p
c1 = g^k mod p
c2 = m*h^k mod p
m = c2*(c1^x)^-1 mod p


DH
A = g^a mod p
B = g^b mod p
K = B^a mod p = A^b mod p


ECC
Q = dG
ECDH: own private + other public -> shared secret
```

---

# 31. ONE-LINE PYTHON OPERATIONS TO REMEMBER

```python
pow(a, b, n)       # a^b mod n
pow(a, -1, n)      # modular inverse
```

These two cover most manual RSA, ElGamal and Diffie–Hellman arithmetic.

---

# 32. SHORTEST "WHICH PROGRAM?" COMMENT

Paste this at the top of your Lab 3 notes:

```python
# LAB 3 QUICK RULE
#
# RSA given n,e,d:
#   c = pow(m,e,n)
#   m = pow(c,d,n)
#
# RSA keygen:
#   n=p*q; phi=(p-1)*(q-1); d=pow(e,-1,phi)
#
# ElGamal:
#   h=pow(g,x,p)
#   c1=pow(g,k,p)
#   c2=m*pow(h,k,p)%p
#   m=c2*pow(pow(c1,x,p),-1,p)%p
#
# Diffie-Hellman:
#   A=pow(g,a,p); B=pow(g,b,p)
#   K1=pow(B,a,p); K2=pow(A,b,p)
#
# ECC:
#   private d -> public Q=dG
#   use ECDH to derive shared key
#
# Large file:
#   DO NOT encrypt whole file directly with RSA.
#   Use hybrid: RSA/ECC for key establishment + AES for file.
#
# Encryption: public encrypts, private decrypts.
# Signature: private signs, public verifies.
```

---

# 33. MANUAL-SPECIFIC CAUTION

The lab manual itself says ECC is **primarily used for key exchange rather than direct message encryption**, while some exercises phrase the task as "encrypt the message using ECC."

If this wording appears in the exam, the safe explanation is:

```text
ECC is used to establish/derive the symmetric key (ECDH),
and the actual message/file is encrypted with a symmetric cipher.
```

If the faculty expects a purely mathematical EC-ElGamal implementation instead, use the exact scheme/curve parameters supplied in the question; those parameters are necessary and should not be invented.

---

# END — LAB 3
