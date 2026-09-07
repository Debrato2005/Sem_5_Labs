Below is the Lab 3 equivalent in the same style: **individual reusable programs**, not one giant abstraction. I am keeping the source’s RSA / ElGamal / ECC / Diffie-Hellman structure. 

One source issue matters: the manual describes classical ElGamal over integers modulo a prime \(p\), but later asks for “ElGamal using secp256r1”. Those are not the same construction. I separate them below instead of silently mixing them.

````md
# Lab 3 — Asymmetric Cryptography Programs

Install:

```bash
pip install pycryptodome cryptography matplotlib
````

---

# 1. RSA From Scratch — Key Generation, Encryption, Decryption

For learning the mathematics:

$$
n=pq
$$

$$
\phi(n)=(p-1)(q-1)
$$

$$
d=e^{-1}\pmod{\phi(n)}
$$

$$
c=m^e \pmod n
$$

$$
m=c^d \pmod n
$$

```python
from math import gcd

p = int(input("Prime p: "))
q = int(input("Prime q: "))

n = p * q
phi = (p - 1) * (q - 1)

e = int(input("Public exponent e: "))

if gcd(e, phi) != 1:
    raise ValueError("e must be coprime with phi(n)")

d = pow(e, -1, phi)

print("Public key :", (n, e))
print("Private key:", (n, d))

m = int(input(f"Message integer [0-{n-1}]: "))

c = pow(m, e, n)
decrypted = pow(c, d, n)

print("Ciphertext:", c)
print("Plaintext :", decrypted)
```

---

# 2. RSA From Scratch — Encrypt Text Character-by-Character

Useful when `n` is small, such as:

```text
n = 323
e = 5
d = 173
```

Each character is converted to its ASCII value.

```python
def encrypt(text, n, e):
    return [
        pow(ord(c), e, n)
        for c in text
    ]


def decrypt(ciphertext, n, d):
    return ''.join(
        chr(pow(c, d, n))
        for c in ciphertext
    )


text = input("Plaintext: ")

n = int(input("n: "))
e = int(input("e: "))
d = int(input("d: "))

cipher = encrypt(text, n, e)

print("Ciphertext:", cipher)
print("Plaintext :", decrypt(cipher, n, d))
```

For the manual example:

```text
n = 323
e = 5
d = 173
```

This character-wise approach is necessary because the entire string converted to one integer would be much larger than `n`.

---

# 3. RSA-2048 Key Generation

```python
from Crypto.PublicKey import RSA

bits = int(input("RSA key size [2048]: ") or 2048)

key = RSA.generate(bits)

private_key = key.export_key()
public_key = key.publickey().export_key()

print("Public key:\n")
print(public_key.decode())

print("\nPrivate key:\n")
print(private_key.decode())
```

---

# 4. RSA-2048 Encryption / Decryption Using OAEP

For practical RSA encryption, use padding such as OAEP rather than textbook RSA.

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

text = input("Plaintext: ").encode()

key = RSA.generate(2048)

public_key = key.publickey()

encryptor = PKCS1_OAEP.new(public_key)

ciphertext = encryptor.encrypt(text)

print("Ciphertext:", ciphertext.hex())


decryptor = PKCS1_OAEP.new(key)

plaintext = decryptor.decrypt(ciphertext)

print("Plaintext:", plaintext.decode())
```

---

# 5. RSA With Public and Private Key Files

Generate and save:

```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

with open("private.pem", "wb") as f:
    f.write(key.export_key())

with open("public.pem", "wb") as f:
    f.write(
        key.publickey().export_key()
    )

print("Keys generated")
```

Encryption:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

text = input("Plaintext: ").encode()

cipher = PKCS1_OAEP.new(public_key)

encrypted = cipher.encrypt(text)

print("Ciphertext:", encrypted.hex())
```

Decryption:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

ciphertext = bytes.fromhex(
    input("Ciphertext hex: ")
)

cipher = PKCS1_OAEP.new(private_key)

plaintext = cipher.decrypt(ciphertext)

print("Plaintext:", plaintext.decode())
```

---

# 6. RSA Key Generation Timing

```python
from Crypto.PublicKey import RSA
from time import perf_counter

bits = int(input("RSA bits: "))

start = perf_counter()

key = RSA.generate(bits)

elapsed = perf_counter() - start

print("Key generation time:", elapsed, "seconds")
```

---

# 7. RSA Encryption / Decryption Timing

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from time import perf_counter

message = input("Message: ").encode()

key = RSA.generate(2048)

encryptor = PKCS1_OAEP.new(
    key.publickey()
)

start = perf_counter()

ciphertext = encryptor.encrypt(message)

enc_time = perf_counter() - start


decryptor = PKCS1_OAEP.new(key)

start = perf_counter()

plaintext = decryptor.decrypt(ciphertext)

dec_time = perf_counter() - start


print("Encryption:", enc_time)
print("Decryption:", dec_time)
print("Plaintext :", plaintext.decode())
```

---

# 8. Classical ElGamal — Key Generation

The manual defines:

$$
y=g^x\pmod p
$$

Public key:

$$
(p,g,y)
$$

Private key:

$$
x
$$

```python
import secrets

p = int(input("Prime p: "))
g = int(input("Generator g: "))

x = secrets.randbelow(p - 2) + 1

y = pow(g, x, p)

print("Private key:", x)
print("Public key :", (p, g, y))
```

---

# 9. Classical ElGamal — Integer Encryption / Decryption

Encryption:

$$
c_1=g^k\pmod p
$$

$$
c_2=m y^k\pmod p
$$

Decryption:

$$
s=c_1^x\pmod p
$$

$$
m=c_2s^{-1}\pmod p
$$

```python
import secrets


def encrypt(m, p, g, y):
    k = secrets.randbelow(p - 2) + 1

    c1 = pow(g, k, p)

    s = pow(y, k, p)

    c2 = (m * s) % p

    return c1, c2


def decrypt(c1, c2, p, x):
    s = pow(c1, x, p)

    s_inv = pow(s, -1, p)

    return (c2 * s_inv) % p


p = int(input("p: "))
g = int(input("g: "))
x = int(input("Private key x: "))

y = pow(g, x, p)

m = int(input(f"Message integer < {p}: "))

c1, c2 = encrypt(
    m,
    p,
    g,
    y
)

print("Ciphertext:", (c1, c2))

plain = decrypt(
    c1,
    c2,
    p,
    x
)

print("Plaintext:", plain)
```

---

# 10. Classical ElGamal — Text Encryption

Each byte is encrypted separately.

This works when:

$$
p > 255
$$

```python
import secrets


def encrypt(text, p, g, y):
    result = []

    for m in text.encode():

        k = secrets.randbelow(p - 2) + 1

        c1 = pow(g, k, p)
        s = pow(y, k, p)

        c2 = (m * s) % p

        result.append(
            (c1, c2)
        )

    return result


def decrypt(ciphertext, p, x):
    result = []

    for c1, c2 in ciphertext:

        s = pow(c1, x, p)

        m = (
            c2
            * pow(s, -1, p)
        ) % p

        result.append(m)

    return bytes(result).decode()


p = int(input("p: "))
g = int(input("g: "))
x = int(input("Private key x: "))

y = pow(g, x, p)

text = input("Plaintext: ")

cipher = encrypt(
    text,
    p,
    g,
    y
)

print("Ciphertext:", cipher)

print(
    "Plaintext:",
    decrypt(cipher, p, x)
)
```

---

# 11. ElGamal Using Given Public and Private Keys

For:

```text
p = 7919
g = 2
h = 6465
x = 2999
```

where the manual calls the public component `h`.

```python
import secrets


def encrypt(text, p, g, h):
    result = []

    for m in text.encode():

        k = secrets.randbelow(p - 2) + 1

        c1 = pow(g, k, p)

        c2 = (
            m * pow(h, k, p)
        ) % p

        result.append(
            (c1, c2)
        )

    return result


def decrypt(ciphertext, p, x):
    result = []

    for c1, c2 in ciphertext:

        s = pow(c1, x, p)

        m = (
            c2
            * pow(s, -1, p)
        ) % p

        result.append(m)

    return bytes(result).decode()


p = 7919
g = 2
h = 6465
x = 2999

text = input("Plaintext: ")

cipher = encrypt(
    text,
    p,
    g,
    h
)

print("Ciphertext:", cipher)

print(
    "Plaintext:",
    decrypt(cipher, p, x)
)
```

---

# 12. ElGamal Key Generation / Encryption / Decryption Timing

```python
import secrets
from time import perf_counter


p = int(input("Prime p: "))
g = int(input("Generator g: "))


start = perf_counter()

x = secrets.randbelow(p - 2) + 1

y = pow(g, x, p)

key_time = perf_counter() - start


m = int(input("Message integer: "))


start = perf_counter()

k = secrets.randbelow(p - 2) + 1

c1 = pow(g, k, p)

c2 = (
    m * pow(y, k, p)
) % p

enc_time = perf_counter() - start


start = perf_counter()

s = pow(c1, x, p)

plain = (
    c2
    * pow(s, -1, p)
) % p

dec_time = perf_counter() - start


print("Key generation:", key_time)
print("Encryption    :", enc_time)
print("Decryption    :", dec_time)
print("Plaintext     :", plain)
```

---

# 13. Basic Diffie-Hellman From Scratch

Public parameters:

$$
p,g
$$

Alice:

$$
A=g^a\pmod p
$$

Bob:

$$
B=g^b\pmod p
$$

Shared secret:

$$
K=B^a=A^b\pmod p
$$

```python
import secrets

p = int(input("Prime p: "))
g = int(input("Generator g: "))

alice_private = secrets.randbelow(
    p - 2
) + 1

bob_private = secrets.randbelow(
    p - 2
) + 1


alice_public = pow(
    g,
    alice_private,
    p
)

bob_public = pow(
    g,
    bob_private,
    p
)


alice_secret = pow(
    bob_public,
    alice_private,
    p
)

bob_secret = pow(
    alice_public,
    bob_private,
    p
)


print("Alice public:", alice_public)
print("Bob public  :", bob_public)

print("Alice secret:", alice_secret)
print("Bob secret  :", bob_secret)

print(
    "Match:",
    alice_secret == bob_secret
)
```

---

# 14. Diffie-Hellman Timing

```python
import secrets
from time import perf_counter

p = int(input("Prime p: "))
g = int(input("Generator g: "))


start = perf_counter()

a = secrets.randbelow(p - 2) + 1
A = pow(g, a, p)

b = secrets.randbelow(p - 2) + 1
B = pow(g, b, p)

key_generation_time = (
    perf_counter() - start
)


start = perf_counter()

alice_secret = pow(
    B,
    a,
    p
)

bob_secret = pow(
    A,
    b,
    p
)

exchange_time = (
    perf_counter() - start
)


print(
    "Key generation:",
    key_generation_time
)

print(
    "Key exchange:",
    exchange_time
)

print(
    "Shared secret:",
    alice_secret
)

print(
    "Equal:",
    alice_secret == bob_secret
)
```

---

# 15. ECC secp256r1 Key Generation

The manual uses ECC and later specifically mentions `secp256r1`.

```python
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(
    ec.SECP256R1()
)

public_key = private_key.public_key()

numbers = public_key.public_numbers()

print(
    "Private key:",
    private_key.private_numbers().private_value
)

print("Public X:", numbers.x)
print("Public Y:", numbers.y)
```

Conceptually:

$$
Q=dG
$$

where:

* `d` = private key
* `G` = curve generator
* `Q` = public key

---

# 16. ECC Key Generation Timing

```python
from cryptography.hazmat.primitives.asymmetric import ec
from time import perf_counter

runs = int(
    input("Runs: ") or 1000
)

start = perf_counter()

for _ in range(runs):

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

elapsed = (
    perf_counter() - start
) / runs

print(
    "Average ECC key generation:",
    elapsed,
    "seconds"
)
```

---

# 17. ECDH Key Exchange Using secp256r1

ECC itself is not normally used to directly encrypt arbitrary messages.

A common practical approach is:

```text
ECC
 ↓
ECDH shared secret
 ↓
derive symmetric key
 ↓
AES encrypts data
```

```python
from cryptography.hazmat.primitives.asymmetric import ec


alice_private = ec.generate_private_key(
    ec.SECP256R1()
)

bob_private = ec.generate_private_key(
    ec.SECP256R1()
)


alice_public = alice_private.public_key()

bob_public = bob_private.public_key()


alice_secret = alice_private.exchange(
    ec.ECDH(),
    bob_public
)

bob_secret = bob_private.exchange(
    ec.ECDH(),
    alice_public
)


print(
    "Alice secret:",
    alice_secret.hex()
)

print(
    "Bob secret:",
    bob_secret.hex()
)

print(
    "Match:",
    alice_secret == bob_secret
)
```

---

# 18. ECC Encryption / Decryption — ECDH + AES-GCM

The source does not define a concrete ECC message-encryption construction. This is a practical hybrid implementation using the source's ECC key-exchange idea plus symmetric encryption.

```python
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes


# Receiver
receiver_private = ec.generate_private_key(
    ec.SECP256R1()
)

receiver_public = (
    receiver_private.public_key()
)


# Sender creates ephemeral ECC key
sender_private = ec.generate_private_key(
    ec.SECP256R1()
)


shared_sender = sender_private.exchange(
    ec.ECDH(),
    receiver_public
)


aes_key_sender = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC encryption"
).derive(shared_sender)


text = input("Plaintext: ").encode()

nonce = get_random_bytes(12)

cipher = AES.new(
    aes_key_sender,
    AES.MODE_GCM,
    nonce=nonce
)

ciphertext, tag = (
    cipher.encrypt_and_digest(text)
)


# Receiver gets sender public key
sender_public = (
    sender_private.public_key()
)


shared_receiver = (
    receiver_private.exchange(
        ec.ECDH(),
        sender_public
    )
)


aes_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"ECC encryption"
).derive(shared_receiver)


cipher = AES.new(
    aes_key_receiver,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = cipher.decrypt_and_verify(
    ciphertext,
    tag
)


print(
    "Ciphertext:",
    ciphertext.hex()
)

print(
    "Plaintext:",
    plaintext.decode()
)
```

---

# 19. ECDH Key Exchange Timing

```python
from cryptography.hazmat.primitives.asymmetric import ec
from time import perf_counter


alice = ec.generate_private_key(
    ec.SECP256R1()
)

bob = ec.generate_private_key(
    ec.SECP256R1()
)


start = perf_counter()

alice_secret = alice.exchange(
    ec.ECDH(),
    bob.public_key()
)

bob_secret = bob.exchange(
    ec.ECDH(),
    alice.public_key()
)

elapsed = perf_counter() - start


print(
    "Exchange time:",
    elapsed
)

print(
    "Secrets equal:",
    alice_secret == bob_secret
)
```

---

# 20. RSA Hybrid Encryption

Important for large messages/files.

Do not encrypt a 1 MB file directly with RSA.

Use:

```text
Random AES key
     ↓
AES encrypts file
     ↓
RSA encrypts AES key
```

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes


data = input("Plaintext: ").encode()


rsa_key = RSA.generate(2048)


# Random AES key
aes_key = get_random_bytes(32)


# Encrypt data using AES
cipher_aes = AES.new(
    aes_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    cipher_aes.encrypt_and_digest(data)
)

nonce = cipher_aes.nonce


# Encrypt AES key using RSA
cipher_rsa = PKCS1_OAEP.new(
    rsa_key.publickey()
)

encrypted_aes_key = (
    cipher_rsa.encrypt(aes_key)
)


# Decrypt AES key
cipher_rsa = PKCS1_OAEP.new(
    rsa_key
)

recovered_aes_key = (
    cipher_rsa.decrypt(
        encrypted_aes_key
    )
)


# Decrypt message
cipher_aes = AES.new(
    recovered_aes_key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = (
    cipher_aes.decrypt_and_verify(
        ciphertext,
        tag
    )
)


print(
    "Ciphertext:",
    ciphertext.hex()
)

print(
    "Plaintext:",
    plaintext.decode()
)
```

---

# 21. RSA Hybrid File Encryption

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes


filename = input("Input file: ")

with open(filename, "rb") as f:
    data = f.read()


rsa_key = RSA.generate(2048)

aes_key = get_random_bytes(32)


# Encrypt file
aes = AES.new(
    aes_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    aes.encrypt_and_digest(data)
)

nonce = aes.nonce


# Encrypt AES key
rsa = PKCS1_OAEP.new(
    rsa_key.publickey()
)

wrapped_key = rsa.encrypt(
    aes_key
)


# Decrypt AES key
rsa = PKCS1_OAEP.new(
    rsa_key
)

aes_key = rsa.decrypt(
    wrapped_key
)


# Decrypt file
aes = AES.new(
    aes_key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = aes.decrypt_and_verify(
    ciphertext,
    tag
)


with open("recovered.bin", "wb") as f:
    f.write(plaintext)


print("Recovered successfully")
```

---

# 22. ECC Hybrid File Encryption

ECC establishes a shared secret, and AES encrypts the file.

```python
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES


filename = input("Input file: ")

with open(filename, "rb") as f:
    data = f.read()


receiver = ec.generate_private_key(
    ec.SECP256R1()
)

sender = ec.generate_private_key(
    ec.SECP256R1()
)


shared = sender.exchange(
    ec.ECDH(),
    receiver.public_key()
)


aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"file-transfer"
).derive(shared)


cipher = AES.new(
    aes_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    cipher.encrypt_and_digest(data)
)

nonce = cipher.nonce


# Receiver
shared2 = receiver.exchange(
    ec.ECDH(),
    sender.public_key()
)


aes_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"file-transfer"
).derive(shared2)


cipher = AES.new(
    aes_key2,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = (
    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )
)


with open(
    "recovered.bin",
    "wb"
) as f:
    f.write(plaintext)


print("File recovered")
```

---

# 23. Generate 1 MB / 10 MB Test Files

```python
from Crypto.Random import get_random_bytes

sizes = {
    "1MB.bin": 1 * 1024 * 1024,
    "10MB.bin": 10 * 1024 * 1024
}

for filename, size in sizes.items():

    with open(filename, "wb") as f:
        f.write(
            get_random_bytes(size)
        )

    print(
        filename,
        "created"
    )
```

---

# 24. RSA vs ECC Key Generation Timing

```python
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from time import perf_counter


runs = int(input("Runs: ") or 100)


start = perf_counter()

for _ in range(runs):

    RSA.generate(2048)

rsa_time = (
    perf_counter() - start
) / runs


start = perf_counter()

for _ in range(runs):

    ec.generate_private_key(
        ec.SECP256R1()
    )

ecc_time = (
    perf_counter() - start
) / runs


print(
    "RSA-2048:",
    rsa_time
)

print(
    "ECC P-256:",
    ecc_time
)
```

---

# 25. RSA vs ECC Public Key Size

```python
from Crypto.PublicKey import RSA

from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization


rsa = RSA.generate(2048)

rsa_public = (
    rsa.publickey().export_key()
)


ecc = ec.generate_private_key(
    ec.SECP256R1()
)

ecc_public = (
    ecc.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)


print(
    "RSA public key:",
    len(rsa_public),
    "bytes"
)

print(
    "ECC public key:",
    len(ecc_public),
    "bytes"
)
```

---

# 26. RSA Hybrid Encryption Performance

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import RSA as _unused
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from time import perf_counter


size = int(
    input("Data size in bytes: ")
)

data = get_random_bytes(size)

rsa_key = RSA.generate(2048)

aes_key = get_random_bytes(32)


start = perf_counter()

aes = AES.new(
    aes_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    aes.encrypt_and_digest(data)
)

nonce = aes.nonce


rsa = PKCS1_OAEP.new(
    rsa_key.publickey()
)

wrapped_key = rsa.encrypt(
    aes_key
)

enc_time = perf_counter() - start


start = perf_counter()

rsa = PKCS1_OAEP.new(
    rsa_key
)

recovered_key = rsa.decrypt(
    wrapped_key
)


aes = AES.new(
    recovered_key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = aes.decrypt_and_verify(
    ciphertext,
    tag
)

dec_time = perf_counter() - start


print("Encryption:", enc_time)
print("Decryption:", dec_time)
print("Correct   :", plaintext == data)
```

Remove the unnecessary `_unused` import if writing this in the notebook:

```python
from Crypto.Cipher import PKCS1_OAEP, AES
```

---

# 27. ECC Hybrid Encryption Performance

```python
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from time import perf_counter


size = int(
    input("Data size in bytes: ")
)

data = get_random_bytes(size)


receiver = ec.generate_private_key(
    ec.SECP256R1()
)

sender = ec.generate_private_key(
    ec.SECP256R1()
)


start = perf_counter()

shared = sender.exchange(
    ec.ECDH(),
    receiver.public_key()
)

key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"test"
).derive(shared)


cipher = AES.new(
    key,
    AES.MODE_GCM
)

ciphertext, tag = (
    cipher.encrypt_and_digest(data)
)

nonce = cipher.nonce

enc_time = perf_counter() - start


start = perf_counter()

shared = receiver.exchange(
    ec.ECDH(),
    sender.public_key()
)

key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"test"
).derive(shared)


cipher = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = (
    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )
)

dec_time = perf_counter() - start


print("Encryption:", enc_time)
print("Decryption:", dec_time)
print("Correct   :", plaintext == data)
```

---

# 28. Performance for Different Message Sizes

```python
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from time import perf_counter


sizes = [
    1024,
    10 * 1024,
    1024 * 1024,
    10 * 1024 * 1024
]

key = get_random_bytes(32)


for size in sizes:

    data = get_random_bytes(size)

    cipher = AES.new(
        key,
        AES.MODE_GCM
    )

    start = perf_counter()

    ciphertext, tag = (
        cipher.encrypt_and_digest(data)
    )

    elapsed = (
        perf_counter() - start
    )

    print(
        size,
        "bytes:",
        elapsed,
        "seconds"
    )
```

---

# 29. Plot Algorithm Timing

```python
import matplotlib.pyplot as plt

algorithms = [
    "RSA",
    "ECC",
    "ElGamal"
]

times = []

for name in algorithms:

    value = float(
        input(
            f"{name} time: "
        )
    )

    times.append(value)


plt.bar(
    algorithms,
    times
)

plt.xlabel("Algorithm")
plt.ylabel("Time (seconds)")
plt.title(
    "Asymmetric Algorithm Performance"
)

plt.show()
```

---

# 30. Toy RSA Factorization Attack

Useful only for deliberately tiny RSA moduli.

If:

$$
n=pq
$$

and `n` is small, brute-force its factors.

```python
from math import isqrt


n = int(input("RSA modulus n: "))


for p in range(
    2,
    isqrt(n) + 1
):

    if n % p == 0:

        q = n // p

        print("p =", p)
        print("q =", q)

        break
```

For:

```text
n = 323
```

it finds:

```text
17 × 19
```

This demonstrates why RSA requires very large primes.

---

# 31. Recover Tiny RSA Private Key

```python
from math import isqrt


n = int(input("n: "))
e = int(input("e: "))


for p in range(
    2,
    isqrt(n) + 1
):

    if n % p == 0:

        q = n // p
        break


phi = (
    (p - 1)
    * (q - 1)
)

d = pow(
    e,
    -1,
    phi
)


print("p:", p)
print("q:", q)
print("phi:", phi)
print("Private exponent d:", d)
```

---

# 32. Toy Diffie-Hellman / ElGamal Discrete-Log Brute Force

Only for tiny parameters.

Given:

$$
y=g^x \pmod p
$$

try every possible `x`.

```python
p = int(input("p: "))
g = int(input("g: "))
y = int(input("Public value y: "))


for x in range(
    1,
    p
):

    if pow(
        g,
        x,
        p
    ) == y:

        print(
            "Private key found:",
            x
        )

        break
```

This is feasible only for tiny classroom values.

---

# 33. RSA Message-Size Limit With OAEP

RSA cannot encrypt arbitrary-sized files directly.

For a modulus of `k` bytes and SHA-1 OAEP:

$$
mLen \le k-2hLen-2
$$

For RSA-2048:

```python
bits = int(input("RSA bits: "))

k = bits // 8

sha1_length = 20

maximum = (
    k
    - 2 * sha1_length
    - 2
)

print(
    "Maximum OAEP plaintext:",
    maximum,
    "bytes"
)
```

With RSA-2048 and SHA-1 OAEP:

```text
214 bytes
```

Using SHA-256 OAEP gives a smaller limit.

---

# 34. Save ECC Private/Public Keys

```python
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives import serialization


private_key = ec.generate_private_key(
    ec.SECP256R1()
)


private_bytes = (
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
)


public_bytes = (
    private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)


with open(
    "ecc_private.pem",
    "wb"
) as f:

    f.write(
        private_bytes
    )


with open(
    "ecc_public.pem",
    "wb"
) as f:

    f.write(
        public_bytes
    )
```

---

# 35. Load ECC Keys

```python
from cryptography.hazmat.primitives import serialization


with open(
    "ecc_private.pem",
    "rb"
) as f:

    private_key = (
        serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    )


with open(
    "ecc_public.pem",
    "rb"
) as f:

    public_key = (
        serialization.load_pem_public_key(
            f.read()
        )
    )


print(private_key)
print(public_key)
```

---

# Quick Mathematical Reference

## RSA

```text
p, q
 ↓
n = pq
φ = (p-1)(q-1)

Public  = (n,e)
Private = (n,d)

d = e⁻¹ mod φ

Encryption:
c = m^e mod n

Decryption:
m = c^d mod n
```

---

## ElGamal

```text
p, g
Private x

y = g^x mod p

Public = (p,g,y)
Private = x
```

Encryption:

```text
choose random k

c1 = g^k mod p
c2 = m × y^k mod p
```

Decryption:

```text
s = c1^x mod p

m = c2 × s⁻¹ mod p
```

---

## Diffie-Hellman

```text
Public:
p, g

Alice private = a
Bob private   = b

A = g^a mod p
B = g^b mod p

Alice:
K = B^a mod p

Bob:
K = A^b mod p
```

Both obtain:

$$
g^{ab}\pmod p
$$

---

## ECC

Curve:

$$
y^2=x^3+ax+b\pmod p
$$

```text
Private key = d
Base point  = G

Public key:

Q = dG
```

The operation `dG` is elliptic-curve scalar multiplication.

---

# What Each Algorithm Is Actually Used For

| Algorithm      | Main role                                              |
| -------------- | ------------------------------------------------------ |
| RSA            | Encryption/key wrapping, signatures                    |
| ElGamal        | Public-key encryption; basis for related constructions |
| Diffie-Hellman | Shared-secret establishment                            |
| ECC            | Framework for ECDH, ECDSA and related schemes          |
| ECDH           | ECC-based key exchange                                 |
| AES            | Actual bulk-data encryption in hybrid systems          |

---

# Practical File-Transfer Architecture

Do not think:

```text
1 MB file
   ↓
RSA encrypt entire file
```

or:

```text
10 MB file
   ↓
ECC encrypt entire file
```

Instead:

## RSA route

```text
File
 ↓
AES-GCM
 ↓
Encrypted File

AES key
 ↓
RSA-OAEP
 ↓
Encrypted AES key
```

## ECC route

```text
Sender ECC key
       +
Receiver ECC key
       ↓
      ECDH
       ↓
 Shared Secret
       ↓
      HKDF
       ↓
    AES Key
       ↓
   AES-GCM
       ↓
Encrypted File
```

That is the technically meaningful way to implement the manual's 1 MB / 10 MB comparison.

---

# Important Distinction in the Manual

The classical ElGamal section defines:

$$
y=g^x\pmod p
$$

which is **finite-field ElGamal**.

The later exercise mentioning:

```text
ElGamal + secp256r1
```

is describing an elliptic-curve setting instead. That requires an **EC-ElGamal or hybrid ECC construction**, which the manual does not define mathematically.

For arbitrary files/medical records, the practical implementation above uses:

```text
secp256r1
   ↓
ECDH
   ↓
HKDF
   ↓
AES-GCM
```

rather than pretending that classical `c1 = g^k mod p`, `c2 = my^k mod p` can simply be used unchanged on an elliptic curve.

---

# Core Components to Remember

## RSA — 6

```text
1. p, q
2. n
3. φ(n)
4. e
5. d
6. modular exponentiation
```

## ElGamal — 6

```text
1. p
2. g
3. private x
4. public y
5. random k
6. modular arithmetic
```

## Diffie-Hellman — 5

```text
1. p
2. g
3. private values
4. public values
5. shared secret
```

## ECC — 5 conceptual components

```text
1. curve parameters
2. base point G
3. private scalar d
4. public point Q=dG
5. point/scalar operations
```

## Practical ECC encryption — 5

```text
1. ECC key pair
2. ECDH
3. HKDF
4. AES key
5. AES-GCM
```

```

The most reusable distinction for Lab 3 is:

**RSA / ElGamal = public-key encryption constructions; DH / ECDH = key agreement; AES = bulk encryption.** Large-file exercises should therefore be implemented as hybrid encryption rather than attempting to feed megabytes directly into RSA or ECC.
```
