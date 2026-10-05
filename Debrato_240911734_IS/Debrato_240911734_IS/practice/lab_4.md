Below is the **Lab 4 equivalent**, keeping the same approach as Lab 3: **individual reusable programs**, not one monolithic application.

Lab 4 specifically adds **Rabin, key management, key rotation/revocation, secure storage, auditing, RBAC/ABAC/MAC/DAC/Bell–LaPadula/time-based access, enterprise RSA+DH communication, a Rabin KMS, ElGamal DRM, and weak-RSA attacks**.  

One important correction: the manual's DRM exercise says to distribute a **master private key** to customers. That defeats meaningful revocation and is not how a secure DRM system should be designed. The implementation below keeps the private key server-side and grants controlled decryption access instead. 

# Lab 4 — Advanced Asymmetric Cryptography

Install:

```bash
pip install pycryptodome cryptography matplotlib
```

---

# 1. RSA From Scratch

```python
from math import gcd

p = int(input("Prime p: "))
q = int(input("Prime q: "))

n = p * q
phi = (p - 1) * (q - 1)

e = int(input("Public exponent e: "))

if gcd(e, phi) != 1:
    raise ValueError("e must be coprime with phi")

d = pow(e, -1, phi)

m = int(input("Message integer: "))

c = pow(m, e, n)
plain = pow(c, d, n)

print("Public key :", (n, e))
print("Private key:", (n, d))
print("Ciphertext :", c)
print("Plaintext  :", plain)
```

---

# 2. RSA-2048 OAEP

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

message = input("Message: ").encode()

key = RSA.generate(2048)

cipher = PKCS1_OAEP.new(
    key.publickey()
)

encrypted = cipher.encrypt(message)

print("Ciphertext:", encrypted.hex())

cipher = PKCS1_OAEP.new(key)

decrypted = cipher.decrypt(encrypted)

print("Plaintext:", decrypted.decode())
```

---

# 3. Classical ElGamal

$$
y=g^x \bmod p
$$

$$
c_1=g^k\bmod p
$$

$$
c_2=m\,y^k\bmod p
$$

```python
import secrets

p = int(input("Prime p: "))
g = int(input("Generator g: "))

x = secrets.randbelow(p - 2) + 1
y = pow(g, x, p)

m = int(input("Message integer: "))

k = secrets.randbelow(p - 2) + 1

c1 = pow(g, k, p)
c2 = (m * pow(y, k, p)) % p

print("Public key :", (p, g, y))
print("Private key:", x)
print("Ciphertext :", (c1, c2))

s = pow(c1, x, p)

plain = (
    c2 * pow(s, -1, p)
) % p

print("Plaintext:", plain)
```

---

# 4. Rabin — Key Generation

Rabin requires:

$$
p\equiv q\equiv3\pmod4
$$

$$
n=pq
$$

Public key:

$$
n
$$

Private key:

$$
(p,q)
$$

```python
from Crypto.Util.number import getPrime

bits = int(input("Key size [1024]: ") or 1024)


def rabin_prime(bits):
    while True:
        p = getPrime(bits)

        if p % 4 == 3:
            return p


p = rabin_prime(bits // 2)
q = rabin_prime(bits // 2)

while q == p:
    q = rabin_prime(bits // 2)

n = p * q

print("Public key n:", n)
print("Private p   :", p)
print("Private q   :", q)
```

---

# 5. Rabin — Integer Encryption

Rabin encryption is exceptionally simple:

$$
c=m^2\bmod n
$$

```python
p = int(input("p: "))
q = int(input("q: "))

n = p * q

m = int(input(f"Message [0-{n-1}]: "))

c = pow(m, 2, n)

print("Public key:", n)
print("Ciphertext:", c)
```

---

# 6. Rabin — Decryption

Rabin gives **four possible plaintext roots**.

```python
p = int(input("p: "))
q = int(input("q: "))

c = int(input("Ciphertext: "))

n = p * q

mp = pow(
    c,
    (p + 1) // 4,
    p
)

mq = pow(
    c,
    (q + 1) // 4,
    q
)

q_inv = pow(q, -1, p)
p_inv = pow(p, -1, q)

r = (
    mp * q * q_inv
    + mq * p * p_inv
) % n

s = (
    mp * q * q_inv
    - mq * p * p_inv
) % n

roots = [
    r,
    n - r,
    s,
    n - s
]

print("Possible plaintexts:")

for x in roots:
    print(x)
```

This four-root ambiguity is one of the fundamental differences between Rabin and RSA.

---

# 7. Rabin — Encrypt + Decrypt Integer

```python
def encrypt(m, n):
    return pow(m, 2, n)


def decrypt(c, p, q):
    n = p * q

    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    r = (
        mp * q * pow(q, -1, p)
        + mq * p * pow(p, -1, q)
    ) % n

    s = (
        mp * q * pow(q, -1, p)
        - mq * p * pow(p, -1, q)
    ) % n

    return [
        r,
        n - r,
        s,
        n - s
    ]


p = int(input("p: "))
q = int(input("q: "))

n = p * q

m = int(input("Message: "))

c = encrypt(m, n)

print("Ciphertext:", c)
print("Roots     :", decrypt(c, p, q))
```

---

# 8. Rabin Text Encryption With Redundancy

To identify the correct one of the four roots, attach recognizable redundancy.

```python
MARKER = 0xA5A5A5A5


def encode_byte(value):
    return (
        value << 32
    ) | MARKER


def encrypt(text, n):
    result = []

    for b in text.encode():
        m = encode_byte(b)

        if m >= n:
            raise ValueError("Rabin modulus too small")

        result.append(
            pow(m, 2, n)
        )

    return result


def roots(c, p, q):
    n = p * q

    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    r = (
        mp * q * pow(q, -1, p)
        + mq * p * pow(p, -1, q)
    ) % n

    s = (
        mp * q * pow(q, -1, p)
        - mq * p * pow(p, -1, q)
    ) % n

    return [
        r,
        n - r,
        s,
        n - s
    ]


def decrypt(ciphertext, p, q):
    data = []

    for c in ciphertext:

        found = None

        for r in roots(c, p, q):

            if (
                r & 0xFFFFFFFF
            ) == MARKER:

                value = r >> 32

                if 0 <= value <= 255:
                    found = value
                    break

        if found is None:
            raise ValueError(
                "Could not identify valid root"
            )

        data.append(found)

    return bytes(data).decode()
```

---

# 9. Rabin Complete Text Example

```python
from Crypto.Util.number import getPrime

MARKER = 0xA5A5A5A5


def prime(bits):
    while True:
        p = getPrime(bits)

        if p % 4 == 3:
            return p


p = prime(256)
q = prime(256)

n = p * q

text = input("Plaintext: ")

ciphertext = []


for b in text.encode():

    m = (
        b << 32
    ) | MARKER

    ciphertext.append(
        pow(m, 2, n)
    )


result = []


for c in ciphertext:

    mp = pow(
        c,
        (p + 1) // 4,
        p
    )

    mq = pow(
        c,
        (q + 1) // 4,
        q
    )

    r = (
        mp * q * pow(q, -1, p)
        + mq * p * pow(p, -1, q)
    ) % n

    s = (
        mp * q * pow(q, -1, p)
        - mq * p * pow(p, -1, q)
    ) % n

    roots = [
        r,
        n-r,
        s,
        n-s
    ]

    for x in roots:

        if (
            x & 0xFFFFFFFF
        ) == MARKER:

            value = x >> 32

            if value <= 255:
                result.append(value)
                break


print("Ciphertext:", ciphertext)
print("Plaintext :", bytes(result).decode())
```

---

# 10. Rabin Key Generation Timing

```python
from Crypto.Util.number import getPrime
from time import perf_counter


def prime(bits):
    while True:
        p = getPrime(bits)

        if p % 4 == 3:
            return p


bits = int(
    input("Key size: ")
)

start = perf_counter()

p = prime(bits // 2)
q = prime(bits // 2)

n = p * q

elapsed = perf_counter() - start

print(
    "Key generation:",
    elapsed,
    "seconds"
)
```

---

# 11. Rabin Encryption / Decryption Timing

```python
from time import perf_counter

m = int(input("Message: "))
p = int(input("p: "))
q = int(input("q: "))

n = p * q


start = perf_counter()

c = pow(m, 2, n)

enc_time = perf_counter() - start


start = perf_counter()

mp = pow(
    c,
    (p + 1) // 4,
    p
)

mq = pow(
    c,
    (q + 1) // 4,
    q
)

dec_time = perf_counter() - start


print(
    "Encryption:",
    enc_time
)

print(
    "Decryption:",
    dec_time
)
```

---

# 12. RSA vs Rabin Encryption Timing

```python
from time import perf_counter

m = int(input("Message integer: "))

# RSA
n_rsa = int(input("RSA n: "))
e = int(input("RSA e: "))

start = perf_counter()

rsa_c = pow(
    m,
    e,
    n_rsa
)

rsa_time = (
    perf_counter() - start
)


# Rabin
n_rabin = int(
    input("Rabin n: ")
)

start = perf_counter()

rabin_c = pow(
    m,
    2,
    n_rabin
)

rabin_time = (
    perf_counter() - start
)


print(
    "RSA encryption:",
    rsa_time
)

print(
    "Rabin encryption:",
    rabin_time
)
```

Rabin encryption is essentially one modular squaring, so it is normally very cheap.

---

# 13. RSA / ElGamal / Rabin Performance Graph

```python
import matplotlib.pyplot as plt

algorithms = [
    "RSA",
    "ElGamal",
    "Rabin"
]

times = []

for name in algorithms:

    t = float(
        input(
            f"{name} time: "
        )
    )

    times.append(t)


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

# 14. Key Entropy

The manual defines:

$$
H(K)=-
\sum_i p(i)\log_2p(i)
$$

```python
import math

probabilities = list(
    map(
        float,
        input(
            "Probabilities: "
        ).split()
    )
)

entropy = -sum(
    p * math.log2(p)
    for p in probabilities
    if p > 0
)

print(
    "Entropy:",
    entropy,
    "bits"
)
```

For uniformly distributed \(n\) keys:

```python
import math

n = int(
    input(
        "Number of possible keys: "
    )
)

entropy = math.log2(n)

print(
    "Entropy:",
    entropy,
    "bits"
)
```

---

# 15. PBKDF2 Key Derivation

The manual describes the generic concept:

$$
DK=KDF(Key,Salt,Iterations)
$$

A concrete implementation:

```python
from hashlib import pbkdf2_hmac
import os

password = input(
    "Password: "
).encode()

salt = os.urandom(16)

key = pbkdf2_hmac(
    "sha256",
    password,
    salt,
    200_000,
    dklen=32
)

print("Salt:", salt.hex())
print("Key :", key.hex())
```

---

# 16. HKDF Key Derivation

Useful after Diffie-Hellman.

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

secret = bytes.fromhex(
    input(
        "Shared secret in hex: "
    )
)

key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"secure-channel"
).derive(secret)

print(
    "Derived key:",
    key.hex()
)
```

---

# 17. Key Expiry

Manual:

$$
Expiry=t_0+L
$$

```python
from datetime import datetime, timedelta

lifetime_days = int(
    input(
        "Key lifetime in days: "
    )
)

created = datetime.now()

expiry = (
    created
    + timedelta(
        days=lifetime_days
    )
)

print("Created:", created)
print("Expires:", expiry)
```

---

# 18. Check Whether a Key Has Expired

```python
from datetime import datetime

expiry = datetime.fromisoformat(
    input(
        "Expiry YYYY-MM-DDTHH:MM:SS: "
    )
)

if datetime.now() >= expiry:
    print("Key expired")

else:
    print("Key valid")
```

---

# 19. Key Rotation Rate

Manual:

$$
RotationRate=\frac NT
$$

```python
N = int(
    input(
        "Number of keys: "
    )
)

T = float(
    input(
        "Rotation period: "
    )
)

rate = N / T

print(
    "Rotation rate:",
    rate
)
```

---

# 20. Basic Key Rotation

```python
from Crypto.PublicKey import RSA

keys = {}


def generate(name):
    keys[name] = RSA.generate(2048)

    print(
        name,
        "key generated"
    )


def rotate(name):
    keys[name] = RSA.generate(2048)

    print(
        name,
        "key rotated"
    )


name = input("System name: ")

generate(name)
rotate(name)
```

---

# 21. Basic Key Revocation

```python
keys = {
    "finance": {
        "key": "KEY1",
        "revoked": False
    },

    "hr": {
        "key": "KEY2",
        "revoked": False
    }
}


def revoke(name):

    keys[name]["revoked"] = True


def valid(name):

    return not keys[name]["revoked"]


name = input(
    "System to revoke: "
)

revoke(name)

print(
    "Valid:",
    valid(name)
)
```

---

# 22. Key Versioning

```python
keys = {}


def add_key(name, key):

    if name not in keys:
        keys[name] = []

    version = (
        len(keys[name]) + 1
    )

    keys[name].append({
        "version": version,
        "key": key,
        "active": True
    })

    for old in keys[name][:-1]:
        old["active"] = False


add_key(
    "Finance",
    "KEY-V1"
)

add_key(
    "Finance",
    "KEY-V2"
)

print(keys)
```

---

# 23. Secure Private-Key Storage

For a lab demonstration, encrypt the stored private key.

```python
from cryptography.fernet import Fernet

master_key = Fernet.generate_key()

cipher = Fernet(master_key)

private_key = input(
    "Private key: "
).encode()

encrypted = cipher.encrypt(
    private_key
)

print(
    "Stored value:",
    encrypted
)

recovered = cipher.decrypt(
    encrypted
)

print(
    "Recovered:",
    recovered.decode()
)
```

In a real deployment, the `master_key` itself belongs in a KMS/HSM/secret manager, not beside the encrypted key.

---

# 24. Store RSA Private Key Encrypted With Password

```python
from Crypto.PublicKey import RSA

password = input(
    "Storage password: "
)

key = RSA.generate(2048)

encrypted_private = key.export_key(
    passphrase=password,
    pkcs=8,
    protection="scryptAndAES128-CBC"
)

with open(
    "private.pem",
    "wb"
) as f:

    f.write(
        encrypted_private
    )

print(
    "Encrypted private key saved"
)
```

Load it:

```python
from Crypto.PublicKey import RSA

password = input(
    "Password: "
)

with open(
    "private.pem",
    "rb"
) as f:

    key = RSA.import_key(
        f.read(),
        passphrase=password
    )

print(
    "Private key loaded"
)
```

---

# 25. Audit Logging

```python
import logging

logging.basicConfig(
    filename="key_audit.log",
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)


def audit(action, entity):

    logging.info(
        "%s | %s",
        action,
        entity
    )


audit(
    "KEY_GENERATED",
    "Finance"
)

audit(
    "KEY_ROTATED",
    "HR"
)

audit(
    "KEY_REVOKED",
    "SupplyChain"
)

print(
    "Audit events recorded"
)
```

---

# 26. RBAC — Role-Based Access Control

Manual:

$$
Access=
HasRole(User,Role)
\land
CanAccess(Role,Object)
$$

```python
roles = {
    "alice": "admin",
    "bob": "doctor",
    "eve": "guest"
}

permissions = {
    "admin": {
        "read",
        "write",
        "delete"
    },

    "doctor": {
        "read",
        "write"
    },

    "guest": {
        "read"
    }
}


def access(user, action):

    role = roles.get(user)

    return (
        role in permissions
        and action in permissions[role]
    )


user = input("User: ")
action = input("Action: ")

print(
    "Granted"
    if access(user, action)
    else "Denied"
)
```

---

# 27. ABAC — Attribute-Based Access Control

```python
def access(user, resource, environment):

    return (
        user["department"]
        == resource["department"]

        and user["clearance"]
        >= resource["level"]

        and environment["trusted"]
    )


user = {
    "department": "oncology",
    "clearance": 3
}

resource = {
    "department": "oncology",
    "level": 2
}

environment = {
    "trusted": True
}

print(
    "Granted"
    if access(
        user,
        resource,
        environment
    )
    else "Denied"
)
```

---

# 28. Bell-LaPadula — Read Rule

Simple Security Property:

> No read up.

```python
def can_read(
    subject_level,
    object_level
):

    return (
        subject_level
        >= object_level
    )


subject = int(
    input(
        "Subject clearance: "
    )
)

obj = int(
    input(
        "Object classification: "
    )
)

print(
    "Read allowed"
    if can_read(subject, obj)
    else "Read denied"
)
```

---

# 29. Bell-LaPadula — Write Rule

`*-property`:

> No write down.

```python
def can_write(
    subject_level,
    object_level
):

    return (
        subject_level
        <= object_level
    )


subject = int(
    input(
        "Subject clearance: "
    )
)

obj = int(
    input(
        "Object classification: "
    )
)

print(
    "Write allowed"
    if can_write(subject, obj)
    else "Write denied"
)
```

---

# 30. Bell-LaPadula — Read + Write

```python
def can_read(subject, obj):
    return subject >= obj


def can_write(subject, obj):
    return subject <= obj


subject = int(
    input(
        "Subject clearance: "
    )
)

obj = int(
    input(
        "Object classification: "
    )
)

print(
    "Read :",
    can_read(subject, obj)
)

print(
    "Write:",
    can_write(subject, obj)
)
```

---

# 31. Mandatory Access Control — MAC

```python
levels = {
    "PUBLIC": 0,
    "CONFIDENTIAL": 1,
    "SECRET": 2,
    "TOP_SECRET": 3
}


def can_access(
    clearance,
    classification
):

    return (
        levels[clearance]
        >= levels[classification]
    )


user = input(
    "Clearance: "
).upper()

document = input(
    "Classification: "
).upper()

print(
    "Granted"
    if can_access(
        user,
        document
    )
    else "Denied"
)
```

---

# 32. Discretionary Access Control — DAC

```python
access_matrix = {
    "alice": {
        "report.txt": {
            "read",
            "write"
        }
    },

    "bob": {
        "report.txt": {
            "read"
        }
    }
}


def access(
    user,
    obj,
    action
):

    return (
        action
        in access_matrix
        .get(user, {})
        .get(obj, set())
    )


print(
    access(
        "alice",
        "report.txt",
        "write"
    )
)
```

---

# 33. Grant / Revoke DAC Permission

```python
access_matrix = {}


def grant(
    user,
    obj,
    permission
):

    access_matrix.setdefault(
        user,
        {}
    ).setdefault(
        obj,
        set()
    ).add(
        permission
    )


def revoke(
    user,
    obj,
    permission
):

    access_matrix.get(
        user,
        {}
    ).get(
        obj,
        set()
    ).discard(
        permission
    )


grant(
    "alice",
    "data.txt",
    "read"
)

print(access_matrix)

revoke(
    "alice",
    "data.txt",
    "read"
)

print(access_matrix)
```

---

# 34. Time-Based Access Control

Manual:

$$
StartTime\le Time\le EndTime
$$

```python
from datetime import datetime

start = datetime.fromisoformat(
    input(
        "Start time: "
    )
)

end = datetime.fromisoformat(
    input(
        "End time: "
    )
)

now = datetime.now()

if start <= now <= end:
    print("Access granted")

else:
    print("Access denied")
```

---

# 35. Temporary Access Grant

```python
from datetime import datetime, timedelta

hours = int(
    input(
        "Access duration hours: "
    )
)

grant = {
    "start": datetime.now(),
    "end": (
        datetime.now()
        + timedelta(hours=hours)
    ),
    "revoked": False
}


def valid(grant):

    return (
        not grant["revoked"]
        and grant["start"]
        <= datetime.now()
        <= grant["end"]
    )


print(
    "Access valid:",
    valid(grant)
)
```

---

# 36. Revoke Temporary Access

```python
grant = {
    "user": "alice",
    "content": "movie1",
    "revoked": False
}

grant["revoked"] = True

print(
    "Revoked:",
    grant["revoked"]
)
```

---

# 37. Probabilistic / Risk-Based Access Control

The manual gives this as:

$$
P(Access)=
f(
Trust,
Sensitivity,
Risk
)
$$

A simple experimental policy:

```python
trust = float(
    input(
        "User trust [0-1]: "
    )
)

sensitivity = float(
    input(
        "Object sensitivity [0-1]: "
    )
)

risk = float(
    input(
        "Environment risk [0-1]: "
    )
)

score = (
    0.6 * trust
    - 0.2 * sensitivity
    - 0.2 * risk
)

print(
    "Score:",
    score
)

print(
    "Granted"
    if score >= 0.3
    else "Denied"
)
```

This weighting is an **illustrative policy**, not something specified by the manual.

---

# 38. Diffie-Hellman Key Exchange

```python
import secrets

p = int(input("Prime p: "))
g = int(input("Generator g: "))

a = secrets.randbelow(
    p - 2
) + 1

b = secrets.randbelow(
    p - 2
) + 1

A = pow(
    g,
    a,
    p
)

B = pow(
    g,
    b,
    p
)

alice = pow(
    B,
    a,
    p
)

bob = pow(
    A,
    b,
    p
)

print(
    "Alice public:",
    A
)

print(
    "Bob public:",
    B
)

print(
    "Shared secret:",
    alice
)

print(
    "Equal:",
    alice == bob
)
```

---

# 39. DH → AES Key With HKDF

Never use a raw DH integer directly as an AES key.

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

shared = int(
    input(
        "Shared DH secret: "
    )
)

shared_bytes = shared.to_bytes(
    (
        shared.bit_length() + 7
    ) // 8,
    "big"
)

aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"secure-channel"
).derive(shared_bytes)

print(
    "AES key:",
    aes_key.hex()
)
```

---

# 40. RSA Digital Signature

Useful for authenticating systems or DH public values.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

message = input(
    "Message: "
).encode()

key = RSA.generate(2048)

h = SHA256.new(message)

signature = pss.new(
    key
).sign(h)

print(
    "Signature:",
    signature.hex()
)


h = SHA256.new(message)

try:

    pss.new(
        key.publickey()
    ).verify(
        h,
        signature
    )

    print(
        "Signature valid"
    )

except ValueError:

    print(
        "Signature invalid"
    )
```

---

# 41. SecureCorp — RSA-Authenticated Diffie-Hellman

A meaningful interpretation of the manual's requirement is:

```text
RSA identity keys
      ↓
authenticate DH exchange
      ↓
Diffie-Hellman
      ↓
shared secret
      ↓
HKDF
      ↓
AES-GCM secure channel
```

```python
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    dh,
    padding
)

from cryptography.hazmat.primitives import (
    hashes,
    serialization
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.Cipher import AES


# Global DH parameters
parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)


def new_system():

    rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    dh_private = (
        parameters.generate_private_key()
    )

    return {
        "rsa": rsa_private,
        "dh": dh_private
    }


finance = new_system()
hr = new_system()


# Serialize Finance DH public key
finance_dh_public = (
    finance["dh"]
    .public_key()
    .public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
)


# Finance signs its DH public key
signature = finance["rsa"].sign(
    finance_dh_public,
    padding.PSS(
        mgf=padding.MGF1(
            hashes.SHA256()
        ),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


# HR verifies identity/authenticity
finance["rsa"].public_key().verify(
    signature,
    finance_dh_public,
    padding.PSS(
        mgf=padding.MGF1(
            hashes.SHA256()
        ),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


# DH shared secret
finance_secret = (
    finance["dh"].exchange(
        hr["dh"].public_key()
    )
)

hr_secret = (
    hr["dh"].exchange(
        finance["dh"].public_key()
    )
)


def derive(secret):

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureCorp"
    ).derive(secret)


finance_key = derive(
    finance_secret
)

hr_key = derive(
    hr_secret
)


print(
    "Shared key equal:",
    finance_key == hr_key
)


# Encrypt communication
message = input(
    "Finance message: "
).encode()

cipher = AES.new(
    finance_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    cipher.encrypt_and_digest(
        message
    )
)

nonce = cipher.nonce


cipher = AES.new(
    hr_key,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = (
    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )
)

print(
    "Received:",
    plaintext.decode()
)
```

---

# 42. Scalable RSA Key Registry

```python
from Crypto.PublicKey import RSA

systems = {}


def add_system(name):

    key = RSA.generate(2048)

    systems[name] = {
        "private": key,
        "public": key.publickey(),
        "revoked": False,
        "version": 1
    }


def revoke(name):

    systems[name][
        "revoked"
    ] = True


def rotate(name):

    key = RSA.generate(2048)

    systems[name][
        "private"
    ] = key

    systems[name][
        "public"
    ] = key.publickey()

    systems[name][
        "version"
    ] += 1

    systems[name][
        "revoked"
    ] = False


add_system("Finance")
add_system("HR")
add_system("SupplyChain")

add_system(
    input(
        "New subsystem: "
    )
)

print(
    list(
        systems.keys()
    )
)
```

This satisfies the basic scalability requirement: new subsystems can be registered without changing the cryptographic structure.

---

# 43. Centralized Rabin Key Manager

```python
from Crypto.Util.number import getPrime
from datetime import datetime


class RabinKMS:

    def __init__(self):

        self.keys = {}
        self.audit = []


    def _prime(self, bits):

        while True:

            p = getPrime(bits)

            if p % 4 == 3:
                return p


    def generate(
        self,
        name,
        bits=1024
    ):

        p = self._prime(
            bits // 2
        )

        q = self._prime(
            bits // 2
        )

        while q == p:
            q = self._prime(
                bits // 2
            )

        self.keys[name] = {
            "public": p*q,
            "private": (p, q),
            "revoked": False,
            "created": datetime.now()
        }

        self.log(
            "GENERATE",
            name
        )


    def public_key(self, name):

        return self.keys[name][
            "public"
        ]


    def revoke(self, name):

        self.keys[name][
            "revoked"
        ] = True

        self.log(
            "REVOKE",
            name
        )


    def renew(self, name):

        self.generate(name)

        self.log(
            "RENEW",
            name
        )


    def log(
        self,
        action,
        name
    ):

        self.audit.append({
            "time": datetime.now(),
            "action": action,
            "entity": name
        })


kms = RabinKMS()

kms.generate(
    "Hospital-A"
)

kms.generate(
    "Clinic-B"
)

print(
    "Hospital public key:",
    kms.public_key(
        "Hospital-A"
    )
)

kms.revoke(
    "Clinic-B"
)

print(kms.audit)
```

---

# 44. Rabin Automatic Renewal Check

```python
from datetime import datetime, timedelta


def needs_renewal(
    created,
    months=12
):

    # Approximation for simple lab use
    return (
        datetime.now()
        >= created
        + timedelta(
            days=30 * months
        )
    )


created = datetime.now() - timedelta(
    days=370
)

print(
    "Renew:",
    needs_renewal(created)
)
```

For production calendrical logic, use calendar-aware month arithmetic rather than treating a month as exactly 30 days.

---

# 45. Protected Rabin Private-Key Storage

```python
from cryptography.fernet import Fernet
import json

master_key = Fernet.generate_key()

cipher = Fernet(master_key)

p = int(input("Rabin p: "))
q = int(input("Rabin q: "))

private_data = json.dumps({
    "p": p,
    "q": q
}).encode()

stored = cipher.encrypt(
    private_data
)

print(
    "Encrypted storage:",
    stored
)

decoded = json.loads(
    cipher.decrypt(stored)
)

print(
    "Recovered p:",
    decoded["p"]
)
```

Again, the Fernet master key would itself need protected storage in a real KMS/HSM.

---

# 46. Rabin vs RSA Trade-Off

| Property                 | RSA                           | Rabin                        |
| ------------------------ | ----------------------------- | ---------------------------- |
| Mathematical basis       | Integer factorization         | Integer factorization        |
| Encryption               | \(m^e\bmod n\)                | \(m^2\bmod n\)               |
| Encryption speed         | Fast                          | **Very fast**                |
| Decryption               | One intended result           | **Four possible roots**      |
| Plaintext disambiguation | Padding handles it            | Requires redundancy/encoding |
| Public key               | \((n,e)\)                     | \(n\)                        |
| Private key              | \(d\)/prime factors           | \(p,q\)                      |
| Practical deployment     | Extremely widespread          | Rare                         |
| Main complication        | Secure padding/implementation | Four-root ambiguity          |

Rabin has a particularly strong theoretical relationship to factorization, but RSA is far easier to deploy in standard protocols and libraries.

---

# 47. ElGamal Content Encryption — Educational Version

```python
import secrets


def encrypt_byte(
    m,
    p,
    g,
    y
):

    k = secrets.randbelow(
        p - 2
    ) + 1

    c1 = pow(
        g,
        k,
        p
    )

    c2 = (
        m
        * pow(y, k, p)
    ) % p

    return (
        c1,
        c2
    )


def decrypt_byte(
    cipher,
    p,
    x
):

    c1, c2 = cipher

    s = pow(
        c1,
        x,
        p
    )

    return (
        c2
        * pow(s, -1, p)
    ) % p
```

For actual movies/files, do not encrypt each byte this way. Use hybrid encryption.

---

# 48. ElGamal Hybrid Content Encryption

Better DRM architecture:

```text
Content
   ↓
AES-GCM
   ↓
Encrypted content

AES content key
   ↓
ElGamal
   ↓
Wrapped key
```

```python
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


p = int(input("ElGamal p: "))
g = int(input("ElGamal g: "))

x = secrets.randbelow(
    p - 2
) + 1

y = pow(
    g,
    x,
    p
)


data = input(
    "Content: "
).encode()


# Encrypt content
aes_key = get_random_bytes(32)

cipher = AES.new(
    aes_key,
    AES.MODE_GCM
)

ciphertext, tag = (
    cipher.encrypt_and_digest(
        data
    )
)

nonce = cipher.nonce


# Convert AES key to integer
m = int.from_bytes(
    aes_key,
    "big"
)

if m >= p:
    raise ValueError(
        "ElGamal modulus too small"
    )


# Wrap AES key
k = secrets.randbelow(
    p - 2
) + 1

c1 = pow(
    g,
    k,
    p
)

c2 = (
    m
    * pow(y, k, p)
) % p


# Server unwraps key
s = pow(
    c1,
    x,
    p
)

recovered_m = (
    c2
    * pow(s, -1, p)
) % p

recovered_key = (
    recovered_m.to_bytes(
        32,
        "big"
    )
)


cipher = AES.new(
    recovered_key,
    AES.MODE_GCM,
    nonce=nonce
)

plain = (
    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )
)


print(
    "Recovered:",
    plain.decode()
)
```

---

# 49. DRM Time-Limited Access

```python
from datetime import datetime, timedelta

access = {}


def grant(
    user,
    content,
    hours
):

    access[
        (user, content)
    ] = {
        "expires": (
            datetime.now()
            + timedelta(hours=hours)
        ),
        "revoked": False
    }


def revoke(
    user,
    content
):

    access[
        (user, content)
    ]["revoked"] = True


def allowed(
    user,
    content
):

    grant = access.get(
        (user, content)
    )

    if not grant:
        return False

    return (
        not grant["revoked"]

        and datetime.now()
        <= grant["expires"]
    )


grant(
    "alice",
    "movie1",
    24
)

print(
    allowed(
        "alice",
        "movie1"
    )
)

revoke(
    "alice",
    "movie1"
)

print(
    allowed(
        "alice",
        "movie1"
    )
)
```

---

# 50. Content-Creator Ownership Check

```python
owners = {
    "movie1": "creatorA",
    "book1": "creatorB"
}


def can_manage(
    creator,
    content
):

    return (
        owners.get(content)
        == creator
    )


print(
    can_manage(
        "creatorA",
        "movie1"
    )
)
```

---

# 51. Weak RSA — Trial-Division Factorization Attack

This demonstrates the manual's vulnerable-small-primes scenario. 

```python
from math import isqrt

n = int(
    input(
        "RSA modulus n: "
    )
)

factor = None

for p in range(
    2,
    isqrt(n) + 1
):

    if n % p == 0:

        factor = p
        break


if factor:

    q = n // factor

    print("p:", factor)
    print("q:", q)

else:

    print(
        "No factor found"
    )
```

---

# 52. Weak RSA — Recover Private Key

```python
from math import isqrt

n = int(input("n: "))
e = int(input("e: "))

p = None

for candidate in range(
    2,
    isqrt(n) + 1
):

    if n % candidate == 0:

        p = candidate
        break


if p is None:
    raise ValueError(
        "Could not factor n"
    )


q = n // p

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
print("d:", d)
```

---

# 53. Weak RSA — Decrypt After Recovering Private Key

```python
from math import isqrt

n = int(input("n: "))
e = int(input("e: "))
c = int(input("Ciphertext: "))


for p in range(
    2,
    isqrt(n) + 1
):

    if n % p == 0:
        break


q = n // p

phi = (
    (p - 1)
    * (q - 1)
)

d = pow(
    e,
    -1,
    phi
)

m = pow(
    c,
    d,
    n
)

print(
    "Recovered d:",
    d
)

print(
    "Plaintext integer:",
    m
)
```

---

# 54. Weak RSA — Fermat Attack on Close Primes

If poorly generated RSA primes are extremely close:

$$
n=a^2-b^2
$$

$$
n=(a-b)(a+b)
$$

```python
from math import isqrt


def fermat_factor(n):

    a = isqrt(n)

    if a * a < n:
        a += 1

    while True:

        b2 = (
            a*a - n
        )

        b = isqrt(b2)

        if b*b == b2:

            return (
                a-b,
                a+b
            )

        a += 1


n = int(
    input(
        "RSA modulus: "
    )
)

p, q = fermat_factor(n)

print("p:", p)
print("q:", q)
```

This can be devastating if \(p\) and \(q\) are generated too close together.

---

# 55. RSA Shared-Prime GCD Attack

Poor randomness can cause two RSA moduli to share a prime:

$$
n_1=pq_1
$$

$$
n_2=pq_2
$$

Then:

$$
\gcd(n_1,n_2)=p
$$

```python
from math import gcd

n1 = int(
    input(
        "First RSA modulus: "
    )
)

n2 = int(
    input(
        "Second RSA modulus: "
    )
)

p = gcd(
    n1,
    n2
)

if p == 1:

    print(
        "No common factor"
    )

else:

    print(
        "Shared prime:",
        p
    )

    print(
        "n1 other factor:",
        n1 // p
    )

    print(
        "n2 other factor:",
        n2 // p
    )
```

---

# 56. Generate Proper RSA Keys

The mitigation is not to manually choose tiny primes.

```python
from Crypto.PublicKey import RSA

key = RSA.generate(
    2048,
    e=65537
)

print(
    key.publickey()
    .export_key()
    .decode()
)
```

For stronger long-lived requirements, policy may call for larger modulus sizes, but the key point is to use a vetted cryptographic key generator rather than hand-selected primes.

---

# 57. RSA Attack Mitigations

For the weak-prime scenario in the manual:

```text
1. Use cryptographically secure randomness
2. Use sufficiently large RSA moduli
3. Never manually choose p and q
4. Ensure p ≠ q
5. Avoid structurally weak / excessively close primes
6. Check for accidental shared factors across generated keys
7. Use standard vetted cryptographic libraries
8. Use RSA-OAEP for encryption
9. Protect private keys using encrypted storage / KMS / HSM
10. Rotate and revoke compromised keys
```

---

# 58. Audit Revocation

```python
import logging

logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format=(
        "%(asctime)s | %(message)s"
    )
)


def revoke_key(
    entity,
    reason
):

    logging.warning(
        "KEY_REVOKED | %s | %s",
        entity,
        reason
    )


revoke_key(
    "Hospital-A",
    "Suspected compromise"
)
```

---

# 59. Access-Control Audit

```python
import logging

logging.basicConfig(
    filename="access.log",
    level=logging.INFO
)


def check_access(
    user,
    allowed
):

    if allowed:

        logging.info(
            "ACCESS_GRANTED %s",
            user
        )

    else:

        logging.warning(
            "ACCESS_DENIED %s",
            user
        )


check_access(
    "alice",
    True
)

check_access(
    "eve",
    False
)
```

---

# 60. Generic Key Lifecycle State

```python
from datetime import datetime

key_record = {
    "id": "finance-v1",
    "created": datetime.now(),
    "status": "ACTIVE",
    "version": 1
}

print(key_record)

key_record[
    "status"
] = "REVOKED"

print(key_record)
```

A useful lifecycle is:

```text
GENERATED
    ↓
ACTIVE
    ↓
ROTATED / EXPIRED
    ↓
REVOKED
    ↓
DESTROYED / ARCHIVED
```

---

# Quick Lab 4 Map

The manual is effectively testing **four distinct areas**:

```text
1. Asymmetric algorithms
   ├ RSA
   ├ ElGamal
   └ Rabin

2. Key management
   ├ Generation
   ├ Distribution
   ├ Storage
   ├ Rotation
   ├ Renewal
   ├ Expiry
   └ Revocation

3. Access control
   ├ RBAC
   ├ ABAC
   ├ Bell-LaPadula
   ├ MAC
   ├ DAC
   ├ Time-based
   └ Risk/probabilistic

4. Attacks
   └ Weak RSA key generation
      ├ small primes
      ├ close primes
      └ reused/shared primes
```

---

# Core Components to Remember

## RSA — 6

```text
1. p, q
2. n = pq
3. φ(n)
4. public exponent e
5. private exponent d
6. modular exponentiation
```

---

## ElGamal — 6

```text
1. prime p
2. generator g
3. private x
4. public y = g^x mod p
5. random ephemeral k
6. modular inverse / exponentiation
```

---

## Rabin — 6

```text
1. p ≡ 3 mod 4
2. q ≡ 3 mod 4
3. n = pq
4. c = m² mod n
5. CRT decryption
6. four-root disambiguation
```

---

## Key Management — 7

```text
1. Generation
2. Distribution
3. Storage
4. Rotation
5. Renewal
6. Expiry
7. Revocation
```

---

## Access Control — 7

```text
1. RBAC
2. ABAC
3. Bell-LaPadula
4. MAC
5. DAC
6. Time-based
7. Risk/probabilistic
```

---

# RSA vs ElGamal vs Rabin

| Property                  | RSA                     | ElGamal             | Rabin              |
| ------------------------- | ----------------------- | ------------------- | ------------------ |
| Hard problem              | Factorization           | Discrete logarithm  | Factorization      |
| Public key                | `(n,e)`                 | `(p,g,y)`           | `n`                |
| Private key               | `d` / factors           | `x`                 | `(p,q)`            |
| Randomness per encryption | With secure padding     | **Required `k`**    | Encoding dependent |
| Ciphertext expansion      | Moderate                | Large               | Moderate           |
| Decryption ambiguity      | No with proper encoding | No                  | **Four roots**     |
| Deployment                | Very common             | Less common         | Rare               |
| Encryption cost           | Modular exponentiation  | Two exponentiations | **One squaring**   |

---

# SecureCorp Architecture

The first Lab 4 exercise is best understood as:

```text
                KEY MANAGEMENT
                     │
       ┌─────────────┼─────────────┐
       ↓             ↓             ↓
    Finance          HR       Supply Chain
       │             │             │
       └──── RSA identity keys ────┘
                     │
            authenticate exchange
                     ↓
              Diffie-Hellman
                     ↓
                Shared secret
                     ↓
                    HKDF
                     ↓
                  AES-GCM
                     ↓
          Secure communication
```

The registry lets more systems be added without redesigning the protocol, satisfying the scalability requirement. 

---

# HealthCare Rabin KMS Architecture

```text
Central Rabin KMS
      │
      ├── Hospital A
      │    ├ public n
      │    └ protected (p,q)
      │
      ├── Hospital B
      │
      └── Clinic C
             │
             ↓
      key lifecycle
      ├ generate
      ├ distribute public key
      ├ renew
      ├ rotate
      ├ revoke
      └ audit
```

The manual additionally calls for secure storage, auditing and privacy-regulation compliance. Encryption, authorization and audit logging are relevant technical controls, but **a Python program by itself cannot establish HIPAA compliance**; compliance also depends on organizational, administrative, physical and operational controls. 

---

# DRM Architecture

Do **not** implement:

```text
Master private key
      ↓
send to every customer
```

because once a customer has the master secret, the service cannot reliably revoke their possession of it.

Use:

```text
Content
   ↓
AES-GCM
   ↓
Encrypted content

AES content key
   ↓
ElGamal public key
   ↓
Wrapped content key

Customer request
   ↓
RBAC / ownership / expiry / revocation check
   ↓
Server-side authorized decryption
```

That preserves the manual's ElGamal + access-control objective while avoiding the unsafe master-private-key-distribution design.
