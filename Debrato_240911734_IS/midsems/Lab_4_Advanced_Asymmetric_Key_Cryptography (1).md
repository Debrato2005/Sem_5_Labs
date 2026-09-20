# Lab 4 — Advanced Asymmetric Key Cryptography

> Exam-ready reference based on the Lab 4 manual.
>
> **Goal:** keep the code modular, user-input based, short enough to reuse in a scenario question, and complete enough to combine components.

---

# 0. WHAT LAB 4 COVERS

The manual focuses on three areas:

1. **Asymmetric algorithms**
   - RSA
   - ElGamal
   - Rabin

2. **Key management**
   - generation
   - distribution
   - revocation
   - renewal / rotation
   - secure storage
   - logging / auditing

3. **Access control**
   - RBAC
   - ABAC
   - Bell–LaPadula
   - MAC
   - DAC
   - time-based access control
   - probabilistic access control

The scenario questions combine these components rather than asking only one isolated algorithm.

---

# 1. QUICK FORMULAS

## RSA

```text
n = p*q
phi = (p-1)(q-1)

gcd(e,phi) = 1
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
Choose prime p, generator g
Private key x
Public value y = g^x mod p

Public key  = (p,g,y)
Private key = x

Choose random k

c1 = g^k mod p
c2 = m*y^k mod p

s = c1^x mod p
m = c2*s^(-1) mod p
```

Python:

```python
y = pow(g, x, p)
c1 = pow(g, k, p)
c2 = m * pow(y, k, p) % p
m = c2 * pow(pow(c1, x, p), -1, p) % p
```

---

## Rabin

```text
Choose primes p,q such that:

p % 4 == 3
q % 4 == 3

n = p*q

Public key  = n
Private key = (p,q)

Encryption:
c = m^2 mod n
```

Decryption produces **four possible roots**.

This ambiguity is an inherent property of textbook Rabin.

---

## Diffie–Hellman

```text
Public: p,g

Alice private = a
Bob private   = b

A = g^a mod p
B = g^b mod p

K1 = B^a mod p
K2 = A^b mod p

K1 = K2
```

---

# 2. INSTALL

For the programs using PyCryptodome:

```bash
pip install pycryptodome
```

Optional for some mathematical work:

```bash
pip install sympy
```

---

# 3. RSA — SHORTEST USER-INPUT VERSION

```python
from math import gcd

p = int(input("p: "))
q = int(input("q: "))
e = int(input("e: "))
m = int(input("Plaintext integer: "))

n = p*q
phi = (p-1)*(q-1)

if gcd(e, phi) != 1:
    raise ValueError("e must be coprime with phi")

if not 0 <= m < n:
    raise ValueError("Plaintext must satisfy 0 <= m < n")

d = pow(e, -1, phi)

c = pow(m, e, n)
pt = pow(c, d, n)

print("Public key:", (n, e))
print("Private key:", (n, d))
print("Ciphertext:", c)
print("Decrypted:", pt)
```

---

# 4. ELGAMAL — SHORTEST USER-INPUT VERSION

```python
p = int(input("Prime p: "))
g = int(input("Generator g: "))
x = int(input("Private key x: "))
k = int(input("Random k: "))
m = int(input("Plaintext integer: "))

if not 0 <= m < p:
    raise ValueError("Plaintext must satisfy 0 <= m < p")

y = pow(g, x, p)

c1 = pow(g, k, p)
c2 = m * pow(y, k, p) % p

s = pow(c1, x, p)
pt = c2 * pow(s, -1, p) % p

print("Public key:", (p, g, y))
print("Private key:", x)
print("Ciphertext:", (c1, c2))
print("Decrypted:", pt)
```

---

# 5. RABIN — SHORTEST COMPLETE NUMERICAL

Use when the question gives or asks for Rabin encryption/decryption.

```python
from math import gcd

p = int(input("p (3 mod 4): "))
q = int(input("q (3 mod 4): "))
m = int(input("Plaintext integer: "))

if p % 4 != 3 or q % 4 != 3:
    raise ValueError("Rabin requires p,q = 3 mod 4")
if not 0 <= m < p*q:
    raise ValueError("Plaintext must be < n")

n = p*q
c = pow(m, 2, n)

mp = pow(c, (p+1)//4, p)
mq = pow(c, (q+1)//4, q)

yp = pow(p, -1, q)
yq = pow(q, -1, p)

r1 = (mp*q*yq + mq*p*yp) % n
r2 = (-r1) % n
r3 = (mp*q*yq - mq*p*yp) % n
r4 = (-r3) % n

roots = [r1, r2, r3, r4]

print("Public key:", n)
print("Private key:", (p, q))
print("Ciphertext:", c)
print("Possible plaintexts:", roots)

if m in roots:
    print("Original plaintext recovered:", m)
```

### Important Rabin point

Rabin decryption gives **four candidates**.

So in a practical system, the plaintext needs redundancy / formatting / padding so the correct root can be identified.

---

# 6. RABIN — GENERATE p,q OF CONFIGURABLE SIZE

Use for the Healthcare key-generation scenario.

```python
from Crypto.Util.number import getPrime

bits = int(input("Key size in bits: "))

def prime3(bits):
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            return p

p = prime3(bits//2)
q = prime3(bits//2)
n = p*q

print("Public key n:", n)
print("Private key:", (p, q))
```

---

# 7. RSA + DIFFIE–HELLMAN SECURE COMMUNICATION

The SecureCorp scenario requires:

```text
RSA + Diffie-Hellman
```

A clean interpretation is:

```text
RSA     -> identity / key protection
DH      -> shared secret
AES     -> actual data encryption
```

For a compact lab demonstration, generate RSA keys and establish the DH shared secret:

```python
from Crypto.PublicKey import RSA

bits = int(input("RSA key size: "))
p = int(input("DH prime p: "))
g = int(input("DH generator g: "))
a = int(input("System A private DH value: "))
b = int(input("System B private DH value: "))

A_rsa = RSA.generate(bits)
B_rsa = RSA.generate(bits)

A = pow(g, a, p)
B = pow(g, b, p)

Ka = pow(B, a, p)
Kb = pow(A, b, p)

print("System A RSA public key:\n", A_rsa.publickey().export_key().decode())
print("System B RSA public key:\n", B_rsa.publickey().export_key().decode())
print("System A DH public:", A)
print("System B DH public:", B)
print("Shared secret:", Ka)
print("Verified:", Ka == Kb)
```

---

# 8. RSA + DH + AES — COMPLETE SECURE COMMUNICATION DEMO

This is a stronger answer for the SecureCorp scenario because the derived shared secret is actually used.

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p = int(input("DH prime p: "))
g = int(input("DH generator g: "))
a = int(input("Sender private DH value: "))
b = int(input("Receiver private DH value: "))
msg = input("Message: ").encode()

A = pow(g, a, p)
B = pow(g, b, p)

Ka = pow(B, a, p)
Kb = pow(A, b, p)

ka = sha256(str(Ka).encode()).digest()
kb = sha256(str(Kb).encode()).digest()

cipher = AES.new(ka, AES.MODE_CBC)
ct = cipher.encrypt(pad(msg, 16))

pt = unpad(AES.new(kb, AES.MODE_CBC, cipher.iv).decrypt(ct), 16)

print("Sender public:", A)
print("Receiver public:", B)
print("Shared key match:", Ka == Kb)
print("IV:", cipher.iv.hex())
print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

If the question explicitly asks for RSA authentication/signing of the DH values, use Lab 6 digital-signature code with the DH public values.

---

# 9. CENTRALIZED KEY MANAGEMENT — GENERIC REUSABLE CLASS

This skeleton handles:

- generation
- distribution
- revocation
- renewal
- logging

It can be adapted to RSA / ElGamal / Rabin.

```python
from datetime import datetime

class KMS:
    def __init__(self):
        self.keys = {}
        self.log = []

    def add(self, name, public, private):
        self.keys[name] = {
            "public": public,
            "private": private,
            "active": True,
            "created": datetime.now()
        }
        self.log.append(("GENERATE", name, datetime.now()))

    def get(self, name):
        k = self.keys.get(name)
        if not k or not k["active"]:
            raise ValueError("Key unavailable/revoked")
        self.log.append(("DISTRIBUTE", name, datetime.now()))
        return k

    def revoke(self, name):
        self.keys[name]["active"] = False
        self.log.append(("REVOKE", name, datetime.now()))

    def show_log(self):
        for x in self.log:
            print(x)
```

Example use:

```python
kms = KMS()

name = input("Entity name: ")
public = input("Public key/value: ")
private = input("Private key/value: ")

kms.add(name, public, private)

print(kms.get(name))

if input("Revoke? (y/n): ").lower() == "y":
    kms.revoke(name)

kms.show_log()
```

---

# 10. RABIN CENTRALIZED KEY MANAGEMENT SERVICE

This directly matches the Healthcare scenario.

```python
from Crypto.Util.number import getPrime
from datetime import datetime

def prime3(bits):
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            return p

class RabinKMS:
    def __init__(self):
        self.keys = {}
        self.log = []

    def generate(self, name, bits):
        p = prime3(bits//2)
        q = prime3(bits//2)

        self.keys[name] = {
            "public": p*q,
            "private": (p, q),
            "active": True,
            "created": datetime.now()
        }

        self.log.append(("GENERATE", name, datetime.now()))

    def distribute(self, name):
        k = self.keys.get(name)

        if not k or not k["active"]:
            raise ValueError("Key unavailable/revoked")

        self.log.append(("DISTRIBUTE", name, datetime.now()))
        return k

    def revoke(self, name):
        self.keys[name]["active"] = False
        self.log.append(("REVOKE", name, datetime.now()))

    def renew(self, name, bits):
        self.generate(name, bits)
        self.log.append(("RENEW", name, datetime.now()))

    def logs(self):
        for x in self.log:
            print(x)

kms = RabinKMS()

name = input("Hospital/clinic: ")
bits = int(input("Key size: "))

kms.generate(name, bits)

print("Keys:", kms.distribute(name))

action = input("Action (revoke/renew/none): ").lower()

if action == "revoke":
    kms.revoke(name)

elif action == "renew":
    kms.renew(name, bits)

kms.logs()
```

---

# 11. KEY RENEWAL BASED ON AGE

The manual mentions periodic renewal, for example every 12 months.

Use this helper:

```python
from datetime import datetime, timedelta

def expired(created, days):
    return datetime.now() >= created + timedelta(days=days)
```

Example:

```python
days = int(input("Renew after how many days? "))

if expired(kms.keys[name]["created"], days):
    kms.renew(name, bits)
```

For an exam, user-input days are easier than hardcoding "12 months".

---

# 12. SECURE STORAGE — SIMPLE AES-GCM KEY VAULT

The manual requires private keys to be stored securely.

A compact demonstration is to encrypt the private-key text before storing it.

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

master = get_random_bytes(32)

def store_private(text):
    c = AES.new(master, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(text.encode())
    return c.nonce, tag, ct

def load_private(data):
    nonce, tag, ct = data
    return AES.new(master, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode()
```

Use:

```python
private = input("Private key data: ")
stored = store_private(private)

print("Encrypted private key:", stored[2].hex())
print("Recovered:", load_private(stored))
```

For the lab, this demonstrates that the private key is not stored as plaintext.

---

# 13. AUDITING / LOGGING

Shortest useful pattern:

```python
from datetime import datetime

logs = []

def log(action, user):
    logs.append((datetime.now(), action, user))
```

Example:

```python
name = input("Entity: ")

log("KEY_GENERATED", name)
log("KEY_DISTRIBUTED", name)

for row in logs:
    print(row)
```

---

# 14. RBAC — ROLE-BASED ACCESS CONTROL

Formula from the manual:

```text
Access(User,Object) =
exists Role:
HasRole(User,Role) AND CanAccess(Role,Object)
```

Compact implementation:

```python
roles = {
    "admin": {"read", "write", "delete"},
    "doctor": {"read", "write"},
    "viewer": {"read"}
}

role = input("Role: ").lower()
action = input("Action: ").lower()

print("Access granted:", action in roles.get(role, set()))
```

---

# 15. RBAC — FULL USER/ROLE VERSION

```python
users = {}
permissions = {
    "admin": {"read", "write", "delete"},
    "staff": {"read", "write"},
    "guest": {"read"}
}

user = input("User: ")
role = input("Role: ").lower()
action = input("Requested action: ").lower()

users[user] = role

allowed = action in permissions.get(users[user], set())

print("Access granted:", allowed)
```

---

# 16. ABAC — ATTRIBUTE-BASED ACCESS CONTROL

The manual defines:

```text
Access(User,Object,Environment)
    = f(UserAttributes,ObjectAttributes,EnvironmentAttributes)
```

Simple reusable example:

```python
user_level = int(input("User clearance level: "))
object_level = int(input("Object sensitivity level: "))
trusted = input("Trusted environment? (y/n): ").lower() == "y"

allowed = user_level >= object_level and trusted

print("Access granted:", allowed)
```

---

# 17. BELL–LAPADULA

Manual rules:

```text
Simple Security Property:
S(subject) >= C(object)
for READ

*-Property:
S(subject) <= C(object)
for WRITE
```

Meaning:

```text
No Read Up
No Write Down
```

Code:

```python
subject = int(input("Subject security level: "))
obj = int(input("Object classification: "))
action = input("Action (read/write): ").lower()

if action == "read":
    allowed = subject >= obj

elif action == "write":
    allowed = subject <= obj

else:
    allowed = False

print("Access granted:", allowed)
```

---

# 18. MAC — MANDATORY ACCESS CONTROL

From the manual:

```text
AccessGranted =
(SubjectClearance >= ObjectClassification)
AND PolicyRuleSatisfied
```

```python
clearance = int(input("Subject clearance: "))
classification = int(input("Object classification: "))
policy = input("Policy satisfied? (y/n): ").lower() == "y"

print("Access granted:", clearance >= classification and policy)
```

---

# 19. DAC — DISCRETIONARY ACCESS CONTROL

Manual idea:

```text
AccessMatrix[Subject,Object] = {Rights}
```

Compact implementation:

```python
access = {}

user = input("User: ")
obj = input("Object: ")
rights = set(input("Rights (space separated): ").lower().split())

access[(user, obj)] = rights

action = input("Requested action: ").lower()

print("Access granted:", action in access[(user, obj)])
```

---

# 20. TIME-BASED ACCESS CONTROL

Manual formula:

```text
Access =
(Time >= StartTime)
AND
(Time <= EndTime)
AND
OtherConditions
```

Compact implementation:

```python
from datetime import datetime

start = int(input("Start hour (0-23): "))
end = int(input("End hour (0-23): "))

hour = datetime.now().hour

print("Access granted:", start <= hour <= end)
```

---

# 21. PROBABILISTIC ACCESS CONTROL

The manual describes access probability as a function of:

```text
UserTrustLevel
ObjectSensitivity
EnvironmentRisk
```

The manual does **not** specify an exact function `f`.

Therefore do not invent a claimed official formula.

For a lab demonstration only, you may define your own policy, for example:

```python
trust = float(input("Trust (0-1): "))
sensitivity = float(input("Sensitivity (0-1): "))
risk = float(input("Environment risk (0-1): "))

score = trust * (1-sensitivity) * (1-risk)

threshold = float(input("Required threshold: "))

print("Access granted:", score >= threshold)
```

If asked in viva:

```text
The exact probability function is policy-defined.
```

---

# 22. ELGAMAL DRM — CORE ENCRYPTION

The additional question describes a DRM system using ElGamal.

Core cryptographic part:

```python
from secrets import randbelow

p = int(input("Prime p: "))
g = int(input("Generator g: "))
x = int(input("Master private key x: "))
m = int(input("Content block as integer: "))

y = pow(g, x, p)

k = randbelow(p-2) + 1

c1 = pow(g, k, p)
c2 = m * pow(y, k, p) % p

pt = c2 * pow(pow(c1, x, p), -1, p) % p

print("Master public key:", (p, g, y))
print("Ciphertext:", (c1, c2))
print("Decrypted:", pt)
```

---

# 23. DRM ACCESS CONTROL — LIMITED-TIME / REVOKE

```python
from datetime import datetime, timedelta

access = {}

user = input("Customer: ")
content = input("Content ID: ")
minutes = int(input("Access duration in minutes: "))

access[(user, content)] = {
    "expires": datetime.now() + timedelta(minutes=minutes),
    "revoked": False
}

def allowed(user, content):
    a = access.get((user, content))
    return bool(a and not a["revoked"] and datetime.now() < a["expires"])

print("Access granted:", allowed(user, content))

if input("Revoke now? (y/n): ").lower() == "y":
    access[(user, content)]["revoked"] = True

print("Access after update:", allowed(user, content))
```

---

# 24. WEAK RSA ATTACK — FACTOR SMALL / WEAK n

The manual's additional scenario asks to demonstrate recovery of an RSA private key when `p` and `q` are too small or insufficiently random.

This is the shortest dependency-free demonstration.

```python
from math import isqrt, gcd

n = int(input("Public modulus n: "))
e = int(input("Public exponent e: "))
c = int(input("Ciphertext integer: "))

p = None

for i in range(2, isqrt(n)+1):
    if n % i == 0:
        p = i
        break

if p is None:
    raise ValueError("No small factor found")

q = n // p
phi = (p-1)*(q-1)

if gcd(e, phi) != 1:
    raise ValueError("Invalid RSA parameters")

d = pow(e, -1, phi)
m = pow(c, d, n)

print("Recovered p:", p)
print("Recovered q:", q)
print("Recovered private exponent d:", d)
print("Recovered plaintext:", m)
```

### Mitigation to write

```text
- use sufficiently large RSA keys
- generate p and q with a cryptographically secure random generator
- ensure p and q are distinct
- use established cryptographic libraries
- never implement production RSA prime generation manually
- protect the private key
- use current recommended key sizes / standards
```

---

# 25. RSA vs RABIN — TRADE-OFF POINTS

The Healthcare question explicitly asks for a trade-off analysis.

```text
RSA
----
Key generation:
    choose p,q
    compute n,phi,e,d

Encryption:
    c = m^e mod n

Decryption:
    m = c^d mod n

Decryption result:
    one intended plaintext when used correctly

Security basis:
    difficulty of factoring n


Rabin
-----
Key generation:
    choose p,q with p=q=3 mod 4 condition
    n = pq

Encryption:
    c = m^2 mod n

Decryption:
    square roots mod n

Decryption result:
    four possible plaintext roots

Security basis:
    closely related to integer factorization

Main practical issue:
    identifying the correct one of four roots requires redundancy /
    encoding / padding
```

Do not claim timing results unless you actually measured them.

---

# 26. KEY MANAGEMENT CHECKLIST

If a scenario question says **"implement key management"**, include these concepts:

```text
[ ] Key generation
[ ] Key storage
[ ] Key distribution
[ ] Key revocation
[ ] Key renewal / rotation
[ ] Key expiry
[ ] Logging / auditing
[ ] Access control
```

If the scenario explicitly asks for compliance, state the relevant control objective rather than claiming that a short classroom script is fully compliant.

For example:

```text
The implementation demonstrates technical controls such as access
restriction, logging, key revocation, and encrypted key storage.
A complete regulatory-compliance system would require additional
organizational, operational, and legal controls.
```

---

# 27. KEY ENTROPY / KDF / ROTATION FORMULAS

From the manual:

```text
Entropy:

H(K) = -Σ p(i) log2 p(i)
```

```text
Key derivation:

DK = KDF(Key, Salt, Iterations)
```

```text
Rotation rate:

Rotation Rate = N/T
```

```text
Expiry:

Expiry Time = t0 + L
```

---

# 28. KDF EXAMPLE

Useful if a scenario says derive a secure key from a password.

```python
from hashlib import pbkdf2_hmac
from os import urandom

password = input("Password: ").encode()
iterations = int(input("Iterations: "))

salt = urandom(16)

key = pbkdf2_hmac(
    "sha256",
    password,
    salt,
    iterations,
    32
)

print("Salt:", salt.hex())
print("Derived key:", key.hex())
```

---

# 29. KEY ROTATION RATE

```python
N = int(input("Number of keys: "))
T = float(input("Rotation period: "))

print("Rotation rate:", N/T)
```

---

# 30. KEY EXPIRY

```python
from datetime import datetime, timedelta

days = int(input("Key lifetime in days: "))

created = datetime.now()
expires = created + timedelta(days=days)

print("Created:", created)
print("Expires:", expires)
```

---

# 31. PERFORMANCE TIMING TEMPLATE

Use this around any algorithm.

```python
from time import perf_counter

t = perf_counter()

# operation

elapsed = perf_counter() - t

print("Time:", elapsed, "seconds")
```

---

# 32. RSA / ELGAMAL / RABIN TIMING TEMPLATE

```python
from time import perf_counter

def measure(fn):
    t = perf_counter()
    result = fn()
    return result, perf_counter()-t
```

Example:

```python
result, t = measure(lambda: pow(123, 65537, 99991))
print("Result:", result)
print("Time:", t)
```

---

# 33. SECURECORP — WHAT TO INCLUDE

If you get a SecureCorp-like scenario, your answer should have:

```text
1. RSA keys for each subsystem
2. DH public/private values
3. shared-secret verification
4. key-management dictionary/class
5. revoke / renew functions
6. ability to add new subsystem
7. optional AES encryption using the shared secret
```

Do not hardcode System A/B/C into the logic.

Use:

```python
name = input("Subsystem name: ")
```

and store dynamically.

---

# 34. HEALTHCARE RABIN KMS — WHAT TO INCLUDE

Required components from the manual:

```text
1. configurable Rabin key size
2. key generation
3. key distribution
4. key revocation
5. key renewal
6. secure private-key storage
7. logging/auditing
8. compliance-related controls
9. Rabin vs RSA discussion
```

Sections 10–13 + 25 cover these.

---

# 35. DIGIRIGHTS ELGAMAL DRM — WHAT TO INCLUDE

Required components:

```text
1. ElGamal master key
2. content encryption
3. private-key distribution to authorized users
4. access control
5. limited-time access
6. revocation
7. renewal
8. secure storage
9. logging
```

Sections 22–23 plus the generic KMS/logging/secure-storage sections cover these.

---

# 36. RSA WEAK-KEY ATTACK — WHAT TO INCLUDE

```text
1. Read n,e,c
2. factor weak n
3. recover p,q
4. compute phi
5. recover d
6. decrypt ciphertext
7. print mitigation
```

Use Section 24.

---

# 37. ACCESS CONTROL QUICK TABLE

| Model | Core idea |
|---|---|
| RBAC | permissions assigned through roles |
| ABAC | decision based on attributes |
| Bell–LaPadula | confidentiality model: no read up, no write down |
| MAC | system-enforced clearance/classification |
| DAC | owner-controlled rights |
| Time-based | access allowed during valid time window |
| Probabilistic | policy-defined probability/risk decision |

---

# 38. EXAM ROUTING TABLE

| Question wording | Use |
|---|---|
| RSA | Section 3 |
| ElGamal | Section 4 |
| Rabin | Sections 5–6 |
| RSA + Diffie-Hellman system | Sections 7–8 |
| key management service | Sections 9–13 |
| Rabin hospital KMS | Section 10 |
| secure private-key storage | Section 12 |
| logging/auditing | Section 13 |
| RBAC | Sections 14–15 |
| ABAC | Section 16 |
| Bell–LaPadula | Section 17 |
| MAC | Section 18 |
| DAC | Section 19 |
| time access | Section 20 |
| probabilistic access | Section 21 |
| ElGamal DRM | Sections 22–23 |
| weak RSA attack | Section 24 |
| Rabin vs RSA | Section 25 |
| KDF | Section 28 |
| rotation/expiry | Sections 29–30 |
| performance | Sections 31–32 |

---

# 39. COMMON ERRORS

## Rabin

Wrong assumption:

```text
Rabin decryption gives exactly one plaintext.
```

Correct:

```text
Rabin decryption gives four roots.
```

---

## RSA

Do not use:

```text
tiny predictable p,q
```

in anything except the educational attack demonstration.

---

## ElGamal

Never reuse a fixed `k` in a real system.

For classroom numericals, the examiner may explicitly provide `k`.

---

## DH

Diffie–Hellman establishes a secret.

It does not by itself provide authenticated identity.

---

## Key management

Do not confuse:

```text
revocation = disable/reject existing key
renewal    = replace with new key
rotation   = periodically replace keys
expiry     = key becomes invalid after lifetime
```

---

## Access control

Remember Bell–LaPadula:

```text
NO READ UP
NO WRITE DOWN
```

---

# 40. ONE COMMENT BLOCK TO KEEP AT THE TOP

```python
# LAB 4 QUICK REFERENCE
#
# RSA:
#   n=p*q
#   phi=(p-1)*(q-1)
#   d=pow(e,-1,phi)
#   c=pow(m,e,n)
#   m=pow(c,d,n)
#
# ELGAMAL:
#   y=pow(g,x,p)
#   c1=pow(g,k,p)
#   c2=m*pow(y,k,p)%p
#   m=c2*pow(pow(c1,x,p),-1,p)%p
#
# RABIN:
#   p%4==3 and q%4==3
#   n=p*q
#   c=pow(m,2,n)
#   decryption gives FOUR roots
#
# DIFFIE-HELLMAN:
#   A=pow(g,a,p)
#   B=pow(g,b,p)
#   K1=pow(B,a,p)
#   K2=pow(A,b,p)
#
# KEY MANAGEMENT:
#   generate -> distribute -> store -> revoke -> renew/rotate -> log
#
# ACCESS CONTROL:
#   RBAC = role permissions
#   ABAC = attribute policy
#   Bell-LaPadula = no read up, no write down
#   MAC = clearance/classification + policy
#   DAC = owner-controlled rights
#
# WEAK RSA ATTACK:
#   factor weak n -> recover p,q -> phi -> d -> decrypt
```

---

# 41. FINAL EXAM STRATEGY

For a long scenario question:

```text
STEP 1: underline every required component
STEP 2: map each component to one small function/class
STEP 3: keep all entity names/messages/parameters as input()
STEP 4: print every important intermediate result requested
STEP 5: add timing only if asked
STEP 6: add comparison/observation only if asked
```

The Lab 4 questions are intentionally scenario-based and combine multiple components.  
Do not try to write one giant cryptographic program from scratch. Reuse the smallest relevant blocks above.

---

# END — LAB 4
