# Lab 6 — Digital Signatures

> Exam-ready reference based on the uploaded **Lab No. 6: Digital Signature** manual.
>
> The manual covers:
> - signing and verifying RSA digital signatures,
> - generating RSA key pairs,
> - exchanging/verifying signatures,
> - trying ElGamal, Schnorr, and Diffie–Hellman-based variants,
> - client/server verification,
> - a combined CIA-style exercise using RSA encryption, digital signatures, and SHA hashing.
>
> **Exam rule:** all message/key/file values below are user-input based unless cryptographic keys/nonces must be securely generated.

---

# 0. CORE IDEA

A digital signature provides:

```text
AUTHENTICITY  -> who signed
INTEGRITY     -> message was not changed
NON-REPUDIATION -> signer cannot easily deny signing (assuming key control)
```

Core flow:

```text
Sender:
Message
   ↓
Hash
   ↓
Sign hash using PRIVATE key
   ↓
Signature
```

Receiver:

```text
Message + Signature
        ↓
Hash message
        ↓
Verify signature using PUBLIC key
        ↓
VALID / INVALID
```

---

# 1. MOST IMPORTANT EXAM RULE

```text
ENCRYPTION
----------
Public key  -> encrypt
Private key -> decrypt


DIGITAL SIGNATURE
-----------------
Private key -> sign
Public key  -> verify
```

Do not mix these up.

---

# 2. INSTALL

```bash
pip install pycryptodome
```

Most code below uses:

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
```

---

# 3. RSA DIGITAL SIGNATURE — SHORTEST COMPLETE PROGRAM

Use when the question says:

- generate RSA keys,
- sign a message,
- verify the signature.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
bits = int(input("RSA key size: "))

key = RSA.generate(bits)

h = SHA256.new(msg)
sig = pkcs1_15.new(key).sign(h)

print("Public key:\n", key.publickey().export_key().decode())
print("Signature:", sig.hex())

try:
    pkcs1_15.new(key.publickey()).verify(SHA256.new(msg), sig)
    print("Signature valid")
except:
    print("Signature invalid")
```

For modern PyCryptodome RSA generation, use at least a library-supported secure size such as 1024/2048 bits depending on the lab environment.

---

# 4. RSA SIGN + VERIFY — EXISTING PEM KEYS

Use when keys are stored in files.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
priv_path = input("Private key file: ")
pub_path = input("Public key file: ")

priv = RSA.import_key(open(priv_path, "rb").read())
pub = RSA.import_key(open(pub_path, "rb").read())

sig = pkcs1_15.new(priv).sign(SHA256.new(msg))

print("Signature:", sig.hex())

try:
    pkcs1_15.new(pub).verify(SHA256.new(msg), sig)
    print("Signature valid")
except:
    print("Signature invalid")
```

---

# 5. RSA — GENERATE AND SAVE KEYS

```python
from Crypto.PublicKey import RSA

bits = int(input("RSA key size: "))
prefix = input("File prefix: ")

key = RSA.generate(bits)

open(prefix + "_private.pem", "wb").write(key.export_key())
open(prefix + "_public.pem", "wb").write(key.publickey().export_key())

print("Keys saved")
```

---

# 6. RSA — SIGN A FILE

Use when the question says "document", "file", "legal document", etc.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

path = input("File to sign: ")
key_path = input("Private key file: ")
sig_path = input("Signature output file: ")

data = open(path, "rb").read()
key = RSA.import_key(open(key_path, "rb").read())

sig = pkcs1_15.new(key).sign(SHA256.new(data))

open(sig_path, "wb").write(sig)

print("Signature:", sig.hex())
```

---

# 7. RSA — VERIFY A FILE SIGNATURE

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

path = input("File: ")
sig_path = input("Signature file: ")
pub_path = input("Public key file: ")

data = open(path, "rb").read()
sig = open(sig_path, "rb").read()
pub = RSA.import_key(open(pub_path, "rb").read())

try:
    pkcs1_15.new(pub).verify(SHA256.new(data), sig)
    print("Signature valid")
except:
    print("Signature invalid")
```

---

# 8. RSA — TAMPERING DEMONSTRATION

This is useful when the question asks to show that a signature detects modification.

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Original message: ").encode()
bits = int(input("RSA key size: "))

key = RSA.generate(bits)
sig = pkcs1_15.new(key).sign(SHA256.new(msg))

received = input("Received message: ").encode()

try:
    pkcs1_15.new(key.publickey()).verify(SHA256.new(received), sig)
    print("Signature valid")
except:
    print("Signature invalid - message/key/signature changed")
```

If `received != msg`, verification should fail.

---

# 9. RSA SIGNATURE — NUMERICAL / TEXTBOOK VERSION

Use if the exam gives:

```text
n, e, d
```

and wants mathematical RSA signing rather than a library implementation.

```python
from hashlib import sha256

msg = input("Message: ").encode()
n = int(input("n: "))
e = int(input("e: "))
d = int(input("d: "))

h = int.from_bytes(sha256(msg).digest(), "big") % n

sig = pow(h, d, n)
verified = pow(sig, e, n)

print("Hash mod n:", h)
print("Signature:", sig)
print("Recovered hash:", verified)
print("Signature valid:", verified == h)
```

Formula:

```text
h = H(M)

Signature:
S = h^d mod n

Verification:
h' = S^e mod n

Valid if:
h' = h
```

---

# 10. HASH ONLY — SHA-256

```python
from hashlib import sha256

msg = input("Message: ").encode()

print("SHA-256:", sha256(msg).hexdigest())
```

Remember:

```text
Hashing alone -> integrity comparison
Digital signature -> integrity + signer authentication
```

---

# 11. RSA ENCRYPTION + RSA SIGNATURE + SHA-256

This is a compact combined answer for scenarios requiring:

```text
confidentiality + integrity + authentication
```

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
bits = int(input("RSA key size: "))

sender = RSA.generate(bits)
receiver = RSA.generate(bits)

# Sender signs plaintext
sig = pkcs1_15.new(sender).sign(SHA256.new(msg))

# Sender encrypts for receiver
ct = PKCS1_OAEP.new(receiver.publickey()).encrypt(msg)

print("Ciphertext:", ct.hex())
print("Signature:", sig.hex())

# Receiver decrypts
pt = PKCS1_OAEP.new(receiver).decrypt(ct)

# Receiver verifies sender
try:
    pkcs1_15.new(sender.publickey()).verify(SHA256.new(pt), sig)
    print("Signature valid")
    print("Decrypted:", pt.decode())
except:
    print("Signature invalid")
```

This demonstrates:

```text
RSA encryption -> confidentiality
SHA-256         -> message digest
RSA signature  -> integrity + authenticity
```

---

# 12. IMPORTANT CIA-TRIAD NOTE

The manual's additional exercise says to demonstrate the **CIA triad** using RSA encryption, digital signature, and SHA hashing.

Those mechanisms directly demonstrate:

```text
Confidentiality -> encryption
Integrity       -> hash/signature
Authenticity    -> signature
```

Strictly speaking:

```text
Availability
```

is not guaranteed by RSA, signatures, or hashing alone.

Availability normally requires system/network controls such as:

```text
redundancy
backup
failover
DoS resistance
recovery mechanisms
```

So if viva asks:

```text
"Does RSA + SHA + signature itself provide availability?"
```

answer:

```text
No. They mainly provide confidentiality, integrity and authenticity.
Availability requires separate operational/system controls.
```

---

# 13. VERIFY BEFORE DECRYPTING — SIGN THE CIPHERTEXT

Sometimes a combined scenario explicitly says:

```text
1. encrypt
2. hash/sign encrypted message
3. receiver verifies
4. ONLY IF VALID -> decrypt
```

Use this structure:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
bits = int(input("RSA key size: "))

sender = RSA.generate(bits)
receiver = RSA.generate(bits)

ct = PKCS1_OAEP.new(receiver.publickey()).encrypt(msg)

sig = pkcs1_15.new(sender).sign(SHA256.new(ct))

print("Ciphertext:", ct.hex())
print("Signature:", sig.hex())

try:
    pkcs1_15.new(sender.publickey()).verify(SHA256.new(ct), sig)

    print("Sender verified")
    print("Integrity verified")

    pt = PKCS1_OAEP.new(receiver).decrypt(ct)

    print("Decrypted:", pt.decode())

except:
    print("Integrity/authenticity failed")
    print("Decryption not performed")
```

This ordering is ideal if the question explicitly says:

```text
do not decrypt when integrity fails
```

---

# 14. FORCE INTEGRITY FAILURE BY MODIFYING CIPHERTEXT

```python
tampered = bytearray(ct)

if not tampered:
    raise ValueError("Ciphertext is empty")

tampered[0] ^= 1
tampered = bytes(tampered)
```

Verification:

```python
try:
    pkcs1_15.new(sender.publickey()).verify(
        SHA256.new(tampered),
        sig
    )

    print("Signature valid")

except:
    print("Integrity failed")
```

Do **not** decrypt after failure if the question says not to.

---

# 15. RSA ENCRYPTION AND SIGNATURE — KEY ROLES

If Alice sends securely to Bob:

```text
ENCRYPTION:
Alice encrypts using Bob's PUBLIC key
Bob decrypts using Bob's PRIVATE key

SIGNATURE:
Alice signs using Alice's PRIVATE key
Bob verifies using Alice's PUBLIC key
```

This is extremely important.

---

# 16. ELGAMAL DIGITAL SIGNATURE — TEXTBOOK PROGRAM

The Lab 6 exercise asks to try ElGamal.

A standard ElGamal signature scheme can be demonstrated mathematically.

Requirements:

```text
p = prime
g = generator
x = private key
y = g^x mod p = public value

Choose k such that:
gcd(k, p-1) = 1
```

Signature:

```text
r = g^k mod p

s = k^(-1) * (H(m) - x*r) mod (p-1)
```

Verification:

```text
g^H(m) mod p
=
y^r * r^s mod p
```

Program:

```python
from hashlib import sha256
from math import gcd

msg = input("Message: ").encode()
p = int(input("Prime p: "))
g = int(input("Generator g: "))
x = int(input("Private key x: "))
k = int(input("Random k: "))

if gcd(k, p-1) != 1:
    raise ValueError("k must be coprime with p-1")

y = pow(g, x, p)
h = int.from_bytes(sha256(msg).digest(), "big") % (p-1)

r = pow(g, k, p)
s = (pow(k, -1, p-1) * (h - x*r)) % (p-1)

left = pow(g, h, p)
right = pow(y, r, p) * pow(r, s, p) % p

print("Public key:", (p, g, y))
print("Signature:", (r, s))
print("Signature valid:", left == right)
```

---

# 17. ELGAMAL SIGNATURE — USER PROVIDES PUBLIC KEY FOR VERIFY

Useful if sender and receiver are separated.

```python
from hashlib import sha256

msg = input("Message: ").encode()

p = int(input("p: "))
g = int(input("g: "))
y = int(input("Public key y: "))

r = int(input("Signature r: "))
s = int(input("Signature s: "))

h = int.from_bytes(sha256(msg).digest(), "big") % (p-1)

left = pow(g, h, p)
right = pow(y, r, p) * pow(r, s, p) % p

print("Signature valid:", left == right)
```

---

# 18. SCHNORR DIGITAL SIGNATURE — TEXTBOOK VERSION

The manual asks to try Schnorr but does not provide the mathematical specification.

The following is a standard educational Schnorr-style formulation.

Parameters:

```text
q divides p-1
g has order q modulo p

private x
public y = g^x mod p
```

Signing:

```text
r = g^k mod p
e = H(message || r) mod q
s = k + e*x mod q
```

Verification:

```text
g^s mod p
=
r * y^e mod p
```

Program:

```python
from hashlib import sha256

msg = input("Message: ").encode()

p = int(input("Prime p: "))
q = int(input("Prime q dividing p-1: "))
g = int(input("Generator g of order q: "))
x = int(input("Private key x: "))
k = int(input("Random nonce k: "))

if (p-1) % q != 0:
    raise ValueError("q must divide p-1")

y = pow(g, x, p)
r = pow(g, k, p)

e = int.from_bytes(
    sha256(msg + str(r).encode()).digest(),
    "big"
) % q

s = (k + e*x) % q

valid = pow(g, s, p) == (r * pow(y, e, p)) % p

print("Public key:", y)
print("Signature:", (e, s))
print("Signature valid:", valid)
```

---

# 19. SCHNORR — VERIFY PROVIDED SIGNATURE

Because the signature above stores `(e,s)`, the verifier reconstructs `r`.

From:

```text
g^s = r*y^e
```

therefore:

```text
r = g^s * (y^e)^(-1) mod p
```

Program:

```python
from hashlib import sha256

msg = input("Message: ").encode()

p = int(input("p: "))
q = int(input("q: "))
g = int(input("g: "))
y = int(input("Public key y: "))

e = int(input("Signature e: "))
s = int(input("Signature s: "))

r = pow(g, s, p) * pow(pow(y, e, p), -1, p) % p

e2 = int.from_bytes(
    sha256(msg + str(r).encode()).digest(),
    "big"
) % q

print("Signature valid:", e2 == e)
```

---

# 20. DIFFIE–HELLMAN — WHAT THE MANUAL ASKS VS WHAT IT DOES

The manual asks to:

```text
Try using the Diffie-Hellman asymmetric encryption standard
and verify the above steps.
```

But Diffie–Hellman itself is a:

```text
KEY EXCHANGE mechanism
```

not a digital-signature algorithm.

So the technically correct way to use DH in a Lab 6-style authentication/integrity exercise is:

```text
DH -> establish shared secret
shared secret -> authenticate message using HMAC
```

This gives shared-key message authentication, **not a public-key digital signature**.

---

# 21. DIFFIE–HELLMAN + HMAC — COMPLETE DEMO

```python
from hashlib import sha256
import hmac

p = int(input("Prime p: "))
g = int(input("Generator g: "))
a = int(input("Alice private key: "))
b = int(input("Bob private key: "))
msg = input("Message: ").encode()

A = pow(g, a, p)
B = pow(g, b, p)

Ka = pow(B, a, p)
Kb = pow(A, b, p)

ka = sha256(str(Ka).encode()).digest()
kb = sha256(str(Kb).encode()).digest()

tag = hmac.new(ka, msg, sha256).hexdigest()

valid = hmac.compare_digest(
    tag,
    hmac.new(kb, msg, sha256).hexdigest()
)

print("Alice public:", A)
print("Bob public:", B)
print("Shared secret match:", Ka == Kb)
print("HMAC:", tag)
print("Message authenticated:", valid)
```

Remember:

```text
HMAC != digital signature
```

because both parties know the same secret key.

---

# 22. CLIENT/SERVER RSA SIGNATURE — SERVER

The manual asks to perform the signature workflow in a client/server scenario.

Use this as `server.py`.

```python
import socket, json, base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

host = input("Host (blank for all): ")
port = int(input("Port: "))

s = socket.socket()
s.bind((host, port))
s.listen(1)

print("Waiting for client...")

c, addr = s.accept()

obj = json.loads(c.recv(65536).decode())

msg = obj["message"].encode()
sig = bytes.fromhex(obj["signature"])
pub = RSA.import_key(base64.b64decode(obj["public_key"]))

try:
    pkcs1_15.new(pub).verify(SHA256.new(msg), sig)
    result = "Signature valid"
except:
    result = "Signature invalid"

print("Client:", addr)
print("Message:", msg.decode())
print(result)

c.sendall(result.encode())

c.close()
s.close()
```

---

# 23. CLIENT/SERVER RSA SIGNATURE — CLIENT

Use as `client.py`.

```python
import socket, json, base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

host = input("Server host: ")
port = int(input("Port: "))
msg = input("Message: ").encode()
bits = int(input("RSA key size: "))

key = RSA.generate(bits)

sig = pkcs1_15.new(key).sign(SHA256.new(msg))

obj = {
    "message": msg.decode(),
    "signature": sig.hex(),
    "public_key": base64.b64encode(
        key.publickey().export_key()
    ).decode()
}

s = socket.socket()
s.connect((host, port))
s.sendall(json.dumps(obj).encode())

print(s.recv(1024).decode())

s.close()
```

---

# 24. CLIENT/SERVER — TAMPERING TEST

In the client code, after creating the signature:

```python
sig = pkcs1_15.new(key).sign(SHA256.new(msg))
```

you can intentionally send a changed message:

```python
sent = input("Message actually sent: ").encode()
```

but keep the original signature.

Then:

```python
obj["message"] = sent.decode()
```

If:

```text
sent != msg
```

the server should print:

```text
Signature invalid
```

---

# 25. SIGNATURE + ENCRYPTION — COMPLETE TWO-PARTY MODEL

Suppose Alice sends to Bob.

```text
Alice:
1. hash message
2. sign using ALICE PRIVATE key
3. encrypt message using BOB PUBLIC key
4. send ciphertext + signature

Bob:
1. decrypt using BOB PRIVATE key
2. hash decrypted message
3. verify signature using ALICE PUBLIC key
```

Code roles:

```python
sender_private
sender_public

receiver_private
receiver_public
```

Do not accidentally verify using Bob's public key.

---

# 26. HASH-THEN-SIGN

Standard conceptual sequence:

```text
Message
   ↓
Hash
   ↓
Digest
   ↓
Sign digest with private key
```

With PyCryptodome:

```python
h = SHA256.new(msg)
sig = pkcs1_15.new(private_key).sign(h)
```

Verification:

```python
pkcs1_15.new(public_key).verify(SHA256.new(msg), sig)
```

---

# 27. WHAT HAPPENS IF MESSAGE CHANGES?

Original:

```text
H(M)
```

Tampered:

```text
H(M')
```

Normally:

```text
H(M) != H(M')
```

So the old signature no longer verifies against the changed message.

---

# 28. WHAT HAPPENS IF SIGNATURE CHANGES?

```python
tampered = bytearray(sig)
tampered[0] ^= 1
tampered = bytes(tampered)
```

Then:

```python
try:
    pkcs1_15.new(pub).verify(SHA256.new(msg), tampered)
    print("Valid")
except:
    print("Invalid")
```

---

# 29. WHAT HAPPENS IF WRONG PUBLIC KEY IS USED?

```python
wrong = RSA.generate(bits)

try:
    pkcs1_15.new(wrong.publickey()).verify(SHA256.new(msg), sig)
    print("Valid")
except:
    print("Invalid")
```

Expected:

```text
Invalid
```

because the signature was created with another private key.

---

# 30. AUTHENTICITY vs INTEGRITY

```text
HASH ONLY
---------
Can detect change if you already trust the expected hash.

DIGITAL SIGNATURE
-----------------
Binds the message digest to the signer's private key.

Therefore:
signature verification checks both
- message integrity
- signer possession of the corresponding private key
```

---

# 31. PUBLIC / PRIVATE KEY SHARING

Standard cryptographic practice:

```text
PUBLIC key:
can be distributed

PRIVATE key:
must remain secret
```

The manual's website exercise asks students to copy/exchange both public and private RSA values during the educational activity.

For an actual cryptographic system:

```text
DO NOT distribute the private key.
```

If the exam asks what should be exchanged in a real system:

```text
public key + message/signature
```

not the private key.

---

# 32. MANUAL ONLINE-RSA TOOL CAUTION

The manual shows an online RSA signing tool and gives:

```text
Public Modulus
Private Exponent
Public Exponent
```

but the manual does **not** specify the exact padding/hash encoding used internally by that website.

Therefore, a local PyCryptodome program using:

```text
SHA-256 + PKCS#1 v1.5 signature
```

is a standard implementation, but you should **not expect its signature bytes to exactly match the website's output** unless the website uses the same signature encoding and hash.

---

# 33. ELGAMAL vs RSA SIGNATURE QUICK DIFFERENCE

```text
RSA signature:
signature is based on RSA private operation over an encoded hash

ElGamal signature:
uses modular exponentiation plus a fresh random nonce k
produces pair (r,s)
```

For ElGamal:

```text
k must satisfy gcd(k,p-1)=1
```

and should not be reused.

---

# 34. SCHNORR QUICK IDEA

```text
private key = x
public key  = y = g^x mod p

fresh nonce k
commitment r = g^k

challenge e = H(message || r)

response s = k + e*x mod q
```

Verification checks the algebraic relation between:

```text
g, y, r, e, s
```

---

# 35. RSA SIGNATURE TIMING

```python
from time import perf_counter
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
bits = int(input("RSA key size: "))

t = perf_counter()
key = RSA.generate(bits)
kg = perf_counter() - t

t = perf_counter()
sig = pkcs1_15.new(key).sign(SHA256.new(msg))
st = perf_counter() - t

t = perf_counter()
pkcs1_15.new(key.publickey()).verify(SHA256.new(msg), sig)
vt = perf_counter() - t

print("Key generation:", kg)
print("Signing:", st)
print("Verification:", vt)
```

---

# 36. HASH FILE + SIGN HASH

For a document/file:

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

path = input("File: ")
bits = int(input("RSA key size: "))

data = open(path, "rb").read()
key = RSA.generate(bits)

h = SHA256.new(data)
sig = pkcs1_15.new(key).sign(h)

print("SHA-256:", h.hexdigest())
print("Signature:", sig.hex())

try:
    pkcs1_15.new(key.publickey()).verify(SHA256.new(data), sig)
    print("Signature valid")
except:
    print("Signature invalid")
```

---

# 37. SAVE SIGNATURE AS HEX TEXT

```python
path = input("Signature output file: ")

open(path, "w").write(sig.hex())
```

Read later:

```python
sig = bytes.fromhex(open(path).read().strip())
```

---

# 38. EXAM ROUTING TABLE

| Question wording | Use |
|---|---|
| RSA sign + verify message | Section 3 |
| Use existing RSA PEM keys | Section 4 |
| Generate/save RSA keys | Section 5 |
| Sign a document/file | Section 6 |
| Verify document signature | Section 7 |
| Demonstrate message tampering | Section 8 |
| Numerical RSA signature with `n,e,d` | Section 9 |
| SHA hashing | Section 10 |
| RSA encryption + signature + hash | Section 11 |
| Verify before decrypting | Section 13 |
| Tamper ciphertext | Section 14 |
| ElGamal signature | Sections 16–17 |
| Schnorr signature | Sections 18–19 |
| Diffie–Hellman lab variant | Sections 20–21 |
| Client/server signature | Sections 22–24 |
| Explain key roles | Sections 15, 25 |
| Compare hash vs signature | Sections 26–30 |
| Timing | Section 35 |

---

# 39. COMMON ERRORS

## Error 1 — signing with public key

Wrong:

```text
public key signs
```

Correct:

```text
private key signs
public key verifies
```

---

## Error 2 — verifying using receiver's public key

If Alice signed:

```text
verify with ALICE'S public key
```

not Bob's.

---

## Error 3 — confusing signature with encryption

A signature does not hide the message.

Encryption gives confidentiality.

Signature gives authenticity/integrity.

---

## Error 4 — hashing and calling it a signature

```text
SHA256(message)
```

is a digest.

It is not a digital signature.

---

## Error 5 — distributing private key

Do not do this in a real system.

Only the public key is distributed.

---

## Error 6 — reusing ElGamal/Schnorr nonce

Fresh nonce:

```text
k
```

is important.

Do not reuse it in real cryptographic signing.

---

## Error 7 — calling DH a digital signature

Diffie–Hellman is key exchange.

DH + HMAC provides shared-key authentication, not public-key digital signatures.

---

# 40. MASTER COMMENT FOR LAB 6

Paste this at the top of your Lab 6 notes:

```python
# LAB 6 DIGITAL SIGNATURE QUICK REFERENCE
#
# ENCRYPTION:
#   receiver PUBLIC key  -> encrypt
#   receiver PRIVATE key -> decrypt
#
# SIGNATURE:
#   sender PRIVATE key -> sign
#   sender PUBLIC key  -> verify
#
# RSA signature:
#   h = SHA256(message)
#   signature = sign(h, private_key)
#   verify(h, signature, public_key)
#
# If message/signature/public key changes:
#   verification should fail
#
# Combined secure communication:
#   1. sender signs
#   2. encrypt for receiver
#   3. receiver decrypts
#   4. verify using sender public key
#
# If question says VERIFY BEFORE DECRYPT:
#   sign/hash the CIPHERTEXT
#   verify ciphertext first
#   decrypt only when valid
#
# ELGAMAL SIGNATURE:
#   y = g^x mod p
#   r = g^k mod p
#   s = k^-1 * (H(m)-x*r) mod (p-1)
#   verify:
#   g^H(m) == y^r * r^s (mod p)
#
# SCHNORR:
#   y=g^x
#   r=g^k
#   e=H(m||r)
#   s=k+e*x mod q
#
# DH:
#   key exchange, NOT digital signature
#
# Hash != signature
# Signature != encryption
#
# Public key may be shared.
# Private key must remain secret.
```

---

# 41. MINIMUM RSA CODE TO REMEMBER

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

msg = input("Message: ").encode()
key = RSA.generate(int(input("RSA bits: ")))

sig = pkcs1_15.new(key).sign(SHA256.new(msg))

try:
    pkcs1_15.new(key.publickey()).verify(SHA256.new(msg), sig)
    print("Valid")
except:
    print("Invalid")
```

If you remember only one Lab 6 program, remember this one.

---

# END — LAB 6
