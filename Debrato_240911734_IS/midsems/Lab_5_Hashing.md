# Lab 5 — Hashing

> Exam-ready reference based on the uploaded **Lab No. 5: Hashing** manual.
>
> The manual covers:
> 1. a user-defined 32-bit hash beginning at `5381`,
> 2. socket-based integrity verification,
> 3. MD5 vs SHA-1 vs SHA-256 timing + collision checks,
> 4. multipart client/server transmission with reassembly and hash verification.
>
> All question-specific values are taken through `input()` wherever practical.

---

# 0. QUICK THEORY

A hash function maps arbitrary-length input to a fixed-size digest:

```text
h = H(M)
```

The lab manual emphasizes two security properties of cryptographic hashes:

```text
1. One-way property
2. Collision resistance
```

Main use in this lab:

```text
DATA INTEGRITY
```

If the message changes:

```text
H(original) != H(received)
```

then tampering/corruption is detected.

---

# 1. USER-DEFINED HASH — SHORTEST CORRECT VERSION

The manual says:

```text
Initial hash = 5381

For every character:
- multiply current hash by 33
- add ASCII value of character
- use bitwise operations
- keep result within 32 bits
```

A compact implementation is:

```python
def my_hash(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xffffffff
    return h

msg = input("Message: ")
print("Hash:", my_hash(msg))
```

Why this matches the manual:

```text
(h << 5) + h
= 32h + h
= 33h
```

and:

```python
& 0xffffffff
```

keeps the result within 32 bits.

---

# 2. USER-DEFINED HASH — HEX OUTPUT

Useful when the examiner expects a hash-looking hexadecimal result.

```python
def my_hash(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xffffffff
    return h

msg = input("Message: ")

print("Decimal:", my_hash(msg))
print("Hex:", f"{my_hash(msg):08x}")
```

---

# 3. USER-DEFINED HASH — TAMPER DETECTION

```python
def my_hash(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xffffffff
    return h

original = input("Original message: ")
received = input("Received message: ")

h1 = my_hash(original)
h2 = my_hash(received)

print("Original hash:", h1)
print("Received hash:", h2)
print("Integrity verified:", h1 == h2)
```

---

# 4. HASHLIB — GENERIC HASH FUNCTION

For standard hashes:

```python
import hashlib

def digest(msg, algorithm):
    return hashlib.new(algorithm, msg.encode()).hexdigest()

msg = input("Message: ")
alg = input("Algorithm (md5/sha1/sha256): ").lower()

print("Hash:", digest(msg, alg))
```

Common algorithm names:

```text
md5
sha1
sha256
```

---

# 5. MD5 — SHORTEST

```python
import hashlib

msg = input("Message: ").encode()

print(hashlib.md5(msg).hexdigest())
```

---

# 6. SHA-1 — SHORTEST

```python
import hashlib

msg = input("Message: ").encode()

print(hashlib.sha1(msg).hexdigest())
```

---

# 7. SHA-256 — SHORTEST

```python
import hashlib

msg = input("Message: ").encode()

print(hashlib.sha256(msg).hexdigest())
```

---

# 8. HASH A FILE

This is useful if a scenario combines hashing with encrypted files or file transfer.

```python
import hashlib

path = input("File path: ")
alg = input("Algorithm (md5/sha1/sha256): ").lower()

data = open(path, "rb").read()

print("Hash:", hashlib.new(alg, data).hexdigest())
```

---

# 9. VERIFY FILE INTEGRITY

```python
import hashlib

p1 = input("Original file: ")
p2 = input("Received file: ")
alg = input("Algorithm: ").lower()

h1 = hashlib.new(alg, open(p1, "rb").read()).hexdigest()
h2 = hashlib.new(alg, open(p2, "rb").read()).hexdigest()

print("Original hash:", h1)
print("Received hash:", h2)

if h1 == h2:
    print("Integrity verified")
else:
    print("Integrity failed")
```

---

# 10. SOCKET INTEGRITY — SERVER

The manual asks for a server that:

```text
1. receives data
2. computes its hash
3. sends the hash back to the client
```

Use this as `server.py`:

```python
import socket, hashlib

host = input("Host (blank for all): ")
port = int(input("Port: "))
alg = input("Hash algorithm: ").lower()

s = socket.socket()
s.bind((host, port))
s.listen(1)

print("Waiting for client...")

conn, addr = s.accept()
data = conn.recv(65536)

h = hashlib.new(alg, data).hexdigest()

print("Received:", data.decode())
print("Hash:", h)

conn.send(h.encode())

conn.close()
s.close()
```

For local testing:

```text
Host can be left blank on server.
```

---

# 11. SOCKET INTEGRITY — CLIENT

Use this as `client.py`:

```python
import socket, hashlib

host = input("Server host: ")
port = int(input("Port: "))
alg = input("Hash algorithm: ").lower()
msg = input("Message: ").encode()

s = socket.socket()
s.connect((host, port))

s.sendall(msg)

server_hash = s.recv(1024).decode()
local_hash = hashlib.new(alg, msg).hexdigest()

print("Server hash:", server_hash)
print("Local hash:", local_hash)

if server_hash == local_hash:
    print("Integrity verified")
else:
    print("Integrity failed")

s.close()
```

---

# 12. SOCKET INTEGRITY — TAMPERING DEMONSTRATION

The manual specifically asks to show that hash verification detects corruption/tampering.

The simplest way is to let the client optionally modify the transmitted message while still comparing against the original message's hash.

```python
import socket, hashlib

host = input("Server host: ")
port = int(input("Port: "))
alg = input("Hash algorithm: ").lower()

original = input("Original message: ")
sent = original

if input("Tamper before sending? (y/n): ").lower() == "y":
    sent = input("Tampered message: ")

s = socket.socket()
s.connect((host, port))

s.sendall(sent.encode())

server_hash = s.recv(1024).decode()
local_hash = hashlib.new(alg, original.encode()).hexdigest()

print("Original:", original)
print("Sent:", sent)
print("Original/local hash:", local_hash)
print("Server hash:", server_hash)

if server_hash == local_hash:
    print("Integrity verified")
else:
    print("Integrity failed - data was modified")

s.close()
```

Use with the same server from Section 10.

---

# 13. SERVER THAT RETURNS HASH + RECEIVED MESSAGE

Sometimes a scenario asks to display both what arrived and its hash.

```python
import socket, hashlib

host = input("Host (blank for all): ")
port = int(input("Port: "))
alg = input("Algorithm: ").lower()

s = socket.socket()
s.bind((host, port))
s.listen(1)

c, addr = s.accept()
data = c.recv(65536)

h = hashlib.new(alg, data).hexdigest()

reply = data.decode() + "\n" + h
c.sendall(reply.encode())

print("Client:", addr)
print("Received:", data.decode())
print("Hash:", h)

c.close()
s.close()
```

---

# 14. PERFORMANCE TEST — MD5 vs SHA-1 vs SHA-256

The manual asks to:

```text
- generate 50 to 100 random strings
- hash them with MD5, SHA-1 and SHA-256
- measure computation time
- detect collisions
```

Compact complete version:

```python
import hashlib, random, string, time

n = int(input("Number of strings (50-100): "))
length = int(input("Length of each string: "))

if not 50 <= n <= 100:
    raise ValueError("Manual requires 50-100 strings")

data = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    for _ in range(n)
]

for alg in ["md5", "sha1", "sha256"]:
    t = time.perf_counter()

    hashes = [
        hashlib.new(alg, s.encode()).hexdigest()
        for s in data
    ]

    elapsed = time.perf_counter() - t
    collisions = len(hashes) - len(set(hashes))

    print(
        alg,
        "time =", elapsed,
        "collisions =", collisions
    )
```

---

# 15. PERFORMANCE TEST — USER-SELECTED DATASET SIZE

If the examiner does not enforce 50–100:

```python
import hashlib, random, string, time

n = int(input("Number of strings: "))
length = int(input("String length: "))

data = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    for _ in range(n)
]

for alg in ("md5", "sha1", "sha256"):
    t = time.perf_counter()

    hashes = [
        hashlib.new(alg, x.encode()).hexdigest()
        for x in data
    ]

    dt = time.perf_counter() - t

    print(
        alg,
        "Time:", dt,
        "Collisions:", len(hashes) - len(set(hashes))
    )
```

---

# 16. COLLISION DETECTION — EXPLICIT PAIRS

If the question asks you to **identify which inputs collided**, not just count collisions:

```python
import hashlib

alg = input("Algorithm: ").lower()
n = int(input("Number of messages: "))

seen = {}

for _ in range(n):
    msg = input("Message: ")
    h = hashlib.new(alg, msg.encode()).hexdigest()

    if h in seen and seen[h] != msg:
        print("Collision:", seen[h], "<->", msg)
    else:
        seen[h] = msg
```

With MD5/SHA-1/SHA-256 and a tiny random classroom dataset, you should normally expect:

```text
0 observed collisions
```

Do not claim that zero observed collisions proves an algorithm is collision-free.

---

# 17. PERFORMANCE TEST — REPEAT FOR MORE STABLE TIMING

Hashing only 50–100 short strings can finish extremely quickly.

To make timing easier to observe while still using the same dataset:

```python
import hashlib, random, string, time

n = int(input("Number of strings (50-100): "))
length = int(input("String length: "))
runs = int(input("Number of repetitions: "))

if not 50 <= n <= 100:
    raise ValueError("Use 50-100 strings")

data = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    for _ in range(n)
]

for alg in ("md5", "sha1", "sha256"):
    t = time.perf_counter()

    hashes = None

    for _ in range(runs):
        hashes = [
            hashlib.new(alg, x.encode()).hexdigest()
            for x in data
        ]

    dt = time.perf_counter() - t

    print(
        alg,
        "Time:", dt,
        "Collisions:", len(hashes) - len(set(hashes))
    )
```

If the question literally asks only one hashing pass, use Section 14 instead.

---

# 18. PLOT HASHING TIMES

Useful if the exam asks for a graph.

```python
import hashlib, random, string, time
import matplotlib.pyplot as plt

n = int(input("Number of strings: "))
length = int(input("String length: "))

data = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    for _ in range(n)
]

algs = ["md5", "sha1", "sha256"]
times = []

for alg in algs:
    t = time.perf_counter()

    for x in data:
        hashlib.new(alg, x.encode()).hexdigest()

    times.append(time.perf_counter() - t)

print(dict(zip(algs, times)))

plt.bar(algs, times)
plt.xlabel("Hash Algorithm")
plt.ylabel("Time (seconds)")
plt.title("Hashing Performance")
plt.show()
```

---

# 19. MULTIPART MESSAGE — SERVER

The additional exercise asks:

```text
client sends message in multiple parts
server reassembles it
server hashes reassembled message
server sends hash back
client compares against original
```

Use `server.py`:

```python
import socket, hashlib

host = input("Host (blank for all): ")
port = int(input("Port: "))
alg = input("Hash algorithm: ").lower()

s = socket.socket()
s.bind((host, port))
s.listen(1)

c, addr = s.accept()

parts = []

while True:
    data = c.recv(1024)

    if not data:
        break

    if data == b"END":
        break

    parts.append(data)

msg = b"".join(parts)
h = hashlib.new(alg, msg).hexdigest()

print("Reassembled:", msg.decode())
print("Hash:", h)

c.sendall(h.encode())

c.close()
s.close()
```

---

# 20. MULTIPART MESSAGE — CLIENT

```python
import socket, hashlib

host = input("Server host: ")
port = int(input("Port: "))
alg = input("Hash algorithm: ").lower()

msg = input("Message: ")
size = int(input("Part size: "))

s = socket.socket()
s.connect((host, port))

data = msg.encode()

for i in range(0, len(data), size):
    s.sendall(data[i:i+size])

s.sendall(b"END")

server_hash = s.recv(1024).decode()
local_hash = hashlib.new(alg, data).hexdigest()

print("Server hash:", server_hash)
print("Local hash:", local_hash)
print("Integrity verified:", server_hash == local_hash)

s.close()
```

---

# 21. IMPORTANT SOCKET CAVEAT

TCP is a **byte stream**.

This means:

```text
one send() != guaranteed one recv()
```

So using a literal marker like:

```python
b"END"
```

is acceptable for a simple classroom demonstration, but it is not a robust general network framing protocol.

For the exam, use it if the question is only demonstrating multipart hashing.

---

# 22. BETTER MULTIPART VERSION — LENGTH PREFIX

If you want a more correct reusable implementation, send the total length first.

## Server

```python
import socket, hashlib

host = input("Host (blank for all): ")
port = int(input("Port: "))
alg = input("Algorithm: ").lower()

s = socket.socket()
s.bind((host, port))
s.listen(1)

c, addr = s.accept()

size = int(c.recv(32).decode())
c.sendall(b"OK")

data = b""

while len(data) < size:
    data += c.recv(min(4096, size-len(data)))

h = hashlib.new(alg, data).hexdigest()

print("Reassembled:", data.decode())
print("Hash:", h)

c.sendall(h.encode())

c.close()
s.close()
```

## Client

```python
import socket, hashlib

host = input("Server host: ")
port = int(input("Port: "))
alg = input("Algorithm: ").lower()
msg = input("Message: ").encode()
part = int(input("Part size: "))

s = socket.socket()
s.connect((host, port))

s.sendall(str(len(msg)).encode())
s.recv(2)

for i in range(0, len(msg), part):
    s.sendall(msg[i:i+part])

server_hash = s.recv(1024).decode()
local_hash = hashlib.new(alg, msg).hexdigest()

print("Server hash:", server_hash)
print("Local hash:", local_hash)
print("Integrity verified:", server_hash == local_hash)

s.close()
```

---

# 23. HASH A CIPHERTEXT

Very useful if Lab 5 is combined with AES/DES in a scenario.

If ciphertext is already a `bytes` object:

```python
import hashlib

h = hashlib.sha256(ciphertext).hexdigest()

print("Ciphertext hash:", h)
```

If ciphertext is stored in a file:

```python
import hashlib

path = input("Encrypted file: ")

data = open(path, "rb").read()

print("SHA-256:", hashlib.sha256(data).hexdigest())
```

---

# 24. VERIFY BEFORE DECRYPTING

For combined questions:

```text
Sender:
plaintext
   ↓
encrypt
   ↓
ciphertext
   ↓
hash(ciphertext)
```

Receiver:

```text
received ciphertext
      ↓
hash(received ciphertext)
      ↓
compare with sender hash
      ↓
MATCH? ── yes ──> decrypt
   │
   no
   ↓
Integrity failed
DO NOT decrypt
```

Code skeleton:

```python
import hashlib

received = input("Received ciphertext hex: ")
sender_hash = input("Sender hash: ")

ct = bytes.fromhex(received)
receiver_hash = hashlib.sha256(ct).hexdigest()

if receiver_hash == sender_hash:
    print("Integrity verified")
    # decrypt here
else:
    print("Integrity failed")
```

---

# 25. MODIFY ONE CHARACTER / BYTE TO SHOW TAMPERING

For text:

```python
msg = input("Message: ")

if not msg:
    raise ValueError("Message cannot be empty")

tampered = msg[:-1] + chr(ord(msg[-1]) ^ 1)

print("Original:", msg)
print("Tampered:", tampered)
```

For ciphertext bytes:

```python
ct = bytearray(bytes.fromhex(input("Ciphertext hex: ")))

if not ct:
    raise ValueError("Ciphertext cannot be empty")

ct[0] ^= 1

tampered = bytes(ct)

print("Tampered ciphertext:", tampered.hex())
```

Then hash both:

```python
import hashlib

print("Original hash:", hashlib.sha256(original).hexdigest())
print("Tampered hash:", hashlib.sha256(tampered).hexdigest())
```

---

# 26. SIMPLE SENDER / RECEIVER INTEGRITY WITHOUT SOCKETS

Useful if the exam asks only to demonstrate integrity.

```python
import hashlib

msg = input("Message: ").encode()

sender_hash = hashlib.sha256(msg).hexdigest()

received = input("Received message: ").encode()
receiver_hash = hashlib.sha256(received).hexdigest()

print("Sender hash:", sender_hash)
print("Receiver hash:", receiver_hash)

if sender_hash == receiver_hash:
    print("Integrity verified")
else:
    print("Integrity failed")
```

---

# 27. IMPORTANT: HASHING IS NOT ENCRYPTION

Remember:

```text
Encryption
----------
plaintext -> ciphertext
reversible using key

Hashing
-------
message -> digest
intended to be one-way
no decryption
```

So never write:

```text
"decrypt the hash"
```

That is conceptually wrong.

---

# 28. DIGEST LENGTHS

Useful for viva:

```text
MD5     = 128 bits = 16 bytes = 32 hex digits
SHA-1   = 160 bits = 20 bytes = 40 hex digits
SHA-256 = 256 bits = 32 bytes = 64 hex digits
```

Reason:

```text
1 hex digit = 4 bits
```

---

# 29. COLLISION TERMINOLOGY

A collision means:

```text
M1 != M2
```

but:

```text
H(M1) = H(M2)
```

The manual asks you to check for collisions in the generated dataset.

For a small random dataset, seeing zero collisions is expected.

---

# 30. PREIMAGE / COLLISION QUICK DEFINITIONS

```text
Preimage resistance:
Given h, difficult to find M such that H(M)=h

Second-preimage resistance:
Given M1, difficult to find different M2 with same hash

Collision resistance:
Difficult to find any M1 != M2 such that H(M1)=H(M2)
```

The manual explicitly emphasizes the one-way and collision-resistant nature of cryptographic hash functions.

---

# 31. EXAM ROUTING TABLE

| Question wording | Use |
|---|---|
| Implement custom hash starting at 5381 | Section 1 |
| Show hash in hex | Section 2 |
| Show tampering with custom hash | Section 3 |
| MD5/SHA-1/SHA-256 of message | Sections 4–7 |
| Hash a file | Section 8 |
| Compare two files | Section 9 |
| Client/server hash integrity | Sections 10–11 |
| Demonstrate tampering over socket | Sections 10 + 12 |
| Compare MD5/SHA-1/SHA-256 performance | Section 14 |
| Explicitly find collisions | Section 16 |
| Need more measurable timings | Section 17 |
| Plot timings | Section 18 |
| Multipart socket hashing | Sections 19–20 |
| More correct multipart TCP framing | Section 22 |
| Hash AES/DES ciphertext | Section 23 |
| Verify integrity before decrypting | Section 24 |
| Modify ciphertext to force integrity failure | Section 25 |
| Simple sender/receiver integrity | Section 26 |

---

# 32. COMMON ERRORS

## Error 1 — using Python's built-in `hash()`

Do not use:

```python
hash(msg)
```

for this lab's cryptographic hashing tasks.

Use:

```python
hashlib
```

or the manual's specified user-defined hash.

---

## Error 2 — forgetting `.encode()`

Wrong:

```python
hashlib.sha256(msg)
```

if `msg` is a Python string.

Correct:

```python
hashlib.sha256(msg.encode())
```

---

## Error 3 — hashing hex text instead of ciphertext bytes

Suppose:

```python
ct.hex()
```

returns a string.

These are different:

```python
hashlib.sha256(ct).hexdigest()
```

and:

```python
hashlib.sha256(ct.hex().encode()).hexdigest()
```

For cryptographic integrity of ciphertext, normally hash the actual:

```python
ct
```

bytes.

---

## Error 4 — decrypting before integrity verification

If the question says:

```text
verify integrity first
if valid -> decrypt
otherwise -> error
```

then structure the code exactly that way.

---

## Error 5 — expecting a visible collision in 50–100 random messages

For normal random inputs, do not expect MD5/SHA-1/SHA-256 collisions in such a tiny dataset.

The experiment demonstrates:

```text
timing + collision-checking logic
```

not that collisions must occur.

---

## Error 6 — interpreting "no collisions observed" as "collision impossible"

Wrong conclusion.

Use:

```text
No collisions were observed in this dataset.
```

---

# 33. LAB 5 MASTER COMMENT

Paste this at the top of your Lab 5 notes:

```python
# LAB 5 HASHING QUICK REFERENCE
#
# Custom hash:
#   h = 5381
#   for c in msg:
#       h = ((h << 5) + h + ord(c)) & 0xffffffff
#
# hashlib:
#   hashlib.md5(data).hexdigest()
#   hashlib.sha1(data).hexdigest()
#   hashlib.sha256(data).hexdigest()
#
# Strings must be encoded:
#   data = input("Message: ").encode()
#
# Integrity:
#   sender_hash = H(original)
#   receiver_hash = H(received)
#
#   if sender_hash == receiver_hash:
#       integrity verified
#   else:
#       integrity failed
#
# For encrypted data:
#   HASH THE CIPHERTEXT BYTES, not plaintext, if the question says
#   "hash the encrypted message".
#
# Verify hash BEFORE decrypting when the question requires it.
#
# Tamper demo:
#   ct = bytearray(ct)
#   ct[0] ^= 1
#   ct = bytes(ct)
#
# Collision:
#   M1 != M2 but H(M1) == H(M2)
#
# Digest sizes:
#   MD5     = 128 bits = 32 hex digits
#   SHA-1   = 160 bits = 40 hex digits
#   SHA-256 = 256 bits = 64 hex digits
#
# Hashing != encryption:
#   hash is one-way; there is no "hash decryption".
```

---

# 34. MINIMUM CODE TO REMEMBER FOR TOMORROW

If you forget everything else:

```python
import hashlib

msg = input("Message: ").encode()
h = hashlib.sha256(msg).hexdigest()

print("Hash:", h)
```

Integrity:

```python
if h1 == h2:
    print("Integrity verified")
else:
    print("Integrity failed")
```

Custom lab hash:

```python
def my_hash(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xffffffff
    return h
```

---

# END — LAB 5
