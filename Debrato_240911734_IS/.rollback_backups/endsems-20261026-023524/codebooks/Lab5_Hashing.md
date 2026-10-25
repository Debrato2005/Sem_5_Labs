# Lab 5 — Hashing, integrity over sockets, performance and collisions

Toolkit: `toolkit/hashing.py` (`custom_hash`, `digest`, `file_digest`, `verify_digest`,
`hmac_hex/hmac_ok`, `random_strings`, `hash_benchmark`, `find_collisions`, `truncated`) and
`toolkit/net.py` (length-prefixed JSON sockets). Templates: `templates/net_server.py` /
`net_client.py` already include "server hashes data, client compares".

**Facts.** MD5 128 bit = 32 hex, SHA-1 160 = 40 hex, SHA-256 256 = 64 hex, SHA-512 512 = 128 hex.
Hash = one-way, fixed size, avalanche; **not** encryption (no "decrypt a hash"). MD5/SHA-1
have practical collisions — use only when asked. Python's built-in `hash()` is randomised per run:
never use it for integrity. Hash **bytes**: `text.encode()`. Hash the ciphertext if the question
says "hash the encrypted message"; verify the hash **before** decrypting.

## 1. User-defined hash (manual Q1): start 5381, ×33 + ASCII, 32-bit mask

<!-- stdin: hello world -->
```python
def my_hash(s):
    h = 5381                                   # initial value
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF    # (h<<5)+h == h*33 ; mask to 32 bits
    return h

def my_hash_mixed(s):                          # extra bit mixing (XOR + final avalanche)
    h = 5381
    for c in s:
        h = (((h << 5) + h) ^ ord(c)) & 0xFFFFFFFF
    h ^= h >> 16; h = (h * 0x45D9F3B) & 0xFFFFFFFF
    return h ^ (h >> 16)

msg = input('Message: ')
print(f'hash = {my_hash(msg)}  (hex {my_hash(msg):08x})   mixed = {my_hash_mixed(msg):08x}')
changed = msg[:-1] + chr(ord(msg[-1]) ^ 1) if msg else '\x01'
print(f'one-bit change "{changed}" -> {my_hash(changed):08x}   mixed {my_hash_mixed(changed):08x}')
```

## 2. Any standard hash of text or a file; integrity comparison

<!-- stdin: sha256 | The quick brown fox -->
```python
import hashlib

alg = input('Algorithm (md5/sha1/sha256/sha512/sha3_256): ').strip().lower()
data = input('Message: ').encode()
h = hashlib.new(alg, data).hexdigest()
print(f'{alg}: {h}  ({len(h) * 4} bits)')

open('doc.txt', 'wb').write(data)                       # file hashing in chunks
f = hashlib.new(alg)
with open('doc.txt', 'rb') as fh:
    for chunk in iter(lambda: fh.read(65536), b''):
        f.update(chunk)
print('file hash equal:', f.hexdigest() == h)

received = data.replace(b'quick', b'quack')             # simulate tampering
print('received hash  :', hashlib.new(alg, received).hexdigest())
print('integrity      :', 'OK' if hashlib.new(alg, received).hexdigest() == h else 'FAILED - data modified')
```

## 3. Socket integrity check (manual Q2): server hashes received data and sends it back

Run the server first (terminal 1), then the client (terminal 2). Messages are length-prefixed
so large data and multiple messages are received completely (plain `recv(1024)` can split them).

<!-- server: lab5q2 | {PORT} -->
```python
# hash_server.py
import hashlib, socket, struct

def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        part = conn.recv(n - len(buf))
        if not part: raise ConnectionError('closed')
        buf += part
    return buf

port = int(input('Port: '))
with socket.socket() as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port)); srv.listen()
    print('[server] listening on', port)
    while True:
        conn, addr = srv.accept()
        with conn:
            try:
                while True:
                    (n,) = struct.unpack('>I', recv_exact(conn, 4))
                    data = recv_exact(conn, n)
                    digest = hashlib.sha256(data).hexdigest()
                    print(f'[server] {n} bytes from {addr} -> {digest}')
                    conn.sendall(digest.encode())
            except ConnectionError:
                pass                                 # client finished
```

<!-- client: lab5q2 | {PORT} | Transfer this message safely | y -->
```python
# hash_client.py
import hashlib, socket, struct

def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part: raise ConnectionError('closed before the hash arrived')
        data += part
    return data

port = int(input('Server port: '))
msg = input('Message: ').encode()
corrupt = input('Simulate corruption in transit? (y/n): ').strip().lower() == 'y'
local = hashlib.sha256(msg).hexdigest()
with socket.create_connection(('127.0.0.1', port)) as s:
    for label, payload in (('original', msg), ('tampered', bytes([msg[0] ^ 1]) + msg[1:] if msg else b'\x01')):
        if label == 'tampered' and not corrupt:
            break
        s.sendall(struct.pack('>I', len(payload)) + payload)
        remote = recv_exact(s, 64).decode()
        print(f'[{label}] local  {local}\n[{label}] server {remote}')
        print(f'[{label}] ->', 'INTEGRITY VERIFIED' if remote == local else 'MISMATCH: data corrupted/tampered')
```

## 4. Multipart message (additional exercise): client sends parts, server reassembles

<!-- server: lab5multi | {PORT} -->
```python
# multipart_server.py  - protocol: 4-byte part count, then each part length-prefixed
import hashlib, socket, struct

def recv_exact(c, n):
    b = b''
    while len(b) < n:
        p = c.recv(n - len(b))
        if not p: raise ConnectionError
        b += p
    return b

port = int(input('Port: '))
with socket.socket() as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port)); srv.listen()
    print('[server] listening')
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                (count,) = struct.unpack('>I', recv_exact(conn, 4))
                parts = [recv_exact(conn, struct.unpack('>I', recv_exact(conn, 4))[0]) for _ in range(count)]
            except (ConnectionError, struct.error):
                continue
            whole = b''.join(parts)
            print(f'[server] reassembled {count} parts: {whole!r}')
            conn.sendall(hashlib.sha256(whole).hexdigest().encode())
```

<!-- client: lab5multi | {PORT} | This message travels in several separate parts | 5 -->
```python
# multipart_client.py
import hashlib, socket, struct

def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part: raise ConnectionError('closed before the hash arrived')
        data += part
    return data

port = int(input('Server port: '))
msg = input('Message: ').encode()
k = int(input('Number of parts: '))
if k < 1: raise ValueError('Number of parts must be positive')
parts = [msg[len(msg) * i // k:len(msg) * (i + 1) // k] for i in range(k)]
with socket.create_connection(('127.0.0.1', port)) as s:
    s.sendall(struct.pack('>I', len(parts)))
    for p in parts:
        s.sendall(struct.pack('>I', len(p)) + p)
        print('sent part:', p)
    remote = recv_exact(s, 64).decode()
local = hashlib.sha256(msg).hexdigest()
print('server hash:', remote, '\nlocal hash :', local)
print('INTEGRITY VERIFIED' if remote == local else 'MISMATCH')
```

## 5. Performance of MD5 / SHA-1 / SHA-256 + collision detection (manual Q3)

<!-- stdin: 100 | 1000 -->
```python
import hashlib, random, string, time

n = int(input('Number of random strings (50-100): '))
reps = int(input('Timing repetitions: '))
data = [''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 64)))
        for _ in range(n)]
data += [data[0]]                       # a duplicate INPUT is not a collision - handled below
for alg in ('md5', 'sha1', 'sha256'):
    t = time.perf_counter()
    for _ in range(reps):
        digests = [hashlib.new(alg, s.encode()).hexdigest() for s in data]
    avg = (time.perf_counter() - t) / reps
    seen, collisions = {}, []
    for s, h in zip(data, digests):
        if h in seen and seen[h] != s:  # same digest, DIFFERENT input = collision
            collisions.append((seen[h], s))
        seen.setdefault(h, s)
    print(f'{alg:6}: {avg * 1e6:9.1f} us per dataset, {len(collisions)} collisions')

# Demonstrate that collisions DO appear when the output is tiny (birthday bound ~ 2^(bits/2))
for bits in (8, 16, 32):
    seen, hits = {}, 0
    for s in set(data):
        h = int(hashlib.sha256(s.encode()).hexdigest(), 16) >> (256 - bits)
        hits += h in seen; seen[h] = s
    print(f'SHA-256 truncated to {bits:2} bits: {hits} collisions among {len(set(data))} strings')
```

Write-up: report the speed order measured on this machine. CPU acceleration and the
hash implementation can change the order. No collisions in
100 strings is expected for all three (birthday bound 2⁶⁴, 2⁸⁰, 2¹²⁸) — this does **not**
prove collision resistance; MD5 and SHA-1 collisions are known to be constructible.

## 6. Keyed integrity (HMAC) and "hash the ciphertext, verify before decrypting"

<!-- stdin: Wire 5000 to account 42 -->
```python
import hashlib, hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

enc_key, mac_key = get_random_bytes(32), get_random_bytes(32)      # separate keys
msg = input('Message: ').encode()
c = AES.new(enc_key, AES.MODE_CBC)
ct = c.iv + c.encrypt(pad(msg, 16))
tag = hmac.new(mac_key, ct, hashlib.sha256).hexdigest()           # MAC over ciphertext
sha = hashlib.sha256(ct).hexdigest()                              # plain hash (no key)
print('ciphertext:', ct.hex()); print('HMAC:', tag); print('SHA-256(ct):', sha)

for label, received in (('genuine', ct), ('tampered', ct[:20] + bytes([ct[20] ^ 1]) + ct[21:])):
    ok = hmac.compare_digest(hmac.new(mac_key, received, hashlib.sha256).hexdigest(), tag)
    if ok:                                                        # verify FIRST
        print(label, '-> verified, plaintext:', unpad(AES.new(enc_key, AES.MODE_CBC, received[:16]).decrypt(received[16:]), 16).decode())
    else:
        print(label, '-> INTEGRITY FAILED, decryption not performed')
```

Plain hash vs HMAC: an attacker who changes the data can also recompute a plain hash; an
HMAC (or a signature, Lab 6) needs a secret key. A stored hash is only trustworthy if the hash
itself is protected (signed, HMACed, or kept separately).

## 7. Exam checklist (Lab 5)
* Hash bytes, print hex digests and their bit length; state which object was hashed.
* Show a tampered case failing (flip one byte) and the untampered case passing.
* Socket questions: two separate scripts, server started first, length-prefixed messages.
* Collision experiment: distinguish duplicate inputs from real collisions; explain the birthday bound.
