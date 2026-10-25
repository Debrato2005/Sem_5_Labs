# Lab 6 — Digital signatures (RSA, ElGamal, Schnorr, DSA/ECDSA), DH, client/server, CIA

Toolkit: `toolkit/signatures.py` (`rsa_sign/rsa_verify` any hash incl. MD5, PKCS#1 v1.5 or PSS;
`rsa_textbook_*`; `elgamal_sign/verify` and `*_hash` variants; `schnorr_*`; `dss_sign/verify`
for DSA/ECDSA; `TimestampAuthority` + `verify_timestamp`).

**Rule.** Sender's **private** key signs; anyone verifies with the sender's **public** key.
Signature = integrity + authenticity + non-repudiation. Hash-then-sign: sign `H(m)`.
"Compute MD5 of the record and sign the hash" = `pkcs1_15.new(priv).sign(MD5.new(record))`
(the library signs the hash object; do **not** hash twice by passing a hex digest as data).
If verification must happen before decryption, sign the **ciphertext** (or the stored record).

## 0. Formulas

| Scheme | Sign | Verify |
|---|---|---|
| RSA (textbook) | s = H(m)ᵈ mod n | sᵉ mod n == H(m) |
| ElGamal (p, g, y=gˣ) | k with gcd(k,p−1)=1: r=gᵏ mod p, s=k⁻¹(H(m)−x·r) mod (p−1) | gᴴ⁽ᵐ⁾ ≡ yʳ·rˢ (mod p), 0<r<p |
| Schnorr (p, q, g of order q) | r=gᵏ, e=H(r‖m) mod q, s=(k + x·e) mod q | r'=gˢ·y⁻ᵉ; valid iff H(r'‖m) mod q == e |
| DSA / ECDSA | library `DSS.new(key,'fips-186-3')` | same |

Never reuse k (ElGamal/Schnorr/DSA): two signatures with the same k reveal the private key.

## 1. Manual exercise: verify Alice's / Bob's signature with the Table 1 key, then sign your name

The manual's website uses **raw textbook RSA on the text** (no hash, no padding):
`sᵉ mod n` gives back the signer's name. This reproduces the exercise offline.

<!-- stdin: 0xc8 0x93 0xa9 0x0d 0x8f 0x4e 0xc5 0xc3 0x64 0xec 0x86 0x9d 0x2b 0x2e 0xc9 0x21 0xe3 0x8b 0xab 0x23 0x4a 0x4f 0x45 0xe8 0x96 0x9b 0x98 0xbe 0x25 0x41 0x15 0x9e 0xab 0x6a 0xfb 0x75 0x9a 0x13 0xb6 0x26 0x04 0xc0 0x60 0x72 0x28 0x1a 0x73 0x45 0x71 0x83 0x42 0xd4 0x7f 0x57 0xd1 0xac 0x91 0x8c 0xae 0x2f 0x3b 0xd2 0x99 0x30 0x3e 0xe8 0xa8 0x3a 0xb3 0x5d 0xfb 0x4a 0xc9 0x18 0x19 0xfd 0x3f 0x0c 0x0a 0x1f 0x3d 0xa4 0xa4 0xfe 0x02 0x9d 0x96 0x2f 0x50 0x34 0xd3 0x95 0x55 0xe0 0xb7 0x2a 0x46 0xa4 0x9e 0xae 0x80 0xc9 0x77 0x43 0x16 0xc0 0xab 0xfd 0xdc 0x88 0x95 0x05 0x56 0xdf 0xc4 0xfc 0x13 0xa6 0x48 0xa3 0x3c 0xe2 0x87 0x52 0xc5 0x3f 0x0c 0x0d | Debrato Ghosh -->
```python
N = int('d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a68a30c428b39e3362fb3779a4'
        '97eceaea37100f264d7fb9fb1a97fbf621133de55fdcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d4'
        '5cbf843e8474babc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549', 16)   # Table 1 public
D = int('47b9cfde843176b88741d68cf096952e950813151058ce46f2b048791a26e507a1095793c12bae1e09d82213ad93'
        '26928cf7c2350acb19c98f19d32d577d666cd7bb8b2b5ba629d25ccf72a5ceb8a8da038906c84dcdb1fe677dffb2c0'
        '29fd8926318eede1b58272af22bda5c5232be066839398e42f5352df58848adad11a1', 16)     # Table 1 private
E = 0x10001

sig = bytes(int(t, 16) for t in input('Signature bytes (0x.. 0x..): ').split())
m = pow(int.from_bytes(sig, 'big'), E, N)                       # verify: s^e mod n
print('Signer identified:', m.to_bytes(128, 'big').lstrip(b'\0').decode())

name = input('Your name to sign: ').encode()
s = pow(int.from_bytes(name, 'big'), D, N)                      # sign: m^d mod n
print('Your signature:', ' '.join(f'0x{b:02x}' for b in s.to_bytes(128, 'big')))
print('Partner verifies ->', pow(s, E, N).to_bytes(128, 'big').lstrip(b'\0').decode())
```

## 2. RSA signature done properly (hash + PKCS#1 v1.5 or PSS), keys saved as PEM

<!-- stdin: Contract: pay 500 to Bob | sha256 | pss -->
```python
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss

H = {'md5': MD5, 'sha1': SHA1, 'sha256': SHA256, 'sha512': SHA512}
msg = input('Document: ').encode()
alg = input('Hash (md5/sha1/sha256/sha512): ').strip().lower()
scheme = input('Scheme (pkcs1/pss): ').strip().lower()
Scheme = pss if scheme == 'pss' else pkcs1_15

key = RSA.generate(2048)
open('signer_private.pem', 'wb').write(key.export_key())
open('signer_public.pem', 'wb').write(key.publickey().export_key())

h = H[alg].new(msg)
print('Hash      :', h.hexdigest())
sig = Scheme.new(key).sign(h)                                   # PRIVATE key signs
print('Signature :', sig.hex()[:64], '...')

pub = RSA.import_key(open('signer_public.pem', 'rb').read())
for label, data in (('original', msg), ('tampered', msg + b'0')):
    try:
        Scheme.new(pub).verify(H[alg].new(data), sig)           # PUBLIC key verifies
        print(label, '-> signature VALID')
    except (ValueError, TypeError):
        print(label, '-> signature INVALID')
```

## 3. ElGamal signature (manual Q1) — any p, g or the standard 2048-bit group

<!-- stdin: n | Pay 100 to Alice -->
```python
import hashlib, secrets
from math import gcd

G14 = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
          '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
          '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
          'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
          '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
          '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
          'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
          '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
if input('Enter own p, g, x? (y/n): ').strip().lower() == 'y':
    p, g, x = int(input('p: ')), int(input('g: ')), int(input('x: '))
else:
    p, g = G14, 2
    x = secrets.randbelow(p - 3) + 2
y = pow(g, x, p)                                               # public key (p, g, y)
H = lambda m: int.from_bytes(hashlib.sha256(m).digest(), 'big') % (p - 1)

msg = input('Message: ').encode()
while True:                                                    # sign
    k = secrets.randbelow(p - 3) + 2
    if gcd(k, p - 1) == 1:
        r = pow(g, k, p)
        s = (H(msg) - x * r) * pow(k, -1, p - 1) % (p - 1)
        if s: break
print('Signature r =', hex(r)[:24], '... s =', hex(s)[:24], '...')

def verify(m, r, s):
    return 0 < r < p and 0 < s < p - 1 and pow(g, H(m), p) == pow(y, r, p) * pow(r, s, p) % p
print('verify original:', verify(msg, r, s), '| tampered:', verify(msg + b'!', r, s))
```

## 4. Schnorr signature (manual Q1)

<!-- stdin: Login challenge 8812 -->
```python
import hashlib, secrets

p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
q, g = (p - 1) // 2, 2                       # safe prime: g = 2 has prime order q
x = secrets.randbelow(q - 1) + 1             # private
y = pow(g, x, p)                             # public
H = lambda r, m: int.from_bytes(hashlib.sha256(str(r).encode() + m).digest(), 'big') % q

msg = input('Message: ').encode()
k = secrets.randbelow(q - 1) + 1
r = pow(g, k, p)
e = H(r, msg)
s = (k + x * e) % q
print('Signature (e, s):', hex(e)[:20], '...', hex(s)[:20], '...')

def verify(m, e, s):
    r2 = pow(g, s, p) * pow(y, -e, p) % p    # g^s * y^-e = g^k
    return H(r2, m) == e
print('valid:', verify(msg, e, s), '| tampered:', verify(msg + b'x', e, s))
```

## 5. DSA and ECDSA (library)

<!-- stdin: Firmware v2.1 -->
```python
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA, ECC
from Crypto.Signature import DSS

msg = input('Message: ').encode()
for key in (DSA.generate(2048), ECC.generate(curve='P-256')):
    sig = DSS.new(key, 'fips-186-3').sign(SHA256.new(msg))
    try:
        DSS.new(key.public_key(), 'fips-186-3').verify(SHA256.new(msg), sig)
        print(type(key).__name__, 'signature valid, length', len(sig))
    except ValueError:
        print('invalid')
```

## 6. Diffie–Hellman "verify the above steps" (manual Q2)

DH is **key agreement, not a signature**. To "verify" with DH: both sides derive the same key
and authenticate a message with an HMAC under it (only the two parties can produce it — but
either of them could, so there is no non-repudiation).

<!-- stdin: I agree to the terms -->
```python
import hashlib, hmac, secrets
p = 2 ** 255 - 19                    # demo prime (use RFC 3526 group for real)
g = 2
a, b = secrets.randbelow(p - 3) + 2, secrets.randbelow(p - 3) + 2
A, B = pow(g, a, p), pow(g, b, p)
ka = hashlib.sha256(str(pow(B, a, p)).encode()).digest()
kb = hashlib.sha256(str(pow(A, b, p)).encode()).digest()
msg = input('Alice message: ').encode()
tag = hmac.new(ka, msg, hashlib.sha256).hexdigest()
print('Keys equal:', ka == kb, '| tag:', tag)
print('Bob verifies:', hmac.compare_digest(tag, hmac.new(kb, msg, hashlib.sha256).hexdigest()))
print('Tampered    :', hmac.compare_digest(tag, hmac.new(kb, msg + b'!', hashlib.sha256).hexdigest()))
```

## 7. Client/server signatures (manual Q3)

<!-- server: lab6 | {PORT} -->
```python
# sign_server.py : receives (message, signature, signer public key PEM) and verifies
import json, socket, struct
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def recv_msg(c):
    head = c.recv(4, socket.MSG_WAITALL)
    if len(head) < 4: raise ConnectionError
    return json.loads(c.recv(struct.unpack('>I', head)[0], socket.MSG_WAITALL))

trusted = {}                                         # name -> public key (registered once)
port = int(input('Port: '))
with socket.socket() as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port)); srv.listen()
    print('[server] listening')
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                while True:
                    req = recv_msg(conn)
                    if req['type'] == 'register':
                        trusted.setdefault(req['name'], req['pem'])
                        reply = 'registered'
                    else:
                        try:
                            pkcs1_15.new(RSA.import_key(trusted[req['name']])).verify(
                                SHA256.new(req['msg'].encode()), bytes.fromhex(req['sig']))
                            reply = f'VALID signature from {req["name"]}'
                        except (ValueError, KeyError):
                            reply = 'INVALID signature - rejected'
                    data = reply.encode()
                    conn.sendall(struct.pack('>I', len(data)) + data)
            except ConnectionError:
                pass
```

<!-- client: lab6 | {PORT} | alice | Order #991: 3 laptops -->
```python
# sign_client.py
import json, socket, struct
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def call(s, obj):
    data = json.dumps(obj).encode()
    s.sendall(struct.pack('>I', len(data)) + data)
    n = struct.unpack('>I', s.recv(4, socket.MSG_WAITALL))[0]
    return s.recv(n, socket.MSG_WAITALL).decode()

port, name = int(input('Server port: ')), input('Your name: ')
key = RSA.generate(2048)
msg = input('Message: ')
sig = pkcs1_15.new(key).sign(SHA256.new(msg.encode())).hex()
with socket.create_connection(('127.0.0.1', port)) as s:
    print(call(s, {'type': 'register', 'name': name, 'pem': key.publickey().export_key().decode()}))
    print('genuine :', call(s, {'type': 'msg', 'name': name, 'msg': msg, 'sig': sig}))
    print('tampered:', call(s, {'type': 'msg', 'name': name, 'msg': msg + ' + 1 more', 'sig': sig}))
```

Observation: this server trusts the first key registered for a name (trust on first use).
Registration happens over this unauthenticated connection. It does not establish real identity
and permits a first registrant to claim someone else's name. A repeated run with a fresh
key and the same name fails until the server restarts. A real system needs an independently
authenticated key directory or certificates and protected transport.

## 8. CIA triad with RSA encryption + RSA signature + SHA (additional exercise)

<!-- stdin: Patient 42: diagnosis flu -->
```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

sender, receiver = RSA.generate(2048), RSA.generate(2048)
msg = input('Message: ').encode()
# Confidentiality: AES data key, wrapped with RECEIVER public key
k = get_random_bytes(32); c = AES.new(k, AES.MODE_GCM, nonce=get_random_bytes(12))
ct, tag = c.encrypt_and_digest(msg)
wrapped = PKCS1_OAEP.new(receiver.publickey()).encrypt(k)
# Integrity + authenticity: SHA-256 of the ciphertext, signed by SENDER private key
digest = SHA256.new(c.nonce + ct + tag)
sig = pkcs1_15.new(sender).sign(digest)
print('SHA-256(ct):', digest.hexdigest())
# Receiver: verify FIRST, then decrypt
try:
    pkcs1_15.new(sender.publickey()).verify(SHA256.new(c.nonce + ct + tag), sig)
    key = PKCS1_OAEP.new(receiver).decrypt(wrapped)
    print('verified; plaintext:', AES.new(key, AES.MODE_GCM, nonce=c.nonce).decrypt_and_verify(ct, tag).decode())
except ValueError:
    print('verification failed - not decrypted')
# Availability: keep the service reachable (redundant copies/backups, rate limiting) - not crypto.
```

## 9. Trusted timestamp (signed time bound to a hash)

<!-- stdin: ballot-hash-abc -->
```python
from datetime import datetime, timedelta, timezone
from toolkit.asymmetric import rsa_generate
from toolkit.hashing import digest
from toolkit.signatures import TimestampAuthority, verify_timestamp

tsa_key = rsa_generate(2048)                       # the authority's key
h = digest(input('Data to timestamp: '), 'sha512')
token = TimestampAuthority(tsa_key).stamp(h)
print(token)
now = datetime.now(timezone.utc)
print(verify_timestamp(token, tsa_key.publickey(), h, now - timedelta(hours=1), now + timedelta(hours=1)))
print(verify_timestamp(dict(token, time='2000-01-01T00:00:00+00:00'), tsa_key.publickey()))
```

## 10. Exam checklist (Lab 6)
* Name whose key signs (private) and verifies (public); print hash, signature, verify result.
* Always show a tampered message / wrong key → INVALID.
* Verify with a public key you obtained independently (stored/registered), not one shipped with the message.
* If the hash itself must be signed (MD5/SHA-512 mentioned), use that hash in the signer.
