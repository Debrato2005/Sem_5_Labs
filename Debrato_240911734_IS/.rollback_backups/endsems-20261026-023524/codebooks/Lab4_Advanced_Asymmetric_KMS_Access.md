# Lab 4 — Rabin, key management, access control, weak-RSA attack

Toolkit: `toolkit/asymmetric.py` (Rabin, RSA, DH, `break_weak_rsa`), `toolkit/access.py`
(`KeyManager` + RBAC/ABAC/BLP/MAC/DAC/time/probabilistic + formulas), `toolkit/net.py` (API).

## 0. Formulas from the manual

* **Rabin**: p ≡ q ≡ 3 (mod 4), n = pq; `c = m² mod n`; `mp = c^((p+1)/4) mod p`,
  `mq = c^((q+1)/4) mod q`; with `yp·p + yq·q = 1`:
  `r1 = (yp·p·mq + yq·q·mp) mod n`, `r2 = n − r1`, `r3 = (yp·p·mq − yq·q·mp) mod n`, `r4 = n − r3`.
  One of the four roots is m → add **redundancy** to pick it.
* **Entropy** `H(K) = −Σ pᵢ log₂ pᵢ` (uniform 2ᵏ keys → k bits). **KDF** `DK = KDF(key, salt, iterations)`.
  **Rotation rate** = N / T. **Expiry** = t₀ + L. **DH** `K = Aᵇ = Bᵃ = gᵃᵇ mod p`.
* **RBAC** `Access = ∃role: HasRole(u,role) ∧ CanAccess(role,obj)`; **ABAC** `f(user, object, env)`;
  **Bell–LaPadula** read iff `S ≥ C` (no read up), write iff `S ≤ C` (no write down);
  **MAC** clearance ≥ classification ∧ rule; **DAC** access matrix; **time** `start ≤ t ≤ end`;
  **probabilistic** `P = f(trust, sensitivity, risk)`.

## 1. Rabin cryptosystem (configurable key size, redundancy, all four roots)

<!-- stdin: Patient record 17 | 1024 -->
```python
import hashlib
from Crypto.Util.number import getPrime

def prime_3mod4(bits):
    while True:
        p = getPrime(bits)
        if p % 4 == 3: return p

msg = input('Message: ').encode()
bits = int(input('Key size n in bits (e.g. 1024): '))
p, q = prime_3mod4(bits // 2), prime_3mod4(bits // 2)
n = p * q
print('public n =', hex(n)[:40], '...  private (p, q)')

tagged = b'\x01' + msg + hashlib.sha256(msg).digest()[:4]        # redundancy
m = int.from_bytes(tagged, 'big')
if m >= n: raise ValueError('message too long for n')
c = pow(m, 2, n)                                                 # encrypt
print('ciphertext =', hex(c)[:40], '...')

mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
yp, yq = pow(p, -1, q), pow(q, -1, p)
r1 = (yp * p * mq + yq * q * mp) % n
r3 = (yp * p * mq - yq * q * mp) % n
for r in (r1, n - r1, r3, n - r3):
    b = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    ok = b[:1] == b'\x01' and hashlib.sha256(b[1:-4]).digest()[:4] == b[-4:]
    print('root', hex(r)[:20], '...', '<- message: ' + b[1:-4].decode() if ok else '')
```

Rabin vs RSA trade-offs: Rabin is provably as hard as factoring and encryption is one
squaring (faster than RSA); decryption yields 4 roots (needs redundancy) and textbook Rabin
falls to a chosen-ciphertext attack that factors n. RSA has a unique decryption, mature
padding (OAEP/PSS) and a signature scheme, so it is the industry default.

## 2. Centralised Key Management Service — menu (HealthCare Rabin KMS / SecureCorp / DRM)

Generate · distribute · revoke · renew · encrypt private keys with AES-GCM under a
PBKDF2 master key · audit log. Works for RSA, Rabin and ElGamal.

This menu simulates owner checks: `Requested by` is a supplied string, not an authenticated
identity. Anyone who unlocks this local KMS can claim an owner name. `renew_due` checks
expiry only when called. It is not a background scheduler. The demo does not supply a
secure network API, transport encryption, or regulatory compliance.

<!-- stdin: kms.json | master | 1 | HospitalA | RABIN | 1024 | 365 | 1 | ClinicB | RSA | 2048 | 365 | 2 | HospitalA | 3 | ClinicB | ClinicB | 3 | ClinicB | HospitalA | 4 | HospitalA | compromised | 2 | HospitalA | 5 | HospitalA | 6 | 0 | 7 | 8 | 0 -->
```python
from toolkit.access import KeyManager
from toolkit.util import ask, ask_int, menu

kms = KeyManager(ask('Key store file: '), ask('KMS master passphrase: '))

def gen():
    e = ask('Hospital/clinic/system name: ')
    k = kms.generate(e, ask('Algorithm (RSA/RABIN/ELGAMAL): '), ask_int('Key bits: ', 512),
                     ask_int('Lifetime in days: ', 1))
    print(f'{e}: {k["alg"]}-{k["bits"]} v{k["version"]} expires {k["expires"]}')

menu('KEY MANAGEMENT SERVICE', [
    ('Generate key pair', gen),
    ('Distribute public key', lambda: print(kms.get_public(ask('Entity: '))[:120])),
    ('Distribute private key (owner only)', lambda: print(kms.get_private(ask('Entity: '), ask('Requested by: '))[:80], '...')),
    ('Revoke key', lambda: kms.revoke(ask('Entity: '), ask('Reason: '))),
    ('Renew key now', lambda: print('new version', kms.renew(ask('Entity: '))['version'])),
    ('Auto-renew keys expiring within N days', lambda: print('renewed:', kms.renew_due(ask_int('N: ', 0)))),
    ('Report', kms.report),
    ('Audit log', lambda: [print(r) for r in kms.db['log']])])
```

For the manual's secure API requirement, the local menu is only a starting point. Add
authenticated entity identities, authorization of each request, TLS, and key-distribution
routes. `toolkit/net.py` supplies transport helpers, not those controls. `templates/net_server.py`
handles records, not a complete hospital KMS API. State encryption at rest, audit logs,
rotation and revocation as implemented classroom controls. They do not prove HIPAA compliance.

## 3. SecureCorp: RSA + Diffie–Hellman secure channel between subsystems

DH gives a fresh shared AES key per session; RSA signatures authenticate the DH public
values (stops man-in-the-middle). New subsystems just register an RSA key (scalability).

<!-- stdin: Finance | HR | Quarterly report: revenue up 12% -->
```python
import hashlib, secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
        '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
        '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
        '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
        '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
        '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
G = 2
directory = {}                                    # KMS: subsystem -> RSA public key

class Subsystem:
    def __init__(self, name):
        self.name, self.rsa = name, RSA.generate(2048)
        directory[name] = self.rsa.publickey()   # register (scalable: add any number)
    def dh_offer(self):
        self.a = secrets.randbelow(P - 3) + 2
        A = pow(G, self.a, P)
        sig = pkcs1_15.new(self.rsa).sign(SHA256.new(str(A).encode()))
        return self.name, A, sig
    def dh_accept(self, offer):
        name, B, sig = offer
        pkcs1_15.new(directory[name]).verify(SHA256.new(str(B).encode()), sig)   # raises if forged
        return hashlib.sha256(str(pow(B, self.a, P)).encode()).digest()

s1, s2 = Subsystem(input('Sender subsystem: ')), Subsystem(input('Receiver subsystem: '))
o1, o2 = s1.dh_offer(), s2.dh_offer()
k1, k2 = s1.dh_accept(o2), s2.dh_accept(o1)
print('Authenticated DH keys match:', k1 == k2)
c = AES.new(k1, AES.MODE_GCM, nonce=get_random_bytes(12))
ct, tag = c.encrypt_and_digest(input('Document: ').encode())
print('Encrypted:', ct.hex())
print('Received :', AES.new(k2, AES.MODE_GCM, nonce=c.nonce).decrypt_and_verify(ct, tag).decode())
```

## 4. DigiRights: ElGamal DRM teaching example with limited-time grants

The service keeps the master key and checks a supplied customer label. This is a local
access-policy example, not customer authentication. It does not distribute the master
private key, implement creator ownership, persist licenses, expose an upload API, or
automatically rotate keys. Sharing the master key would also prevent effective later
revocation of copies already decrypted. Those manual requirements need additional code.

<!-- stdin: Ebook chapter 1 text | alice | 2 | bob -->
```python
import secrets
from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

P = 2 ** 127 - 1                       # demo prime; use the 2048-bit RFC 3526 prime in practice
g = 3
x = secrets.randbelow(P - 3) + 2       # MASTER private key (kept by DRM service only)
y = pow(g, x, P)                       # master public key
grants = {}                            # customer -> expiry   (access control list)

def publish(content):                  # creator: AES content key, ElGamal-wrap the key
    k = secrets.randbelow(2 ** 120) + 1
    aes = AES.new(k.to_bytes(16, 'big'), AES.MODE_GCM, nonce=get_random_bytes(12))
    ct, tag = aes.encrypt_and_digest(content.encode())
    r = secrets.randbelow(P - 3) + 2
    return {'c1': pow(g, r, P), 'c2': k * pow(y, r, P) % P, 'nonce': aes.nonce, 'ct': ct, 'tag': tag}

def read(customer, item):              # service unwraps only for valid, unexpired grants
    exp = grants.get(customer)
    if exp is None or datetime.now(timezone.utc) > exp:
        raise PermissionError(f'{customer}: no valid licence')
    k = item['c2'] * pow(pow(item['c1'], x, P), -1, P) % P
    return AES.new(k.to_bytes(16, 'big'), AES.MODE_GCM, nonce=item['nonce']).decrypt_and_verify(item['ct'], item['tag']).decode()

item = publish(input('Content to protect: '))
cust = input('Customer: ')
grants[cust] = datetime.now(timezone.utc) + timedelta(hours=int(input('Licence hours: ')))
print(cust, 'reads:', read(cust, item))
grants.pop(cust)                                                 # revoke
try:
    read(cust, item)
except PermissionError as e:
    print('After revocation:', e)
try:
    read(input('Unlicensed customer: '), item)
except PermissionError as e:
    print(e)
```

Extension recipe for master-key revocation/renewal: generate a new (x, y), re-wrap every content key
(decrypt with old x, encrypt with new y), destroy old x, log it.

## 5. Attack on weak RSA (p, q close together or one small)

<!-- stdin: 256 -->
```python
from math import gcd, isqrt
from Crypto.Util.number import getPrime, isPrime

bits = int(input('Prime size in bits for the vulnerable key: '))
p = getPrime(bits); q = p + 2
while not isPrime(q): q += 2                   # VULNERABLE: q right next to p
n, e = p * q, 65537
d_real = pow(e, -1, (p - 1) * (q - 1))
print('Eve knows only n =', hex(n)[:30], '... and e =', e)

def fermat(n):                                 # works when |p - q| is small
    a = isqrt(n) + (isqrt(n) ** 2 < n)
    while True:
        b2 = a * a - n; b = isqrt(b2)
        if b * b == b2: return a - b, a + b
        a += 1

def pollard_rho(n, c=1):                       # works when a factor is small
    x = y = 2; d = 1
    while d == 1:
        x = (x * x + c) % n; y = (y * y + c) % n; y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    return d, n // d

fp, fq = fermat(n)
d = pow(e, -1, (fp - 1) * (fq - 1))
print('Recovered p, q:', fp == p or fp == q, '  private d correct:', d == d_real)
m = 42; print('Eve decrypts c:', pow(pow(m, e, n), d, n))
print('Pollard rho on n = 1000003 * prime:', pollard_rho(1000003 * getPrime(64))[0])
```

Mitigation: ≥2048-bit n, p and q independently random of equal size with |p−q| large,
CSPRNG for prime generation, OAEP padding, protect private key storage, rotate keys.

## 6. Access-control models (one runnable demo)

<!-- stdin: -->
```python
from datetime import datetime, timedelta, timezone

LEVEL = {'unclassified': 0, 'confidential': 1, 'secret': 2, 'top secret': 3}
user_roles = {'alice': {'doctor'}, 'bob': {'nurse'}}
role_perms = {'doctor': {'read', 'write', 'decrypt'}, 'nurse': {'read'}}
rbac = lambda u, perm: any(perm in role_perms.get(r, ()) for r in user_roles.get(u, ()))
abac = lambda user, obj, env: user['dept'] == obj['dept'] and 9 <= env['hour'] < 17
blp_read = lambda s, o: LEVEL[s] >= LEVEL[o]          # no read up
blp_write = lambda s, o: LEVEL[s] <= LEVEL[o]         # no write down
acl = {('alice', 'report.txt'): {'read', 'write'}}    # DAC access matrix
in_window = lambda start, end: start <= datetime.now(timezone.utc) <= end
prob = lambda trust, sens, risk: trust * (1 - sens) * (1 - risk)

print('RBAC bob decrypt   :', rbac('bob', 'decrypt'))
print('ABAC same dept 10h :', abac({'dept': 'ICU'}, {'dept': 'ICU'}, {'hour': 10}))
print('BLP secret reads TS:', blp_read('secret', 'top secret'), '| writes conf.:', blp_write('secret', 'confidential'))
print('DAC alice write    :', 'write' in acl.get(('alice', 'report.txt'), set()))
now = datetime.now(timezone.utc)
print('Time window        :', in_window(now - timedelta(hours=1), now + timedelta(hours=1)))
p = prob(0.9, 0.3, 0.2); print(f'Probabilistic P={p:.2f} ->', 'grant' if p >= 0.5 else 'deny')
```

## 7. Exam checklist (Lab 4)
* KMS questions: show generate → distribute → revoke → renew → audit log, and that a
  revoked/expired key is refused and non-owners cannot get private keys.
* Store private keys encrypted (never plaintext JSON) and say where the master key comes from.
* Rabin: show all four roots and how the right one is chosen.
* Access-control questions: implement the exact model named and print allow/deny for test cases.
