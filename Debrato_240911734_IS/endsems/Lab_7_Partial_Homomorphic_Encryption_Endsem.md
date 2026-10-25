# LAB 7 — Partial Homomorphic Encryption | Modular Endsem Codebook

**Source:** MIT Information Security Lab Manual [7–8], **Lab 7, pages 1–7**.  **Status:** syllabus-mapped reference, with corrected implementations. **Scope:** Lab 7 only. Lab 8 is a separate slice.

> **Goal:** build the shortest *correct* Python program for a new numerical, multi-user, file, or menu-driven exam question. **All question-specific values come from `input()`**: amounts, messages, record IDs, keys/parameters, counts, paths, and benchmark repetitions. Algorithm-defined constants (for example AES-192's 24-byte key and Paillier's `g = n + 1`) are intrinsic, not hardcoded question answers.
>
> **Reading rule:** a section marked **STANDALONE** can run by itself; a section marked **REUSABLE** is a function to paste into an existing program. The final master program is fully self-contained and menu-driven.

## 0. Syllabus-to-code index

| Manual requirement / likely variation | Section |
|---|---|
| Paillier encrypt 2 values → encrypted sum → decrypt total | 2 |
| Implement Paillier mathematically without relying on `phe` | 3 |
| Paillier encrypt N values → sum / difference / scalar / mean | 4 |
| Paillier weighted sum / weighted average | 5 |
| Signed integers / money with exact decimal input | 6 |
| Persist ciphertext and reconstruct it after restart | 7 |
| Two-party encrypted sharing, with an aggregator | 8 |
| Secure threshold / count approvals / final-total condition | 9 |
| Textbook RSA encrypted multiplication | 10 |
| ElGamal encrypted multiplication | 11 |
| ElGamal encrypted multiplication of N values | 12 |
| Time encryption / operation benchmarks (Paillier vs ElGamal) | 13 |
| Tamper detection / MD5, SHA256, RSA signatures, AES-192 | 14 |
| **Complete menu-driven, role-based, persistent scenario assembler** | 15 |
| Formula sheet, limitations, error handling, exam routing | 16–19 |

## 1. Environment and key principles

Installed by your existing setup:

```bash
uv pip install --python .venv/bin/python phe pycryptodome sympy
```

Confirm imports:

```python
from phe import paillier
from Crypto.Util.number import getPrime, isPrime
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
print('Lab 7 ready')
```

| Scheme | Allowed ciphertext operation | Plaintext result | **Not supported** |
|---|---|---|---|
| **Paillier** | `E(a) + E(b)` in `phe` | `a + b` | `E(a) * E(b)` |
| Paillier | `E(a) * k` | `a * k` for **unencrypted** `k` | General encrypted × encrypted multiplication |
| **Textbook RSA** | `E(a) * E(b) % n` | `a * b (mod n)` | Secure OAEP encryption with this property |
| **ElGamal** | `(c1a*c1b % p, c2a*c2b % p)` | `a * b (mod p)` | Encrypted `a > b` comparison |

**Crucial:** Paillier and ElGamal have *different* homomorphisms. Multiplying two Paillier ciphertexts is the raw modular operation that **adds** their plaintexts; do not confuse it with `EncryptedNumber.__mul__`, which accepts only a *plaintext scalar*.

**Do not claim encrypted comparisons work by default.** The manual's ElGamal “homomorphic comparison” example does not calculate `a > b`. Thresholding by **decrypting one final aggregate** is a valid demonstration; a true fully private comparison requires another protocol.

## 2. Paillier: encrypt 2 integers, add encrypted values, decrypt result — STANDALONE

```python
from phe import paillier
bits = int(input('Paillier key bits (>=2048): '))
if bits < 2048: raise ValueError('Use at least 2048 bits')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
a, b = int(input('Integer a: ')), int(input('Integer b: '))
x, y = pub.encrypt(a), pub.encrypt(b)
z = x + y                         # homomorphic operation; NO decrypt yet
print('Public n:', pub.n)
print('E(a):', x.ciphertext())
print('E(b):', y.ciphertext())
print('E(a+b):', z.ciphertext())
print('Decrypted sum:', priv.decrypt(z))
print('Correct:', priv.decrypt(z) == a + b)
```

**To adapt:** change two scalar inputs to a list (`§4`) or store encrypted values (`§7`). PHE uses fresh randomness; different ciphertexts for the same plaintext are expected.

## 3. Correct Paillier FROM SCRATCH: no `phe` — STANDALONE

The lab manual's illustrative “Paillier” sample incorrectly borrows RSA objects and unrelated equations. This is the correct integer-only Paillier construction using *user-supplied* primes; it is a **teaching implementation**, not hardened production cryptography.

```python
from math import gcd, lcm
from secrets import randbelow
from sympy import isprime

p, q = int(input('Prime p: ')), int(input('Different prime q: '))
if p == q or not isprime(p) or not isprime(q): raise ValueError('Distinct primes required')
n, lam = p*q, lcm(p-1, q-1)
if gcd(lam, n) != 1: raise ValueError('Choose different primes')
ns, g = n*n, n+1
L = lambda x: (x-1)//n
mu = pow(L(pow(g, lam, ns)), -1, n)

def enc(m):
    if not 0 <= m < n: raise ValueError('Require 0 <= m < n')
    while True:
        r = randbelow(n-1)+1
        if gcd(r, n) == 1: break
    return pow(g, m, ns)*pow(r, n, ns) % ns

def dec(c):
    if not 0 < c < ns or gcd(c, n) != 1: raise ValueError('Invalid ciphertext')
    return L(pow(c, lam, ns))*mu % n

a, b = int(input('a (>=0): ')), int(input('b (>=0): '))
if a+b >= n: raise ValueError('Use larger primes: sum would wrap modulo n')
x, y = enc(a), enc(b)
z = x*y % ns                     # raw Paillier ciphertext multiplication
print('Public key (n,g):', (n, g))
print('Ciphertexts:', x, y)
print('Encrypted sum:', z)
print('Decrypted sum:', dec(z), '| Expected:', a+b)
```

Equations: `n=pq`, `λ=lcm(p−1,q−1)`, `g=n+1`, `L(u)=(u−1)/n`, `μ=L(g^λ mod n²)⁻¹ mod n`; `E(m)=g^m r^n mod n²`, `D(c)=L(c^λ mod n²)μ mod n`.

**Small-prime warning:** tiny primes make the exam arithmetic easy but provide **no real security**. Use §2 (`phe`) for realistic key sizes.

## 4. N values: total, subtraction, add plaintext, scalar multiplication, average — STANDALONE

```python
from phe import paillier
bits = int(input('Paillier key bits (>=2048): '))
if bits < 2048: raise ValueError('Key too small')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
n = int(input('How many integers? '))
if n < 1: raise ValueError('Need at least one value')
values = [int(input(f'Value {i+1}: ')) for i in range(n)]
ct = [pub.encrypt(v) for v in values]
total = sum(ct)                   # ciphertext + ciphertext
print('Encrypted total:', total.ciphertext())
print('Decrypted total:', priv.decrypt(total))
print('Average (after decrypting total):', priv.decrypt(total)/n)

index = int(input('Index to modify (starting at 1): ')) - 1
if not 0 <= index < n: raise ValueError('Invalid index')
k = int(input('Public scalar: '))
b = int(input('Public adjustment: '))
print('Encrypted value * scalar:', (ct[index] * k).ciphertext())
print('Decrypted scalar product:', priv.decrypt(ct[index] * k))
print('Decrypted value + constant:', priv.decrypt(ct[index] + b))
print('Decrypted value - constant:', priv.decrypt(ct[index] - b))
if n > 1:
    print('Difference first-second:', priv.decrypt(ct[0] - ct[1]))
```

**Correctness:** `sum(ct)`, `ct[0]-ct[1]`, `ct[0]+public_int`, and `ct[0]*public_int` are supported; `ct[0]*ct[1]` is **not**.

## 5. Weighted encrypted sum, public prices × private quantities — STANDALONE

```python
from phe import paillier
bits = int(input('Paillier bits (>=2048): '))
if bits < 2048: raise ValueError('Key too small')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
n = int(input('Number of items: '))
if n < 1: raise ValueError('Need at least one')
enc_values, weights = [], []
for i in range(n):
    value = int(input(f'Private value {i+1}: '))
    weight = int(input(f'Public weight {i+1}: '))
    enc_values.append(pub.encrypt(value))
    weights.append(weight)
weighted = sum(c*w for c,w in zip(enc_values, weights))
print('Encrypted weighted total:', weighted.ciphertext())
print('Decrypted weighted total:', priv.decrypt(weighted))
if sum(weights):
    print('Weighted mean:', priv.decrypt(weighted)/sum(weights))
```

Useful for encrypted budgets, line-item costs, salary totals, grants, attendance counts, and score aggregation. **Public weights** only; multiplying two independently encrypted quantities is not supported.

## 6. Decimal money without binary floating-point error — STANDALONE

Use a **user-selected number of decimal places** and encrypt the corresponding *integer units*. This avoids a binary-float representation of currency.

```python
from decimal import Decimal
from phe import paillier
bits = int(input('Paillier bits (>=2048): '))
if bits < 2048: raise ValueError('Key too small')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
places = int(input('Decimal places (0=integers, 2=cents): '))
n = int(input('Number of amounts: '))
if places < 0 or n < 1: raise ValueError('Invalid settings')
scale = 10 ** places
ct = []
for i in range(n):
    value = Decimal(input(f'Amount {i+1}: ')) * scale
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError('Too many decimal places')
    ct.append(pub.encrypt(int(value)))
s = sum(ct)
print('Encrypted total:', s.ciphertext())
print('Final total:', Decimal(priv.decrypt(s)) / scale)
```

Remember the chosen `places` in persistent programs. Do **not** round silently. The `phe` library can also encode floats, but fixed-point integers are better for exact money.

## 7. Save Paillier keys and ciphertexts; restart and restore — STANDALONE

Encrypted ciphertext is serialized as **decimal string + exponent**. The original keypair must be preserved; regenerate keys and old ciphertext cannot be decrypted. Files/paths are prompted, not hardcoded.

```python
import json
from pathlib import Path
from phe import paillier

path = Path(input('Data file path (.json): ').strip())
if path.exists():
    d = json.loads(path.read_text())
    pub = paillier.PaillierPublicKey(int(d['n']))
    priv = paillier.PaillierPrivateKey(pub, int(d['p']), int(d['q']))
    enc = [paillier.EncryptedNumber(pub, int(r['ct']), int(r['exp'])) for r in d['records']]
    print('Restored', len(enc), 'encrypted records')
else:
    bits = int(input('Paillier bits (>=2048): '))
    if bits < 2048: raise ValueError('Key too small')
    pub, priv = paillier.generate_paillier_keypair(n_length=bits)
    enc = []

while True:
    choice = input('1 Add | 2 List ciphertexts | 3 Aggregate | 4 Save/exit: ')
    if choice == '1': enc.append(pub.encrypt(int(input('Integer: '))))
    elif choice == '2':
        for i, c in enumerate(enc, 1): print(i, c.ciphertext(), 'exp', c.exponent)
    elif choice == '3':
        if enc: print('Encrypted total:', sum(enc).ciphertext(), 'Decrypted total:', priv.decrypt(sum(enc)))
        else: print('No values')
    elif choice == '4':
        data = dict(n=str(pub.n), p=str(priv.p), q=str(priv.q),
                    records=[dict(ct=str(c.ciphertext()), exp=c.exponent) for c in enc])
        path.write_text(json.dumps(data, indent=2))
        path.chmod(0o600)
        print('Saved'); break
    else: print('Invalid choice')
```

**Security note:** this simplified file contains a **plaintext private key**. Use it only for a disposable lab exercise; do not push to GitHub or share it. In real systems the aggregator must not have unrestricted access to the decryption key.

## 8. Secure data sharing: two parties encrypt; aggregator adds ciphertexts — STANDALONE

```python
from phe import paillier
bits = int(input('Paillier bits (>=2048): '))
if bits < 2048: raise ValueError('Key too small')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
n = int(input('How many participants? '))
if n < 2: raise ValueError('Need at least two participants')
submitted = []
for i in range(n):
    name = input(f'Participant {i+1} label: ')
    value = int(input(f'{name} private value: '))
    submitted.append((name, pub.encrypt(value)))
for name, ct in submitted:
    print('Received encrypted contribution from', name, ':', ct.ciphertext())
total = sum(c for _, c in submitted)  # aggregator uses public ciphertexts only
print('Encrypted combined result:', total.ciphertext())
print('Authorized final decrypted result:', priv.decrypt(total))
```

The single-process program simulates parties; it is **not** a networked secure multi-party protocol. The labels and public key are not private.

## 9. Secure thresholding: encrypted approval counts / aggregate threshold — STANDALONE

The aggregation can remain encrypted; a designated decryption step learns only the **final count**, then compares it with a public threshold. This is **not a zero-knowledge comparison** or genuine threshold Paillier key-sharing.

```python
from phe import paillier
bits = int(input('Paillier bits (>=2048): '))
if bits < 2048: raise ValueError('Key too small')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
n = int(input('Number of voters/approvers: '))
required = int(input('Minimum approvals needed: '))
if n < 1 or not 0 <= required <= n: raise ValueError('Invalid count/threshold')
ballots = []
for i in range(n):
    vote = int(input(f'Participant {i+1} vote (0/1): '))
    if vote not in (0, 1): raise ValueError('Vote must be 0/1')
    ballots.append(pub.encrypt(vote))
encrypted_count = sum(ballots)
print('Encrypted approval count:', encrypted_count.ciphertext())
count = priv.decrypt(encrypted_count)             # only final aggregate decrypted
print('Total approvals:', count)
print('Threshold reached:', count >= required)
```

**Privacy limitation:** encrypted ballots alone do not prevent a compromised party from submitting malformed votes or learning information from other context. The script does not provide authenticated voting, individual-vote proofs, or genuine cryptographic threshold decryption.

## 10. Textbook RSA multiplicative homomorphism — STANDALONE

```python
from math import gcd
from Crypto.Util.number import isPrime
p, q = int(input('Prime p: ')), int(input('Distinct prime q: '))
e = int(input('RSA public exponent e: '))
if p == q or not isPrime(p) or not isPrime(q): raise ValueError('Distinct primes required')
n, phi = p*q, (p-1)*(q-1)
if not 1 < e < phi or gcd(e, phi) != 1: raise ValueError('Invalid RSA e')
d = pow(e, -1, phi)
a, b = int(input('a: ')), int(input('b: '))
if not 0 <= a < n or not 0 <= b < n: raise ValueError('0 <= a,b < n required')
ca, cb = pow(a,e,n), pow(b,e,n)
product_ct = ca*cb % n                 # homomorphic ciphertext multiplication
print('Public key:', (n,e), '| Private exponent:', d)
print('Ciphertexts:', ca, cb, '| Encrypted product:', product_ct)
print('Decrypted:', pow(product_ct,d,n), '| Expected modulo n:', a*b % n)
if a*b >= n: print('NOTE: ordinary product wraps modulo n')
```

**IMPORTANT:** This requires **un-padded textbook RSA** and is **not semantically secure**. RSA-OAEP encryption is randomized and does **not** preserve simple multiplicative homomorphism. Only use this educational construction to demonstrate the manual exercise, not to encrypt real grants.

## 11. ElGamal multiplicative homomorphism — STANDALONE

```python
from secrets import randbelow
from Crypto.Util.number import isPrime
p = int(input('Prime modulus p: '))
g = int(input('Base g: '))
x = int(input('Private exponent x: '))
if not isPrime(p) or p < 5 or not 1 < g < p or not 0 < x < p-1:
    raise ValueError('Invalid ElGamal parameters')
y = pow(g, x, p)

def encrypt(m):
    if not 0 <= m < p: raise ValueError('Message must be in 0..p-1')
    k = randbelow(p-2)+1                 # a fresh random nonce per encryption
    return pow(g,k,p), m*pow(y,k,p)%p

def decrypt(c):
    a,b = c
    return b*pow(pow(a,x,p),-1,p)%p

m1, m2 = int(input('m1: ')), int(input('m2: '))
c1, c2 = encrypt(m1), encrypt(m2)
c = (c1[0]*c2[0]%p, c1[1]*c2[1]%p)
print('Public key:', (p,g,y))
print('Ciphertexts:', c1, c2)
print('Encrypted product:', c)
print('Decrypted product:', decrypt(c), '| Expected mod p:', m1*m2%p)
if m1*m2 >= p: print('NOTE: ordinary product wraps modulo p')
```

**Group caution:** standard multiplicative ElGamal uses a well-defined cyclic subgroup and valid public parameters. This teaching snippet validates basic ranges and prime modulus but does not prove `g` has the required order. Zero is mathematically representable here but not a standard group element and leaks information; for group-based encryption choose nonzero messages.

## 12. ElGamal: multiply N encrypted inputs — STANDALONE

```python
from secrets import randbelow
from math import prod
from Crypto.Util.number import isPrime
p, g, x = (int(input(s)) for s in ('Prime p: ', 'Base g: ', 'Private x: '))
if p < 5 or not isPrime(p) or not 1 < g < p or not 0 < x < p-1:
    raise ValueError('Invalid parameters')
y = pow(g,x,p)
n = int(input('Number of nonzero plaintext values: '))
if n < 1: raise ValueError('Need values')
cs, values = [], []
for i in range(n):
    m = int(input(f'Value {i+1} in 1..p-1: '))
    if not 1 <= m < p: raise ValueError('Invalid group element')
    k = randbelow(p-2)+1
    cs.append((pow(g,k,p), m*pow(y,k,p)%p))
    values.append(m)
a, b = prod(z[0] for z in cs)%p, prod(z[1] for z in cs)%p
answer = b*pow(pow(a,x,p),-1,p)%p
print('Ciphertext product:', (a,b))
print('Decrypted:', answer, '| Expected modulo p:', prod(values)%p)
```

## 13. Performance benchmark: Paillier addition vs ElGamal multiplication — STANDALONE

Benchmark equivalent **requested operations** (not misleading claims about equal security levels). Encryption is generally randomized; use `perf_counter()` and average over a user-chosen number of trials.

```python
from time import perf_counter
from secrets import randbelow
from phe import paillier
from Crypto.Util.number import isPrime

bits = int(input('Paillier bits (>=2048): '))
p = int(input('ElGamal prime p: '))
g = int(input('ElGamal g: '))
x = int(input('ElGamal private x: '))
a, b = int(input('a (positive): ')), int(input('b (positive): '))
reps = int(input('Trials: '))
if bits < 2048 or not isPrime(p) or not 1 < g < p or not 0 < x < p-1 or not 0 < a < p or not 0 < b < p or reps < 1:
    raise ValueError('Invalid parameters')
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
y = pow(g,x,p)

def elg_enc(m):
    k = randbelow(p-2)+1
    return pow(g,k,p), m*pow(y,k,p)%p

def run(fn):
    start = perf_counter()
    for _ in range(reps): fn()
    return (perf_counter()-start)*1000/reps

pa, pb = pub.encrypt(a), pub.encrypt(b)
ea, eb = elg_enc(a), elg_enc(b)
print('Paillier encrypt ms:', run(lambda: pub.encrypt(a)))
print('Paillier ciphertext add ms:', run(lambda: pa+pb))
print('Paillier decrypt ms:', run(lambda: priv.decrypt(pa)))
print('ElGamal encrypt ms:', run(lambda: elg_enc(a)))
print('ElGamal ciphertext multiply ms:', run(lambda: (ea[0]*eb[0]%p,ea[1]*eb[1]%p)))
print('ElGamal decrypt ms:', run(lambda: ea[1]*pow(pow(ea[0],x,p),-1,p)%p))
```

**Interpretation:** sizes, security assumptions, and plaintext operations differ, so do **not** infer “scheme A is universally faster/more secure.” Avoid excessive `reps` for key generation; benchmark it separately only if required.

## 14. Building blocks for combined scenarios — REUSABLE

These components can be pasted into the question's application. They support **AES-192 description encryption**, **hash of exact serialized record**, **RSA signature of that hash**, and **Paillier ciphertext storage**. Choose MD5 *only if explicitly asked*; use SHA-256 otherwise.

```python
import json
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from phe import paillier

def encrypt_text(text, key):
    if len(key) != 24: raise ValueError('AES-192 requires a 24-byte key')
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv.hex(), cipher.encrypt(pad(text.encode(),16)).hex()

def decrypt_text(iv, ct, key):
    return unpad(AES.new(key,AES.MODE_CBC,iv=bytes.fromhex(iv)).decrypt(bytes.fromhex(ct)),16)

def record_bytes(record):
    # Sign only the data fields, not 'hash' and 'signature' themselves.
    return json.dumps(record,sort_keys=True,separators=(',',':')).encode()

def sign(record, rsa_private, algorithm='SHA256'):
    h = (MD5 if algorithm.upper()=='MD5' else SHA256).new(record_bytes(record))
    return h.hexdigest(), pkcs1_15.new(rsa_private).sign(h).hex()

def verify(record, digest_hex, signature_hex, rsa_public, algorithm='SHA256'):
    h = (MD5 if algorithm.upper()=='MD5' else SHA256).new(record_bytes(record))
    try:
        if h.hexdigest() != digest_hex: return False
        pkcs1_15.new(rsa_public).verify(h,bytes.fromhex(signature_hex))
        return True
    except (ValueError,TypeError): return False

def pack_encrypted_number(c):
    return {'ciphertext':str(c.ciphertext()), 'exponent':c.exponent}

def unpack_encrypted_number(pub, d):
    return paillier.EncryptedNumber(pub,int(d['ciphertext']),int(d['exponent']))
```

**Combine with user input:**

```python
bits = int(input('RSA bits (>=2048): '))
if bits < 2048: raise ValueError('RSA key too small')
rsa = RSA.generate(bits)
aes_key = get_random_bytes(24)                 # fresh AES-192 key; no fixed key
record = {'id': input('ID: '), 'description': input('Description: ')}
iv, ct = encrypt_text(record.pop('description'), aes_key)
record.update({'iv':iv, 'description_ct':ct})
h, signature = sign(record,rsa,input('Hash algorithm (MD5/SHA256): ').upper())
print('Hash:',h, 'Signature:',signature)
```

**Caution:** the code above is a **component demonstration**: preserve the selected hash algorithm for later verification; in a full scenario, sign the entire canonical stored record, including the Paillier ciphertext, encryption IV, metadata and ID. Do not append or modify signed fields afterwards. A signature establishes authenticity only if the public key is itself trusted.

## 15. COMPLETE MENU-DRIVEN MASTER: persistent encrypted records + three roles — STANDALONE

This is a **general reusable scenario blueprint**, not a preselected answer to any unseen exam question. The record has a user-entered **ID**, **description**, and **amount**. Rename those labels to *Grant ID*, *Patient ID*, *Invoice ID*, *Salary*, *Research Expense*, etc. according to the question.

It implements:

- **Submitter**: input ID/description/amount; AES-192-CBC encrypt description; Paillier encrypt integer amount; MD5 hash canonical encrypted record; sign using RSA PKCS#1 v1.5; save across runs; list entries.
- **Reviewer**: ID lookup; verify stored hash + RSA signature; if valid, decrypt AES-192 description and print its **hex dump**; tamper-demo uses a modified copy (original file preserved).
- **Aggregator/Finance**: select IDs; verify all records; **homomorphically add** Paillier ciphertexts; decrypt **only the final sum**. Never decrypt individual amounts in this role.
- **Persistence**: input the key/record JSON file paths on each run. They are created on first run and reused on restart if you enter the same paths. It refuses to silently replace missing keys for existing records.
- **Input:** record values, file paths, number precision and key sizes come from input. The required AES-192 key is randomly generated rather than fixed.

**Copy this entire program into a single `.py` file:**

```python
"""Lab 7: menu-driven encrypted-record composition template (educational)."""
from pathlib import Path
from decimal import Decimal, InvalidOperation
import json
import os

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from phe import paillier

def ask_path(prompt):
    name = input(prompt).strip()
    if not name:
        raise ValueError('File path cannot be empty')
    return Path(name)


KEY_FILE = ask_path('Private-key JSON path (reuse on restart): ')
DB_FILE = ask_path('Record JSON path (reuse on restart): ')
if KEY_FILE == DB_FILE:
    raise ValueError('Key and record files must be different')
FIELDS = ('id', 'iv', 'description', 'amount', 'exponent')


def number(prompt, minimum=None):
    while True:
        try:
            x = int(input(prompt))
            if minimum is not None and x < minimum:
                raise ValueError
            return x
        except ValueError:
            print('Enter a valid integer.')


def save(path, data, private=False):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    if private:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def setup():
    if KEY_FILE.exists():
        k = json.loads(KEY_FILE.read_text())
        pub = paillier.PaillierPublicKey(int(k['n']))
        priv = paillier.PaillierPrivateKey(pub, int(k['p']), int(k['q']))
        rsa = RSA.import_key(k['rsa_private'])
        aes = bytes.fromhex(k['aes'])
        places = int(k['places'])
        if len(aes) != 24 or places < 0:
            raise ValueError('Key file is invalid.')
    else:
        if DB_FILE.exists():
            raise RuntimeError('Records exist but keys are missing. Restore keys; do not regenerate.')
        bits = number('Paillier key size (at least 2048 bits): ', 2048)
        rsa_bits = number('RSA key size (at least 2048 bits): ', 2048)
        places = number('Amount decimal places (0 for integers): ', 0)
        pub, priv = paillier.generate_paillier_keypair(n_length=bits)
        rsa, aes = RSA.generate(rsa_bits), get_random_bytes(24)
        save(KEY_FILE, dict(n=str(pub.n), p=str(priv.p), q=str(priv.q),
                            rsa_private=rsa.export_key().decode(), aes=aes.hex(),
                            places=places), True)
    rows = json.loads(DB_FILE.read_text()) if DB_FILE.exists() else []
    if not isinstance(rows, list):
        raise ValueError('Invalid record file')
    return pub, priv, rsa, aes, places, rows


def payload(r):
    return json.dumps({k: r[k] for k in FIELDS}, sort_keys=True,
                      separators=(',', ':')).encode()


def verified(r, public_rsa):
    try:
        digest = MD5.new(payload(r))
        if digest.hexdigest() != r['hash']:
            return False
        pkcs1_15.new(public_rsa).verify(digest, bytes.fromhex(r['signature']))
        return True
    except (ValueError, TypeError, KeyError, OverflowError):
        return False


def get(rows):
    rid = input('Record ID: ').strip()
    return next((r for r in rows if r.get('id') == rid), None)


def add(rows, pub, rsa, aes, places):
    rid = input('New record ID: ').strip()
    if not rid or any(r.get('id') == rid for r in rows):
        print('Empty or duplicate ID.'); return
    desc = input('Description: ').encode()
    try:
        raw = Decimal(input('Amount: ')) * (10 ** places)
        if not raw.is_finite() or raw != raw.to_integral_value():
            raise ValueError
        amount = int(raw)
        enc_amount = pub.encrypt(amount)
    except (InvalidOperation, ValueError, OverflowError):
        print('Invalid amount or unsupported precision/range.'); return
    cipher = AES.new(aes, AES.MODE_CBC)
    ct = cipher.encrypt(pad(desc, AES.block_size))
    r = dict(id=rid, iv=cipher.iv.hex(), description=ct.hex(),
             amount=str(enc_amount.ciphertext()), exponent=enc_amount.exponent)
    digest = MD5.new(payload(r))
    r['hash'] = digest.hexdigest()
    r['signature'] = pkcs1_15.new(rsa).sign(digest).hex()
    rows.append(r)
    save(DB_FILE, rows)
    print('Stored ID:', rid, '| AES ciphertext:', r['description'])
    print('Paillier ciphertext:', r['amount'], '| MD5:', r['hash'])
    print('RSA signature:', r['signature'])


def list_records(rows):
    if not rows:
        print('No records.'); return
    for r in rows:
        print('ID:', r.get('id'), '| AES:', r.get('description'),
              '| Encrypted amount:', r.get('amount'), '| MD5:', r.get('hash'))


def review(rows, rsa, aes):
    r = get(rows)
    if r is None:
        print('Record not found.'); return
    ok = verified(r, rsa.publickey())
    print('MD5 and RSA signature:', 'VALID' if ok else 'INVALID')
    if not ok:
        print('Decryption blocked.'); return
    try:
        data = unpad(AES.new(aes, AES.MODE_CBC, iv=bytes.fromhex(r['iv']))
                     .decrypt(bytes.fromhex(r['description'])), AES.block_size)
        print('Decrypted description (hex):', data.hex())
    except (ValueError, KeyError):
        print('Invalid encrypted description.')


def aggregate(rows, pub, priv, rsa, places):
    if not rows:
        print('No records.'); return
    ids = input('Select comma-separated IDs (empty = all): ').strip()
    selected = rows if not ids else [r for r in rows if r.get('id') in {s.strip() for s in ids.split(',')}]
    if not selected or (ids and set(s.strip() for s in ids.split(',')) != {r.get('id') for r in selected}):
        print('Unknown ID or empty selection.'); return
    if any(not verified(r, rsa.publickey()) for r in selected):
        print('Tampered/invalid record: aggregation blocked.'); return
    try:
        encrypted = [paillier.EncryptedNumber(pub, int(r['amount']), int(r['exponent']))
                     for r in selected]
        total = sum(encrypted)                 # Addition on ciphertexts only
        print('Encrypted aggregate:', total.ciphertext())
        answer = priv.decrypt(total)          # ONLY decryption: final aggregate
        print('Decrypted aggregate:', Decimal(answer) / (10 ** places))
    except (ValueError, TypeError, OverflowError, KeyError):
        print('Invalid ciphertext or aggregate out of range.')


def demo_tamper(rows):
    r = get(rows)
    if r is None:
        print('Record not found.'); return
    if r.get('description'):
        changed = dict(r)
        changed['description'] = ('0' if changed['description'][0] != '0' else '1') + changed['description'][1:]
        print('Tampered copy ready (original storage unchanged).')
        return changed
    print('Cannot change empty ciphertext.')


def main():
    pub, priv, rsa, aes, places, rows = setup()
    while True:
        print('\n1 Researcher  2 Reviewer  3 Finance  4 Exit')
        role = input('Role: ').strip()
        if role == '1':
            while True:
                print('\n1 Submit  2 List submitted  3 Back')
                action = input('Choice: ').strip()
                if action == '1': add(rows, pub, rsa, aes, places)
                elif action == '2': list_records(rows)
                elif action == '3': break
                else: print('Invalid choice.')
        elif role == '2':
            while True:
                print('\n1 Search and verify by ID  2 Tamper test  3 Back')
                action = input('Choice: ').strip()
                if action == '1': review(rows, rsa, aes)
                elif action == '2':
                    changed = demo_tamper(rows)
                    if changed:
                        print('Modified-copy verification:', verified(changed, rsa.publickey()))
                elif action == '3': break
                else: print('Invalid choice.')
        elif role == '3': aggregate(rows, pub, priv, rsa, places)
        elif role == '4': return
        else: print('Invalid choice.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print('Cannot load/save lab data:', exc)
```

### Run the menu master

```bash
source .venv/bin/activate
python Lab_7_Endsem_Menu_Master.py
```

For an unknown question: change only field labels, permitted roles, allowed actions, hash algorithm (`MD5` vs `SHA256`), encryption scheme, and output format. **Do not delete the verification gate before aggregation or plaintext display.** Use the same keypair after restarting, and back up the two JSON files together.

**Important limits:** this is a console **role-menu simulation**, *not* real login/authentication or an isolated financial service: every menu is available locally, and the plaintext private key is stored on disk. AES-CBC provides confidentiality only; signature validation is what the example uses to detect record changes. MD5 is cryptographically broken against collisions; it is retained solely for exam prompts that explicitly require it.

## 16. Very short interactive helpers — REUSABLE

```python
from pathlib import Path

def ask_int(label, smallest=None):
    while True:
        try:
            x = int(input(label))
            if smallest is not None and x < smallest: raise ValueError
            return x
        except ValueError: print('Invalid integer')

def choose_ids(records):
    wanted = {x.strip() for x in input('IDs separated by commas: ').split(',') if x.strip()}
    found = [r for r in records if r['id'] in wanted]
    if len(found) != len(wanted): raise ValueError('Unknown record ID')
    return found

def write_text_file():
    path = Path(input('Output filename: '))
    path.write_text(input('Text to save: '))
    print('Saved:', path)
```

## 17. Question → shortest component lookup

| If the exam says... | Use / change |
|---|---|
| “Add encrypted amounts, decrypt only total” | §2 (two) or §4 (N) |
| “Implement Paillier manually” | §3 |
| “Encrypt salaries/grants from different participants” | §8 + §7 |
| “Aggregate selected records by ID” | §15 `aggregate()` |
| “Include negative values / discount / difference” | §4 |
| “Weighted sales/research spending” | §5 |
| “Store currency values to two decimal places” | §6; enter `2` at runtime |
| “Recover encrypted records after restart” | §7 or §15 |
| “Homomorphic RSA multiplication” | §10 |
| “Homomorphic ElGamal multiplication” | §11 or §12 |
| “Determine whether final total exceeds threshold” | §9 adapted to final-sum condition; decrypt **aggregate only** |
| “Encrypted greater-than without decrypting aggregate” | **Not supplied by basic Paillier/ElGamal/RSA**; requires a different protocol |
| “Measure execution time and compare algorithms” | §13 |
| “Secure record portal with signatures, AES, homomorphic total” | §14 + §15 |
| “Only authorized roles can view description” | §15 `review()` + `verified()`; note menu ≠ authentication |
| “Integrity failure must prevent decryption” | §15 `verified()` → `review()` gate |
| “Display plaintext as a hexadecimal dump” | `print(plaintext_bytes.hex())` |
| “Show sender and receiver hashes” | compute hash of the **exact same bytes** and compare |
| “No individual decryption by finance” | compute `sum(ciphertexts)` and call private `decrypt` **once**, on total |

## 18. Input / correctness / common exam traps

1. **No question values hardcoded.** Always prompt for message, amount, count, prime, public exponent, record ID, input path, decimal precision, and the scheme requested. Algorithm constants such as AES-192 key length do not change.
2. `phe` encrypted ciphertext values are huge; print them as integers or decimal strings. Persist **ciphertext and exponent**; save the public modulus `n` separately. All encrypted values added together must use the **same public key**.
3. With `phe`, `sum(ciphertexts)` works (it supports `0 + EncryptedNumber`); do not decrypt inside a loop if the question forbids individual amounts being revealed.
4. **Paillier:** `ct + ct` → sum, `ct * public_scalar` → product, `ct * ct` → **unsupported**. In a manual raw implementation, multiplying ciphertexts modulo `n²` corresponds to plaintext addition.
5. **RSA:** `c1*c2 % n` → product **modulo n**, and only for insecure *textbook* RSA, not RSA-OAEP.
6. **ElGamal:** componentwise ciphertext multiplication → plaintext product **modulo p**. It does not support arbitrary encrypted greater-than checks. Nonces must not be reused.
7. **Modulo wrapping:** if the intended mathematical sum/product exceeds the native modulus's representable domain, decrypted results may wrap or overflow. Choose/validate key size and message bounds.
8. **MD5 vs SHA-256:** follow the question, but never claim MD5 is collision-resistant in modern security. SHA-256 is preferable unless the exercise requires MD5.
9. **Signature key roles:** private key **signs**, public key **verifies**; the encryption public key and signature public key have different purposes.
10. **AES key size:** 192 bits = **24 bytes**. CBC IV = **16 bytes**. Decryption must use exactly the original key and IV. Authentication is separate from encryption.
11. **Tampering:** if hashes or signatures mismatch, **do not decrypt** (for a verify-before-decrypt question). Hash verification alone does **not** authenticate the sender.
12. **Key secrecy:** private-key JSON files are confidential; no student should publish them. Real deployments require key isolation, authenticated role enforcement and AEAD (e.g. AES-GCM), unlike this teaching template.
13. **Menus:** implement `while True`, numbered choices, a “Back” path for submenus, and an “Exit”; invalid input must display an error, not exit silently.
14. **Persistence:** do not regenerate a new private key for old encrypted records. Use `open(...)/json` or `sqlite3` to persist ciphertext + metadata; keep signing-key continuity.
15. **Exam variations:** the lab manual explicitly permits novel combinations. Assemble from the reusable blocks; do not falsely equate template coverage with a guarantee for any possible question.

## 19. Self-check list before submission

- [ ] All requested data and mathematical parameters are obtained through input.
- [ ] Key pairs are valid; RSA/ElGamal/Paillier are not mixed up.
- [ ] Ciphertexts and any IV/nonces are displayed when asked.
- [ ] Addition/multiplication uses the **specified** homomorphic operation.
- [ ] Only allowed decrypted values are displayed.
- [ ] For file persistence, stopping and restarting does not erase old records.
- [ ] Tampering causes verification failure and prevents prohibited decryption.
- [ ] All requested roles, menu options, prompts and output labels are present.
- [ ] Empty dataset, bad index, invalid prime, malformed ciphertext, duplicate ID are handled.
- [ ] Test with a small positive input, a negative input (Paillier), an aggregate of 2+ records, a restart and a tampered copy.

### Provenance and validation boundaries

- **Syllabus:** uploaded *IS Lab Manual [7–8]*, Lab 7 (pages 1–7). Core Paillier addition, textbook RSA multiplication, ElGamal multiplication, two-party sharing, threshold scenario and benchmarking are all explicitly present in the manual.
- **Corrections:** the manual's RSA-derived Paillier “implementation” and ElGamal comparison are mathematically invalid; those examples are **replaced with correct educational constructions** rather than copied. `phe` Paillier serialization/addition APIs are documented at https://python-paillier.readthedocs.io/en/stable/ .
- **Additional reusable material:** AES-192, signature verification, persistent JSON, fixed-point currency, RBAC-style menus and tamper handling extend the manual to address scenario-based exams. They are *expansions*, not stated Lab 7 exercises.
- **Verification at creation:** Python syntax compilation was performed on the menu master and all complete Python blocks; standalone pure-math programs can be tested without optional third-party cryptography packages. Full end-to-end execution with `phe` and `pycryptodome` requires those installed packages and must be verified in PyCharm before examination.

**Next slice: Lab 8 — Searchable Encryption. Do not start it until the user says “next lab.”**
