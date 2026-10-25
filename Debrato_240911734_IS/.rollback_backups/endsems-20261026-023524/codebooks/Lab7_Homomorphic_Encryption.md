# Lab 7 — Partially homomorphic encryption (Paillier, RSA, ElGamal, threshold)

Toolkit: `toolkit/homomorphic.py` — Paillier from scratch (`paillier_keygen`, `_encrypt`
(optional explicit r), `_decrypt` (negatives supported), `_add`, `_add_const`, `_mul_const`,
`_sub`, `_weighted_sum`, `_rerandomize`), `encrypt_one_hot` + `tally`, **cooperative threshold arithmetic demo**
(`paillier_threshold_keygen`, `partial_decrypt`, `combine_partials`), RSA and ElGamal
multiplicative, exponential (additive) ElGamal. No `phe` needed.

**The manual's sample "Paillier" code is wrong** (it builds keys from RSA objects and
uses unrelated equations) and its ElGamal "homomorphic comparison" does not compare anything.
Use the code below.

## 0. Formulas

| | Key | Encrypt | Decrypt | Homomorphism |
|---|---|---|---|---|
| Paillier | n=pq, λ=lcm(p−1,q−1), g=n+1, μ=L(g^λ mod n²)⁻¹ mod n, L(u)=(u−1)/n | c = gᵐ·rⁿ mod n² | m = L(c^λ mod n²)·μ mod n | E(a)·E(b)=E(a+b); E(a)ᵏ=E(k·a) |
| RSA | (n,e),(n,d) | c = mᵉ mod n | m = cᵈ mod n | E(a)·E(b)=E(a·b mod n) |
| ElGamal | (p,g,y=gˣ), x | (gᵏ, m·yᵏ) | c2·(c1ˣ)⁻¹ | component-wise product = E(m1·m2) |
| Exp-ElGamal | same | (gᵏ, gᵐ·yᵏ) | gᵐ then small discrete log | product = E(m1+m2) |

Paillier cannot multiply two ciphertexts' plaintexts; it can only add, and multiply by a
**public** constant. To count votes per candidate, encrypt a **one-hot** vector
(E(1) for the chosen candidate, E(0) for others) — summing encrypted candidate *IDs* gives
the sum of IDs, not counts. Decrypt only the aggregate when the question forbids individual decryption.

## 1. Paillier from scratch: encrypt two integers, add encrypted, decrypt (manual Q1)

<!-- stdin: 15 | 25 | 1024 -->
```python
from math import gcd
import secrets
from Crypto.Util.number import getPrime

a, b = int(input('First integer: ')), int(input('Second integer: '))
bits = int(input('Key bits (1024/2048): '))
while True:
    p, q = getPrime(bits // 2), getPrime(bits // 2)
    n = p * q
    if p != q and gcd(n, (p - 1) * (q - 1)) == 1: break
n2, g = n * n, n + 1
lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
mu = pow((pow(g, lam, n2) - 1) // n, -1, n)          # = lam^-1 mod n when g = n+1

def enc(m):
    if not -(n // 2) <= m <= n // 2: raise ValueError('Input exceeds the signed range')
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1: break
    return pow(g, m % n, n2) * pow(r, n, n2) % n2

def dec(c):
    m = (pow(c, lam, n2) - 1) // n * mu % n
    return m - n if m > n // 2 else m                  # map back to negatives

if not -(n // 2) <= a + b <= n // 2: raise ValueError('Sum would wrap modulo n')
ca, cb = enc(a), enc(b)
print('E(a) =', str(ca)[:50], '...\nE(b) =', str(cb)[:50], '...')
c_sum = ca * cb % n2                                   # homomorphic ADDITION
print('E(a+b) =', str(c_sum)[:50], '...')
print('Decrypted sum:', dec(c_sum), '| expected', a + b, '| match:', dec(c_sum) == a + b)
print('Same plaintext encrypts differently:', enc(a) != ca)
```

## 2. Many values: sum, difference, scalar multiple, add constant, average, weighted sum

<!-- stdin: 120, 340, -25, 99 | 3 | 1,2,3,4 -->
```python
from toolkit.homomorphic import (paillier_keygen, paillier_encrypt, paillier_decrypt, paillier_add,
                                 paillier_sub, paillier_mul_const, paillier_add_const, paillier_weighted_sum)

values = [int(v) for v in input('Integers (comma separated): ').split(',')]
k = int(input('Public constant k: '))
weights = [int(w) for w in input(f'{len(values)} public weights: ').split(',')]
if len(values) < 2 or len(weights) != len(values): raise ValueError('Need at least two values and one weight per value')
pub, priv = paillier_keygen(1024)
# Bounds checked before encryption. A remote aggregator needs agreed public bounds instead.
results = [sum(values), values[0] - values[1], k * values[0], sum(values) + k,
           sum(v * w for v, w in zip(values, weights))]
if any(abs(v) > pub['n'] // 2 for v in values + results): raise ValueError('Result would wrap modulo n')
cts = [paillier_encrypt(pub, v) for v in values]             # individual values never decrypted
total = paillier_add(pub, *cts)
print('sum             :', paillier_decrypt(priv, total))
print('first - second  :', paillier_decrypt(priv, paillier_sub(pub, cts[0], cts[1])))
print(f'k * first       :', paillier_decrypt(priv, paillier_mul_const(pub, cts[0], k)))
print(f'sum + k         :', paillier_decrypt(priv, paillier_add_const(pub, total, k)))
print('average         :', paillier_decrypt(priv, total) / len(values))   # divide AFTER decrypting
print('weighted sum    :', paillier_decrypt(priv, paillier_weighted_sum(pub, cts, weights)))
```

All signed arithmetic is modulo n. Every input and result must stay in
`[-(n//2), n//2]`. An encrypted aggregate does not reveal overflow. With a public per-record
bound B and weights w, require `B * sum(abs(w)) <= n//2` before computing the weighted sum.
For unweighted totals, use `count * B`. Choose bounds before encryption and preserve them
with the dataset. Large keys alone do not make unrestricted integer input safe.

Decimals (money): scale to integers first (`12.50 → 1250` with 2 places, `Decimal` not float),
decrypt the total, then divide by 100. Average = decrypt(sum) / count (division is not homomorphic).

## 3. RSA multiplicative homomorphism (manual Q2: 7 and 3)

<!-- stdin: 7 | 3 -->
```python
from Crypto.PublicKey import RSA

a, b = int(input('a: ')), int(input('b: '))
key = RSA.generate(2048)
n, e, d = key.n, key.e, key.d
ca, cb = pow(a, e, n), pow(b, e, n)                      # textbook RSA (no padding!)
print('E(a) =', str(ca)[:40], '...\nE(b) =', str(cb)[:40], '...')
c_prod = ca * cb % n                                      # multiply ciphertexts
print('E(a*b) =', str(c_prod)[:40], '...')
print('Decrypted product:', pow(c_prod, d, n), '| expected modulo n', a * b % n)
```

Textbook RSA is deterministic (same m → same c) and malleable; OAEP-padded RSA is *not*
homomorphic — that is why the demo must use raw RSA.

## 4. ElGamal multiplicative homomorphism (additional 1a) + additive variant

<!-- stdin: 6 | 7 -->
```python
import secrets
from Crypto.Util.number import getPrime

m1, m2 = int(input('m1: ')), int(input('m2: '))
p = getPrime(512); g = secrets.randbelow(p - 3) + 2
x = secrets.randbelow(p - 3) + 2; y = pow(g, x, p)
enc = lambda m: (lambda k: (pow(g, k, p), m * pow(y, k, p) % p))(secrets.randbelow(p - 3) + 2)
dec = lambda c: c[1] * pow(pow(c[0], x, p), -1, p) % p
c1, c2 = enc(m1), enc(m2)
prod = (c1[0] * c2[0] % p, c1[1] * c2[1] % p)              # component-wise multiply
print('E(m1)*E(m2) decrypts to', dec(prod), '| expected modulo p', m1 * m2 % p)
# Exponential ElGamal: encrypt g^m -> product decrypts to g^(m1+m2) (ADDITION, small totals)
e1, e2 = enc(pow(g, m1, p)), enc(pow(g, m2, p))
gs = dec((e1[0] * e2[0] % p, e1[1] * e2[1] % p))
print('additive variant  ->', next(m for m in range(10000) if pow(g, m, p) == gs), '| expected', m1 + m2)
```

## 5. Secure data sharing (1b): parties encrypt, aggregator adds without the private key

<!-- stdin: 3 | Hospital A | 120 | Hospital B | 75 | Hospital C | 40 -->
```python
from toolkit.homomorphic import paillier_keygen, paillier_encrypt, paillier_add, paillier_decrypt

pub, priv = paillier_keygen(2048)           # analyst holds priv; parties get only pub
parties = int(input('Number of parties: '))
shared = {}
for _ in range(parties):
    name = input('Party name: ')
    shared[name] = paillier_encrypt(pub, int(input(f'{name} private value: ')))   # with pub only
    print(f'{name} sends ciphertext', str(shared[name])[:30], '...')
agg = paillier_add(pub, *shared.values())   # aggregator: no private key needed
print('Aggregator result (encrypted):', str(agg)[:40], '...')
print('Analyst decrypts ONLY the total:', paillier_decrypt(priv, agg))
```

## 6. Secure thresholding (1c): cooperative t-of-N decryption arithmetic

A trusted dealer shares exponent d (d ≡ 0 mod λ, d ≡ 1 mod n) with a polynomial
over the composite ring Z_{nλ}. This is not ordinary Shamir sharing over a field.
Authority i returns `cᵢ = c^{sᵢ} mod n²`. Any t honest partials combine with integer
Lagrange coefficients (Δ = N!) into `c^{Δd} = 1 + Δ·m·n`, so `m = L(·)·Δ⁻¹ mod n`.

The tests establish honest-party reconstruction and API refusal below t. They do not
prove secrecy with fewer shares or security against malicious partials. The implementation
has no privacy proof, no proofs of correct partial decryption, and no secure erasure.
The dealer and this single process initially see all shares. Treat this as an unqualified
cooperative arithmetic demo, not a vetted threshold-Paillier protocol.

<!-- stdin: 5 | 3 | 40, 25, 61 | 1, 4, 5 -->
```python
from toolkit.homomorphic import (paillier_threshold_keygen, paillier_encrypt, paillier_add,
                                 partial_decrypt, combine_partials)

N = int(input('Number of authorities N: '))
t = int(input('Threshold t: '))
pub, shares = paillier_threshold_keygen(2048, t, N)        # conceptual distribution: each authority should receive one share
values = [int(v) for v in input('Encrypted inputs (comma separated): ').split(',')]
total = paillier_add(pub, *[paillier_encrypt(pub, v) for v in values])
who = [int(i) for i in input(f'Which {t} authorities cooperate (ids): ').split(',')]
partials = [partial_decrypt(pub, shares[i - 1], total) for i in who]
print('Combined result:', combine_partials(pub, partials))
try:
    combine_partials(pub, partials[:t - 1])
except ValueError as err:
    print(f'With only {t - 1} authorities:', err)
limit = 100
print(f'Aggregate above threshold {limit}?', combine_partials(pub, partials) > limit)
```

## 7. Encrypted voting / counting with one-hot vectors

<!-- stdin: 1,2,3 | 2,2,1,3,2 -->
```python
from toolkit.homomorphic import paillier_keygen, encrypt_one_hot, tally, paillier_decrypt

cands = [c.strip() for c in input('Candidate IDs: ').split(',')]
votes = [v.strip() for v in input('Votes cast (candidate IDs): ').split(',')]
pub, priv = paillier_keygen(2048)
ballots = [encrypt_one_hot(pub, v, cands) for v in votes]          # each voter
enc_totals = tally(pub, ballots, cands)                           # server, still encrypted
print({c: paillier_decrypt(priv, ct) for c, ct in enc_totals.items()})   # only totals
```

## 8. Persist keys and ciphertexts (restart-safe) — Python ints are JSON-native

<!-- stdin: 500 -->
```python
import json, os
from toolkit.homomorphic import paillier_keygen, paillier_encrypt, paillier_add, paillier_decrypt

if not os.path.exists('he_keys.json'):
    pub, priv = paillier_keygen(2048)
    json.dump({'pub': pub, 'priv': priv}, open('he_keys.json', 'w'))   # protect priv in real use
keys = json.load(open('he_keys.json'))
db = json.load(open('he_db.json')) if os.path.exists('he_db.json') else []
db.append(paillier_encrypt(keys['pub'], int(input('Value to store: '))))
json.dump(db, open('he_db.json', 'w'))
print(len(db), 'stored; running total =', paillier_decrypt(keys['priv'], paillier_add(keys['pub'], *db)))
```

## 9. Benchmark Paillier vs ElGamal (1d)

<!-- stdin: 20 -->
```python
import time, secrets
from Crypto.Util.number import getPrime
from toolkit.homomorphic import paillier_keygen, paillier_encrypt, paillier_add, paillier_decrypt

reps = int(input('Repetitions: '))
def avg(f):
    t = time.perf_counter()
    for _ in range(reps): f()
    return (time.perf_counter() - t) / reps * 1000
pub, priv = paillier_keygen(2048)
c = paillier_encrypt(pub, 5)
print(f'Paillier-2048  enc {avg(lambda: paillier_encrypt(pub, 5)):7.2f} ms  add {avg(lambda: paillier_add(pub, c, c)):7.3f} ms  dec {avg(lambda: paillier_decrypt(priv, c)):7.2f} ms')
p = getPrime(2048); g = 2; x = secrets.randbelow(p - 3) + 2; y = pow(g, x, p)
enc = lambda m: (lambda k: (pow(g, k, p), m * pow(y, k, p) % p))(secrets.randbelow(p - 3) + 2)
e = enc(5)
print(f'ElGamal-2048   enc {avg(lambda: enc(5)):7.2f} ms  mul {avg(lambda: (e[0] * e[0] % p, e[1] * e[1] % p)):7.3f} ms  dec {avg(lambda: e[1] * pow(pow(e[0], x, p), -1, p) % p):7.2f} ms')
```

## 10. If the lab machine has `phe` and the question expects it

<!-- no-run -->
```python
from phe import paillier
pub, priv = paillier.generate_paillier_keypair(n_length=2048)
x, y = pub.encrypt(15), pub.encrypt(25)
print(priv.decrypt(x + y), priv.decrypt(x * 3))          # 40, 45  (+ adds, * by plain int)
c_int = x.ciphertext()                                   # store as int; reload with
x2 = paillier.EncryptedNumber(pub, c_int, x.exponent)    # EncryptedNumber(pub, int, exponent)
```

## 11. Exam checklist (Lab 7)
* Print both ciphertexts, the encrypted result, and the decrypted result vs the expected value.
* Decrypt only aggregates when asked; verify signatures/hashes of inputs before aggregating.
* Enforce input/result bounds before encryption. Ciphertexts cannot prove that the signed total did not wrap modulo n.
* Say which operation is homomorphic for which scheme (Paillier +, RSA ×, ElGamal ×).
