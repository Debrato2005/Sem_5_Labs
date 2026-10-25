# Lab 1 — Classical (basic symmetric) ciphers

Toolkit module: `toolkit/classical.py` (all functions below, tested).
Every block here is **standalone** (copy into an empty file and run). `<!-- stdin: ... -->`
lines are the sample inputs the test-suite feeds; ignore them.

## 0. Question → code

| Question says | Use | Section |
|---|---|---|
| additive / shift / Caesar, key k | `C=(P+k) mod 26` | §2 |
| multiplicative, key k (gcd(k,26)=1) | `C=(P·k) mod 26` | §2 |
| affine (a,b) | `C=(aP+b) mod 26` | §2 |
| Vigenère keyword | `C_i=(P_i+K_{i mod m})` | §3 |
| autokey, key = number or word | key stream = key ‖ plaintext | §3 |
| Playfair with keyword (e.g. GUIDANCE) | 5×5 matrix, I/J merged | §4 |
| Hill with matrix K | `C = K·P (mod 26)`, needs `gcd(det,26)=1` | §5 |
| rail fence / columnar / permutation | transposition | §6 |
| "ciphertext CIW is plaintext yes" | known-plaintext attack | §7 |
| "brute force", "affine ab→GL" | try all keys / solve pair | §7 |
| "Eve types abcdefghi, screen shows ..." | chosen-plaintext attack | §7 |

Attack names: **ciphertext-only** (only ciphertext), **known-plaintext** (some P,C pairs),
**chosen-plaintext** (attacker picks P, sees C — Eve on Alice's computer), **chosen-ciphertext**,
**brute force** (try whole key space: 26 additive, 12 multiplicative, 312 affine).

## 1. Common helpers (paste once at the top)

```python
from math import gcd

def clean(t):                      # lab: "ignore the space between words"
    return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')

def nums(t):
    return [ord(c) - 65 for c in clean(t)]

def text(ns, upper=True):
    s = ''.join(chr(n % 26 + 65) for n in ns)
    return s if upper else s.lower()

print(nums('Hi there'), text([7, 8]))
```

## 2. Additive / multiplicative / affine (one function family)

Formulas: additive `C=(P+k)`, `P=(C−k)`; multiplicative `C=P·k`, `P=C·k⁻¹`;
affine `C=a·P+b`, `P=a⁻¹(C−b)` — all mod 26. `a` must satisfy `gcd(a,26)=1`
(valid a: 1,3,5,7,9,11,15,17,19,21,23,25). `pow(a, -1, 26)` gives a⁻¹ (Python ≥3.8).

<!-- stdin: I am learning information security | affine | 15 | 20 -->
```python
from math import gcd

def clean(t): return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')

def affine_enc(t, a, b):
    if gcd(a, 26) != 1: raise ValueError('a has no inverse mod 26')
    return ''.join(chr((a * (ord(c) - 65) + b) % 26 + 65) for c in clean(t))

def affine_dec(t, a, b):
    ai = pow(a, -1, 26)
    return ''.join(chr(ai * (ord(c) - 65 - b) % 26 + 97) for c in clean(t))

msg = input('Message: ')
kind = input('Cipher (additive/multiplicative/affine): ').strip().lower()
if kind == 'additive':
    a, b = 1, int(input('Key k: '))
elif kind == 'multiplicative':
    a, b = int(input('Key k: ')), 0
else:
    a, b = int(input('Key a: ')), int(input('Key b: '))
ct = affine_enc(msg, a, b)
print('Ciphertext:', ct)
print('Decrypted :', affine_dec(ct, a, b))
```

## 3. Vigenère and Autokey

Vigenère `C_i = (P_i + K_{i mod m}) mod 26`. Autokey (manual): key stream `k = (k1, P1, P2, …)`,
`C_i = (P_i + k_i)`, decryption rebuilds the stream from recovered plaintext.

<!-- stdin: the house is being sold tonight | dollars | 7 -->
```python
def clean(t): return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')
N = lambda t: [ord(c) - 65 for c in clean(t)]
T = lambda ns, up=True: ''.join(chr(n % 26 + (65 if up else 97)) for n in ns)

def vig_enc(p, k): k = N(k); return T([x + k[i % len(k)] for i, x in enumerate(N(p))])
def vig_dec(c, k): k = N(k); return T([x - k[i % len(k)] for i, x in enumerate(N(c))], False)

def auto_enc(p, key):                     # key: int (e.g. 7) or word
    p = N(p); s = ([key % 26] if isinstance(key, int) else N(key)) + p
    return T([x + s[i] for i, x in enumerate(p)])

def auto_dec(c, key):
    s, out = ([key % 26] if isinstance(key, int) else N(key)), []
    for i, x in enumerate(N(c)):
        out.append((x - s[i]) % 26); s.append(out[-1])
    return T(out, False)

msg = input('Message: ')
vk = input('Vigenere keyword: ')
ak = input('Autokey key (number or word): ')
ak = int(ak) if ak.isdigit() else ak
c1, c2 = vig_enc(msg, vk), auto_enc(msg, ak)
print('Vigenere:', c1, '->', vig_dec(c1, vk))
print('Autokey :', c2, '->', auto_dec(c2, ak))
```

## 4. Playfair

Rules: matrix from keyword (I=J) + rest of alphabet; split into digraphs, insert `X`
between doubled letters and pad odd length; same row → right, same column → down,
rectangle → swap columns. Decrypt: left / up / swap. Manual: key `GUIDANCE`,
message "The key is hidden under the door pad" →
`POCLBXDRLGIYIBCGBGLXPOBILZLTTGIY` (tested).

<!-- stdin: The key is hidden under the door pad | GUIDANCE -->
```python
def clean(t): return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')

def matrix(key):
    seq = []
    for c in clean(key).replace('J', 'I') + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seq: seq.append(c)
    return [seq[i:i + 5] for i in range(0, 25, 5)]

def pairs(t):
    t, out, i = clean(t).replace('J', 'I'), [], 0
    while i < len(t):
        a = t[i]; b = t[i + 1] if i + 1 < len(t) else 'X'
        if a == b: out.append(a + 'X'); i += 1
        else: out.append(a + b); i += 2
    return out

def play(prs, m, step):
    pos = {m[r][c]: (r, c) for r in range(5) for c in range(5)}
    out = ''
    for a, b in prs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:   out += m[r1][(c1 + step) % 5] + m[r2][(c2 + step) % 5]
        elif c1 == c2: out += m[(r1 + step) % 5][c1] + m[(r2 + step) % 5][c2]
        else:          out += m[r1][c2] + m[r2][c1]
    return out

msg, key = input('Message: '), input('Keyword: ')
m = matrix(key)
for row in m: print(' '.join(row))
ct = play(pairs(msg), m, 1)
print('Digraphs  :', pairs(msg))
print('Ciphertext:', ct)
print('Decrypted :', play([ct[i:i + 2] for i in range(0, len(ct), 2)], m, -1).lower())
```

## 5. Hill cipher (any n×n)

`C = K·P mod 26` on column vectors of n letters; `P = K⁻¹·C`. `K⁻¹ = det⁻¹ · adj(K) mod 26`
and requires `gcd(det K, 26) = 1`. Manual key `[[3,3],[2,7]]` (det = 15, invertible).
2×2 shortcut: `K⁻¹ = det⁻¹ · [[d, −b], [−c, a]] mod 26`.

<!-- stdin: We live in an insecure world | 2 | 3 3 | 2 7 -->
```python
from math import gcd

def clean(t): return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')

def det(m):
    if len(m) == 1: return m[0][0]
    return sum((-1) ** j * m[0][j] * det([r[:j] + r[j + 1:] for r in m[1:]]) for j in range(len(m)))

def inv_mod26(m):
    n, d = len(m), det(m) % 26
    if gcd(d, 26) != 1: raise ValueError(f'det={d} not invertible mod 26 - choose another key')
    di = pow(d, -1, 26)
    if n == 1: return [[di]]
    return [[di * (-1) ** (i + j) * det([r[:i] + r[i + 1:] for k, r in enumerate(m) if k != j]) % 26
             for j in range(n)] for i in range(n)]

def hill(nums, k):
    n, out = len(k), []
    for i in range(0, len(nums), n):
        blk = nums[i:i + n]
        out += [sum(k[r][c] * blk[c] for c in range(n)) % 26 for r in range(n)]
    return out

msg = input('Message: ')
n = int(input('Matrix size n: '))
K = [[int(x) for x in input(f'Row {i + 1} (space separated): ').split()] for i in range(n)]
p = [ord(c) - 65 for c in clean(msg)]
p += [23] * (-len(p) % n)                       # pad with X
ct = ''.join(chr(x + 65) for x in hill(p, K))
print('Inverse key:', inv_mod26(K))
print('Ciphertext :', ct)
print('Decrypted  :', ''.join(chr(x + 97) for x in hill([ord(c) - 65 for c in ct], inv_mod26(K))))
```

## 6. Transposition: rail fence, columnar (keyed), block permutation

<!-- stdin: wearediscoveredfleeatonce | 3 | ZEBRA -->
```python
def clean(t): return ''.join(c for c in t.upper() if 'A' <= c <= 'Z')

def rail_pattern(n, rails):
    r, step, pat = 0, 1, []
    for _ in range(n):
        pat.append(r)
        if rails > 1:
            step = 1 if r == 0 else -1 if r == rails - 1 else step
            r += step
    return pat

def rail_enc(t, rails):
    t = clean(t); pat = rail_pattern(len(t), rails)
    return ''.join(c for _, c in sorted(zip(pat, t), key=lambda x: x[0]))

def rail_dec(c, rails):
    pat = rail_pattern(len(c), rails)
    order = sorted(range(len(c)), key=lambda i: pat[i])
    out = [''] * len(c)
    for ch, i in zip(c, order): out[i] = ch
    return ''.join(out).lower()

def col_enc(t, key):
    t = clean(t); n = len(key); t += 'X' * (-len(t) % n)
    order = sorted(range(n), key=lambda i: (key[i], i))
    return ''.join(t[i::n] for i in order)

def col_dec(c, key):
    n, rows = len(key), len(c) // len(key)
    order = sorted(range(n), key=lambda i: (key[i], i))
    cols = {col: c[k * rows:(k + 1) * rows] for k, col in enumerate(order)}
    return ''.join(cols[j][r] for r in range(rows) for j in range(n)).lower()

msg, rails, key = input('Message: '), int(input('Rails: ')), input('Column key word: ').upper()
c1, c2 = rail_enc(msg, rails), col_enc(msg, key)
print('Rail fence:', c1, '->', rail_dec(c1, rails))
print('Columnar  :', c2, '->', col_dec(c2, key))
```

## 7. Attacks (manual exercises 5, 6 and additional 1–2)

* **Known plaintext, shift:** `k = (C − P) mod 26`. Manual: "CIW" = "yes" → k = 4;
  "XVIEWYWI" → `treasuse` (the manual's ciphertext has a typo; intended *treasure*).
* **Affine, "ab" → "GL":** `b = G = 6`, `a + b = L = 11` → `a = 5`; decrypting the manual's
  ciphertext gives "the best of a fight is making up afterwards" (one letter off — manual typo).
* **Brute force additive near the 13th:** try keys 0..25 (or 10..16) and rank by English
  letter frequency. Key 11 → "cryptography and steganography are two sides of a coin".
* **Eve typed `abcdefghi`, saw `CABDEHFGL`:** chosen-plaintext attack. The literal
  output is not a transposition of the input: it contains `L` and loses `I`. The first
  three letters suggest a 3-letter block and permutation [2,0,1], but that would produce
  `CABFDEIGH` across all three blocks. The supplied pair cannot establish a valid fixed
  permutation key. Report the inconsistent source instead of claiming a recovered key.

<!-- stdin: XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS | ab | GL -->
```python
from math import gcd
clean = lambda t: ''.join(c for c in t.upper() if 'A' <= c <= 'Z')
VALID_A = [a for a in range(26) if gcd(a, 26) == 1]
FREQ = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
score = lambda s: sum(26 - FREQ.index(c) for c in s.upper())

def aff_dec(t, a, b):
    ai = pow(a, -1, 26)
    return ''.join(chr(ai * (ord(c) - 65 - b) % 26 + 97) for c in clean(t))

ct = input('Ciphertext: ')
known_p, known_c = input('Known plaintext (blank if none): '), input('Its ciphertext: ')
keys = [(a, b) for a in VALID_A for b in range(26)]
if known_p:                                 # known-plaintext: keep consistent keys
    P, C = [ord(x) - 65 for x in clean(known_p)], [ord(x) - 65 for x in clean(known_c)]
    keys = [(a, b) for a, b in keys if all((a * p + b) % 26 == c for p, c in zip(P, C))]
print('Candidate keys:', keys)
for a, b in sorted(keys, key=lambda k: -score(aff_dec(ct, *k)))[:5]:
    print((a, b), aff_dec(ct, a, b))
# shift cipher: same idea with a = 1 -> 26 keys;  k = (C - P) % 26
```

## 8. Check a chosen-plaintext permutation against every block

This small exhaustive search also detects the inconsistent manual pair. A fixed block
permutation must preserve every character and apply the same order to every block.

<!-- stdin: abcdefghi | CABDEHFGL | 3 -->
```python
from itertools import permutations

plain = input('Chosen plaintext: ').upper()
cipher = input('Observed ciphertext: ').upper()
n = int(input('Block size to test (1-8): '))
if not 1 <= n <= 8 or len(plain) != len(cipher) or len(plain) % n:
    raise ValueError('Use equal lengths, complete blocks, and a block size from 1 to 8')
keys = []
for order in permutations(range(n)):
    trial = ''.join(plain[start + i] for start in range(0, len(plain), n) for i in order)
    if trial == cipher:
        keys.append([i + 1 for i in order])
print('Consistent keys (1-based):', keys)
if not keys:
    print('The supplied pair does not fit a fixed permutation of this size')
```

## 9. Exam checklist (Lab 1)
* Take message and keys with `input()`; print matrix/key/intermediate values asked for.
* Validate: multiplicative/affine `gcd(a,26)=1`; Hill `gcd(det,26)=1`; Playfair I/J merge.
* Show both ciphertext **and** decrypted plaintext; mention padding letters (X) added.
* Name the attack type when asked (see §0).
