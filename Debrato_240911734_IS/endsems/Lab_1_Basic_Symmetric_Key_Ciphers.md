# IS LAB 1 — Basic Symmetric Key Ciphers

**Purpose:** Midsem-ready reference for every Lab 1 component in the manual. All programs are **user-input based**, with no question-specific plaintext/key hardcoded. Implementations are from scratch unless explicitly marked optional.

**Manual scope:** additive/Caesar, multiplicative, affine, Vigenère, autokey, Playfair, Hill, transposition, and classical-cipher attacks/brute force. The manual also warns that exam questions may contain **variations/combinations** of lab questions, so these are written as reusable functions.

---

## 0. Fast decision table

| If the question says... | Use |
|---|---|
| shift / Caesar / additive | `mono(text, 1, key)` |
| multiplicative | `mono(text, key, 0)` |
| affine `(a,b)` | `mono(text, a, b)` |
| repeating keyword | `vigenere()` |
| initial key followed by plaintext as key | `autokey()` |
| 5×5 square, I/J together, digraphs | `playfair()` |
| matrix key | `hill2()` or generic `hill()` |
| rearrange positions only | `rail()` / `permute()` |
| try every shift | `brute_caesar()` |
| try all affine keys | `brute_affine()` |
| known plaintext + ciphertext | `find_affine_key()` / derive Caesar shift |

### Core formulas

- Additive: `C = (P + k) mod 26`, `P = (C - k) mod 26`
- Multiplicative: `C = kP mod 26`, `P = k⁻¹C mod 26`; require `gcd(k,26)=1`
- Affine: `C = (aP+b) mod 26`, `P = a⁻¹(C-b) mod 26`; require `gcd(a,26)=1`
- Vigenère: `Cᵢ=(Pᵢ+Kᵢ) mod 26`
- Autokey: initial key followed by plaintext symbols
- Hill: `C = KP mod 26`, `P = K⁻¹C mod 26`

`A=0, B=1, ..., Z=25` unless the question explicitly specifies another mapping.

---

# 1. Additive + Multiplicative + Affine in ONE function

This one function covers all three manual ciphers while preserving case, spaces and punctuation.

```python
# Additive / Multiplicative / Affine cipher
from math import gcd

def mono(text,a=1,b=0,decrypt=False):
    a%=26; b%=26
    if gcd(a,26)!=1: raise ValueError("a/key must be coprime with 26")
    inv=pow(a,-1,26)
    out=[]
    for ch in text:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            x=ord(ch)-base
            y=(inv*(x-b) if decrypt else a*x+b)%26
            out.append(chr(base+y))
        else: out.append(ch)
    return ''.join(out)

kind=input("Cipher [add/mul/aff]: ").lower()
t=input("Plaintext: ")
if kind.startswith("add"):
    a,b=1,int(input("Key: "))
elif kind.startswith("mul"):
    a,b=int(input("Key: ")),0
else:
    a,b=map(int,input("Enter a b: ").split())

c=mono(t,a,b)
print("Ciphertext:",c)
print("Decrypted :",mono(c,a,b,True))
```

### Minimal calls

```python
# Additive
c=mono(text,1,k)
p=mono(c,1,k,True)

# Multiplicative
c=mono(text,k,0)
p=mono(c,k,0,True)

# Affine
c=mono(text,a,b)
p=mono(c,a,b,True)
```

### Critical validity rule

For multiplicative/affine, the multiplicative key must have an inverse modulo 26:

```python
from math import gcd
print(gcd(a,26)==1)
```

Valid values of `a` modulo 26 are:

`1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`

---

# 2. Vigenère Cipher

Repeats a user-entered keyword. Key advances only for alphabetic characters.

```python
# Vigenere encryption + decryption

def vigenere(text,key,decrypt=False):
    k=[ord(c.upper())-65 for c in key if c.isalpha()]
    if not k: raise ValueError("Key must contain letters")
    out=[]; j=0
    for ch in text:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            x=ord(ch)-base
            s=k[j%len(k)]*(-1 if decrypt else 1)
            out.append(chr(base+(x+s)%26)); j+=1
        else: out.append(ch)
    return ''.join(out)

t=input("Plaintext: ")
k=input("Keyword: ")
c=vigenere(t,k)
print("Ciphertext:",c)
print("Decrypted :",vigenere(c,k,True))
```

---

# 3. Autokey Cipher

Supports either a **numeric initial key** such as `7` or an alphabetic seed such as `QUEEN`.

```python
# Autokey encryption + decryption

def seedvals(seed):
    s=str(seed).strip()
    if s.lstrip('-').isdigit(): return [int(s)%26]
    k=[ord(c.upper())-65 for c in s if c.isalpha()]
    if not k: raise ValueError("Seed must be a number or letters")
    return k

def autokey(text,seed,decrypt=False):
    stream=seedvals(seed)
    out=[]; j=0
    for ch in text:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            x=ord(ch)-base; k=stream[j]
            y=(x-k if decrypt else x+k)%26
            out.append(chr(base+y))
            stream.append(y if decrypt else x)
            j+=1
        else: out.append(ch)
    return ''.join(out)

t=input("Plaintext: ")
k=input("Initial key/seed: ")
c=autokey(t,k)
print("Ciphertext:",c)
print("Decrypted :",autokey(c,k,True))
```

**Why decryption is different:** the plaintext is part of the future keystream, so during decryption each recovered plaintext character must be appended back to the key stream.

---

# 4. Playfair Cipher

Rules used:
- remove nonletters
- merge `J` into `I`
- 5×5 key square
- split plaintext into digraphs
- insert `X` between repeated letters in a pair
- append `X` if final length is odd

```python
# Playfair encryption + decryption

def clean(s): return ''.join(c for c in s.upper() if c.isalpha())

def pf_square(key):
    seq=clean(key).replace('J','I')+'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    sq=[]
    for c in seq:
        if c not in sq: sq.append(c)
    return sq

def pf_pairs(text):
    s=clean(text).replace('J','I'); out=[]; i=0
    while i<len(s):
        a=s[i]
        if i+1>=len(s): b='X'; i+=1
        elif s[i+1]==a: b='X'; i+=1
        else: b=s[i+1]; i+=2
        out.append(a+b)
    return out

def playfair(text,key,decrypt=False):
    sq=pf_square(key); pos={c:divmod(i,5) for i,c in enumerate(sq)}
    s=clean(text).replace('J','I')
    if decrypt:
        if len(s)%2: raise ValueError("Ciphertext length must be even")
        pairs=[s[i:i+2] for i in range(0,len(s),2)]
    else: pairs=pf_pairs(s)
    step=-1 if decrypt else 1; out=[]
    for a,b in pairs:
        r1,c1=pos[a]; r2,c2=pos[b]
        if r1==r2:
            out += [sq[5*r1+(c1+step)%5],sq[5*r2+(c2+step)%5]]
        elif c1==c2:
            out += [sq[5*((r1+step)%5)+c1],sq[5*((r2+step)%5)+c2]]
        else:
            out += [sq[5*r1+c2],sq[5*r2+c1]]
    return ''.join(out)

k=input("Key: ")
t=input("Plaintext: ")
print("Matrix:")
sq=pf_square(k)
for i in range(0,25,5): print(*sq[i:i+5])
c=playfair(t,k)
print("Ciphertext:",c)
print("Decrypted :",playfair(c,k,True))
```

**Important:** decrypted Playfair text may still contain filler `X` characters. Removing them automatically is unsafe because a real `X` is indistinguishable from a filler in the general case.

---

# 5. Hill Cipher — shortest 2×2 version for the manual

The Lab 1 manual uses a 2×2 key. Enter four integers row-wise.

```python
# Hill 2x2 encryption + decryption
from math import gcd

def clean(s): return ''.join(c for c in s.upper() if c.isalpha())

def hill2(text,key,decrypt=False):
    if len(key)!=4: raise ValueError("Enter 4 integers row-wise")
    a,b,c,d=[int(x)%26 for x in key]
    det=(a*d-b*c)%26
    if gcd(det,26)!=1: raise ValueError("Key matrix is not invertible mod 26")
    if decrypt:
        z=pow(det,-1,26)
        a,b,c,d=(d*z)%26,(-b*z)%26,(-c*z)%26,(a*z)%26
    s=clean(text)
    if len(s)%2: s+='X'
    out=[]
    for i in range(0,len(s),2):
        x,y=ord(s[i])-65,ord(s[i+1])-65
        out += [chr((a*x+b*y)%26+65),chr((c*x+d*y)%26+65)]
    return ''.join(out)

K=list(map(int,input("Enter 4 key values row-wise: ").split()))
t=input("Plaintext: ")
c=hill2(t,K)
print("Ciphertext:",c)
print("Decrypted :",hill2(c,K,True))
```

### Hill validity

For a 2×2 key

`K = [[a,b],[c,d]]`

`det(K)=ad-bc`

The matrix is decryptable only if:

```python
from math import gcd
valid = gcd((a*d-b*c)%26,26)==1
```

---

# 6. Hill Cipher — generic n×n backup

Use this if the exam changes the Hill key from 2×2 to 3×3 or another square size.

Requires:

```bash
pip install sympy
```

```python
# Generic n x n Hill cipher
from math import gcd
from sympy import Matrix

def clean(s): return ''.join(c for c in s.upper() if c.isalpha())

def hill(text,K,decrypt=False):
    n=len(K)
    if n<1 or any(len(r)!=n for r in K): raise ValueError("Key must be square")
    M=Matrix(K)
    if gcd(int(M.det()),26)!=1: raise ValueError("Key not invertible mod 26")
    if decrypt: M=M.inv_mod(26)
    s=clean(text); s+='X'*(-len(s)%n); out=[]
    for i in range(0,len(s),n):
        v=Matrix([ord(c)-65 for c in s[i:i+n]])
        out += [chr(int(x)%26+65) for x in M*v]
    return ''.join(out)

n=int(input("Matrix size n: "))
K=[list(map(int,input(f"Row {i+1}: ").split())) for i in range(n)]
t=input("Plaintext: ")
c=hill(t,K)
print("Ciphertext:",c)
print("Decrypted :",hill(c,K,True))
```

---

# 7. Keyless Transposition — Rail Fence

The manual names keyless transposition but does not prescribe one exact algorithm. Rail Fence is a compact generic implementation if such a variation is asked.

```python
# Rail Fence encryption + decryption

def rail(text,k,decrypt=False):
    k=int(k)
    if k<=1 or k>=len(text): return text
    p=list(range(k))+list(range(k-2,0,-1))
    rows=[p[i%len(p)] for i in range(len(text))]
    if not decrypt:
        return ''.join(text[i] for r in range(k) for i,x in enumerate(rows) if x==r)
    out=['']*len(text); j=0
    for r in range(k):
        for i,x in enumerate(rows):
            if x==r: out[i]=text[j]; j+=1
    return ''.join(out)

t=input("Plaintext: ")
k=int(input("Rails: "))
c=rail(t,k)
print("Ciphertext:",c)
print("Decrypted :",rail(c,k,True))
```

---

# 8. Keyed Transposition — permutation cipher

Useful for the manual's keyed-transposition/chosen-plaintext attack style. Enter the permutation in 1-based form such as `3 1 2`.

Meaning: for each block, ciphertext takes plaintext positions in that order.

```python
# Keyed permutation transposition

def permute(text,key,decrypt=False,pad='X'):
    k=[int(x)-1 for x in key]; n=len(k)
    if sorted(k)!=list(range(n)): raise ValueError("Key must be a permutation of 1..n")
    if decrypt: k=[k.index(i) for i in range(n)]
    if not decrypt: text+=pad*(-len(text)%n)
    elif len(text)%n: raise ValueError("Ciphertext length must be multiple of key size")
    return ''.join(''.join(b[i] for i in k) for b in [text[j:j+n] for j in range(0,len(text),n)])

t=input("Plaintext: ")
k=input("Permutation, e.g. 3 1 2: ").split()
c=permute(t,k)
print("Ciphertext:",c)
print("Decrypted :",permute(c,k,True))
```

---

# 9. Brute-force Additive / Caesar

Tries every possible shift.

```python
# Caesar brute force

def brute_caesar(ct):
    for k in range(26): print(k,mono(ct,1,k,True))

brute_caesar(input("Ciphertext: "))
```

Look through the 26 results for readable English.

---

# 10. Brute-force Multiplicative

Only invertible keys modulo 26 are valid.

```python
# Multiplicative brute force
from math import gcd

def brute_multiplicative(ct):
    for k in range(26):
        if gcd(k,26)==1: print(k,mono(ct,k,0,True))

brute_multiplicative(input("Ciphertext: "))
```

---

# 11. Brute-force Affine

There are only `12 × 26 = 312` valid affine keys.

```python
# Affine brute force
from math import gcd

def brute_affine(ct):
    for a in range(26):
        if gcd(a,26)==1:
            for b in range(26): print(a,b,mono(ct,a,b,True))

brute_affine(input("Ciphertext: "))
```

---

# 12. Find an Affine key from known plaintext/ciphertext

This is better than manually solving simultaneous congruences during the exam.

```python
# Find every affine key matching known plaintext/ciphertext
from math import gcd

def letters(s): return ''.join(c for c in s.upper() if c.isalpha())

def find_affine_key(plain,cipher):
    p,c=letters(plain),letters(cipher)
    if len(p)!=len(c): raise ValueError("Known strings must have same number of letters")
    ans=[]
    for a in range(26):
        if gcd(a,26)==1:
            for b in range(26):
                if all((a*(ord(x)-65)+b)%26==ord(y)-65 for x,y in zip(p,c)):
                    ans.append((a,b))
    return ans

p=input("Known plaintext: ")
c=input("Known ciphertext: ")
keys=find_affine_key(p,c)
print("Possible keys:",keys)
ct=input("Ciphertext to decrypt: ")
for a,b in keys: print((a,b),mono(ct,a,b,True))
```

For the manual's known pair `ab -> GL` under `A=0`, the unique affine key is `(a,b)=(5,6)`.

---

# 13. Find Caesar/Additive key from known plaintext

```python
# Known-plaintext attack on Caesar/Additive

def caesar_key(plain,cipher):
    p=''.join(c for c in plain.upper() if c.isalpha())
    c=''.join(c for c in cipher.upper() if c.isalpha())
    if len(p)!=len(c) or not p: raise ValueError("Need equal non-empty letter strings")
    ks={(ord(y)-ord(x))%26 for x,y in zip(p,c)}
    return ks.pop() if len(ks)==1 else None

p=input("Known plaintext: ")
c=input("Known ciphertext: ")
k=caesar_key(p,c)
print("Key:",k)
if k is not None:
    x=input("Other ciphertext: ")
    print("Decrypted:",mono(x,1,k,True))
```

### Manual trap worth remembering

From `YES -> CIW`, the shift is `4`.

Using that key on the manual's literal ciphertext `XVIEWYWI` gives:

`TREASUSE`

So the printed ciphertext is internally inconsistent with the obvious English word **TREASURE**. Do not silently change exam input; decrypt exactly what is provided, and if needed mention that the source appears to contain a typo.

---

# 14. Brute-force a small keyed permutation

Only practical for small key sizes because the search is `n!`.

```python
# Recover a small permutation key from chosen/known plaintext
from itertools import permutations

def find_perm(plain,cipher,n):
    for k in permutations(range(1,n+1)):
        if permute(plain,k)==cipher: print(k)

p=input("Known plaintext: ")
c=input("Known ciphertext: ")
n=int(input("Key size: "))
find_perm(p,c,n)
```

---

# 15. Attack-type cheat sheet

### Ciphertext-only attack
Attacker has only ciphertext and tries to infer plaintext/key.

### Known-plaintext attack
Attacker knows one or more plaintext ↔ ciphertext pairs and uses them to recover the key.

Example pattern from the manual: knowing that `YES` became `CIW` under a shift cipher.

### Chosen-plaintext attack
Attacker can choose plaintext and observe the produced ciphertext.

Example pattern from the manual: Eve types a chosen sequence such as `abcdefghi` into Alice's cipher and observes the output.

### Brute-force attack
Try every key in the feasible keyspace until meaningful plaintext appears.

---

# 16. Exact manual-question checkpoints

These are useful to verify that your functions are behaving consistently with the Lab 1 conventions.

### Additive / Multiplicative / Affine
Manual plaintext: `I am learning information security`.

Use user input for the plaintext and keys; do **not** hardcode them into your exam program.

### Vigenère / Autokey
Manual plaintext: `the house is being sold tonight`.

Again, the code above accepts any plaintext/key.

### Playfair
The manual uses key `GUIDANCE`; its square is:

```text
G U I D A
N C E B F
H K L M O
P Q R S T
V W X Y Z
```

### Hill
Manual key is the 2×2 matrix:

```text
3 3
2 7
```

The 2×2 implementation above reads the same matrix as:

```text
3 3 2 7
```

### Affine known-plaintext exercise
For `ab -> GL`, `find_affine_key()` returns `(5,6)`.

Decrypting the **literal** manual ciphertext with `(5,6)` gives:

`THEBESTOFAFIGHTISMAKINGUPAKTERWARDS`

The `AKTERWARDS` spelling is what follows mathematically from the manual's literal ciphertext; it appears to be another source typo rather than a cipher-code error.

---

# 17. Common midsem mistakes

1. **Multiplicative/Affine key not invertible:** always check `gcd(a,26)==1`.
2. **Wrong alphabet mapping:** these implementations use `A=0`.
3. **Vigenère key moving over spaces:** this code advances only on letters.
4. **Autokey decryption:** append recovered plaintext, not ciphertext.
5. **Playfair repeated pair:** insert `X` and re-process the second repeated letter.
6. **Playfair J:** merge `J -> I`.
7. **Hill inverse:** ordinary decimal matrix inverse is wrong; inverse must be modulo 26.
8. **Hill orientation:** these functions use column plaintext vectors and row-wise input matrix.
9. **Hill padding:** extra trailing `X` after decryption can be padding.
10. **Attack terminology:** chosen plaintext means the attacker chooses what is encrypted; known plaintext means the pair is merely known.
11. **Manual typos:** trust the literal characters given in the exam and show the mathematically obtained output.

---

# 18. Minimum dependencies

Everything except generic n×n Hill uses only Python's standard library.

```bash
pip install sympy
```

is needed only for the optional generic Hill implementation.

---

# 19. Ultra-short exam assembly pattern

When a scenario combines algorithms, define only the functions you need, then do:

```python
text=input("Enter text: ")
# read ALL keys/parameters using input()
# encrypt
# print ciphertext / keys / intermediate values requested
# decrypt
# print recovered plaintext
```

Never bury a question's message, key, IV, matrix, or parameters inside the function. Read them using `input()` so the same code survives question variations.
