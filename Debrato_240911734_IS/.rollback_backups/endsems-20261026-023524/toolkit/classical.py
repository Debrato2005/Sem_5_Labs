"""Lab 1 - classical ciphers and attacks.  Standard library only.

Letters are A-Z (mod 26). Non-letters are dropped by `clean()` because the lab
says "ignore the space between words".  Ciphertext is UPPER, plaintext lower.
"""
from math import gcd

A = ord('A')


def clean(text):
    return ''.join(c for c in text.upper() if 'A' <= c <= 'Z')


def _nums(text):
    return [ord(c) - A for c in clean(text)]


def _text(nums, upper=True):
    s = ''.join(chr(n % 26 + A) for n in nums)
    return s if upper else s.lower()


# ------------------------------------------- additive / multiplicative / affine
# Additive:       C = (P + k) mod 26          P = (C - k) mod 26
# Multiplicative: C = (P * k) mod 26          P = (C * k^-1) mod 26, gcd(k,26)=1
# Affine:         C = (a*P + b) mod 26        P = a^-1 (C - b) mod 26
def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError(f'a={a} has no inverse mod 26 (gcd != 1)')
    return _text([(a * p + b) for p in _nums(text)])


def affine_decrypt(text, a, b):
    ai = pow(a, -1, 26)
    return _text([ai * (c - b) for c in _nums(text)], upper=False)


def additive_encrypt(text, k):
    return affine_encrypt(text, 1, k)


def additive_decrypt(text, k):
    return affine_decrypt(text, 1, k)


def multiplicative_encrypt(text, k):
    return affine_encrypt(text, k, 0)


def multiplicative_decrypt(text, k):
    return affine_decrypt(text, k, 0)


VALID_A = [a for a in range(1, 26) if gcd(a, 26) == 1]   # 12 values


# ------------------------------------------------------- Vigenere / Autokey
def vigenere_encrypt(text, key):
    k = _nums(key)
    if not k:
        raise ValueError('key must contain A-Z letters')
    return _text([p + k[i % len(k)] for i, p in enumerate(_nums(text))])


def vigenere_decrypt(text, key):
    k = _nums(key)
    if not k:
        raise ValueError('key must contain A-Z letters')
    return _text([c - k[i % len(k)] for i, c in enumerate(_nums(text))], upper=False)


def autokey_encrypt(text, key):
    """key: int (lab: key = 7) or a word. Key stream = key + PLAINTEXT."""
    p = _nums(text)
    k = [key % 26] if isinstance(key, int) else _nums(key)
    if not k:
        raise ValueError('key must contain A-Z letters')
    stream = k + p
    return _text([x + stream[i] for i, x in enumerate(p)])


def autokey_decrypt(text, key):
    stream = [key % 26] if isinstance(key, int) else _nums(key)
    if not stream:
        raise ValueError('key must contain A-Z letters')
    out = []
    for i, c in enumerate(_nums(text)):
        p = (c - stream[i]) % 26
        out.append(p)
        stream.append(p)                          # recovered plaintext extends key
    return _text(out, upper=False)


# ------------------------------------------------------------------ Playfair
def playfair_matrix(key):
    seen = []
    for c in clean(key).replace('J', 'I') + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.append(c)
    return [seen[i:i + 5] for i in range(0, 25, 5)]


def _pairs(text, filler='X'):
    t = clean(text).replace('J', 'I')
    out, i = [], 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else filler
        if a == b:                                # split doubled letters
            out.append(a + ('Q' if a == filler else filler))
            i += 1
        else:
            out.append(a + b)
            i += 2
    return out


def _pf(pairs, m, step):
    pos = {m[r][c]: (r, c) for r in range(5) for c in range(5)}
    out = ''
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:
            out += m[r1][(c1 + step) % 5] + m[r2][(c2 + step) % 5]
        elif c1 == c2:
            out += m[(r1 + step) % 5][c1] + m[(r2 + step) % 5][c2]
        else:
            out += m[r1][c2] + m[r2][c1]
    return out


def playfair_encrypt(text, key):
    return _pf(_pairs(text), playfair_matrix(key), 1)


def playfair_decrypt(text, key):
    t = clean(text)
    return _pf([t[i:i + 2] for i in range(0, len(t), 2)], playfair_matrix(key), -1).lower()


# ---------------------------------------------------------------------- Hill
def _det(m):
    if len(m) == 1:
        return m[0][0]
    return sum((-1) ** j * m[0][j] * _det([r[:j] + r[j + 1:] for r in m[1:]])
               for j in range(len(m)))


def matrix_inverse_mod(m, mod=26):
    """Inverse of square matrix modulo `mod` via adjugate (works for any n)."""
    n = len(m)
    if (n == 0 or any(len(row) != n for row in m)
            or any(type(v) is not int for row in m for v in row)
            or type(mod) is not int or mod < 2):
        raise ValueError('matrix must be nonempty and square with integer entries; modulus must be >= 2')
    d = _det(m) % mod
    if gcd(d, mod) != 1:
        raise ValueError(f'key matrix not invertible mod {mod} (det={d})')
    di = pow(d, -1, mod)
    if n == 1:
        return [[di]]
    adj = [[(-1) ** (i + j) * _det([r[:i] + r[i + 1:] for k, r in enumerate(m) if k != j])
            for j in range(n)] for i in range(n)]
    return [[(di * adj[i][j]) % mod for j in range(n)] for i in range(n)]


def _hill(nums, k):
    n = len(k)
    out = []
    for i in range(0, len(nums), n):
        blk = nums[i:i + n]
        out += [sum(k[r][c] * blk[c] for c in range(n)) % 26 for r in range(n)]
    return out


def hill_encrypt(text, key, filler='X'):
    """key: list of rows, e.g. [[3,3],[2,7]].  C = K * P (column vectors)."""
    matrix_inverse_mod(key)                      # validate invertibility first
    p = _nums(text)
    while len(p) % len(key):
        p.append(ord(filler) - A)
    return _text(_hill(p, key))


def hill_decrypt(text, key):
    if not key or len(_nums(text)) % len(key):
        raise ValueError('ciphertext length must be a multiple of the matrix size')
    return _text(_hill(_nums(text), matrix_inverse_mod(key)), upper=False)


# ------------------------------------------------------------- transposition
def rail_fence_encrypt(text, rails):
    if type(rails) is not int or rails < 1:
        raise ValueError('rails must be a positive integer')
    t = clean(text)
    rows = [''] * rails
    r, step = 0, 1
    for c in t:
        rows[r] += c
        if rails > 1:
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
    return ''.join(rows)


def rail_fence_decrypt(text, rails):
    if type(rails) is not int or rails < 1:
        raise ValueError('rails must be a positive integer')
    n = len(text)
    pattern, r, step = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if rails > 1:
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
    order = sorted(range(n), key=lambda i: pattern[i])
    out = [''] * n
    for ch, i in zip(text, order):
        out[i] = ch
    return ''.join(out).lower()


def columnar_encrypt(text, key, filler='X'):
    """Keyed (columnar) transposition. key = word or list of column order."""
    t = clean(text)
    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    cols = len(key)
    if cols == 0:
        raise ValueError('key must be nonempty')
    while len(t) % cols:
        t += filler
    rows = [t[i:i + cols] for i in range(0, len(t), cols)]
    return ''.join(''.join(r[c] for r in rows) for c in order)


def columnar_decrypt(text, key):
    cols = len(key)
    if cols == 0 or len(text) % cols:
        raise ValueError('key must be nonempty and ciphertext length must be a multiple of key length')
    nrows = len(text) // cols
    order = sorted(range(cols), key=lambda i: (key[i], i))
    grid = [[''] * cols for _ in range(nrows)]
    k = 0
    for c in order:
        for r in range(nrows):
            grid[r][c] = text[k]
            k += 1
    return ''.join(''.join(r) for r in grid).lower()


def permutation_encrypt(text, perm, filler='X'):
    """Block permutation: output position i takes input position perm[i] (0-based)."""
    t = clean(text)
    m = len(perm)
    if m == 0 or sorted(perm) != list(range(m)):
        raise ValueError('perm must contain each position 0..n-1 exactly once')
    while len(t) % m:
        t += filler
    return ''.join(''.join(t[i + p] for p in perm) for i in range(0, len(t), m))


def permutation_decrypt(text, perm):
    m = len(perm)
    if m == 0 or sorted(perm) != list(range(m)) or len(text) % m:
        raise ValueError('invalid permutation or incomplete ciphertext block')
    out = []
    for i in range(0, len(text), m):
        blk = [''] * m
        for j, p in enumerate(perm):
            blk[p] = text[i + j]
        out.append(''.join(blk))
    return ''.join(out).lower()


# ------------------------------------------------------------------- attacks
ENGLISH = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'


def english_score(text):
    """Higher = more English-like (letter-frequency rank score)."""
    return sum(26 - ENGLISH.index(c) for c in clean(text))


def brute_additive(ct):
    return [(k, additive_decrypt(ct, k)) for k in range(26)]


def brute_affine(ct):
    return [((a, b), affine_decrypt(ct, a, b)) for a in VALID_A for b in range(26)]


def additive_key_from_pair(plain, cipher):
    """Known-plaintext attack on shift cipher: k = (C - P) mod 26."""
    P, C = _nums(plain), _nums(cipher)
    if not P or len(P) != len(C):
        raise ValueError('known plaintext and ciphertext must have equal nonzero lengths')
    ks = {(c - p) % 26 for p, c in zip(P, C)}
    if len(ks) != 1:
        raise ValueError('pair is not consistent with a single shift')
    return ks.pop()


def affine_keys_from_pair(plain, cipher):
    """All (a, b) that map every known plaintext letter to its ciphertext."""
    P, C = _nums(plain), _nums(cipher)
    if not P or len(P) != len(C):
        raise ValueError('known plaintext and ciphertext must have equal nonzero lengths')
    return [(a, b) for a in VALID_A for b in range(26)
            if all((a * p + b) % 26 == c for p, c in zip(P, C))]


def permutation_from_chosen(plain, cipher, size):
    """Chosen-plaintext: recover block permutation from plaintext 'abc..' run."""
    P, C = clean(plain), clean(cipher)
    return [P[:size].index(C[i]) for i in range(size)]
