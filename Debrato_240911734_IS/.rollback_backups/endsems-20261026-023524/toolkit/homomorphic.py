"""Lab 7 - partially homomorphic encryption, implemented from scratch
(no `phe` needed; only Crypto.Util.number for primes).

Paillier (ADDITIVE):   E(a)*E(b) mod n^2 = E(a+b)      E(a)^k = E(k*a)
RSA textbook (MULT):   E(a)*E(b) mod n   = E(a*b)
ElGamal (MULT):        (a1*a2, b1*b2)    = E(m1*m2)
Exp-ElGamal (ADD):     E(g^m) multiplies -> g^(m1+m2); small totals only.

Keys are plain ints / dicts of ints, so json.dump persists them directly.
Negative values are supported: decrypt() maps results > n/2 to negatives.
Arithmetic is modulo n. Keep the absolute result <= n//2 for signed
answers. Ciphertexts alone cannot reveal whether an aggregate overflowed.
"""
from fractions import Fraction
from math import factorial, gcd

from Crypto.Random import random
from Crypto.Util.number import getPrime, isPrime


def _paillier_n(pub):
    n = pub['n']
    if type(n) is not int or n < 9 or n % 2 == 0:
        raise ValueError('n must be an odd integer >= 9')
    return n


def _paillier_ciphertext(n, c):
    if type(c) is not int or not 0 < c < n * n or gcd(c, n) != 1:
        raise ValueError('ciphertext must be a unit in 1..n^2-1')


def _integer(value, name):
    if type(value) is not int:
        raise ValueError(f'{name} must be an integer')
    return value


# ================================================================== Paillier
def paillier_keygen(bits=2048):
    """-> (pub, priv).  pub = {'n'}, priv = {'n','lam','mu'}; g = n + 1."""
    if type(bits) is not int or bits < 8:
        raise ValueError('bits must be an integer >= 8')
    while True:
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        n = p * q
        if p != q and gcd(n, (p - 1) * (q - 1)) == 1:
            break
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)        # lcm(p-1, q-1)
    mu = pow(lam, -1, n)                                # valid because g = n + 1
    return {'n': n}, {'n': n, 'lam': lam, 'mu': mu}


def paillier_keys_from_pq(p, q):
    """Numerical questions with given small primes p, q."""
    if (type(p) is not int or type(q) is not int or p <= 2 or q <= 2
            or p == q or not isPrime(p) or not isPrime(q)):
        raise ValueError('p and q must be distinct odd primes')
    n = p * q
    if gcd(n, (p - 1) * (q - 1)) != 1:
        raise ValueError('gcd(n, phi) != 1 - pick other primes')
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    g = n + 1
    mu = pow((pow(g, lam, n * n) - 1) // n, -1, n)      # mu = L(g^lam mod n^2)^-1
    return {'n': n}, {'n': n, 'lam': lam, 'mu': mu}


def paillier_encrypt(pub, m, r=None):
    """c = g^m * r^n mod n^2 with g = n+1  ->  (1 + m n) r^n mod n^2.
    r is random unless given (re-encryption check: same m, r -> same c)."""
    n = _paillier_n(pub)
    n2 = n * n
    _integer(m, 'm')
    if not -(n // 2) <= m <= n // 2:
        raise ValueError('|m| too large for this key')
    if r is None:
        r = random.randint(1, n - 1)
        while gcd(r, n) != 1:
            r = random.randint(1, n - 1)
    elif type(r) is not int or not 0 < r < n or gcd(r, n) != 1:
        raise ValueError('r must be a unit in 1..n-1')
    return (1 + (m % n) * n) * pow(r, n, n2) % n2


def paillier_decrypt(priv, c):
    """m = L(c^lam mod n^2) * mu mod n, where L(u) = (u - 1) / n."""
    n = _paillier_n(priv)
    n2 = n * n
    _paillier_ciphertext(n, c)
    u = pow(c, priv['lam'], n2)
    if (u - 1) % n:
        raise ValueError('ciphertext is incompatible with this private key')
    m = (u - 1) // n * priv['mu'] % n
    return m - n if m > n // 2 else m


def paillier_add(pub, *cts):
    """E(m1) * E(m2) * ... mod n^2 = E(m1 + m2 + ...)."""
    n = _paillier_n(pub)
    n2 = n ** 2
    out = 1
    for c in cts:
        _paillier_ciphertext(n, c)
        out = out * c % n2
    return out


def paillier_add_const(pub, c, k):
    """E(m) * g^k = E(m + k)."""
    n = _paillier_n(pub)
    _paillier_ciphertext(n, c)
    _integer(k, 'k')
    return c * (1 + (k % n) * n) % (n * n)


def paillier_mul_const(pub, c, k):
    """E(m)^k = E(k * m)  (k is a PLAIN integer; k = -1 negates)."""
    n = _paillier_n(pub)
    _paillier_ciphertext(n, c)
    _integer(k, 'k')
    n2 = n ** 2
    return pow(c, k, n2)


def paillier_sub(pub, c1, c2):
    """E(m1 - m2)."""
    return paillier_add(pub, c1, paillier_mul_const(pub, c2, -1))


def paillier_weighted_sum(pub, cts, weights):
    """E(sum w_i * m_i) with PUBLIC integer weights."""
    cts, weights = list(cts), list(weights)
    if len(cts) != len(weights):
        raise ValueError('each ciphertext needs one weight')
    return paillier_add(pub, *[paillier_mul_const(pub, c, w) for c, w in zip(cts, weights)])


def paillier_rerandomize(pub, c):
    return paillier_add(pub, c, paillier_encrypt(pub, 0))


# ---- encrypted voting / counting: one-hot vectors -------------------------
def encrypt_one_hot(pub, choice, options, rand=None):
    """{option: E(1 if option == choice else 0)}.  Summing these per option
    gives per-candidate COUNTS (summing candidate IDs would not).
    rand: optional {option: r} to make the encryption reproducible/checkable."""
    if choice not in options:
        raise ValueError('invalid choice')
    rand = rand or {}
    return {str(o): paillier_encrypt(pub, int(o == choice), rand.get(str(o))) for o in options}


def tally(pub, ballots, options):
    """ballots: list of one-hot dicts -> {option: E(count)} (no decryption)."""
    return {str(o): paillier_add(pub, *[b[str(o)] for b in ballots]) for o in options}


# ======================================= Threshold Paillier (t-of-N, dealer) =
def paillier_threshold_keygen(bits, t, parties):
    """Cooperative threshold arithmetic demo with a trusted dealer.
    d = 0 (mod lam), d = 1 (mod n); polynomial shares use the composite
    ring Z_(n*lam), not a Shamir field. Any t honest shares recover m.
    This code has no privacy proof or malicious-share verification.
    The dealer and calling process see all shares. Deleting local names
    does not securely erase key material from memory."""
    if type(t) is not int or type(parties) is not int or not 1 <= t <= parties:
        raise ValueError('need 1 <= t <= parties')
    pub, priv = paillier_keygen(bits)
    n, lam = priv['n'], priv['lam']
    if gcd(factorial(parties), n) != 1:
        raise ValueError('party factorial must be invertible modulo n; use a larger key')
    mod = n * lam
    d = lam * pow(lam, -1, n) % mod                     # CRT: d=0 mod lam, d=1 mod n
    coeffs = [d] + [random.randint(0, mod - 1) for _ in range(t - 1)]
    shares = [(i, sum(a * i ** j for j, a in enumerate(coeffs)) % mod)
              for i in range(1, parties + 1)]
    pub.update(t=t, parties=parties)
    del priv, lam, d, coeffs
    return pub, shares


def partial_decrypt(pub, share, c):
    """Authority i publishes c_i = c^(s_i) mod n^2 (its share never leaves it)."""
    i, s = share
    n, _, parties = _threshold_parameters(pub)
    if type(i) is not int or not 1 <= i <= parties:
        raise ValueError('authority ID must be in 1..parties')
    if type(s) is not int or s < 0:
        raise ValueError('share must be a nonnegative integer')
    _paillier_ciphertext(n, c)
    return i, pow(c, s, n ** 2)


def _threshold_parameters(pub):
    n = _paillier_n(pub)
    t, parties = pub['t'], pub['parties']
    if type(t) is not int or type(parties) is not int or not 1 <= t <= parties:
        raise ValueError('need 1 <= t <= parties')
    if gcd(factorial(parties), n) != 1:
        raise ValueError('party factorial must be invertible modulo n')
    return n, t, parties


def combine_partials(pub, partials):
    """c' = prod c_i^(L_i) with integer Lagrange coefficients
    L_i = Delta * prod j/(j-i), Delta = N!.  Since sum L_i*s_i = Delta*d
    (mod n*lam):  c' = c^(Delta*d) = 1 + Delta*m*n (mod n^2)  ->  m."""
    n, t, N = _threshold_parameters(pub)
    n2 = n * n
    items = list(partials)
    partials = {}
    for i, part in items:
        if type(i) is not int or not 1 <= i <= N or i in partials:
            raise ValueError('partial decryptions need distinct authority IDs in 1..parties')
        _paillier_ciphertext(n, part)
        partials[i] = part
    if len(partials) < t:
        raise ValueError(f'need {t} partial decryptions, got {len(partials)}')
    ids = sorted(partials)[:t]
    delta = factorial(N)
    acc = 1
    for i in ids:
        lag = Fraction(delta)
        for j in ids:
            if j != i:
                lag *= Fraction(j, j - i)
        if lag.denominator != 1:
            raise ValueError('nonintegral Lagrange coefficient')
        acc = acc * pow(partials[i], lag.numerator, n2) % n2   # negative exp = inverse
    # This catches some corrupt shares, not every malicious partial decryption.
    if (acc - 1) % n:
        raise ValueError('inconsistent partial decryptions')
    m = (acc - 1) // n * pow(delta, -1, n) % n
    return m - n if m > n // 2 else m


# ===================================================== textbook RSA (MULT) ==
def rsa_mult_keygen(bits=1024, e=65537):
    from Crypto.PublicKey import RSA
    k = RSA.generate(bits, e=e)
    return (k.n, k.e), (k.n, k.d)


def rsa_mult_encrypt(pub, m):
    n, e = pub
    if not 0 <= m < n:
        raise ValueError('need 0 <= m < n')
    return pow(m, e, n)


def rsa_mult_decrypt(priv, c):
    n, d = priv
    return pow(c, d, n)


def rsa_mult(pub, c1, c2):
    """E(a) * E(b) mod n = E(a*b mod n).  Textbook RSA is deterministic/insecure."""
    return c1 * c2 % pub[0]


# ================================================= ElGamal (MULT and ADD) ===
def elgamal_he_keygen(bits=1024, p=None, g=None):
    """Random prime p and base g unless the question gives them.  (Correctness
    of encrypt/decrypt/multiply does not depend on g being a generator.)"""
    if p is None:
        if type(bits) is not int or bits < 3:
            raise ValueError('bits must be an integer >= 3')
        p = getPrime(bits)
        if g is None:
            g = random.randint(2, p - 2)
    if type(p) is not int or p < 5 or not isPrime(p) or type(g) is not int or not 1 < g < p - 1:
        raise ValueError('need a prime p >= 5 and 1 < g < p-1')
    x = random.randint(2, p - 2)
    while pow(g, x, p) in (1, p - 1):
        x = random.randint(2, p - 2)
    return (p, g, pow(g, x, p)), x


def elgamal_he_encrypt(pub, m):
    p, g, y = pub
    if (any(type(v) is not int for v in (p, g, y)) or p < 5
            or not 1 < g < p - 1 or not 1 < y < p - 1):
        raise ValueError('invalid ElGamal public key')
    if type(m) is not int or not 0 < m < p:
        raise ValueError('need 0 < m < p')
    k = random.randint(2, p - 2)
    return pow(g, k, p), m * pow(y, k, p) % p


def elgamal_he_decrypt(pub, x, c):
    p = pub[0]
    if (any(type(v) is not int for v in (p, x, *c)) or len(c) != 2 or p < 5
            or not 1 <= x <= p - 2 or not 0 < c[0] < p or not 0 < c[1] < p):
        raise ValueError('invalid ElGamal private key or ciphertext')
    return c[1] * pow(pow(c[0], x, p), -1, p) % p


def elgamal_mult(pub, c1, c2):
    """(a1 a2, b1 b2) decrypts to m1 * m2 mod p."""
    p = pub[0]
    return c1[0] * c2[0] % p, c1[1] * c2[1] % p


def exp_elgamal_encrypt(pub, m):
    """Additive ('exponential') ElGamal: encrypt g^m."""
    p, g, _ = pub
    return elgamal_he_encrypt(pub, pow(g, m, p))


def exp_elgamal_decrypt(pub, x, c, max_m=10_000):
    """Decrypt to g^m, then brute-force the small discrete log m <= max_m."""
    p, g, _ = pub
    gm = elgamal_he_decrypt(pub, x, c)
    acc = 1
    for m in range(max_m + 1):
        if acc == gm:
            return m
        acc = acc * g % p
    raise ValueError('result larger than max_m')
