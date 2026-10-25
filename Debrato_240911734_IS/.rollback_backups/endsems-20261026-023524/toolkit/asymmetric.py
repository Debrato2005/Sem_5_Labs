"""Labs 3-4 - RSA (OAEP, hybrid, textbook, weak-key attack), ElGamal, Rabin,
Diffie-Hellman, ECC (ECDH + ECIES-style encryption).  Needs pycryptodome.

KEY RULE  encryption: receiver PUBLIC encrypts, receiver PRIVATE decrypts.
          signature : sender PRIVATE signs,   sender PUBLIC verifies (signatures.py).
"""
import hashlib
from math import gcd, isqrt

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256, SHA512
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import getPrime, isPrime
from Crypto.Util.Padding import pad, unpad

# RFC 3526 group 14: 2048-bit safe prime p = 2q + 1, generator g = 2 (order q).
# Use it whenever the question does not give p and g (instant, no prime search).
G14_P = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
G14_G = 2


def text_blocks(data, modulus):
    """Byte blocks plus a final length marker, all strictly below modulus.
    The encrypted marker preserves leading NUL bytes in the final block.
    This framed format replaces the old, lossy text ciphertext format."""
    if type(modulus) is not int or modulus < 256:
        raise ValueError('modulus must be >= 256 to encode every byte')
    size = (modulus.bit_length() - 1) // 8
    blocks = [int.from_bytes(data[i:i + size], 'big') for i in range(0, len(data), size)]
    if blocks:
        blocks.append((len(data) - 1) % size + 1)
    return blocks, size


def blocks_text(ints, size):
    if type(size) is not int or size < 1:
        raise ValueError('block size must be a positive integer')
    if not ints:
        return b''
    if len(ints) < 2 or not 1 <= ints[-1] <= size:
        raise ValueError('invalid final block length marker')
    if any(type(i) is not int or not 0 <= i < 256 ** size for i in ints[:-1]):
        raise ValueError('invalid plaintext block')
    return b''.join(i.to_bytes(size, 'big') for i in ints[:-2]) + ints[-2].to_bytes(ints[-1], 'big')


# ======================================================================= RSA
def rsa_generate(bits=2048):
    """RSA key object (private). key.publickey() is the public half."""
    return RSA.generate(bits)


def rsa_export(key, passphrase=None):
    """PEM string (private keys optionally passphrase-protected)."""
    if passphrase and key.has_private():
        return key.export_key(passphrase=passphrase, pkcs=8,
                              protection='PBKDF2WithHMAC-SHA1AndAES256-CBC').decode()
    return key.export_key().decode()


def rsa_import(pem, passphrase=None):
    return RSA.import_key(pem, passphrase=passphrase)


_HASHES = {'SHA1': SHA1, 'SHA256': SHA256, 'SHA512': SHA512}


def rsa_encrypt(pub, data, hash_name='SHA256'):
    """RSA-OAEP. Max data = k - 2*hLen - 2 bytes (190 B for RSA-2048/SHA-256)."""
    return PKCS1_OAEP.new(pub, hashAlgo=_HASHES[hash_name]).encrypt(data)


def rsa_decrypt(priv, ct, hash_name='SHA256'):
    """Raises ValueError on wrong key / tampered ciphertext."""
    return PKCS1_OAEP.new(priv, hashAlgo=_HASHES[hash_name]).decrypt(ct)


def hybrid_encrypt(pub, data, aes_bits=256, mode='GCM'):
    """Random AES session key encrypts data; RSA-OAEP wraps the session key.
    mode 'GCM' (authenticated) or 'CBC' (when the question says CBC)."""
    if mode not in ('GCM', 'CBC'):
        raise ValueError('mode must be GCM or CBC')
    if type(aes_bits) is not int or aes_bits not in (128, 192, 256):
        raise ValueError('AES key size must be 128, 192, or 256 bits')
    key = get_random_bytes(aes_bits // 8)
    box = {'wrapped_key': rsa_encrypt(pub, key).hex(), 'mode': mode}
    if mode == 'GCM':
        c = AES.new(key, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(data)
        box.update(iv=c.nonce.hex(), ct=ct.hex(), tag=tag.hex())
    else:
        c = AES.new(key, AES.MODE_CBC)
        box.update(iv=c.iv.hex(), ct=c.encrypt(pad(data, 16)).hex())
    return box


def hybrid_decrypt(priv, box):
    if box['mode'] not in ('GCM', 'CBC'):
        raise ValueError('mode must be GCM or CBC')
    key = rsa_decrypt(priv, bytes.fromhex(box['wrapped_key']))
    iv, ct = bytes.fromhex(box['iv']), bytes.fromhex(box['ct'])
    if box['mode'] == 'GCM':
        return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, bytes.fromhex(box['tag']))
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)


# --- textbook RSA (numerical questions: given p, q, e or n, e, d) -----------
def rsa_from_pq(p, q, e=65537):
    """n = pq, phi = (p-1)(q-1), d = e^-1 mod phi.  Returns (n, e, d)."""
    if p == q or not (isPrime(p) and isPrime(q)):
        raise ValueError('p and q must be distinct primes')
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError('gcd(e, phi) != 1 - choose another e')
    return p * q, e, pow(e, -1, phi)


def rsa_textbook_encrypt(m, e, n):
    if not 0 <= m < n:
        raise ValueError('need 0 <= m < n (split the message into blocks)')
    return pow(m, e, n)


def rsa_textbook_decrypt(c, d, n):
    return pow(c, d, n)


def rsa_encrypt_text(msg, e, n):
    """Block-wise textbook RSA of a string; works even for tiny n like 323."""
    ints, size = text_blocks(msg.encode(), n)
    return [pow(m, e, n) for m in ints], size


def rsa_decrypt_text(cts, d, n, size):
    if any(type(c) is not int or not 0 <= c < n for c in cts):
        raise ValueError('need 0 <= ciphertext < n')
    return blocks_text([pow(c, d, n) for c in cts], size).decode()


# --- weak-key attack (Lab 4 additional Q2) -------------------------------
def fermat_factor(n, max_steps=1_000_000):
    """Fast when p and q are close together."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def pollard_rho(n, max_steps=2_000_000):
    """Fast when one prime factor is small."""
    if n % 2 == 0:
        return 2, n // 2
    for c in range(1, 20):
        x = y = 2
        d = 1
        f = lambda v: (v * v + c) % n
        steps = 0
        while d == 1 and steps < max_steps:
            x, y = f(x), f(f(y))
            d = gcd(abs(x - y), n)
            steps += 1
        if 1 < d < n:
            return d, n // d
    return None


def break_weak_rsa(n, e):
    """Factor n (Fermat, then Pollard rho) and rebuild d.  -> (p, q, d) or None."""
    pq = fermat_factor(n, 200_000) or pollard_rho(n)
    if not pq:
        return None
    p, q = pq
    return p, q, pow(e, -1, (p - 1) * (q - 1))


# =================================================================== ElGamal
def elgamal_keygen(p=G14_P, g=G14_G, x=None):
    """Public (p, g, y = g^x mod p), private x.  Give p,g,x when the question does."""
    if type(p) is not int or p < 5 or not isPrime(p) or type(g) is not int or not 1 < g < p - 1:
        raise ValueError('need a prime p >= 5 and 1 < g < p-1')
    if x is None:
        x = random.randint(2, p - 2)
        while pow(g, x, p) in (1, p - 1):
            x = random.randint(2, p - 2)
    if type(x) is not int or not 1 <= x <= p - 2 or pow(g, x, p) in (1, p - 1):
        raise ValueError('need 1 <= x <= p-2')
    return (p, g, pow(g, x, p)), x


def elgamal_encrypt(m, pub, k=None):
    """c1 = g^k mod p, c2 = m * y^k mod p.  Fresh random k every time!"""
    p, g, y = pub
    if (any(type(v) is not int for v in (p, g, y)) or p < 5
            or not 1 < g < p - 1 or not 1 < y < p - 1):
        raise ValueError('invalid ElGamal public key')
    if type(m) is not int or not 0 < m < p:
        raise ValueError('need 0 < m < p')
    if k is None:
        k = random.randint(2, p - 2)
        while pow(g, k, p) == 1:
            k = random.randint(2, p - 2)
    elif type(k) is not int or not 1 <= k <= p - 2 or pow(g, k, p) == 1:
        raise ValueError('need 1 <= k <= p-2 and a nonidentity ephemeral public value')
    return pow(g, k, p), m * pow(y, k, p) % p


def elgamal_decrypt(c, x, p):
    """s = c1^x mod p, m = c2 * s^-1 mod p."""
    c1, c2 = c
    if (any(type(v) is not int for v in (p, x, c1, c2)) or p < 5
            or not 1 <= x <= p - 2 or not 0 < c1 < p or not 0 < c2 < p):
        raise ValueError('invalid ElGamal private key or ciphertext')
    return c2 * pow(pow(c1, x, p), -1, p) % p


def elgamal_encrypt_text(msg, pub):
    p = pub[0]
    ints, size = text_blocks(msg.encode(), p - 1)
    # +1 offset so a zero byte block never encrypts m = 0
    return [elgamal_encrypt(m + 1, pub) for m in ints], size


def elgamal_decrypt_text(cts, x, p, size):
    ints = [elgamal_decrypt(c, x, p) - 1 for c in cts]
    return blocks_text(ints, size).decode()


# ===================================================================== Rabin
def rabin_keygen(bits=1024):
    """p, q prime with p = q = 3 (mod 4).  Public n, private (p, q)."""
    if type(bits) is not int or bits < 8:
        raise ValueError('bits must be an integer >= 8')
    def prime34():
        while True:
            p = getPrime(bits // 2)
            if p % 4 == 3:
                return p
    p, q = prime34(), prime34()
    while q == p:
        q = prime34()
    return p * q, (p, q)


def rabin_roots(c, p, q):
    """The four square roots of c mod n (CRT)."""
    if (type(p) is not int or type(q) is not int or p == q or
            p % 4 != 3 or q % 4 != 3 or not isPrime(p) or not isPrime(q)):
        raise ValueError('p and q must be distinct primes congruent to 3 modulo 4')
    n = p * q
    if type(c) is not int or not 0 <= c < n:
        raise ValueError('need 0 <= ciphertext < n')
    mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
    yp, yq = pow(p, -1, q), pow(q, -1, p)          # yp*p = 1 (mod q), yq*q = 1 (mod p)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    roots = [r1, (-r1) % n, r3, (-r3) % n]
    if any(pow(r, 2, n) != c for r in roots):
        raise ValueError('ciphertext is not a quadratic residue modulo n')
    return roots


def rabin_encrypt(msg, n):
    """c = m^2 mod n, with redundancy (0x01 | msg | 4-byte hash) to pick the root."""
    data = b'\x01' + msg + hashlib.sha256(msg).digest()[:4]
    m = int.from_bytes(data, 'big')
    if m >= n:
        raise ValueError('message too long for this n')
    return pow(m, 2, n)


def rabin_decrypt(c, p, q):
    """Returns (message_bytes, all_four_roots)."""
    roots = rabin_roots(c, p, q)
    for r in roots:
        b = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        if b[:1] == b'\x01' and len(b) >= 5 and hashlib.sha256(b[1:-4]).digest()[:4] == b[-4:]:
            return b[1:-4], roots
    raise ValueError('no root has valid redundancy (wrong key or tampered)')


# ============================================================ Diffie-Hellman
def dh_keypair(p=G14_P, g=G14_G):
    if type(p) is not int or p < 5 or not isPrime(p) or type(g) is not int or not 1 < g < p - 1:
        raise ValueError('need a prime p >= 5 and 1 < g < p-1')
    a = random.randint(2, p - 2)
    while pow(g, a, p) in (1, p - 1):
        a = random.randint(2, p - 2)
    return a, pow(g, a, p)                          # (private a, public A = g^a)


def dh_shared(peer_public, private, p=G14_P):
    if (any(type(v) is not int for v in (p, private, peer_public)) or p < 5
            or not 1 <= private <= p - 2 or not 1 < peer_public < p - 1):
        raise ValueError('invalid DH public value')
    if p == G14_P and pow(peer_public, (p - 1) // 2, p) != 1:
        raise ValueError('DH public value is outside the group-14 subgroup')
    return pow(peer_public, private, p)            # K = B^a = A^b = g^ab


def kdf(secret_int_or_bytes, length=32):
    """Shared secret -> AES key (SHA-256).  Never use the raw DH number as a key."""
    if type(length) is not int or not 1 <= length <= 32:
        raise ValueError('SHA-256 key length must be in 1..32 bytes')
    s = secret_int_or_bytes
    if isinstance(s, int):
        s = s.to_bytes((s.bit_length() + 7) // 8, 'big')
    return hashlib.sha256(s).digest()[:length]


# ======================================================================= ECC
def ecc_generate(curve='P-256'):
    """ECC private key (d, Q = d*G).  secp256r1 == P-256 == prime256v1."""
    return ECC.generate(curve=curve)


def ecdh(priv, peer_pub):
    """Shared AES key = SHA-256(x-coordinate of d_A * Q_B)."""
    if not priv.has_private() or priv.curve != peer_pub.curve:
        raise ValueError('ECDH needs a private key and a public key on the same curve')
    point = peer_pub.pointQ * priv.d
    if point.is_point_at_infinity():
        raise ValueError('invalid ECDH shared point')
    size = (priv.pointQ.size_in_bits() + 7) // 8
    return hashlib.sha256(int(point.x).to_bytes(size, 'big')).digest()


def ecies_encrypt(pub, data):
    """'ECC encryption' / EC-ElGamal style: ephemeral ECDH + AES-GCM."""
    eph = ECC.generate(curve=pub.curve)
    key = ecdh(eph, pub)
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return {'eph': eph.public_key().export_key(format='PEM'),
            'iv': c.nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()}


def ecies_decrypt(priv, box):
    key = ecdh(priv, ECC.import_key(box['eph']))
    return AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(box['iv'])).decrypt_and_verify(
        bytes.fromhex(box['ct']), bytes.fromhex(box['tag']))
