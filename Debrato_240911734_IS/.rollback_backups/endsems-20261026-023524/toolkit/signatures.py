"""Lab 6 - digital signatures: RSA (PKCS#1 v1.5 / PSS, any hash incl. MD5),
textbook RSA, ElGamal, Schnorr, DSA/ECDSA, and a signed timestamp authority.
Needs pycryptodome.

RULE: sender PRIVATE key signs, sender PUBLIC key verifies.  Verify functions
return True/False and never raise on bad input.
"""
import hashlib
import json
from datetime import datetime, timezone
from math import gcd

from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_256, SHA3_512
from Crypto.PublicKey import DSA, ECC, RSA
from Crypto.Random import random
from Crypto.Signature import DSS, pkcs1_15, pss
from Crypto.Util.number import isPrime

HASH_OBJ = {'md5': MD5, 'sha1': SHA1, 'sha224': SHA224, 'sha256': SHA256,
            'sha384': SHA384, 'sha512': SHA512, 'sha3_256': SHA3_256, 'sha3_512': SHA3_512}

# RFC 3526 group 14 (same as asymmetric.G14_P); q = (p-1)/2, g = 2 has order q.
G14_P = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
G14_Q = (G14_P - 1) // 2
G14_G = 2


def hash_obj(data, alg='sha256'):
    """pycryptodome hash object (what pkcs1_15/pss/DSS sign)."""
    return HASH_OBJ[alg.lower().replace('-', '')].new(data)


# ======================================================================= RSA
def rsa_sign(priv, data, alg='sha256', scheme='pkcs1'):
    """Hash `data` ONCE with alg and sign that hash.  -> signature hex.
    'Compute MD5 of the record and sign the hash' == rsa_sign(key, record, 'md5')."""
    if scheme not in ('pkcs1', 'pss'):
        raise ValueError('scheme must be pkcs1 or pss')
    h = hash_obj(data, alg)
    signer = pss.new(priv) if scheme == 'pss' else pkcs1_15.new(priv)
    return signer.sign(h).hex()


def rsa_verify(pub, data, sig_hex, alg='sha256', scheme='pkcs1'):
    try:
        if scheme not in ('pkcs1', 'pss'):
            return False
        h = hash_obj(data, alg)
        verifier = pss.new(pub) if scheme == 'pss' else pkcs1_15.new(pub)
        verifier.verify(h, bytes.fromhex(sig_hex))
        return True
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def rsa_textbook_sign(m_int, d, n):
    """s = H(m)^d mod n (numerical lab questions only - no padding)."""
    return pow(m_int % n, d, n)


def rsa_textbook_verify(m_int, s, e, n):
    try:
        if any(type(v) is not int for v in (m_int, s, e, n)) or n < 3 or e < 2 or not 0 <= s < n:
            return False
        return pow(s, e, n) == m_int % n
    except (ValueError, TypeError):
        return False


def h_int(data, alg='sha256'):
    if isinstance(data, str):
        data = data.encode()
    return int.from_bytes(hashlib.new(alg, data).digest(), 'big')


# =================================================================== ElGamal
def elgamal_sig_keygen(p=G14_P, g=G14_G, x=None):
    if type(p) is not int or p < 5 or not isPrime(p) or type(g) is not int or not 1 < g < p - 1:
        raise ValueError('need a prime p >= 5 and 1 < g < p-1')
    x = random.randint(2, p - 2) if x is None else x
    if type(x) is not int or not 1 <= x <= p - 2 or pow(g, x, p) == 1:
        raise ValueError('invalid private exponent or identity public key')
    return (p, g, pow(g, x, p)), x


def elgamal_sign(data, x, p=G14_P, g=G14_G, alg='sha256'):
    """r = g^k mod p, s = k^-1 (H(m) - x r) mod (p-1); fresh k with gcd(k, p-1) = 1."""
    return elgamal_sign_hash(h_int(data, alg), x, p, g)


def elgamal_sign_hash(hm, x, p=G14_P, g=G14_G):
    """Sign an already-computed hash integer (e.g. int(sha512_hex, 16))."""
    hm %= p - 1
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) != 1:
            continue
        r = pow(g, k, p)
        s = (hm - x * r) * pow(k, -1, p - 1) % (p - 1)
        if s:
            return r, s


def elgamal_verify(data, sig, pub, alg='sha256'):
    """g^H(m) == y^r * r^s (mod p), with 0 < r < p and 0 < s < p-1."""
    try:
        return elgamal_verify_hash(h_int(data, alg), sig, pub)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def elgamal_verify_hash(hm, sig, pub):
    try:
        p, g, y = pub
        r, s = sig
        if any(type(v) is not int for v in (p, g, y, r, s, hm)):
            return False
        if not (p >= 5 and isPrime(p) and 1 < g < p - 1 and 1 < y < p - 1):
            return False
        if not (0 < r < p and 0 < s < p - 1):
            return False
        return pow(g, hm % (p - 1), p) == pow(y, r, p) * pow(r, s, p) % p
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


# =================================================================== Schnorr
def schnorr_keygen(p=G14_P, q=G14_Q, g=G14_G):
    if not _schnorr_group(p, q, g):
        raise ValueError('invalid Schnorr prime-order subgroup')
    x = random.randint(1, q - 1)
    return (p, q, g, pow(g, x, p)), x


def schnorr_sign(data, x, p=G14_P, q=G14_Q, g=G14_G, alg='sha256'):
    """r = g^k, e = H(r || m) mod q, s = (k + x e) mod q.  Signature (e, s)."""
    if isinstance(data, str):
        data = data.encode()
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = h_int(str(r).encode() + data, alg) % q
    return e, (k + x * e) % q


def schnorr_verify(data, sig, pub, alg='sha256'):
    """r' = g^s * y^-e mod p; valid iff H(r' || m) mod q == e."""
    try:
        if isinstance(data, str):
            data = data.encode()
        p, q, g, y = pub
        e, s = sig
        if any(type(v) is not int for v in (p, q, g, y, e, s)):
            return False
        if not _schnorr_group(p, q, g) or not 1 < y < p or pow(y, q, p) != 1:
            return False
        if not (0 <= e < q and 0 <= s < q):
            return False
        r = pow(g, s, p) * pow(y, -e, p) % p
        return h_int(str(r).encode() + data, alg) % q == e
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def _schnorr_group(p, q, g):
    return (all(type(v) is int for v in (p, q, g)) and p > 3 and q > 2
            and (p - 1) % q == 0 and 1 < g < p and isPrime(p) and isPrime(q)
            and pow(g, q, p) == 1)


# ============================================================== DSA / ECDSA
def dsa_generate(bits=2048):
    return DSA.generate(bits)


def ecdsa_generate(curve='P-256'):
    return ECC.generate(curve=curve)


def dss_sign(priv, data, alg='sha256'):
    """DSA or ECDSA (FIPS 186-3) signature hex."""
    return DSS.new(priv, 'fips-186-3').sign(hash_obj(data, alg)).hex()


def dss_verify(pub, data, sig_hex, alg='sha256'):
    try:
        DSS.new(pub, 'fips-186-3').verify(hash_obj(data, alg), bytes.fromhex(sig_hex))
        return True
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


# ============================================== Trusted timestamp authority
class TimestampAuthority:
    """Issues RSA-signed tokens binding (digest, UTC time, random nonce).
    Real signatures, but the 'authority' is a key held by this program: it is
    a local stand-in for an RFC 3161 TSA, not an external trusted service."""

    def __init__(self, key):
        self.key = key

    def stamp(self, digest_hex, when=None):
        when = when or datetime.now(timezone.utc).replace(microsecond=0)
        token = {'digest': digest_hex, 'time': when.isoformat(),
                 'nonce': '%016x' % random.getrandbits(64)}
        token['tsa_sig'] = rsa_sign(self.key, _tok(token), 'sha256')
        return token


def _tok(token):
    body = {k: token[k] for k in ('digest', 'time', 'nonce')}
    return json.dumps(body, sort_keys=True, separators=(',', ':')).encode()


def verify_timestamp(token, tsa_pub, digest_hex=None, start=None, end=None):
    """Signature valid, bound to digest_hex, and start <= time <= end (aware datetimes)."""
    try:
        if not rsa_verify(tsa_pub, _tok(token), token['tsa_sig'], 'sha256'):
            return False, 'timestamp signature invalid'
        if digest_hex is not None and token['digest'] != digest_hex:
            return False, 'timestamp not bound to this record'
        t = datetime.fromisoformat(token['time'])
        if (start and t < start) or (end and t > end):
            return False, f'time {token["time"]} outside allowed window'
        return True, 'timestamp OK ' + token['time']
    except (KeyError, ValueError, TypeError) as e:
        return False, f'malformed timestamp ({e})'
