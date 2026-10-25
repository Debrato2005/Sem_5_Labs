"""Lab 5 - hashing: custom djb2-style hash, MD5/SHA-1/SHA-2/SHA-3 of bytes/files,
HMAC, integrity check, timing + collision experiment.  Standard library only.

Digest sizes: MD5 128 bit (32 hex), SHA-1 160 (40), SHA-256 256 (64), SHA-512 512 (128).
MD5 and SHA-1 are broken for collisions: use them only when the question says so.
"""
import hashlib
import hmac
import string
import time
from random import Random          # non-crypto RNG: test data only

ALGORITHMS = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
              'sha3_256', 'sha3_512', 'blake2b')


def custom_hash(text):
    """Lab 5 Q1: start 5381; h = h*33 + ord(c) (as (h<<5)+h); mask to 32 bits."""
    h = 5381
    for c in text:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def custom_hash_xor(text):
    """Variant with extra bit mixing (djb2a: XOR instead of add + avalanche)."""
    h = 5381
    for c in text:
        h = (((h << 5) + h) ^ ord(c)) & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    return h ^ (h >> 16)


def digest(data, alg='sha256'):
    """Hex digest of bytes (str is encoded as UTF-8)."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.new(alg.lower().replace('-', ''), data).hexdigest()


def file_digest(path, alg='sha256', chunk=65536):
    h = hashlib.new(alg.lower().replace('-', ''))
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(chunk), b''):
            h.update(block)
    return h.hexdigest()


def verify_digest(data, expected_hex, alg='sha256'):
    """Constant-time comparison of a recomputed digest with a stored one."""
    return hmac.compare_digest(digest(data, alg), expected_hex.lower())


def hmac_hex(key, data, alg='sha256'):
    return hmac.new(key, data, alg).hexdigest()


def hmac_ok(key, data, tag_hex, alg='sha256'):
    return hmac.compare_digest(hmac_hex(key, data, alg), tag_hex)


def random_strings(count, min_len=8, max_len=32, seed=None):
    rnd = Random(seed)
    chars = string.ascii_letters + string.digits
    return [''.join(rnd.choice(chars) for _ in range(rnd.randint(min_len, max_len)))
            for _ in range(count)]


def hash_benchmark(strings, algs=('md5', 'sha1', 'sha256'), repeat=100):
    """{alg: average seconds to hash the whole dataset once}."""
    out = {}
    for a in algs:
        t = time.perf_counter()
        for _ in range(repeat):
            for s in strings:
                hashlib.new(a, s.encode()).digest()
        out[a] = (time.perf_counter() - t) / repeat
    return out


def find_collisions(strings, hash_fn):
    """{digest: [inputs...]} for digests produced by 2+ DIFFERENT inputs."""
    seen = {}
    for s in set(strings):
        seen.setdefault(hash_fn(s), []).append(s)
    return {h: v for h, v in seen.items() if len(v) > 1}


def truncated(alg, bits):
    """Weak hash (first `bits` bits) - lets students OBSERVE collisions."""
    return lambda s: int(hashlib.new(alg, s.encode()).hexdigest(), 16) >> (
        hashlib.new(alg).digest_size * 8 - bits)
