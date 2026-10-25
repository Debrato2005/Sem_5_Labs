"""Lab 2 - DES / 3DES / AES (128/192/256) in every mode, files, timing, and a
from-scratch AES with round-by-round trace (key expansion, SubBytes, ShiftRows,
MixColumns, AddRoundKey).  Needs pycryptodome.

Sizes: DES key 8 B, 3DES key 16/24 B, AES key 16/24/32 B (AES-128/192/256).
Block: DES/3DES 8 B, AES 16 B.  CBC/CFB/OFB IV = 1 block.  GCM nonce 12 B (96-bit standard).
"""
import hashlib
import time

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

CIPHERS = {'AES': AES, 'DES': DES, 'DES3': DES3}
KEY_SIZES = {'AES': (16, 24, 32), 'DES': (8,), 'DES3': (16, 24)}
MODES = ('ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM', 'EAX')


def new_key(alg='AES', size=32):
    """Random key of `size` bytes (DES always 8; 3DES 16/24 with valid parity)."""
    if alg == 'DES3':
        while True:                                # avoid degenerate 3DES keys
            try:
                return DES3.adjust_key_parity(get_random_bytes(size if size in (16, 24) else 24))
            except ValueError:
                pass
    return get_random_bytes(8 if alg == 'DES' else size)


def check_key(alg, key):
    if len(key) not in KEY_SIZES[alg]:
        raise ValueError(f'{alg} key must be {KEY_SIZES[alg]} bytes, got {len(key)}')


# ------------------------------------------------ simple most-used helpers ---
def aes_cbc_encrypt(key, data, iv=None):
    """-> (iv, ciphertext).  PKCS#7 padding.  Random IV unless one is given."""
    c = AES.new(key, AES.MODE_CBC, iv=iv) if iv else AES.new(key, AES.MODE_CBC)
    return c.iv, c.encrypt(pad(data, 16))


def aes_cbc_decrypt(key, iv, ct):
    """Raises ValueError on wrong key/corrupt padding."""
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)


def aes_gcm_encrypt(key, data, aad=b''):
    """Authenticated encryption -> (nonce, ciphertext, tag).  96-bit nonce."""
    c = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    c.update(aad)
    ct, tag = c.encrypt_and_digest(data)
    return c.nonce, ct, tag


def aes_gcm_decrypt(key, nonce, ct, tag, aad=b''):
    """Raises ValueError('MAC check failed') if anything was tampered with."""
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    return c.decrypt_and_verify(ct, tag)


# ------------------------------------------- password-protected key vaults ---
def password_key(password, salt, length=32, rounds=200_000):
    """KDF: DK = PBKDF2-HMAC-SHA256(password, salt, rounds)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds, length)


def password_seal(password, data):
    """Encrypt bytes under a password (PBKDF2 + AES-256-GCM) -> JSON-safe dict.
    Use it to give each role its OWN keys: only that role's password opens them."""
    salt = get_random_bytes(16)
    nonce, ct, tag = aes_gcm_encrypt(password_key(password, salt), data)
    return {'salt': salt.hex(), 'nonce': nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()}


def password_open(password, box):
    """Raises ValueError if the password is wrong or the vault was modified."""
    try:
        return aes_gcm_decrypt(password_key(password, bytes.fromhex(box['salt'])),
                               bytes.fromhex(box['nonce']), bytes.fromhex(box['ct']),
                               bytes.fromhex(box['tag']))
    except ValueError:
        raise ValueError('wrong password (or vault tampered)') from None


# ------------------------------------------------- generic: any alg + mode ---
def sym_encrypt(alg, mode, key, data, iv=None, padding=True):
    """Encrypt with alg in {AES,DES,DES3} and mode in MODES.
    Returns a JSON-safe dict of hex strings; pass it to sym_decrypt().
    iv: optional fixed IV (CBC/CFB/OFB) or nonce (CTR/GCM/EAX)."""
    alg, mode = alg.upper(), mode.upper()
    check_key(alg, key)
    mod = CIPHERS[alg]
    bs = mod.block_size
    m = getattr(mod, 'MODE_' + mode)
    if mode == 'ECB':
        c = mod.new(key, m)
    elif mode in ('CBC', 'CFB', 'OFB'):
        c = mod.new(key, m, iv=iv) if iv else mod.new(key, m)
    else:                                          # CTR / GCM / EAX use a nonce
        if mode == 'GCM' and alg != 'AES':
            raise ValueError('GCM needs a 128-bit block cipher (AES)')
        if iv is None:                             # CTR nonce = half a block
            iv = get_random_bytes(bs // 2 if mode == 'CTR' else 12 if mode == 'GCM' else 16)
        c = mod.new(key, m, nonce=iv)
    needs_pad = mode in ('ECB', 'CBC')
    if needs_pad and padding:
        data = pad(data, bs)
    elif needs_pad and len(data) % bs:
        raise ValueError(f'no-padding {mode} needs data multiple of {bs} bytes')
    out = {'alg': alg, 'mode': mode, 'pad': bool(needs_pad and padding)}
    if mode in ('GCM', 'EAX'):
        ct, tag = c.encrypt_and_digest(data)
        out['tag'] = tag.hex()
    else:
        ct = c.encrypt(data)
    if hasattr(c, 'iv'):
        out['iv'] = c.iv.hex()
    if hasattr(c, 'nonce'):
        out['iv'] = c.nonce.hex()
    out['ct'] = ct.hex()
    return out


def sym_decrypt(key, box):
    alg, mode = box['alg'], box['mode']
    mod = CIPHERS[alg]
    m = getattr(mod, 'MODE_' + mode)
    ct = bytes.fromhex(box['ct'])
    if mode == 'ECB':
        c = mod.new(key, m)
    elif mode in ('CBC', 'CFB', 'OFB'):
        c = mod.new(key, m, iv=bytes.fromhex(box['iv']))
    else:
        c = mod.new(key, m, nonce=bytes.fromhex(box['iv']))
    if mode in ('GCM', 'EAX'):
        pt = c.decrypt_and_verify(ct, bytes.fromhex(box['tag']))
    else:
        pt = c.decrypt(ct)
    return unpad(pt, mod.block_size) if box.get('pad') else pt


# ------------------------------------------------------------------- files ---
def encrypt_file(src, dst, key):
    """AES-GCM file encryption: dst = nonce(12) | tag(16) | ciphertext."""
    with open(src, 'rb') as f:
        nonce, ct, tag = aes_gcm_encrypt(key, f.read())
    with open(dst, 'wb') as f:
        f.write(nonce + tag + ct)


def decrypt_file(src, dst, key):
    with open(src, 'rb') as f:
        blob = f.read()
    pt = aes_gcm_decrypt(key, blob[:12], blob[28:], blob[12:28])
    with open(dst, 'wb') as f:
        f.write(pt)


# ------------------------------------------------------------------ timing ---
def time_op(fn, repeat=200):
    """Average seconds per call (perf_counter)."""
    t = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - t) / repeat


def cipher_benchmark(message, combos=(('DES', 'ECB', 8), ('AES', 'ECB', 16), ('AES', 'ECB', 24),
                               ('AES', 'ECB', 32)), repeat=200):
    """[(label, enc_seconds, dec_seconds)] for e.g. DES vs AES-128/192/256."""
    rows = []
    for alg, mode, ksz in combos:
        key = get_random_bytes(ksz)
        box = sym_encrypt(alg, mode, key, message)
        e = time_op(lambda: sym_encrypt(alg, mode, key, message), repeat)
        d = time_op(lambda: sym_decrypt(key, box), repeat)
        rows.append((f'{alg}-{ksz * 8} {mode}', e, d))
    return rows


# ============================================== AES from scratch (teaching) ===
def gf_mul(a, b):
    """Multiply in GF(2^8) mod x^8+x^4+x^3+x+1 (0x11B)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = next((y for y in range(1, 256) if gf_mul(x, y) == 1), 0) if x else 0
        s = inv
        for i in range(1, 5):                       # affine transform
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox[x] = s ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [SBOX.index(i) for i in range(256)]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def key_expansion(key):
    """-> list of 4-byte words. Nk = 4/6/8, rounds Nr = 10/12/14."""
    check_key('AES', key)
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [SBOX[b] for b in t]                # SubWord
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return w


# state = 16 bytes in column-major order (s[r + 4c]) exactly like FIPS-197
def sub_bytes(s, box=SBOX):
    return [box[b] for b in s]


def shift_rows(s):
    """Row r rotates left by r: s'[r,c] = s[r, (c+r) mod 4]."""
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_column(col, m=(2, 3, 1, 1)):
    """out[i] = XOR_j m[(j-i) mod 4] * col[j]  (circulant matrix in GF(2^8))."""
    return [gf_mul(col[0], m[-i % 4]) ^ gf_mul(col[1], m[(1 - i) % 4]) ^
            gf_mul(col[2], m[(2 - i) % 4]) ^ gf_mul(col[3], m[(3 - i) % 4])
            for i in range(4)]


def mix_columns(s, m=(2, 3, 1, 1)):
    out = []
    for c in range(4):
        out += mix_column(s[4 * c:4 * c + 4], m)
    return out


def inv_mix_columns(s):
    return mix_columns(s, (14, 11, 13, 9))


def add_round_key(s, w, rnd):
    k = [b for word in w[4 * rnd:4 * rnd + 4] for b in word]
    return [a ^ b for a, b in zip(s, k)]


def aes_encrypt_block(key, block, trace=False):
    """Single 16-byte block, AES-128/192/256. trace=True prints every step."""
    if len(block) != 16:
        raise ValueError('AES block must be exactly 16 bytes')
    w = key_expansion(key)
    nr = len(key) // 4 + 6
    show = (lambda label, s: print(f'{label:<28}{bytes(s).hex()}')) if trace else (lambda *a: None)
    if trace:
        print(f'AES-{len(key) * 8}: {nr} rounds, {len(w)} key words')
        for r in range(nr + 1):
            show(f'round key {r}', [b for word in w[4 * r:4 * r + 4] for b in word])
    s = list(block)
    show('input', s)
    s = add_round_key(s, w, 0)
    show('initial AddRoundKey', s)
    for rnd in range(1, nr + 1):
        s = sub_bytes(s)
        show(f'R{rnd} SubBytes', s)
        s = shift_rows(s)
        show(f'R{rnd} ShiftRows', s)
        if rnd != nr:                                # final round: no MixColumns
            s = mix_columns(s)
            show(f'R{rnd} MixColumns', s)
        s = add_round_key(s, w, rnd)
        show(f'R{rnd} AddRoundKey', s)
    return bytes(s)


def aes_decrypt_block(key, block):
    if len(block) != 16:
        raise ValueError('AES block must be exactly 16 bytes')
    w = key_expansion(key)
    nr = len(key) // 4 + 6
    s = add_round_key(list(block), w, nr)
    for rnd in range(nr - 1, -1, -1):
        s = inv_shift_rows(s)
        s = sub_bytes(s, INV_SBOX)
        s = add_round_key(s, w, rnd)
        if rnd:
            s = inv_mix_columns(s)
    return bytes(s)
