"""SECURE GRANT EXPENSE PORTAL  (menu-driven, role-based, persistent)
Logins: researcher/res123   reviewer/rev123   finance/fin123
AES-192 description | Paillier amount | MD5 hash | RSA signature of the MD5 hash | HMAC index on Grant ID
Files: grant_keys.json (keys, made on first run), grant_db.json (records) next to this file."""
import base64, hashlib, hmac, json, math, os, random, secrets, sys
from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import getPrime, isPrime
from Crypto.Util.Padding import pad, unpad
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# ===========================================================================
# COPIED MODULAR FUNCTIONS (from islib.py, unchanged)
# ===========================================================================

# ---------------------------------------------------------------------------
# ask: read a value from the keyboard - with a default, a type and/or validation
# [1] PREREQS  imports  : import sys
#              functions: (none - standalone)
# [2] PARAMS   text    : question shown, e.g. "Message"
#              default : used when Enter is pressed, and used silently when the script is not
#                        run from a terminal (piped / auto-run). None = a value is required.
#              cast    : applied to the typed text: int, float, str.upper, or any function
#                        that raises ValueError on bad input. Default: type(default), else str
#              valid   : function(value) -> True/False; keeps asking while it is False
#              secret  : True hides the typing (passwords)
#              error   : message printed when valid() says False
#     RETURNS  the converted value (asks again on bad input instead of crashing)
#     CHANGE   lab scripts: just change the default. Exam menus: add cast / valid / error.
#              Yes/no question: ask("Sure? (y/n)", cast=str.lower, valid=lambda v: v in "yn")
#     EXAMPLE  k   = ask("Additive key", 20)
#              amt = ask("Amount", cast=float, valid=lambda v: v > 0, error="must be > 0")
#              pw  = ask("Password", secret=True)
def ask(text, default=None, cast=None, valid=None, secret=False, error="not allowed, try again"):
    cast = cast or (type(default) if default is not None else str)
    if default is not None and not sys.stdin.isatty():
        print(f"{text} [{default}]")
        return default
    label = f"{text} [{default}]: " if default is not None else f"{text}: "
    while True:
        try:
            if secret and sys.stdin.isatty():
                import getpass
                raw = getpass.getpass(label)
            else:
                raw = input(label)
                if not sys.stdin.isatty():               # echo piped input so logs are readable
                    print("****" if secret else raw)
        except EOFError:
            print("\n[end of input] exiting")
            sys.exit(0)
        raw = raw.strip()
        if not raw:
            if default is not None:
                return default
            print("  ! a value is required")
            continue
        try:
            value = cast(raw)
        except (ValueError, TypeError):
            print(f"  ! invalid input '{raw}'")
            continue
        if valid and not valid(value):
            print(f"  ! {error}")
            continue
        return value


# ---------------------------------------------------------------------------
# to_bytes: str / int / bytes -> bytes  (every modern cipher runs its input through this)
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   x : str -> UTF-8 bytes,  int -> big-endian bytes (shortest),  bytes -> unchanged
#     CHANGE   different text encoding -> change .encode() to e.g. .encode("latin-1")
#     EXAMPLE  to_bytes("Hi") -> b'Hi'      to_bytes(258) -> b'\x01\x02'
def to_bytes(x):
    if isinstance(x, bytes):
        return x
    if isinstance(x, int):
        return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    return str(x).encode()


# ---------------------------------------------------------------------------
# fmt: display bytes / numbers as HEX, base64, website '0x..' list, shortened text or hexdump
# [1] PREREQS  imports  : import base64
#              functions: to_bytes()
# [2] PARAMS   x     : bytes, str or int
#              style : "hex"   -> 'A1B2C3...' (upper-case hex, the default)
#                      "b64"   -> base64 text
#                      "0x"    -> '0xa1 0xb2 ...'  (format of the lab's RSA website)
#                      "short" -> first n characters + '...(N chars)' for long ciphertexts/numbers
#                      "dump"  -> multi-line  offset | hex bytes | ASCII  (like xxd) - print it
#              n     : characters kept for "short" (default 24), bytes per line for "dump" (16)
#     RETURNS  a string
#     EXAMPLE  print(fmt(ct))   print(fmt(sig, "0x"))   print(fmt(c, "short", 40))
#              print(fmt(plaintext, "dump"))
def fmt(x, style="hex", n=None):
    if style == "short":
        s = x.hex() if isinstance(x, bytes) else str(x)
        n = n or 24
        return s if len(s) <= n else f"{s[:n]}...({len(s)} chars)"
    b = to_bytes(x)
    if style == "hex":
        return b.hex().upper()
    if style == "b64":
        return base64.b64encode(b).decode()
    if style == "0x":
        return " ".join(f"0x{c:02x}" for c in b)
    if style == "dump":
        n, lines = n or 16, []
        for i in range(0, len(b), n):
            chunk = b[i:i + n]
            text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            lines.append(f"  {i:08x}  {chunk.hex(' '):<{n * 3}} |{text}|")
        return "\n".join(lines)
    raise ValueError(f"unknown style {style!r}: use hex, b64, 0x, short or dump")


# ---------------------------------------------------------------------------
# print_table: print rows as an aligned text table (floats shown with 6 decimals)
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   headers : list of column titles
#              rows    : list of rows, each a list with one value per column
#     CHANGE   other float format -> edit f"{c:.6f}"
#     EXAMPLE  print_table(["Algo", "Time ms"], [["DES", 0.12], ["AES", 0.05]])
def print_table(headers, rows):
    rows = [[f"{c:.6f}" if isinstance(c, float) else str(c) for c in r] for r in rows]
    widths = [max(len(str(h)), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = " | ".join(f"{{:<{w}}}" for w in widths)
    print(line.format(*headers))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(line.format(*r))


SYM = {"DES": DES, "3DES": DES3, "AES": AES}       # algorithm name -> pycryptodome module


_NOTED = set()                                     # 3DES keys already explained (note printed once)


# ---------------------------------------------------------------------------
# symmetric: DES / 3DES / AES-128/192/256 in ECB, CBC, CFB, OFB, CTR, GCM, EAX
#            - encryption AND decryption (and a full printed demo) in one function
# [1] PREREQS  imports  : import base64
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED
#              pip      : pycryptodome
# [2] PARAMS   algo    : "DES" (8-byte key) | "3DES" (16 or 24) | "AES" (16 / 24 / 32 bytes
#                        = AES-128 / 192 / 256; "AES-256" etc. also accepted, key length decides)
#              key     : bytes - use key_bytes("hex or ascii", size) for keys given as text
#              data    : plaintext (str/bytes) to encrypt, or ciphertext bytes to decrypt
#              mode    : "ECB" "CBC" (padding added)  "CFB" "OFB" "CTR" (stream, no padding)
#                        "GCM" (AES only) / "EAX" -> authenticated: a tag is appended to the
#                        ciphertext and checked on decryption (tampering -> ValueError)
#              decrypt : False = encrypt, True = decrypt
#              iv      : IV (CBC/CFB/OFB: 8 bytes DES, 16 AES) or nonce (CTR: half a block,
#                        GCM: 12, EAX: 16). None -> random when encrypting.
#              packed  : True -> encrypt returns ONE bytes value iv||ciphertext, and decrypt
#                        takes that value back (handy for storing; default iv sizes assumed)
#              show    : True (encrypt only) -> also decrypts and prints algo, key, IV,
#                        plaintext, ciphertext (hex), decrypted text and match
#     RETURNS  encrypt: (ciphertext, iv)   [ECB: iv is None]   or iv||ciphertext if packed
#              decrypt: plaintext bytes   (.decode() for text)
#     CHANGE   fixed IV: iv=key_bytes("12345678", 8) (DES) or 16 bytes (AES)
#              fixed CTR nonce: iv=key_bytes("0000000000000000", 8) (AES)
#              3DES key with K1=K2=K3 -> note printed, single DES used (it is identical)
#     EXAMPLE  ct, iv = symmetric("AES", key, "Sensitive Information", "CBC", show=True)
#              symmetric("AES", key, ct, "CBC", decrypt=True, iv=iv).decode()
#              blob = symmetric("AES", key, record, "GCM", packed=True)
#              symmetric("AES", key, blob, "GCM", decrypt=True, packed=True)
def symmetric(algo, key, data, mode="ECB", decrypt=False, iv=None, packed=False, show=False):
    algo, mode, key, data = algo.upper().split("-")[0], mode.upper(), to_bytes(key), to_bytes(data)
    module, given_key = SYM[algo], key
    if algo == "3DES" and len(key) == 24 and key[:8] == key[8:16] == key[16:]:
        if key not in _NOTED:                            # E_K(D_K(E_K(m))) = E_K(m)
            print("  [note] 3DES key has K1=K2=K3 -> mathematically equal to single DES with K1")
            _NOTED.add(key)
        module, key = DES, key[:8]
    bs = module.block_size
    iv_len = {"ECB": 0, "CBC": bs, "CFB": bs, "OFB": bs, "CTR": bs // 2, "GCM": 12, "EAX": 16}[mode]
    aead, padded = mode in ("GCM", "EAX"), mode in ("ECB", "CBC")
    if decrypt and packed:
        iv, data = data[:iv_len], data[iv_len:]
    if iv_len and iv is None:
        if decrypt:
            raise ValueError(f"{mode} decryption needs the iv/nonce returned by the encryption")
        iv = get_random_bytes(iv_len)
    kw = {} if mode == "ECB" else {("nonce" if mode in ("CTR", "GCM", "EAX") else "iv"): iv}

    def dec(blob):
        c = module.new(key, getattr(module, "MODE_" + mode), **kw)
        if aead:
            return c.decrypt_and_verify(blob[:-bs], blob[-bs:])   # last block = auth tag
        pt = c.decrypt(blob)
        return unpad(pt, bs) if padded else pt

    if decrypt:
        return dec(data)
    c = module.new(key, getattr(module, "MODE_" + mode), **kw)
    ct = c.encrypt(pad(data, bs) if padded else data)
    if aead:
        ct += c.digest()
    if show:
        pt = dec(ct)
        name = f"AES-{len(key) * 8}" if algo == "AES" else algo
        print(f"  Algorithm : {name}-{mode}   key ({len(given_key) * 8} bits) = {fmt(given_key)}")
        if iv:
            print(f"  IV/nonce  : {fmt(iv)}")
        print(f"  Plaintext : {data.decode(errors='replace')}")
        print(f"  Ciphertext: {fmt(ct)}" + (f"   (last {bs} bytes = auth tag)" if aead else ""))
        print(f"  Decrypted : {pt.decode(errors='replace')}")
        print(f"  Match     : {pt == data}")
    return (iv or b"") + ct if packed else (ct, iv)


DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
    "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
    "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
    "1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
    "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
    "955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)


DH_G = 2


# ---------------------------------------------------------------------------
# generate_keys: key generation for EVERY public-key scheme in one place
# [1] PREREQS  imports  : import math, random, secrets
#                         from Crypto.PublicKey import RSA
#                         from Crypto.Util.number import getPrime, isPrime
#                         from cryptography.hazmat.primitives import serialization
#                         from cryptography.hazmat.primitives.asymmetric import ec
#              functions: DH_P, DH_G, MERSENNE_1279, _MERSENNE_EXPONENTS, field_prime(), shamir()
#              pip      : cryptography pycryptodome
# [2] PARAMS   scheme  : one of the names below
#              bits    : key / prime size (defaults below)
#              as_json : True -> (public, private) as JSON-friendly dicts / PEM strings
#                        (for json_store or KeyManager)
#              **opt   : extra options listed per scheme
#     RETURNS  (public values first, private last)
#       "rsa"          bits=2048, e=65537   -> RsaKey object: key.n key.e key.d key.p key.q,
#                                              key.publickey() = public key
#       "rsa_textbook" bits=1024 or p=, q=, e= -> (n, e, d)  (small given primes for hand work;
#                                              if gcd(e, phi) != 1 the next valid e is used)
#       "elgamal"      bits=512, g=2, p=, x= -> (p, g, y, x)  y = g^x mod p
#                                              (give p, g to reuse a group; x for a given key)
#       "ecc"          curve="secp256r1"    -> EC private key; .public_key() = public point.
#                                              Curves: secp256r1 secp384r1 secp521r1 secp256k1.
#                                              Same key works for ECIES, ECDH and ECDSA.
#       "rabin"        bits=1024            -> (n, p, q)  with p = q = 3 (mod 4)
#       "paillier"     bits=1024            -> (pub, priv) = ((n, g), (lam, mu, n)), g = n + 1
#                      threshold=(t, k)     -> (pub, shares): private key split into k Shamir
#                                              shares, any t decrypt (paillier_cipher)
#       "schnorr"      bits=1024, qbits=160 -> (p, q, g, y, x);  params=(p, q, g) reuses a group
#       "dh"           p=DH_P, g=DH_G       -> (A, a)  public A = g^a mod p, private a
#     EXAMPLE  key = generate_keys("rsa", 2048);       pub = key.publickey()
#              p, g, y, x = generate_keys("elgamal", 512)
#              n, e, d = generate_keys("rsa_textbook", p=17, q=19, e=5)
#              pub, priv = generate_keys("paillier", 1024)
#              A, a = generate_keys("dh")
def generate_keys(scheme, bits=None, as_json=False, **opt):
    s = scheme.lower()
    if s == "rsa":
        key = RSA.generate(bits or 2048, e=opt.get("e", 65537))
        return (key.publickey().export_key().decode(), key.export_key().decode()) if as_json else key
    if s == "rsa_textbook":
        p = opt.get("p") or getPrime((bits or 1024) // 2)
        q = opt.get("q") or getPrime((bits or 1024) // 2)
        e, phi = opt.get("e", 65537), (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            new_e = next(x for x in range(3, phi, 2) if math.gcd(x, phi) == 1)
            print(f"  [note] gcd(e={e}, phi={phi}) != 1 -> using e = {new_e}")
            e = new_e
        n, d = p * q, pow(e, -1, phi)
        return ({"n": n, "e": e}, {"n": n, "d": d}) if as_json else (n, e, d)
    if s == "elgamal":
        p, g = opt.get("p") or getPrime(bits or 512), opt.get("g", 2)
        x = opt.get("x") or secrets.randbelow(p - 3) + 2
        y = pow(g, x, p)
        return ({"p": p, "g": g, "y": y}, {"x": x}) if as_json else (p, g, y, x)
    if s in ("ecc", "ecdh", "ecdsa"):
        priv = ec.generate_private_key(getattr(ec, opt.get("curve", "secp256r1").upper())())
        if as_json:
            return (priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()).decode())
        return priv
    if s == "rabin":
        def prime_3mod4():
            while True:
                p = getPrime((bits or 1024) // 2)
                if p % 4 == 3:
                    return p
        p, q = prime_3mod4(), prime_3mod4()
        return ({"n": p * q}, {"p": p, "q": q}) if as_json else (p * q, p, q)
    if s == "paillier":
        b = bits or 1024
        p, q = getPrime(b // 2), getPrime(b // 2)
        n = p * q
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)           # lcm(p-1, q-1)
        pub, priv = (n, n + 1), (lam, pow(lam, -1, n), n)
        if "threshold" in opt:                                      # split lam, discard priv
            t, k = opt["threshold"]
            return pub, shamir(lam, t, k, field_prime(n.bit_length()))
        return (list(pub), list(priv)) if as_json else (pub, priv)
    if s == "schnorr":
        if "params" in opt:
            p, q, g = opt["params"]
        else:
            pbits, qbits = bits or 1024, opt.get("qbits", 160)
            q = getPrime(qbits)
            while True:                                             # p = 2*q*r + 1 prime
                p = 2 * q * random.getrandbits(pbits - qbits - 1) + 1
                if p.bit_length() == pbits and isPrime(p):
                    break
            h = 2
            while pow(h, (p - 1) // q, p) == 1:
                h += 1
            g = pow(h, (p - 1) // q, p)                             # g has order q
        x = secrets.randbelow(q - 1) + 1
        y = pow(g, x, p)
        return ({"p": p, "q": q, "g": g, "y": y}, {"x": x}) if as_json else (p, q, g, y, x)
    if s == "dh":
        p, g = opt.get("p", DH_P), opt.get("g", DH_G)
        a = secrets.randbelow(p - 3) + 2
        return ({"A": pow(g, a, p)}, {"a": a}) if as_json else (pow(g, a, p), a)
    raise ValueError(f"unknown scheme {scheme!r}")


# ---------------------------------------------------------------------------
# derive_key: password -> key with PBKDF2-HMAC-SHA256 (key derivation function)
# [1] PREREQS  imports  : from Crypto.Hash import SHA256
#                         from Crypto.Protocol.KDF import PBKDF2
#                         from Crypto.Random import get_random_bytes
#              functions: (none - standalone)
#              pip      : pycryptodome
# [2] PARAMS   password   : str
#              salt       : bytes, None = new random 16-byte salt (store it with the result)
#              iterations : work factor (more = slower brute force)
#              length     : key size in bytes (32 = AES-256)
#     RETURNS  (key, salt)
#     EXAMPLE  key, salt = derive_key("hunter2");  same, _ = derive_key("hunter2", salt)
def derive_key(password, salt=None, iterations=100_000, length=32):
    salt = salt or get_random_bytes(16)
    return PBKDF2(password, salt, length, count=iterations, hmac_hash_module=SHA256), salt


# ---------------------------------------------------------------------------
# djb2_hash: the custom hash of Lab 5 Q1 - h = 5381, h = h*33 + ord(c) per char, 32-bit
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   s   : string
#              mix : True -> extra xor-shift / multiply finaliser so a 1-bit change in the input
#                    flips ~half the output bits;  False -> classic djb2
#     RETURNS  int 0 .. 2^32-1   (print with f"{h:08X}")
#     CHANGE   64-bit version -> mask 0xFFFFFFFFFFFFFFFF;  other start / multiplier -> 5381 / << 5
#     EXAMPLE  djb2_hash("Information Security")
def djb2_hash(s, mix=True):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF        # h*33 + c, kept in 32 bits
    if mix:                                              # murmur3-style bit mixing
        h ^= h >> 16
        h = (h * 0x85EBCA6B) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xC2B2AE35) & 0xFFFFFFFF
        h ^= h >> 16
    return h


# ---------------------------------------------------------------------------
# hash_hex: hash of any data as hex - MD5, SHA-1, SHA-2, SHA-3, BLAKE2, djb2, or HMAC with a key
# [1] PREREQS  imports  : import hashlib, hmac
#              functions: to_bytes(), djb2_hash()
# [2] PARAMS   data : str / bytes / int
#              algo : "md5" "sha1" "sha224" "sha256" "sha384" "sha512" "sha3_256" "blake2b"
#                     "djb2" (Lab 5 custom hash, 8 hex chars)
#              key  : bytes -> keyed hash HMAC-<algo>(key, data)  (MAC with a shared key)
#     RETURNS  hex string
#     EXAMPLE  hash_hex("hello", "md5")      hash_hex(record, "sha512")
#              hash_hex(msg, "sha256", key=shared_key)                # HMAC-SHA256
def hash_hex(data, algo="sha256", key=None):
    if algo == "djb2":
        return f"{djb2_hash(data if isinstance(data, str) else to_bytes(data).decode(errors='replace')):08x}"
    if key is not None:
        return hmac.new(to_bytes(key), to_bytes(data), algo).hexdigest()
    return hashlib.new(algo, to_bytes(data)).hexdigest()


_HASH = {"md5": MD5, "sha1": SHA1, "sha224": SHA224, "sha256": SHA256, "sha384": SHA384,
         "sha512": SHA512}                       # hash names usable for RSA PKCS#1 signatures


# ---------------------------------------------------------------------------
# signature: SIGN or VERIFY with RSA, raw RSA (lab website), ElGamal, Schnorr, ECDSA or HMAC
# [1] PREREQS  imports  : import hashlib, hmac, math, secrets
#                         from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512
#                         from Crypto.Signature import pkcs1_15
#                         from cryptography.exceptions import InvalidSignature
#                         from cryptography.hazmat.primitives import hashes
#                         from cryptography.hazmat.primitives.asymmetric import ec
#              functions: to_bytes(), _HASH
#              pip      : cryptography pycryptodome
# [2] PARAMS   scheme : "rsa"     RSA PKCS#1 v1.5 of hash(data)    key: RsaKey
#                       "rsa_raw" s = m^d mod n (lab website)      key: (d, n) sign / (e, n) verify
#                                                                  or an RsaKey
#                       "elgamal" r = g^k, s = (H - x r) k^-1      key: (p, g, x) sign / (p, g, y) verify
#                       "schnorr" e = H(g^k || m), s = k + x e     key: (p, q, g, x) / (p, q, g, y)
#                       "ecdsa"   ECDSA                            key: EC private / public key
#                       "hmac"    HMAC tag (shared key, e.g. DH)   key: bytes (same both sides)
#              data   : message (str / bytes). rsa_raw verify: None -> return the recovered text
#              key    : private key to sign, public key to verify (see above)
#              sig    : None -> SIGN.  Given -> VERIFY that signature
#              algo   : hash used: "sha256" (default), "md5", "sha1", "sha512" ...
#     RETURNS  sign: rsa/ecdsa/hmac -> bytes, rsa_raw -> int, elgamal -> (r, s), schnorr -> (e, s)
#              verify: True / False   (rsa_raw with data=None: the recovered text)
#     CHANGE   "sign the MD5 / SHA-512 hash" -> algo="md5" / "sha512" on BOTH sign and verify
#     EXAMPLE  s = signature("rsa", doc, key);  signature("rsa", doc, key.publickey(), sig=s)
#              p, g, y, x = generate_keys("elgamal", 512)
#              s = signature("elgamal", doc, (p, g, x));  signature("elgamal", doc, (p, g, y), s)
#              signature("rsa_raw", None, (E, n), sig=parse_hex_bytes(website_sig))  # -> 'Alice'
def signature(scheme, data, key, sig=None, algo="sha256"):
    s, verify = scheme.lower(), sig is not None
    H = lambda d, mod: int.from_bytes(hashlib.new(algo, to_bytes(d)).digest(), "big") % mod
    if s == "rsa":
        h = _HASH[algo].new(to_bytes(data))
        if not verify:
            return pkcs1_15.new(key).sign(h)
        try:
            pkcs1_15.new(key).verify(h, sig)
            return True
        except (ValueError, TypeError):
            return False
    if s == "rsa_raw":
        exp, n = ((key.e if verify else key.d), key.n) if hasattr(key, "n") else key
        if not verify:
            return pow(int.from_bytes(to_bytes(data), "big"), exp, n)    # s = m^d mod n
        text = to_bytes(pow(sig, exp, n)).decode(errors="replace")      # m = s^e mod n
        return text if data is None else text == to_bytes(data).decode(errors="replace")
    if s == "elgamal":
        if not verify:
            p, g, x = key
            while True:                                  # fresh k with gcd(k, p-1) = 1
                k = secrets.randbelow(p - 3) + 2
                if math.gcd(k, p - 1) == 1:
                    break
            r = pow(g, k, p)
            return r, ((H(data, p - 1) - x * r) * pow(k, -1, p - 1)) % (p - 1)
        p, g, y = key
        r, s_ = sig
        return 0 < r < p and pow(g, H(data, p - 1), p) == (pow(y, r, p) * pow(r, s_, p)) % p
    if s == "schnorr":
        p, q, g, xy = key
        if not verify:
            k = secrets.randbelow(q - 1) + 1
            e = H(to_bytes(pow(g, k, p)) + to_bytes(data), q)
            return e, (k + xy * e) % q
        e, s_ = sig
        r = (pow(g, s_, p) * pow(xy, -e, p)) % p             # r' = g^s * y^-e
        return H(to_bytes(r) + to_bytes(data), q) == e
    if s == "ecdsa":
        alg = ec.ECDSA(getattr(hashes, algo.upper())())
        if not verify:
            return key.sign(to_bytes(data), alg)
        try:
            key.verify(sig, to_bytes(data), alg)
            return True
        except InvalidSignature:
            return False
    if s == "hmac":
        tag = hmac.new(to_bytes(key), to_bytes(data), algo).digest()
        return hmac.compare_digest(tag, sig) if verify else tag
    raise ValueError(f"unknown scheme {scheme!r}")


# ---------------------------------------------------------------------------
# paillier_cipher: Paillier encryption / decryption (normal or threshold), one value or a list
# [1] PREREQS  imports  : import math, secrets
#              functions: MERSENNE_1279, _MERSENNE_EXPONENTS, field_prime(), shamir()
# [2] PARAMS   data    : int m (0 <= m < n) or a list of ints to encrypt;
#                        ciphertext int or list to decrypt
#              key     : pub (n, g) to encrypt;  priv (lam, mu, n) to decrypt;  OR a list of
#                        >= t Shamir shares from generate_keys("paillier", threshold=(t, k))
#              decrypt : False = encrypt, True = decrypt
#              pub     : public key - needed only for threshold (shares) decryption
#     HOW      E(m) = g^m * r^n mod n^2 (random r);  D(c) = L(c^lam mod n^2) * mu mod n,
#              L(u) = (u - 1) / n.   Too few shares -> wrong random-looking number.
#     CHANGE   negative / decimal amounts -> store round(x * 100) and divide after decrypting
#     EXAMPLE  pub, priv = generate_keys("paillier", 1024)
#              c = paillier_cipher(15, pub);   paillier_cipher(c, priv, decrypt=True)   # 15
#              cs = paillier_cipher([5, 7, 9], pub)
#              paillier_cipher(total, shares[:2], decrypt=True, pub=pub)              # threshold
def paillier_cipher(data, key, decrypt=False, pub=None):
    if isinstance(data, list):
        return [paillier_cipher(d, key, decrypt, pub) for d in data]
    if not decrypt:
        n, g = key
        n2 = n * n
        while True:
            r = secrets.randbelow(n - 1) + 1
            if math.gcd(r, n) == 1:
                break
        return (pow(g, data, n2) * pow(r, n, n2)) % n2
    if isinstance(key[0], (list, tuple)):                         # list of Shamir shares
        n = pub[0]
        lam = shamir(key, prime=field_prime(n.bit_length()))
        mu = pow(lam, -1, n) if math.gcd(lam, n) == 1 else 0
    else:
        lam, mu, n = key
    return ((pow(data, lam, n * n) - 1) // n * mu) % n


# ---------------------------------------------------------------------------
# homomorphic: compute on CIPHERTEXTS - Paillier (add), RSA and ElGamal (multiply)
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   scheme : "paillier" | "rsa" | "elgamal"
#              c      : op "combine" -> LIST of ciphertexts;  *_const ops -> ONE ciphertext
#              pub    : paillier (n, g);  rsa n, (e, n) or RsaKey;  elgamal p or (p, g, y)
#              op     : "combine"   paillier: E(a)*E(b)*... = E(a + b + ...)   (sum)
#                                   rsa / elgamal: = E(a * b * ...)            (product)
#                       "add_const" paillier: E(a) * g^k = E(a + k)
#                       "mul_const" paillier: E(a)^k = E(a * k);  elgamal (c1, c2 k) = E(a k);
#                                   rsa: E(a) * k^e = E(a * k)  (pub must include e)
#              k      : the plain constant for *_const
#     RETURNS  a ciphertext of the result - decrypt it with the matching *_cipher function
#     EXAMPLE  s = homomorphic("paillier", [ca, cb], pub)          # E(a + b)
#              homomorphic("paillier", ca, pub, "mul_const", 3)   # E(3a)
#              homomorphic("rsa", [c1, c2], n)                   # E(a * b), textbook RSA
#              homomorphic("elgamal", [c1, c2], p)
def homomorphic(scheme, c, pub, op="combine", k=None):
    s, op = scheme.lower(), op.lower()
    if s == "paillier":
        n, g = pub
        n2 = n * n
        if op == "combine":
            out = 1
            for x in c:
                out = out * x % n2
            return out
        if op == "add_const":
            return c * pow(g, k, n2) % n2
        if op == "mul_const":
            return pow(c, k, n2)
    elif s == "rsa":
        if hasattr(pub, "n"):
            e, n = pub.e, pub.n
        else:
            e, n = pub if isinstance(pub, (tuple, list)) else (None, pub)
        if op == "combine":
            out = 1
            for x in c:
                out = out * x % n
            return out
        if op == "mul_const":
            return c * pow(k, e, n) % n
    elif s == "elgamal":
        p = pub if isinstance(pub, int) else pub[0]
        if op == "combine":
            a = b = 1
            for c1, c2 in c:
                a, b = a * c1 % p, b * c2 % p
            return a, b
        if op == "mul_const":
            return c[0], c[1] * k % p
    raise ValueError(f"op {op!r} not supported for {scheme!r}")


MERSENNE_1279 = 2 ** 1279 - 1           # default Shamir prime: big enough for 1024-bit secrets


_MERSENNE_EXPONENTS = [127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941]


# ---------------------------------------------------------------------------
# field_prime: smallest Mersenne prime 2^e - 1 bigger than a `bits`-bit secret (Shamir field)
# [1] PREREQS  imports  : (none)
#              functions: _MERSENNE_EXPONENTS
# [2] PARAMS   bits : size of the secret, e.g. n.bit_length()
#     EXAMPLE  shamir(secret, 3, 5, prime=field_prime(secret.bit_length()))
def field_prime(bits):
    return next(2 ** e - 1 for e in _MERSENNE_EXPONENTS if e > bits)


# ---------------------------------------------------------------------------
# shamir: Shamir secret sharing - SPLIT a secret into n shares, or COMBINE t shares back
# [1] PREREQS  imports  : import secrets
#              functions: MERSENNE_1279
# [2] PARAMS   data  : int secret -> split;   list of (x, y) shares -> combine
#              t     : threshold (shares needed);   n : number of shares made   (split only)
#              prime : field prime, must be > secret (same value for split and combine)
#     RETURNS  split: [(1, y1), (2, y2), ...];   combine: the secret (wrong value if < t shares)
#     EXAMPLE  shares = shamir(123456789, 3, 5);   shamir(shares[:3])    # 123456789
def shamir(data, t=None, n=None, prime=MERSENNE_1279):
    if isinstance(data, int):                            # SPLIT: random polynomial, f(0) = secret
        if not 0 <= data < prime:
            raise ValueError("secret too large for the Shamir prime - pass prime=field_prime(bits)")
        coeffs = [data] + [secrets.randbelow(prime) for _ in range(t - 1)]
        return [(i, sum(c * pow(i, j, prime) for j, c in enumerate(coeffs)) % prime)
                for i in range(1, n + 1)]
    s = 0                                                # COMBINE: Lagrange interpolation at x = 0
    for i, (xi, yi) in enumerate(data):
        num = den = 1
        for j, (xj, _) in enumerate(data):
            if i != j:
                num, den = num * -xj % prime, den * (xi - xj) % prime
        s = (s + yi * num * pow(den, -1, prime)) % prime
    return s


# ---------------------------------------------------------------------------
# search_token: searchable-index token HMAC-SHA256(key, keyword) - store {token: [record ids]}
# [1] PREREQS  imports  : import hashlib, hmac
#              functions: to_bytes(), djb2_hash(), hash_hex()
# [2] PARAMS   key     : secret index key (bytes);   keyword : value to index / search for
#     HOW      to search, compute the token of the query and look it up: the server (or the
#              JSON file) never contains the keyword itself. Case and spaces are normalised.
#     EXAMPLE  db["index"].setdefault(search_token(K, "const:KA-21"), []).append(ballot_id)
def search_token(key, keyword):
    return hash_hex(str(keyword).strip().lower(), "sha256", key=key)


# ---------------------------------------------------------------------------
# menu: numbered menu - pick ONE option (list), or a LOOPING menu that runs functions (dict)
# [1] PREREQS  imports  : import sys
#              functions: ask()
# [2] PARAMS   title      : heading printed above the options
#              options    : list  -> show once, return the chosen text
#                           dict  -> {"label": function}: run the chosen function, show the menu
#                                    again, until exit_label is chosen; errors inside a
#                                    function are printed and the menu continues
#              exit_label : extra last option that leaves a looping menu
#     EXAMPLE  choice = menu("Main menu", ["Login", "Exit"])
#              menu("Researcher menu", {"Submit grant": submit, "View all": view_all}, "Logout")
def menu(title, options, exit_label="Back"):
    if isinstance(options, dict):
        while True:
            choice = menu(title, list(options) + [exit_label])
            if choice == exit_label:
                return
            try:
                options[choice]()
            except KeyboardInterrupt:
                print("\n  (cancelled)")
            except Exception as e:
                print(f"  ! {type(e).__name__}: {e}")
    print(f"\n========== {title} ==========")
    for i, o in enumerate(options, 1):
        print(f"  {i}. {o}")
    return options[ask("Enter choice", cast=int, valid=lambda v: 1 <= v <= len(options),
                       error=f"choose 1-{len(options)}") - 1]


# ---------------------------------------------------------------------------
# json_store: persistent storage in a JSON file - LOAD, SAVE, or LOAD-OR-CREATE (keys)
# [1] PREREQS  imports  : import json, os
#              functions: (none - standalone)
# [2] PARAMS   path    : file name, e.g. HERE / "db.json"
#              data    : given -> SAVE it (atomic write) and return it
#              default : returned when loading and the file does not exist yet
#              create  : function run ONCE when the file does not exist (e.g. make_keys);
#                        its result is saved and returned - keys survive restarts
#     STORE    ints, str, lists, dicts. bytes -> .hex() / bytes.fromhex();
#              RSA keys -> key.export_key().decode() / RSA.import_key(text)
#     CORRUPT  unreadable file -> renamed to .bak, a warning is printed, default / create used
#     EXAMPLE  K  = json_store(KEYS_FILE, create=make_keys)
#              db = json_store(DB_FILE, default={"records": []})
#              json_store(DB_FILE, db)                                   # save
def json_store(path, data=None, default=None, create=None):
    if data is not None:
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        return data
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        print(f"  ! {path} is corrupted - moved to {path}.bak, starting fresh")
        os.replace(path, f"{path}.bak")
    if create is None:
        return default
    print(f"[setup] generating keys -> {os.path.basename(str(path))} (first run only)")
    return json_store(path, create())


# ---------------------------------------------------------------------------
# canonical: stable bytes of a dict / list (sorted keys) - hash and sign records with this
# [1] PREREQS  imports  : import json
#              functions: (none - standalone)
# [2] PARAMS   obj : dict / list of JSON-able values
#     EXAMPLE  sig = signature("rsa", canonical({k: r[k] for k in ("id", "ct")}), priv)
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# password_hash: login passwords - HASH a new password, or CHECK one against the stored hash
# [1] PREREQS  imports  : import hmac
#                         from Crypto.Hash import SHA256
#                         from Crypto.Protocol.KDF import PBKDF2
#                         from Crypto.Random import get_random_bytes
#              functions: derive_key()
#              pip      : pycryptodome
# [2] PARAMS   password : the password typed
#              stored   : None -> return a new 'salt:key' PBKDF2-SHA256 string to store
#                         'salt:key' string -> return True / False (does the password match?)
#     EXAMPLE  users = {"alice": {"role": "Doctor", "pw": password_hash("alice123")}}
#              password_hash("alice123", users["alice"]["pw"])         # True
def password_hash(password, stored=None):
    if stored is None:
        key, salt = derive_key(password, iterations=50_000)
        return f"{salt.hex()}:{key.hex()}"
    salt, key = stored.split(":")
    return hmac.compare_digest(derive_key(password, bytes.fromhex(salt), 50_000)[0].hex(), key)


# ---------------------------------------------------------------------------
# login: username + password prompt (hidden), up to `attempts` tries
# [1] PREREQS  imports  : import hmac, sys
#                         from Crypto.Hash import SHA256
#                         from Crypto.Protocol.KDF import PBKDF2
#                         from Crypto.Random import get_random_bytes
#              functions: ask(), derive_key(), password_hash()
#              pip      : pycryptodome
# [2] PARAMS   users    : {name: {"role": "...", "pw": password_hash("...")}}
#              attempts : tries before giving up
#     RETURNS  (name, role) on success, (None, None) after too many failures
#     EXAMPLE  user, role = login(K["users"])
def login(users, attempts=3):
    for _ in range(attempts):
        name = ask("Username")
        pw = ask("Password", secret=True)
        if name in users and password_hash(pw, users[name]["pw"]):
            print(f"  Logged in as {name} ({users[name]['role']})")
            return name, users[name]["role"]
        print("  ! wrong username or password")
    print("  ! too many failed attempts")
    return None, None


# ===========================================================================
# QUESTION-SPECIFIC CODE
# ===========================================================================
HERE = os.path.dirname(os.path.abspath(__file__))
KEYS, DB = os.path.join(HERE, "grant_keys.json"), os.path.join(HERE, "grant_db.json")


def make_keys():
    rsa = generate_keys("rsa", 2048)
    pub, priv = generate_keys("paillier", 1024)
    return {"aes192": get_random_bytes(24).hex(), "index": get_random_bytes(32).hex(),
            "rsa_priv": rsa.export_key().decode(), "rsa_pub": rsa.publickey().export_key().decode(),
            "p_pub": pub, "p_priv": priv,
            "users": {"researcher": {"role": "Researcher", "pw": password_hash("res123")},
                      "reviewer": {"role": "Reviewer", "pw": password_hash("rev123")},
                      "finance": {"role": "Finance Officer", "pw": password_hash("fin123")}}}


K = json_store(KEYS, create=make_keys)
AES_KEY, INDEX_KEY = bytes.fromhex(K["aes192"]), bytes.fromhex(K["index"])
RSA_PRIV, RSA_PUB = RSA.import_key(K["rsa_priv"]), RSA.import_key(K["rsa_pub"])
db = json_store(DB, default={"records": []})


def record_bytes(r):                                  # the part that is hashed and signed
    return canonical({k: r[k] for k in ("gid", "iv", "desc_ct", "amount_ct")})


def status(r):
    h = hash_hex(record_bytes(r), "md5") == r["md5"]
    try:
        s = signature("rsa", record_bytes(r), RSA_PUB, sig=bytes.fromhex(r["sig"]), algo="md5")
    except ValueError:
        s = False
    return "OK" if h and s else f"TAMPERED (MD5 {'ok' if h else 'MISMATCH'}, signature {'ok' if s else 'INVALID'})"


def find(gid):                                        # index search: only the HMAC token is compared
    tok = search_token(INDEX_KEY, gid)
    return next((r for r in db["records"] if r["token"] == tok), None)


def ask_record():
    r = find(ask("Grant ID", cast=str.upper))
    if not r:
        print("  ! no such Grant ID")
    return r


# ---------- Researcher ----------
def submit():
    gid = ask("Grant ID", cast=str.upper, valid=lambda v: v.replace("-", "").isalnum() and not find(v),
              error="letters/digits/- only, and must not exist already")
    desc = ask("Grant description")
    amount = ask("Grant amount", cast=float, valid=lambda v: v > 0, error="must be > 0")
    ct, iv = symmetric("AES", AES_KEY, desc, "CBC")                               # AES-192
    r = {"gid": gid, "iv": iv.hex(), "desc_ct": ct.hex(),
         "amount_ct": str(paillier_cipher(round(amount * 100), K["p_pub"])),        # Paillier (paise)
         "token": search_token(INDEX_KEY, gid)}
    r["md5"] = hash_hex(record_bytes(r), "md5")                                    # MD5
    r["sig"] = signature("rsa", record_bytes(r), RSA_PRIV, algo="md5").hex()       # RSA sign
    db["records"].append(r)
    json_store(DB, db)
    print(f"  stored {gid}\n    AES-192 : {fmt(r['desc_ct'], 'short', 40)}\n"
          f"    Paillier: {fmt(r['amount_ct'], 'short', 40)}\n    MD5     : {r['md5']}\n"
          f"    RSA sig : {fmt(r['sig'], 'short', 40)}")


def view_all():
    print_table(["Grant ID", "Description (AES)", "Amount (Paillier)", "MD5", "Signature"],
                [[r["gid"], fmt(r["desc_ct"], "short", 16), fmt(r["amount_ct"], "short", 16), r["md5"],
                  fmt(r["sig"], "short", 12)] for r in db["records"]] or [["(none)", "", "", "", ""]])


# ---------- Reviewer ----------
def verify_all():
    print_table(["Grant ID", "Recomputed MD5", "Status"],
                [[r["gid"], hash_hex(record_bytes(r), "md5"), status(r)] for r in db["records"]]
                or [["(none)", "", ""]])


def search():
    r = ask_record()
    if r:
        print(f"  found via token {r['token'][:16]}... -> {r['gid']}, status {status(r)} (contents stay encrypted)")


def view_hex():
    r = ask_record()
    if not r:
        return
    try:
        pt = symmetric("AES", AES_KEY, bytes.fromhex(r["desc_ct"]), "CBC", decrypt=True, iv=bytes.fromhex(r["iv"]))
    except ValueError:
        print("  ! cannot decrypt - ciphertext tampered")
        return
    print(f"  status: {status(r)}\n" + fmt(pt, "dump"))


# ---------- Finance Officer ----------
def aggregate():
    sel = ask("Grant IDs (comma separated) or ALL", cast=str.upper)
    chosen = db["records"] if sel == "ALL" else [find(g.strip()) for g in sel.split(",")]
    valid = []
    for r in filter(None, chosen):
        st = status(r)
        print(f"  {r['gid']:<10} {st}")
        if st == "OK":
            valid.append(r)
    if not valid:
        print("  ! no valid grants selected")
        return
    enc = homomorphic("paillier", [int(r["amount_ct"]) for r in valid], K["p_pub"])
    print(f"  E(total) = {fmt(enc, 'short', 48)}")
    print(f"  TOTAL of {len(valid)} grant(s) = {paillier_cipher(enc, K['p_priv'], decrypt=True) / 100:,.2f}"
          "  (only the aggregate was decrypted)")


def tamper():                                         # demo: attacker edits the stored file
    r = ask_record()
    if r:
        r["amount_ct"] = str(paillier_cipher(99999999, K["p_pub"]))
        json_store(DB, db)
        print(f"  amount of {r['gid']} replaced in {os.path.basename(DB)}")


MENUS = {"Researcher": {"Submit grant": submit, "View all records": view_all},
         "Reviewer": {"Verify signatures + MD5": verify_all, "Search by Grant ID": search,
                      "View decrypted description (hex dump)": view_hex},
         "Finance Officer": {"Aggregate selected grants": aggregate}}

if __name__ == "__main__":
    print(f"{len(db['records'])} record(s) loaded from {os.path.basename(DB)}")
    while True:
        choice = menu("SECURE GRANT EXPENSE PORTAL",
                      [f"{r} login" for r in MENUS] + ["Simulate tampering", "Exit"])
        if choice == "Exit":
            break
        if choice == "Simulate tampering":
            tamper()
            continue
        role = choice[:-len(" login")]
        user, got = login(K["users"])
        if got and got != role:
            print(f"  ! {user} is not a {role}")
        elif got:
            menu(f"{role} menu ({user})", MENUS[role], "Logout")
