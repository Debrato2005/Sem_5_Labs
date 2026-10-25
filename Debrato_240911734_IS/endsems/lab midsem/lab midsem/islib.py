"""
islib.py  -  Information Security Lab master library (Labs 1 - 8)
=====================================================================

Install once (before the internet goes off):
    pip3 install pycryptodome cryptography sympy numpy matplotlib python-gnupg

Use from any script:
    import sys; sys.path.insert(0, "/path/to/folder/with/islib")
    from islib import *

List every function:            python3 islib.py
Search for a function:          python3 islib.py rsa
Full instructions for one:      python3 islib.py symmetric

HOW EVERY FUNCTION IS DOCUMENTED  (comment block directly above each def / class)
    [1] PREREQS  imports   : import lines to paste if you copy the function into another file
                 functions : other islib functions / constants it needs - copy them too.
                             The list already includes what THEY need, in file order.
                 pip       : packages that must be installed
    [2] PARAMS   what each argument means;  RETURNS what you get back;
        CHANGE   what to edit when the question is different;  EXAMPLE a ready-made call

SECTIONS (search for the "# ===" banners)
    0. Utilities ............ ask, banner, to_bytes, fmt, key_bytes, timed, print_table, plot
    1. Classical ciphers .... classical_cipher (additive / multiplicative / affine / vigenere /
                              autokey), playfair, hill, transposition (columnar / permutation /
                              rail fence), brute_force, known_plaintext_attack
    2. Symmetric ............ symmetric (DES / 3DES / AES in ECB CBC CFB OFB CTR GCM EAX),
                              sym_benchmark, aes_encrypt_block_verbose (every AES round)
    3. Asymmetric ........... generate_keys (every scheme), rsa_cipher, elgamal_cipher,
                              ecc_cipher, rabin_cipher, dh_shared
    4. Key management ....... KeyManager, AccessControl, key_entropy, derive_key, rsa_weak_attack
    5. Hashing + sockets .... hash_hex (md5 / sha* / djb2 / HMAC), djb2_hash, find_collisions,
                              sock_send / sock_recv, run_server, connect
    6. Digital signatures ... signature (rsa / rsa_raw / elgamal / schnorr / ecdsa / hmac), timestamp
    7. Homomorphic .......... paillier_cipher, homomorphic (add / multiply / constants), shamir, tally
    8. Searchable enc ....... SSE, PKSE, search_token, gpg_available, analyze_snort_alerts
    9. Exam program helpers . menu, json_store, canonical, password_hash, login, password_seal

CONVENTIONS
    * Classical ciphers: text in, text out (letters only, upper-case result).
    * Modern ciphers: bytes in, bytes out; str is auto-converted with to_bytes().
    * Every *_cipher / symmetric function ENCRYPTS by default; pass decrypt=True to decrypt.
    * Key tuples are always PUBLIC values first, PRIVATE last, e.g. ElGamal (p, g, y, x).
"""

import base64
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import socket
import string
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# =====================================================================
# 0. UTILITIES
# =====================================================================

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
# banner: print a heading between two lines of '=' (separates the parts of an answer)
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   title : heading text
#     EXAMPLE  banner("a) Additive cipher  C = (P + k) mod 26")
def banner(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


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
# parse_hex_bytes: read a number written as hex bytes ('0xc8 0x93 ...' or 'c893a9...')
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   s : '0xc8 0x93 0xa9' (website format, spaces/commas/newlines ok) or 'c893a9'
#     RETURNS  int  (inverse of fmt(x, "0x"))
#     EXAMPLE  sig = parse_hex_bytes("0xc8 0x93 0xa9 0x0d")
def parse_hex_bytes(s):
    parts = s.replace(",", " ").split()
    data = bytes(int(x, 16) for x in parts) if len(parts) > 1 else bytes.fromhex(s.replace("0x", ""))
    return int.from_bytes(data, "big")


# ---------------------------------------------------------------------------
# key_bytes: turn a key / IV / nonce written in the question into exactly `size` bytes
# [1] PREREQS  imports  : import string
#              functions: (none - standalone)
# [2] PARAMS   key  : hex text "A1B2C3D4E5F60708", ASCII text "A1B2C3D4", or bytes
#              size : bytes needed - DES 8, 3DES 24 (or 16), AES-128 16, AES-192 24,
#                     AES-256 32, IV 8 (DES) / 16 (AES), CTR nonce 4 (DES) / 8 (AES)
#     RETURNS  bytes of length size. Tries: hex of the right length -> ASCII of the right
#              length -> ASCII cut / zero-padded (prints a note you can quote in the viva)
#     EXAMPLE  key = key_bytes("0123456789ABCDEF0123456789ABCDEF", 16)   # AES-128 from hex
#              iv  = key_bytes("12345678", 8)                            # DES IV from ASCII
def key_bytes(key, size):
    if isinstance(key, bytes) and len(key) == size:
        return key
    key = key.decode() if isinstance(key, bytes) else key
    if all(c in string.hexdigits for c in key) and len(key) == 2 * size:
        return bytes.fromhex(key)
    if len(key) == size:
        return key.encode()
    fixed = key.encode()[:size].ljust(size, b"\0")
    print(f"  [note] key '{key}' is not {size} bytes as hex or ASCII -> using ASCII "
          f"truncated/padded to {size} bytes: {fixed}")
    return fixed


# ---------------------------------------------------------------------------
# timed: run a function `repeat` times and measure the average time (every benchmark question)
# [1] PREREQS  imports  : import time
#              functions: (none - standalone)
# [2] PARAMS   fn       : function to time - pass the NAME, do not call it
#              *args    : its positional arguments;   **kwargs : its keyword arguments
#              repeat   : number of runs averaged (bigger = steadier numbers)
#     RETURNS  (result of the last call, average seconds)   ->  * 1000 = ms,  * 1e6 = us
#     EXAMPLE  ct, t = timed(symmetric, "AES", key, msg, "CBC", repeat=100)
#              key, t = timed(generate_keys, "rsa", 2048)
def timed(fn, *args, repeat=1, **kwargs):
    start = time.perf_counter()
    for _ in range(repeat):
        result = fn(*args, **kwargs)
    return result, (time.perf_counter() - start) / repeat


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


# ---------------------------------------------------------------------------
# plot: bar chart or line graph saved as PNG (and shown when run from a terminal)
# [1] PREREQS  imports  : import os, sys
#              functions: (none - standalone)
#              pip      : matplotlib numpy
# [2] PARAMS   data     : {label: value}                  -> one bar / point per label
#                         {group: {series: value}}        -> grouped bars / one line per series
#              title    : graph title;   ylabel / xlabel : axis titles
#              filename : PNG file written in the folder you run from, e.g. "aes_modes.png"
#              kind     : "bar" (default) or "line" (good for time vs message size)
#     CHANGE   bigger figure -> figsize;  log scale -> add ax.set_yscale("log")
#     EXAMPLE  plot({"DES": 12.1, "AES-128": 4.3}, "Encryption time", "us", "time.png")
#              plot({"1 KB": {"RSA": 2.1, "ECC": 0.9}, "10 KB": {"RSA": 2.4, "ECC": 1.1}},
#                   "Encrypt time", "ms", "rsa_ecc.png", kind="line", xlabel="message size")
def plot(data, title, ylabel, filename, kind="bar", xlabel=""):
    import matplotlib
    if not sys.stdin.isatty():
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    if not any(isinstance(v, dict) for v in data.values()):
        data = {label: {"": v} for label, v in data.items()}      # flat dict -> single series
    groups = list(data)
    series = list(dict.fromkeys(s for g in groups for s in data[g]))
    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(max(6, len(groups) * 1.6), 4.5))
    if kind == "line":
        for s in series:
            ax.plot(x, [data[g].get(s, np.nan) for g in groups], marker="o", label=s or None)
    else:
        w = 0.8 / len(series)
        for i, s in enumerate(series):
            ax.bar(x + i * w - 0.4 + w / 2, [data[g].get(s, 0) for g in groups], w, label=s or None)
    ax.set_xticks(x, [str(g) for g in groups])
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    if series != [""]:
        ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(filename, dpi=120)
    print(f"  graph saved -> {os.path.abspath(filename)}")
    if sys.stdin.isatty():
        plt.show()
    plt.close(fig)


# =====================================================================
# 1. CLASSICAL CIPHERS  (Lab 1)
#    Letters A-Z only; spaces/punctuation are dropped (questions say
#    "ignore the space").  Numbers: A=0 ... Z=25.
# =====================================================================

ALPHA = string.ascii_uppercase           # alphabet; every classical cipher works mod len(ALPHA)
EN_FREQ = dict(zip(ALPHA, [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4,
                           6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074]))


# ---------------------------------------------------------------------------
# clean: keep only the letters of ALPHA, upper-cased  ('I am x!' -> 'IAMX')
# [1] PREREQS  imports  : import string
#              functions: ALPHA
# [2] PARAMS   text : any string
#     CHANGE   keep digits too -> ALPHA = string.ascii_uppercase + string.digits (mod 36)
def clean(text):
    return "".join(c for c in text.upper() if c in ALPHA)


# ---------------------------------------------------------------------------
# classical_cipher: additive (Caesar / shift), multiplicative, affine, Vigenere, autokey
#                   - encryption AND decryption in one function
# [1] PREREQS  imports  : import math, string
#              functions: ALPHA, clean()
# [2] PARAMS   text    : plaintext or ciphertext; non-letters are dropped, result is A-Z
#              cipher  : "additive" (or "caesar" / "shift")   C = P + k
#                        "multiplicative"                     C = P * k
#                        "affine"                             C = a*P + b
#                        "vigenere"                           C_i = P_i + K_(i mod keylen)
#                        "autokey"                            key stream = key, then plaintext
#              key     : additive / multiplicative -> int, e.g. 20 / 15
#                        affine   -> (a, b), e.g. (15, 20)
#                        vigenere -> word, e.g. "dollars"
#                        autokey  -> int (7) or word ("deceptive")
#              decrypt : False = encrypt (default),  True = decrypt
#     RETURNS  upper-case string
#     CHANGE   multiplicative k / affine a must satisfy gcd(k, 26) = 1, else a ValueError says
#              to pick another key.  Caesar = additive with k = 3.
#     EXAMPLE  ct = classical_cipher("I am learning", "affine", (15, 20))
#              classical_cipher(ct, "affine", (15, 20), decrypt=True)        # 'IAMLEARNING'
#              classical_cipher("the house", "vigenere", "dollars")
def classical_cipher(text, cipher, key, decrypt=False):
    m, cipher = len(ALPHA), cipher.lower()
    p = [ALPHA.index(c) for c in clean(text)]
    if cipher in ("additive", "caesar", "shift"):
        out = [x - key if decrypt else x + key for x in p]
    elif cipher in ("multiplicative", "affine"):                 # multiplicative = affine, b = 0
        a, b = (key, 0) if cipher == "multiplicative" else key
        if math.gcd(a, m) != 1:
            raise ValueError(f"key {a} has no inverse mod {m}: pick a key with gcd(key, {m}) = 1")
        inv = pow(a, -1, m)
        out = [inv * (x - b) if decrypt else a * x + b for x in p]
    elif cipher == "vigenere":
        k = [ALPHA.index(c) for c in clean(key)]
        out = [x - k[i % len(k)] if decrypt else x + k[i % len(k)] for i, x in enumerate(p)]
    elif cipher == "autokey":
        stream = [key] if isinstance(key, int) else [ALPHA.index(c) for c in clean(key)]
        out = []
        for i, x in enumerate(p):
            y = (x - stream[i]) % m if decrypt else (x + stream[i]) % m
            stream.append(y if decrypt else x)           # key stream continues with the PLAINTEXT
            out.append(y)
    else:
        raise ValueError(f"unknown cipher {cipher!r}")
    return "".join(ALPHA[y % m] for y in out)


# ---------------------------------------------------------------------------
# playfair_matrix: the 5x5 Playfair square for a key (I and J share one cell)
# [1] PREREQS  imports  : import string
#              functions: ALPHA, clean()
# [2] PARAMS   key : key word, e.g. "GUIDANCE" (repeated letters are skipped)
#     RETURNS  list of 5 rows, each a list of 5 letters
#     CHANGE   merge Q into another letter instead of J/I -> edit the two .replace() calls
#     EXAMPLE  for row in playfair_matrix("GUIDANCE"): print(" ".join(row))
def playfair_matrix(key):
    letters = list(dict.fromkeys(clean(key).replace("J", "I") + ALPHA.replace("J", "")))
    return [letters[i:i + 5] for i in range(0, 25, 5)]


# ---------------------------------------------------------------------------
# playfair: Playfair cipher - encryption and decryption
# [1] PREREQS  imports  : import string
#              functions: ALPHA, clean(), playfair_matrix()
# [2] PARAMS   text    : message; J is treated as I, non-letters dropped
#              key     : key word, e.g. "GUIDANCE"
#              decrypt : False = encrypt, True = decrypt (filler X's stay in the output)
#              show    : True also prints the 5x5 matrix and the digraphs (working shown)
#              filler  : letter put between doubled letters and at the end of odd text
#     RULES    same row -> letter to the right (left when decrypting)
#              same column -> letter below (above when decrypting)
#              rectangle -> swap the columns
#     EXAMPLE  ct = playfair("The key is hidden under the door pad", "GUIDANCE", show=True)
#              playfair(ct, "GUIDANCE", decrypt=True)
def playfair(text, key, decrypt=False, show=False, filler="X"):
    M = playfair_matrix(key)
    pos = {M[r][c]: (r, c) for r in range(5) for c in range(5)}
    t, pairs, i = clean(text).replace("J", "I"), [], 0
    if decrypt:
        pairs = [t[j:j + 2] for j in range(0, len(t), 2)]
    while not decrypt and i < len(t):                    # split plaintext into digraphs
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else filler       # odd length -> pad with filler
        if a == b:                                       # doubled letter -> insert filler
            b, i = filler, i + 1
        else:
            i += 2
        pairs.append(a + b)
    if show:
        print("  Playfair matrix:\n" + "\n".join("    " + " ".join(row) for row in M))
        print("  Digraphs:", " ".join(pairs))
    d, out = (-1 if decrypt else 1), ""
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:                                     # same row -> shift right/left
            out += M[r1][(c1 + d) % 5] + M[r2][(c2 + d) % 5]
        elif c1 == c2:                                   # same column -> shift down/up
            out += M[(r1 + d) % 5][c1] + M[(r2 + d) % 5][c2]
        else:                                            # rectangle -> swap columns
            out += M[r1][c2] + M[r2][c1]
    return out


# ---------------------------------------------------------------------------
# hill: Hill cipher with any n x n key matrix - encryption and decryption
# [1] PREREQS  imports  : import string
#              functions: ALPHA, clean()
#              pip      : sympy
# [2] PARAMS   text    : message (padded with filler to a multiple of n)
#              K       : key matrix as a list of rows, e.g. [[3, 3], [2, 7]] or a 3x3
#              decrypt : False -> C = K * P mod 26;  True -> P = K^-1 * C mod 26
#              filler  : padding letter
#     CHANGE   det(K) must be coprime with 26 (else "Matrix det == 0; not invertible").
#              Book uses row vectors (C = P * K)? pass the transpose:  [list(r) for r in zip(*K)]
#     EXAMPLE  ct = hill("We live in an insecure world", [[3, 3], [2, 7]])
#              hill(ct, [[3, 3], [2, 7]], decrypt=True)
def hill(text, K, decrypt=False, filler="X"):
    from sympy import Matrix
    m, K = len(ALPHA), Matrix(K)
    if decrypt:
        K = K.inv_mod(m)
    p, n = clean(text), K.shape[0]
    p += filler * (-len(p) % n)
    out = ""
    for i in range(0, len(p), n):
        v = Matrix([ALPHA.index(c) for c in p[i:i + n]])          # column vector of n letters
        out += "".join(ALPHA[x % m] for x in K * v)
    return out


# ---------------------------------------------------------------------------
# transposition: keyed columnar / block permutation / rail fence - encryption and decryption
# [1] PREREQS  imports  : import string
#              functions: ALPHA, clean()
# [2] PARAMS   text    : message (letters only)
#              key     : str  -> KEYED COLUMNAR: write row-wise under the key, read columns in
#                                alphabetical order of the key letters, e.g. "ZEBRA";
#                                digits work as column numbers, e.g. "4312567"
#                        list -> BLOCK PERMUTATION (1-based): output char i of every block =
#                                input char key[i], e.g. [3, 1, 2]
#                        int  -> RAIL FENCE with that many rails, e.g. 3
#              decrypt : False = encrypt, True = decrypt
#              filler  : padding letter for columnar / permutation
#     EXAMPLE  transposition("attack at dawn", "ZEBRA")
#              transposition("abcdef", [3, 1, 2])           # 'CABFDE'
#              transposition("we are discovered", 3, decrypt=False)
def transposition(text, key, decrypt=False, filler="X"):
    t = clean(text)
    if isinstance(key, int):                             # RAIL FENCE
        if key < 2:
            return t
        cycle = 2 * (key - 1)
        rail = [min(i % cycle, cycle - i % cycle) for i in range(len(t))]   # zig-zag row of each char
        order = sorted(range(len(t)), key=lambda i: (rail[i], i))          # read rail by rail
        if not decrypt:
            return "".join(t[i] for i in order)
        out = [""] * len(t)
        for ch, i in zip(t, order):
            out[i] = ch
        return "".join(out)
    if isinstance(key, str):                             # KEYED COLUMNAR
        n, key = len(key), key.upper()
        order = sorted(range(n), key=lambda i: (key[i], i))                 # column read order
        if not decrypt:
            t += filler * (-len(t) % n)
            return "".join(t[c::n] for c in order)
        rows, cols = len(t) // n, [""] * n
        for idx, col in enumerate(order):
            cols[col] = t[idx * rows:(idx + 1) * rows]
        return "".join(cols[j][i] for i in range(rows) for j in range(n))
    m = len(key)                                         # BLOCK PERMUTATION
    if decrypt:
        key = [key.index(i) + 1 for i in range(1, m + 1)]                  # inverse permutation
    t += filler * (-len(t) % m)
    return "".join(t[b + k - 1] for b in range(0, len(t), m) for k in key)


# ---------------------------------------------------------------------------
# english_score: how English-like a text is (average letter frequency) - used to rank guesses
# [1] PREREQS  imports  : import string
#              functions: ALPHA, EN_FREQ
# [2] PARAMS   text : upper-case letters
#     RETURNS  float, higher = more English-like
def english_score(text):
    return sum(EN_FREQ.get(c, 0) for c in text) / max(1, len(text))


# ---------------------------------------------------------------------------
# brute_force: try every key of an additive / multiplicative / affine cipher
# [1] PREREQS  imports  : import math, string
#              functions: ALPHA, EN_FREQ, clean(), classical_cipher(), english_score()
# [2] PARAMS   ct     : ciphertext
#              cipher : "additive" (26 keys), "multiplicative" (12 keys), "affine" (312 keys)
#              top    : keep only the best `top` results (None = all)
#     RETURNS  [(key, plaintext), ...] most English-looking first
#     CHANGE   only keys near 13 -> filter: [r for r in brute_force(ct) if 10 <= r[0] <= 16]
#     EXAMPLE  k, pt = brute_force("NCJAEZRCLAS", "additive")[0]
#              for key, pt in brute_force(ct, "affine", top=3): print(key, pt)
def brute_force(ct, cipher="additive", top=None):
    m, cipher = len(ALPHA), cipher.lower()
    if cipher in ("additive", "caesar", "shift"):
        keys = range(m)
    elif cipher == "multiplicative":
        keys = [k for k in range(1, m) if math.gcd(k, m) == 1]
    elif cipher == "affine":
        keys = [(a, b) for a in range(1, m) if math.gcd(a, m) == 1 for b in range(m)]
    else:
        raise ValueError("brute_force supports additive, multiplicative and affine")
    res = sorted(((k, classical_cipher(ct, cipher, k, decrypt=True)) for k in keys),
                 key=lambda r: -english_score(r[1]))
    return res[:top] if top else res


# ---------------------------------------------------------------------------
# known_plaintext_attack: recover the key from a known (plaintext, ciphertext) pair
# [1] PREREQS  imports  : import math, string
#              functions: ALPHA, clean(), classical_cipher(), hill(), transposition()
#              pip      : sympy
# [2] PARAMS   pt, ct : the known plaintext and its ciphertext (e.g. "yes" -> "CIW")
#              cipher : "additive"       -> returns k (int)
#                       "multiplicative" -> returns [k, ...] every key that fits
#                       "affine"         -> returns [(a, b), ...] every key that fits
#                       "vigenere"       -> returns the key word (shortest repeating part)
#                       "permutation"    -> returns (block_size, key list) or None
#                       "hill"           -> returns K (list of rows) or None
#              size   : Hill matrix size n (needs >= n*n known letters)
#     CHANGE   chosen-plaintext attack = the same call (attacker picked pt himself)
#     EXAMPLE  k = known_plaintext_attack("yes", "CIW", "additive")           # 4
#              known_plaintext_attack("ab", "GL", "affine")                  # [(5, 6)]
#              known_plaintext_attack("abcdefghi", "CABDEHFGI", "permutation")
def known_plaintext_attack(pt, ct, cipher, size=2):
    p, c, m, cipher = clean(pt), clean(ct), len(ALPHA), cipher.lower()
    if cipher in ("additive", "caesar", "shift"):
        return (ALPHA.index(c[0]) - ALPHA.index(p[0])) % m          # k = C - P
    if cipher == "multiplicative":
        return [k for k in range(1, m) if math.gcd(k, m) == 1 and classical_cipher(p, cipher, k) == c]
    if cipher == "affine":
        return [(a, b) for a in range(1, m) if math.gcd(a, m) == 1 for b in range(m)
                if classical_cipher(p, cipher, (a, b)) == c]
    if cipher == "vigenere":
        stream = "".join(ALPHA[(ALPHA.index(y) - ALPHA.index(x)) % m] for x, y in zip(p, c))
        period = next(L for L in range(1, len(stream) + 1)
                      if all(stream[i] == stream[i % L] for i in range(len(stream))))
        return stream[:period]
    if cipher == "permutation":
        for b in range(1, len(p) + 1):                   # smallest block size that explains it
            if len(p) % b:
                continue
            key = [p[:b].find(ch) + 1 for ch in c[:b]]
            if 0 not in key and transposition(p, key) == c:
                return b, key
        return None
    if cipher == "hill":
        from itertools import combinations
        from sympy import Matrix
        n = size
        P = [[ALPHA.index(ch) for ch in p[i:i + n]] for i in range(0, len(p) - n + 1, n)]
        C = [[ALPHA.index(ch) for ch in c[i:i + n]] for i in range(0, len(c) - n + 1, n)]
        used = min(len(P), len(C)) * n
        for cols in combinations(range(min(len(P), len(C))), n):      # n blocks with invertible P
            Pm = Matrix([P[j] for j in cols]).T
            if math.gcd(int(Pm.det()) % m, m) != 1:
                continue
            K = (Matrix([C[j] for j in cols]).T * Pm.inv_mod(m)).applyfunc(lambda v: v % m)
            K = [[int(v) for v in row] for row in K.tolist()]        # K = C * P^-1 mod 26
            if hill(p[:used], K) == c[:used]:
                return K
        return None
    raise ValueError(f"unknown cipher {cipher!r}")


# =====================================================================
# 2. SYMMETRIC BLOCK CIPHERS  (Lab 2)
# =====================================================================

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


# ---------------------------------------------------------------------------
# sym_benchmark: average encryption and decryption time of one symmetric configuration
# [1] PREREQS  imports  : import base64, time
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), timed(), SYM, _NOTED, symmetric()
#              pip      : pycryptodome
# [2] PARAMS   algo, key, message, mode : same as symmetric()
#              repeat                   : runs averaged
#     RETURNS  (encrypt_seconds, decrypt_seconds)
#     EXAMPLE  t_enc, t_dec = sym_benchmark("AES", get_random_bytes(32), msg, "CBC", 1000)
def sym_benchmark(algo, key, message, mode="ECB", repeat=1000):
    (ct, iv), t_enc = timed(symmetric, algo, key, message, mode, repeat=repeat)
    _, t_dec = timed(symmetric, algo, key, ct, mode, True, iv, repeat=repeat)
    return t_enc, t_dec


# ---- AES from scratch with every step printed (Lab 2 Q5) ------------

_SBOX = []                                          # filled once by aes_sbox()


# ---------------------------------------------------------------------------
# _gmul: multiply two bytes in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (AES field)
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   a, b : ints 0-255
def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return r


# ---------------------------------------------------------------------------
# aes_sbox: build the AES S-box (inverse in GF(2^8) + affine transform), cached in _SBOX
# [1] PREREQS  imports  : (none)
#              functions: _SBOX, _gmul()
# [2] RETURNS  list of 256 ints;  aes_sbox()[0x53] == 0xED
def aes_sbox():
    if not _SBOX:
        for x in range(256):
            inv = next((y for y in range(1, 256) if _gmul(x, y) == 1), 0) if x else 0
            s = inv
            for i in range(1, 5):
                s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
            _SBOX.append(s ^ 0x63)
    return _SBOX


# ---------------------------------------------------------------------------
# aes_key_expansion: AES key schedule for 128 / 192 / 256-bit keys
# [1] PREREQS  imports  : (none)
#              functions: _SBOX, _gmul(), aes_sbox()
# [2] PARAMS   key : 16, 24 or 32 bytes
#     RETURNS  (list of 4-byte words, number_of_rounds = 10 / 12 / 14)
def aes_key_expansion(key):
    S, nk = aes_sbox(), len(key) // 4
    nr = nk + 6
    w, rcon = [list(key[4 * i:4 * i + 4]) for i in range(nk)], 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = [S[b] for b in t[1:] + t[:1]]            # RotWord + SubWord
            t[0] ^= rcon                                 # Rcon
            rcon = _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:                     # extra SubWord for AES-256
            t = [S[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return w, nr


# ---------------------------------------------------------------------------
# aes_encrypt_block_verbose: AES on ONE 16-byte block, printing key expansion and every round
#                            (SubBytes, ShiftRows, MixColumns, AddRoundKey)
# [1] PREREQS  imports  : (none)
#              functions: _SBOX, _gmul(), aes_sbox(), aes_key_expansion()
# [2] PARAMS   key   : 16 / 24 / 32 bytes (AES-128 / 192 / 256 -> 10 / 12 / 14 rounds)
#              block : exactly 16 bytes, e.g. pad(to_bytes(msg), 16) for a short message
#              show  : False = compute silently
#     RETURNS  16-byte ciphertext block (equals AES-ECB from the library)
#     EXAMPLE  ct = aes_encrypt_block_verbose(key_bytes("FEDCBA98...", 24), pad(b"Top Secret", 16))
def aes_encrypt_block_verbose(key, block, show=True):
    S = aes_sbox()
    w, nr = aes_key_expansion(key)
    rk = lambda r: sum(w[4 * r:4 * r + 4], [])
    say = print if show else (lambda *a: None)
    st = lambda s: " | ".join(" ".join(f"{s[4 * c + r]:02X}" for c in range(4)) for r in range(4))
    say(f"\n  KEY EXPANSION ({len(key) * 8}-bit key, {nr} rounds, {len(w)} words)")
    for r in range(nr + 1):
        say(f"    round key {r:2d}: {bytes(rk(r)).hex().upper()}")
    s = list(block)
    say(f"\n  Input state      : {st(s)}")
    s = [a ^ b for a, b in zip(s, rk(0))]
    say(f"  INITIAL ROUND AddRoundKey: {st(s)}")
    for r in range(1, nr + 1):
        s = [S[b] for b in s]
        say(f"  Round {r:2d} SubBytes   : {st(s)}")
        s = [s[4 * ((c + row) % 4) + row] for c in range(4) for row in range(4)]
        say(f"  Round {r:2d} ShiftRows  : {st(s)}")
        if r != nr:                                      # final round skips MixColumns
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
                        a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
                        a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
                        _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)]
            s = out
            say(f"  Round {r:2d} MixColumns : {st(s)}")
        s = [a ^ b for a, b in zip(s, rk(r))]
        say(f"  Round {r:2d} AddRoundKey: {st(s)}" + ("   <- FINAL ROUND" if r == nr else ""))
    return bytes(s)


# =====================================================================
# 3. ASYMMETRIC CIPHERS  (Lab 3, Lab 4)
# =====================================================================

# RFC 3526 group 14: standard 2048-bit safe prime, generator 2 (default Diffie-Hellman group).
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
    "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
    "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
    "1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
    "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
    "955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_G = 2


# ---------------------------------------------------------------------------
# text_to_blocks: split a message into integers that are each smaller than the modulus n
# [1] PREREQS  imports  : (none)
#              functions: to_bytes()
# [2] PARAMS   msg : str / bytes;   n : modulus (RSA n, ElGamal p)
#     RETURNS  list of ints (one character per block when n is tiny, e.g. n = 323)
def text_to_blocks(msg, n):
    size, data = max(1, (n.bit_length() - 1) // 8), to_bytes(msg)
    return [int.from_bytes(data[i:i + size], "big") for i in range(0, len(data), size)]


# ---------------------------------------------------------------------------
# blocks_to_text: inverse of text_to_blocks
# [1] PREREQS  imports  : (none)
#              functions: to_bytes()
# [2] PARAMS   blocks : iterable of ints
#     RETURNS  str
def blocks_to_text(blocks):
    return b"".join(to_bytes(b) for b in blocks).decode(errors="replace")


# ---------------------------------------------------------------------------
# _hkdf: shared secret bytes -> `length`-byte AES key (HKDF-SHA256), used by ECIES / ECDH
# [1] PREREQS  imports  : from cryptography.hazmat.primitives import hashes
#                         from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#              functions: (none - standalone)
#              pip      : cryptography
# [2] PARAMS   secret : bytes;   length : key size in bytes
def _hkdf(secret, length=32):
    return HKDF(hashes.SHA256(), length, None, b"islab").derive(secret)


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
# rsa_cipher: RSA encryption / decryption - OAEP (secure), textbook (m^e mod n) or hybrid
# [1] PREREQS  imports  : import base64
#                         from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), text_to_blocks(),
#                         blocks_to_text()
#              pip      : pycryptodome
# [2] PARAMS   data    : message to encrypt / ciphertext to decrypt (see mode)
#              key     : RsaKey from generate_keys("rsa") - public to encrypt, private to
#                        decrypt.  textbook mode also accepts a tuple (e, n) / (d, n).
#              decrypt : False = encrypt, True = decrypt
#              mode    : "oaep"     -> padded RSA, message up to ~190 bytes (2048-bit key)
#                        "textbook" -> c = m^e mod n.  int in -> int out; text in -> list of
#                                      ints (split into blocks < n), list in -> text out
#                        "hybrid"   -> any size (files): random AES-256 key wrapped with
#                                      RSA-OAEP, data encrypted with AES-GCM; bytes out
#     CHANGE   "Plaintext is too long" -> use mode="hybrid".
#              Given small n, e, d (n=323, e=5, d=173) -> key=(5, 323) / (173, 323), "textbook"
#     EXAMPLE  ct = rsa_cipher("Asymmetric Encryption", key.publickey())
#              rsa_cipher(ct, key, decrypt=True).decode()
#              cts = rsa_cipher("Hi", (5, 323), mode="textbook")
#              rsa_cipher(cts, (173, 323), decrypt=True, mode="textbook")
def rsa_cipher(data, key, decrypt=False, mode="oaep"):
    mode = mode.lower()
    if mode == "textbook":
        exp, n = ((key.d if decrypt else key.e), key.n) if hasattr(key, "n") else key
        if isinstance(data, int):
            return pow(data, exp, n)                                # c = m^e,  m = c^d (mod n)
        if decrypt:
            return blocks_to_text(pow(c, exp, n) for c in data)
        return [pow(m, exp, n) for m in text_to_blocks(data, n)]
    oaep = PKCS1_OAEP.new(key)
    if mode == "oaep":
        return oaep.decrypt(data) if decrypt else oaep.encrypt(to_bytes(data))
    if mode == "hybrid":
        if decrypt:
            kl = key.size_in_bytes()
            return symmetric("AES", oaep.decrypt(data[:kl]), data[kl:], "GCM", decrypt=True, packed=True)
        k = get_random_bytes(32)
        return oaep.encrypt(k) + symmetric("AES", k, data, "GCM", packed=True)
    raise ValueError(f"unknown mode {mode!r}: use oaep, textbook or hybrid")


# ---------------------------------------------------------------------------
# elgamal_cipher: ElGamal (integers mod p) encryption / decryption - numbers, text or hybrid
# [1] PREREQS  imports  : import base64, hashlib, secrets
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), text_to_blocks(),
#                         blocks_to_text()
#              pip      : pycryptodome
# [2] PARAMS   data    : encrypt: int m < p, or text (split into blocks < p)
#                        decrypt: (c1, c2) pair, list of pairs, or hybrid packet
#              p, g    : public group (from generate_keys("elgamal") or the question)
#              key     : y (public, y = g^x mod p) to encrypt;  x (private) to decrypt
#              decrypt : False = encrypt, True = decrypt
#              mode    : "block"  -> c1 = g^k, c2 = m * y^k (mod p), fresh random k
#                        "hybrid" -> any size: random number k encrypted with ElGamal,
#                                    AES-GCM key = SHA-256(k); returns ((c1, c2), blob)
#     RETURNS  encrypt: (c1, c2) for an int, [(c1, c2), ...] for text, packet for hybrid
#              decrypt: int, str or bytes (hybrid) to match
#     CHANGE   given p=7919, g=2, x=2999 -> y = pow(g, x, p); check y matches the question
#     EXAMPLE  p, g, y, x = generate_keys("elgamal", 512)
#              cts = elgamal_cipher("Confidential Data", p, g, y)
#              elgamal_cipher(cts, p, g, x, decrypt=True)
#              pkt = elgamal_cipher(file_bytes, p, g, y, mode="hybrid")
def elgamal_cipher(data, p, g, key, decrypt=False, mode="block"):
    if mode == "hybrid":
        if decrypt:
            c, blob = data
            k = elgamal_cipher(c, p, g, key, decrypt=True)
            return symmetric("AES", hashlib.sha256(to_bytes(k)).digest(), blob, "GCM",
                             decrypt=True, packed=True)
        k = secrets.randbelow(p - 2) + 1
        return (elgamal_cipher(k, p, g, key),
                symmetric("AES", hashlib.sha256(to_bytes(k)).digest(), data, "GCM", packed=True))
    if decrypt:
        if isinstance(data[0], int):                                # one (c1, c2) pair
            c1, c2 = data
            return (c2 * pow(pow(c1, key, p), -1, p)) % p           # m = c2 * (c1^x)^-1
        return blocks_to_text(elgamal_cipher(c, p, g, key, decrypt=True) for c in data)
    if isinstance(data, int):
        k = secrets.randbelow(p - 3) + 2
        return pow(g, k, p), (data * pow(key, k, p)) % p
    return [elgamal_cipher(m, p, g, key) for m in text_to_blocks(data, p)]


# ---------------------------------------------------------------------------
# ecc_cipher: ECC encryption = ECIES (EC-ElGamal style hybrid), any message size
# [1] PREREQS  imports  : import base64
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#                         from cryptography.hazmat.primitives import hashes, serialization
#                         from cryptography.hazmat.primitives.asymmetric import ec
#                         from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), _hkdf()
#              pip      : cryptography pycryptodome
# [2] PARAMS   data    : bytes / str to encrypt, or the ciphertext to decrypt
#              key     : public key (priv.public_key()) to encrypt, private key to decrypt
#              decrypt : False = encrypt, True = decrypt
#     HOW      sender: random r, C1 = r*G, shared S = r*Q, C2 = AES-GCM(HKDF(S), M)
#              receiver: S = d*C1 -> same AES key -> M
#     RETURNS  encrypt: C1 point || nonce || C2 || tag (bytes);  decrypt: plaintext bytes
#     CHANGE   other curve -> generate_keys("ecc", curve="secp384r1")
#     EXAMPLE  priv = generate_keys("ecc");  ct = ecc_cipher("Secure Transactions", priv.public_key())
#              ecc_cipher(ct, priv, decrypt=True).decode()
def ecc_cipher(data, key, decrypt=False):
    if decrypt:
        n = 2 * ((key.curve.key_size + 7) // 8) + 1                 # bytes of the C1 point
        c1 = ec.EllipticCurvePublicKey.from_encoded_point(key.curve, data[:n])
        return symmetric("AES", _hkdf(key.exchange(ec.ECDH(), c1)), data[n:], "GCM",
                         decrypt=True, packed=True)
    eph = ec.generate_private_key(key.curve)                        # ephemeral r
    c1 = eph.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint)
    return c1 + symmetric("AES", _hkdf(eph.exchange(ec.ECDH(), key)), data, "GCM", packed=True)


# ---------------------------------------------------------------------------
# rabin_roots: the four square roots of c mod n = p*q (CRT) - one of them is the message
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   c : ciphertext int;   p, q : private primes (both = 3 mod 4)
#     RETURNS  [r1, n - r1, r2, n - r2]
def rabin_roots(c, p, q):
    n = p * q
    mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
    yp, yq = pow(p, -1, q), pow(q, -1, p)                           # yp*p + yq*q = 1 (mod n)
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = (yp * p * mq - yq * q * mp) % n
    return [r1, n - r1, r2, n - r2]


# ---------------------------------------------------------------------------
# rabin_cipher: Rabin encryption (c = m^2 mod n) / decryption - raw, tagged or hybrid
# [1] PREREQS  imports  : import base64, hashlib
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), rabin_roots()
#              pip      : pycryptodome
# [2] PARAMS   data    : message / ciphertext (see mode)
#              key     : n (public) to encrypt;  (p, q) (private) to decrypt
#              decrypt : False = encrypt, True = decrypt
#              mode    : "tagged" -> bytes/str in; a 4-byte SHA-256 tag is added so the right
#                                    root of the four can be recognised; bytes out
#                        "raw"    -> int m in, c out; decrypt returns all 4 roots
#                        "hybrid" -> any size: random AES key Rabin-encrypted, data AES-GCM;
#                                    returns (c, blob)
#     CHANGE   "message too long" -> mode="hybrid" or a bigger key
#     EXAMPLE  n, p, q = generate_keys("rabin", 1024)
#              c = rabin_cipher("hello", n);   rabin_cipher(c, (p, q), decrypt=True)
#              rabin_cipher(rabin_cipher(42, n, mode="raw"), (p, q), True, "raw")   # 4 roots
def rabin_cipher(data, key, decrypt=False, mode="tagged"):
    if mode == "hybrid":
        if decrypt:
            c, blob = data
            return symmetric("AES", rabin_cipher(c, key, decrypt=True), blob, "GCM",
                             decrypt=True, packed=True)
        k = get_random_bytes(32)
        return rabin_cipher(k, key), symmetric("AES", k, data, "GCM", packed=True)
    if mode == "raw":
        return rabin_roots(data, *key) if decrypt else pow(data, 2, key)
    if decrypt:
        for r in rabin_roots(data, *key):
            b = to_bytes(r)
            if b[:1] == b"\x01" and hashlib.sha256(b[1:-4]).digest()[:4] == b[-4:]:
                return b[1:-4]
        raise ValueError("no root carried a valid tag (wrong key or corrupted ciphertext)")
    data = to_bytes(data)
    m = int.from_bytes(b"\x01" + data + hashlib.sha256(data).digest()[:4], "big")   # 0x01 keeps leading zeros
    if m >= key:
        raise ValueError("message too long for this Rabin key - use mode='hybrid'")
    return pow(m, 2, key)


# ---------------------------------------------------------------------------
# dh_shared: Diffie-Hellman / ECDH shared secret (same value on both sides)
# [1] PREREQS  imports  : import hashlib
#                         from cryptography.hazmat.primitives import hashes
#                         from cryptography.hazmat.primitives.asymmetric import ec
#                         from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#              functions: to_bytes(), DH_P, _hkdf()
#              pip      : cryptography
# [2] PARAMS   my_priv   : my private value a (int)  - or my EC private key for ECDH
#              their_pub : the other side's public value B (int) - or their EC public key
#              p         : the DH prime (only for integer DH)
#              as_key    : False -> raw secret (int g^ab mod p, or bytes for ECDH)
#                          True  -> 32-byte AES key (SHA-256 / HKDF of the secret)
#     CHANGE   own group from the question -> generate_keys("dh", p=23, g=5) and pass p=23 here
#     EXAMPLE  A, a = generate_keys("dh");  B, b = generate_keys("dh")
#              dh_shared(a, B) == dh_shared(b, A)                     # True
#              k = dh_shared(a, B, as_key=True)                       # AES-256 session key
#              k = dh_shared(ec_priv, peer_ec_priv.public_key(), as_key=True)    # ECDH
def dh_shared(my_priv, their_pub, p=DH_P, as_key=False):
    if isinstance(my_priv, ec.EllipticCurvePrivateKey):
        secret = my_priv.exchange(ec.ECDH(), their_pub)
        return _hkdf(secret) if as_key else secret
    secret = pow(their_pub, my_priv, p)                             # K = B^a mod p
    return hashlib.sha256(to_bytes(secret)).digest() if as_key else secret


# =====================================================================
# 4. KEY MANAGEMENT, ACCESS CONTROL, ATTACKS  (Lab 4)
# =====================================================================

# ---------------------------------------------------------------------------
# key_entropy: Shannon entropy H = -sum p(i) log2 p(i) of a key's bytes (max 8 bits/byte)
# [1] PREREQS  imports  : import math
#                         from collections import Counter
#              functions: to_bytes()
# [2] PARAMS   key : bytes / str
#     RETURNS  bits of entropy per byte
#     EXAMPLE  key_entropy(get_random_bytes(32))     key_entropy("aaaaaaaa")  -> 0.0
def key_entropy(key):
    data = to_bytes(key)
    return sum(-c / len(data) * math.log2(c / len(data)) for c in Counter(data).values())


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
# KeyManager: centralised key-management service (generation, distribution, revocation,
#             renewal, secure storage, auditing) for any public-key scheme
# [1] PREREQS  imports  : import base64, hmac, json, math, random, secrets, time
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Hash import SHA256
#                         from Crypto.Protocol.KDF import PBKDF2
#                         from Crypto.PublicKey import RSA
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.number import getPrime, isPrime
#                         from Crypto.Util.Padding import pad, unpad
#                         from cryptography.hazmat.primitives import serialization
#                         from cryptography.hazmat.primitives.asymmetric import ec
#              functions: to_bytes(), fmt(), print_table(), SYM, _NOTED, symmetric(), DH_P, DH_G,
#                         generate_keys(), derive_key(), MERSENNE_1279, _MERSENNE_EXPONENTS,
#                         field_prime(), shamir()
#              pip      : cryptography pycryptodome
# [2] PARAMS   scheme          : "rsa" | "rabin" | "elgamal" | "ecc" | "paillier" ... (any
#                                generate_keys name) or your own function bits -> (pub, priv)
#              bits            : key size;   lifetime_days : expiry (renewal period)
#              master_password : protects the stored private keys (AES-GCM, PBKDF2 key)
#              log_file        : also append the audit log to this file (None = memory only)
#     METHODS  token = km.register("Hospital-A")     generate keys, returns the secret token
#              km.get_public("Hospital-A")           public distribution
#              km.get_private("Hospital-A", token)   secure distribution (token required)
#              km.revoke("Hospital-A", "reason")     revocation
#              km.renew("Hospital-A")                new key pair (rotation)
#              km.renew_expired(now=...)             renew every expired active key
#              km.is_active(entity, now=...)         not revoked and not expired?
#              km.log(action, entity, detail)        add your own audit entry
#              km.print_status() / km.print_audit()  key table / audit log
#     RETURNS  keys come back as generate_keys(..., as_json=True) gives them: RSA/ECC -> PEM
#              strings (RSA.import_key(pem)), ElGamal/Rabin -> dicts, e.g. pub["n"], priv["p"]
#     CHANGE   simulate time passing -> now=time.time() + days * 86400
#     EXAMPLE  km = KeyManager("rabin", bits=1024, lifetime_days=365)
#              tok = km.register("Clinic"); priv = km.get_private("Clinic", tok)
class KeyManager:
    def __init__(self, scheme="rsa", bits=1024, lifetime_days=365, master_password="change-me",
                 log_file=None):
        self.keygen = scheme if callable(scheme) else (lambda b: generate_keys(scheme, b, as_json=True))
        self.bits, self.lifetime = bits, lifetime_days * 86400
        self._master, self._salt = derive_key(master_password)
        self.keys, self._tokens, self.audit, self.log_file = {}, {}, [], log_file

    # timestamped audit entry (screen log + optional file)
    def log(self, action, entity, detail=""):
        entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {action:<10} | {entity:<14} | {detail}"
        self.audit.append(entry)
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(entry + "\n")

    # generate a key pair; the private key is stored AES-GCM sealed under the master key
    def _new_keys(self, entity, now=None):
        pub, priv = self.keygen(self.bits)
        now = now or time.time()
        self.keys[entity] = {"public": pub,
                             "sealed": symmetric("AES", self._master, json.dumps(priv), "GCM", packed=True),
                             "created": now, "expires": now + self.lifetime, "status": "active"}

    # new entity -> key pair + secret API token (returned)
    def register(self, entity):
        self._new_keys(entity)
        self._tokens[entity] = secrets.token_hex(16)
        self.log("GENERATE", entity, f"{self.bits}-bit keys")
        return self._tokens[entity]

    # True if the key exists, is not revoked and has not expired (now = simulated time)
    def is_active(self, entity, now=None):
        k = self.keys.get(entity)
        return bool(k) and k["status"] == "active" and (now or time.time()) < k["expires"]

    # public key of an entity (PermissionError if revoked / expired)
    def get_public(self, entity):
        self.log("DIST-PUB", entity)
        if not self.is_active(entity):
            raise PermissionError(f"{entity}: key revoked or expired")
        return self.keys[entity]["public"]

    # private key, only for the owner holding the right token
    def get_private(self, entity, token):
        if not hmac.compare_digest(self._tokens.get(entity, ""), token):
            self.log("DENIED", entity, "bad token")
            raise PermissionError("invalid token")
        if not self.is_active(entity):
            self.log("DENIED", entity, "revoked/expired")
            raise PermissionError(f"{entity}: key revoked or expired")
        self.log("DIST-PRIV", entity)
        return json.loads(symmetric("AES", self._master, self.keys[entity]["sealed"], "GCM",
                                    decrypt=True, packed=True))

    # mark a key as revoked (reason goes to the audit log)
    def revoke(self, entity, reason=""):
        self.keys[entity]["status"] = "revoked"
        self.log("REVOKE", entity, reason)

    # new key pair for the entity (same token), old one discarded
    def renew(self, entity, now=None):
        self._new_keys(entity, now)
        self.log("RENEW", entity, "new key pair issued")

    # renew every ACTIVE key past its lifetime (revoked ones stay revoked); call periodically
    def renew_expired(self, now=None):
        now = now or time.time()
        for e in [e for e, k in self.keys.items() if now >= k["expires"] and k["status"] == "active"]:
            self.renew(e, now)

    # table: entity | status | created | expires
    def print_status(self):
        rows = [[e, k["status"], time.strftime("%Y-%m-%d", time.localtime(k["created"])),
                 time.strftime("%Y-%m-%d", time.localtime(k["expires"]))] for e, k in self.keys.items()]
        print_table(["Entity", "Status", "Created", "Expires"], rows)

    # print the whole audit log
    def print_audit(self):
        print("\n".join(self.audit))


# ---------------------------------------------------------------------------
# AccessControl: time-limited, owner-managed access grants (DRM / licences)
# [1] PREREQS  imports  : import time
#              functions: (none - standalone)
# [2] PARAMS   log : optional function(action, entity, detail), e.g. km.log to share an audit log
#     METHODS  ac.set_owner("movie1", "creatorA")                 who manages the content
#              ac.grant("creatorA", "alice", "movie1", seconds=3600)   by, user, content, time
#              ac.revoke("creatorA", "alice", "movie1")
#              ac.can_access("alice", "movie1", now=None)        True / False
#     RULES    'admin' manages everything; an owner only their own content (else PermissionError)
#     EXAMPLE  ac = AccessControl(log=km.log)
class AccessControl:
    def __init__(self, log=None):
        self.owners, self.grants, self.log = {}, {}, log or (lambda *a: None)

    # record the owner (creator) of a piece of content
    def set_owner(self, content, owner):
        self.owners[content] = owner

    def _check_manager(self, by, content):
        if by != "admin" and self.owners.get(content) != by:
            self.log("AC-DENIED", by, f"not owner of {content}")
            raise PermissionError(f"{by} cannot manage {content}")

    # `by` gives `user` access to `content` for `seconds`
    def grant(self, by, user, content, seconds):
        self._check_manager(by, content)
        self.grants[(user, content)] = time.time() + seconds
        self.log("GRANT", user, f"{content} for {seconds}s by {by}")

    # `by` removes `user`'s access to `content`
    def revoke(self, by, user, content):
        self._check_manager(by, content)
        self.grants.pop((user, content), None)
        self.log("AC-REVOKE", user, f"{content} by {by}")

    # is the grant still valid at time `now` (default: now)?
    def can_access(self, user, content, now=None):
        return (now or time.time()) < self.grants.get((user, content), 0)


# ---------------------------------------------------------------------------
# rsa_weak_attack: factor a weak RSA modulus (small or close primes) and rebuild the private key
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
#              pip      : sympy
# [2] PARAMS   n, e : the public key
#     HOW      Fermat first (n = a^2 - b^2, instant when |p - q| is small), then sympy factorint
#              (Pollard rho etc., works when the primes are small)
#     RETURNS  (p, q, d)  -> decrypt with rsa_cipher(c, (d, n), True, "textbook")
#     EXAMPLE  p, q, d = rsa_weak_attack(n, 65537)
def rsa_weak_attack(n, e):
    from sympy import factorint
    from math import isqrt
    a = isqrt(n) + (isqrt(n) ** 2 != n)
    for _ in range(100_000):                             # Fermat: n = a^2 - b^2
        b2 = a * a - n
        if isqrt(b2) ** 2 == b2:
            p, q = a - isqrt(b2), a + isqrt(b2)
            break
        a += 1
    else:
        p, q = list(factorint(n))[:2]
    return p, q, pow(e, -1, (p - 1) * (q - 1))


# =====================================================================
# 5. HASHING + SOCKETS  (Lab 5)
# =====================================================================

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


# ---------------------------------------------------------------------------
# random_strings: `count` random letter/digit strings (datasets for hash experiments)
# [1] PREREQS  imports  : import random, string
#              functions: (none - standalone)
# [2] PARAMS   count : how many;  min_len / max_len : length range;  seed : int = repeatable
#     EXAMPLE  data = random_strings(100, seed=1)
def random_strings(count, min_len=8, max_len=32, seed=None):
    rnd = random.Random(seed)
    chars = string.ascii_letters + string.digits
    return ["".join(rnd.choices(chars, k=rnd.randint(min_len, max_len))) for _ in range(count)]


# ---------------------------------------------------------------------------
# find_collisions: group different inputs that have the same hash
# [1] PREREQS  imports  : from collections import defaultdict
#              functions: (none - standalone)
# [2] PARAMS   items   : list of inputs
#              hash_fn : function input -> hash, e.g. lambda s: hash_hex(s, "md5")
#     RETURNS  {hash: [inputs...]} only for hashes shared by more than one input ({} = none)
#     CHANGE   force collisions to test the detector -> lambda s: hash_hex(s)[:2]
#     EXAMPLE  find_collisions(random_strings(100), lambda s: hash_hex(s, "sha1"))
def find_collisions(items, hash_fn):
    groups = defaultdict(set)
    for it in items:
        groups[hash_fn(it)].add(it)
    return {h: sorted(v) for h, v in groups.items() if len(v) > 1}


# ---- sockets: length-prefixed messages that keep their type ----------

# ---------------------------------------------------------------------------
# sock_send: send bytes, a str, or any JSON-able object (dict / list / int) over a socket
# [1] PREREQS  imports  : import json
#              functions: (none - standalone)
# [2] PARAMS   sock : connected socket (from connect() or the server handler's conn)
#              obj  : bytes / str / dict / list / int ...  - sock_recv returns the same type
#     WIRE     4-byte length | 1-byte type (B bytes, S str, J json) | payload
#     EXAMPLE  sock_send(s, "hello");  sock_send(s, {"sig": sig.hex(), "n": n})
def sock_send(sock, obj):
    if isinstance(obj, bytes):
        kind, data = b"B", obj
    elif isinstance(obj, str):
        kind, data = b"S", obj.encode()
    else:
        kind, data = b"J", json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, "big") + kind + data)


# ---------------------------------------------------------------------------
# sock_recv: receive one message sent by sock_send (waits until it has fully arrived)
# [1] PREREQS  imports  : import json
#              functions: (none - standalone)
# [2] PARAMS   sock : connected socket
#     RETURNS  bytes, str or the JSON object - whatever was sent
#     EXAMPLE  data = sock_recv(conn)
def sock_recv(sock):
    def exact(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed")
            buf += chunk
        return buf
    size = int.from_bytes(exact(4), "big")
    kind, data = exact(1), exact(size)
    return data if kind == b"B" else data.decode() if kind == b"S" else json.loads(data)


# ---------------------------------------------------------------------------
# run_server: TCP server - calls handler(conn, addr) for every client that connects
# [1] PREREQS  imports  : import socket, threading, time
#              functions: (none - standalone)
# [2] PARAMS   handler     : your function(conn, addr) that talks to ONE client with
#                            sock_recv(conn) / sock_send(conn, ...)
#              port, host  : where to listen (127.0.0.1 = this PC only, "0.0.0.0" = network)
#              max_clients : stop after this many clients (None = forever, Ctrl+C to stop)
#              background  : True -> run in a thread and return at once (client + server in
#                            ONE file / demo)
#     CHANGE   "Address already in use" -> change port (or wait a few seconds)
#     EXAMPLE  def handle(conn, addr): sock_send(conn, hash_hex(sock_recv(conn)))
#              run_server(handle, 5000)
def run_server(handler, port=5000, host="127.0.0.1", max_clients=None, background=False):
    if background:
        t = threading.Thread(target=run_server, args=(handler, port, host, max_clients), daemon=True)
        t.start()
        time.sleep(0.3)                                  # give it time to start listening
        return t
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen()
        print(f"[server] listening on {host}:{port}")
        served = 0
        while max_clients is None or served < max_clients:
            conn, addr = srv.accept()
            with conn:
                print(f"[server] client {addr}")
                handler(conn, addr)
            served += 1


# ---------------------------------------------------------------------------
# connect: open a client connection to a server
# [1] PREREQS  imports  : import socket
#              functions: (none - standalone)
# [2] PARAMS   port, host : the server's address (server's IP for two PCs)
#     RETURNS  socket - use as  with connect(5000) as s: ...
#     EXAMPLE  with connect(5000) as s: sock_send(s, "hi"); print(sock_recv(s))
def connect(port=5000, host="127.0.0.1"):
    s = socket.socket()
    s.connect((host, port))
    return s


# =====================================================================
# 6. DIGITAL SIGNATURES  (Lab 6)
# =====================================================================

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
# timestamp: trusted timestamp - CREATE one (authority RSA-signs "SHA-256(data)|time") or
#            VERIFY one (optionally that the time lies in [start, end], e.g. a voting period)
# [1] PREREQS  imports  : import hashlib, hmac, math, secrets
#                         from datetime import datetime
#                         from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512
#                         from Crypto.Signature import pkcs1_15
#                         from cryptography.exceptions import InvalidSignature
#                         from cryptography.hazmat.primitives import hashes
#                         from cryptography.hazmat.primitives.asymmetric import ec
#              functions: to_bytes(), djb2_hash(), hash_hex(), _HASH, signature()
#              pip      : cryptography pycryptodome
# [2] PARAMS   tsa_key    : timestamp authority's RSA private key (create) / public key (verify)
#              data       : the data being timestamped (str / bytes)
#              token      : None -> create;  {"time": ..., "sig": ...} -> verify it
#              start, end : datetime limits checked when verifying (None = no limit)
#              when       : datetime to stamp (create; default now)
#     RETURNS  create: {"time": ISO string, "sig": hex};   verify: True / False
#     EXAMPLE  tok = timestamp(tsa, digest)
#              timestamp(tsa.publickey(), digest, tok, start=open_time, end=close_time)
def timestamp(tsa_key, data, token=None, start=None, end=None, when=None):
    if token is None:
        t = (when or datetime.now()).isoformat(timespec="seconds")
        return {"time": t, "sig": signature("rsa", f"{hash_hex(data)}|{t}", tsa_key).hex()}
    try:
        ok = signature("rsa", f"{hash_hex(data)}|{token['time']}", tsa_key, sig=bytes.fromhex(token["sig"]))
        t = datetime.fromisoformat(token["time"])
    except (KeyError, ValueError, TypeError):
        return False
    return ok and (start is None or t >= start) and (end is None or t <= end)


# =====================================================================
# 7. PARTIAL HOMOMORPHIC ENCRYPTION + SECRET SHARING  (Lab 7)
# =====================================================================

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
# tally: vote counting with ONE Paillier ciphertext per ballot - encode a choice / decode a sum
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] PARAMS   value     : encode: choice index k (0-based)  -> returns base^k
#                          decode: the decrypted homomorphic sum
#              decode    : False = encode, True = decode
#              n_choices : number of candidates (decode)
#              base      : must be > the number of voters (each count is one base-`base` digit)
#     RETURNS  encode: int to encrypt;  decode: [votes for 0, votes for 1, ...]
#     EXAMPLE  c = paillier_cipher(tally(2), pub)                       # vote for candidate 3
#              tally(paillier_cipher(total, priv, True), decode=True, n_choices=4)
def tally(value, decode=False, n_choices=None, base=1000):
    if decode:
        return [(value // base ** k) % base for k in range(n_choices)]
    return base ** value


# =====================================================================
# 8. SEARCHABLE ENCRYPTION, GnuPG, SNORT  (Lab 8)
# =====================================================================

# ---------------------------------------------------------------------------
# sample_documents: ten small documents for searchable-encryption exercises
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
# [2] RETURNS  {doc_id: text}
#     CHANGE   use your own dataset: any dict {"doc1": "text", ...}
def sample_documents():
    return {
        "doc1": "the patient record shows high blood pressure and diabetes",
        "doc2": "encryption keeps the patient data confidential in the cloud",
        "doc3": "the bank transfer was flagged by the fraud detection system",
        "doc4": "cloud storage providers must protect customer data",
        "doc5": "aes encryption is fast and secure for bulk data",
        "doc6": "rsa and elgamal are public key encryption schemes",
        "doc7": "the hospital shares blood test results with the doctor",
        "doc8": "fraud analysts search encrypted bank records daily",
        "doc9": "searchable encryption lets the cloud search without decryption",
        "doc10": "the doctor updated the patient prescription today",
    }


# ---------------------------------------------------------------------------
# build_inverted_index: word -> sorted list of the documents containing it
# [1] PREREQS  imports  : import re
#                         from collections import defaultdict
#              functions: (none - standalone)
# [2] PARAMS   docs : {doc_id: text}
#     RETURNS  {word: [doc_id, ...]}  (lower-case words, letters/digits only)
def build_inverted_index(docs):
    idx = defaultdict(set)
    for doc_id, text in docs.items():
        for w in re.findall(r"[a-z0-9]+", text.lower()):
            idx[w].add(doc_id)
    return {w: sorted(ids) for w, ids in idx.items()}


# ---------------------------------------------------------------------------
# SSE: Symmetric Searchable Encryption with AES
# [1] PREREQS  imports  : import base64, hashlib, re
#                         from collections import defaultdict
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), build_inverted_index()
#              pip      : pycryptodome
# [2] PARAMS   key : 16/24/32-byte AES key (None = random)
#     HOW      index key   = AES-ECB(K, SHA256(word))  deterministic -> equal words match
#              index value = [AES-CBC(K, doc_id)]      randomised
#              documents   = AES-CBC(K, text)
#     METHODS  sse.build(docs)     -> encrypted index (also sets sse.enc_docs)
#              sse.token(word)     -> encrypted query token (what the server sees)
#              sse.search("words") -> {doc_id: decrypted text} containing EVERY query word
#     EXAMPLE  sse = SSE(); sse.build(sample_documents()); sse.search("patient data")
class SSE:
    def __init__(self, key=None):
        self.key = key or get_random_bytes(16)

    # "encrypt the query": deterministic token of one word
    def token(self, word):
        return symmetric("AES", self.key, hashlib.sha256(word.lower().encode()).digest(), "ECB")[0]

    # encrypt documents + build the encrypted inverted index
    def build(self, docs):
        self.enc_docs = {d: symmetric("AES", self.key, t, "CBC", packed=True) for d, t in docs.items()}
        self.index = {self.token(w): [symmetric("AES", self.key, d, "CBC", packed=True) for d in ids]
                      for w, ids in build_inverted_index(docs).items()}
        return self.index

    # documents containing every word of the query, decrypted
    def search(self, query):
        result = None
        for w in query.lower().split():
            ids = {symmetric("AES", self.key, c, "CBC", decrypt=True, packed=True).decode()
                   for c in self.index.get(self.token(w), [])}
            result = ids if result is None else result & ids
        return {d: symmetric("AES", self.key, self.enc_docs[d], "CBC", decrypt=True, packed=True).decode()
                for d in sorted(result or [])}


# ---------------------------------------------------------------------------
# PKSE: Public-Key Searchable Encryption with Paillier
# [1] PREREQS  imports  : import hashlib, math, random, re, secrets
#                         from collections import defaultdict
#                         from Crypto.PublicKey import RSA
#                         from Crypto.Util.number import getPrime, isPrime
#                         from cryptography.hazmat.primitives import serialization
#                         from cryptography.hazmat.primitives.asymmetric import ec
#              functions: to_bytes(), DH_P, DH_G, generate_keys(), paillier_cipher(), MERSENNE_1279,
#                         _MERSENNE_EXPONENTS, field_prime(), shamir(), build_inverted_index()
#              pip      : cryptography pycryptodome
# [2] PARAMS   bits : Paillier key size (512 = fast practice, 1024+ = realistic)
#     HOW      index = [(E(h(word)), [E(doc_id), ...])]  - anyone with the public key can add
#              match: (E(h(w)) * E(h(q))^-1)^r = E(r (h(w) - h(q))) decrypts to 0 only if w == q
#     METHODS  pk.build(docs)          -> encrypted index;   pk.pub / pk.priv = Paillier keys
#              pk.encrypt_query(word)  -> E(h(word)) made with the public key
#              pk.search(word)         -> sorted list of matching doc ids
#     EXAMPLE  pk = PKSE(1024); pk.build(sample_documents()); pk.search("fraud")
class PKSE:
    def __init__(self, bits=1024):
        self.pub, self.priv = generate_keys("paillier", bits)

    # keyword -> 128-bit integer
    @staticmethod
    def h(word):
        return int.from_bytes(hashlib.sha256(word.lower().encode()).digest()[:16], "big")

    # E(h(word)) with the public key
    def encrypt_query(self, word):
        return paillier_cipher(self.h(word), self.pub)

    # encrypted index of every word -> encrypted doc ids
    def build(self, docs):
        self.index = [(paillier_cipher(self.h(w), self.pub),
                       [paillier_cipher(int.from_bytes(d.encode(), "big"), self.pub) for d in ids])
                      for w, ids in build_inverted_index(docs).items()]
        return self.index

    # doc ids containing the word (blinded equality test, then decrypt the ids)
    def search(self, query):
        n2, eq = self.pub[0] ** 2, self.encrypt_query(query)
        inv_q = pow(eq, -1, n2)
        for enc_word, enc_ids in self.index:
            diff = pow(enc_word * inv_q % n2, secrets.randbelow(self.pub[0] - 1) + 1, n2)
            if paillier_cipher(diff, self.priv, decrypt=True) == 0:
                return sorted(to_bytes(paillier_cipher(c, self.priv, decrypt=True)).decode() for c in enc_ids)
        return []


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
# gpg_available: True if the gpg program and the python-gnupg package are both installed
# [1] PREREQS  imports  : (none)
#              functions: (none - standalone)
#              pip      : python-gnupg
# [2] EXAMPLE  if not gpg_available(): print("install gnupg + python-gnupg")
def gpg_available():
    try:
        import gnupg
        gnupg.GPG()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# analyze_snort_alerts: parse a Snort 'alert_fast' log and print counts by rule / IP / protocol
# [1] PREREQS  imports  : import re
#                         from collections import Counter
#              functions: (none - standalone)
# [2] PARAMS   path : alert file, e.g. "/var/log/snort/alert" or "./logs/alert"
#     RETURNS  list of dicts {sid, msg, proto, src, dst, src_ip}
#     EXAMPLE  alerts = analyze_snort_alerts("sample_alert.log")
def analyze_snort_alerts(path):
    pat = re.compile(r"\[\*\*\] \[(?P<sid>[\d:]+)\] (?P<msg>.*?) \[\*\*\].*?"
                     r"\{(?P<proto>\w+)\} (?P<src>[\d.:]+) -> (?P<dst>[\d.:]+)")
    with open(path) as f:
        alerts = [m.groupdict() for m in map(pat.search, f) if m]
    print(f"  {len(alerts)} alerts")
    for a in alerts:
        a["src_ip"] = a["src"].split(":")[0]
    for title, key in (("By rule", "msg"), ("By source IP", "src_ip"), ("By protocol", "proto")):
        print(f"\n  {title}:")
        for k, v in Counter(a[key] for a in alerts).most_common():
            print(f"    {v:4d}  {k}")
    return alerts


# =====================================================================
# 9. EXAM PROGRAM HELPERS  (menu-driven, role-based, persistent storage)
#    Typical skeleton:
#        K = json_store("keys.json", create=make_keys)     # keys survive restarts
#        db = json_store("db.json", default={"records": []}) ... json_store("db.json", db)
#        user, role = login(users)
#        menu("Researcher", {"Submit": submit, "View all": view})
# =====================================================================

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


# ---------------------------------------------------------------------------
# password_seal: SEAL any JSON-able value (private key, key share) under a password, or UNSEAL it
# [1] PREREQS  imports  : import base64, json
#                         from Crypto.Cipher import AES, DES, DES3
#                         from Crypto.Hash import SHA256
#                         from Crypto.Protocol.KDF import PBKDF2
#                         from Crypto.Random import get_random_bytes
#                         from Crypto.Util.Padding import pad, unpad
#              functions: to_bytes(), fmt(), SYM, _NOTED, symmetric(), derive_key()
#              pip      : pycryptodome
# [2] PARAMS   password : the owner's password
#              data     : seal: the value (int, str, list, dict);  unseal: the hex string
#              unseal   : False = seal, True = unseal
#     HOW      salt || AES-256-GCM(PBKDF2(password, salt), json)   - stored as hex
#     RETURNS  seal: hex string;  unseal: the original value (ValueError on wrong password or
#              tampering)
#     EXAMPLE  blob = password_seal("pw123", x);   x = password_seal("pw123", blob, unseal=True)
def password_seal(password, data, unseal=False):
    if not unseal:
        key, salt = derive_key(password, iterations=50_000)
        return (salt + symmetric("AES", key, json.dumps(data), "GCM", packed=True)).hex()
    blob = bytes.fromhex(data)
    key, _ = derive_key(password, blob[:16], 50_000)
    try:
        return json.loads(symmetric("AES", key, blob[16:], "GCM", decrypt=True, packed=True))
    except ValueError:
        raise ValueError("wrong password or tampered data") from None


# =====================================================================
# Function index:  python3 islib.py [search-word | exact function name]
# =====================================================================

if __name__ == "__main__":
    import inspect
    word = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    me = sys.modules[__name__]
    public = [(n, o) for n, o in vars(me).items() if (inspect.isfunction(o) or inspect.isclass(o))
              and o.__module__ == __name__ and not n.startswith("_")]
    exact = [(n, o) for n, o in public if n.lower() == word]
    if exact:                                            # full instructions for one function
        n, o = exact[0]
        print(inspect.getcomments(o), end="")
        print(f"def {n}{inspect.signature(o)}")
    for n, o in ([] if exact else public):
        if word in n.lower():
            lines = [ln.lstrip("#").strip() for ln in (inspect.getcomments(o) or "").splitlines()]
            title = next((ln for ln in lines if ln and set(ln) != {"-"}), "")
            print(f"{n + str(inspect.signature(o)):<62} {title.split(':', 1)[-1].strip()}")
