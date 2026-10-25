# IS Lab – master library + solutions: how to use and modify

## 0. Before the internet goes off (Linux lab PC)
```bash
pip3 install --user pycryptodome cryptography sympy numpy matplotlib python-gnupg
python3 islib.py                 # must print the list of functions with no error
```
If pip says **"externally-managed-environment"** (Ubuntu 23.04+ / Debian 12), use either
```bash
pip3 install --user --break-system-packages pycryptodome cryptography sympy numpy matplotlib python-gnupg
```
or a virtual environment (then run everything with that python):
```bash
python3 -m venv ~/islab && source ~/islab/bin/activate && pip install pycryptodome cryptography sympy numpy matplotlib python-gnupg
```
No pip at all? `sudo apt install python3-pip` (or `python3 -m ensurepip --user`).

Only for Lab 8 additional (needs sudo; `gpg` is usually already installed on Linux):
```bash
sudo apt install gnupg snort     # Fedora/RHEL: sudo dnf install gnupg2 snort
gpg --version && snort -V
```
Copy the **whole folder**. Every solution file finds `islib.py` two folders up, so keep
the layout `<folder>/islib.py` and `<folder>/LabN/Exercises/*.py`.

## 1. Running a solution
```bash
cd "Lab2/Exercises"
python3 Q1_des.py
```
Each script **asks** for its values with the manual's value as default — press Enter to
keep it or type a new one. That's the fastest way to handle a changed question: no code edits.

Socket questions need two terminals: start `*_server.py` first, then `*_client.py`.

Graphs are saved as PNG in the folder you run from (and pop up when run in a terminal).

## 2. Find the right function
```bash
python3 islib.py            # every function + one-line description
python3 islib.py elgamal    # only names containing "elgamal"
python3 islib.py symmetric  # exact name -> the full instructions for that one function
```

Every function in `islib.py` has a comment block right above it:
```
# [1] PREREQS  imports  : the import lines it needs      <- paste these if you copy the
#              functions: other islib functions/constants   function into a standalone file
#              pip      : packages that must be installed     (indirect ones already included)
# [2] PARAMS   what every argument means
#     RETURNS  what comes back      CHANGE  what to edit for a different question
#     EXAMPLE  a ready-made call
```

One function per family; it **encrypts by default, `decrypt=True` decrypts**:

| Question says… | Use |
|---|---|
| additive / Caesar / shift, multiplicative, affine, Vigenère, autokey | `classical_cipher(pt, "additive", 20)`, `"multiplicative", 15`, `"affine", (15, 20)`, `"vigenere", "dollars"`, `"autokey", 7` or `"autokey", "word"` · decrypt: `classical_cipher(ct, "affine", (15, 20), decrypt=True)` |
| Playfair | `playfair(pt, key, show=True)` (prints matrix + digraphs), `playfair(ct, key, decrypt=True)` |
| Hill | `hill(pt, [[3,3],[2,7]])` (any n×n), `hill(ct, K, decrypt=True)` |
| columnar / permutation / rail fence | `transposition(pt, "ZEBRA")` (word = columnar), `transposition(pt, [3,1,2])` (list = permutation), `transposition(pt, 3)` (int = rail fence) |
| brute force | `brute_force(ct, "additive" / "multiplicative" / "affine", top=3)` |
| known / chosen plaintext attack | `known_plaintext_attack(pt, ct, "additive" / "multiplicative" / "affine" / "vigenere" / "permutation" / "hill")` |
| DES / 3DES / AES, any mode | `symmetric("AES", key, msg, "CBC", show=True)` prints everything · `ct, iv = symmetric(...)` · `symmetric("AES", key, ct, "CBC", decrypt=True, iv=iv)` · modes `ECB CBC CFB OFB CTR GCM EAX` |
| key given as text | `key_bytes("A1B2C3D4", 8)` (hex or ASCII, auto) |
| compare timings | `sym_benchmark`, `timed(fn, *args, repeat=n)`, `print_table`, `plot(data, title, ylabel, "file.png")` (flat or grouped dict, `kind="line"` for a line graph) |
| AES rounds "show all steps" | `aes_encrypt_block_verbose(key, block)` (128/192/256) |
| any key pair | `generate_keys("rsa" / "rsa_textbook" / "elgamal" / "ecc" / "rabin" / "paillier" / "schnorr" / "dh", bits, ...)` — public values first, private last |
| RSA (real, padded) | `key = generate_keys("rsa", 2048)`, `rsa_cipher(msg, key.publickey())`, `rsa_cipher(ct, key, decrypt=True)` |
| RSA with given n, e, d / p, q | `generate_keys("rsa_textbook", p=17, q=19, e=5)` → `(n, e, d)`, `rsa_cipher(msg, (e, n), mode="textbook")`, `rsa_cipher(cts, (d, n), decrypt=True, mode="textbook")` |
| big data / files | `rsa_cipher(data, pub, mode="hybrid")`, `elgamal_cipher(data, p, g, y, mode="hybrid")`, `rabin_cipher(data, n, mode="hybrid")`, `ecc_cipher(data, pub)` |
| ElGamal | `p, g, y, x = generate_keys("elgamal", 512)`, `elgamal_cipher(msg, p, g, y)`, `elgamal_cipher(cts, p, g, x, decrypt=True)` |
| ECC / EC-ElGamal / ECIES / secp256r1 | `priv = generate_keys("ecc", curve="secp256r1")`, `ecc_cipher(data, priv.public_key())`, `ecc_cipher(ct, priv, decrypt=True)` |
| Diffie-Hellman / ECDH | `A, a = generate_keys("dh")`, `dh_shared(a, B)` (int) or `dh_shared(a, B, as_key=True)` (AES key); ECDH: `dh_shared(ec_priv, peer_pub, as_key=True)` |
| Rabin | `n, p, q = generate_keys("rabin", 1024)`, `rabin_cipher(data, n)`, `rabin_cipher(c, (p, q), decrypt=True)`; 4 roots: `mode="raw"` / `rabin_roots` |
| key management (generate/distribute/revoke/renew/log) | `KeyManager("rsa" / "rabin" / "elgamal" / "ecc", bits, lifetime_days)` |
| access control / limited-time access | `AccessControl()` → `set_owner`, `grant(..., seconds)`, `revoke`, `can_access` |
| weak RSA / factor n | `rsa_weak_attack(n, e)` → `(p, q, d)` |
| entropy / KDF | `key_entropy`, `derive_key(password, salt, iterations)` |
| custom hash (5381, ×33) | `djb2_hash(s)` (or `hash_hex(s, "djb2")`) |
| MD5 / SHA-1 / SHA-256 / HMAC | `hash_hex(data, "md5")`, `hash_hex(data, "sha256", key=k)` (HMAC), `find_collisions(items, fn)`, `random_strings(n)` |
| sockets | `run_server(handler, port)`, `connect(port)`, `sock_send(sock, x)` / `sock_recv(sock)` — x may be bytes, str, dict, list (comes back as the same type) |
| any signature | `signature(scheme, data, priv_key)` signs; `signature(scheme, data, pub_key, sig=s)` verifies → True/False |
| RSA signature | `signature("rsa", doc, key)`, `signature("rsa", doc, key.publickey(), sig=s)`; MD5/SHA-512: `algo="md5"` |
| lab website (raw RSA, "0xc8 0x93 …") | `signature("rsa_raw", text, (d, n))`, `signature("rsa_raw", None, (e, n), sig=s)` → recovered text, `parse_hex_bytes`, `fmt(x, "0x")` |
| ElGamal / Schnorr / ECDSA signature | `signature("elgamal", doc, (p, g, x))` / verify `(p, g, y)`; `signature("schnorr", doc, (p, q, g, x))` / `(p, q, g, y)`; `signature("ecdsa", doc, ec_priv)` |
| MAC with shared key | `signature("hmac", doc, key)`, `signature("hmac", doc, key, sig=tag)` |
| Paillier (additive HE) | `pub, priv = generate_keys("paillier", 1024)`, `paillier_cipher(m, pub)` (int or list), `paillier_cipher(c, priv, decrypt=True)` |
| compute on ciphertexts | `homomorphic("paillier", [c1, c2, ...], pub)` = E(sum); `homomorphic("rsa", [c1, c2], n)` / `homomorphic("elgamal", [c1, c2], p)` = E(product); `op="add_const"` / `"mul_const"`, `k=` |
| threshold / secret sharing | `shamir(secret, t, n)` → shares, `shamir(shares)` → secret; Paillier: `generate_keys("paillier", bits, threshold=(t, n))` → `(pub, shares)`, `paillier_cipher(c, shares, decrypt=True, pub=pub)` |
| searchable encryption | `SSE().build(docs)`, `.search("word")`; `PKSE(bits).build(docs)`, `.search("word")`; `sample_documents()`, `build_inverted_index` |
| Snort logs | `analyze_snort_alerts(path)` |

## 3. Scenario questions (menu-driven, roles, storage) – what the endsem looks like
**A program that isn't menu-driven gets half marks.** Start from `TEMPLATE_new_question.py`
(a working menu + login + storage skeleton) or copy the closest worked example:

| Example | Shows |
|---|---|
| `Exam_Examples/grant_portal.py` | AES-192, Paillier amounts, MD5 + RSA signature, index search by ID, hex dump, homomorphic total, tamper detection |
| `Exam_Examples/evoting.py` | SHA-512, AES-256-CBC, RSA-4096 key wrap, ElGamal signatures, Paillier vote tally, trusted timestamps, voting period, search by constituency/time, 2-of-3 threshold decryption |

Run either one, log in with the demo passwords at the top of the file, and try every menu option.
`Simulate tampering` edits the stored file so you can show the examiner the detection.
The data files (`*_keys.json`, `*_db.json`) are created on first run; delete them to start fresh.

Building blocks (all in islib section 9 unless noted):

| Need | Use |
|---|---|
| menu that loops, survives errors | `menu("Title", {"Option": function}, "Logout")` (dict = looping menu), single choice: `menu(title, [options])` (list) |
| validated input | `ask("Amount", cast=float, valid=lambda v: v > 0, error="must be > 0")`, `ask("PIN", secret=True)`, yes/no: `ask("Sure? (y/n)", cast=str.lower, valid=lambda v: v in "yn")` |
| logins + roles (RBAC) | users = `{"name": {"role": "...", "pw": password_hash("...")}}`, then `user, role = login(users)` and pick the role's menu |
| keys that survive restart | `K = json_store("keys.json", create=make_keys)` (RSA → `export_key().decode()`, bytes → `.hex()`) |
| records that survive restart | `db = json_store("db.json", default={"records": []})` … `json_store("db.json", db)` |
| hash / sign a record | `canonical(record_dict)` → `hash_hex(..., "md5"/"sha512")`, `signature("rsa", data, priv, algo="md5")`, `signature("elgamal", data, (p, g, x), algo="sha512")` |
| private key protected by a password | `password_seal(pw, obj)` / `password_seal(pw, blob, unseal=True)` |
| search without revealing content | `search_token(key, "const:KA-21")` → store `{token: [ids]}` (section 8) |
| trusted timestamp + deadline | `timestamp(tsa_priv, data)` creates, `timestamp(tsa_pub, data, tok, start, end)` verifies (section 6) |
| count votes with Paillier | `tally(choice)` → `paillier_cipher` → `homomorphic("paillier", cts, pub)` → decrypt → `tally(total, decode=True, n_choices=n)` (section 7) |
| threshold ("no single authority") | `pub, shares = generate_keys("paillier", bits, threshold=(t, n))`, `paillier_cipher(c, shares, decrypt=True, pub=pub)` (section 7) |
| display | `fmt(bytes)` (hex), `fmt(x, "short", 40)`, `print(fmt(data, "dump"))` (hex dump), `fmt(x, "b64")`, `print_table(headers, rows)` |

Checklist the examiner looks for: every function in the question has a menu option and prints
its output · confidentiality (encryption), integrity (hash), authenticity (signature) each shown ·
data persists after restart · wrong input / wrong password / tampered record handled with a message.

## 4. Modification recipes

**Different message / key / mode** – type it at the prompt, or change the `ask(..., default)`.

**Different symmetric algorithm** – `symmetric(ALGO, key, msg, MODE, show=True)` with ALGO `"DES"` (8-byte key),
`"3DES"` (24), `"AES"` (16/24/32 → AES-128/192/256). MODE `ECB CBC CFB OFB CTR` (+ `GCM` AES only, `EAX`).
Fixed IV: `iv=key_bytes("12345678", 8)` (DES) or 16 bytes (AES). Fixed CTR nonce: `iv=...` (half a block).
Store one value instead of (ct, iv): `packed=True` on both encrypt and decrypt.

**Key is the wrong length** – `key_bytes(key, size)` tries hex, then ASCII, then truncates/pads
and prints a note (say this in the viva). AES-192 with a 32-hex key is the manual's case.

**Small textbook numbers (p=7919, n=323 …)** – text passed to `rsa_cipher(..., mode="textbook")` /
`elgamal_cipher` is split into blocks smaller than the modulus automatically (one character per
block for tiny moduli). Given ElGamal x: `generate_keys("elgamal", p=7919, g=2, x=2999)`.
If the given public key doesn't match the private key, check `pow(g, x, p) == h` (Lab 3 A1 shows how).

**Message too long for RSA/ElGamal/Rabin** – `mode="hybrid"` (or `ecc_cipher`): the public-key
scheme encrypts an AES key, AES-GCM encrypts the data.

**Benchmark + graph** – wrap any call: `result, seconds = timed(fn, arg1, arg2, repeat=100)`,
collect `{label: seconds}` and call `plot(data, title, ylabel, "file.png")`;
for two levels (e.g. mode × algorithm) build `{group: {series: value}}` — same `plot` call
(`kind="line"` for time vs size).

**New scenario (company / hospital / DRM)** – copy `Lab4/Exercises/Q1_securecorp_rsa_dh.py`
or `Lab4/Exercises/Q2_healthcare_rabin_kms.py`. Change the scheme in `KeyManager("rsa" / "rabin" /
"elgamal" / "ecc", ...)` or pass your own `def keygen_x(bits): return public_dict, private_dict`.
Renew: `km.renew_expired(now=time.time()+days*86400)`.

**Socket version of any question** – copy `Lab5/Exercises/Q2_server.py` / `Q2_client.py`;
put the server work in `handle(conn, addr)` and use `sock_send` / `sock_recv` (dicts go as JSON
automatically). Change `PORT` if "address already in use". Both in one file: `run_server(..., background=True)`.

**HE on a list of values** – `homomorphic("paillier", paillier_cipher(values, pub), pub)`;
average = decrypt(sum) / len; weighted = `homomorphic("paillier", c, pub, "mul_const", weight)`.

**Searchable encryption with your own documents** – pass a dict `{"doc1": "text", ...}` to `.build()`.

**Copy a function into a standalone answer file** – paste the function, then everything its
`[1] PREREQS` lists: the import lines exactly as written, and each listed function/constant
(they are already in the right order in islib.py).

## 5. Folder map
```
islib.py                         master library (all modular functions)
TEMPLATE_new_question.py         menu-driven skeleton for a new scenario question
Exam_Examples/                   grant_portal.py, evoting.py (full endsem-style answers)
Lab1  Exercises Q1-Q6, Additional A1-A3      classical ciphers + attacks
Lab2  Exercises Q1-Q5, Additional A1-A5      DES / 3DES / AES, modes, timing, AES steps
Lab3  Exercises Q1-Q5, Additional A1-A5      RSA, ECC, ElGamal, DH, file transfer, benchmarks
Lab4  Exercises Q1-Q2, Additional A1-A2      key management (RSA+DH, Rabin), DRM, weak-RSA attack
Lab5  Exercises Q1-Q3, Additional A1         hashing, socket integrity, collisions
Lab6  Exercises Q0-Q3, Additional A1         signatures (website keys, ElGamal, Schnorr, DH, client-server), CIA
Lab7  Exercises Q1-Q2, Additional A1a-A1d    Paillier, RSA/ElGamal HE, data sharing, threshold, benchmark
Lab8  Exercises Q1-Q2, Additional A1-A2      SSE, PKSE, GnuPG, Snort
```

## 6. Notes on the manual's data (useful in the viva)
* Lab 1 Q5: `XVIEWYWI` decrypts to `TREASUSE` (key 4); the intended word is TREASURE.
* Lab 1 A2: `CABDEHFGL` contains L, which isn't in `abcdefghi` – treated as I; key size 9.
* Lab 2 Q4: the 3DES key is K1=K2=K3 → identical to single DES (pycryptodome refuses it; islib explains and uses DES).
* Lab 2 Q5: the "AES-192" key is only 16 bytes as hex → first 24 ASCII chars used.
* Lab 3 A1: `2^2999 mod 7919 = 3868`, not 6465 → the script uses the consistent h.
* Lab 6: the website signs raw RSA (`m^d mod n`); Alice's and BOB's signatures in the manual verify correctly in Q0.
* Lab 8: the manual's SSE sample code uses random-IV CBC for index keys, so search can never match;
  islib uses deterministic encryption for search tokens (Q1) and a Paillier equality test (Q2).

## 7. Common errors
| Error | Fix |
|---|---|
| `ModuleNotFoundError: islib` | keep the folder layout, or change `parents[2]` in the import line |
| `ModuleNotFoundError: Crypto` | `pip3 install pycryptodome` (not `crypto`) |
| `Incorrect DES key length` / `Incorrect AES key length` | use `key_bytes(key, 8/16/24/32)` |
| `Data must be padded` | ECB/CBC need padding – `symmetric` does it; don't call `.encrypt` raw |
| `Plaintext is too long` (RSA) | use `rsa_cipher(..., mode="hybrid")` |
| `base is not invertible` / `has no inverse mod 26` | key not coprime with 26 / φ(n) – choose another key |
| `Address already in use` | change `PORT` or wait a few seconds |
| `MAC check failed` | GCM/EAX ciphertext or key was changed (tampering detected) — or the wrong key |
