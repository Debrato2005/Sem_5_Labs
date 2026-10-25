# INFORMATION SECURITY LAB — UNIVERSAL ENDSem ASSEMBLY README

**Purpose:** build a correct **menu-driven Python exam answer** from reusable, copy/paste-ready components. Based on the supplied *IS Midsem Scenario Programming Guide*, Labs 1–8, and the grant and e-voting practice scenarios. This is an educational template, **not a promise that every unseen question has the same architecture** and not deployable secure infrastructure.

**Files:**

| File | What you copy / use |
|---|---|
| `README.md` | This main question-to-code assembly manual; complete code for every block appears below |
| `common.py` | File I/O, IDs, input conversions, SHA/MD5, role passwords, tamper demos |
| `classical.py` | Caesar, affine, Vigenère, autokey, Playfair, Hill, rail fence, columnar |
| `symmetric.py` | AES/DES/3DES and modes; AES key-size selection and exact CBC IV |
| `public_key.py` | RSA OAEP/signatures, ElGamal, Schnorr, DH, ECC, Rabin |
| `homomorphic.py` | Paillier, weighted sums, votes per candidate, multiplicative demos |
| `search_index.py` | Confidential document AES-GCM plus HMAC-keyed SSE index |
| `07_math_and_access.py` | Modular arithmetic, AES GF(2⁸), MixColumns, MAC/DAC/ABAC |
| `08_network.py` | Framed sender/receiver sockets and HMAC |
| `EXAM_STARTER.py` | **Runnable three-role menu** with persistent AES + hash + RSA signing + Paillier |
| `BUILD_EXAM.py` | Generate **one Python file** containing the selected modules + optional menu |
| `Secure_Grant_Expense_Portal_Menu.py` | Complete worked example, bundled from earlier practice |
| `Secure_EVoting_Menu.py` | Complete e-voting practice example, bundled from earlier practice |

> **No hardcoded exam data:** IDs, amounts, text, filenames, secrets, role names, key parameters, dates and record selections are obtained from input or generated cryptographically. Some **cryptographic constants, mode identifiers and the semantics of the three operations** are fixed as implementation logic, not scenario data. The menu starter is a working *general record/amount* scenario, not automatically compliant with every possible problem; edit the parts the question changes.

---

## 1. FIRST THREE MINUTES: decode the question

**Do not start writing AES before mapping the problem.** Fill in this table on paper or in a comment:

| Item | Fill from the actual question |
|---|---|
| Actors | e.g. `researcher, reviewer, finance`; which one may decrypt? |
| Inputs | Which IDs, files, plaintext strings, amounts, keywords, voter choices? |
| Symmetric encryption | AES-128 / 192 / 256, mode CBC/GCM/CTR, padding, IV/nonce requirements |
| Public-key encryption | RSA-OAEP, ElGamal, ECC? What exactly is encrypted: data or AES key? |
| Hash | MD5/SHA-1/SHA-256/SHA-512, and **of which bytes**? |
| Signature | RSA/ElGamal/ECDSA, which key signs, which exact bytes are signed? |
| Homomorphic operation | Paillier **sum** / scalar multiply; ElGamal **product**; encrypted vote counts? |
| Search | ID lookup, HMAC-keyword SSE, AND/OR, range/time filters? |
| Persistence | JSON or SQLite; what key material must survive restart? |
| Menu and output | Which separate role menus, prints and negative-input tests? |
| Security limitations | Trusted time? formal threshold? authentication? encryption at rest for keys? |

**Default assembly order:**

```text
USER INPUT -> VALIDATE -> ENCRYPT -> CANONICAL RECORD -> HASH EXACT RECORD
           -> SIGN SAME RECORD/HASH -> PERSIST ENCRYPTED FIELDS AND METADATA
           -> ROLE LOGIN -> SEARCH / VERIFY HASH AND SIGNATURE
           -> ONLY AUTHORIZED ROLE DECRYPTS OR AGGREGATES
```

When the question explicitly says hash the **plaintext ballot file**, follow it; the signed material must match what you later verify. If the submitted ciphertext/Paillier fields also need integrity, sign an **envelope** covering them too. **Never replace the examiner's specified algorithm with another silently.**

## 2. LAB 1–8 QUESTION → BLOCK MAP

| Question keywords | Copy blocks | Essential constraint |
|---|---|---|
| Lab 1 Caesar/additive, affine/multiplicative, Vigenère, autokey | `classical.py` | Affine key `gcd(a,26)==1` |
| Lab 1 Playfair, Hill, rail/columnar transposition | `classical.py` | Hill determinant invertible mod 26; fillers change recovered text |
| Lab 2 AES-128/192/256 CBC, CTR, GCM, ECB, CFB, OFB | `symmetric.py` | Exact key sizes 16/24/32; fresh 16-byte CBC IV |
| Lab 2 DES/3DES, avalanche, GF AES, InvMixColumns | `symmetric.py`, `07_math_and_access.py` | DES/ECB demos are legacy; GF reduction polynomial `0x11b` |
| Lab 3 RSA OAEP/hybrid RSA+AES | `public_key.py` + `symmetric.py` | RSA encrypts short message or session key, not a whole file |
| Lab 3 ElGamal encryption, ECDH/ECC, DH | `public_key.py` | Use real modular math, not nonexistent `ElGamal.encrypt()` |
| Lab 4 Rabin, key handling, MAC/DAC/ABAC, RBAC | `public_key.py`, `07_math_and_access.py`, `common.py` | Rabin has multiple plaintext roots; menus enforce roles |
| Lab 5 custom DJB2/MD5/SHA-1/SHA-256/SHA-512, integrity and HMAC | `common.py`, `08_network.py` | Hash EXACT required bytes; ordinary hash alone not authentication |
| Lab 6 RSA signatures, ElGamal/Schnorr signatures, ECC signatures | `public_key.py` | Private signs, public verifies; sign before storage, verify after loading |
| Lab 7 Paillier encrypted sum/average/weighted sum | `homomorphic.py` | Same Paillier public key; decrypt **aggregate only** if mandated |
| Lab 7 textbook RSA/ElGamal homomorphic multiplication | `homomorphic.py`, `public_key.py` | RSA OAEP is **not** multiplicatively homomorphic |
| Lab 8 encrypted keyword/ID search | `search_index.py`, `common.py` | Randomized ciphertext cannot be searched by equality |
| Lab 8 GnuPG/Snort | Shell snippets in §13 | Both require separate system executables |
| Menu, persistence, tampering, user-input validation | `EXAM_STARTER.py`, `common.py` | No menu = half marks for the provided sample scenario |
| Socket-based sender/receiver | `08_network.py` | Framing and authenticity must be implemented separately |

**Terms that can be misleading:**
- Encrypted **candidate ID sum** is **not** a candidate-by-candidate tally; use an encrypted one-hot vector per candidate.
- Paillier supports addition; it does **not** support arbitrary ciphertext-by-ciphertext multiplication or confidential `>` comparisons by itself.
- RSA-OAEP is randomized: identical keywords do not produce identical ciphertexts. HMAC blind-index lookup is an **SSE-style hybrid**, not a formal public-key searchable-encryption protocol.
- A locally generated signed timestamp is **not** proof from an external trusted timestamp authority.
- Reconstructing a Paillier private key from two shares is **not** real threshold-Paillier decryption.
- MD5 and DES are insecure by modern standards; implement them only when specifically required for the lab.

---

## 3. SETUP IN PYCHARM ON DEBIAN

If `endsem_exam/` is **not already the PyCharm project directory**, open a terminal from its parent directory:

```bash
mkdir -p endsem_exam && cd endsem_exam
uv venv .venv
uv pip install --python .venv/bin/python pycryptodome cryptography numpy sympy matplotlib ecdsa flask 'fastapi[standard]' psutil phe python-gnupg scapy
source .venv/bin/activate
python -c 'from Crypto.Cipher import AES; from Crypto.PublicKey import RSA; from phe import paillier; print("IS LAB ENVIRONMENT READY")'
```

If PyCharm is **already open inside `endsem_exam`**, do NOT create a second nested folder. On Debian, globally upgrading `uv` via `python -m pip` can fail with `externally-managed-environment`; install `uv` via `pipx` or the approved Debian installation method if needed. Set **PyCharm → Settings → Project → Python Interpreter** to `endsem_exam/.venv/bin/python`.

**Run the menu starter when the companion modules are in the same folder:**

```bash
python EXAM_STARTER.py
```

**Make a ONE-FILE copy for submission or quick editing:**

```bash
python BUILD_EXAM.py
# choose: common,symmetric,public_key,homomorphic
# append menu: y
# output: answer.py
python answer.py
```

The builder will **not overwrite** an existing file. A generated one-file program no longer imports local module files. You can alternatively copy a module's complete fenced Python block from §12 into your own script. If copying all blocks into one script, **remove the `from common import ...` / similar local-file imports in `EXAM_STARTER.py`**; the functions already appear above it.

**Fast exam strategy:** Pick only components the question mentions; don't add Flask/FastAPI/network/Paillier if not requested. The large installation list does NOT mean every question uses every package.

---

## 4. UNIVERSAL SHELL: menus, persistent keys, and secure verification

The supplied `EXAM_STARTER.py` is already runnable. It has user-specified RSA bits, Paillier bits, AES key size, AES CBC/GCM mode, hash algorithm, role names/passwords and files. Operations:

```text
Role 1 — Submit record; show old encrypted records
Role 2 — Search ID without contents; verify all; decrypt description as hex; tamper demo
Role 3 — Select multiple IDs; check hash + RSA signature; homomorphically sum
         Paillier ciphertexts; decrypt only the final total
```

- On first launch: supply two distinct new JSON file paths. Save them and use **the same paths** after restart. The separate key/config file is required to decrypt earlier ciphertexts and verify signatures.
- It uses authenticated AES-GCM if selected, or AES-CBC if explicitly asked. CBC encryption does **not** inherently authenticate ciphertext; the separate RSA signature protects the signed record.
- The file-based role passwords are for a local classroom demonstration. The script stores reusable private keys on disk with Linux mode `0600`; that is **not production-grade key isolation**.
- If the question requires another algorithm, change the `submit()` and `valid()` functions **together**; otherwise signatures and hash checks may stop matching.

### Minimal generic role-menu skeleton (paste if you want to build an unrelated scenario)

```python
# Define these operations by copying required functions from the blocks below.
# Use different role labels/action lists to match the examiner's wording.
roles = [input(f'Role {i} name: ').strip() for i in range(1, 4)]
while True:
    print('0 Exit', *(f'{i} {r}' for i, r in enumerate(roles, 1)))
    role = input('Role: ').strip()
    if role == '0': break
    if role not in ('1', '2', '3'): print('Invalid role'); continue
    while True:
        print('1 Submit/Operate  2 View/Verify  0 Back')
        choice = input('Choice: ').strip()
        if choice == '0': break
        if choice == '1': print('PASTE YOUR ALLOWED SUBMIT/OPERATE FUNCTION CALL HERE')
        elif choice == '2': print('PASTE YOUR ALLOWED VIEW/VERIFY FUNCTION CALL HERE')
        else: print('Invalid choice')
```

That tiny snippet is a **menu scaffold**, not a secure RBAC solution. For actual restrictions and login, copy `make_role_passwords`/`role_login` or start from the working `EXAM_STARTER.py`. **Do not leave placeholder `print(...)` branches in a submitted answer.**

---

## 5. SIX READY-MADE QUESTION RECIPES

These are *call sequences*, not standalone scripts. Keep the selected modules in your working directory, import their functions, and insert the calls in the corresponding menu branches. Values labeled `data`, `rows`, `conf`, `pub` etc. must come from the inputs and initialization shown in your program — **never copy isolated lines into a blank file without their setup**.

### Recipe A — researcher/reviewer/finance: AES-192 + Paillier + MD5 + RSA

**Fastest correct answer:** run/edit `EXAM_STARTER.py` and choose AES length `192`, mode `CBC` (or the exact specified mode), digest `md5`, decimal places as required. Rename the three roles to researcher/reviewer/finance. Retains old records and verifies before final-total decryption.

Call mapping: `submit()` encrypts description → `phe_encrypt_integer()` amount → `canonical()` signed payload → `digest(..., 'md5')` → `rsa_sign(..., 'md5')` → `save_json()`. Reviewer uses `valid()`, ID lookup, and `hex_dump(symmetric_decrypt(...))`. Finance calls `phe_sum()` after checking **all signatures**, then decrypts only that sum.

### Recipe B — national e-voting: AES-256 CBC + SHA-512 + RSA-4096 + ElGamal + Paillier + SSE

The bundled `Secure_EVoting_Menu.py` is a complete example of the more elaborate composition. To reconstruct it from blocks:

1. Enter `candidate IDs`, election start/end, voter ID, constituency ID, ballot file path and key paths.
2. Compute `hashlib.sha512(ballot_file_bytes).hexdigest()` **before** encryption as specified.
3. Call `symmetric_encrypt(ballot_bytes, 'AES', 'CBC', key_bits=256)`; RSA-OAEP wrap **only the returned 32-byte AES key**, `rsa_encrypt(aes_key, commission_public_pem)` where the commission key is RSA-4096.
4. `elgamal_sign(ballot_bytes, voter_private, voter_public, 'sha512')`; also sign **the whole serialized ciphertext envelope** (or use an authenticated outer signature) to detect changes to Paillier counts, constituency ID, timestamps and wrapped key. Store the ElGamal public key.
5. Call `encrypt_candidate_ballot(phe_pub, chosen_candidate_id, candidates)` to create a **0/1 encrypted vote for EACH candidate**.
6. Create a timestamp record. Local signed time is a demo only; do not call it independently trusted. Check election time range server-side.
7. Index constituency with `token(index_secret, 'constituency', constituency_id)` and persist the index. The server must not decrypt individual vote ciphertexts.
8. Validate timestamp, hash and digital signatures before tallying; aggregate candidate-wise columns with `tally_candidate_ballots()`.
9. Decrypt only final encrypted counts. A two-share reconstructed key is **not** formal threshold decryption; report that limit clearly.

### Recipe C — doctor/nurse/auditor: hybrid encrypted medical records

1. Input patient details/file as UTF-8 bytes. Use `symmetric_encrypt(..., 'AES', 'CBC', key_bits=128)` with fresh IV unless examiner specifies another mode.
2. `rsa_generate(2048)` for recipient; `rsa_encrypt(aes_key, recipient_public_pem)` to wrap session key.
3. Construct `record={'id': supplied_id, 'aes': cipher_record, 'wrapped_key': wrapped.hex(), 'timestamp': utc_now()}`; `data=canonical(record)`.
4. `hash=digest(data,'sha256')`, `sig=rsa_sign(data, signer_private,'sha256')`, and persist **encrypted fields plus hash and signature**.
5. Doctor: recompute digest and verify RSA signature, then RSA-unwrap AES key, AES-decrypt only if valid. Nurse: ciphertext/hash/signature view and verification only. Auditor: allowed metadata and verification only.
6. Demonstrate tampering by mutating a copy of AES ciphertext with `flip_hex()`; verification must fail.

### Recipe D — file integrity/transmission: SHA + HMAC/RSA signature + socket

1. Read filename/user choice with `ask_bytes(kind='file')`.
2. Hash **exact source requested** (plaintext or ciphertext). `digest(data, 'sha256')` and/or `hmac_sign(data, secret)`; RSA signatures via `rsa_sign()`.
3. Send length-framed JSON with `send_record(host, port, row)` and receive via `receive_record()`.
4. Receiver recomputes digest and verifies HMAC or asymmetric signature before decrypting/disclosing. Run server/receiver first.

### Recipe E — Paillier weighted sum, average, vote tally

```python
# Works AFTER pub/pri are restored, integer inputs collected, and records encrypted.
# See homomorphic.py; decrypt ONLY the computed result where requested.
# final = phe_sum(pub, [phe_encrypt_integer(pub, amount) for amount in values])
# answer = phe_decrypt_final(pri, final)
# weighted = phe_weighted_total(pub, ciphertext_records, integer_weights)
# average = phe_decrypt_final(pri, final) / len(ciphertext_records)
# encrypted_ballots = [encrypt_candidate_ballot(pub, choice, candidate_ids) for choice in choices]
# totals = tally_candidate_ballots(pub, encrypted_ballots, candidate_ids)
```

Inputs should be collected with `input()`/`ask_int()`. For actual privacy-preserving workflows, individual amounts/votes should not be decrypted, and both keys should not be available to one unrestricted user.

### Recipe F — searchable-encryption files and keyword indexing

```python
# Use an initialized store={'documents':{}, 'index':{}} and persisted secret/aes_key.
# sse_add(store, secret, aes_key, input('ID: '),
#         input('Contents: ').encode(), input('Keywords: ').split(','))
# matches = sse_find(store, secret, input('Keywords: ').split(','), 'AND')
# for doc_key in matches:
#     print(doc_key, sse_read(store, doc_key, aes_key).decode(errors='replace'))
# save_json(input('Store path: '), store)
```

**Important:** Search returns encrypted-document handles; reading plaintext should require an authorized role. HMAC keyword equality reveals search/access patterns. It does not hide query repetition or replace genuine PKSE.

---

## 6. DIRECT COPY/PASTE MICRO-PATTERNS

### AES key lengths and input handling

```python
from Crypto.Random import get_random_bytes
bits = int(input('AES bits (128/192/256): '))
if bits not in (128, 192, 256): raise ValueError('Invalid AES size')
aes_key = get_random_bytes(bits // 8)  # securely generated, not hardcoded
text = input('Plaintext: ').encode()
raw_hex = bytes.fromhex(input('Hex input (if required): '))
# IMPORTANT: a hex string must be bytes.fromhex(...), not .encode()!
```

### Full hybrid RSA-OAEP plus AES-CBC one-shot example

```python
from symmetric import symmetric_encrypt, symmetric_decrypt
from public_key import rsa_generate, rsa_encrypt, rsa_decrypt
from Crypto.Random import get_random_bytes
private_pem, public_pem = rsa_generate(int(input('RSA key bits: ')))
message = input('Message: ').encode()
record, session_key = symmetric_encrypt(message, 'AES', 'CBC', key_bits=256)
wrapped = rsa_encrypt(session_key, public_pem)
# Store record + wrapped.hex(); persist private_pem securely if restart is required.
recovered_key = rsa_decrypt(wrapped, private_pem)
print('Recovered:', symmetric_decrypt(record, recovered_key).decode())
```

### Hash the exact object and sign it (no accidental double hash)

```python
from common import canonical, digest
from public_key import rsa_sign, rsa_verify
payload = {'id': input('ID: '), 'encrypted_field': input('Ciphertext HEX: ')}
raw = canonical(payload)
print('SHA-512:', digest(raw, 'sha512'))
# With existing private_pem and public_pem:
# signature_hex = rsa_sign(raw, private_pem, 'sha512')
# print('Valid:', rsa_verify(raw, signature_hex, public_pem, 'sha512'))
# rsa_sign(raw, ...) hashes raw ONCE using SHA-512. Do not pre-hash and hash again.
```

### Simple JSON persisted records (never regenerate keys on restart)

```python
from common import load_json, save_json
path = input('JSON record file path: ')
rows = load_json(path, {})
record_id = input('ID: ').strip()
if not record_id or record_id in rows: raise ValueError('Bad/duplicate ID')
rows[record_id] = {'ciphertext': input('Ciphertext hex: ')}
save_json(path, rows)
print('Saved:', record_id)
```

### DES / 3DES / AES mode selector (lab 2)

```python
from symmetric import symmetric_encrypt, symmetric_decrypt
alg = input('Algorithm (AES/DES/3DES): ').upper().strip()
mode = input('Mode (CBC/ECB/CFB/OFB/CTR; AES GCM too): ').upper().strip()
bits = int(input('AES key bits (128/192/256; ignored for DES): ')) if alg == 'AES' else 192
row, key = symmetric_encrypt(input('Plaintext: ').encode(), alg, mode, key_bits=bits)
print('Ciphertext hex:', row['ct'], '| metadata:', row)
print('Decrypted:', symmetric_decrypt(row, key).decode())
```

### Galois GF(2⁸), MixColumns and InvMixColumns (lab 2 theory/practical)

```python
# Copy 07_math_and_access.py above this block (or import using importlib).
from importlib import import_module
maths = import_module('07_math_and_access')
col = [int(input(f'Column byte {i+1} hex: '), 16) for i in range(4)]
print('MixColumns:', [f'{b:02x}' for b in maths.aes_mix_column(col)])
print('InvMixColumns:', [f'{b:02x}' for b in maths.aes_mix_column(col, inverse=True)])
```

---

## 7. EXAM QUALITY CHECKS — BEFORE SUBMISSION

- [ ] Full **menu-driven** solution; every required role has reachable actions; back/exit work.
- [ ] All scenario-specific IDs, values, text, filenames, keywords, candidates and dates are collected from the user or file.
- [ ] All cryptographic keys are generated from secure randomness or validated user-supplied key bytes. Correct AES key lengths; CBC fresh correct IV; padding matches the question.
- [ ] Bytes/text/hex handled explicitly (`.encode()`, `.decode()`, `.hex()`, `bytes.fromhex()`).
- [ ] Hashes cover **exact bytes required by the prompt** and verification recomputes from loaded/stored ciphertext, not a fresh copy of the original.
- [ ] RSA private key signs, public key verifies; RSA public key wraps AES key, private key unwraps; persistent key material is reloaded after restart.
- [ ] Signatures authenticate **all security-relevant fields** such as ciphertext, nonce/IV, Paillier columns, ID and timestamps, or use multiple signatures that do so.
- [ ] Rejected/tampered records are never decrypted or counted.
- [ ] Paillier aggregation happens on ciphertexts; only final aggregate is decrypted if required; signed integer range/overflow is considered.
- [ ] Per-candidate ballots are **one-hot encrypted vectors**, not encrypted candidate ID sums.
- [ ] ID search does not print encrypted content if forbidden; SSE keyword token matching does not assume equality of randomized AES/RSA ciphertexts.
- [ ] Roles are authenticated (at least local password demonstration), not merely selected by typing any role name.
- [ ] Disk records and relevant keys persist. Test: add record → exit → restart → search → verify/decrypt.
- [ ] Error handling catches invalid input, missing ID, duplicate ID, malformed ciphertext, invalid hash/signature, invalid dates and file errors gracefully.
- [ ] Output demonstrates each requested function and one negative/tamper case.
- [ ] Any fake external TSA, mock threshold reconstruction, or toy ElGamal parameters are explicitly labeled as demonstrations.

**Quick validation command:**

```bash
python -m compileall -q .
```

This checks **syntax only**. It does not prove PyCryptodome/phe runtime behavior, secure deployment, or output correctness. Execute end-to-end tests in your Debian PyCharm virtual environment.

---

### Re-key / AES key rotation (Lab 4)

To rotate encryption, **verify the old signed record**, decrypt it with the old key, re-encrypt with a new securely generated key and nonce/IV, **recompute the digest and re-sign the changed record**, then save the new ciphertext and associated key ID.

```python
from Crypto.Random import get_random_bytes
from symmetric import symmetric_decrypt, symmetric_encrypt
# verified_record, old_key, new_key must be read/generated first
# original = symmetric_decrypt(verified_record, old_key)
# rotated, new_key = symmetric_encrypt(original, 'AES', 'GCM', get_random_bytes(32))
# canonicalize, hash, re-sign and persist the rotated record and key ID
```

Re-keying is **not** achieved by replacing only the saved AES key; old ciphertexts would become unreadable. Persist previous keys only as long as policy permits, protect them and apply explicit key IDs.

### ECDH → AES key derivation (Lab 3)

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from public_key import ecc_generate, ecc_ecdh
private_a, public_a = ecc_generate()
private_b, public_b = ecc_generate()
shared_a = ecc_ecdh(private_a, public_b)
shared_b = ecc_ecdh(private_b, public_a)
assert shared_a == shared_b
context = input('Agreed ECDH context: ').encode()
key_a = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(shared_a)
key_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(shared_b)
assert key_a == key_b
```

HKDF requires an agreed protocol context (and salt where appropriate) for real use. Do not directly slice or use raw ECDH exchange bytes as an AES key.

---

## 8. COMMON FAILURE TRAPS

1. Encrypting RSA-OAEP ciphertext with textbook RSA multiplication expecting homomorphism (**does not work**).
2. Implementing Paillier by squaring messages or splitting RSA modulus into `n//2` (not Paillier).
3. Signing `hashlib.sha512(data).digest()` using `rsa_sign(digest, ..., 'sha512')`: this **double-hashes**. Sign original data using the configured hash.
4. Hashing ciphertext on submit but plaintext after retrieving it, then incorrectly treating the mismatch as tampering.
5. Recomputing the stored hash after a record is modified; the recomputed hash alone cannot authenticate data. Verify an independently signed digest/record.
6. Attempting `AES.new(key, AES.MODE_CBC)` on decrypt without restoring the original IV.
7. `DES3.new()` with an invalid/degenerated 3DES key; use a parity-adjusted nondegenerate key.
8. Calling `RSA_key.encrypt` or direct `ElGamal.encrypt` on a PyCryptodome key: unsupported modern APIs.
9. Calling `private.decrypt(each_vote)` instead of aggregate-only when the privacy requirement forbids it.
10. Logging plaintext or passwords in reviewer/auditor menu branches.
11. Destroying previous keys every time the program restarts, making old stored records unreadable.
12. Treating an untrusted local `datetime.now()` as an independently certified TSA timestamp.
13. Assuming role menus alone stop a local user who can read the saved private-key file; this is a classroom design, not hardened RBAC.
14. Randomized AES/RSA/Paillier encryption used for direct keyword equality lookup; use blind index tokens where permitted.
15. For a true file-signing system with SHA-512, dropping IV, RSA wrapped key, encrypted vote, or metadata from the signed envelope allows undetected modification.

---

## 9. SYSTEM TOOLS (LAB 8): GNU PRIVACY GUARD & SNORT

These are **system applications**, not installed by `python-gnupg` or `scapy`. Only use if the examiner asks.

### GnuPG

```bash
# Prompt for file; password prompt is handled securely by GnuPG
read -r -p 'File path: ' source_file
gpg --symmetric --cipher-algo AES256 -- "$source_file"
read -r -p 'Decrypted output file: ' output_file
gpg --decrypt -- "$source_file.gpg" > "$output_file"
# For public-key workflows, create keys with: gpg --full-generate-key
# Then: gpg --encrypt --recipient 'recipient-key-id' -- "$source_file"
# Sign: gpg --detach-sign --armor -- "$source_file"
# Verify: gpg --verify -- "$source_file.asc" "$source_file"
```

### Snort

Example Snort 2-style alert rule (adapt interface, configuration, HOME_NET and allowed ports to the lab):

```text
alert tcp any any -> $HOME_NET 80 (msg:"IS lab HTTP SYN demo"; flags:S; sid:1000001; rev:1;)
```

Validation syntax is **version/config dependent**: Snort 2 typically uses `snort -T -c /path/to/snort.conf`; Snort 3 uses its own `snort.lua` configuration. Do not assume either is installed or available without root/system configuration.

---

## 10. FILES / SCENARIOS REUSED FROM YOUR PRACTICE

- **Secure Grant Expense Portal**: `Secure_Grant_Expense_Portal_Menu.py` (actual full multi-role example).
- **E-voting**: `Secure_EVoting_Menu.py` (longer scenario with encrypted per-candidate counting).
- **Reference source**: your uploaded **IS Midsem Scenario Programming Guide** already explains earlier examples such as HealthSecure, MediSecure and hybrid hospital. This kit extends the composition approach to Lab 1 and Labs 7–8 while correcting crypto API and modeling pitfalls.

**Educational security boundary:** the examples demonstrate cryptographic primitives and role-oriented menus. They are NOT security-assessed medical, financial or election infrastructure. Production features such as certificate/identity management, proper key custody, independently trusted timestamps, formal threshold decryption, auditing, revocation, fault recovery and side-channel protections need separate design and verification.

---

## 11. HOW TO COPY BLOCKS BELOW

Every block below is **a complete importable `.py` module**; it has its own imports. Three supported workflows:

1. **Fastest:** save all `.py` files beside your answer and use `from symmetric import ...`; run `EXAM_STARTER.py`.
2. **One file:** run `BUILD_EXAM.py`, select component names, append menu if relevant, and open generated `answer.py`. This automatically strips only the local-file imports.
3. **Direct paste:** copy the **entire** module block into the top of a blank answer `.py` file. Choose only what the question needs, then add a main-menu function below. If you also paste the full starter, remove its imports of `common`, `symmetric`, `public_key` and `homomorphic`, since those functions already appear earlier in the same file.

The **small executable code** is in the blocks; the detailed exam reasoning is above. All sample data are prompts or generated values rather than fixed question examples.

---

## 12. FULL COPY/PASTE PYTHON BLOCKS


### 12.1 — Common input, persistence, role login, hashes, HMAC tokens and tampering

Filename: `common.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 01: reusable input, storage, hashing, role-login, and indexing."""
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from getpass import getpass
from pathlib import Path


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def ask_int(label, low=None, high=None):
    v = int(input(label).strip())
    if (low is not None and v < low) or (high is not None and v > high):
        raise ValueError('Number outside allowed range')
    return v


def ask_bytes(label='Content', kind='text'):
    if kind == 'file':
        return Path(input(label + ' file path: ').strip()).expanduser().read_bytes()
    if kind == 'hex':
        return bytes.fromhex(input(label + ' hex: ').strip())
    return input(label + ': ').encode()


def digest(data, name='sha256'):
    return hashlib.new(name.lower().replace('-', ''), data).hexdigest()


def djb2(data, modulus=2**32):
    """Educational DJB2 5381 rolling hash; NOT cryptographic collision resistance."""
    h = 5381
    for b in data:
        h = ((h * 33) + b) % modulus
    return h


def hex_dump(data, width=16):
    for i in range(0, len(data), width):
        print(f'{i:04x}:', data[i:i + width].hex(' '))


def amount_to_int(label='Amount', places=2):
    value = Decimal(input(label + ': ').strip()) * 10 ** places
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError('Amount must fit the configured decimal places')
    return int(value)


def load_json(path, default):
    p = Path(path).expanduser()
    return json.loads(p.read_text()) if p.exists() else default


def save_json(path, obj, private=False):
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + '.tmp')
    tmp.write_text(json.dumps(obj, indent=2), encoding='utf-8')
    if private:
        os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def search_token(secret, label, value):
    msg = f'{label}:{value.strip().casefold()}'.encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def make_role_passwords(roles):
    result = {}
    for name in roles:
        password = getpass(f'Create password for {name}: ')
        if not password:
            raise ValueError('Empty passwords are not permitted')
        salt = os.urandom(16)
        result[name] = (salt.hex(), hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000).hex())
    return result


def role_login(passwords, role):
    if role not in passwords:
        return False
    salt, expected = passwords[role]
    actual = hashlib.pbkdf2_hmac('sha256', getpass(f'{role} password: ').encode(), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(actual.hex(), expected)


def indexed_lookup(rows, record_id):
    """Fast lookup; indexes the ID in plaintext, NOT hidden-search SSE."""
    return rows.get(record_id)


def flip_hex(record, field):
    """Tamper DEMO: mutate one encrypted byte; only call on a copy."""
    row = dict(record)
    raw = bytearray.fromhex(row[field])
    if not raw:
        raise ValueError('Cannot tamper empty ciphertext')
    raw[0] ^= 1
    row[field] = raw.hex()
    return row
```


### 12.2 — Classical cipher suite (Lab 1)

Filename: `classical.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 06: classical ciphers; classroom implementations, not modern security."""
from math import gcd


def shift_cipher(text, shift, decrypt=False):
    k = -shift if decrypt else shift
    return ''.join(chr((ord(c) - (65 if c.isupper() else 97) + k) % 26 +
                       (65 if c.isupper() else 97)) if c.isascii() and c.isalpha() else c
                   for c in text)


def affine_cipher(text, a, b, decrypt=False):
    if gcd(a, 26) != 1:
        raise ValueError('Affine key a must be coprime with 26')
    if decrypt:
        a, b = pow(a, -1, 26), -pow(a, -1, 26) * b
    return ''.join(chr((a * (ord(c) - (65 if c.isupper() else 97)) + b) % 26 +
                       (65 if c.isupper() else 97)) if c.isascii() and c.isalpha() else c
                   for c in text)


def vigenere(text, key, decrypt=False):
    key = [ord(c.upper()) - 65 for c in key if c.isascii() and c.isalpha()]
    if not key:
        raise ValueError('Enter alphabetic key')
    result, j = [], 0
    for c in text:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            result.append(chr((ord(c) - base + (-1 if decrypt else 1) * key[j % len(key)]) % 26 + base))
            j += 1
        else:
            result.append(c)
    return ''.join(result)


def autokey(text, keyword, decrypt=False):
    data = ''.join(c.upper() for c in text if c.isascii() and c.isalpha())
    start = [ord(c.upper()) - 65 for c in keyword if c.isascii() and c.isalpha()]
    if not start:
        raise ValueError('Enter alphabetic keyword')
    result, stream = [], start[:]
    for i, ch in enumerate(data):
        x = (ord(ch) - 65 + (-stream[i] if decrypt else stream[i])) % 26
        result.append(chr(x + 65))
        stream.append(x if decrypt else ord(ch) - 65)
    return ''.join(result)


def playfair(text, keyword, decrypt=False):
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    key = ''.join(dict.fromkeys((keyword + alphabet).upper().replace('J', 'I')))
    square = ''.join(c for c in key if c in alphabet)
    pos = {c: divmod(i, 5) for i, c in enumerate(square)}
    s = ''.join(c for c in text.upper().replace('J', 'I') if c in alphabet)
    if not decrypt:
        pairs, i = [], 0
        while i < len(s):
            a = s[i]
            b = s[i + 1] if i + 1 < len(s) and s[i + 1] != a else ('Q' if a == 'X' else 'X')
            pairs.append((a, b))
            i += 2 if i + 1 < len(s) and b == s[i + 1] else 1
    else:
        if len(s) % 2:
            raise ValueError('Ciphertext length must be even')
        pairs = list(zip(s[::2], s[1::2]))
    step = -1 if decrypt else 1
    out = ''
    for a, b in pairs:
        r1, c1 = pos[a]; r2, c2 = pos[b]
        if r1 == r2:
            c1, c2 = (c1 + step) % 5, (c2 + step) % 5
        elif c1 == c2:
            r1, r2 = (r1 + step) % 5, (r2 + step) % 5
        else:
            c1, c2 = c2, c1
        out += square[r1 * 5 + c1] + square[r2 * 5 + c2]
    return out  # Decryption retains ambiguous filler X/Q; remove fillers manually if needed


def hill2(text, matrix, decrypt=False):
    a, b = matrix[0]; c, d = matrix[1]
    det = (a * d - b * c) % 26
    if gcd(det, 26) != 1:
        raise ValueError('Hill matrix determinant must be invertible modulo 26')
    if decrypt:
        inv = pow(det, -1, 26)
        matrix = [[d * inv % 26, -b * inv % 26], [-c * inv % 26, a * inv % 26]]
    s = ''.join(ch for ch in text.upper() if 'A' <= ch <= 'Z')
    if len(s) % 2:
        s += 'X' if not decrypt else ''
    if len(s) % 2:
        raise ValueError('Hill ciphertext length must be even')
    out = ''
    for x, y in zip(s[::2], s[1::2]):
        u, v = ord(x) - 65, ord(y) - 65
        out += chr((matrix[0][0] * u + matrix[0][1] * v) % 26 + 65)
        out += chr((matrix[1][0] * u + matrix[1][1] * v) % 26 + 65)
    return out


def rail_fence(text, rails, decrypt=False):
    if rails < 2 or rails >= len(text):
        return text
    zig = list(range(rails)) + list(range(rails - 2, 0, -1))
    positions = [zig[i % len(zig)] for i in range(len(text))]
    if not decrypt:
        return ''.join(text[i] for r in range(rails) for i, k in enumerate(positions) if k == r)
    out, j = [''] * len(text), 0
    for r in range(rails):
        for i, k in enumerate(positions):
            if k == r:
                out[i] = text[j]; j += 1
    return ''.join(out)


def columnar(text, key, decrypt=False):
    if not key:
        raise ValueError('Key cannot be blank')
    n = len(key)
    order = sorted(range(n), key=lambda i: (key[i], i))
    if not decrypt:
        return ''.join(text[i::n] for i in order)
    lens = [len(text[i::n]) for i in range(n)]
    cols, k = [''] * n, 0
    for i in order:
        cols[i] = text[k:k + lens[i]]; k += lens[i]
    return ''.join(cols[j][r] for r in range(max(lens)) for j in range(n) if r < len(cols[j]))
```


### 12.3 — AES/DES/3DES suite (Lab 2)

Filename: `symmetric.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 02: AES-128/192/256, DES, 3DES, CBC/ECB/CFB/OFB/CTR/GCM."""
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def symmetric_encrypt(data, algorithm='AES', mode='CBC', key=None, key_bits=192, padding=True):
    algorithm, mode = algorithm.upper(), mode.upper()
    cls = {'AES': AES, 'DES': DES, '3DES': DES3}[algorithm]
    if key is None:
        size = {'AES': key_bits // 8, 'DES': 8, '3DES': 24}[algorithm]
        key = get_random_bytes(size)
        if algorithm == '3DES':
            while True:
                try:
                    key = DES3.adjust_key_parity(key)
                    DES3.new(key, DES3.MODE_ECB)
                    break
                except ValueError:
                    key = get_random_bytes(size)
    if algorithm == 'AES' and len(key) not in (16, 24, 32):
        raise ValueError('AES key needs 16/24/32 bytes')
    if algorithm == 'DES' and len(key) != 8:
        raise ValueError('DES key needs 8 bytes')
    if algorithm == '3DES' and len(key) not in (16, 24):
        raise ValueError('3DES key needs 16/24 bytes')
    if mode == 'GCM':
        if algorithm != 'AES':
            raise ValueError('GCM here supports AES only')
        cipher = AES.new(key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(data)
        return {'algorithm': algorithm, 'mode': mode, 'ct': ct.hex(),
                'nonce': cipher.nonce.hex(), 'tag': tag.hex()}, key
    mode_id = getattr(cls, 'MODE_' + mode)
    if mode in ('CBC', 'CFB', 'OFB'):
        cipher = cls.new(key, mode_id, iv=get_random_bytes(cls.block_size),
                         **({'segment_size': cls.block_size * 8} if mode == 'CFB' else {}))
        extras = {'iv': cipher.iv.hex()}
    elif mode == 'CTR':
        cipher = cls.new(key, mode_id)
        extras = {'nonce': cipher.nonce.hex()}
    elif mode == 'ECB':
        cipher, extras = cls.new(key, mode_id), {}
    else:
        raise ValueError('Unsupported cipher mode')
    padded = mode in ('CBC', 'ECB') and padding
    if mode in ('CBC', 'ECB') and not padded and len(data) % cls.block_size:
        raise ValueError('Without padding, data length must be a block multiple')
    ct = cipher.encrypt(pad(data, cls.block_size) if padded else data)
    return {'algorithm': algorithm, 'mode': mode, 'ct': ct.hex(),
            'padding': padded, **extras}, key


def symmetric_decrypt(record, key):
    algorithm, mode = record['algorithm'], record['mode']
    cls = {'AES': AES, 'DES': DES, '3DES': DES3}[algorithm]
    if mode == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(record['nonce']))
        return cipher.decrypt_and_verify(bytes.fromhex(record['ct']), bytes.fromhex(record['tag']))
    options = {}
    if 'iv' in record:
        options['iv'] = bytes.fromhex(record['iv'])
    if 'nonce' in record:
        options['nonce'] = bytes.fromhex(record['nonce'])
    if mode == 'CFB':
        options['segment_size'] = cls.block_size * 8
    cipher = cls.new(key, getattr(cls, 'MODE_' + mode), **options)
    raw = cipher.decrypt(bytes.fromhex(record['ct']))
    return unpad(raw, cls.block_size) if record.get('padding') else raw


def aes_cbc_with_supplied_iv(data, key, iv, padding=True):
    if len(iv) != 16:
        raise ValueError('CBC IV must be 16 bytes')
    if len(key) not in (16, 24, 32):
        raise ValueError('AES key must be 16/24/32 bytes')
    if not padding and len(data) % 16:
        raise ValueError('No-padding CBC needs 16-byte multiple')
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16) if padding else data)
    return {'algorithm': 'AES', 'mode': 'CBC', 'ct': ct.hex(),
            'iv': iv.hex(), 'padding': padding}
```


### 12.4 — RSA, ElGamal, Schnorr, Rabin, DH and ECC (Labs 3, 4, 6)

Filename: `public_key.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 03: RSA OAEP/signatures, ElGamal encryption/signatures, DH, ECC, Rabin."""
import hashlib
import math
import secrets
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Util.number import getPrime, isPrime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HASH = {'md5': MD5, 'sha1': SHA1, 'sha256': SHA256, 'sha512': SHA512}


def rsa_generate(bits=2048):
    private = RSA.generate(bits)
    return private.export_key().decode(), private.publickey().export_key().decode()


def rsa_encrypt(data, public_pem):
    return PKCS1_OAEP.new(RSA.import_key(public_pem), hashAlgo=SHA256).encrypt(data)


def rsa_decrypt(ciphertext, private_pem):
    return PKCS1_OAEP.new(RSA.import_key(private_pem), hashAlgo=SHA256).decrypt(ciphertext)


def rsa_sign(data, private_pem, hash_name='sha256', scheme='PKCS1'):
    h = HASH[hash_name.lower()]
    signer = pss if scheme.upper() == 'PSS' else pkcs1_15
    return signer.new(RSA.import_key(private_pem)).sign(h.new(data)).hex()


def rsa_verify(data, signature_hex, public_pem, hash_name='sha256', scheme='PKCS1'):
    try:
        h = HASH[hash_name.lower()]
        signer = pss if scheme.upper() == 'PSS' else pkcs1_15
        signer.new(RSA.import_key(public_pem)).verify(h.new(data), bytes.fromhex(signature_hex))
        return True
    except (ValueError, TypeError, KeyError):
        return False


def elgamal_keys(bits=256):
    """Small bit sizes for classroom speed only; safe-prime generator ensures primitive root."""
    if bits < 32:
        raise ValueError('At least 32 bits for demonstrations')
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            break
    x = secrets.randbelow(p - 3) + 2
    return {'p': p, 'g': g, 'y': pow(g, x, p)}, x


def elgamal_encrypt(m, pub):
    p, g, y = (pub[k] for k in ('p', 'g', 'y'))
    if not 0 <= m < p:
        raise ValueError('ElGamal integer requires 0 <= m < p')
    k = secrets.randbelow(p - 2) + 1
    return pow(g, k, p), m * pow(y, k, p) % p


def elgamal_decrypt(pair, private_x, pub):
    c1, c2 = pair
    p = pub['p']
    return c2 * pow(pow(c1, private_x, p), -1, p) % p


def elgamal_sign(data, private_x, pub, hash_name='sha512'):
    p, g = pub['p'], pub['g']
    h = int.from_bytes(hashlib.new(hash_name, data).digest(), 'big') % (p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    return r, (h - private_x * r) * pow(k, -1, p - 1) % (p - 1)


def elgamal_verify(data, signature, pub, hash_name='sha512'):
    try:
        p, g, y = (pub[k] for k in ('p', 'g', 'y'))
        r, s = signature
        if not (1 <= r < p and 0 <= s < p - 1):
            return False
        h = int.from_bytes(hashlib.new(hash_name, data).digest(), 'big') % (p - 1)
        return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p
    except (KeyError, ValueError, TypeError):
        return False


def dh_demo(p, g, a, b):
    """Use trusted supplied DH p/g; returns public values and both shared secrets."""
    A, B = pow(g, a, p), pow(g, b, p)
    return A, B, pow(B, a, p), pow(A, b, p)


def ecc_generate(curve=ec.SECP256R1()):
    private = ec.generate_private_key(curve)
    pri = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    pub = private.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return pri, pub


def ecc_sign(data, private_pem):
    private = serialization.load_pem_private_key(private_pem, password=None)
    return private.sign(data, ec.ECDSA(hashes.SHA256()))


def ecc_verify(data, sig, public_pem):
    from cryptography.exceptions import InvalidSignature
    try:
        key = serialization.load_pem_public_key(public_pem)
        key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def ecc_ecdh(own_private_pem, other_public_pem):
    own = serialization.load_pem_private_key(own_private_pem, password=None)
    other = serialization.load_pem_public_key(other_public_pem)
    return own.exchange(ec.ECDH(), other)  # Feed shared bytes to HKDF before using as AES key


def rabin_demo(m, bits=256):
    """Textbook Rabin; output is FOUR candidate roots, not unambiguous decryption."""
    p = getPrime(bits)
    while p % 4 != 3:
        p = getPrime(bits)
    q = getPrime(bits)
    while q == p or q % 4 != 3:
        q = getPrime(bits)
    n = p * q
    if not 0 <= m < n:
        raise ValueError('Message integer must be < n')
    ct = pow(m, 2, n)
    rp, rq = pow(ct, (p + 1) // 4, p), pow(ct, (q + 1) // 4, q)
    roots = sorted({(a * q * pow(q, -1, p) + b * p * pow(p, -1, q)) % n
                    for a in (rp, -rp % p) for b in (rq, -rq % q)})
    return {'n': n, 'ciphertext': ct, 'candidate_plaintexts': roots}


def schnorr_keys(bits=256):
    """Textbook Schnorr in prime-order subgroup; classroom only, not protocol hardened."""
    eg, x = elgamal_keys(bits)
    p, q = eg['p'], (eg['p'] - 1) // 2
    g = pow(eg['g'], 2, p)  # order q
    x = (x % (q - 1)) + 1
    return {'p': p, 'q': q, 'g': g, 'y': pow(g, x, p)}, x


def schnorr_sign(data, x, pub):
    p, q, g = (pub[k] for k in ('p', 'q', 'g'))
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p)
    challenge = int.from_bytes(hashlib.sha256(data + r.to_bytes((p.bit_length() + 7)//8, 'big')).digest(), 'big') % q
    return r, (k + challenge * x) % q


def schnorr_verify(data, sig, pub):
    try:
        p, q, g, y = (pub[k] for k in ('p', 'q', 'g', 'y'))
        r, s = sig
        if not (1 <= r < p and 0 <= s < q): return False
        challenge = int.from_bytes(hashlib.sha256(data + r.to_bytes((p.bit_length() + 7)//8, 'big')).digest(), 'big') % q
        return pow(g, s, p) == r * pow(y, challenge, p) % p
    except (ValueError, TypeError, KeyError):
        return False
```


### 12.5 — Partial homomorphic cryptography (Lab 7)

Filename: `homomorphic.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 04: real Paillier additive HE; multiplicative textbook RSA/ElGamal."""
from math import gcd
from phe import paillier


def paillier_keys(bits=2048):
    pub, pri = paillier.generate_paillier_keypair(n_length=bits)
    return {'n': str(pub.n), 'p': str(pri.p), 'q': str(pri.q)}  # SECRET: p and q


def paillier_restore(keys):
    pub = paillier.PaillierPublicKey(int(keys['n']))
    pri = paillier.PaillierPrivateKey(pub, int(keys['p']), int(keys['q']))
    return pub, pri


def phe_encrypt_integer(public, integer):
    enc = public.encrypt(int(integer))
    return {'c': str(enc.ciphertext()), 'exponent': enc.exponent}


def phe_restore(public, obj):
    c = int(obj['c'])
    if not 1 <= c < public.n ** 2 or gcd(c, public.n) != 1:
        raise ValueError('Invalid Paillier ciphertext')
    return paillier.EncryptedNumber(public, c, int(obj['exponent']))


def phe_sum(public, ciphertext_records):
    """Only ciphertext additions; caller decides when final decrypted result is allowed."""
    if not ciphertext_records:
        raise ValueError('Select at least one record')
    total = phe_restore(public, ciphertext_records[0])
    for obj in ciphertext_records[1:]:
        total += phe_restore(public, obj)
    return total


def phe_weighted_total(public, records, weights):
    if len(records) != len(weights) or not records:
        raise ValueError('Weights and records must match')
    result = phe_restore(public, records[0]) * int(weights[0])
    for item, weight in zip(records[1:], weights[1:]):
        result += phe_restore(public, item) * int(weight)
    return result


def phe_decrypt_final(private, encrypted_total):
    return private.decrypt(encrypted_total)  # Never call for individual votes/amounts in restricted scenarios


def encrypt_candidate_ballot(public, candidate, candidates):
    """One-hot encrypted vote; summing encrypted candidate IDs does NOT count votes."""
    if candidate not in candidates:
        raise ValueError('Unknown candidate')
    return {str(cid): phe_encrypt_integer(public, int(cid == candidate)) for cid in candidates}


def tally_candidate_ballots(public, ballots, candidates):
    if not ballots:
        raise ValueError('No ballots selected')
    return {str(cid): phe_sum(public, [b[str(cid)] for b in ballots]) for cid in candidates}


def textbook_rsa_multiply(c1, c2, n):
    """Textbook RSA only: multiplication property does NOT hold for RSA-OAEP."""
    return c1 * c2 % n


def elgamal_multiply(pair1, pair2, p):
    return (pair1[0] * pair2[0] % p, pair1[1] * pair2[1] % p)
```


### 12.6 — Searchable encrypted document index (Lab 8)

Filename: `search_index.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 05: AES-GCM encrypted documents + HMAC-token SSE index."""
import hashlib
import hmac
import secrets
from Crypto.Cipher import AES


def token(secret, field, value):
    normalized = value.strip().casefold()
    return hmac.new(secret, (field + '\0' + normalized).encode(), hashlib.sha256).hexdigest()


def sse_add(store, secret, aes_key, doc_id, content, keywords):
    """store = {'documents':{}, 'index':{}}; persist store and BOTH keys separately."""
    doc_key = token(secret, 'id', doc_id)
    if not doc_id.strip() or doc_key in store['documents']:
        raise ValueError('Blank/duplicate document ID')
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(content)
    store['documents'][doc_key] = {'ct': ct.hex(), 'nonce': cipher.nonce.hex(), 'tag': tag.hex()}
    for word in set(k.strip().casefold() for k in keywords if k.strip()):
        t = token(secret, 'keyword', word)
        store['index'].setdefault(t, []).append(doc_key)
    return doc_key


def sse_delete(store, secret, doc_id):
    doc_key = token(secret, 'id', doc_id)
    if doc_key not in store['documents']:
        raise KeyError('Document not found')
    del store['documents'][doc_key]
    for posting in store['index'].values():
        if doc_key in posting:
            posting.remove(doc_key)


def sse_find(store, secret, keywords, operation='AND'):
    groups = [set(store['index'].get(token(secret, 'keyword', word), [])) for word in keywords]
    if not groups:
        return []
    if operation.upper() == 'AND':
        return sorted(set.intersection(*groups))
    if operation.upper() == 'OR':
        return sorted(set.union(*groups))
    raise ValueError('Use AND or OR')


def sse_read(store, doc_key, aes_key):
    row = store['documents'][doc_key]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(row['nonce']))
    return cipher.decrypt_and_verify(bytes.fromhex(row['ct']), bytes.fromhex(row['tag']))


def make_sse_keys():
    return secrets.token_bytes(32), secrets.token_bytes(32)  # HMAC key, AES key
```


### 12.7 — Number theory, AES GF and access policies

Filename: `07_math_and_access.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 07: number theory, AES GF arithmetic, cryptanalysis, MAC/DAC/ABAC."""
import collections
import math
from sympy import mod_inverse


def number_theory(a, b, modulus):
    return {'gcd': math.gcd(a, b), 'a_mod_n': a % modulus,
            'a_power_b_mod_n': pow(a, b, modulus),
            'inverse_a_mod_n': int(mod_inverse(a, modulus)) if math.gcd(a, modulus) == 1 else None}


def gf256_mul(a, b):
    """AES GF(2^8) multiplication modulo x^8+x^4+x^3+x+1 (0x11b)."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = (a << 1) ^ (0x11B if a & 0x80 else 0)
        a &= 0xff
        b >>= 1
    return r


def aes_mix_column(column, inverse=False):
    if len(column) != 4 or any(not 0 <= x < 256 for x in column):
        raise ValueError('Column requires exactly four bytes')
    rows = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14)) if inverse else (
        (2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    return [gf256_mul(row[0], column[0]) ^ gf256_mul(row[1], column[1]) ^
            gf256_mul(row[2], column[2]) ^ gf256_mul(row[3], column[3]) for row in rows]


def byte_xor(a, b):
    if len(a) != len(b):
        raise ValueError('XOR needs equal-length inputs')
    return bytes(x ^ y for x, y in zip(a, b))


def frequency(text):
    letters = [c.upper() for c in text if c.isascii() and c.isalpha()]
    return collections.Counter(letters).most_common()


def mac_allowed(subject_level, object_level, action):
    """Simplified Bell-LaPadula confidentiality model: no read up, no write down."""
    if action == 'read': return subject_level >= object_level
    if action == 'write': return subject_level <= object_level
    return False


def dac_allowed(permissions, user, resource, action):
    return action in permissions.get(resource, {}).get(user, [])


def abac_allowed(attributes, rule):
    """Rule is a dict of required attribute/value pairs; educational exact-match ABAC."""
    return all(attributes.get(k) == v for k, v in rule.items())
```


### 12.8 — Socket and HMAC helpers

Filename: `08_network.py`. You may copy this whole block into a `.py` file.

```python
"""COPY BLOCK 08: simple framed socket transfer (separate optional HMAC; no transport security), localhost by default."""
import hashlib
import hmac
import json
import socket


def send_record(host, port, record):
    data = json.dumps(record, sort_keys=True).encode()
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(len(data).to_bytes(4, 'big') + data)


def receive_record(host, port, max_bytes=1_000_000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        conn, _ = server.accept()
        with conn:
            conn.settimeout(10)
            def read_exact(count):
                out = bytearray()
                while len(out) < count:
                    chunk = conn.recv(count - len(out))
                    if not chunk:
                        raise ConnectionError('Incomplete frame')
                    out.extend(chunk)
                return bytes(out)
            length = int.from_bytes(read_exact(4), 'big')
            if not 0 < length <= max_bytes:
                raise ValueError('Invalid frame length')
            return json.loads(read_exact(length))


def hmac_sign(data, secret, algo='sha256'):
    return hmac.new(secret, data, getattr(hashlib, algo)).hexdigest()


def hmac_verify(data, secret, expected_hex, algo='sha256'):
    return hmac.compare_digest(hmac_sign(data, secret, algo), expected_hex)
```


### 12.9 — Complete menu-driven, persistent scenario starter

Filename: `EXAM_STARTER.py`. You may copy this whole block into a `.py` file.

```python
"""MENU-DRIVEN EXAM STARTER: AES + hash + RSA signature + Paillier + persistent records.
Classroom only: local role passwords, keys on disk; not a production security system.
Change scenario fields/menu labels, but preserve canonical signed payload and verification.
"""
from decimal import Decimal
from pathlib import Path
from common import (canonical, digest, ask_int, amount_to_int, utc_now,
                    make_role_passwords, role_login, load_json, save_json, flip_hex, hex_dump)
from symmetric import symmetric_encrypt, symmetric_decrypt
from public_key import rsa_generate, rsa_sign, rsa_verify
from homomorphic import paillier_keys, paillier_restore, phe_encrypt_integer, phe_sum, phe_decrypt_final
from Crypto.Random import get_random_bytes


def setup():
    key_text = input('Private key/config file path: ').strip()
    db_text = input('Record database path: ').strip()
    if not key_text or not db_text:
        raise ValueError('File paths cannot be blank')
    key_path, db_path = Path(key_text).expanduser(), Path(db_text).expanduser()
    if key_path.resolve() == db_path.resolve():
        raise ValueError('Use distinct key/database paths')
    if key_path.exists() != db_path.exists():
        raise ValueError('Key and database files must be restored together')
    if key_path.exists():
        conf, rows = load_json(key_path, {}), load_json(db_path, {})
    else:
        bits = ask_int('AES key length (128/192/256): ')
        if bits not in (128, 192, 256):
            raise ValueError('AES key length must be 128/192/256')
        mode = input('AES mode (CBC/GCM): ').strip().upper()
        if mode not in ('CBC', 'GCM'):
            raise ValueError('Choose CBC/GCM')
        alg = input('Hash algorithm (md5/sha1/sha256/sha512): ').strip().lower()
        if alg not in ('md5', 'sha1', 'sha256', 'sha512'):
            raise ValueError('Unsupported hash')
        places = ask_int('Decimal places for amount (0 or more): ', 0, 9)
        max_amt = ask_int('Maximum scaled integer amount per entry: ', 1)
        rbits = ask_int('RSA bits (>=2048): ', 2048)
        pbits = ask_int('Paillier bits (>=1024): ', 1024)
        roles = [input(f'Role {i} name: ').strip() for i in range(1, 4)]
        if any(not r for r in roles) or len(set(roles)) != 3:
            raise ValueError('Provide three unique role names')
        rsa_private, rsa_public = rsa_generate(rbits)
        conf = {'aes': get_random_bytes(bits // 8).hex(), 'rsa_priv': rsa_private,
                'rsa_pub': rsa_public, 'paillier': paillier_keys(pbits),
                'mode': mode, 'hash': alg, 'places': places, 'max_amt': max_amt,
                'roles': roles, 'passwords': make_role_passwords(roles)}
        rows = {}
        save_json(key_path, conf, private=True)
        save_json(db_path, rows)
    if not isinstance(rows, dict):
        raise ValueError('Invalid record database format')
    return conf, rows, db_path


def signed_payload(row):
    return {k: row[k] for k in ('id', 'encrypted_description', 'encrypted_amount', 'timestamp')}


def valid(row, conf):
    try:
        raw = canonical(signed_payload(row))
        return (digest(raw, conf['hash']) == row['digest'] and
                rsa_verify(raw, row['signature'], conf['rsa_pub'], conf['hash']))
    except (ValueError, TypeError, KeyError):
        return False


def submit(conf, rows, db_path):
    rid = input('Record ID: ').strip()
    if not rid or rid in rows:
        raise ValueError('Blank/duplicate record ID')
    description = input('Description: ').encode()
    amount = amount_to_int('Amount', conf['places'])
    if not 0 <= amount <= conf['max_amt']:
        raise ValueError('Amount outside configured range')
    encrypted, _ = symmetric_encrypt(description, 'AES', conf['mode'],
                                     bytes.fromhex(conf['aes']))
    pub, _ = paillier_restore(conf['paillier'])
    row = {'id': rid, 'encrypted_description': encrypted,
           'encrypted_amount': phe_encrypt_integer(pub, amount), 'timestamp': utc_now()}
    raw = canonical(signed_payload(row))
    row['digest'] = digest(raw, conf['hash'])
    row['signature'] = rsa_sign(raw, conf['rsa_priv'], conf['hash'])
    rows[rid] = row
    save_json(db_path, rows)
    print('Saved ID:', rid, '| Hash:', row['digest'], '| Signed:', True)


def reviewer(conf, rows):
    while True:
        print('\n1 Search ID  2 Verify all  3 Decrypted description hex  4 Tamper test  0 Back')
        action = input('Choice: ').strip()
        if action == '0': return
        if action == '1':
            rid = input('Record ID: ').strip()
            print('Indexed result:', rid if rid in rows else 'NOT FOUND', '| no contents disclosed')
        elif action == '2':
            for rid, row in rows.items():
                print(rid, 'VALID' if valid(row, conf) else 'INVALID')
        elif action == '3':
            rid = input('Record ID: ').strip()
            row = rows.get(rid)
            if not row or not valid(row, conf):
                print('Record absent/tampered; refused'); continue
            pt = symmetric_decrypt(row['encrypted_description'], bytes.fromhex(conf['aes']))
            hex_dump(pt)
        elif action == '4':
            rid = input('Record ID: ').strip()
            if rid not in rows:
                print('Not found'); continue
            demo = dict(rows[rid])
            demo['encrypted_description'] = flip_hex(demo['encrypted_description'], 'ct')
            print('Verification after changing ONE encrypted byte:', valid(demo, conf))
            print('Stored original is unchanged')
        else: print('Unknown choice')


def finance(conf, rows):
    ids = [x.strip() for x in input('IDs to aggregate (comma-separated): ').split(',') if x.strip()]
    if len(ids) < 2 or len(ids) != len(set(ids)):
        raise ValueError('Select at least two distinct records')
    if any(rid not in rows for rid in ids):
        raise ValueError('Unknown record ID')
    if any(not valid(rows[rid], conf) for rid in ids):
        raise ValueError('Signature/hash verification failed; refusing aggregation')
    pub, pri = paillier_restore(conf['paillier'])
    if len(ids) * conf['max_amt'] > pub.max_int:
        raise ValueError('Total could exceed Paillier signed integer range')
    ct = phe_sum(pub, [rows[rid]['encrypted_amount'] for rid in ids])
    print('Verified entries:', len(ids))
    print('Combined encrypted result:', ct.ciphertext())
    print('FINAL amount (only aggregate decrypted):',
          format(Decimal(phe_decrypt_final(pri, ct)) / 10 ** conf['places'], 'f'))


def main():
    conf, rows, db_path = setup()
    while True:
        print('\n0 Exit' + ''.join(f'  {i} {role}' for i, role in enumerate(conf['roles'], 1)))
        choice = input('Role: ').strip()
        if choice == '0': return
        if choice not in ('1', '2', '3'):
            print('Unknown role'); continue
        role = conf['roles'][int(choice) - 1]
        if not role_login(conf['passwords'], role):
            print('Access denied'); continue
        try:
            if choice == '1':
                while True:
                    print('\n1 Submit  2 View stored encrypted records  0 Back')
                    op = input('Choice: ').strip()
                    if op == '0': break
                    if op == '1': submit(conf, rows, db_path)
                    elif op == '2':
                        for rid, row in rows.items():
                            print(rid, 'ciphertext:', row['encrypted_description']['ct'],
                                  '| hash:', row['digest'], '| signature:', row['signature'])
                    else: print('Unknown choice')
            elif choice == '2': reviewer(conf, rows)
            elif choice == '3': finance(conf, rows)
        except (ValueError, TypeError, KeyError, OverflowError, OSError) as exc:
            print('Error:', exc)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print('Setup error:', exc)
```


### 12.10 — Optional one-file exam assembler

Filename: `BUILD_EXAM.py`. You may copy this whole block into a `.py` file.

```python
"""Optional: combine any library blocks into ONE import-free-from-local-files script.
Run in the same folder as this builder; generated script needs only installed packages.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODULES = {
    'common': 'common.py', 'symmetric': 'symmetric.py',
    'public_key': 'public_key.py', 'homomorphic': 'homomorphic.py',
    'search': 'search_index.py', 'classical': 'classical.py',
    'math': '07_math_and_access.py', 'network': '08_network.py',
}


def flatten(source):
    """Drop only local cross-file imports, retain all third-party and stdlib imports."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    spans = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in {'common', 'symmetric', 'public_key',
                                                                  'homomorphic', 'search_index', 'classical'}:
            spans.append((node.lineno, node.end_lineno))
    for a, b in reversed(spans):
        lines[a-1:b] = []
    return ''.join(lines)


def main():
    print('Available blocks:', ', '.join(MODULES))
    names = [x.strip().lower() for x in input('Choose blocks separated by commas (or ALL): ').split(',')]
    if 'all' in names:
        names = list(MODULES)
    unknown = set(names) - set(MODULES)
    if unknown or not names or any(not n for n in names):
        raise ValueError(f'Invalid modules: {unknown}')
    starter = input('Append working 3-role menu starter? (y/n): ').strip().lower() == 'y'
    if starter:
        names = list(dict.fromkeys(['common', 'symmetric', 'public_key', 'homomorphic'] + names))
    path_text = input('Output .py filename (must not already exist): ').strip()
    if not path_text or not path_text.endswith('.py'):
        raise ValueError('Enter a .py filename')
    path = Path(path_text).expanduser()
    if path.exists():
        raise FileExistsError('Refusing to overwrite existing exam code')
    pieces = ['# Generated from IS_Exam_Modular_Kit. Educational lab use only.\n']
    for name in dict.fromkeys(names):
        pieces.append('\n# ===== BLOCK: ' + name + ' =====\n' + flatten((ROOT / MODULES[name]).read_text()))
    if starter:
        pieces.append('\n# ===== MENU-DRIVEN STARTER =====\n' + flatten((ROOT / 'EXAM_STARTER.py').read_text()))
    result = '\n\n'.join(pieces)
    compile(result, str(path), 'exec')
    path.write_text(result)
    print('Created runnable single-file source:', path.resolve())
    print('Edit its role-specific menus and requirements before submission.')


if __name__ == '__main__':
    main()
```

