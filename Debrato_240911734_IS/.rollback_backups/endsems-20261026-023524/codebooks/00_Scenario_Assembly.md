# Scenario assembly — turning an unseen question into a working program

For a shared menu/socket starting point, use [PLUGPLAY.md](../PLUGPLAY.md).
Edit `templates/plugplay/config.py` once. The standalone menu and the two socket
entry scripts use the same `RecordApp` operations. The older templates below
remain checked examples for direct adaptation and existing saved data.

Read this first in the exam. The labs give the parts; end-sem questions combine them
(the manual: questions "may involve some variations and/or combinations").

## 1. Five-minute decode (write it as comments at the top of your answer)

```text
ROLES + what each may do      : e.g. Researcher submit/view | Reviewer verify/search/hexdump | Finance aggregate
FIELDS (type, secret?)        : Grant ID (plain, unique) | description (text, AES-192) | amount (number, Paillier)
CONFIDENTIALITY               : cipher + key size + mode (+ who holds the key / RSA key wrapping?)
INTEGRITY                     : hash algorithm + EXACTLY which bytes are hashed
AUTHENTICITY / NON-REPUDIATION: signature scheme + whose private key signs, who verifies
HOMOMORPHIC                   : sum / weighted / average / per-candidate counts; who decrypts (threshold?)
SEARCH                        : by ID / keyword / field / time range  -> HMAC tokens
TIME                          : timestamps, deadline/window checks, trusted authority?
STORAGE                       : file/DB, must survive restart (keys too!)
FAILURES TO HANDLE            : wrong password, unknown/duplicate ID, bad number, tampered record, late vote
ARCHITECTURE                  : one menu program | TCP client+server | HTTP API
```

## 2. Choose the architecture

| Wording | Build |
|---|---|
| "menu-driven program", roles, "client side / server side" without networking words | ONE program, role menus (`solutions/*.py`, `templates/secure_records_menu.py`) |
| "socket", "client and server scripts", "transmit over network", "TCP" | two programs: `templates/net_server.py` + `templates/net_client.py` (choose `tcp`) |
| "API", "REST", "endpoint", "HTTP", "web service" | same templates, choose `http` (`POST /api/<op>`, `GET /records/<id>`) |

To move a role across the network: keep its functions, but replace direct dict access with
`call({'op': ..., ...})` on the client and add a branch in `handle()` on the server.

## 3. Starting points (copy into `endsems/` root so `toolkit` imports work)

| Starting file | When |
|---|---|
| `templates/secure_records_menu.py` | any "roles + encrypted records + hash + sign + (Paillier) + search" question — edit the CONFIG block |
| `solutions/grant_portal.py` | AES + Paillier + hash + RSA, reviewer/finance style; very close variants |
| `solutions/evoting.py` | ballots/voting, hybrid RSA-wrapped AES, ElGamal signatures, timestamps, index, threshold |
| `templates/net_server.py` + `net_client.py` | real client/server (TCP or HTTP) |
| codebooks Lab1–Lab8 | single-topic questions or extra pieces to paste in |

`python bundle.py my_answer.py` → `my_answer_single.py` with every toolkit import inlined
(one self-contained file to submit). Run it once before submitting.

## 4. Order of operations (most marks are lost here)

```text
SUBMIT  : input -> validate -> encrypt fields (AES; Paillier for numbers; RSA-wrap AES key if asked)
          -> build record dict {id, ciphertexts, iv/nonce, timestamp, ...}
          -> hash canonical(record)  -> sign (hash or record) with SUBMITTER PRIVATE key
          -> store record + hash + signature (+ index tokens) -> save file
VERIFY  : load -> recompute hash of the same canonical bytes -> compare with stored hash
          -> verify signature with SUBMITTER PUBLIC key -> report VALID / TAMPERED (+ reason)
DECRYPT : only after VERIFY passes, only in roles that hold the key
AGGREGATE: verify each selected record -> skip/stop on tampered -> multiply Paillier ciphertexts
          -> decrypt ONLY the aggregate (never single values) -> print encrypted + plain result
```

**Which bytes to hash?** If the question says "hash of the record/ballot", choose and *state* one:
* hash the **stored (encrypted) record** → anyone can verify integrity without keys (used in both solutions);
* hash the **plaintext** (e.g. "SHA-512 of the ballot file") → verifier must decrypt first, then compare.
  The e-voting solution does both: ballot-file SHA-512 (as asked) + a signature over the whole envelope.
Always hash `canonical(dict)` (sorted-key JSON), never `str(dict)`.

## 5. Requirement phrase → exact call

| Phrase | Call (toolkit) |
|---|---|
| AES-128/192/256 CBC | `aes_cbc_encrypt(key16/24/32, data)` → `(iv, ct)`; `aes_cbc_decrypt(key, iv, ct)` |
| AES any mode / DES / 3DES | `sym_encrypt(alg, mode, key, data)` → dict; `sym_decrypt(key, box)` |
| authenticated encryption | `aes_gcm_encrypt(key, data)` / `aes_gcm_decrypt(...)` (raises on tamper) |
| "encrypt the AES key with RSA public key" | `hybrid_encrypt(pub, data, 256, 'CBC')` / `hybrid_decrypt(priv, box)` or `rsa_encrypt(pub, key)` |
| RSA-OAEP encrypt small data | `rsa_encrypt(pub, data)` / `rsa_decrypt(priv, ct)` |
| MD5/SHA-1/SHA-256/SHA-512 | `digest(data, 'md5')` (hex) |
| sign the hash with RSA | `rsa_sign(priv, data, 'md5')` / `rsa_verify(pub, data, sig, 'md5')` |
| ElGamal signature | `elgamal_sig_keygen()`; `elgamal_sign(data, x, alg='sha512')`; `elgamal_verify(data, sig, pub, 'sha512')`; `*_hash` versions take an int hash |
| Schnorr / DSA / ECDSA | `schnorr_sign/verify`; `dss_sign/verify(ecdsa_generate())` |
| Paillier encrypt/add/decrypt total | `paillier_keygen`; `paillier_encrypt(pub, m)`; `paillier_add(pub, *cts)`; `paillier_decrypt(priv, c)` |
| weighted sum / average / difference | `paillier_weighted_sum`, decrypt(sum)/count, `paillier_sub` |
| votes per candidate | `encrypt_one_hot(pub, choice, cands)`; `tally(pub, ballots, cands)` |
| threshold decryption | `paillier_threshold_keygen(bits, t, N)`; `partial_decrypt`; `combine_partials` |
| search by ID/keyword without revealing | `token(key, value, field)` as dict key / `field_index_*`; documents: `sse_*` |
| search by time range | index `hour` buckets + `hour_buckets(start, end)` + exact filter |
| trusted timestamp | `TimestampAuthority(rsa_key).stamp(hash_hex)`; `verify_timestamp(token, pub, hash, start, end)` |
| hex dump | `hexdump(bytes)` |
| role passwords / key per role | `password_seal(pw, canonical(keys))` / `password_open(pw, box)` |
| persistent storage | `load_json(path, default)` / `save_json(path, obj)` (atomic) |
| robust menus | `menu(title, [(label, fn), ...])` — prints errors instead of crashing |
| input validation | `ask`, `ask_int(lo, hi)`, `ask_amount(places)`, `ask_choice`, `ask_list`, `ask_time`, `parse_bytes(text, sizes)` |
| key management lifecycle | `KeyManager(path, passphrase)`: generate / get_public / get_private / revoke / renew / renew_due |
| tamper demo | `tamper_hex(hex_str)` on a stored field, then re-verify |

## 6. Key custody per role (cryptographic RBAC)

Give each role only the keys its actions need, sealed under that role's password:

<!-- stdin: dr-pass | nurse-pass | wrong -->
```python
import json
from Crypto.Random import get_random_bytes
from toolkit.asymmetric import rsa_generate
from toolkit.symmetric import password_seal, password_open
from toolkit.util import ask_secret, canonical

aes, rsa = get_random_bytes(32), rsa_generate(2048)
needs = {'Doctor': {'aes': aes.hex(), 'sign': rsa.export_key().decode()},   # encrypt + sign
         'Nurse': {}}                                                       # verify only (public key)
vaults = {role: password_seal(ask_secret(f'Set {role} password: '), canonical(k)) for role, k in needs.items()}
public = {'rsa_pub': rsa.publickey().export_key().decode()}                 # everyone may read
try:
    keys = json.loads(password_open(ask_secret('Doctor password: '), vaults['Doctor']))
except ValueError:
    print('ACCESS DENIED - the Doctor keys stay encrypted')
```

## 7. A complete program assembled from scratch (pattern for any new scenario)

Hospital teaching skeleton: add records with AES-256-GCM, SHA-256 and RSA-PSS,
verify and display plaintext, inspect metadata, and test tampering. JSON stores the data
and plaintext keys locally. The role words below are menu labels. This skeleton has no
login or role enforcement. The verify action also decrypts, so it must not serve a Nurse
who is forbidden to see plaintext. Use `templates/secure_records_menu.py` with separate
role vaults for that requirement. This short example demonstrates operation order only.

<!-- stdin: 1 | P1 | Flu, rest 3 days | 1 | P2 | Fracture, cast | 1 | P1 | 2 | 3 | 4 | P1 | 2 | 0 -->
```python
import os
from Crypto.Random import get_random_bytes
from toolkit.util import ask, menu, load_json, save_json, canonical, now_iso, tamper_hex
from toolkit.symmetric import aes_gcm_encrypt, aes_gcm_decrypt
from toolkit.asymmetric import rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import rsa_sign, rsa_verify

KEYS, DB = 'hospital_keys.json', 'hospital_db.json'
if not os.path.exists(KEYS):                         # first run only: keys persist
    k = rsa_generate(2048)
    save_json(KEYS, {'aes': get_random_bytes(32).hex(), 'priv': k.export_key().decode(),
                     'pub': k.publickey().export_key().decode()})
keys, db = load_json(KEYS, None), load_json(DB, {})
SIGNED = ('id', 'nonce', 'ct', 'tag', 'time')

def add():
    pid = ask('Patient ID: ')
    if pid in db: raise ValueError('duplicate ID')
    nonce, ct, tag = aes_gcm_encrypt(bytes.fromhex(keys['aes']), ask('Diagnosis: ').encode())
    rec = {'id': pid, 'nonce': nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex(), 'time': now_iso()}
    rec['sha256'] = digest(canonical(rec), 'sha256')
    rec['sig'] = rsa_sign(rsa_import(keys['priv']), canonical({k: rec[k] for k in SIGNED}), 'sha256', 'pss')
    db[pid] = rec; save_json(DB, db); print('stored', pid, rec['sha256'])

def check(rec):
    body = canonical({k: rec[k] for k in SIGNED})
    return digest(body, 'sha256') == rec['sha256'] and \
        rsa_verify(rsa_import(keys['pub']), body, rec['sig'], 'sha256', 'pss')

def verify_all():
    for pid, rec in db.items():
        ok = check(rec)
        plain = aes_gcm_decrypt(bytes.fromhex(keys['aes']), *(bytes.fromhex(rec[k]) for k in ('nonce', 'ct', 'tag'))) if ok else b'-'
        print(pid, 'VALID' if ok else 'TAMPERED', plain.decode())

def audit():
    for pid, rec in db.items(): print(pid, rec['time'], rec['sha256'])

def tamper():
    pid = ask('Patient ID to tamper: ')
    db[pid]['ct'] = tamper_hex(db[pid]['ct'])      # flip one stored ciphertext bit
    save_json(DB, db); print('record', pid, 'modified on disk')

menu('HOSPITAL', [('Doctor: add record', add), ('Verify and decrypt (authorized reader only)', verify_all),
                  ('Auditor: IDs, hashes, timestamps', audit), ('Attacker: tamper record', tamper)])
```

## 8. Variation recipes for `templates/secure_records_menu.py` (edit CONFIG only)

| Scenario | CONFIG changes |
|---|---|
| Hospital: doctor/nurse/auditor, AES-256-GCM, SHA-256, RSA | `TEXT_FIELDS=['Diagnosis','Prescription']`, `NUMBER_FIELDS=[]`, `AES_BITS, AES_MODE = 256, 'GCM'`, `HASH='sha256'`, `ROLES={'Doctor':['submit','view'],'Nurse':['verify','search'],'Auditor':['list','verify']}` |
| Bank: teller/auditor/manager, ECDSA, Paillier balances, interest = weighted sum | `NUMBER_FIELDS=['Balance']`, `SIGN='ecdsa'`, `HASH='sha512'`, manager → `aggregate` (weighted) |
| Student marks: faculty/student-office/HOD averages, ElGamal signatures | `NUMBER_FIELDS=['Marks']`, `PLACES=0`, `SIGN='elgamal'`, `SEARCH_FIELDS=['Course']`, `PLAIN_FIELDS=['Course']` |
| Supply chain: department search | `PLAIN_FIELDS=['Department']`, `SEARCH_FIELDS=['Department']` |

Adding an action: write `def my_action(keys, db, sec): ...`, add it to `ACTIONS` and to
`NEEDS` (which keys it needs), then list it under the roles allowed to use it.

## 9. What must be said honestly (write as comments)
* Single-program demos keep all roles' data on one machine; separation is by password-sealed
  key vaults + menus, not by OS isolation.
* A local "timestamp authority" signs with its own RSA key — real deployments use RFC 3161 TSAs.
* The cooperative threshold arithmetic uses a trusted dealer and a composite-ring polynomial.
  Its privacy below the threshold is unproven. It has no proofs of correct partial decryption.
* MD5/SHA-1 are only used because the question asks; mention their collision weakness.
* SSE leaks search/access patterns. Textbook RSA and the small arithmetic demos are educational constructions.
