# LAB 8 — Searchable Encryption | Modular Endsem Codebook

**Source basis:** `IS Lab Manual [7-8](1).pdf`, **Lab 8, PDF pages 8–15** (eight Lab 8 pages). **Scope: Lab 8 only.** The manual's objectives, SSE exercise 1a–1d, PKSE exercise 2a–2d, and two additional questions are mapped below. Extra scenario-ready tools are separately identified as **extensions**.

**Exam goal:** extract the necessary components for any variant, assemble the shortest correct solution, and keep it **input-driven**. Document IDs, contents, queries, numbers of documents, file paths, AES key size, RSA/Paillier key sizes, users, ports, and Snort paths come from `input()` or command-line prompts. Constants imposed by algorithms (nonce length, hash name, etc.) are not hardcoded exam answers.

**Use:** Sections labelled **STANDALONE** can be copied into their own `.py` files. **REUSABLE** blocks go into an existing Python program. Every section identifies dependencies. For a complete persistent, role-based SSE application, run the companion `Lab_8_Endsem_Menu_Master.py`. Only import the modules needed for the question; copying every import is unnecessary.

## 0. Exact syllabus → program locator

| Manual task / likely modification | Sections |
|---|---|
| Create **at least 10** documents with multiple words | 4, 15 |
| AES encrypt/decrypt documents | 2, 3, 4 |
| Build `word → document IDs` inverted index | 4, 5 |
| Encrypt index, query, and returned IDs; search without bulk decryption | 4–7 |
| Search case-insensitive, ignore punctuation; find duplicates once | 1, 4–5 |
| AND / OR / NOT queries, phrase searches | 5, 6 |
| Add, edit, delete documents; index refresh | 7, 15 |
| Persistence across restart; key restoration; tamper checks | 8, 15 |
| PKSE exercise explicitly specifies **Paillier** | 10–11 |
| Manual *separate* PKSE example uses **RSA OAEP** | 12 |
| Document-ID lookup, encrypted fields and role scenarios | 9, 13, 15 |
| Prefix queries, statistics and performance trade-offs | 14, 16 |
| GnuPG encryption/signature/verification/transmission | 17–18 |
| Snort rules, capture, live/PCAP analysis and alerts | 19–20 |
| Errors, misuse, how to construct a combined exam answer | 21–24 |

## 1. Searchable encryption basics and two important manual errors

**Terms from the manual:**

- **SSE (Symmetric Searchable Encryption):** shared secret permits search; usually efficient, but keyword/search/access-pattern leakage is possible.
- **PKSE (Public-Key Searchable Encryption):** public-key-based encrypted search, normally more expensive; constructing true PKSE requires a purpose-built searchable-encryption protocol.
- **Inverted index:** `keyword → {matching document IDs}`.
- **Search token / trapdoor:** stable, keyed representation of the keyword used for lookup.
- **Posting list:** encrypted references to the matching documents.

**Critical mathematical corrections — do NOT copy the manual sample literally:**

1. The manual's **AES-CBC sample** encrypts the same lookup word with a fresh random IV. A second encryption yields a different ciphertext, so dictionary equality lookup fails. It also drops the IV from the encrypted index, preventing correct decryption.
2. The manual's **RSA-OAEP sample** likewise compares randomized ciphertexts, so it cannot search by encrypting the query and comparing ciphertext bytes.
3. **Paillier encryption is randomized** and accepts *integer messages*, not arbitrary plaintext words. The manual's PKSE exercise (Paillier) cannot be implemented as direct equality of `E(keyword) == E(query)`.

**Correct exam adaptation in this codebook:** create a deterministic **HMAC-SHA256 token** for each normalized word *with a secret token key*. Keep document contents encrypted with **AES-GCM**, and encrypt document identifiers in each posting using AES-GCM (SSE) or Paillier (hybrid demonstration). The query generator holds the token key; the untrusted index only sees opaque tokens and ciphertexts. This is a **practical educational encrypted-index design**, **not a formally proven SSE/PKSE scheme**. In the Paillier example, Paillier protects document IDs but the keyword lookup is symmetric; call it **Paillier-assisted hybrid search**, *not genuine Paillier-only PKSE*.

**What remains visible to a search server:** number of records, approximate ciphertext lengths, frequency of token matches, repeated query tokens, and access patterns. It is incorrect to claim zero information leakage.

## 2. Dependencies and universal core — REUSABLE

Your Debian/PyCharm `.venv` install already includes `cryptography`, `pycryptodome`, `phe`, and `sympy`.

```python
import json, os, re, hmac, hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# AES encryption with integrity: stores nonce and encrypted bytes (including GCM tag)
def enc(key, data):
    nonce = os.urandom(12)
    return {'nonce': nonce.hex(), 'ct': AESGCM(key).encrypt(nonce, data, None).hex()}

def dec(key, record):
    return AESGCM(key).decrypt(bytes.fromhex(record['nonce']), bytes.fromhex(record['ct']), None)

def words(text):
    return set(re.findall(r'\w+', text.casefold()))

def token(secret, word):
    return hmac.new(secret, word.encode(), hashlib.sha256).hexdigest()
```

**Adaptation:** AES key lengths are 16/24/32 bytes; generate one with `os.urandom(int(input('AES bits: '))//8)` **after validating the choice is 128/192/256**. Token key must be independent: `token_key = os.urandom(32)`. Keep keys across restarts. A fresh random nonce per encryption is essential. `InvalidTag` means a wrong key or tampering; do not display decrypted data.

### Minimal usage — STANDALONE

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
bits = int(input('AES key size (128/192/256): '))
if bits not in (128, 192, 256): raise ValueError('Invalid AES size')
key, text = os.urandom(bits//8), input('Document: ').encode()
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, text, None)
print('Encrypted (hex):', ct.hex())
print('Decrypted:', AESGCM(key).decrypt(nonce, ct, None).decode())
```

## 3. AES-CBC version matching the manual — STANDALONE

Use CBC only if the question explicitly requires it. Save **both IV and ciphertext**; CBC alone does not authenticate data. Add HMAC/signature if integrity is required.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

bits = int(input('AES key size (128/192/256): '))
if bits not in (128, 192, 256): raise ValueError('Invalid AES size')
key = get_random_bytes(bits // 8)
message = input('Data: ').encode()
c = AES.new(key, AES.MODE_CBC)
ct = c.encrypt(pad(message, AES.block_size))
print('IV:', c.iv.hex(), '| Ciphertext:', ct.hex())
pt = unpad(AES.new(key, AES.MODE_CBC, iv=c.iv).decrypt(ct), AES.block_size)
print('Recovered:', pt.decode())
```

**Reusable integrity for CBC (recommended when using CBC):**

```python
import hmac, hashlib
# Assume iv, ct and a SEPARATE secret mac_key exist (do not reuse AES key).
tag = hmac.new(mac_key, iv+ct, hashlib.sha256).digest()
# Receiver: verify BEFORE CBC decryption.
if not hmac.compare_digest(tag, hmac.new(mac_key, iv+ct, hashlib.sha256).digest()):
    raise ValueError('Integrity failure')
```

For a stored record, save `iv.hex()`, `ct.hex()` and `tag.hex()`, then reconstruct bytes with `bytes.fromhex` before verification. The example above demonstrates the operation, not a standalone record file.

## 4. **Core manual SSE lab:** N encrypted documents, inverted index, query, decrypt IDs + documents — STANDALONE

**Exactly matches exercise 1a–1d in behavior.** No predefined document contents; user enters count, document IDs, text, and queries. No document plaintext is kept in the database; HMAC token names are stored instead of raw keywords.

```python
import os, re, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def box(k, msg):
    n = os.urandom(12)
    return (n.hex(), AESGCM(k).encrypt(n, msg.encode(), None).hex())

def open_box(k, b):
    return AESGCM(k).decrypt(bytes.fromhex(b[0]), bytes.fromhex(b[1]), None).decode()

def tok(k, word):
    return hmac.new(k, word.encode(), hashlib.sha256).hexdigest()

bits = int(input('AES bits (128/192/256): '))
if bits not in (128, 192, 256): raise ValueError('Invalid AES bits')
aes, search_key = os.urandom(bits//8), os.urandom(32)
count = int(input('Number of documents (manual requires >=10): '))
if count < 10: raise ValueError('Enter at least 10 documents for exercise 1')
records, index = {}, {}
for _ in range(count):
    doc_id, text = input('Document ID: ').strip(), input('Document text: ')
    if not doc_id or doc_id in records: raise ValueError('Empty/duplicate document ID')
    records[doc_id] = box(aes, text)
    for word in set(re.findall(r'\w+', text.casefold())):
        index.setdefault(tok(search_key, word), []).append(box(aes, doc_id))
print('Encrypted document count:', len(records))
print('Encrypted-index keywords:', len(index))
while True:
    query = input('Keyword (blank = exit): ').casefold().strip()
    if not query: break
    matching = index.get(tok(search_key, query), [])
    ids = [open_box(aes, x) for x in matching]
    print('Matching encrypted-index IDs:', ids)
    for doc_id in ids:
        print(doc_id, '=>', open_box(aes, records[doc_id]))
```

**Manual check:** `document` should return all documents that contain it; `common` should return only matching records. HMAC gives equal tokens for equal normalized keywords, even though AES-GCM ciphertext differs on every encryption. For this snippet, enter **one word per query**; use §5 for multiword support.

## 5. Core inverted-index building/search functions — REUSABLE

Paste after the §2 core definitions (`enc`, `dec`, `words`, `token`). The encrypted posting list keeps document IDs encrypted until an authorized client receives results.

```python
def make_index(docs, aes_key, token_key):
    out = {}
    for doc_id, item in docs.items():
        text = dec(aes_key, item).decode()
        for word in words(text):
            out.setdefault(token(token_key, word), []).append(enc(aes_key, doc_id.encode()))
    return out

def search(index, query, aes_key, token_key, mode='AND'):
    terms = words(query)
    if not terms: return []
    sets = [set(dec(aes_key, item).decode()
                for item in index.get(token(token_key, w), [])) for w in terms]
    return sorted(set.union(*sets) if mode.upper() == 'OR' else set.intersection(*sets))
```

Example calls (assuming `docs`, `aes_key`, `token_key` already exist):

```python
idx = make_index(docs, aes_key, token_key)
query = input('Words to search: ')
mode = input('AND or OR: ').strip().upper()
if mode not in ('AND', 'OR'): raise ValueError('Invalid search mode')
ids = search(idx, query, aes_key, token_key, mode)
print('Matching IDs:', ids)
```

The **index must be regenerated after edits**. Use `make_index(...)` only inside the *trusted* component holding keys, not on an untrusted search server.

## 6. AND / OR / NOT / exact phrase search — REUSABLE

Built on §5. `NOT` needs a known document universe; phrase search must check plaintext **at the authorized client** after the index narrows candidates.

```python
# Assume docs, index, aes_key, token_key, and search() from §5 exist.
query = input('Query: ')
mode = input('AND / OR / NOT / PHRASE: ').upper().strip()
if mode in ('AND', 'OR'):
    result = search(index, query, aes_key, token_key, mode)
elif mode == 'NOT':
    result = sorted(set(docs) - set(search(index, query, aes_key, token_key, 'OR')))
elif mode == 'PHRASE':
    phrase = list(re.findall(r'\w+', query.casefold()))
    candidates = search(index, query, aes_key, token_key, 'AND')
    result = []
    for doc_id in candidates:
        full = re.findall(r'\w+', dec(aes_key, docs[doc_id]).decode().casefold())
        if any(full[i:i+len(phrase)] == phrase for i in range(len(full)-len(phrase)+1)):
            result.append(doc_id)
else:
    raise ValueError('Invalid search mode')
print('Matches:', result)
```

**If a query is empty:** reject it or return no matches; never treat an empty query as an unrestricted search accidentally.

## 7. Add / edit / remove documents — REUSABLE

Assumes §2 and §5 plus a dictionary `docs` of AES-encrypted document records. The caller must save state afterward (§8). Rebuild after each change to avoid stale postings.

```python
choice = input('A=add, U=update, D=delete: ').upper().strip()
doc_id = input('Document ID: ').strip()
if not doc_id: raise ValueError('Empty ID')
if choice == 'A':
    if doc_id in docs: raise ValueError('ID exists')
    docs[doc_id] = enc(aes_key, input('Document: ').encode())
elif choice == 'U':
    if doc_id not in docs: raise KeyError('Unknown ID')
    docs[doc_id] = enc(aes_key, input('Replacement text: ').encode())
elif choice == 'D':
    if doc_id not in docs: raise KeyError('Unknown ID')
    del docs[doc_id]
else:
    raise ValueError('Unknown operation')
index = make_index(docs, aes_key, token_key)
```

**Cost:** full rebuilding is O(total document text). It is suitable for small lab datasets. For large datasets, change only the affected token postings and maintain encrypted token metadata carefully.

## 8. Persistent AES/index keys and records + integrity verification — REUSABLE

The **complete master program** handles persistence automatically. When writing your own solution, use this compact JSON persistence pattern. Inputs must include **different paths**; never generate replacement keys if records already exist.

```python
import json, os, hmac, hashlib
from pathlib import Path

def save(path, obj, private=False):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(obj, indent=2))
    if private: os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def digest(secret, obj):
    raw = json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()

key_path = Path(input('Key file: ').strip())
db_path = Path(input('Database file: ').strip())
if key_path.resolve() == db_path.resolve(): raise ValueError('Separate paths required')
# FIRST-RUN WRITE ONLY: when keys already exist, use the loader below instead.
if key_path.exists() or db_path.exists():
    raise FileExistsError('Existing dataset: do not replace keys; use loader below')
# Suppose aes_key/token_key/mac_key and docs/index already exist:
save(key_path, {'aes': aes_key.hex(), 'token': token_key.hex(), 'mac': mac_key.hex()}, True)
payload = {'docs': docs, 'index': index}
save(db_path, {**payload, 'hmac': digest(mac_key, payload)})
```

On restart, reverse the process (do **not** overwrite an existing key file):

```python
keys = json.loads(key_path.read_text())
aes_key = bytes.fromhex(keys['aes'])
token_key = bytes.fromhex(keys['token'])
mac_key = bytes.fromhex(keys['mac'])
stored = json.loads(db_path.read_text())
payload = {'docs': stored['docs'], 'index': stored['index']}
if not hmac.compare_digest(stored['hmac'], digest(mac_key, payload)):
    raise ValueError('Stored data tampered with')
docs, index = payload['docs'], payload['index']
```

**Important:** The first snippet demonstrates the *write/restart operations*, not initialization. The master provides safe first-run initialization. It stores raw keys in a local restricted-permission file **only for an educational lab**. A MAC detects unauthorized changes without the key, but cannot prevent deletion or rollback to an older valid database. Do not upload private keys to GitHub.

## 9. Exact ID lookup and encrypted field search — REUSABLE

Some scenarios say “search by index (record ID)” rather than by *word*. A direct dictionary/SQL index finds the ID; encryption protects the stored fields. This is **not** itself encrypted keyword search.

```python
record_id = input('Record ID: ').strip()
if record_id in docs:
    print('Encrypted document:', docs[record_id]['ct'])
    if input('Authorized to decrypt? (yes/no): ').lower() == 'yes':
        print('Plaintext:', dec(aes_key, docs[record_id]).decode())
else:
    print('No record matches the ID')
```

For multiple searchable fields, build **one independent HMAC token index per field** (for example `patient_id`, `diagnosis`, `department`); include the field name in the HMAC input (`'diagnosis:'+value`) to prevent cross-field token reuse. Authorization must be enforced separately by a real identity system.

## 10. Paillier-assisted encrypted index — STANDALONE (**manual exercise 2a–2d**)

**Manual requirement:** at least ten documents; Paillier encrypt/decrypt; encrypted inverted index; enter a search query; obtain and decrypt matching document IDs. **Protocol correction:** Paillier does **not** support ciphertext equality of two independently encrypted keywords. Here HMAC-SHA256 finds the posting list, and **Paillier encrypts each numerical document ID**, which the authorized holder of the Paillier private key decrypts. This meets the educational component requirements but is a **hybrid index, not a true PKSE construction**.

```python
import os, re, hmac, hashlib
from phe import paillier
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def box(key, message):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, message.encode(), None)

def unbox(key, item):
    return AESGCM(key).decrypt(*item, None).decode()

def tok(key, word):
    return hmac.new(key, word.encode(), hashlib.sha256).hexdigest()

bits = int(input('Paillier bits (>=2048): '))
if bits < 2048: raise ValueError('Paillier key too small')
public, private = paillier.generate_paillier_keypair(n_length=bits)
aes, search_key = os.urandom(32), os.urandom(32)
n = int(input('Number of documents (>=10): '))
if n < 10: raise ValueError('Need at least 10 for manual exercise')
labels, docs, index = {}, {}, {}
for i in range(1, n+1):
    doc_id = input(f'ID {i}: ').strip()
    text = input('Document content: ')
    if not doc_id or doc_id in labels.values(): raise ValueError('Invalid/duplicate ID')
    labels[i] = doc_id
    docs[i] = box(aes, text)
    for word in set(re.findall(r'\w+', text.casefold())):
        c = public.encrypt(i)                # encrypt NUMERICAL document ID
        index.setdefault(tok(search_key, word), []).append(
            (str(c.ciphertext()), c.exponent))

while True:
    query = input('Keyword (blank=exit): ').casefold().strip()
    if not query: break
    posting = index.get(tok(search_key, query), [])
    matches = [private.decrypt(paillier.EncryptedNumber(public, int(c), int(e)))
               for c, e in posting]
    print('Encrypted ID postings:', posting)
    print('Matching document IDs:', [labels[i] for i in matches])
    for i in matches:
        print(labels[i], '=>', unbox(aes, docs[i]))
```

**Data privacy:** no Paillier private-key decryption occurs until matches have been selected; user enters every document/query. This demo displays recovered document contents to the authorized client; in a *private-index only* question, omit the final `unbox` loop.

**Code modularization:** `index[token]` is the **server-side encrypted posting list**; `private.decrypt(EncryptedNumber(...))` is the **client-side recovery step**. To store across restarts, use §11 + §8.

## 11. Paillier persistence: serialize / reload encrypted postings — REUSABLE

`phe.EncryptedNumber` should not be JSON-serialized directly. Store its public modulus, ciphertext integer and exponent. The **private primes** are required to reopen the same keypair and must remain secret.

```python
from phe import paillier
import json

# Existing: public, private, value (encrypted Paillier number)
packed = {'n': str(public.n), 'c': str(value.ciphertext()), 'e': value.exponent}
print('JSON-safe ciphertext:', json.dumps(packed))

# Receiver/authorized client: private key corresponding to public.n already loaded
pub2 = paillier.PaillierPublicKey(int(packed['n']))
if pub2.n != private.public_key.n: raise ValueError('Wrong Paillier key')
restored = paillier.EncryptedNumber(pub2, int(packed['c']), int(packed['e']))
print('Recovered integer:', private.decrypt(restored))
```

For a lab-only persistent keyfile, store `{'n': str(public.n), 'p': str(private.p), 'q': str(private.q)}` in a **0600-permission file**; reload:

```python
saved = json.load(open(input('Paillier private key JSON path: ')))
public = paillier.PaillierPublicKey(int(saved['n']))
private = paillier.PaillierPrivateKey(public, int(saved['p']), int(saved['q']))
```

The object created by `private.decrypt(...)` reveals each matched **document ID**, not the entire underlying dataset. This is the lab's authorized retrieval behavior. If the question requires finance-style **aggregate-only** access, use Lab 7's aggregation model instead. Protect local key files; storing primes without encryption is for a disposable lab only.

## 12. RSA-OAEP encrypted posting IDs with keyed lookup — STANDALONE (**manual's RSA example correction**)

**Manual distinction:** the **PKSE *sample code*** uses RSA/OAEP, but **exercise 2 explicitly asks for Paillier**. Use this RSA version only when the question says RSA. Since OAEP is randomized, **keyword matching still uses HMAC tokens**; RSA OAEP encrypts posting document IDs. Documents themselves use AES-GCM.

```python
import os, hmac, hashlib, re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

bits = int(input('RSA bits (>=2048): '))
if bits < 2048: raise ValueError('RSA key too small')
private = RSA.generate(bits)
public = private.publickey()
search_key, aes = os.urandom(32), os.urandom(32)

def tok(word):
    return hmac.new(search_key, word.encode(), hashlib.sha256).hexdigest()

def seal(text):
    n = os.urandom(12)
    return n, AESGCM(aes).encrypt(n, text.encode(), None)

n = int(input('Number of documents (>=10): '))
if n < 10: raise ValueError('Need >=10 for manual dataset')
docs, index = {}, {}
for _ in range(n):
    doc_id, content = input('Document ID: ').strip(), input('Content: ')
    if not doc_id or doc_id in docs: raise ValueError('Duplicate/empty ID')
    docs[doc_id] = seal(content)
    for w in set(re.findall(r'\w+', content.casefold())):
        ct_id = PKCS1_OAEP.new(public, hashAlgo=SHA256).encrypt(doc_id.encode())
        index.setdefault(tok(w), []).append(ct_id)

while True:
    query = input('Search keyword (blank=exit): ').strip().casefold()
    if not query: break
    found = index.get(tok(query), [])
    ids = [PKCS1_OAEP.new(private, hashAlgo=SHA256).decrypt(c).decode() for c in found]
    print('Matching IDs:', ids)
    for doc_id in ids:
        nonce, ct = docs[doc_id]
        print(doc_id, '=>', AESGCM(aes).decrypt(nonce, ct, None).decode())
```

**RSA OAEP limit:** a single `doc_id.encode()` must fit OAEP's message-size limit. For long IDs or large documents, encrypt using AES-GCM and use RSA-OAEP to wrap the AES key instead. **Do not call this a standards-based public-key searchable-encryption protocol**; the indexing/search key is symmetric.

## 13. Encrypted record search with signatures, integrity and simple role menus — REUSABLE (**extension**)

For questions combining Labs 5–8: **encrypt data → index keywords → hash/sign ciphertext → store → verify → search → decrypt only when authorized**. AES-GCM already protects integrity; RSA signatures additionally authenticate the sender if the verifier has a trusted public key.

```python
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# Assume `record` is an AES-GCM record like §2's enc().
signer = RSA.generate(int(input('RSA signing key bits (>=2048): ')))
protected = json.dumps(record, sort_keys=True).encode()
digest = SHA256.new(protected)
signature = pkcs1_15.new(signer).sign(digest)
print('Hash:', digest.hexdigest())
print('Signature:', signature.hex())

# Reviewer: require hash + signature verification BEFORE disclosing plaintext.
received = json.dumps(record, sort_keys=True).encode()
try:
    pkcs1_15.new(signer.publickey()).verify(
        SHA256.new(received), signature)
    print('Signature VALID; decrypt only if role is authorized')
except (ValueError, TypeError):
    print('Signature INVALID: do not decrypt')
```

The RSA signer must use a validated key size; supply 2048 or greater. A menu choice labelled “Researcher”/“Reviewer” alone is **not authentication**. Implement actual logins or an externally trusted identity layer if the examiner requires **enforced RBAC**.

### Minimal role-based menu structure — REUSABLE

```python
while True:
    print('1 Owner  2 Searcher  3 Auditor  0 Exit')
    role = input('Role: ').strip()
    if role == '0': break
    if role == '1':
        print('Owner: add / update / delete / list')
    elif role == '2':
        print('Searcher: search → verify → optionally decrypt')
    elif role == '3':
        print('Auditor: verify integrity; no plaintext display')
    else:
        print('Invalid choice')
```

This is only a **menu skeleton**, not a full access-control program; use `Lab_8_Endsem_Menu_Master.py` (§15) for actual operations.

## 14. Prefix, substring, case handling and query normalization — REUSABLE (**extensions**)

The basic manual asks **exact whole-word search**. For prefixes, an exact-token index does not suffice. Index separate HMAC tokens for each prefix, or retrieve candidate documents and perform filtering at the trusted client.

```python
import re

def normalize(text):
    return re.findall(r'\w+', text.casefold())

def prefix_terms(word, shortest):
    if shortest < 1: raise ValueError('Minimum prefix length must be positive')
    return [word[:i] for i in range(shortest, len(word)+1)]

shortest = int(input('Minimum allowed prefix length: '))
keyword = input('Keyword to index: ').casefold().strip()
print('Prefixes to tokenize:', prefix_terms(keyword, shortest))
```

**To implement prefix search:** during index building, add `token(secret, 'PREFIX:'+prefix)` for each returned prefix; at query time, compute the same token. Prefix indexing increases index size and leaks more query/search structure. A substring or fuzzy-search extension needs its own n-gram or trusted-client filtering scheme; one-word lookup cannot silently perform it.

### Case-folding, duplicate postings and punctuation — REUSABLE

```python
import re
text = input('Document: ')
unique_words = set(re.findall(r'\w+', text.casefold()))
print('Normalized unique keywords:', sorted(unique_words))
```

`set(...)` prevents a document from appearing twice for a repeated word. The simple tokenizer includes underscore and Unicode word characters; it is not a linguistic tokenizer or stemming engine.

## 15. **Complete persistent menu-driven master:** companion `.py`

**Download:** `Lab_8_Endsem_Menu_Master.py` in this response. It is an actual, runnable program, not pseudocode.

**Copy into PyCharm → execute → enter key-path and data-path → enter AES size on first run → choose a role.** On restart, enter the **same** key-file and database-file names; do **not** generate new keys.

```
LAB 8: 1 Owner  2 Searcher  3 Auditor  0 Exit
  1 Owner:
      1 Add document
      2 Update document
      3 Delete document
      4 List encrypted document records
      5 Bulk-create documents (enter at least ten for the manual)
  2 Searcher:
      1 Exact keyword
      2 AND
      3 OR
      4 Exact phrase
      Choose whether to decrypt matching documents
  3 Auditor:
      1 Verify encrypted-document integrity
      2 Index statistics
      3 Tamper test (in-memory; preserves stored records)
```

**Security and persistence properties implemented:**

- AES-128/192/256-GCM content encryption using a user-selected AES key size; encrypted postings for document IDs.
- HMAC-SHA256 secret-keyed word tokens; case-insensitive exact whole-word search.
- No plaintext documents persisted; fresh nonce each encryption; authenticated decryption rejects tampering.
- Database-wide HMAC checked at program startup; atomic JSON writes to reduce partial-file risk; private key file mode `0600` (Debian).
- Input-driven document IDs, data, queries, paths and counts; no fixed sample content or predetermined secret keys.
- Full index rebuild after every change, avoiding stale results.

**Limitations stated explicitly:** role switching is a **simulation**, not authentication; raw encryption/search keys are stored locally; stable tokens/search frequencies leak patterns; reusing an older valid database cannot be detected without extra rollback protection. Not hardened for hostile multiuser production deployment.

## 16. Benchmark and compare encryption/search performance — STANDALONE (**extension**)

Use the corpus already in memory (the exam's *own inputs*) rather than fixed sample texts. Time several runs and calculate averages. No system guarantees or fake performance numbers.

```python
from time import perf_counter
import statistics

# Assume `index, aes_key, token_key, query, search` from §5 exist.
repetitions = int(input('Repetitions: '))
if repetitions < 1: raise ValueError('Need positive repetitions')
timings = []
for _ in range(repetitions):
    start = perf_counter()
    result = search(index, query, aes_key, token_key, 'AND')
    timings.append((perf_counter()-start)*1000)
print('Matches:', result)
print('Search time mean (ms):', statistics.mean(timings))
print('Search time median (ms):', statistics.median(timings))
```

**Performance comparison rubric:** measure AES encryption per byte, HMAC index build time, query search time, encrypted-ID recovery time, and persistent disk operations separately. RSA-OAEP or Paillier per-ID encryption is generally more costly than AES; actual timings depend on key lengths, machine and dataset. Key generation time and per-query time are distinct metrics.

## 17. GnuPG — secure storage, sharing and signatures (**manual additional question 1**)

This task is a **separate application of GnuPG**, not searchable encryption. Your Python packages (`python-gnupg`) do **not** install the system `gpg` executable.

```bash
sudo apt update
sudo apt install -y gnupg
command -v gpg && gpg --version
```

**Interactive key creation (you choose identity, expiry, passphrase):**

```bash
gpg --full-generate-key
gpg --list-keys
gpg --list-secret-keys
gpg --fingerprint
```

**Encrypt for recipient, decrypt as recipient (all paths/recipient come from prompt):**

```bash
read -r -p 'Recipient key ID/email: ' RECIPIENT
read -r -p 'Input file path: ' SOURCE
read -r -p 'Encrypted output path: ' ENCRYPTED
read -r -p 'Recovered plaintext output path: ' RECOVERED

gpg --output "$ENCRYPTED" --encrypt --recipient "$RECIPIENT" "$SOURCE"
gpg --output "$RECOVERED" --decrypt "$ENCRYPTED"
```

**Detached signature → transmit encrypted file and separate signature → verify:**

```bash
read -r -p 'Signer key ID/email: ' SIGNER
read -r -p 'File to sign: ' FILE
read -r -p 'Detached signature output path: ' SIG

gpg --local-user "$SIGNER" --armor --output "$SIG" --detach-sign "$FILE"
gpg --verify "$SIG" "$FILE"
```

For a proper sender→receiver workflow: the **sender** signs the original file and encrypts it for the **receiver**. Transmit the ciphertext and signature. The receiver decrypts and verifies using the sender's trusted public key. If you sign the **ciphertext** instead, the receiver can verify ciphertext authenticity **before** decryption, but must know and trust the signer's public key.

**Combine sign + encrypt in one step:**

```bash
read -r -p 'Sender signing key: ' SIGNER
read -r -p 'Recipient public key: ' RECIPIENT
read -r -p 'Source file: ' SOURCE
read -r -p 'Encrypted signed output: ' OUTPUT

gpg --local-user "$SIGNER" --recipient "$RECIPIENT" --output "$OUTPUT" --sign --encrypt "$SOURCE"
# Receiver must have the matching private key:
read -r -p 'Decrypt output path: ' PLAIN
gpg --output "$PLAIN" --decrypt "$OUTPUT"
```

**Public-key exchange and trust verification:**

```bash
read -r -p 'Public key identity: ' USER_ID
read -r -p 'Public key export path: ' PUBFILE
gpg --armor --output "$PUBFILE" --export "$USER_ID"
# The other user does:
read -r -p 'Received public key path: ' RECEIVED_KEY
gpg --import "$RECEIVED_KEY"
gpg --fingerprint "$USER_ID"
```

Check the **complete fingerprint through a separately trusted channel** before trusting a key. Do **not** export or distribute the secret key. `gpg --verify` confirms a signature cryptographically; verified key ownership requires appropriate trust checks.

**Tamper demo:** modify a copy of the signed file, then run `gpg --verify "$SIG" "$MODIFIED_FILE"` — verification must fail. Do not alter your only original file.

Official reference: https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html

## 18. GnuPG from Python — STANDALONE (**manual extension**)

The system `gpg` executable is required. Use `subprocess.run([...])` instead of constructing a shell command from untrusted user input.

```python
import subprocess

def gpg(*args):
    subprocess.run(['gpg', *args], check=True)

while True:
    print('1 Encrypt  2 Decrypt  3 Sign  4 Verify  0 Exit')
    op = input('Choice: ').strip()
    if op == '0': break
    try:
        if op == '1':
            who = input('Recipient: ')
            src = input('Input path: ')
            dst = input('Encrypted output path: ')
            gpg('--output', dst, '--encrypt', '--recipient', who, src)
        elif op == '2':
            src, dst = input('Encrypted input: '), input('Decrypted output: ')
            gpg('--output', dst, '--decrypt', src)
        elif op == '3':
            src = input('File to sign: ')
            signer = input('Signing identity: ')
            dst = input('Signature output: ')
            gpg('--local-user', signer, '--armor', '--output', dst, '--detach-sign', src)
        elif op == '4':
            sig, src = input('Signature path: '), input('Signed data path: ')
            gpg('--verify', sig, src)
        else:
            print('Invalid choice')
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print('GnuPG operation failed:', exc)
```

This is a menu-driven **GnuPG operations demo**; it does not implement an identity/authorization server. Importing `gnupg` from `python-gnupg` is optional — invoking the official `gpg` command is often simpler for an exam.

## 19. Snort 3 NIDS — configure, validate, observe traffic (**manual additional question 2**)

Snort is a **system-level IDS**, not a Python library. Use only on your own/authorized traffic. Snort **3** uses `snort.lua`; Snort **2** typically uses `snort.conf`. Verify the actual installed version before copying commands.

```bash
snort -V
snort --help
```

**Snort 3: choose the actual paths/interface interactively** (your Debian installation may use different locations):

```bash
read -r -p 'Absolute path to snort.lua: ' CONF
read -r -p 'Absolute path to local .rules file: ' RULES
read -r -p 'Network interface name (e.g. loopback or lab NIC): ' IFACE
snort -c "$CONF" -R "$RULES" -T                 # check configuration and rules
sudo snort -c "$CONF" -R "$RULES" -i "$IFACE" -A alert_fast
```

**Create a local ICMP alert rule** (SID is chosen by user):

```bash
read -r -p 'Path for local rules file: ' RULES
read -r -p 'Custom rule SID (positive integer, e.g. >=1000000): ' SID
case "$SID" in ''|*[!0-9]*) echo 'Invalid SID'; exit 1;; esac
printf 'alert icmp any any -> any any (msg:"Lab ICMP observed"; sid:%s; rev:1;)\n' "$SID" > "$RULES"
cat "$RULES"
```

**Meaning of the rule:** when Snort sees ICMP traffic covered by this rule, it generates an alert. It **does not mean the packet is malicious**; it is simply a controlled demonstration that the detection pipeline works. To inspect traffic content, enable appropriate packet logging/inspection as permitted by the course lab setup.

**Snort 3: inspect an already captured PCAP** (reproducible, lower risk than live monitoring):

```bash
read -r -p 'snort.lua path: ' CONF
read -r -p 'Local rules path: ' RULES
read -r -p 'PCAP file path: ' PCAP
snort -c "$CONF" -R "$RULES" -r "$PCAP" -A alert_fast
```

If you must capture **only authorized lab traffic**, first identify the interface using `ip link`, then:

```bash
read -r -p 'Capture interface: ' IFACE
read -r -p 'PCAP output path: ' PCAP
sudo tcpdump -i "$IFACE" -w "$PCAP"
# Press Ctrl+C to finish the capture, then use Snort -r above.
```

`tcpdump` is a separate package: `sudo apt install tcpdump`. Snort 3 installation/build packages differ by Debian release; **do not assume** that `apt install snort` installs Snort 3. Ask the lab administrator for the approved installation or inspect `apt-cache policy snort snort3` if necessary.

**Snort 2 quick translation:** `snort -T -c /path/to/snort.conf`, followed by `snort -c ... -i ... -A console` (syntax/configuration differ). Avoid mixing Snort 2 rule/configuration assumptions with Snort 3 commands.

Official references: https://docs.snort.org/start/help and https://docs.snort.org/start/configuration

## 20. Snort rules/logs using Python — STANDALONE (**manual extension**)

This minimal script helps analyze **existing alert text**. It does **not** perform packet sniffing or replace Snort.

```python
from pathlib import Path
from collections import Counter

path = Path(input('Path to readable Snort alert log: ').strip())
if not path.is_file(): raise FileNotFoundError(path)
lines = [s.strip() for s in path.read_text(errors='replace').splitlines() if s.strip()]
needle = input('Filter by keyword (blank=all): ').casefold().strip()
matched = [line for line in lines if needle in line.casefold()]
print('Lines in log:', len(lines))
print('Matching alert lines:', len(matched))
for line in matched: print(line)
print('Exact-line frequencies:', Counter(matched).most_common(int(input('Top N lines: '))))
```

**Alternative: launch Snort 3 for an authorized PCAP from Python:**

```python
import subprocess
config = input('snort.lua path: ').strip()
rules = input('rules path: ').strip()
pcap = input('PCAP path: ').strip()
subprocess.run(['snort', '-c', config, '-R', rules, '-r', pcap, '-A', 'alert_fast'], check=True)
```

Expect errors when Snort is absent, the capture cannot be read, or the rule/configuration is invalid. Do not swallow those errors and report false success.

## 21. Client/server encrypted-index search — OPTIONAL **extension**

Some exam scenarios describe a remote untrusted search server. The correct component boundary is:

```
AUTHORIZED CLIENT                           STORAGE/SEARCH SERVER
Document → AES-GCM ciphertext       --->    Store ciphertext
Words → HMAC keyword tokens         --->    Store token → encrypted postings
Query → HMAC query token            --->    Look up opaque token
Decrypt encrypted result IDs        <---    Return encrypted postings
Decrypt document if authorized      <---    Return selected AES ciphertext
```

**Minimal transport idea:** send `{ "token": "<HMAC_HEX>" }`, not the plaintext keyword. Return the server-side encrypted posting blobs unchanged; the client decrypts them. Use length-prefixed JSON to prevent partial-read errors when using TCP sockets:

```python
import json, struct

def read_exact(sock, count):
    out = bytearray()
    while len(out) < count:
        part = sock.recv(count-len(out))
        if not part: raise ConnectionError('Connection ended early')
        out += part
    return bytes(out)

def send_json(sock, data):
    blob = json.dumps(data).encode()
    sock.sendall(struct.pack('!I', len(blob)) + blob)

def recv_json(sock):
    length = struct.unpack('!I', read_exact(sock, 4))[0]
    if length > 10_000_000: raise ValueError('Excessive message length')
    return json.loads(read_exact(sock, length))
```

The length limit above is a protocol safety bound, **not** an exam-specific plaintext, key, ID or question answer. Socket framing itself does **not** provide transport confidentiality, endpoint authentication or replay protection; add authenticated TLS and access control for an actual remote system. SSE leaks token repetition and access patterns as already noted.

## 22. Failure handling and common incorrect approaches

| Problem | Correct response |
|---|---|
| `E(query) != E(keyword)` with CBC/OAEP/Paillier | Randomized encryption cannot be directly equality-matched; use consistent keyed tokens / formal SE protocol |
| `AES.MODE_CBC` IV dropped | Store/transmit the 16-byte IV with ciphertext |
| AES-CBC tamper detected by `unpad()` only | Not sufficient. Verify MAC/signature or use authenticated AES-GCM |
| Wrong AES key size | Only 16, 24, 32 bytes; reject invalid sizes |
| Reusing AES-GCM nonce with same key | Never do this; use fresh random 12-byte nonce |
| Duplicate ID | Reject or implement an explicit update operation |
| Duplicate keyword repeated in same document | Deduplicate per-document tokens |
| Missing word | Return empty matches; do not raise `KeyError` |
| Empty query | Reject or return no matches; do not accidentally show all |
| Unknown/invalid key | Fail safely; never silently regenerate keys for existing encrypted records |
| `Paillier.encrypt('hello')` | Convert relevant IDs to integers; Paillier works on supported numbers, not arbitrary text |
| Paillier ciphertext compared for keyword equality | Incorrect; randomized Paillier ciphertext cannot be used as an equality key |
| AES/Paillier/RSA library installation succeeds but `gpg`/`snort` fails | They are separate **system executables** |
| GPG signature verifies but key belongs to attacker | Signature alone is insufficient: check trusted public-key fingerprint |
| Snort alert = proven compromise | False: a matching rule only indicates traffic/event matching conditions |
| `print('Valid')` despite exception | Report error and suppress plaintext |
| `except:` hides every failure | Catch meaningful errors and show a clear failure reason |
| Searcher or auditor role selected by number | This is menu routing, *not* verified identity/RBAC |
| Hashing encrypted text without a keyed MAC | A public hash detects accidental change against a trusted original, but is not sender authentication |

## 23. Question-to-component assembly recipes

**A. “Search ten encrypted documents using AES”** → §§2+4; use the manual's dataset size, inverted index, encrypted posting IDs and authorized decryption.

**B. “Search multiple keywords / filter sensitive records”** → §§2+5+6; use AND/OR/NOT; phrase verification happens client-side.

**C. “Hospital/library/legal records with roles, restart, add/update/delete”** → §15 master; rename roles/menus; choose which roles may decrypt; for *real authorization*, add credentials and server-side enforcement.

**D. “Find matching encrypted files by patient ID, grant ID or file ID”** → §9 direct-index lookup; encrypt record contents; add cryptographic field-token indexing when the ID itself must remain private.

**E. “Paillier-based encrypted document-ID search”** → §10; encrypted integer posting IDs + HMAC keyword index; §11 for serialization; describe as a **hybrid construction**.

**F. “RSA-based encrypted searchable index”** → §12; HMAC search + RSA-OAEP encrypted IDs + AES-GCM document content; do not compare RSA ciphertexts.

**G. “Signature verification before showing results”** → §§13+15; sign canonical ciphertext metadata; trusted public key; stop on invalid signature.

**H. “Encrypted files transferred using GnuPG”** → §§17–18; encrypt, optionally sign, transmit files, decrypt, verify fingerprints and signatures.

**I. “Snort real-time NIDS and offline evidence review”** → §§19–20; version check, configuration, custom rule, validation, authorized capture/PCAP, inspect matching alerts.

**J. “Performance comparison and security efficiency trade-offs”** → §§14+16; time individual operations, report observed rather than assumed numbers, and explain search-pattern leakage.

**K. “Server/client application”** → §21 framing + §15 search functions; keep query-token generation and result decryption client-side.

**L. “Full exam scenario: owner, reviewer, auditor; encryption + signature + encrypted search + persistent storage”**:

```
1. Create/load keys safely; load existing JSON records
2. Owner enters ID, content and searchable metadata
3. Encrypt private content with AES-GCM; make HMAC search tokens
4. Add encrypted document ID to index postings
5. If required, sign canonical ciphertext with RSA private key
6. Persist ciphertext, postings, signatures and timestamps
7. Searcher submits query; compute HMAC search token
8. Search index for encrypted postings; decrypt matched IDs only
9. Recompute/authenticate signature or MAC before showing plaintext
10. Decrypt selected document only for permitted role
11. Auditor verifies integrity and logs actions without showing plaintext
12. Handle corrupted entries, missing key, wrong ID, invalid input cleanly
```

## 24. Exam readiness checklist

- [ ] **Menu-driven** if required: actual nested role menus, repeat until Exit, invalid choice handling.
- [ ] Every question-specific ID, message, query, file path, role option, data count and configurable key size is user-supplied.
- [ ] For the official SSE/PKSE exercise, enter **at least ten documents** with multiple words.
- [ ] Print the encrypted document(s), index/token statistics, matching encrypted IDs and requested decrypted results.
- [ ] AES decryption reuses its stored nonce/IV; encrypted search uses a stable HMAC token, **not** randomized ciphertext equality.
- [ ] Load persistent keys/records on restart; never overwrite old keys unexpectedly.
- [ ] Check tampering *before* disclosing decrypted content; safely handle failures.
- [ ] For Paillier: encrypted ID is an integer; reconstruct `EncryptedNumber(public, ciphertext, exponent)` before decrypting.
- [ ] For RSA OAEP: respect message length; hybrid encryption for large files.
- [ ] For GnuPG: system `gpg` installed and key fingerprints checked; signature verification demonstrated.
- [ ] For Snort: version/config/rules verified; only authorized networks; inspect actual alerts, do not invent them.
- [ ] Mention measurable leakage, performance overhead and authorization limitations in viva.
- [ ] Before submission, run one valid lookup, one missing-word lookup, a restart test and a tampering test.

## 25. Expected tests / validation status

**Menu-driven companion:** Python syntax checked and its actual SSE flow tested under `cryptography` AES-GCM. Checked: AES authenticated roundtrip, index search, 10-record bulk insertion, AND/phrase query behavior, persistence after restart, update/delete, in-memory tamper detection and modified-database rejection. The companion does **not** depend on `phe` or PyCryptodome; both are available in your planned Debian exam environment if you need Paillier or RSA variants.

**Reference snippets:** syntactically checked as Python blocks; some marked **REUSABLE** intentionally depend on variables/functions from earlier sections. Paillier (`phe`), RSA (`pycryptodome`), GnuPG (`gpg`), Snort and shell workflows **must be executed and checked in the actual PyCharm/lab environment** before you rely on them; their full runtime integration is not claimed to be verified here.

## 26. Sources and scope

- **Primary:** Your uploaded `IS Lab Manual [7-8](1).pdf`, **Lab 8 pages 8–15**. SSE categories and the two exercises come directly from the manual. GnuPG and Snort are its two additional exercises.
- **Independent correction/implementation choice:** deterministic keyed search tokens; authenticated AES-GCM storage; Paillier-assisted hybrid search (rather than claiming Paillier-only equality queries); encrypted database HMAC; optional RSA sign/index, prefix, performance, remote/client role patterns.
- **Implementation documentation:** [PyCryptodome](https://www.pycryptodome.org/en/latest/src/introduction.html), [GnuPG](https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html), [Snort 3 command line](https://docs.snort.org/start/help), [Snort 3 configuration](https://docs.snort.org/start/configuration).

**STOP — Lab 8 complete.** Continue to another lab **only when requested**.
