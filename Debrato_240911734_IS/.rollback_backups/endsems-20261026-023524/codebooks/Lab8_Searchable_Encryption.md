# Lab 8 — Searchable encryption (SSE, Paillier PKSE), GnuPG, Snort

Toolkit: `toolkit/searchable.py` — SSE (`new_search_keys`, `new_store`, `sse_add`,
`sse_search` AND/OR, `sse_read`, `sse_remove`), record indexes (`token`,
`field_index_add/find/find_any` for equality and bucketed time ranges), deterministic
AES token (`det_token_aes`), and Paillier PKSE (`pkse_build`, `pkse_query`,
`pkse_server_match`, `pkse_client_resolve`).

## 0. Why the manual's sample code finds nothing — and the fix

The manual "encrypts the query" with AES-CBC using a **new random IV**, and the PKSE sample uses
RSA-OAEP — both are randomized, so the same keyword never produces the same ciphertext and the
dictionary lookup always misses. Searching needs either
1. a **deterministic keyed trapdoor**: `token = HMAC-SHA256(k, word)` (or AES-ECB of `SHA-256(word)`),
   used as the index key — the server matches tokens without learning words; or
2. a **homomorphic equality test** (Paillier): server computes `E(r·(H(w) − H(q)))`; only the
   private-key holder sees which entries decrypt to 0.

Leakage to state: SSE reveals the *search pattern* (same query → same token) and *access pattern*
(which/how many documents match), corpus size and ciphertext lengths. Tokens do not
contain literal keywords, but frequency and background knowledge can reveal likely words.
These teaching examples do not provide a formal searchable-encryption security proof.

## 1. SSE — manual exercise 1 (corpus, AES encryption, encrypted inverted index, search)

Documents are AES-CBC encrypted (as the manual asks); index keys are HMAC tokens; posting
lists hold AES-encrypted document IDs; search → token → decrypt IDs → decrypt documents.

<!-- stdin: 10 | d1 | the patient has a fever and cough | d2 | fever reduced after treatment | d3 | annual budget report for finance | d4 | cough syrup prescribed to patient | d5 | security audit of the finance system | d6 | network intrusion detected last night | d7 | patient discharged after recovery | d8 | quarterly finance budget approved | d9 | firewall rules updated for the network | d10 | treatment plan for chronic cough | patient | finance budget | xyz | -->
```python
import hashlib, hmac, re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

enc_key, tok_key = get_random_bytes(32), get_random_bytes(32)     # client's secrets

def encrypt(data):                      # AES-CBC, random IV stored in front
    c = AES.new(enc_key, AES.MODE_CBC)
    return c.iv + c.encrypt(pad(data.encode(), 16))

def decrypt(blob):
    return unpad(AES.new(enc_key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]), 16).decode()

def words(text):
    return set(re.findall(r"[\w']+", text.casefold()))

def trapdoor(word):                     # deterministic search token
    return hmac.new(tok_key, word.casefold().encode(), hashlib.sha256).hexdigest()

# --- 1a/1b: dataset (from input) + encryption -------------------------------
n = int(input('Number of documents (>= 10): '))
if n < 10: raise ValueError('the exercise asks for at least ten documents')
docs = {}
for _ in range(n):
    doc_id = input('Document ID: ').strip()
    if not doc_id or doc_id in docs: raise ValueError('Empty or duplicate document ID')
    docs[doc_id] = input('Text: ')
server_docs = {doc_id: encrypt(text) for doc_id, text in docs.items()}

# --- 1c: inverted index word -> [doc ids], then encrypt it -------------------
inverted = {}
for doc_id, text in docs.items():
    for w in words(text):
        inverted.setdefault(w, []).append(doc_id)
server_index = {trapdoor(w): [encrypt(i) for i in ids] for w, ids in inverted.items()}
print(f'Encrypted index: {len(server_index)} tokens, e.g. {next(iter(server_index))[:24]}...')

# --- 1d: search ---------------------------------------------------------------
while True:
    query = input('Search query (blank = stop): ').strip()
    if not query: break
    result = None
    for w in words(query):                     # AND over all words
        ids = {decrypt(e) for e in server_index.get(trapdoor(w), [])}
        result = ids if result is None else result & ids
    result = result or set()
    print('  matching IDs:', sorted(result))
    for i in sorted(result):
        print(f'  {i}: {decrypt(server_docs[i])}')
```

This standalone example stores document IDs as dictionary keys in `server_docs`, so the
server sees those IDs. Encrypted postings do not hide IDs already present in that map.
`toolkit.searchable` uses opaque document handles. Both examples run client/server logic
in one process. The client must hold encryption and token keys in a real separated setup.

## 2. PKSE with Paillier — manual exercise 2 (encrypt index + query with Paillier)

<!-- stdin: 10 | a | secure cloud storage | b | cloud search engine | c | local disk | d | cloud backups daily | e | financial audit report | f | local security logs | g | cloud finance archive | h | public library catalog | i | private disk backup | j | search security review | CLOUD! | disk | none | -->
```python
import hashlib, re, secrets
from math import gcd
from Crypto.Util.number import getPrime

# ---- Paillier (from scratch) ----
while True:
    p, q = getPrime(512), getPrime(512)
    n = p * q
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    if p != q and gcd(lam, n) == 1: break
n2 = n * n
mu = pow(lam, -1, n)

def random_unit():
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1: return r
def enc(m):
    if not 0 <= m < n: raise ValueError('Encoded value must fit the modulus')
    r = random_unit()
    return (1 + m * n) * pow(r, n, n2) % n2
def dec(c): return (pow(c, lam, n2) - 1) // n * mu % n
H = lambda w: int.from_bytes(hashlib.sha256(w.casefold().encode()).digest(), 'big')   # < n
to_int = lambda s: int.from_bytes(b'\x01' + s.encode(), 'big')
to_str = lambda i: i.to_bytes((i.bit_length() + 7) // 8, 'big')[1:].decode()

# ---- 2a/2c: corpus and Paillier-encrypted inverted index (public key only) ----
docs = {}
count = int(input('Number of documents (>=10): '))
if count < 10: raise ValueError('The manual requires at least ten documents')
for _ in range(count):
    i = input('Document ID: ').strip()
    if not i or i in docs: raise ValueError('Empty or duplicate document ID')
    docs[i] = input('Text: ')
postings = {}
for i, t in docs.items():
    for w in set(re.findall(r"[\w']+", t.casefold())): postings.setdefault(w, []).append(i)
index = [(enc(H(w)), [enc(to_int(i)) for i in ids]) for w, ids in postings.items()]

# ---- 2d: search ----
while True:
    word = input('Query (blank = stop): ').strip()
    if not word: break
    terms = re.findall(r"[\w']+", word.casefold())
    if len(terms) != 1:
        print('Enter exactly one keyword')
        continue
    eq = enc(H(terms[0]))                                         # query encrypted with PUBLIC key
    # server (no private key): E(r * (H(w) - H(q))) for every entry
    blinded = [pow(ek * pow(eq, -1, n2) % n2, random_unit(), n2) for ek, _ in index]
    # private-key holder: entry matches iff it decrypts to 0, then decrypt the doc IDs
    hits = [to_str(dec(c)) for (ek, ids), b in zip(index, blinded) if dec(b) == 0 for c in ids]
    print('  matching documents:', sorted(hits), [docs[h] for h in sorted(hits)])
```

This is a Paillier-assisted equality demonstration, not a vetted PKSE protocol. It uses
a fresh unit modulo n for encryption and for each equality-test blinder. Keywords and
queries use the same case folding and tokenizer. Encoded document IDs must fit n.
The private-key holder receives all blinded tests and encrypted postings, then detects zero
results. No match selection returns to the simulated server. A real retrieval request can
reveal which entries matched. Corpus size and posting-list lengths remain visible. The
algorithm scans every index entry. The code keeps plaintext `docs` at the simulated client.

## 3. Full SSE store: add / search AND·OR / read / delete / persist (toolkit)

<!-- stdin: -->
```python
import json
from toolkit.searchable import new_search_keys, new_store, sse_add, sse_search, sse_read, sse_remove

keys, store = new_search_keys(), new_store()        # keys stay with the client; store = server
for doc_id, text in {'r1': 'blood test normal', 'r2': 'blood pressure high', 'r3': 'x-ray normal'}.items():
    sse_add(store, keys, doc_id, text, extra_keywords=['radiology'] if 'x-ray' in text else [])
print('blood AND normal ->', sse_search(store, keys, 'blood normal', 'AND'))
print('blood OR radiology ->', sse_search(store, keys, 'blood radiology', 'OR'))
print('read r2          ->', sse_read(store, keys, 'r2'))
sse_remove(store, keys, 'r1')
print('after delete     ->', sse_search(store, keys, 'blood'))
json.dump({'keys': keys, 'store': store}, open('sse.json', 'w'))   # everything is JSON-safe
```

## 4. Searchable index for records: equality fields and time ranges (used in e-voting)

<!-- stdin: -->
```python
import os
from datetime import datetime, timedelta, timezone
from toolkit.searchable import field_index_add, field_index_find, field_index_find_any
from toolkit.util import hour_buckets

key, index, times = os.urandom(32), {}, {}
now = datetime.now(timezone.utc)
for rid, const, t in (('b1', 'C1', now), ('b2', 'C2', now - timedelta(hours=5)), ('b3', 'C1', now - timedelta(hours=30))):
    field_index_add(index, key, 'constituency', const, rid)          # HMAC(constituency=C1)
    field_index_add(index, key, 'hour', t.strftime('%Y-%m-%dT%H'), rid)
    times[rid] = t
print('constituency C1:', field_index_find(index, key, 'constituency', 'C1'))
start, end = now - timedelta(hours=6), now
hits = field_index_find_any(index, key, 'hour', hour_buckets(start, end))   # bucket tokens
print('last 6 hours   :', [r for r in hits if start <= times[r] <= end])   # exact filter
print('index keys are opaque tokens:', list(index)[:2])
```

## 5. GnuPG — store, transmit, sign, verify (additional Q1)

Install: `sudo apt install gnupg` (Python wrapper: `pip install python-gnupg`, still needs `gpg`).

```bash
gpg --full-generate-key                                 # create your key pair
gpg --list-keys
gpg --armor --export you@example.com > you_pub.asc      # share public key
gpg --import partner_pub.asc                            # import partner's key
gpg --fingerprint partner@example.com                   # check through a separate trusted channel
gpg --encrypt --sign --armor -r partner@example.com secret.txt   # -> secret.txt.asc
gpg --decrypt secret.txt.asc > secret_out.txt           # partner decrypts + verifies signature
gpg --detach-sign --armor report.pdf                    # -> report.pdf.asc
gpg --verify report.pdf.asc report.pdf                  # "Good signature from ..."
gpg --symmetric --cipher-algo AES256 backup.tar         # password-based storage encryption
```

<!-- no-run -->
```python
import gnupg                                             # python-gnupg
gpg = gnupg.GPG()
key = gpg.gen_key(gpg.gen_key_input(name_email='lab@example.com', passphrase='pass'))
enc = gpg.encrypt('confidential data', key.fingerprint, sign=key.fingerprint, passphrase='pass')
dec = gpg.decrypt(str(enc), passphrase='pass')
print(dec.data.decode(), '| signature valid:', dec.valid)
signed = gpg.sign('message', keyid=key.fingerprint, passphrase='pass')      # clearsigned
print('clearsigned signature valid:', gpg.verify(str(signed)).valid)
```

A good signature proves consistency with a key. Check its full fingerprint through a
separate trusted channel before attributing it to a person. The sender must export a
public signing key for the receiver as well. Transfer the signed ciphertext to the receiver,
then decrypt and verify there. Do not exchange private keys. Modify a copy of a signed
file and show that verification fails.

## 6. Snort NIDS (additional Q2)

Snort is a system tool. Its package, configuration and output options depend on the
installed version. Check the lab machine before choosing one of these procedures.
These commands are reference procedures and were not executed in this audit.

```bash
snort -V
ip link
# Use the configuration and interface approved for this lab.
# Snort 2 normally uses snort.conf. Snort 3 uses snort.lua.
```

Snort 2 example: make sure `snort.conf` includes the selected local rule file and that
`HOME_NET` identifies the lab host or subnet. Put the following rule in that file.

```text
alert icmp any any -> $HOME_NET any (msg:"Lab ICMP observed"; sid:1000001; rev:1;)
```

```bash
read -r -p 'Snort 2 snort.conf path: ' CONF
read -r -p 'Lab interface: ' IFACE
sudo snort -T -c "$CONF"
sudo snort -A console -q -c "$CONF" -i "$IFACE" 2>&1 | tee snort2-alerts.txt
# Generate a ping to the monitored lab host from another terminal, then stop with Ctrl+C.
tail snort2-alerts.txt
```

Snort 3 example: put the same ICMP rule in a local `.rules` file. Select the configuration
that defines `HOME_NET`, then load both the configuration and that rule file.

```bash
read -r -p 'Snort 3 snort.lua path: ' CONF
read -r -p 'Local .rules path: ' RULES
read -r -p 'Lab interface: ' IFACE
snort -T -c "$CONF" -R "$RULES"
sudo snort -c "$CONF" -R "$RULES" -i "$IFACE" -A alert_fast 2>&1 | tee snort3-alerts.txt
# Generate the test ping, stop with Ctrl+C, then inspect the captured console output.
tail snort3-alerts.txt
```

For a repeatable capture/replay test, capture traffic on the chosen lab interface. `tcpdump`
is a separate system tool. Stop the capture after the test ping.

```bash
read -r -p 'Lab interface: ' IFACE
sudo tcpdump -i "$IFACE" -w lab.pcap
# Press Ctrl+C after the test traffic. Use the matching Snort version below.
snort -r lab.pcap -c "$CONF" -A console 2>&1 | tee replay-snort2.txt
# Snort 3 alternative, with CONF and RULES set for Snort 3:
snort -r lab.pcap -c "$CONF" -R "$RULES" -A alert_fast 2>&1 | tee replay-snort3.txt
```

Record the rule SID, source, destination, protocol and timestamp from actual alerts.
A matching ping rule demonstrates detection, not a proven intrusion. Explain false positives
and how a narrower rule would affect results. Console output captured by `tee` is the
log used here. Do not assume a separate `/var/log/snort/alert` file exists.

## 7. Exam checklist (Lab 8)
* Explain why the index uses deterministic tokens (and the leakage that implies).
* Show: build index → query → matching IDs → decrypted documents; a non-matching query → [].
* Never print or store plaintext keywords on the server side; keys stay with the client/owner.
* For PKSE say which party holds the private key and what the server learns.
