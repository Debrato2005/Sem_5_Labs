# INFORMATION SECURITY LAB — Combined Scenario Endsem Codebook

**Two complete exam solutions + reusable modular templates**  
Target: **PyCharm on Debian** · Python 3.10+ · `pycryptodome` · `phe`  
**Format:** all exam data, roles' passwords, file paths, candidates, constituencies, records, dates, and key bit sizes are entered at runtime. The cryptographic algorithms/key lengths explicitly required by each question remain fixed by the question.

> **Scope:** classroom demonstration only. It is NOT a production grant portal or deployable election platform. See the security limitations near the end. Use these as templates and adapt the named fields and menu actions when the examiner changes the scenario.

## 0. Installation and run in Debian PyCharm

Inside the PyCharm terminal, from your project directory:

```bash
uv venv .venv
uv pip install --python .venv/bin/python pycryptodome phe cryptography sympy numpy matplotlib ecdsa flask 'fastapi[standard]' psutil python-gnupg scapy
source .venv/bin/activate
python Secure_Grant_Expense_Portal_Menu.py
# Alternatively: python Secure_EVoting_Menu.py
```

If `uv` is not installed, install it first by a Debian-supported method (`pipx install uv`, where `pipx` is available). **Do not assume Debian's system Python allows `pip install` globally.** Configure PyCharm's interpreter to `.venv/bin/python`.

Dependencies actually used in the two complete scripts: **`pycryptodome`, `phe`**, plus Python standard library. All other installed packages are optional for extensions.

## 1. Translate a long scenario into components

| Examiner wording | Import / method | Reuse |
|---|---|---|
| AES-192 description | `AES.new(key_24_bytes, AES.MODE_CBC)` | Grant `add`, `reviewer_dump` |
| AES-256 ballot/file | `AES.new(key_32_bytes, AES.MODE_CBC)` | Election `cast`, `verify` |
| RSA-4096 public/private keys | `RSA.generate(bits)` | Election `setup` |
| RSA encrypt AES key | `PKCS1_OAEP.new(rsa_public, hashAlgo=SHA256)` | Election `cast` |
| MD5 of record | `MD5.new(canonical(record))` | Grant `payload`, `verify` |
| SHA-512 of ballot file | `hashlib.sha512(file.read()).hexdigest()` | Election `cast`, `verify` |
| RSA sign/verify hash | `pkcs1_15.new(private).sign(digest)` / `.verify(...)` | Grant `add`, `verify` |
| ElGamal sign/verify SHA-512 | `sign_elgamal` / `verify_elgamal` | Election helper functions |
| Paillier encrypt amount | `pub.encrypt(integer)` | Grant `add` |
| Paillier encrypted sum | `total_enc = enc1 + enc2` | Grant `total`, Election `final_tally` |
| Per-candidate vote counts | Encrypt **one-hot 0/1 per candidate**, add each column | Election `cast`, `final_tally` |
| Index search without revealing content | Index by clear ID, or keyed HMAC token | Grant `search`; Election `tag`, `search` |
| Timestamp authority | Verify a **signed timestamp**; local simulation is not an external TSA | Election `tsa_stamp`, `verify` |
| Threshold/authority split | Two independently held private-factor shares, combined at *final aggregate only* | Election `split_private`, `join_private` |
| Persistent storage | JSON files + reloaded persistent keys | Both `save`, `setup` |
| Role-based UI and authentication | Per-role password hashes + submenus | Both `create_roles`, `authorized`, `main` |
| Integrity failure | Verify before showing plaintext/tally | Both `verify` functions |

**Golden assembly rule:** `read input → encrypt → construct canonical record → hash → sign → persist → search/verify → only then decrypt or aggregate`.

---

# PART A — Secure Grant Expense Portal

## A1. Requirements → code paths

| Requirement | Implementation |
|---|---|
| Grant ID, description, amount | `add()` prompts |
| AES-192 description | 24 random key bytes, CBC IV stored |
| Paillier encrypted amount | `public.encrypt(scaled_integer)`; decimal precision user-selected |
| MD5 + RSA signature | Hash of canonical encrypted record and PKCS#1 v1.5 RSA signature |
| Earlier records visible on restart | Load existing JSON files in `setup()` |
| Reviewer verify and lookup by Grant ID | `verify`, `search` |
| Reviewer decrypted description as hex dump | `reviewer_dump` after verification |
| Finance aggregate selected IDs without decrypting amounts | `total`; encrypted additions first, decrypt **only aggregate** |
| Role-specific menu | Researcher, Reviewer, Finance Officer |
| Graceful bad data | Duplicate, missing, wrong precision, wrong signature, damaged data |

**How to save/run:** copy *the entire* A2 block into `Secure_Grant_Expense_Portal_Menu.py`. Start it from your project working directory. On first launch choose TWO distinct file paths, set login passwords and cryptographic parameters. On later launches enter the **same paths**. Do not delete the key file.

## A2. COMPLETE STANDALONE PROGRAM — menu-driven

```python
"""Educational exam demo: AES-192 + Paillier + MD5 + RSA; NOT production authentication."""
import json
import os
import hashlib
import hmac
from getpass import getpass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from phe import paillier


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def save(path, value, private=False):
    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(value, indent=2))
    if private:
        os.chmod(temp, 0o600)
    os.replace(temp, path)


def number(prompt, minimum=0):
    x = int(input(prompt))
    if x < minimum:
        raise ValueError(f'Must be at least {minimum}')
    return x



def create_roles(labels):
    result = {}
    for role, label in labels.items():
        secret = getpass(f'Set {label} login password: ')
        if not secret:
            raise ValueError('Role password must not be blank')
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt, 200000)
        result[role] = [salt.hex(), digest.hex()]
    return result


def authorized(roles, role):
    salt_hex, wanted = roles[role]
    actual = hashlib.pbkdf2_hmac('sha256', getpass('Role password: ').encode(),
                                bytes.fromhex(salt_hex), 200000)
    return hmac.compare_digest(actual.hex(), wanted)

def setup():
    key_name = input('Key JSON path: ').strip()
    db_name = input('Record JSON path: ').strip()
    if not key_name or not db_name:
        raise ValueError('File paths cannot be blank')
    kp, db = Path(key_name).expanduser(), Path(db_name).expanduser()
    if kp.resolve() == db.resolve():
        raise ValueError('Use distinct key and record file paths')
    if kp.exists() != db.exists():
        raise ValueError('Keys/records incomplete: restore the missing file')
    if kp.exists():
        saved = json.loads(kp.read_text())
        records = json.loads(db.read_text())
    else:
        places = number('Amount decimal places (e.g., 2): ', 0)
        rsa_bits = number('RSA key bits (>=2048): ', 2048)
        phe_bits = number('Paillier key bits (>=1024, 2048 preferred): ', 1024)
        public, private = paillier.generate_paillier_keypair(n_length=phe_bits)
        saved = {'aes': get_random_bytes(24).hex(),
                 'rsa': RSA.generate(rsa_bits).export_key().decode(),
                 'n': str(public.n), 'p': str(private.p), 'q': str(private.q),
                 'places': places, 'roles': create_roles({'1': 'Researcher', '2': 'Reviewer', '3': 'Finance Officer'})}
        records = {}
        save(kp, saved, private=True)
        save(db, records)
    public = paillier.PaillierPublicKey(int(saved['n']))
    private = paillier.PaillierPrivateKey(public, int(saved['p']), int(saved['q']))
    rsa = RSA.import_key(saved['rsa'])
    aes = bytes.fromhex(saved['aes'])
    if len(aes) != 24 or not isinstance(records, dict):
        raise ValueError('Invalid key/record format')
    return db, int(saved['places']), public, private, rsa, aes, records, saved['roles']


def payload(row):
    return {k: row[k] for k in ('id', 'iv', 'description', 'amount')}


def verify(row, rsa_public):
    try:
        digest = MD5.new(canonical(payload(row)))
        if digest.hexdigest() != row['md5']:
            return False
        pkcs1_15.new(rsa_public).verify(digest, bytes.fromhex(row['signature']))
        return True
    except (ValueError, TypeError, KeyError, OverflowError):
        return False


def add(records, db, places, public, rsa, aes):
    rid = input('Grant ID: ').strip()
    if not rid or rid in records:
        raise ValueError('Empty/duplicate Grant ID')
    desc = input('Grant description: ')
    value = Decimal(input('Grant amount: ').strip()) * (10 ** places)
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError('Amount exceeds configured decimal precision')
    amount = public.encrypt(int(value))
    cipher = AES.new(aes, AES.MODE_CBC)
    row = {'id': rid, 'iv': cipher.iv.hex(),
           'description': cipher.encrypt(pad(desc.encode(), 16)).hex(),
           'amount': str(amount.ciphertext())}
    digest = MD5.new(canonical(payload(row)))
    row['md5'] = digest.hexdigest()
    row['signature'] = pkcs1_15.new(rsa).sign(digest).hex()
    records[rid] = row
    save(db, records)
    print('Stored Grant ID:', rid, '| MD5:', row['md5'], '| Signed: yes')


def search(records, rsa):
    rid = input('Grant ID to search: ').strip()
    row = records.get(rid)
    if not row:
        print('Not found'); return
    print('Index hit:', rid, '| Integrity/authenticity:', 'VALID' if verify(row, rsa.publickey()) else 'FAILED')
    print('Encrypted contents are not displayed by the index search')


def reviewer_dump(records, rsa, aes):
    rid = input('Grant ID to decrypt description: ').strip()
    row = records.get(rid)
    if not row or not verify(row, rsa.publickey()):
        print('Record missing/tampered: decryption refused'); return
    raw = AES.new(aes, AES.MODE_CBC, bytes.fromhex(row['iv'])).decrypt(bytes.fromhex(row['description']))
    clear = unpad(raw, 16)
    print('Decrypted description hexadecimal dump:', clear.hex(' '))


def total(records, public, private, rsa, places):
    ids = [s.strip() for s in input('Selected Grant IDs (comma-separated): ').split(',') if s.strip()]
    if len(ids) < 2 or len(ids) != len(set(ids)):
        raise ValueError('Choose at least two distinct grants (never decrypt one amount)')
    missing = [rid for rid in ids if rid not in records]
    if missing:
        raise ValueError('Unknown Grant IDs: ' + ', '.join(missing))
    if any(not verify(records[rid], rsa.publickey()) for rid in ids):
        print('Tampered/invalid signature: aggregation refused'); return
    encrypted = [paillier.EncryptedNumber(public, int(records[rid]['amount']), 0) for rid in ids]
    aggregate = encrypted[0]
    for part in encrypted[1:]:
        aggregate += part  # Paillier addition; no individual decryption
    print('Verified records:', len(ids))
    print('Aggregated Paillier ciphertext:', aggregate.ciphertext())
    print('Final decrypted total:', format(Decimal(private.decrypt(aggregate)).scaleb(-places), 'f'))


def main():
    db, places, public, private, rsa, aes, records, roles = setup()
    while True:
        print('\n1 Researcher  2 Reviewer  3 Finance Officer  0 Exit')
        role = input('Role: ').strip()
        if role == '0':
            return
        try:
            if role in roles and not authorized(roles, role):
                print('Access denied'); continue
            if role == '1':
                while True:
                    print('\nResearcher: 1 Submit  2 View all encrypted records  0 Back')
                    c = input('Choice: ').strip()
                    if c == '0': break
                    if c == '1': add(records, db, places, public, rsa, aes)
                    elif c == '2':
                        for rid, row in records.items():
                            print('Grant:', rid, '\n', json.dumps(row, indent=2))
                    else: print('Unknown choice')
            elif role == '2':
                while True:
                    print('\nReviewer: 1 Search by ID  2 Verify and view decrypted hex  0 Back')
                    c = input('Choice: ').strip()
                    if c == '0': break
                    if c == '1': search(records, rsa)
                    elif c == '2': reviewer_dump(records, rsa, aes)
                    else: print('Unknown choice')
            elif role == '3':
                while True:
                    print('\nFinance: 1 Aggregate selected grants  2 Show IDs  0 Back')
                    c = input('Choice: ').strip()
                    if c == '0': break
                    if c == '1': total(records, public, private, rsa, places)
                    elif c == '2': print('Grant IDs:', ', '.join(records))
                    else: print('Unknown choice')
            else:
                print('Unknown role')
        except (ValueError, InvalidOperation, KeyError, TypeError, OverflowError, OSError) as exc:
            print('Error:', exc)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('Setup error:', exc)

```

## A3. Test plan (runtime input examples are up to you)

1. Start with **new** `key JSON` and `record JSON` paths. Choose amount precision, RSA/Paillier sizes and three independent role passwords.
2. Researcher → submit **two or more** grants with distinct IDs. The encrypted amount is never decrypted at submission.
3. Researcher → view earlier IDs → exit → relaunch using the same paths → confirm persistence.
4. Reviewer → search for an existing ID, a nonexistent ID, and display verified description bytes as hex.
5. Finance → choose two or more IDs → verify all signatures → show Paillier ciphertext and **only the final monetary sum**.
6. Close the program, edit one character of a record's stored ciphertext or encrypted amount in JSON, then run reviewer/finance again. Verification must fail and dependent decryption must be refused.
7. Try duplicate ID, malformed amount, excessive decimal precision, bad role password and a missing key file.

**Expected output properties:** MD5 is a 32-character hex digest; AES-192 uses a 24-byte key and 16-byte CBC IV; the Paillier ciphertext changes with randomized encryption; the decrypted sum must match the sum of user-entered amounts. Ciphertext hex values should **not** be expected to be stable across executions.

---

# PART B — Secure National E-Voting (educational model)

## B1. Exact requirements and necessary interpretation

- The voter chooses their **numeric candidate ID** and **constituency**, enrolled with an ElGamal signing public key; the private signing scalar is shown once for offline custody.
- Ballot bytes are written to a temporary file, **SHA-512 hashed**, AES-256-CBC encrypted, and wrapped with the commission's **RSA-4096 OAEP** public key.
- The ballot's **SHA-512 digest is signed with ElGamal**, and a second ElGamal signature authenticates the full encrypted submission envelope (including the encrypted voting vector and timestamp).
- The candidate ID itself is Paillier-encrypted for the literal wording. **Correct election tallying does not sum candidate IDs**: it also encrypts a *one-hot 0/1 vector for each candidate*, allowing one encrypted sum per candidate.
- The timestamp is signed by a **local simulated TSA**; verification enforces user-configured election dates. Real trusted time requires an external clock/TSA trust boundary.
- Search uses **keyed deterministic HMAC index tags** for constituency and voting date. Search returns ballot IDs, not candidate choices.
- Two secret shares are printed **only when the election database is created**. Two authorities must retain them **independently**. They are entered together to reconstruct the Paillier private key **for final aggregated ciphertexts only**. This is **NOT a formal threshold-Paillier scheme**; see security note.
- Commission can verify and search ballots, close voting, then perform the final tally; voter cannot submit after closure. Auditor can inspect metadata/verification status.

**How to save/run:** copy the complete B2 block into `Secure_EVoting_Menu.py` and execute. First launch: choose file names, candidates, voting window, cryptographic sizes, and three role passwords. Safeguard the two separate authority shares. Later launches: reuse those same file paths and passwords. **Losing either share permanently prevents final result recovery in this teaching demonstration.**

## B2. COMPLETE STANDALONE PROGRAM — menu-driven

```python
"""Educational e-voting composition; not safe for real elections or formal threshold HE."""
import hashlib
import hmac
import json
import math
from getpass import getpass
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, isPrime
from phe import paillier


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def save(path, value, private=False):
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2))
    if private:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def utc(text):
    instant = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('Use timezone-aware ISO timestamps, e.g., +00:00')
    return instant.astimezone(timezone.utc)


def ask_int(label, low=0):
    value = int(input(label))
    if value < low:
        raise ValueError(f'Value must be >= {low}')
    return value


def tag(key, field, value):
    return hmac.new(key, f'{field}:{str(value).strip().casefold()}'.encode(), hashlib.sha256).hexdigest()


def split_private(priv):
    """2-of-2 XOR shares of Paillier factors; requires joining at final tally."""
    a, b = [], []
    for prime in (priv.p, priv.q):
        mask = secrets.randbits(prime.bit_length() + 8)
        a.append(format(mask, 'x'))
        b.append(format(prime ^ mask, 'x'))
    return ':'.join(a), ':'.join(b)


def join_private(pub, a, b):
    try:
        x, y = [int(s, 16) for s in a.strip().split(':')], [int(s, 16) for s in b.strip().split(':')]
        if len(x) != 2 or len(y) != 2:
            raise ValueError('Each share must have p:q hex parts')
        p, q = x[0] ^ y[0], x[1] ^ y[1]
        if p * q != pub.n or p == q or not isPrime(p) or not isPrime(q):
            raise ValueError('Shares do not reconstruct the correct private key')
        return paillier.PaillierPrivateKey(pub, p, q)
    except (IndexError, ValueError, TypeError) as exc:
        raise ValueError('Invalid shares: ' + str(exc)) from exc



def create_roles(labels):
    result = {}
    for role, label in labels.items():
        secret = getpass(f'Set {label} login password: ')
        if not secret:
            raise ValueError('Role password cannot be blank')
        salt = os.urandom(16)
        result[role] = [salt.hex(), hashlib.pbkdf2_hmac('sha256', secret.encode(), salt, 200000).hex()]
    return result


def authorized(roles, role):
    salt, expected = roles[role]
    digest = hashlib.pbkdf2_hmac('sha256', getpass('Role password: ').encode(),
                                bytes.fromhex(salt), 200000).hex()
    return hmac.compare_digest(digest, expected)

def setup():
    keys_path = Path(input('Election key JSON path: ').strip()).expanduser()
    db_path = Path(input('Election database JSON path: ').strip()).expanduser()
    if keys_path.resolve() == db_path.resolve():
        raise ValueError('Key and database paths must differ')
    if keys_path.exists() != db_path.exists():
        raise ValueError('One persistent file is missing: restore it')
    if keys_path.exists():
        keys = json.loads(keys_path.read_text())
        db = json.loads(db_path.read_text())
    else:
        candidates = [int(x.strip()) for x in input('Numeric candidate IDs (comma-separated): ').split(',')]
        if len(candidates) < 2 or len(candidates) != len(set(candidates)):
            raise ValueError('Provide at least two unique candidate IDs')
        start = utc(input('Voting opens (ISO UTC with offset): '))
        end = utc(input('Voting closes (ISO UTC with offset): '))
        if end <= start:
            raise ValueError('End must be later than start')
        rsa_bits = ask_int('Commission RSA bits (4096 or more): ', 4096)
        phe_bits = ask_int('Paillier bits (>=1024; >=2048 preferred): ', 1024)
        commission = RSA.generate(rsa_bits)
        tsa = RSA.generate(rsa_bits)
        pub, priv = paillier.generate_paillier_keypair(n_length=phe_bits)
        auth1, auth2 = split_private(priv)
        print('\nSAVE THESE SHARES SEPARATELY. NOT STORED IN THIS PROGRAM.')
        print('Authority 1 share:', auth1)
        print('Authority 2 share:', auth2)
        print('Both shares are required to decrypt final aggregate totals.')
        keys = {'commission_rsa': commission.export_key().decode(),
                'local_tsa_rsa': tsa.export_key().decode(),
                'search': get_random_bytes(32).hex(), 'n': str(pub.n),
                'roles': create_roles({'1': 'Voter', '2': 'Election Commission', '3': 'Auditor'})}
        db = {'candidates': candidates, 'start': start.isoformat(), 'end': end.isoformat(),
              'closed': False, 'voters': {}, 'ballots': {}}
        save(keys_path, keys, private=True)
        save(db_path, db)
        del priv
    if not isinstance(db.get('ballots'), dict) or not isinstance(db.get('voters'), dict):
        raise ValueError('Invalid persistent database')
    return db_path, db, RSA.import_key(keys['commission_rsa']), RSA.import_key(keys['local_tsa_rsa']), \
        paillier.PaillierPublicKey(int(keys['n'])), bytes.fromhex(keys['search']), keys['roles']


def sign_elgamal(digest_bytes, p, g, x):
    digest = int.from_bytes(digest_bytes, 'big') % (p - 1)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            r = pow(g, k, p)
            s = (digest - x * r) * pow(k, -1, p - 1) % (p - 1)
            return [str(r), str(s)]


def verify_elgamal(digest_bytes, sig, pub):
    try:
        p, g, y = [int(pub[k]) for k in ('p', 'g', 'y')]
        r, s = map(int, sig)
        if not (1 <= r < p and 0 <= s < p - 1):
            return False
        digest = int.from_bytes(digest_bytes, 'big') % (p - 1)
        return pow(g, digest, p) == pow(y, r, p) * pow(r, s, p) % p
    except (ValueError, TypeError, KeyError, OverflowError):
        return False


def enroll(db, db_path):
    voter = input('New voter ID: ').strip()
    if not voter or voter in db['voters']:
        raise ValueError('Blank or already-registered voter ID')
    bits = ask_int('ElGamal prime bits (>=512; 2048+ recommended): ', 512)
    p = getPrime(bits)
    g = secrets.randbelow(p - 3) + 2
    x = secrets.randbelow(p - 2) + 1
    db['voters'][voter] = {'p': str(p), 'g': str(g), 'y': str(pow(g, x, p))}
    save(db_path, db)
    print('Registered voter:', voter)
    print('PRIVATE ElGamal signing key x (store privately, not in database):', format(x, 'x'))
    print('Public p, g, y stored. You must supply x when voting.')


def tsa_stamp(tsa, voter, digest, moment):
    proof = {'voter': voter, 'time': moment.isoformat(), 'sha512': digest}
    sig = pkcs1_15.new(tsa).sign(SHA256.new(canonical(proof)))
    return {'proof': proof, 'signature': sig.hex()}


def core(row):
    return {k: row[k] for k in ('voter', 'const_tag', 'day_tag', 'iv', 'ciphertext',
                               'wrapped_key', 'ballot_sha512', 'candidate_enc', 'votes_enc', 'stamp', 'ballot_signature')}


def cast(db, db_path, commission, tsa, public, search_key):
    if db['closed']:
        raise ValueError('Election already closed')
    now = datetime.now(timezone.utc)
    if not utc(db['start']) <= now <= utc(db['end']):
        raise ValueError('Current time is outside voting period')
    voter = input('Registered voter ID: ').strip()
    if voter not in db['voters'] or voter in db['ballots']:
        raise ValueError('Unknown voter or already voted')
    x = int(input('Your private ElGamal x (hex): ').strip(), 16)
    pub_sig = db['voters'][voter]
    p, g, y = (int(pub_sig[k]) for k in ('p', 'g', 'y'))
    if not 1 <= x < p - 1 or pow(g, x, p) != y:
        raise ValueError('Wrong signing key')
    constituency = input('Constituency ID: ').strip()
    candidate = ask_int('Selected numeric candidate ID: ')
    if not constituency or candidate not in db['candidates']:
        raise ValueError('Invalid constituency/candidate')
    ballot = {'voter': voter, 'constituency': constituency, 'candidate': candidate}
    raw = canonical(ballot)
    with tempfile.TemporaryFile() as ballot_file:
        ballot_file.write(raw)
        ballot_file.seek(0)
        digest = hashlib.sha512(ballot_file.read()).hexdigest()  # SHA-512 of ballot file bytes
    session = get_random_bytes(32)
    cipher = AES.new(session, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(raw, 16)).hex()
    wrapped = PKCS1_OAEP.new(commission.publickey(), hashAlgo=SHA256).encrypt(session).hex()
    moment = datetime.now(timezone.utc)
    stamp = tsa_stamp(tsa, voter, digest, moment)  # local TSA simulation
    row = {'voter': voter,
           'const_tag': tag(search_key, 'const', constituency),
           'day_tag': tag(search_key, 'day', moment.date().isoformat()),
           'iv': cipher.iv.hex(), 'ciphertext': ciphertext,
           'wrapped_key': wrapped, 'ballot_sha512': digest,
           'candidate_enc': str(public.encrypt(candidate).ciphertext()),
           'votes_enc': {str(c): str(public.encrypt(int(c == candidate)).ciphertext()) for c in db['candidates']},
           'stamp': stamp}
    row['ballot_signature'] = sign_elgamal(bytes.fromhex(digest), p, g, x)
    row['signature'] = sign_elgamal(hashlib.sha512(canonical(core(row))).digest(), p, g, x)
    db['ballots'][voter] = row
    save(db_path, db)
    print('Ballot encrypted/submitted; SHA-512:', digest)
    print('AES-256 CBC ciphertext (hex):', ciphertext)
    print('RSA-wrapped session key (hex):', wrapped)
    print('Encrypted candidate ID:', row['candidate_enc'])
    print('ElGamal ballot SHA-512 signature:', row['ballot_signature'])
    print('ElGamal encrypted-envelope signature:', row['signature'])
    print('Locally signed timestamp:', stamp['proof']['time'])


def verify(row, db, commission, tsa, search_key):
    try:
        voter = row['voter']
        sig_pub = db['voters'][voter]
        if not verify_elgamal(bytes.fromhex(row['ballot_sha512']), row['ballot_signature'], sig_pub):
            return False, 'ElGamal ballot-hash signature failed'
        if not verify_elgamal(hashlib.sha512(canonical(core(row))).digest(), row['signature'], sig_pub):
            return False, 'ElGamal envelope signature failed'
        stamp = row['stamp']
        pkcs1_15.new(tsa.publickey()).verify(
            SHA256.new(canonical(stamp['proof'])), bytes.fromhex(stamp['signature']))
        proof = stamp['proof']
        when = utc(proof['time'])
        if proof['voter'] != voter or proof['sha512'] != row['ballot_sha512']:
            return False, 'Timestamp is not bound to ballot'
        if not utc(db['start']) <= when <= utc(db['end']):
            return False, 'Outside election period'
        if row['day_tag'] != tag(search_key, 'day', when.date().isoformat()):
            return False, 'Time index mismatch'
        session = PKCS1_OAEP.new(commission, hashAlgo=SHA256).decrypt(bytes.fromhex(row['wrapped_key']))
        plaintext = unpad(AES.new(session, AES.MODE_CBC, bytes.fromhex(row['iv']))
                          .decrypt(bytes.fromhex(row['ciphertext'])), 16)
        if hashlib.sha512(plaintext).hexdigest() != row['ballot_sha512']:
            return False, 'Ballot SHA-512 mismatch'
        ballot = json.loads(plaintext)
        if (ballot['voter'] != voter or
                row['const_tag'] != tag(search_key, 'const', ballot['constituency']) or
                ballot['candidate'] not in db['candidates']):
            return False, 'Ballot identity/index mismatch'
        if set(row['votes_enc']) != set(map(str, db['candidates'])):
            return False, 'Encrypted candidate vector mismatch'
        return True, 'Verified: hash, signature, timestamp, searchable tags'
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError) as exc:
        return False, type(exc).__name__ + ' (tampered/invalid record)'


def inspect(db, commission, tsa, search_key):
    voter = input('Ballot voter ID to verify: ').strip()
    if voter not in db['ballots']:
        print('No ballot'); return
    good, reason = verify(db['ballots'][voter], db, commission, tsa, search_key)
    print('VALID' if good else 'INVALID', '|', reason)
    print('No plaintext vote is displayed')


def search(db, search_key):
    print('Search: 1 Constituency  2 UTC time interval')
    mode = input('Choice: ').strip()
    if mode == '1':
        key = tag(search_key, 'const', input('Constituency ID: '))
        found = [v for v, row in db['ballots'].items() if row.get('const_tag') == key]
    elif mode == '2':
        start, end = utc(input('From (ISO with timezone): ')), utc(input('To (ISO with timezone): '))
        if end < start or (end - start).days > 366:
            raise ValueError('Invalid/overly broad time interval')
        days = set()
        day = start.date()
        while day <= end.date():
            days.add(tag(search_key, 'day', day.isoformat()))
            day += timedelta(days=1)
        found = [v for v, row in db['ballots'].items()
                 if row.get('day_tag') in days and
                 start <= utc(row['stamp']['proof']['time']) <= end]
    else:
        print('Unknown search'); return
    print('Matching encrypted ballot IDs:', found)
    print('No ballot contents revealed by the search')


def close(db, path):
    if input('Type CLOSE to end voting and freeze submissions: ').strip() == 'CLOSE':
        db['closed'] = True
        save(path, db)
        print('Election closed')


def final_tally(db, public, commission, tsa, search_key):
    if not db['closed']:
        raise ValueError('Close voting before FINAL tally')
    verified = []
    for row in db['ballots'].values():
        good, why = verify(row, db, commission, tsa, search_key)
        if not good:
            print('Invalid ballot:', row.get('voter'), why, '— tally aborted')
            return
        verified.append(row)
    if len(verified) < 2:
        raise ValueError('At least two ballots required for this demonstration')
    totals = {}
    for candidate in db['candidates']:
        values = [paillier.EncryptedNumber(public, int(r['votes_enc'][str(candidate)]), 0)
                  for r in verified]
        aggregate = values[0]
        for value in values[1:]:
            aggregate += value  # no individual vote ciphertext is decrypted
        totals[candidate] = aggregate
        print('Candidate', candidate, 'aggregated ciphertext:', aggregate.ciphertext())
    authority1 = input('Authority 1 Paillier share: ')
    authority2 = input('Authority 2 Paillier share: ')
    private = join_private(public, authority1, authority2)
    print('Final aggregate counts (no individual decryption):')
    for candidate, aggregate in totals.items():
        print('Candidate', candidate, ':', private.decrypt(aggregate))


def main():
    db_path, db, commission, tsa, public, search_key, roles = setup()
    while True:
        print('\n1 Voter  2 Election Commission  3 Auditor  0 Exit')
        role = input('Role: ').strip()
        if role == '0': return
        try:
            if role in roles and not authorized(roles, role):
                print('Access denied'); continue
            if role == '1':
                while True:
                    print('\nVoter: 1 Register  2 Cast ballot  3 View submitted ballot IDs  0 Back')
                    c = input('Choice: ').strip()
                    if c == '0': break
                    if c == '1': enroll(db, db_path)
                    elif c == '2': cast(db, db_path, commission, tsa, public, search_key)
                    elif c == '3': print('Submitted IDs:', list(db['ballots']))
                    else: print('Unknown choice')
            elif role == '2':
                while True:
                    print('\nCommission: 1 Verify ballot  2 Search index  3 Close election  4 Final encrypted tally  0 Back')
                    c = input('Choice: ').strip()
                    if c == '0': break
                    if c == '1': inspect(db, commission, tsa, search_key)
                    elif c == '2': search(db, search_key)
                    elif c == '3': close(db, db_path)
                    elif c == '4': final_tally(db, public, commission, tsa, search_key)
                    else: print('Unknown choice')
            elif role == '3':
                print('Auditor: ballot IDs, signed timestamp, verification result (no plaintext)')
                for voter, row in db['ballots'].items():
                    valid, msg = verify(row, db, commission, tsa, search_key)
                    print(voter, '|', row.get('stamp', {}).get('proof', {}).get('time'), '|', 'VALID' if valid else 'INVALID', msg)
            else: print('Unknown role')
        except (ValueError, OSError, KeyError, TypeError, OverflowError) as exc:
            print('Error:', exc)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('Setup error:', exc)

```

## B3. Test plan

1. On initial start, enter **two or more numeric candidate IDs** and an election period that includes the test time (timezone-aware ISO 8601, e.g., an appropriate UTC interval). Set role passwords.
2. Securely record each of the two printed authority shares **separately**. Do not put both into the database.
3. Voter → register, save the displayed private ElGamal `x` offline, then cast once using `x`, candidate ID, and constituency.
4. Register at least one **other** voter and cast. Check that one voter cannot cast twice; bogus keys and invalid candidate IDs are rejected.
5. Commission → verify ballot (SHA-512, *two* ElGamal signatures, RSA unwrap, local TSA signature, signed time bounds), search by constituency and UTC time range.
6. Auditor → inspect status without printing ballot plaintext.
7. Commission → close election; try to cast again (must be rejected). Then aggregate every accepted encrypted **one-hot** vector and enter both authority shares; final counts should equal the submitted votes.
8. Edit a stored ciphertext, HMAC search tag, Paillier tally field or timestamp; verification and tally should reject the damaged ballot.
9. Restart with the same JSON files; check that ballots, voter public keys, candidate list and closed-state survive.

**Important test condition:** use an actual voting interval containing *the current UTC time*. The program deliberately refuses ballots outside the window.

---

# PART C — Small reusable building blocks (paste only what the question needs)

These snippets are deliberately independent of scenario names. Copy the snippet and its imports, then connect it to the appropriate menu action. Pass values as function parameters; **never embed exercise-specific messages, amounts, candidate IDs, dates or passwords in the code**.

## C1. Generic AES CBC — key length chooses AES-128/192/256

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(message: bytes, key: bytes):
    if len(key) not in (16, 24, 32): raise ValueError('Use 16/24/32 byte key')
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv.hex(), cipher.encrypt(pad(message, 16)).hex()

def aes_decrypt(iv_hex, ciphertext_hex, key):
    return unpad(AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex))
                 .decrypt(bytes.fromhex(ciphertext_hex)), 16)

key = bytes.fromhex(input('AES key hex (32/48/64 digits): '))
plaintext = input('Text: ').encode()
iv, ciphertext = aes_encrypt(plaintext, key)
print('IV:', iv, 'Ciphertext:', ciphertext)
print('Decrypted hex:', aes_decrypt(iv, ciphertext, key).hex(' '))
```

If the question says **random key**, replace the key-reading line with `key = get_random_bytes(int(input('AES bits 128/192/256: ')) // 8)` **after checking that the entered number is in {128,192,256}**. CBC does not authenticate ciphertext by itself; verify a signature/MAC first or use AES-GCM when permitted.

## C2. MD5 / SHA-512 over any exact object

```python
import hashlib, json

def canonical(x): return json.dumps(x, sort_keys=True, separators=(',', ':')).encode()
def digest_bytes(data, algorithm): return hashlib.new(algorithm, data).digest()

record = {'id': input('ID: '), 'description': input('Description: ')}
name = input('Algorithm (md5/sha512/sha256): ').lower()
h = digest_bytes(canonical(record), name)
print(name.upper(), h.hex())
```

For a file, use `digest_bytes(open(input('File: '), 'rb').read(), name)`. Hash exactly the plaintext **or ciphertext** specified by the question. Never hash a Python `repr()` with unstable field ordering. MD5 must be used when explicitly prescribed, but is **not collision-resistant** and should be replaced by SHA-256/512 in real deployments.

## C3. RSA digital signature — sign and verify a hash

```python
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA256, SHA512
from Crypto.Signature import pkcs1_15

hash_type = input('MD5/SHA256/SHA512: ').upper()
H = {'MD5': MD5, 'SHA256': SHA256, 'SHA512': SHA512}[hash_type]
key = RSA.generate(int(input('RSA key bits (>=2048): ')))
message = input('Message: ').encode()
signature = pkcs1_15.new(key).sign(H.new(message))
try:
    pkcs1_15.new(key.publickey()).verify(H.new(message), signature)
    print('VALID', signature.hex())
except (ValueError, TypeError): print('INVALID')
```

For the grant problem, the signed input is **canonical encrypted-record bytes**; use `H = MD5`. For a changed requirement use `SHA256` or `SHA512`. In full scenarios **persist keys**; do not regenerate on every restart.

## C4. RSA-OAEP — encrypt/decrypt an AES session key

```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

rsa = RSA.generate(int(input('RSA bits (>=2048): ')))
aes_bits = int(input('AES bits (128/192/256): '))
if aes_bits not in (128, 192, 256): raise ValueError('Invalid AES key length')
session = get_random_bytes(aes_bits // 8)
wrapped = PKCS1_OAEP.new(rsa.publickey(), hashAlgo=SHA256).encrypt(session)
recovered = PKCS1_OAEP.new(rsa, hashAlgo=SHA256).decrypt(wrapped)
print('RSA-wrapped key:', wrapped.hex(), '| Same AES key:', recovered == session)
```

Use RSA only to wrap a small key; large files belong under AES. The election problem requires `RSA bits = 4096` and `AES bits = 256`.

## C5. Paillier — persist/reload, add, multiply by public scalar

```python
from phe import paillier

bits = int(input('Paillier key bits: '))
pub, priv = paillier.generate_paillier_keypair(n_length=bits)
values = [int(x.strip()) for x in input('Integer amounts (comma-separated): ').split(',')]
if not values: raise ValueError('Provide amounts')
ciphertexts = [pub.encrypt(x) for x in values]
saved_numbers = [str(x.ciphertext()) for x in ciphertexts]
restored = [paillier.EncryptedNumber(pub, int(x), 0) for x in saved_numbers]
total = restored[0]
for item in restored[1:]: total += item
factor = int(input('Public scale/weight: '))
print('Encrypted sum:', total.ciphertext())
print('Decrypted sum (final ONLY):', priv.decrypt(total))
print('Encrypted weighted sum:', (total * factor).ciphertext())
```

In an actual scenario **persist the keypair once** (or use a threshold custody solution); use user-selected monetary decimal precision to convert decimal amounts to fixed-point integers before encryption.

## C6. Paillier candidate counts — correctly count votes

```python
from phe import paillier

candidates = [int(x) for x in input('Candidate IDs (comma-separated): ').split(',')]
votes = [int(x) for x in input('Selected candidate IDs (comma-separated): ').split(',')]
if len(set(candidates)) != len(candidates) or any(v not in candidates for v in votes):
    raise ValueError('Invalid/duplicate candidate or invalid vote')
pub, priv = paillier.generate_paillier_keypair(n_length=int(input('Paillier bits: ')))
for candidate in candidates:
    parts = [pub.encrypt(int(v == candidate)) for v in votes]
    if not parts: continue
    encrypted_count = parts[0]
    for part in parts[1:]: encrypted_count += part
    print('Candidate', candidate, 'aggregate count:', priv.decrypt(encrypted_count))
```

**Never use** `sum(pub.encrypt(candidate_id))` for the number of votes per candidate. That computes only the numerical sum of IDs. A secure real election additionally needs voter eligibility, double-vote prevention, ballot validity proofs, anonymity, independent auditing, and genuine threshold cryptography.

## C7. ElGamal digital signature — from the full election solution

Copy **`sign_elgamal()`** and **`verify_elgamal()`** from B2. Both accept a **precomputed digest as bytes**, then calculate the signature over its numeric value modulo `p-1`. Required inputs: a suitable prime `p`, generator `g`, private exponent `x`, and public value `y=pow(g,x,p)`. The signature is a pair `(r,s)` and verification checks

`pow(g, H, p) == pow(y, r, p) * pow(r, s, p) % p`.

To sign `SHA-512(message)`: `sign_elgamal(hashlib.sha512(message).digest(), p, g, x)`. The full example stores the **public** voter key and asks for their **private** signing exponent at submission. Reusing an ElGamal signing nonce is dangerous; use fresh `secrets` randomness every time. The exam implementation does not prove its randomly chosen `g` is a generator: it is a teaching example, not cryptographic validation.

## C8. Searchable index — equality tokens plus date-range filter

```python
import hmac, hashlib
from datetime import date, timedelta

def token(k: bytes, label: str, text: str):
    return hmac.new(k, f'{label}:{text.strip().casefold()}'.encode(), hashlib.sha256).hexdigest()

secret_key = bytes.fromhex(input('32-byte search key (64 hex): '))
constituency = input('Constituency: ')
stored_tag = token(secret_key, 'const', constituency)
query = input('Constituency to search: ')
print('Search matches:', hmac.compare_digest(stored_tag, token(secret_key, 'const', query)))
```

In B2, the search uses stored *constituency/day* tokens and returns IDs, not vote ciphertext or plaintext. Tags still leak equality/access patterns; they are **not a proof of fully secure searchable encryption**. Randomized AES-CBC, RSA-OAEP and Paillier ciphertexts cannot be searched by naive ciphertext equality.

## C9. Timestamp / deadline input validation

```python
from datetime import datetime, timezone

def utc(s):
    d = datetime.fromisoformat(s.replace('Z', '+00:00'))
    if d.tzinfo is None: raise ValueError('Include UTC offset')
    return d.astimezone(timezone.utc)

start = utc(input('Start ISO timestamp: '))
end = utc(input('End ISO timestamp: '))
received = utc(input('Signed receipt timestamp: '))
print('Within deadline:', start <= received <= end)
```

A timestamp read from the local clock is **not trusted by itself**. B2 demonstrates a simulated authority that signs a `proof`, then a verifier checks its RSA signature. A real authority would have independent custody of its private key and an independently authenticated time source.

## C10. Persistent JSON pattern — no data loss on restart

```python
import json, os
from pathlib import Path

def save(path, data):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)

path = Path(input('JSON database path: '))
records = json.loads(path.read_text()) if path.exists() else {}
record_id = input('Record ID: ')
if not record_id or record_id in records: raise ValueError('Invalid/duplicate ID')
records[record_id] = {'description': input('Text: ')}
save(path, records)
print('Stored IDs:', list(records))
```

For *encrypted* scenarios save **encrypted fields**, signatures, hashes, and public metadata, not the plaintext `description` used in this generic persistence demonstration. Keep key files separate, with restricted filesystem access.

## C11. Graceful tampering test (modify only a test copy)

```python
import copy

record = copy.deepcopy(existing_record)  # supplied by your running program
name = input('Ciphertext field to tamper with: ').strip()
if name not in record or not isinstance(record[name], str) or not record[name]:
    raise ValueError('Choose a populated string ciphertext field')
record[name] = ('0' if record[name][0] != '0' else '1') + record[name][1:]
print('Verification result:', verify(record, public_key))  # adapt verifier signature
```

`existing_record`, `verify`, and `public_key` are **intentionally integration placeholders**, not a standalone script. Never corrupt your only original record; a normal verifier must return invalid and **not decrypt**.

## C12. Role authentication + submenu skeleton

```python
# Attach the role-specific operation functions from Part A or Part B.
roles = {'1': ('Researcher', researcher_menu),
         '2': ('Reviewer', reviewer_menu),
         '3': ('Finance Officer', finance_menu)}
while True:
    print('1 Researcher  2 Reviewer  3 Finance  0 Exit')
    option = input('Role: ').strip()
    if option == '0': break
    if option not in roles: print('Invalid role'); continue
    if authorized(role_hashes, option):  # password verifier from A2/B2
        roles[option][1]()
    else: print('Access denied')
```

`researcher_menu`, `reviewer_menu`, `finance_menu`, `role_hashes` are component hooks: **connect to your scenario**. Your standalone Part A and B programs already provide complete functional menus.

---

# PART D — How to rewrite either program when the exam question changes

| Change to requirement | Minimal modification |
|---|---|
| AES-192 → AES-256 | Create 32-byte key instead of 24; CBC block size stays 16 bytes |
| CBC → GCM | Use `AES.MODE_GCM`; save nonce/tag; `decrypt_and_verify`; no PKCS#7 padding |
| MD5 → SHA-256 | Replace `MD5.new()` with `SHA256.new()` in **both** sign and verify |
| MD5 → SHA-512 | Replace with `Crypto.Hash.SHA512` in **both** sign and verify |
| RSA signature → ElGamal | Use `sign_elgamal(hashlib.sha512(payload).digest(),p,g,x)` and corresponding verify |
| User-entered AES key/IV | Parse `bytes.fromhex(input())`, validate key length 24/32 and IV length 16 |
| Grant Amount → Salary/Marks/Cost | Rename fields; keep fixed-point integer Paillier storage and aggregation |
| Single total → department-specific total | Filter verified records by authorized metadata before encrypted addition |
| Per-candidate votes → per-category inventory | Replace `candidate` with selected category and keep encrypted one-hot counts |
| Search Grant ID → Employee ID | Change index key and user prompt; don't decrypt merely to match |
| Search by private string | Store/search deterministic HMAC tokens with separate search key |
| Persist in SQLite | Replace `json.load/dump` with `sqlite3`, `PRIMARY KEY` ID; retain cryptographic fields |
| Timestamp signed by TSA | Signed data must include timestamp + record ID/digest; verify under TSA public key |
| Split authority final decryption | Supply separate independent shares; never output per-record decrypted amounts |
| Multiple submenus | Map role choice to permitted functions, verify a configured role password |
| Reviewer must not see plaintext | Omit/deactivate the description-dump function and show only validity |
| Detect tampering | Verify exact bytes of signed record before decryption/tally; do not silently continue |
| Show hexadecimal dump | `plaintext_bytes.hex(' ')`, not `ciphertext.hex()` |

## D1. Correct operation order for mixed questions

```text
INPUT (role + ID + details)
  → VALIDATE (unique ID, amounts, choice, deadline, permissions)
  → ENCRYPT DATA (AES/Paillier)
  → WRAP SESSION KEY (RSA, if specified)
  → BUILD ENCRYPTED RECORD (IV + ciphertext + encrypted amount/vote + metadata)
  → HASH EXACT REQUIRED OBJECT (MD5/SHA-512)
  → SIGN (RSA/ElGamal private key)
  → PERSIST (ciphertexts + hashes + signatures + search tags)

RECEIVER/REVIEWER
  → LOOKUP BY INDEX
  → VERIFY SIGNATURE + HASH + TIMESTAMP/POLICY
  → REJECT IF INVALID
  → DECRYPT ONLY AUTHORIZED FIELDS OR OUTPUT AUTHORIZED METADATA

FINANCE / ELECTION AUTHORITY
  → FILTER AND VERIFY ALL SELECTED RECORDS
  → ADD PAILLIER CIPHERTEXTS (never decrypt individual items)
  → REQUIRE FINAL-TALLY POLICY / BOTH SHARES AS APPLICABLE
  → DECRYPT ONLY AGGREGATED CIPHERTEXT
```

## D2. Critical correctness and security notes

1. **MD5 is collision-broken.** The grant problem explicitly requires it, so the code uses it. For any non-exam system, prefer modern digests and authenticated encryption.
2. **Role menu + local password hash is not full access-control isolation.** These single-process demos hold private materials on one filesystem. In a real system, use separately authenticated users, OS/DB permissions, a backend service, secret management and independent key custody.
3. **Paillier is additively homomorphic only.** Do not claim that it enables arbitrary encrypted comparisons or multiplication of two encrypted operands.
4. **A sum of encrypted candidate numbers is NOT a vote count.** Use one-hot encodings and one sum per candidate, plus validity proofs in a genuine election.
5. **The election's two XOR shares enable 2-person key reconstruction, not threshold Paillier decryption.** Both authorities' shares are combined inside a single process to recover `p` and `q`; the true threshold requirement would need a purpose-built threshold-Paillier protocol and independent custody, and is **not fully implemented** here.
6. **A locally signed time is not an independently trusted timestamp.** B2's local simulated TSA verifies a signature/period, but not a real trusted external authority.
7. **AES-CBC is not authenticated encryption.** Signing the encrypted envelope detects tampering before decryption in these demos. For production choose AEAD (e.g., AES-GCM), with clearly bound metadata.
8. **Vote privacy and non-repudiation are not absolute here.** A commission RSA private-key holder can decrypt ballot envelopes; voter IDs and metadata are stored. Real anonymous e-voting needs verified eligibility, anonymous credentials/ballots, no linkable voter-choice plaintext, safeguards against coercion, and independent audits.
9. **No ZK proof of ballot validity exists in this demo.** A malicious client could encrypt invalid one-hot vectors or ciphertexts. The system illustrates honest-client workflows, not malicious-voter security.
10. **Repeated overlapping grant aggregate queries leak individual values by differencing.** The sample rejects a single-item total, but that alone is insufficient. Real finance systems require controlled reporting policies and minimum group thresholds.
11. **Cryptographic randomness means outputs change.** Compare decrypted totals, signature validity, stored fields, and round-trip integrity rather than hardcoded ciphertext bytes.
12. **Preserve all keys and authority shares.** Re-generating keys on restart breaks old ciphertext/signature verification; loss of shares prevents final election result recovery.

## D3. Pre-exam checklist

- [ ] The correct PyCharm interpreter points to `endsem_exam/.venv/bin/python`.
- [ ] `from Crypto.Cipher import AES; from phe import paillier` imports without error.
- [ ] The examiner's **exact algorithm and key lengths** are used, with keys, values and paths read/generated at runtime.
- [ ] A main **role menu and individual submenus** are present.
- [ ] Every role does only its permitted tasks after authentication.
- [ ] Records and cryptographic keys survive restart; old values are not overwritten.
- [ ] Reviewer verifies hash AND signature; invalid records do not decrypt.
- [ ] AES-192=24-byte key; AES-256=32-byte key; CBC IV=16 bytes.
- [ ] Finance uses `EncryptedNumber + EncryptedNumber`, not decrypted values.
- [ ] Per-candidate count uses **one-hot encrypted votes**, not candidate-ID sums.
- [ ] Final tally decrypts only **aggregate** values.
- [ ] Errors (duplicates, tampering, missing ID, invalid input, bad shares) are handled.
- [ ] Outputs demonstrate every required function, including a bad-record test.

---

**Source grounding:** Both questions were supplied in this conversation. The Paillier/ElGamal experiments were cross-checked against the uploaded *IS Lab Manual [7–8]*, especially Lab 7; the cryptographic composition follows the uploaded Lab 1–6 materials and the earlier modular Lab 7/8 codebooks. Where the manual suggests mathematically invalid ElGamal encrypted comparisons or imitation Paillier construction, this codebook intentionally uses valid homomorphic **addition**, and calls out unsupported threshold properties rather than pretending they were implemented.
