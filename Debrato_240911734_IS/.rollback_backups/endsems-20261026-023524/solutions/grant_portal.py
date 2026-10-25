"""SECURE GRANT EXPENSE PORTAL  (end-sem sample question 1) - menu driven.
SECURE GRANT EXPENSE PORTAL
Scenario:
A research institute manages grant expenses through an online portal. Researchers submit grant details, reviewers check their integrity and authenticity, and the finance officer computes the total grant expenditure. The system must keep grant data confidential and verifiable, and the total must be computed without decrypting individual amounts.
Requirements:
Researcher side: The researcher enters a Grant ID, Grant Description and Grant Amount. Before storing, the system:
Encrypts the grant description with AES-192.
Encrypts the grant amount with the Paillier cryptosystem.
Computes an MD5 hash of the grant record.
Signs the hash with an RSA digital signature.
The researcher can submit grant details, and view all submitted records, including those entered earlier.
Reviewer side: The reviewer verifies the RSA signature and recomputes the MD5 hash to detect tampering. The reviewer can search the stored records by index (Grant ID) without exposing the encrypted contents. The reviewer can also view the AES-192 decrypted grant description as a hexadecimal dump.
Finance Officer side: The finance officer homomorphically aggregates the Paillier-encrypted amounts of the selected grants. The officer then verifies the signatures and decrypts only the final aggregate, never individual amounts.
Task:
Write a menu-driven Python program implementing the above roles and functions. Use role-based menus and cryptographic operations for confidentiality, integrity and authenticity. Store the encrypted, hashed and signed records persistently (file or database), so that earlier entries remain visible after a restart. Handle invalid input and tampered records gracefully. Display outputs for all functions.
Note: If the Python code is not menu-driven, the total marks obtained will be reduced to half.

Researcher : enter Grant ID / description / amount
             description -> AES-192-CBC, amount -> Paillier, MD5(record) -> RSA signature
             submit; view ALL stored records (persist across restarts)
Reviewer   : verify RSA signature + recompute MD5 (tamper detection);
             search by Grant ID through a keyed blind index (HMAC token) without
             showing encrypted contents; decrypt description -> hex dump
Finance    : verify signatures, homomorphically add selected Paillier amounts,
             decrypt ONLY the aggregate (never an individual amount)

Key custody: each role's keys are sealed under that role's password
(PBKDF2 + AES-GCM), so a role physically cannot use another role's keys:
  Researcher {AES key, RSA private, index key}   Reviewer {AES key, index key}
  Finance    {Paillier private, index key}        public: RSA public, Paillier n
What is hashed/signed: the canonical JSON of the STORED record (Grant ID,
IV, AES ciphertext, Paillier ciphertext, timestamp), so changing any stored
byte is detected without decrypting anything.

Run:  python solutions/grant_portal.py [data_folder]      (default ./grant_data)
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # TOOLKIT-PATH
import json
import os

from Crypto.Random import get_random_bytes

from toolkit.util import (AuditLog, ask, ask_amount, ask_choice, ask_list, ask_secret, canonical,
                          fmt_amount, hexdump, load_json, menu, now_iso, save_json, tamper_hex)
from toolkit.symmetric import aes_cbc_decrypt, aes_cbc_encrypt, password_open, password_seal
from toolkit.asymmetric import rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import rsa_sign, rsa_verify
from toolkit.homomorphic import paillier_add, paillier_decrypt, paillier_encrypt, paillier_keygen
from toolkit.searchable import token

DATA = sys.argv[1] if len(sys.argv) > 1 else 'grant_data'
KEYS = os.path.join(DATA, 'keys.json')
DB = os.path.join(DATA, 'grants.json')
LOG = AuditLog(os.path.join(DATA, 'audit.log'))
ROLES = ('Researcher', 'Reviewer', 'Finance Officer')
PLACES = 2                                   # amounts stored as integer cents
SIGNED = ('grant_id', 'desc_iv', 'desc_ct', 'amount_ct', 'timestamp')


# ------------------------------------------------------------------ setup ---
def first_run_setup():
    print('\nFIRST RUN - generating AES-192, RSA-2048 and Paillier-2048 keys ...')
    aes = get_random_bytes(24)                       # AES-192 = 24-byte key
    rsa = rsa_generate(2048)
    p_pub, p_priv = paillier_keygen(2048)
    idx = get_random_bytes(32).hex()                 # blind-index (search) key
    secret = {'Researcher': {'aes': aes.hex(), 'rsa': rsa.export_key().decode(), 'idx': idx},
              'Reviewer': {'aes': aes.hex(), 'idx': idx},
              'Finance Officer': {'paillier': p_priv, 'idx': idx}}
    vaults = {}
    for role in ROLES:
        while True:
            pw = ask_secret(f'Set password for {role}: ')
            if pw:
                break
            print('  ! blank password not allowed')
        vaults[role] = password_seal(pw, canonical(secret[role]))
    keys = {'rsa_pub': rsa.publickey().export_key().decode(), 'paillier_pub': p_pub,
            'vaults': vaults}
    save_json(KEYS, keys)
    print('Keys saved to', KEYS, '(private keys only inside password vaults)')
    return keys


def load_state():
    if not os.path.exists(KEYS):
        if os.path.exists(DB):
            raise SystemExit('grants.json exists but keys.json is missing - cannot verify records')
        keys = first_run_setup()
    else:
        keys = load_json(KEYS, None)
    db = load_json(DB, {})
    if not isinstance(db, dict) or any(not isinstance(r, dict) for r in db.values()):
        raise SystemExit('grants.json is malformed')
    return keys, db


def login(keys, role):
    try:
        sec = json.loads(password_open(ask_secret(f'{role} password: '), keys['vaults'][role]))
    except ValueError:
        LOG.log(role, 'LOGIN FAILED')
        print('  ACCESS DENIED - wrong password')
        return None
    LOG.log(role, 'login')
    return sec


# --------------------------------------------------------- crypto checks ---
def verify(rec, keys):
    """-> (ok, reason).  Recompute MD5 over the signed fields, compare with the
    stored MD5, then verify the RSA signature with the researcher PUBLIC key."""
    try:
        body = canonical({k: rec[k] for k in SIGNED})
        recomputed = digest(body, 'md5')
        if recomputed != rec['md5']:
            return False, f'MD5 MISMATCH stored={rec["md5"]} recomputed={recomputed}'
        if not rsa_verify(rsa_import(keys['rsa_pub']), body, rec['signature'], 'md5'):
            return False, 'RSA SIGNATURE INVALID'
        return True, f'MD5 matches ({recomputed}) and RSA signature valid'
    except (KeyError, TypeError, ValueError) as e:
        return False, f'MALFORMED record ({type(e).__name__})'


def find(db, sec, gid):
    """Index search: Grant ID -> HMAC token -> record (no scan, no decryption)."""
    return db.get(token(sec['idx'], gid, 'grant'))


def short(v, n=48):
    s = str(v)
    return s if len(s) <= n else f'{s[:n]}... ({len(s)} chars)'


# ------------------------------------------------------------ researcher ---
def submit(keys, db, sec):
    gid = ask('Grant ID: ')
    tok = token(sec['idx'], gid, 'grant')
    if tok in db:
        raise ValueError(f'Grant ID {gid!r} already exists')
    desc = ask('Grant description: ')
    amount = ask_amount('Grant amount: ', PLACES)
    iv, ct = aes_cbc_encrypt(bytes.fromhex(sec['aes']), desc.encode())     # AES-192
    rec = {'grant_id': gid, 'desc_iv': iv.hex(), 'desc_ct': ct.hex(),
           'amount_ct': paillier_encrypt(keys['paillier_pub'], amount),    # Paillier
           'timestamp': now_iso()}
    body = canonical(rec)
    rec['md5'] = digest(body, 'md5')                                       # MD5
    rec['signature'] = rsa_sign(rsa_import(sec['rsa']), body, 'md5')       # RSA sign MD5
    db[tok] = rec
    save_json(DB, db)
    LOG.log('Researcher', 'submit', gid)
    print('\nStored grant', gid)
    print('  AES-192 ciphertext :', rec['desc_ct'])
    print('  Paillier ciphertext:', short(rec['amount_ct']))
    print('  MD5 of record      :', rec['md5'])
    print('  RSA signature      :', short(rec['signature']))
    print('  Index token        :', tok)


def view_all(keys, db, sec):
    if not db:
        print('No records yet.')
        return
    for tok, rec in db.items():
        ok, why = verify(rec, keys)
        print(f'\nGrant {rec.get("grant_id")}  [{rec.get("timestamp")}]  '
              f'{"VALID" if ok else "TAMPERED"}')
        print('  description (AES ct):', short(rec.get('desc_ct')))
        if ok:
            desc = aes_cbc_decrypt(bytes.fromhex(sec['aes']), bytes.fromhex(rec['desc_iv']),
                                   bytes.fromhex(rec['desc_ct'])).decode()
            print('  description (plain) :', desc)
        print('  amount (Paillier ct):', short(rec.get('amount_ct')))
        print('  MD5                 :', rec.get('md5'))
        print('  signature           :', short(rec.get('signature')))
        if not ok:
            print('  !', why)


# -------------------------------------------------------------- reviewer ---
def verify_all(keys, db, sec):
    if not db:
        print('No records.')
    for rec in db.values():
        ok, why = verify(rec, keys)
        print(f'{rec.get("grant_id")!s:<12} {"VALID   " if ok else "TAMPERED"} {why}')
    LOG.log('Reviewer', 'verify all', f'{len(db)} records')


def search(keys, db, sec):
    gid = ask('Grant ID to search: ')
    tok = token(sec['idx'], gid, 'grant')
    print('Search token:', tok)
    rec = db.get(tok)
    if rec is None:
        print('NOT FOUND')
        return
    ok, why = verify(rec, keys)
    print(f'FOUND grant {rec["grant_id"]} submitted {rec["timestamp"]}')
    print(f'Integrity/authenticity: {"VALID" if ok else "TAMPERED"} - {why}')
    print('(encrypted description/amount are not displayed by the index search)')
    LOG.log('Reviewer', 'search', gid)


def hex_view(keys, db, sec):
    gid = ask('Grant ID: ')
    rec = find(db, sec, gid)
    if rec is None:
        print('NOT FOUND')
        return
    ok, why = verify(rec, keys)
    if not ok:                                         # verify BEFORE decrypting
        print('REFUSED - record failed verification:', why)
        return
    plain = aes_cbc_decrypt(bytes.fromhex(sec['aes']), bytes.fromhex(rec['desc_iv']),
                            bytes.fromhex(rec['desc_ct']))
    print('Verified:', why)
    print('AES-192 decrypted description - hexadecimal dump:')
    print(hexdump(plain))
    LOG.log('Reviewer', 'hex view', gid)


# --------------------------------------------------------------- finance ---
def list_grants(keys, db, sec):
    for rec in db.values():
        ok, _ = verify(rec, keys)
        print(f'{rec.get("grant_id")!s:<12} {rec.get("timestamp")}  {"VALID" if ok else "TAMPERED"}')


def aggregate(keys, db, sec):
    # Overlapping totals can reveal individual amounts by subtraction.
    # The two-record minimum only prevents a direct one-record total.
    ids = ask_list('Grant IDs to aggregate (comma separated, or ALL): ')
    if [i.upper() for i in ids] == ['ALL']:
        ids = [r['grant_id'] for r in db.values()]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate Grant IDs selected')
    chosen = []
    for gid in ids:
        rec = find(db, sec, gid)
        if rec is None:
            print(f'  {gid}: NOT FOUND - skipped')
            continue
        ok, why = verify(rec, keys)
        print(f'  {gid}: {"signature VALID" if ok else "EXCLUDED - " + why}')
        if ok:
            chosen.append(rec)
    if len(chosen) < 2:
        print('Need at least 2 valid grants (decrypting one would reveal an individual amount).')
        return
    total_ct = paillier_add(keys['paillier_pub'], *[r['amount_ct'] for r in chosen])
    print('Encrypted aggregate (product of Paillier ciphertexts mod n^2):', short(total_ct, 80))
    total = paillier_decrypt(sec['paillier'], total_ct)                   # ONLY the total
    print(f'TOTAL expenditure of {len(chosen)} grants = {fmt_amount(total, PLACES)}')
    LOG.log('Finance Officer', 'aggregate', ','.join(r['grant_id'] for r in chosen))


# ----------------------------------------------------- tamper simulation ---
def tamper(keys, db):
    if not db:
        print('No records.')
        return
    ids = {r['grant_id']: t for t, r in db.items()}
    gid = ask_choice('Grant ID to tamper', list(ids))
    field = ask_choice('Field', ['desc_ct', 'amount_ct', 'timestamp', 'md5', 'signature'])
    rec = db[ids[gid]]
    if field == 'amount_ct':
        rec[field] = rec[field] + 1
    elif field == 'timestamp':
        rec[field] = '1999-01-01T00:00:00+00:00'
    else:
        rec[field] = tamper_hex(rec[field])
    save_json(DB, db)
    LOG.log('ATTACKER', 'tamper', f'{gid}.{field}')
    print(f'Stored record {gid}.{field} modified on disk. Now verify it as Reviewer.')


# ------------------------------------------------------------------ menus ---
def role_session(keys, db, role):
    sec = login(keys, role)
    if sec is None:
        return
    if role == 'Researcher':
        menu('Researcher', [('Submit grant', lambda: submit(keys, db, sec)),
                            ('View all submitted records', lambda: view_all(keys, db, sec))])
    elif role == 'Reviewer':
        menu('Reviewer', [('Verify all records (MD5 + RSA)', lambda: verify_all(keys, db, sec)),
                          ('Search by Grant ID (index)', lambda: search(keys, db, sec)),
                          ('Decrypt description as hex dump', lambda: hex_view(keys, db, sec))])
    else:
        menu('Finance Officer', [('List grants + validity', lambda: list_grants(keys, db, sec)),
                                 ('Aggregate selected amounts', lambda: aggregate(keys, db, sec))])


def main():
    keys, db = load_state()
    print(f'Loaded {len(db)} stored grant record(s) from {DB}')
    menu('SECURE GRANT EXPENSE PORTAL',
         [(r, (lambda r=r: role_session(keys, db, r))) for r in ROLES] +
         [('Tamper simulation (attacker - for testing)', lambda: tamper(keys, db))])
    print('Goodbye.')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExit.')
    except json.JSONDecodeError as e:
        print('Data file is corrupted:', e)
