"""GENERIC SECURE-RECORDS MENU PROGRAM - adapt the CONFIG block to the question.

Compatibility template. For shared menu/TCP/HTTP operations, prefer
templates/plugplay/ and toolkit.records.RecordApp. Keep this program for its
existing saved-data format and direct single-menu adaptations.

Covers the usual end-sem pattern: roles -> submit records -> encrypt fields
(AES), encrypt numbers (Paillier), hash + sign the stored record, persistent
JSON storage, keyed search index, verify-before-decrypt, homomorphic sum /
average / weighted sum, tamper simulation, audit log.

Every role's keys are sealed under that role's password, and a role only
receives the keys its actions need (see NEEDS) - RBAC enforced by
cryptography, not just by hiding menu entries.

Run:  python templates/secure_records_menu.py [data_folder]
Copy: cp templates/secure_records_menu.py my_answer.py  (from endsems/), edit CONFIG,
      rename labels, delete actions you do not need; `python bundle.py my_answer.py`
      gives a single self-contained file if required.
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # TOOLKIT-PATH
import json
import os

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

from toolkit.util import (AuditLog, ask, ask_amount, ask_choice, ask_list, ask_secret, canonical,
                          fmt_amount, hexdump, load_json, menu, now_iso, save_json, tamper_hex)
from toolkit.symmetric import new_key, password_open, password_seal, sym_decrypt, sym_encrypt
from toolkit.asymmetric import rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import (dss_sign, dss_verify, elgamal_sig_keygen, elgamal_sign,
                                elgamal_verify, rsa_sign, rsa_verify)
from toolkit.homomorphic import (paillier_add, paillier_decrypt, paillier_encrypt, paillier_keygen,
                                 paillier_weighted_sum)
from toolkit.searchable import token

# ============================== CONFIG - EDIT FOR THE QUESTION ==============
TITLE = 'SECURE RECORDS SYSTEM'
ID_LABEL = 'Record ID'                     # unique key, indexed with an HMAC token
TEXT_FIELDS = ['Description']              # encrypted with AES (AES_BITS, AES_MODE)
NUMBER_FIELDS = ['Amount']                 # encrypted with Paillier ([] = none)
PLAIN_FIELDS = []                          # stored in clear but signed (e.g. 'Department')
SEARCH_FIELDS = []                         # equality-searchable via HMAC tokens (any of the above)
PLACES = 2                                 # decimals kept for NUMBER_FIELDS (0 = integers)
CIPHER = 'AES'                             # AES / DES / DES3 (or 3DES)
AES_BITS, AES_MODE = 192, 'CBC'            # 128/192/256 ; CBC/GCM/CTR/ECB/CFB/OFB
HASH = 'md5'                               # md5/sha1/sha256/sha512/...
SIGN = 'rsa'                               # rsa / elgamal / ecdsa
RSA_BITS, PAILLIER_BITS = 2048, 2048
MIN_AGGREGATE = 2                          # refuse to decrypt a "total" of 1 record
# Multiple overlapping totals can reveal individual values by subtraction.
# This minimum alone does not give privacy across repeated aggregate queries.
ROLES = {                                  # role -> actions (see ACTIONS below)
    'Researcher': ['submit', 'view'],
    'Reviewer': ['verify', 'search', 'decrypt'],
    'Finance Officer': ['list', 'aggregate'],
}
# ============================================================================

NEEDS = {'submit': {'aes', 'sign'}, 'view': {'aes'}, 'decrypt': {'aes'},
         'aggregate': {'paillier'}, 'verify': set(), 'search': set(), 'list': set()}
DATA = sys.argv[1] if len(sys.argv) > 1 else 'records_data'
KEYS, DB = os.path.join(DATA, 'keys.json'), os.path.join(DATA, 'records.json')
LOG = AuditLog(os.path.join(DATA, 'audit.log'))
SIGNED = ['id', 'text', 'numbers', 'plain', 'tags', 'timestamp']


# --------------------------------------------------------- key management ---
def record_config():
    """Save the field and key configuration to prevent incompatible restarts."""
    return {'cipher': CIPHER, 'aes_bits': AES_BITS, 'mode': AES_MODE, 'hash': HASH,
            'sign': SIGN, 'id_label': ID_LABEL, 'text': TEXT_FIELDS, 'numbers': NUMBER_FIELDS,
            'plain': PLAIN_FIELDS, 'search': SEARCH_FIELDS, 'places': PLACES, 'roles': ROLES,
            'minimum_aggregate': MIN_AGGREGATE, 'rsa_bits': RSA_BITS, 'paillier_bits': PAILLIER_BITS}


def validate_config():
    alg = 'DES3' if CIPHER == '3DES' else CIPHER
    if alg not in ('AES', 'DES', 'DES3'):
        raise ValueError('CIPHER must be AES, DES, or DES3')
    if AES_BITS not in (128, 192, 256):
        raise ValueError('AES_BITS must be 128, 192, or 256')
    if AES_MODE not in ('CBC', 'GCM', 'CTR', 'ECB', 'CFB', 'OFB', 'EAX'):
        raise ValueError('unsupported cipher mode')
    if AES_MODE == 'GCM' and alg != 'AES':
        raise ValueError('GCM requires AES')
    if SIGN not in ('rsa', 'elgamal', 'ecdsa'):
        raise ValueError('SIGN must be rsa, elgamal, or ecdsa')
    digest(b'', HASH)                       # reject unsupported hashes before key setup
    if SIGN in ('rsa', 'ecdsa') and HASH not in ('md5', 'sha1', 'sha224', 'sha256',
                                                'sha384', 'sha512', 'sha3_256', 'sha3_512'):
        raise ValueError('unsupported signature hash')
    if SIGN == 'ecdsa' and HASH not in ('sha224', 'sha256', 'sha384', 'sha512',
                                       'sha3_256', 'sha3_512'):
        raise ValueError('ECDSA requires SHA-224 or a stronger SHA-2/SHA-3 hash')
    fields = TEXT_FIELDS + NUMBER_FIELDS + PLAIN_FIELDS
    if len(set(fields)) != len(fields) or any(not isinstance(f, str) or not f for f in fields):
        raise ValueError('field names must be nonblank and unique')
    if any(f not in fields for f in SEARCH_FIELDS):
        raise ValueError('SEARCH_FIELDS must name configured data fields')
    if not isinstance(PLACES, int) or not 0 <= PLACES <= 12:
        raise ValueError('PLACES must be an integer from 0 to 12')
    if not isinstance(MIN_AGGREGATE, int) or MIN_AGGREGATE < 2:
        raise ValueError('MIN_AGGREGATE must be at least 2')
    for actions in ROLES.values():
        if any(a not in NEEDS for a in actions):
            raise ValueError('unknown role action')
        if 'aggregate' in actions and not NUMBER_FIELDS:
            raise ValueError('aggregate requires at least one NUMBER_FIELDS entry')
    return alg


def cipher_label():
    return f'AES-{AES_BITS}' if CIPHER == 'AES' else ('3DES' if CIPHER in ('DES3', '3DES') else CIPHER)


def setup():
    alg = validate_config()
    print(f'FIRST RUN: {cipher_label()}, {SIGN.upper()} signatures, Paillier-{PAILLIER_BITS}')
    private = {'aes': new_key(alg, AES_BITS // 8 if alg == 'AES' else 24).hex(),
               'idx': get_random_bytes(32).hex()}
    keys = {'config': record_config()}
    if SIGN == 'rsa':
        k = rsa_generate(RSA_BITS)
        private['sign'], keys['sign_pub'] = k.export_key().decode(), k.publickey().export_key().decode()
    elif SIGN == 'elgamal':
        pub, x = elgamal_sig_keygen()
        private['sign'], keys['sign_pub'] = x, list(pub)
    else:
        k = ECC.generate(curve='P-256')
        private['sign'], keys['sign_pub'] = k.export_key(format='PEM'), k.public_key().export_key(format='PEM')
    if NUMBER_FIELDS:
        keys['paillier_pub'], private['paillier'] = paillier_keygen(PAILLIER_BITS)
    keys['vaults'] = {}
    for role, actions in ROLES.items():
        need = {'idx'}.union(*(NEEDS[a] for a in actions))
        if not TEXT_FIELDS:
            need.discard('aes')
        while True:
            pw = ask_secret(f'Set password for {role}: ')
            if pw:
                break
        keys['vaults'][role] = password_seal(pw, canonical({k: v for k, v in private.items() if k in need}))
    save_json(KEYS, keys)
    return keys


def sign(sec, data):
    if SIGN == 'rsa':
        return rsa_sign(rsa_import(sec['sign']), data, HASH)
    if SIGN == 'elgamal':
        return list(elgamal_sign(data, sec['sign'], alg=HASH))
    return dss_sign(ECC.import_key(sec['sign']), data, HASH)


def check_sig(keys, data, sig):
    if SIGN == 'rsa':
        return rsa_verify(rsa_import(keys['sign_pub']), data, sig, HASH)
    if SIGN == 'elgamal':
        return elgamal_verify(data, sig, keys['sign_pub'], HASH)
    return dss_verify(ECC.import_key(keys['sign_pub']), data, sig, HASH)


def verify(keys, rec):
    """Recompute the hash of the stored (encrypted) record, then check signature."""
    try:
        body = canonical({k: rec[k] for k in SIGNED})
        if digest(body, HASH) != rec['hash']:
            return False, f'{HASH.upper()} mismatch - record modified'
        if not check_sig(keys, body, rec['sig']):
            return False, f'{SIGN.upper()} signature invalid'
        return True, f'{HASH.upper()} matches and {SIGN.upper()} signature valid'
    except (KeyError, TypeError, ValueError) as e:
        return False, f'malformed record ({type(e).__name__})'


# ---------------------------------------------------------------- actions ---
def submit(keys, db, sec):
    rid = ask(f'{ID_LABEL}: ')
    tok = token(sec['idx'], rid, 'id')
    if tok in db:
        raise ValueError(f'{ID_LABEL} already exists')
    aes = bytes.fromhex(sec['aes']) if TEXT_FIELDS else None
    values = {f: ask(f'{f}: ') for f in TEXT_FIELDS + PLAIN_FIELDS}
    nums = {f: ask_amount(f'{f}: ', PLACES, lo=-10 ** 30) for f in NUMBER_FIELDS}
    rec = {'id': rid,
           'text': {f: sym_encrypt('DES3' if CIPHER == '3DES' else CIPHER, AES_MODE, aes,
                                   values[f].encode()) for f in TEXT_FIELDS},
           'numbers': {f: paillier_encrypt(keys['paillier_pub'], v) for f, v in nums.items()},
           'plain': {f: values[f] for f in PLAIN_FIELDS},
           'tags': [token(sec['idx'], values.get(f, nums.get(f)), f) for f in SEARCH_FIELDS],
           'timestamp': now_iso()}
    body = canonical(rec)
    rec['hash'] = digest(body, HASH)
    rec['sig'] = sign(sec, body)
    db[tok] = rec
    save_json(DB, db)
    LOG.log('submit', rid)
    print(f'Stored {rid}\n  {HASH.upper()}: {rec["hash"]}\n  signature: {str(rec["sig"])[:60]}...')
    for f, box in rec['text'].items():
        print(f'  {f} {cipher_label()}-{AES_MODE} ct: {box["ct"]}')


def view(keys, db, sec):
    for rec in db.values():
        ok, why = verify(keys, rec)
        print(f'\n{rec.get("id")} [{rec.get("timestamp")}] {"VALID" if ok else "TAMPERED - " + why}')
        for f, box in rec.get('text', {}).items():
            plain = sym_decrypt(bytes.fromhex(sec['aes']), box).decode() if ok else '(not decrypted)'
            print(f'  {f}: ct={box["ct"][:40]}... plain={plain}')
        for f, c in rec.get('numbers', {}).items():
            print(f'  {f}: Paillier ct={str(c)[:40]}...')
        for f, v in rec.get('plain', {}).items():
            print(f'  {f}: {v}')


def verify_all(keys, db, sec):
    for rec in db.values():
        ok, why = verify(keys, rec)
        print(f'{rec.get("id")!s:<12} {"VALID   " if ok else "TAMPERED"} {why}')


def search(keys, db, sec):
    field = ask_choice('Search field', [ID_LABEL] + SEARCH_FIELDS)
    value = (ask_amount('Value: ', PLACES, lo=-10 ** 30)
             if field in NUMBER_FIELDS else ask('Value: '))
    if field == ID_LABEL:
        hits = [db[t] for t in [token(sec['idx'], value, 'id')] if t in db]
    else:
        t = token(sec['idx'], value, field)
        hits = [r for r in db.values() if t in r.get('tags', [])]
    print(f'{len(hits)} match(es) (encrypted contents not shown):')
    for r in hits:
        ok, _ = verify(keys, r)
        print(f'  {r["id"]} [{r["timestamp"]}] {"VALID" if ok else "TAMPERED"}')


def decrypt(keys, db, sec):
    rec = db.get(token(sec['idx'], ask(f'{ID_LABEL}: '), 'id'))
    if rec is None:
        print('NOT FOUND')
        return
    ok, why = verify(keys, rec)
    if not ok:
        print('REFUSED -', why)
        return
    for f, box in rec['text'].items():
        plain = sym_decrypt(bytes.fromhex(sec['aes']), box)
        print(f'{f}: {plain.decode(errors="replace")}\n{hexdump(plain)}')


def list_ids(keys, db, sec):
    for rec in db.values():
        print(rec.get('id'), rec.get('timestamp'), 'VALID' if verify(keys, rec)[0] else 'TAMPERED')


def aggregate(keys, db, sec):
    field = NUMBER_FIELDS[0] if len(NUMBER_FIELDS) == 1 else ask_choice('Field', NUMBER_FIELDS)
    ids = ask_list(f'{ID_LABEL}s (comma separated, or ALL): ')
    if [i.upper() for i in ids] == ['ALL']:
        pairs = [(r.get('id'), r) for r in db.values()]
    else:
        pairs = [(i, db.get(token(sec['idx'], i, 'id'))) for i in dict.fromkeys(ids)]
    good = []
    for i, r in pairs:
        ok, why = verify(keys, r) if r else (False, 'not found')
        print(f'  {i}: {"OK" if ok else "EXCLUDED - " + why}')
        if ok:
            good.append(r['numbers'][field])
    if len(good) < MIN_AGGREGATE:
        print(f'Need at least {MIN_AGGREGATE} valid records.')
        return
    pub, priv = keys['paillier_pub'], sec['paillier']
    op = ask_choice('Operation', ['sum', 'average', 'weighted'])
    if op == 'weighted':
        w = [int(x) for x in ask_list(f'{len(good)} integer weights: ')]
        if len(w) != len(good):
            raise ValueError('one weight per record')
        if sum(weight != 0 for weight in w) < MIN_AGGREGATE:
            raise ValueError(f'need at least {MIN_AGGREGATE} nonzero weights')
        enc = paillier_weighted_sum(pub, good, w)
    else:
        enc = paillier_add(pub, *good)
    print('Encrypted result:', str(enc)[:70], '...')
    total = paillier_decrypt(priv, enc)                  # only the aggregate
    if op == 'average':
        print(f'AVERAGE {field} = {fmt_amount(total, PLACES)} / {len(good)} = '
              f'{total / len(good) / 10 ** PLACES:.{max(PLACES, 2)}f}')
    else:
        print(f'{op.upper()} of {field} over {len(good)} records = {fmt_amount(total, PLACES)}')
    LOG.log('aggregate', f'{op} {field} n={len(good)}')


ACTIONS = {'submit': ('Submit record', submit), 'view': ('View all records', view),
           'verify': ('Verify all (hash + signature)', verify_all),
           'search': ('Search (index)', search), 'decrypt': ('Verify + decrypt (hex dump)', decrypt),
           'list': ('List records', list_ids), 'aggregate': ('Homomorphic aggregate', aggregate)}


def tamper(keys, db):
    rid = ask(f'{ID_LABEL} to tamper: ')
    rec = next((r for r in db.values() if r['id'] == rid), None)
    if rec is None:
        print('NOT FOUND')
        return
    if rec['text']:
        box = next(iter(rec['text'].values()))
        box['ct'] = tamper_hex(box['ct'])
    else:
        rec['timestamp'] = '2000-01-01T00:00:00+00:00'
    save_json(DB, db)
    print('Stored ciphertext modified on disk - verification will now fail.')


def session(keys, db, role):
    try:
        sec = json.loads(password_open(ask_secret(f'{role} password: '), keys['vaults'][role]))
    except ValueError:
        print('ACCESS DENIED')
        LOG.log('LOGIN FAILED', role)
        return
    menu(role, [(ACTIONS[a][0], (lambda f=ACTIONS[a][1]: f(keys, db, sec))) for a in ROLES[role]])


def main():
    validate_config()
    if not os.path.exists(KEYS) and os.path.exists(DB):
        raise SystemExit('records.json exists but keys.json is missing - restore the original keys')
    keys = load_json(KEYS, None)
    if keys is None and os.path.exists(KEYS):
        raise SystemExit('keys.json is empty - restore the original keys')
    keys = keys if keys is not None else setup()
    db = load_json(DB, {})
    if not isinstance(db, dict) or any(not isinstance(r, dict) for r in db.values()):
        raise SystemExit('records.json is malformed')
    if keys.get('config') != record_config():
        raise SystemExit('CONFIG differs from stored keys - use the original CONFIG or a new data folder')
    print(f'{len(db)} stored record(s) loaded')
    menu(TITLE, [(r, (lambda r=r: session(keys, db, r))) for r in ROLES] +
         [('Tamper simulation (testing)', lambda: tamper(keys, db))])


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExit.')
    except json.JSONDecodeError as e:
        print('Data file is corrupted:', e)
    except ValueError as e:
        print('CONFIG error:', e)
