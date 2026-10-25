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
