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
