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
