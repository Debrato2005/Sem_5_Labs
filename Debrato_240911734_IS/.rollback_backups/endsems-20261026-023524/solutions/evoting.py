"""NATIONAL E-VOTING SYSTEM  (end-sem sample question 2) - menu driven.
QUESTION:
A national e-voting system has been deployed to allow citizens to cast their votes securely from
remote locations. The system ensures privacy, verifiability, integrity, and non-repudiation while
allowing aggregate computations without revealing individual votes.
1. Client side: a voter fills out an electronic ballot (candidate selection, constituency ID).
   SHA-512 hash of the ballot file; ballot encrypted with AES-256-CBC; AES key encrypted with the
   Election Commission's RSA-4096 public key; voter signs the SHA-512 hash with ElGamal; the
   numerical candidate ID is Paillier-encrypted for tallying; a trusted-authority timestamp is added.
2. Server side: decrypt the AES key with the RSA private key (keep Paillier values encrypted);
   verify the signature with the voter's public key and compare the SHA-512 hash; check the
   timestamp is within the voting period; tally homomorphically; keep a searchable encrypted
   index (constituency / time range) without revealing votes; at the end decrypt only the final
   aggregate with THRESHOLD decryption so no single authority can view votes.
3. Menu-driven program, role-based access control, store encrypted/signed/hashed data, show outputs.

DESIGN:

CLIENT (Voter device)                       SERVER (Election Commission)
 ballot file {voter, constituency, cand}     RSA-4096 private key unwraps AES key
 SHA-512(ballot file)                        AES-256-CBC decrypt, recompute SHA-512
 AES-256-CBC(ballot), random key + IV        verify both ElGamal signatures
 RSA-4096-OAEP(AES key, EC public key)       verify TSA timestamp + voting window
 ElGamal signature on the SHA-512 hash       re-encryption check: Paillier vote
 Paillier one-hot vote vector                  vector really encodes the ballot
 TSA timestamp (RSA-signed) on the hash      searchable index (HMAC tokens):
 ElGamal signature on the whole envelope       constituency + hour buckets
                                             homomorphic tally (no decryption)
AUTHORITIES: t-of-N threshold Paillier - each authority decrypts a partial
             with its own share; only the final per-candidate totals are revealed.
AUDITOR    : verifies signatures/timestamps, searches index, reads audit log -
             never sees votes.

Why a one-hot vector: summing encrypted candidate IDs gives sum(IDs), not
counts.  E(1) for the chosen candidate and E(0) for the rest gives counts.
Honest limitations (exam setting): the timestamp authority and all roles run
in this one program (separate keys, password-sealed vaults); the threshold
scheme uses a trusted dealer at setup and no zero-knowledge proofs.

Run:  python solutions/evoting.py [data_folder]        (default ./evote_data)
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # TOOLKIT-PATH
import json
import os
import secrets
import tempfile

from Crypto.Random import get_random_bytes, random

from toolkit.util import (AuditLog, ask, ask_choice, ask_int, ask_list, ask_secret, canonical,
                          hour_buckets, load_json, menu, now_utc, parse_time, save_json,
                          tamper_hex)
from toolkit.symmetric import aes_cbc_decrypt, aes_cbc_encrypt, password_open, password_seal
from toolkit.asymmetric import rsa_decrypt, rsa_encrypt, rsa_generate, rsa_import
from toolkit.hashing import digest, file_digest
from toolkit.signatures import (G14_G, G14_P, TimestampAuthority, elgamal_sig_keygen,
                                elgamal_sign_hash, elgamal_verify_hash, rsa_sign, rsa_verify,
                                verify_timestamp)
from toolkit.homomorphic import (combine_partials, encrypt_one_hot, paillier_threshold_keygen,
                                 partial_decrypt, tally)
from toolkit.searchable import field_index_add, field_index_find, field_index_find_any, token

DATA = sys.argv[1] if len(sys.argv) > 1 else 'evote_data'
CFG = os.path.join(DATA, 'election.json')
BALLOTS = os.path.join(DATA, 'ballots.json')
INDEX = os.path.join(DATA, 'index.json')
LOG = AuditLog(os.path.join(DATA, 'audit.log'))
ENVELOPE = ('voter', 'iv', 'ballot_ct', 'wrapped_key', 'ballot_sha512', 'vote_ct',
            'opening_iv', 'opening_ct', 'timestamp', 'ballot_sig')


def h512(hex_digest):
    return int(hex_digest, 16)


def short(v, n=40):
    s = str(v)
    return s if len(s) <= n else f'{s[:n]}...({len(s)})'


def new_password(label):
    while True:
        pw = ask_secret(f'Set password for {label}: ')
        if pw:
            return pw
        print('  ! blank password not allowed')


def unlock(box, label):
    try:
        return json.loads(password_open(ask_secret(f'{label} password: '), box))
    except ValueError:
        LOG.log(label, 'LOGIN FAILED')
        print('  ACCESS DENIED - wrong password')
        return None


# ================================================================== setup ===
def setup():
    print('\nFIRST RUN - Election Commission configuration')
    while True:
        cands = {}
        try:
            for item in ask_list('Candidates as id:name, comma separated (e.g. 1:Asha, 2:Ravi): '):
                cid, _, name = item.partition(':')
                if not cid.strip().isdecimal() or not name.strip():
                    raise ValueError(f'bad candidate entry {item!r}')
                cid = str(int(cid.strip()))
                if cid in cands:
                    raise ValueError(f'duplicate candidate ID {cid}')
                cands[cid] = name.strip()
            if len(cands) < 2:
                raise ValueError('need at least 2 candidates')
            break
        except ValueError as e:
            print('  !', e)
    while True:
        consts = ask_list('Valid constituency IDs, comma separated: ')
        if consts:
            break
        print('  ! need at least one constituency')
    while True:
        try:
            s = ask('Voting opens  (YYYY-MM-DD HH:MM[+05:30], blank = now): ', allow_blank=True)
            start = parse_time(s) if s else now_utc()
            break
        except (ValueError, OverflowError) as e:
            print('  !', e)
    while True:
        try:
            end = parse_time(ask('Voting closes (YYYY-MM-DD HH:MM[+05:30]): '))
            if end <= start:
                raise ValueError('closing time must be after opening time')
            break
        except (ValueError, OverflowError) as e:
            print('  !', e)
    n_auth = ask_int('Number of tallying authorities N (>= 2): ', 2, 9)
    t = ask_int(f'Threshold t (authorities needed to decrypt, 2..{n_auth}): ', 2, n_auth)

    print('Generating RSA-4096 (commission), RSA-2048 (timestamp authority), '
          f'{t}-of-{n_auth} threshold Paillier-2048 ...')
    ec = rsa_generate(4096)
    tsa = rsa_generate(2048)
    p_pub, shares = paillier_threshold_keygen(2048, t, n_auth)
    idx = get_random_bytes(32).hex()
    vaults = {'Election Commission': password_seal(new_password('Election Commission'),
                                                   canonical({'rsa': ec.export_key().decode(), 'idx': idx})),
              'Auditor': password_seal(new_password('Auditor'), canonical({'idx': idx}))}
    for i, share in shares:
        vaults[f'Authority {i}'] = password_seal(new_password(f'Authority {i}'),
                                                 canonical({'share': [i, share]}))
    del shares                                   # dealer forgets the shares
    cfg = {'candidates': cands, 'constituencies': consts,
           'start': start.isoformat(), 'end': end.isoformat(), 'closed_at': None,
           'ec_pub': ec.publickey().export_key().decode(),
           'tsa_pub': tsa.publickey().export_key().decode(),
           'tsa_key': tsa.export_key().decode(),   # simulated external TSA service
           'paillier': p_pub, 'vaults': vaults, 'voters': {}, 'results': None}
    save_json(CFG, cfg)
    LOG.log('Election Commission', 'setup', f'{len(cands)} candidates, {t}-of-{n_auth}')
    print('Election configured; window', cfg['start'], '->', cfg['end'])
    return cfg


def window(cfg):
    end = parse_time(cfg['end'])
    if cfg['closed_at']:
        end = min(end, parse_time(cfg['closed_at']))
    return parse_time(cfg['start']), end


# ============================================================ voter (client) =
def voter_session(cfg, ballots):
    vid = ask('Voter ID: ')
    if vid not in cfg['voters']:
        print('  Not a registered voter.')
        return
    sec = unlock(cfg['voters'][vid]['vault'], f'Voter {vid}')
    if sec is None:
        return
    menu(f'Voter {vid} (client device)',
         [('Cast ballot', lambda: cast(cfg, ballots, vid, sec['x'])),
          ('My submission status', lambda: my_status(ballots, vid))])


def cast(cfg, ballots, vid, x):
    start, end = window(cfg)
    now = now_utc()
    if not start <= now <= end:
        raise ValueError(f'voting is closed (window {start.isoformat()} -> {end.isoformat()})')
    if any(b['voter'] == vid and b['status'] in ('pending', 'accepted') for b in ballots.values()):
        raise ValueError('you have already voted')
    print('Candidates:', ', '.join(f'{c}={n}' for c, n in cfg['candidates'].items()))
    cand = ask_choice('Candidate ID', list(cfg['candidates']))
    const = ask_choice('Constituency ID', cfg['constituencies'])
    if const != cfg['voters'][vid]['constituency']:
        raise ValueError('ballot constituency differs from your registered constituency')

    # 1. electronic ballot file + SHA-512 of the file
    ballot = canonical({'voter': vid, 'constituency': const, 'candidate': int(cand),
                        'nonce': secrets.token_hex(8)})
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'ballot.json')
        with open(path, 'wb') as f:
            f.write(ballot)
        sha = file_digest(path, 'sha512')          # ballot file deleted afterwards
    # 2. AES-256-CBC with a fresh session key, 3. key wrapped with RSA-4096
    session = get_random_bytes(32)
    iv, ct = aes_cbc_encrypt(session, ballot)
    wrapped = rsa_encrypt(rsa_import(cfg['ec_pub']), session)
    # 4. ElGamal signature on the SHA-512 hash
    ballot_sig = elgamal_sign_hash(h512(sha), x)
    # 5. Paillier one-hot vector; randomness travels AES-encrypted ("opening")
    n = cfg['paillier']['n']
    rand = {c: random.randint(1, n - 1) for c in cfg['candidates']}
    vote_ct = encrypt_one_hot(cfg['paillier'], cand, list(cfg['candidates']), rand)
    oiv, oct_ = aes_cbc_encrypt(session, canonical(rand))
    # 6. trusted timestamp on the ballot hash
    stamp = TimestampAuthority(rsa_import(cfg['tsa_key'])).stamp(sha)
    env = {'voter': vid, 'iv': iv.hex(), 'ballot_ct': ct.hex(), 'wrapped_key': wrapped.hex(),
           'ballot_sha512': sha, 'vote_ct': vote_ct, 'opening_iv': oiv.hex(),
           'opening_ct': oct_.hex(), 'timestamp': stamp, 'ballot_sig': list(ballot_sig)}
    # 7. ElGamal signature over the whole envelope (binds vote vector + time)
    env['envelope_sig'] = list(elgamal_sign_hash(h512(digest(canonical(env), 'sha512')), x))
    env['status'], env['reason'] = 'pending', 'awaiting server verification'
    sid = secrets.token_hex(6)
    ballots[sid] = env
    save_json(BALLOTS, ballots)
    LOG.log(f'Voter {vid}', 'cast', sid)
    print(f'\nBallot submitted. Receipt ID: {sid}')
    print('  SHA-512(ballot file) :', sha)
    print('  AES-256-CBC ct       :', short(env['ballot_ct'], 64))
    print('  RSA-4096 wrapped key :', short(env['wrapped_key'], 64))
    print('  ElGamal sig (r, s)   :', short(ballot_sig[0]), short(ballot_sig[1]))
    for c, v in vote_ct.items():
        print(f'  Paillier E(vote[{c}]) :', short(v, 64))
    print('  Timestamp (TSA)      :', stamp['time'], '| TSA sig', short(stamp['tsa_sig']))


def my_status(ballots, vid):
    mine = [(s, b) for s, b in ballots.items() if b['voter'] == vid]
    for sid, b in mine:
        print(f'{sid}: {b["status"]} - {b["reason"]} ({b["timestamp"]["time"]})')
    if not mine:
        print('No submissions.')


# =============================================================== verifying ===
def check_public(cfg, b):
    """Checks needing NO private key: ElGamal envelope + ballot-hash signatures,
    TSA timestamp bound to the hash and inside the voting window."""
    try:
        voter = cfg['voters'][b['voter']]
        pub = (G14_P, G14_G, voter['y'])
        body = {k: b[k] for k in ENVELOPE}
        if not elgamal_verify_hash(h512(digest(canonical(body), 'sha512')), b['envelope_sig'], pub):
            return False, 'envelope ElGamal signature INVALID (record modified)'
        if not elgamal_verify_hash(h512(b['ballot_sha512']), b['ballot_sig'], pub):
            return False, 'ballot-hash ElGamal signature INVALID'
        start, end = window(cfg)
        ok, why = verify_timestamp(b['timestamp'], rsa_import(cfg['tsa_pub']),
                                   b['ballot_sha512'], start, end)
        return (True, 'signatures + timestamp valid') if ok else (False, why)
    except (KeyError, TypeError, ValueError) as e:
        return False, f'malformed record ({type(e).__name__})'


def check_private(cfg, b, rsa_priv):
    """Server-only checks: unwrap key, decrypt, recompute SHA-512, ballot
    consistency, and re-encryption check of the Paillier vector."""
    try:
        session = rsa_decrypt(rsa_priv, bytes.fromhex(b['wrapped_key']))
        ballot = aes_cbc_decrypt(session, bytes.fromhex(b['iv']), bytes.fromhex(b['ballot_ct']))
        if digest(ballot, 'sha512') != b['ballot_sha512']:
            return False, 'SHA-512 mismatch (ballot tampered)', None
        bl = json.loads(ballot)
        if bl['voter'] != b['voter']:
            return False, 'ballot voter differs from envelope', None
        if bl['constituency'] != cfg['voters'][b['voter']]['constituency']:
            return False, 'wrong constituency', None
        if str(bl['candidate']) not in cfg['candidates']:
            return False, 'invalid candidate', None
        rand = json.loads(aes_cbc_decrypt(session, bytes.fromhex(b['opening_iv']),
                                          bytes.fromhex(b['opening_ct'])))
        expect = encrypt_one_hot(cfg['paillier'], str(bl['candidate']), list(cfg['candidates']), rand)
        if expect != b['vote_ct']:
            return False, 'Paillier vote vector does not match ballot', None
        return True, 'decrypted, SHA-512 matches, vote vector consistent', bl
    except (KeyError, TypeError, ValueError) as e:
        return False, f'cannot decrypt/parse ({type(e).__name__}: {e})', None


def acceptance_body(sid, b):
    """Bind server approval to the receipt and the complete signed envelope."""
    return canonical({'receipt': sid,
                      'envelope': {k: b[k] for k in ENVELOPE + ('envelope_sig',)}})


def check_acceptance(cfg, sid, b):
    try:
        return rsa_verify(rsa_import(cfg['ec_pub']), acceptance_body(sid, b),
                          b['acceptance_sig'], 'sha512')
    except (KeyError, TypeError, ValueError):
        return False


# ========================================================= commission (server)
def commission_session(cfg, ballots, index):
    sec = unlock(cfg['vaults']['Election Commission'], 'Election Commission')
    if sec is None:
        return
    rsa_priv = rsa_import(sec['rsa'])
    menu('Election Commission (server)', [
        ('Register voter', lambda: register(cfg)),
        ('Process pending ballots (verify + index)', lambda: process(cfg, ballots, index, rsa_priv, sec['idx'])),
        ('View stored ballots (encrypted)', lambda: view_ballots(cfg, ballots)),
        ('Search index (constituency / time range)', lambda: search(ballots, index, sec['idx'])),
        ('Homomorphic tally (encrypted totals)', lambda: show_tally(cfg, ballots, index, sec['idx'])),
        ('Close election now', lambda: close(cfg))])


def register(cfg):
    vid = ask('New voter ID: ')
    if vid in cfg['voters']:
        raise ValueError('voter already registered')
    const = ask_choice('Registered constituency', cfg['constituencies'])
    pw = new_password(f'voter {vid} (voter types it)')
    (p, g, y), x = elgamal_sig_keygen()
    cfg['voters'][vid] = {'constituency': const, 'y': y,
                          'vault': password_seal(pw, canonical({'x': x}))}
    save_json(CFG, cfg)
    LOG.log('Election Commission', 'register', vid)
    print(f'Voter {vid} registered; ElGamal public y = {short(y)} (private x sealed under voter password)')


def process(cfg, ballots, index, rsa_priv, idx):
    pending = [s for s, b in ballots.items() if b['status'] == 'pending']
    if not pending:
        print('No pending ballots.')
    for sid in pending:
        b = ballots[sid]
        ok, why = check_public(cfg, b)
        bl = None
        if ok:
            ok, why, bl = check_private(cfg, b, rsa_priv)
        if ok and any(o['voter'] == b['voter'] and o['status'] == 'accepted' for o in ballots.values()):
            ok, why = False, 'duplicate vote by this voter'
        b['status'], b['reason'] = ('accepted' if ok else 'rejected'), why
        b.pop('acceptance_sig', None)
        if ok:                                   # index: no vote content in tokens
            b['acceptance_sig'] = rsa_sign(rsa_priv, acceptance_body(sid, b), 'sha512')
            field_index_add(index, idx, 'constituency', bl['constituency'], sid)
            hour = parse_time(b['timestamp']['time']).strftime('%Y-%m-%dT%H')
            field_index_add(index, idx, 'hour', hour, sid)
        print(f'{sid} ({b["voter"]}): {b["status"].upper()} - {why}')
        LOG.log('Election Commission', f'process {b["status"]}', f'{sid}: {why}')
    save_json(BALLOTS, ballots)
    save_json(INDEX, index)


def view_ballots(cfg, ballots):
    for sid, b in ballots.items():
        print(f'{sid} voter={b.get("voter")} status={b.get("status")} time={b["timestamp"]["time"]}')
        print('   SHA-512', short(b.get('ballot_sha512'), 32), '| AES ct', short(b.get('ballot_ct'), 32),
              '| E(votes)', {c: short(v, 12) for c, v in b.get('vote_ct', {}).items()})


def search(ballots, index, idx):
    how = ask_choice('Search by', ['constituency', 'time'])
    if how == 'constituency':
        value = ask('Constituency ID: ')
        print('Search token HMAC-SHA256(constituency):', token(idx, value, 'constituency'))
        hits = field_index_find(index, idx, 'constituency', value)
    else:
        start = parse_time(ask('From (YYYY-MM-DD HH:MM): '))
        end = parse_time(ask('To   (YYYY-MM-DD HH:MM): '))
        cands = field_index_find_any(index, idx, 'hour', hour_buckets(start, end))
        hits = [s for s in cands if start <= parse_time(ballots[s]['timestamp']['time']) <= end]
    print(f'{len(hits)} ballot(s) found (vote content NOT revealed):')
    for s in hits:
        b = ballots[s]
        print(f'  {s} voter={b["voter"]} time={b["timestamp"]["time"]} status={b["status"]}')
    LOG.log('search', how, f'{len(hits)} hits')


def encrypted_tally(cfg, ballots, index, idx, const=None):
    """Re-verify every accepted ballot (no decryption), then multiply the
    Paillier ciphertexts candidate by candidate."""
    ids = [s for s, b in ballots.items() if b['status'] == 'accepted']
    if const:
        ids = [s for s in ids if s in field_index_find(index, idx, 'constituency', const)]
    good, voters = [], set()
    for s in ids:
        ok, why = check_public(cfg, ballots[s])
        if ok and not check_acceptance(cfg, s, ballots[s]):
            ok, why = False, 'missing or invalid Commission acceptance signature'
        if ok and ballots[s]['voter'] in voters:
            ok, why = False, 'duplicate voter'
        if ok:
            good.append(ballots[s]['vote_ct'])
            voters.add(ballots[s]['voter'])
        else:
            print(f'  EXCLUDED {s}: {why}')
    if not good:
        raise ValueError('no valid accepted ballots to tally')
    return tally(cfg['paillier'], good, list(cfg['candidates'])), len(good)


def show_tally(cfg, ballots, index, idx):
    const = ask('Constituency filter (blank = all): ', allow_blank=True)
    enc, k = encrypted_tally(cfg, ballots, index, idx, const or None)
    print(f'Encrypted totals over {k} valid ballot(s) (cannot be read without {cfg["paillier"]["t"]} authorities):')
    for c, v in enc.items():
        print(f'  candidate {c} ({cfg["candidates"][c]}): E(count) = {short(v, 60)}')


def close(cfg):
    if ask('Type CLOSE to end voting now: ') == 'CLOSE':
        cfg['closed_at'] = now_utc().isoformat()
        save_json(CFG, cfg)
        LOG.log('Election Commission', 'close election')
        print('Voting closed at', cfg['closed_at'])


# ============================================================= authorities ===
def threshold_decrypt(cfg, ballots, index):
    _, end = window(cfg)
    if now_utc() < end:
        raise ValueError(f'election still open until {end.isoformat()} (Commission can close it)')
    p = cfg['paillier']
    print('Re-verifying ballots and computing encrypted tally ...')
    enc, k = encrypted_tally(cfg, ballots, index, None)
    partials = {c: [] for c in enc}
    used = set()
    while len(used) < p['t']:
        i = ask_int(f'Authority number (1..{p["parties"]}) [{len(used)}/{p["t"]} done]: ', 1, p['parties'])
        if i in used:
            print('  ! this authority already contributed')
            continue
        sec = unlock(cfg['vaults'][f'Authority {i}'], f'Authority {i}')
        if sec is None:
            continue
        share = tuple(sec['share'])
        for c, v in enc.items():
            partials[c].append(partial_decrypt(p, share, v))
        used.add(i)
        LOG.log(f'Authority {i}', 'partial decryption')
        print(f'  Authority {i} partial decryption done (share never leaves its vault)')
    results = {c: combine_partials(p, partials[c]) for c in enc}
    cfg['results'] = {'counted_ballots': k, 'totals': results, 'authorities': sorted(used),
                      'time': now_utc().isoformat()}
    save_json(CFG, cfg)
    print(f'\nFINAL RESULTS ({k} ballots, decrypted by authorities {sorted(used)}):')
    for c, n in sorted(results.items(), key=lambda kv: -kv[1]):
        print(f'  {c} {cfg["candidates"][c]:<15} {n}')


# ================================================================= auditor ===
def auditor_session(cfg, ballots, index):
    sec = unlock(cfg['vaults']['Auditor'], 'Auditor')
    if sec is None:
        return

    def audit():
        for sid, b in ballots.items():
            ok, why = check_public(cfg, b)
            print(f'{sid} voter={b.get("voter")} status={b.get("status")}: '
                  f'{"OK" if ok else "FAIL"} - {why}')

    menu('Auditor', [('Verify all ballots (signatures + timestamps)', audit),
                     ('Search index', lambda: search(ballots, index, sec['idx'])),
                     ('View audit log', LOG.show),
                     ('View published results', lambda: print(cfg['results'] or 'not published'))])


def tamper(ballots):
    if not ballots:
        print('No ballots.')
        return
    sid = ask_choice('Submission ID', list(ballots))
    field = ask_choice('Field', ['ballot_ct', 'vote_ct', 'time', 'ballot_sha512'])
    b = ballots[sid]
    if field == 'vote_ct':
        c = next(iter(b['vote_ct']))
        b['vote_ct'][c] += 1
    elif field == 'time':
        b['timestamp']['time'] = '2000-01-01T00:00:00+00:00'
    else:
        b[field] = tamper_hex(b[field])
    save_json(BALLOTS, ballots)
    LOG.log('ATTACKER', 'tamper', f'{sid}.{field}')
    print(f'Ballot {sid}: {field} modified on disk.')


def main():
    if not os.path.exists(CFG) and os.path.exists(BALLOTS):
        raise SystemExit('ballots.json exists but election.json is missing - restore the original election keys')
    cfg = load_json(CFG, None)
    if cfg is None and os.path.exists(CFG):
        raise SystemExit('election.json is empty - restore the original election keys')
    cfg = cfg if cfg is not None else setup()
    ballots = load_json(BALLOTS, {})
    index = load_json(INDEX, {})
    if not isinstance(cfg, dict) or not all(k in cfg for k in
            ('voters', 'candidates', 'start', 'end', 'closed_at', 'vaults', 'paillier', 'ec_pub')):
        raise SystemExit('election.json is malformed - restore the original election configuration')
    if not isinstance(ballots, dict) or any(not isinstance(b, dict) for b in ballots.values()):
        raise SystemExit('ballots.json is malformed')
    if not isinstance(index, dict):
        raise SystemExit('index.json is malformed')
    print(f'Election loaded: {len(cfg["voters"])} voters, {len(ballots)} submissions. '
          f'Window {cfg["start"]} -> {cfg["end"]}')
    menu('NATIONAL E-VOTING SYSTEM', [
        ('Voter (client side)', lambda: voter_session(cfg, ballots)),
        ('Election Commission (server side)', lambda: commission_session(cfg, ballots, index)),
        ('Tallying authorities (threshold decryption)', lambda: threshold_decrypt(cfg, ballots, index)),
        ('Auditor', lambda: auditor_session(cfg, ballots, index)),
        ('Tamper simulation (attacker - for testing)', lambda: tamper(ballots))])
    print('Goodbye.')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExit.')
    except json.JSONDecodeError as e:
        print('Data file is corrupted:', e)
