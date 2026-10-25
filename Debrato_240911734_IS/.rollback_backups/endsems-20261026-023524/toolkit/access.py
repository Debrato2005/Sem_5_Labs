"""Lab 4 - key management service (generate / distribute / revoke / renew /
secure storage / audit) and access-control models (RBAC, ABAC, Bell-LaPadula,
MAC, DAC, time-based, probabilistic) + key-management formulas.

Private keys are stored AES-GCM-encrypted under a master key derived with
PBKDF2 from an operator passphrase (KDF: DK = KDF(passphrase, salt, iterations)).
"""
import hashlib
import json
import math
import os
from datetime import datetime, timedelta, timezone

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

from toolkit.asymmetric import elgamal_keygen, rabin_keygen


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


class KeyManager:
    """Centralised KMS persisted in one JSON file.
    entity -> {alg, version, public, private(enc), created, expires, status}."""

    def __init__(self, path, passphrase):
        self.path = path
        try:
            with open(path, encoding='utf-8') as f:
                self.db = json.load(f)
        except FileNotFoundError:
            self.db = {'salt': os.urandom(16).hex(), 'keys': {}, 'log': []}
        self.master = hashlib.pbkdf2_hmac('sha256', passphrase.encode(),
                                          bytes.fromhex(self.db['salt']), 200_000)
        if 'check' in self.db:                      # detect wrong passphrase early
            self._open(self.db['check'])
        else:
            self.db['check'] = self._seal(b'ok')
            self._save()

    # -- secure storage ------------------------------------------------------
    def _seal(self, data):
        c = AES.new(self.master, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(data)
        return (c.nonce + tag + ct).hex()

    def _open(self, blob):
        b = bytes.fromhex(blob)
        try:
            return AES.new(self.master, AES.MODE_GCM, nonce=b[:16]).decrypt_and_verify(b[32:], b[16:32])
        except ValueError:
            raise ValueError('wrong KMS passphrase or tampered key store') from None

    def _save(self):
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self.db, f, indent=2)
        os.replace(tmp, self.path)

    def _log(self, action, entity, detail=''):
        self.db['log'].append({'time': _now().isoformat(), 'action': action,
                               'entity': entity, 'detail': detail})

    # -- lifecycle -----------------------------------------------------------
    def generate(self, entity, alg='RSA', bits=2048, lifetime_days=365):
        alg = alg.upper()
        if alg == 'RSA':
            k = RSA.generate(bits)
            public, private = k.publickey().export_key().decode(), k.export_key().decode()
        elif alg == 'RABIN':
            n, (p, q) = rabin_keygen(bits)
            public, private = str(n), json.dumps([p, q])
        elif alg == 'ELGAMAL':
            (p, g, y), x = elgamal_keygen()
            public, private = json.dumps([p, g, y]), str(x)
        else:
            raise ValueError('alg must be RSA / RABIN / ELGAMAL')
        old = self.db['keys'].get(entity)
        created = _now()
        self.db['keys'][entity] = {
            'alg': alg, 'bits': bits, 'version': (old['version'] + 1) if old else 1,
            'public': public, 'private': self._seal(private.encode()),
            'created': created.isoformat(),
            'expires': (created + timedelta(days=lifetime_days)).isoformat(),
            'lifetime_days': lifetime_days, 'status': 'active'}
        self._log('renew' if old else 'generate', entity, f'{alg}-{bits} v{self.db["keys"][entity]["version"]}')
        self._save()
        return self.db['keys'][entity]

    def _active(self, entity):
        k = self.db['keys'].get(entity)
        if not k:
            raise KeyError(f'no key for {entity}')
        if k['status'] != 'active':
            raise PermissionError(f'key for {entity} is {k["status"]}')
        if datetime.fromisoformat(k['expires']) < _now():
            raise PermissionError(f'key for {entity} expired {k["expires"]}')
        return k

    def get_public(self, entity):
        k = self._active(entity)
        self._log('distribute-public', entity)
        self._save()
        return k['public']

    def get_private(self, entity, requester):
        """Key distribution: only the owner entity may fetch its private key."""
        if requester != entity:
            self._log('DENIED-private', entity, f'requester={requester}')
            self._save()
            raise PermissionError('only the owner may obtain its private key')
        k = self._active(entity)
        self._log('distribute-private', entity)
        self._save()
        return self._open(k['private']).decode()

    def revoke(self, entity, reason=''):
        self.db['keys'][entity]['status'] = 'revoked'
        self._log('revoke', entity, reason)
        self._save()

    def renew(self, entity):
        k = self.db['keys'][entity]
        return self.generate(entity, k['alg'], k['bits'], k['lifetime_days'])

    def renew_due(self, within_days=0):
        """Automatic renewal: renew every active key expiring within N days."""
        limit = _now() + timedelta(days=within_days)
        done = [e for e, k in list(self.db['keys'].items())
                if k['status'] == 'active' and datetime.fromisoformat(k['expires']) <= limit]
        for e in done:
            self.renew(e)
        return done

    def report(self):
        for e, k in self.db['keys'].items():
            print(f'{e:<15} {k["alg"]:<8} v{k["version"]} {k["status"]:<8} expires {k["expires"]}')


# ================================================================ policies ===
def rbac(user_roles, role_perms, user, perm):
    """Access = exists role: HasRole(user, role) and CanAccess(role, perm)."""
    return any(perm in role_perms.get(r, ()) for r in user_roles.get(user, ()))


def abac(policy, user_attrs, obj_attrs, env):
    """policy: function(user, obj, env) -> bool, e.g.
    lambda u, o, e: u['dept'] == o['dept'] and 9 <= e['hour'] < 17."""
    return bool(policy(user_attrs, obj_attrs, env))


LEVELS = {'unclassified': 0, 'confidential': 1, 'secret': 2, 'top secret': 3}


def blp_read(subject_level, object_level):
    """Simple security property: no read UP  (S >= C)."""
    return LEVELS[subject_level] >= LEVELS[object_level]


def blp_write(subject_level, object_level):
    """*-property: no write DOWN  (S <= C)."""
    return LEVELS[subject_level] <= LEVELS[object_level]


def mac(clearance, classification, rule_ok=True):
    return LEVELS[clearance] >= LEVELS[classification] and rule_ok


class DAC:
    """Access matrix: owner grants / revokes rights per subject."""

    def __init__(self):
        self.owner, self.matrix = {}, {}

    def create(self, subject, obj):
        if obj in self.owner:
            raise ValueError('object already exists')
        self.owner[obj] = subject
        self.matrix[(subject, obj)] = {'read', 'write', 'own'}

    def grant(self, by, subject, obj, right):
        if self.owner.get(obj) != by:
            raise PermissionError('only the owner can grant')
        self.matrix.setdefault((subject, obj), set()).add(right)

    def revoke(self, by, subject, obj, right):
        if self.owner.get(obj) != by:
            raise PermissionError('only the owner can revoke')
        self.matrix.get((subject, obj), set()).discard(right)

    def check(self, subject, obj, right):
        return right in self.matrix.get((subject, obj), set())


def time_window(start, end, now=None, other=True):
    """Access(u, o, t) = start <= t <= end and other conditions."""
    now = now or _now()
    return start <= now <= end and other


def probabilistic_access(trust, sensitivity, risk, threshold=0.5):
    """P = trust * (1 - sensitivity) * (1 - risk), all in [0, 1]."""
    p = trust * (1 - sensitivity) * (1 - risk)
    return p, p >= threshold


# ======================================================= KMS formulas ========
def entropy(probabilities):
    """H(K) = -sum p_i log2 p_i  (uniform 2^k keys -> k bits)."""
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def password_entropy(length, alphabet_size):
    return length * math.log2(alphabet_size)


def rotation_rate(n_keys, period):
    return n_keys / period


def expiry_time(t0, lifetime):
    return t0 + lifetime
