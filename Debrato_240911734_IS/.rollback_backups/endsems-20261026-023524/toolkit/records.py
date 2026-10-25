"""Plug-and-play record operations. No input(), print(), sockets, or menu logic.

Menu, TCP and HTTP adapters call the SAME handle(request) method.
Educational application boundary: the server can unlock role keys after login.
Aggregate decryption does not prevent disclosure through overlapping queries.
"""
import json
from pathlib import Path
from threading import RLock

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

from toolkit.util import canonical, fmt_amount, hexdump, load_json, now_iso, save_json, scale_decimal
from toolkit.symmetric import KEY_SIZES, MODES, new_key, password_open, password_seal, sym_decrypt, sym_encrypt
from toolkit.asymmetric import rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import (dss_sign, dss_verify, elgamal_sig_keygen, elgamal_sign,
                                elgamal_verify, hash_obj, rsa_sign, rsa_verify)
from toolkit.homomorphic import (paillier_decrypt, paillier_encrypt, paillier_keygen,
                                 paillier_weighted_sum)
from toolkit.searchable import token


class RecordApp:
    """CONFIG fields: text -> symmetric cipher, number -> Paillier, plain -> clear.

    Actions: submit, list, verify, search, decrypt (text only), aggregate.
    Add a new operation as action_NAME(self, request, role_keys).
    """
    ACTION_KEYS = {'submit': {'cipher', 'sign'}, 'decrypt': {'cipher'},
                   'aggregate': {'paillier'}}

    def __init__(self, folder, config):
        if not isinstance(config, dict):
            raise ValueError('CONFIG must be a dictionary')
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.config = {'cipher': 'AES', 'bits': 192, 'mode': 'CBC', 'hash': 'sha256',
                       'signature': 'rsa', 'places': 2, 'minimum': 2, 'max_abs': 10**12,
                       'rsa_bits': 2048, 'paillier_bits': 2048, **config}
        self.fields, self.roles = self.config.get('fields'), self.config.get('roles')
        if (not isinstance(self.fields, dict) or not self.fields
                or any(not isinstance(k, str) or not k.strip() or k == 'id' for k in self.fields)
                or any(v not in ('text', 'number', 'plain') for v in self.fields.values())):
            raise ValueError('fields must map nonblank names other than id to text, number, or plain')
        if self.config['signature'] not in ('rsa', 'elgamal', 'ecdsa'):
            raise ValueError('signature must be rsa, elgamal, or ecdsa')
        if (any(type(self.config[k]) is not int for k in ('places', 'minimum', 'max_abs'))
                or not 0 <= self.config['places'] <= 8 or self.config['minimum'] < 1
                or self.config['max_abs'] < 1):
            raise ValueError('invalid places, minimum, or max_abs')
        cipher, bits, mode = self.config['cipher'], self.config['bits'], self.config['mode']
        if (not isinstance(cipher, str) or cipher not in KEY_SIZES or type(bits) is not int
                or bits not in tuple(size * 8 for size in KEY_SIZES[cipher])):
            raise ValueError('cipher and bit count must match AES 128/192/256, DES 64, or DES3 128/192')
        if mode not in MODES or (mode == 'GCM' and cipher != 'AES'):
            raise ValueError('unsupported cipher mode; GCM requires AES')
        if (type(self.config['rsa_bits']) is not int or self.config['rsa_bits'] < 1024
                or type(self.config['paillier_bits']) is not int or self.config['paillier_bits'] < 8):
            raise ValueError('RSA bits must be >= 1024 and Paillier bits must be >= 8')
        try:
            hash_obj(b'check', self.config['hash'])
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError('unsupported signature hash') from None
        if self.config['signature'] == 'ecdsa' and self.config['hash'] not in ('sha256','sha384','sha512'):
            raise ValueError('ECDSA needs a SHA-2 hash')
        if (not isinstance(self.roles, dict) or not self.roles
                or any(not isinstance(role, str) or not role.strip() for role in self.roles)
                or any(not isinstance(actions, list) or not actions
                       or any(not isinstance(a, str) or not hasattr(self, 'action_' + a) for a in actions)
                       for actions in self.roles.values())):
            raise ValueError('roles need supported actions')
        if ('number' not in self.fields.values() and any(
                'paillier' in self.ACTION_KEYS.get(action, set())
                for actions in self.roles.values() for action in actions)):
            raise ValueError('Paillier actions require a number field')
        self.lock = RLock()
        self.keys_file, self.db_file = self.folder/'keys.json', self.folder/'records.json'
        self.keys = load_json(self.keys_file, None)
        if self.keys is None and self.db_file.exists():
            raise ValueError('records exist without keys; restore the matching keys backup')
        if self.keys is not None and self.keys.get('config_hash') != digest(canonical(self.config)):
            raise ValueError('CONFIG changed; use a fresh folder or restore its matching CONFIG')
        self.db = load_json(self.db_file, {})
        if not isinstance(self.db, dict):
            raise ValueError('records must be a JSON object')

    def setup(self, passwords):
        if self.keys is not None:
            raise ValueError('already configured')
        if set(passwords) != set(self.roles) or any(not p for p in passwords.values()):
            raise ValueError('supply a nonblank password for every role')
        c = self.config
        # Validate the cipher/mode before generating expensive keys.
        symmetric_key = new_key(c['cipher'], c['bits']//8)
        sym_encrypt(c['cipher'], c['mode'], symmetric_key, b'check')
        private = {'cipher': symmetric_key.hex(), 'index': get_random_bytes(32).hex()}
        keys = {'config_hash': digest(canonical(c)), 'vaults': {}}
        if c['signature'] == 'rsa':
            k = rsa_generate(c['rsa_bits'])
            private['sign'], keys['public'] = k.export_key().decode(), k.publickey().export_key().decode()
        elif c['signature'] == 'elgamal':
            pub, private['sign'] = elgamal_sig_keygen()
            keys['public'] = list(pub)
        else:
            k = ECC.generate(curve='P-256')
            private['sign'], keys['public'] = k.export_key(format='PEM'), k.public_key().export_key(format='PEM')
        if 'number' in self.fields.values():
            keys['paillier'], private['paillier'] = paillier_keygen(c['paillier_bits'])
        for role, actions in self.roles.items():
            needed = {'index'}
            for action in actions:
                needed.update(self.ACTION_KEYS.get(action, set()))
            keys['vaults'][role] = password_seal(passwords[role], canonical(
                {name: value for name, value in private.items() if name in needed}))
        save_json(self.keys_file, keys)
        self.keys = keys

    def sign(self, data, secret):
        alg, kind = self.config['hash'], self.config['signature']
        if kind == 'rsa':
            return rsa_sign(rsa_import(secret), data, alg)
        if kind == 'elgamal':
            return list(elgamal_sign(data, secret, alg=alg))
        return dss_sign(ECC.import_key(secret), data, alg)

    def valid(self, record):
        try:
            if not isinstance(record, dict) or not isinstance(record.get('body'), dict):
                return False
            data, alg, pub = canonical(record['body']), self.config['hash'], self.keys['public']
            if digest(data, alg) != record['hash']:
                return False
            if self.config['signature'] == 'rsa':
                return rsa_verify(rsa_import(pub), data, record['sig'], alg)
            if self.config['signature'] == 'elgamal':
                return elgamal_verify(data, record['sig'], pub, alg)
            return dss_verify(ECC.import_key(pub), data, record['sig'], alg)
        except (ValueError, KeyError, TypeError):
            return False

    def handle(self, request):
        """JSON request -> JSON result. Check password AND permission on every call."""
        with self.lock:
            try:
                if (not isinstance(request, dict)
                        or any(not isinstance(request.get(k), str) for k in ('role', 'action', 'password'))):
                    raise ValueError('role, action, and password must be strings')
                role, action = request['role'], request['action']
                if action not in self.roles.get(role, []):
                    raise ValueError('action denied for this role')
                secret = json.loads(password_open(request['password'], self.keys['vaults'][role]))
                result = getattr(self, 'action_' + action)(request, secret)
                return {'ok': True, **result}
            except (ValueError, KeyError, TypeError, IndexError, ArithmeticError, OSError) as e:
                return {'ok': False, 'error': str(e)}

    def record(self, rid, secret):
        record = self.db.get(token(secret['index'], rid, 'id'))
        if record is None:
            raise ValueError('record not found')
        if not self.valid(record) or record['body']['id'] != rid:
            raise ValueError('tampered record; operation refused')
        return record

    def number(self, value):
        return scale_decimal(value, self.config['places'], self.config['max_abs'])

    def action_submit(self, req, secret):
        rid, values = req['id'], req['values']
        if not isinstance(rid, str) or not rid.strip() or set(values) != set(self.fields):
            raise ValueError('supply a nonblank ID and exactly the configured fields')
        index = token(secret['index'], rid, 'id')
        if index in self.db:
            raise ValueError('duplicate record ID')
        body = {'id': rid, 'time': now_iso(), 'text': {}, 'numbers': {}, 'plain': {}, 'tags': {}}
        c = self.config
        for field, kind in self.fields.items():
            value = values[field]
            if kind == 'number':
                number = self.number(value)
                body['numbers'][field] = paillier_encrypt(self.keys['paillier'], number)
                value = fmt_amount(number, c['places'])
            elif not isinstance(value, str) or not value.strip():
                raise ValueError('text fields must be nonblank strings')
            elif kind == 'text':
                body['text'][field] = sym_encrypt(c['cipher'], c['mode'], bytes.fromhex(secret['cipher']), value.encode())
            else:
                body['plain'][field] = value
            body['tags'][field] = token(secret['index'], value, field)
        raw = canonical(body)
        record = {'body': body, 'hash': digest(raw, c['hash']), 'sig': self.sign(raw, secret['sign'])}
        updated = {**self.db, index: record}
        save_json(self.db_file, updated)
        self.db = updated
        return {'id': rid, 'record': record}

    def action_list(self, req, secret):
        rows = []
        for r in self.db.values():
            body = r.get('body') if isinstance(r, dict) else None
            rid = body.get('id') if isinstance(body, dict) else None
            rows.append({'id': rid, 'valid': self.valid(r)})
        return {'records': rows}

    def action_verify(self, req, secret):
        return self.action_list(req, secret)

    def action_search(self, req, secret):
        field, value = req['field'], req['value']
        if field not in self.fields and field != 'id':
            raise ValueError('unknown search field')
        if field == 'id':
            return {'ids': [self.record(value, secret)['body']['id']]}
        if self.fields[field] == 'number':
            value = fmt_amount(self.number(value), self.config['places'])
        tag = token(secret['index'], value, field)
        return {'ids': [r['body']['id'] for r in self.db.values()
                        if self.valid(r) and r['body']['tags'].get(field) == tag]}

    def action_decrypt(self, req, secret):
        body = self.record(req['id'], secret)['body']
        decoded = {f: sym_decrypt(bytes.fromhex(secret['cipher']), box) for f, box in body['text'].items()}
        return {'values': {f: value.decode() for f, value in decoded.items()},
                'hex': {f: hexdump(value) for f, value in decoded.items()}}

    def action_aggregate(self, req, secret):
        ids, field = req['ids'], req['field']
        if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
            raise ValueError('ids must be a list of record IDs')
        ids = list(dict.fromkeys(ids))
        if self.fields.get(field) != 'number' or len(ids) < self.config['minimum']:
            raise ValueError('select a number field and enough distinct records')
        weights = req.get('weights', [1] * len(ids))
        if len(weights) != len(ids) or any(type(w) is not int for w in weights):
            raise ValueError('one integer weight per selected record')
        if sum(w != 0 for w in weights) < self.config['minimum']:
            raise ValueError('too few nonzero weights')
        pub = self.keys['paillier']
        if sum(abs(w) for w in weights) * self.config['max_abs'] >= pub['n']//2:
            raise ValueError('public bound cannot rule out Paillier wraparound')
        ciphertexts = [self.record(rid, secret)['body']['numbers'][field] for rid in ids]
        encrypted = paillier_weighted_sum(pub, ciphertexts, weights)
        total = paillier_decrypt(secret['paillier'], encrypted)
        return {'ciphertext': encrypted, 'total': fmt_amount(total, self.config['places']),
                'count': len(ids), 'weights': weights}
