"""Encrypted request/response adapter, independent of TCP versus HTTP.

Credentials travel INSIDE RSA-OAEP/AES-GCM, never in the public hello message.
Server key pinning is trust on first use. It does not authenticate first contact.
"""
import json
import hashlib
from pathlib import Path
import secrets

from toolkit.asymmetric import hybrid_decrypt, hybrid_encrypt, rsa_generate, rsa_import
from toolkit.signatures import rsa_sign, rsa_verify
from toolkit.util import canonical


class ServerProtocol:
    def __init__(self, app):
        self.app = app
        path = app.folder / 'transport_key.pem'
        if path.exists():
            self.key = rsa_import(path.read_text())
        else:
            self.key = rsa_generate(2048)
            with path.open('x') as f:
                f.write(self.key.export_key().decode())

    def handle(self, message):
        try:
            if message.get('op') == 'hello':
                hello = {'ok': True, 'nonce': message.get('nonce'),
                         'server_public': self.key.publickey().export_key().decode(),
                         'config': self.app.config}
                hello['signature'] = rsa_sign(self.key, canonical(hello), 'sha256')
                return hello
            inner = json.loads(hybrid_decrypt(self.key, message['box']))
            client_key = rsa_import(inner['reply_public'])
            result = self.app.handle(inner['request'])
            payload = {'nonce': inner['nonce'], 'result': result}
            payload['signature'] = rsa_sign(self.key, canonical(payload), 'sha256')
            return {'ok': True, 'box': hybrid_encrypt(client_key, canonical(payload))}
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            return {'ok': False, 'error': 'invalid encrypted request: ' + type(e).__name__}


class ClientProtocol:
    def __init__(self, raw_call, pin_file):
        self.raw_call = raw_call
        nonce = secrets.token_hex(16)
        hello = raw_call({'op': 'hello', 'nonce': nonce})
        if not isinstance(hello, dict) or not hello.get('ok'):
            raise ValueError('invalid server hello')
        hello = dict(hello)
        signature = hello.pop('signature', None)
        public = hello['server_public']
        self.server_key = rsa_import(public)
        if hello.get('nonce') != nonce or not rsa_verify(self.server_key, canonical(hello), signature, 'sha256'):
            raise ValueError('invalid or replayed signed server configuration')
        pin = Path(pin_file)
        if pin.exists() and pin.read_text() != public:
            raise ValueError('server key changed; verify the server before replacing the pin file')
        print('Server public-key SHA-256:', hashlib.sha256(self.server_key.export_key(format='DER')).hexdigest())
        if not pin.exists():
            with pin.open('x') as f:
                f.write(public)
            print('First server key saved. Verify its fingerprint through a trusted channel for real use.')
        self.key = rsa_generate(2048)
        self.config = hello['config']

    def call(self, request):
        nonce = secrets.token_hex(16)
        inner = {'nonce': nonce, 'request': request,
                 'reply_public': self.key.publickey().export_key().decode()}
        response = self.raw_call({'op': 'call', 'box': hybrid_encrypt(self.server_key, canonical(inner))})
        if not response.get('ok'):
            return response
        payload = json.loads(hybrid_decrypt(self.key, response['box']))
        signature = payload.pop('signature')
        if payload['nonce'] != nonce or not rsa_verify(self.server_key, canonical(payload), signature, 'sha256'):
            raise ValueError('invalid or replayed server response')
        return payload['result']
