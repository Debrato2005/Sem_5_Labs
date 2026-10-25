"""SECURE CLIENT/SERVER TEMPLATE - SERVER.  Real TCP sockets OR a JSON HTTP API.

Start the server first, then templates/net_client.py in a second terminal.
    python templates/net_server.py            (asks: tcp/http, port, data folder)

Protocol (same messages over both transports; HTTP = POST /api/<op>):
  hello     -> server RSA public key (clients encrypt to it / verify receipts)
  register  {client, pub}             store client's signing public key (TOFU*)
  submit    {client, id, box, hash_alg, digest, sig}
            box = hybrid AES-GCM + RSA-OAEP(session key)  [confidentiality]
            server: verify client RSA signature over canonical(envelope)  [authenticity]
                    decrypt, recompute hash of plaintext == digest        [integrity]
                    store ENCRYPTED envelope; return server-signed receipt [non-repudiation]
  get       {client, id, sig} -> owner's stored envelope
            HTTP GET /records/<id> also accepts client and sig in its JSON body
  list      {client, sig}     -> owner's ids + metadata
            sig covers the complete request, including op, without sig
  hash      {data_b64, alg} -> hash computed by server (Lab 5 integrity check)
*TOFU: the first key registered for a client name is trusted.  A real system
 would distribute keys through a certificate authority / KMS.
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # TOOLKIT-PATH
import os
import threading

from toolkit.util import ask, ask_choice, ask_int, b64d, canonical, load_json, now_iso, save_json
from toolkit.asymmetric import hybrid_decrypt, rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import rsa_sign, rsa_verify
from toolkit.net import serve_http, serve_tcp

DATA = 'server_data'
STATE = {}
STATE_LOCK = threading.RLock()


def load():
    os.makedirs(DATA, exist_ok=True)
    keyfile = os.path.join(DATA, 'server_key.pem')
    if not os.path.exists(keyfile):
        if os.path.exists(os.path.join(DATA, 'records.json')) or os.path.exists(os.path.join(DATA, 'clients.json')):
            raise ValueError('server key is missing but stored records or clients exist - restore the original key')
        with open(keyfile, 'w') as f:
            f.write(rsa_generate(2048).export_key().decode())
    with open(keyfile) as f:
        STATE['key'] = rsa_import(f.read())
    STATE['db'] = load_json(os.path.join(DATA, 'records.json'), {})
    STATE['clients'] = load_json(os.path.join(DATA, 'clients.json'), {})
    if not isinstance(STATE['db'], dict) or not isinstance(STATE['clients'], dict):
        raise ValueError('stored records or client registry are malformed')


def persist():
    save_json(os.path.join(DATA, 'records.json'), STATE['db'])
    save_json(os.path.join(DATA, 'clients.json'), STATE['clients'])


# ----------------------------------------------------------------- handler ---
def handle(req):
    # Serialize requests so duplicate checks and file writes form one operation.
    # This limits one server process. Separate server processes need a database lock.
    with STATE_LOCK:
        try:
            if not isinstance(req, dict):
                raise ValueError('request must be a JSON object')
            return handle_request(req)
        except (KeyError, ValueError, TypeError, OSError) as e:
            return {'ok': False, 'error': f'{type(e).__name__}: {e}'}


def handle_request(req):
    op = req.get('op')
    print(f'[server] request: {op}')
    if op == 'hello':
        return {'ok': True, 'server_pub': STATE['key'].publickey().export_key().decode()}
    if op == 'register':
        client, pem = req['client'], req['pub']
        if not isinstance(client, str) or not client.strip() or len(client) > 256:
            raise ValueError('client must be a nonblank name of at most 256 characters')
        if not isinstance(pem, str) or len(pem) > 16384:
            raise ValueError('pub must be an RSA public key in PEM format')
        key = rsa_import(pem)
        if key.has_private() or key.size_in_bits() < 2048:
            raise ValueError('register an RSA public key of at least 2048 bits')
        pem = key.export_key().decode()
        if client in STATE['clients'] and STATE['clients'][client] != pem:
            return {'ok': False, 'error': 'client already registered with another key'}
        STATE['clients'][client] = pem
        persist()
        return {'ok': True, 'msg': f'registered {req["client"]}'}
    if op == 'submit':
        return submit(req)
    if op == 'get':
        if not authenticated(req):
            return {'ok': False, 'error': 'signed client authentication required'}
        rec = STATE['db'].get(req['id'])
        if rec is not None and rec['client'] != req['client']:
            return {'ok': False, 'error': 'not found'}
        return {'ok': rec is not None, 'record': rec, 'error': None if rec else 'not found'}
    if op == 'list':
        if not authenticated(req):
            return {'ok': False, 'error': 'signed client authentication required'}
        return {'ok': True, 'records': {i: {'client': r['client'], 'time': r['received']}
                                        for i, r in STATE['db'].items() if r['client'] == req['client']}}
    if op == 'hash':
        return {'ok': True, 'digest': digest(b64d(req['data_b64']), req.get('alg', 'sha256'))}
    return {'ok': False, 'error': f'unknown op {op!r}'}


def authenticated(req):
    pub = STATE['clients'].get(req.get('client'))
    return bool(pub and rsa_verify(rsa_import(pub), canonical({k: v for k, v in req.items() if k != 'sig'}),
                                  req.get('sig', ''), 'sha256'))


ENVELOPE = ('client', 'id', 'box', 'hash_alg', 'digest')


def submit(req):
    pub = STATE['clients'].get(req.get('client'))
    if pub is None:
        return {'ok': False, 'error': 'unknown client - register first'}
    if req['id'] in STATE['db']:
        return {'ok': False, 'error': 'duplicate record id'}
    body = canonical({k: req[k] for k in ENVELOPE})
    if not isinstance(req['id'], str) or not req['id'].strip() or len(req['id']) > 256:
        raise ValueError('id must be a nonblank string of at most 256 characters')
    if not rsa_verify(rsa_import(pub), body, req['sig'], 'sha256'):
        print('[server] REJECTED: bad signature')
        return {'ok': False, 'error': 'signature verification FAILED (tampered or forged)'}
    try:
        plain = hybrid_decrypt(STATE['key'], req['box'])
    except ValueError:
        return {'ok': False, 'error': 'decryption failed (ciphertext tampered)'}
    recomputed = digest(plain, req['hash_alg'])
    if recomputed != req['digest']:
        return {'ok': False, 'error': 'hash mismatch - integrity FAILED'}
    rec = {k: req[k] for k in ENVELOPE}
    rec.update(sig=req['sig'], received=now_iso())      # store ENCRYPTED box only
    STATE['db'][req['id']] = rec
    persist()
    receipt = {'id': req['id'], 'digest': recomputed, 'received': rec['received']}
    print(f'[server] ACCEPTED {req["id"]}: signature OK, {req["hash_alg"]} OK')
    return {'ok': True, 'receipt': receipt,
            'receipt_sig': rsa_sign(STATE['key'], canonical(receipt), 'sha256')}


def main():
    global DATA
    transport = ask_choice('Transport', ['tcp', 'http'])
    port = ask_int('Port (e.g. 5000): ', 1024, 65535)
    DATA = ask('Server data folder [server_data]: ', allow_blank=True) or DATA
    load()
    print(f'{len(STATE["db"])} stored records, {len(STATE["clients"])} registered clients')
    if transport == 'tcp':
        serve_tcp(handle, port=port)
    else:
        serve_http({('POST', '/api/'): lambda body, q: (200, handle({**body, 'op': q['_rest']})),
                    ('GET', '/records/'): lambda body, q: (200, handle({**body, 'op': 'get', 'id': q['_rest']}))},
                   port=port)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nserver stopped')
    except (ValueError, OSError) as e:
        print('Server error:', e)
