"""SECURE CLIENT/SERVER TEMPLATE - CLIENT (menu driven).  Run AFTER net_server.py.
    python templates/net_client.py           (asks: tcp/http, port, client name)

The client keeps its RSA signing key in a filename derived from SHA-256(name) and gets the
server's public key with 'hello'.  See net_server.py for the protocol.
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # TOOLKIT-PATH
import os

from toolkit.util import ask, ask_choice, ask_int, b64e, canonical, menu
from toolkit.asymmetric import hybrid_encrypt, rsa_generate, rsa_import
from toolkit.hashing import digest
from toolkit.signatures import rsa_sign, rsa_verify
from toolkit.net import TcpClient, http_json

S = {}


def call(req):
    """Same request dict over either transport."""
    req = dict(req)
    if req.get('op') in ('get', 'list'):
        req['client'] = S['name']
        req['sig'] = rsa_sign(S['key'], canonical(req), 'sha256')
    if S['transport'] == 'tcp':
        resp = S['conn'].call(req)
    else:
        op = req.pop('op')
        _, resp = http_json('POST', f'http://127.0.0.1:{S["port"]}/api/{op}', req)
    if not resp.get('ok'):
        print('  SERVER ERROR:', resp.get('error'))
    return resp


def connect():
    S['server_pub'] = rsa_import(call({'op': 'hello'})['server_pub'])
    print('Got server public key.')
    registered = call({'op': 'register', 'client': S['name'],
                       'pub': S['key'].publickey().export_key().decode()})
    if not registered.get('ok'):
        raise ConnectionError(f'client registration failed: {registered.get("error")}')
    print(registered.get('msg', ''))


def make_envelope(rid, data, alg):
    env = {'client': S['name'], 'id': rid, 'box': hybrid_encrypt(S['server_pub'], data),
           'hash_alg': alg, 'digest': digest(data, alg)}
    env['sig'] = rsa_sign(S['key'], canonical(env), 'sha256')
    return env


def submit():
    rid = ask('Record ID: ')
    data = ask('Message / record content: ').encode()
    alg = ask_choice('Hash', ['sha256', 'sha512', 'md5', 'sha1'])
    env = make_envelope(rid, data, alg)
    print(f'  {alg} digest: {env["digest"]}\n  AES-GCM ct: {env["box"]["ct"][:60]}')
    resp = call({'op': 'submit', **env})
    if resp.get('ok'):
        good = rsa_verify(S['server_pub'], canonical(resp['receipt']), resp['receipt_sig'], 'sha256')
        print('  ACCEPTED. Receipt:', resp['receipt'], '| server signature', 'VALID' if good else 'INVALID')


def tamper_submit():
    """Modify the ciphertext AFTER signing - server must reject it."""
    env = make_envelope(ask('Record ID: '), ask('Content: ').encode(), 'sha256')
    ct = bytearray(bytes.fromhex(env['box']['ct']))
    ct[0] ^= 1
    env['box']['ct'] = ct.hex()
    print('  sent tampered envelope ->', call({'op': 'submit', **env}).get('ok'))


def integrity_check():
    """Lab 5: send data, server returns its hash, client compares."""
    data = ask('Data to send: ').encode()
    corrupt = ask_choice('Simulate corruption in transit', ['no', 'yes'])
    sent = data[:-1] + bytes([data[-1] ^ 1]) if corrupt == 'yes' else data
    local = digest(data, 'sha256')
    remote = call({'op': 'hash', 'data_b64': b64e(sent), 'alg': 'sha256'})['digest']
    print(f'  local  {local}\n  server {remote}\n  ->',
          'INTEGRITY OK' if local == remote else 'MISMATCH - data corrupted/tampered')


def get_record():
    r = call({'op': 'get', 'id': ask('Record ID: ')})
    if r.get('ok'):
        rec = r['record']
        print('  stored (encrypted):', {k: (str(v)[:50] + '...') for k, v in rec.items()})


def main():
    S['transport'] = ask_choice('Transport', ['tcp', 'http'])
    S['port'] = ask_int('Server port: ', 1024, 65535)
    S['name'] = ask('Client name: ')
    path = f'client_{digest(S["name"].encode(), "sha256")}.pem'
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(rsa_generate(2048).export_key().decode())
    with open(path) as f:
        S['key'] = rsa_import(f.read())
    if S['transport'] == 'tcp':
        S['conn'] = TcpClient(port=S['port'])
    try:
        connect()
        menu(f'CLIENT {S["name"]}', [('Submit signed + encrypted record', submit),
                                     ('List records on server', lambda: print(call({'op': 'list'}).get('records'))),
                                     ('Fetch stored record', get_record),
                                     ('Integrity check (server hashes data)', integrity_check),
                                     ('Tamper test (server must reject)', tamper_submit)])
    finally:
        if S['transport'] == 'tcp':
            S['conn'].close()


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nbye')
    except (OSError, ValueError) as e:
        print('Cannot reach server:', e)
