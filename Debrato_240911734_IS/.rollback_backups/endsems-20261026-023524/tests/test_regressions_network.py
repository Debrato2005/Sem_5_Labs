"""Network request validation, record access, and persistence regressions."""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from toolkit import net
from toolkit.asymmetric import hybrid_encrypt, rsa_generate
from toolkit.hashing import digest
from toolkit.signatures import rsa_sign
from toolkit.util import canonical


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class RecordServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa_generate(2048)

    def setUp(self):
        self.server = module('regression_net_server', 'templates/net_server.py')
        self.client = module('regression_net_client', 'templates/net_client.py')
        self.server.STATE.update(key=self.key, clients={'alice': self.key.publickey().export_key().decode()}, db={})
        self.enterContext(patch.object(self.server, 'persist'))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def signed(self, op, client='alice', **fields):
        req = {'op': op, 'client': client, **fields}
        req['sig'] = rsa_sign(self.key, canonical(req))
        return req

    def test_get_and_list_require_signed_owner_requests(self):
        self.server.STATE['db']['R1'] = {'client': 'alice', 'received': 'now'}
        self.server.STATE['clients']['bob'] = self.key.publickey().export_key().decode()
        self.assertFalse(self.server.handle({'op': 'get', 'id': 'R1'})['ok'])
        self.assertFalse(self.server.handle({'op': 'list'})['ok'])
        self.assertFalse(self.server.handle(self.signed('get', 'bob', id='R1'))['ok'])
        self.assertEqual(self.server.handle(self.signed('list', 'bob'))['records'], {})
        self.assertTrue(self.server.handle(self.signed('get', id='R1'))['ok'])

    def test_invalid_registration_does_not_poison_identity(self):
        bad = self.server.handle({'op': 'register', 'client': 'new', 'pub': 'not RSA'})
        self.assertFalse(bad['ok'])
        self.assertNotIn('new', self.server.STATE['clients'])

    def test_private_key_registration_is_refused(self):
        bad = self.server.handle({'op': 'register', 'client': 'new',
                                  'pub': self.key.export_key().decode()})
        self.assertFalse(bad['ok'])
        self.assertNotIn('new', self.server.STATE['clients'])

    def test_server_does_not_replace_missing_keys_for_existing_records(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'records.json').write_text('{"old": {}}', encoding='utf-8')
            with patch.object(self.server, 'DATA', d):
                with self.assertRaisesRegex((SystemExit, ValueError), 'missing'):
                    self.server.load()
            self.assertFalse((Path(d) / 'server_key.pem').exists())

    def test_arbitrary_client_names_use_a_safe_local_key_filename(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            try:
                os.chdir(d)
                with patch.object(self.client, 'ask_choice', return_value='http'), \
                        patch.object(self.client, 'ask_int', return_value=5000), \
                        patch.object(self.client, 'ask', return_value='../invalid/client'), \
                        patch.object(self.client, 'rsa_generate', return_value=self.key), \
                        patch.object(self.client, 'connect'), patch.object(self.client, 'menu'):
                    self.client.main()
                self.assertEqual(len(list(Path(d).glob('*.pem'))), 1)
            finally:
                os.chdir(old)

    def test_simultaneous_duplicate_submission_is_accepted_once(self):
        body = b'secret'
        req = {'client': 'alice', 'id': 'same', 'box': hybrid_encrypt(self.key.publickey(), body),
               'hash_alg': 'sha256', 'digest': digest(body)}
        req['sig'] = rsa_sign(self.key, canonical(req))
        req['op'] = 'submit'
        original = self.server.hybrid_decrypt
        def slow_decrypt(*args):
            time.sleep(0.1)              # Both old handlers pass the duplicate check.
            return original(*args)
        with patch.object(self.server, 'hybrid_decrypt', side_effect=slow_decrypt), \
                concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.server.handle, [req, req]))
        self.assertEqual(sum(bool(r['ok']) for r in results), 1)


class HTTPWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        code = (f'import sys; sys.path.insert(0, {str(ROOT)!r}); '
                'from toolkit.net import serve_http; '
                'serve_http({("POST", "/echo/"): lambda b,q: (200, {"body":b,"query":q})}, '
                f'port={cls.port})')
        cls.process = subprocess.Popen([sys.executable, '-u', '-c', code],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        cls.addClassCleanup(cls.stop_server)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=1):
                    return
            except PermissionError:
                raise                         # A real sandbox failure needs a runtime retry.
            except OSError:
                if cls.process.poll() is not None:
                    raise RuntimeError(cls.process.stdout.read())
                time.sleep(0.05)
        raise RuntimeError('HTTP server did not start')

    @classmethod
    def stop_server(cls):
        cls.process.kill()
        cls.process.communicate(timeout=5)

    def raw(self, length, body=b'{}'):
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as sock:
            sock.sendall((f'POST /echo/test HTTP/1.0\r\nHost: localhost\r\n'
                          f'Content-Length: {length}\r\n\r\n').encode() + body)
            sock.shutdown(socket.SHUT_WR)
            data = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        return int(data.split(b' ', 2)[1])

    def test_negative_content_length_is_rejected(self):
        self.assertEqual(self.raw(-1), 400)

    def test_oversized_content_length_is_rejected_before_reading(self):
        self.assertEqual(self.raw(64 * 1024 * 1024 + 1, b''), 413)

    def test_json_arrays_are_rejected(self):
        self.assertEqual(self.raw(2, b'[]'), 400)

    def test_http_path_and_query_are_url_decoded(self):
        status, result = net.http_json('POST',
            f'http://127.0.0.1:{self.port}/echo/A%2FB?label=hello%20world', {})
        self.assertEqual(status, 200)
        self.assertEqual(result['query']['_rest'], 'A/B')
        self.assertEqual(result['query']['label'], 'hello world')


class TCPWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        code = (f'import sys; sys.path.insert(0, {str(ROOT)!r}); '
                'from toolkit.net import serve_tcp; '
                f'serve_tcp(lambda r: {{"ok": True}}, port={cls.port}, timeout=0.15)')
        cls.process = subprocess.Popen([sys.executable, '-u', '-c', code],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        cls.addClassCleanup(cls.stop_server)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=1):
                    return
            except PermissionError:
                raise
            except OSError:
                if cls.process.poll() is not None:
                    raise RuntimeError(cls.process.stdout.read())
                time.sleep(0.05)
        raise RuntimeError('TCP server did not start')

    @classmethod
    def stop_server(cls):
        cls.process.kill()
        cls.process.communicate(timeout=5)

    def test_idle_connection_releases_server_for_the_next_client(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=1) as idle:
            with socket.create_connection(('127.0.0.1', self.port), timeout=2) as active:
                net.send_msg(active, {'request': 'hello'})
                self.assertTrue(net.recv_msg(active)['ok'])

    def test_nonobject_tcp_json_is_refused_and_server_continues(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as bad:
            bad.sendall(struct.pack('>I', 2) + b'[]')
            self.assertEqual(bad.recv(4), b'')
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as good:
            net.send_msg(good, {'request': 'hello'})
            self.assertTrue(net.recv_msg(good)['ok'])


if __name__ == '__main__':
    unittest.main()
