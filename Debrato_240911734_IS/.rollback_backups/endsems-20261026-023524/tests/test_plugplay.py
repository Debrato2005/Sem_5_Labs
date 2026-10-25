"""One domain service must behave identically behind menus, TCP, and HTTP."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
import socket
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class PlugPlay(unittest.TestCase):
    def test_plugplay_menu_bundles_and_runs_without_sibling_files(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)/'answer.py'
            result = subprocess.run([sys.executable, str(root/'bundle.py'),
                str(root/'templates/plugplay/menu_app.py'), '-o', str(out)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([sys.executable, str(out), str(Path(d)/'data')], cwd=d,
                input='a\nb\nc\n0\n', capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            self.assertIn('SECURE RECORDS', run.stdout)

    def _wire_flow(self, http=False, bundled=False):
        root = Path(__file__).resolve().parents[1]
        from tests.helpers import free_port
        port = free_port()
        with tempfile.TemporaryDirectory() as d:
            server_path, client_path = root/'templates/plugplay/socket_server.py', root/'templates/plugplay/socket_client.py'
            if bundled:
                server_out, client_out = Path(d)/'server.py', Path(d)/'client.py'
                for src, dst in ((server_path, server_out), (client_path, client_out)):
                    subprocess.run([sys.executable, str(root/'bundle.py'), str(src), '-o', str(dst)],
                                   check=True, capture_output=True)
                server_path, client_path = server_out, client_out
            command = [sys.executable, '-u', str(server_path),
                       '--port', str(port), '--data', str(Path(d)/'data')]
            if http:
                command.append('--http')
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, cwd=d)
            process.stdin.write('a\nb\nc\n')
            process.stdin.flush()
            try:
                ready = False
                for _ in range(200):
                    if process.poll() is not None:
                        self.fail(process.communicate()[0])
                    try:
                        with socket.create_connection(('127.0.0.1', port), .2):
                            ready = True
                            break
                    except OSError:
                        time.sleep(.05)
                self.assertTrue(ready, 'server did not listen')
                client = [sys.executable, str(client_path), '--port', str(port)]
                if http:
                    client.append('--http')
                # Same input adapter as the standalone menu.
                script = ('1\na\n1\nG1\nMicroscope\n10.50\nBio\n'
                          '1\nG2\nTravel\n2.25\nBio\n0\n'
                          '2\nb\n2\nDepartment\nbio\n3\nG1\n0\n'
                          '3\nc\n2\nAmount\nG1,G2\nsum\n0\n0\n')
                result = subprocess.run(client, input=script, text=True, capture_output=True, cwd=d, timeout=120)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                self.assertIn('Microscope', output)
                self.assertIn('"total": "12.75"', output)
                self.assertNotIn('"ok": false', output)
                self.assertNotIn('Traceback', output)
            finally:
                process.kill()
                process.communicate()

    def test_real_tcp_two_programs(self):
        self._wire_flow()

    def test_real_http_two_programs(self):
        self._wire_flow(http=True)

    def test_bundled_socket_pair_without_toolkit_files(self):
        self._wire_flow(bundled=True)

    def test_roles_fields_restart_search_tamper_and_aggregate(self):
        from toolkit.records import RecordApp
        cfg = {'fields': {'Memo': 'text', 'Cost': 'number', 'Department': 'plain'},
               'roles': {'Author': ['submit', 'list'], 'Reader': ['verify', 'decrypt', 'search'],
                         'Treasurer': ['aggregate']},
               'cipher': 'AES', 'bits': 192, 'mode': 'CBC', 'hash': 'sha256',
               'signature': 'rsa', 'places': 2, 'minimum': 2, 'max_abs': 10**9,
               'rsa_bits': 1024, 'paillier_bits': 256}
        pw = {'Author': 'a', 'Reader': 'r', 'Treasurer': 't'}
        with tempfile.TemporaryDirectory() as d:
            app = RecordApp(d, cfg)
            app.setup(pw)

            def call(role, action, **data):
                return app.handle({'role': role, 'password': pw[role], 'action': action, **data})

            for rid, amount in [('A', '12.50'), ('B', '2.25')]:
                self.assertTrue(call('Author', 'submit', id=rid,
                    values={'Memo': 'private ' + rid, 'Cost': amount, 'Department': 'Lab'})['ok'])
            self.assertFalse(call('Reader', 'submit', id='X', values={})['ok'])
            self.assertFalse(app.handle({'role': 'Author', 'password': 'wrong', 'action': 'list'})['ok'])
            self.assertFalse(call('Author', 'submit', id='C', values={'Memo':'x', 'Cost':'NaN','Department':'Lab'})['ok'])
            self.assertEqual(call('Treasurer', 'aggregate', ids=['A','B'], field='Cost')['total'], '14.75')
            self.assertFalse(call('Treasurer', 'aggregate', ids=['A','B'], field='Cost', weights=[1,0])['ok'])
            self.assertEqual(call('Reader', 'search', field='Department', value='lab')['ids'], ['A','B'])
            self.assertEqual(call('Reader', 'decrypt', id='A')['values']['Memo'], 'private A')
            self.assertNotIn('private A', (Path(d)/'records.json').read_text())
            app = RecordApp(d, cfg)
            self.assertEqual(call('Reader', 'decrypt', id='B')['values']['Memo'], 'private B')
            records = json.loads((Path(d)/'records.json').read_text())
            next(iter(records.values()))['body']['plain']['Department'] = 'changed'
            (Path(d)/'records.json').write_text(json.dumps(records))
            app = RecordApp(d, cfg)
            self.assertFalse(call('Reader', 'decrypt', id='A')['ok'])
            self.assertFalse(call('Treasurer', 'aggregate', ids=['A','B'], field='Cost')['ok'])
            changed = {**cfg, 'bits': 256}
            with self.assertRaises(ValueError):
                RecordApp(d, changed)

    def test_missing_keys_never_reinitializes_existing_records(self):
        from toolkit.records import RecordApp
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'records.json').write_text('{}')
            with self.assertRaises(ValueError):
                RecordApp(d, {'fields': {'Memo':'text'}, 'roles': {'Author':['submit']}})


if __name__ == '__main__':
    unittest.main()
