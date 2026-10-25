"""End-to-end tests of the complete programs (scripted menu input, restarts,
tampering, wrong passwords, invalid input, real TCP + HTTP processes)."""
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.helpers import PY, ROOT, TempDir, free_port, run  # noqa: E402
import pathlib  # noqa: E402


def load(*parts):
    with open(os.path.join(*parts), encoding='utf-8') as f:
        return json.load(f)


class GrantPortal(unittest.TestCase):
    def test_full_flow_restart_and_tamper(self):
        with TempDir() as d:
            out = run('solutions/grant_portal.py', [
                'r1', 'r2', 'r3',                                   # role passwords
                '1', 'r1',                                          # Researcher
                '1', 'G1', 'Lab equipment', '1500.50',
                '1', 'G2', 'Travel', 'abc', '250.255', '250.25',    # invalid amounts re-prompted
                '1', 'G1',                                          # duplicate ID -> error
                '2', '0',
                '2', 'r2', '1', '2', 'G1', '2', 'NOPE', '3', 'G2', '0',
                '3', 'r3', '2', 'G1,G2', '2', 'G1', '0',
                '0'], d)
            self.assertIn('already exists', out)
            self.assertIn('enter a number with at most 2 decimal places', out)
            self.assertIn('TOTAL expenditure of 2 grants = 1750.75', out)
            self.assertIn('Need at least 2 valid grants', out)
            self.assertIn('NOT FOUND', out)
            self.assertIn('|Travel|', out)                          # hex dump ASCII column
            self.assertIn('54 72 61 76 65 6c', out)                 # 'Travel' in hex
            self.assertNotIn('Traceback', out)
            stored = load(d, 'grants.json')
            self.assertFalse(any('Lab equipment' in json.dumps(r) for r in stored.values()))

            out = run('solutions/grant_portal.py', [                # RESTART
                '2', 'wrong',                                       # wrong password
                '4', 'G1', 'desc_ct',                               # tamper on disk
                '2', 'r2', '1', '3', 'G1', '0',
                '3', 'r3', '2', 'ALL', '0',
                '1', 'r1', '1', 'G3', 'Books', '99.99', '0',
                '3', 'r3', '2', 'ALL', '0', '0'], d)
            self.assertIn('Loaded 2 stored grant record(s)', out)
            self.assertIn('ACCESS DENIED', out)
            self.assertIn('TAMPERED MD5 MISMATCH', out)
            self.assertIn('REFUSED', out)
            self.assertIn('Need at least 2 valid grants', out)      # only G2 valid
            self.assertIn('TOTAL expenditure of 2 grants = 350.24', out)
            self.assertNotIn('Traceback', out)


class EVoting(unittest.TestCase):
    def test_election(self):
        with TempDir() as d:
            out = run('solutions/evoting.py', [
                '1:Asha, 2:Ravi, 3:Meena', 'C1, C2', '', '2099-01-01 00:00+00:00', '3', '2',
                'ec', 'au', 'a1', 'a2', 'a3',
                '2', 'ec', '1', 'V1', 'C1', 'v1', '1', 'V2', 'C1', 'v2', '1', 'V3', 'C2', 'v3',
                '1', 'V1', '0',                                     # duplicate registration
                '1', 'V1', 'v1', '1', '1', 'C1', '1', '0',          # cast, then try again
                '1', 'V2', 'bad',                                   # wrong voter password
                '1', 'V2', 'v2', '1', '2', 'C2', '1', '2', 'C1', '0',   # wrong constituency first
                '1', 'V3', 'v3', '1', '2', 'C2', '2', '0',
                '3',                                                # tally before close -> refused
                '2', 'ec', '2', '4', 'constituency', 'C1', '5', '', '0',
                '0'], d)
            self.assertIn('voter already registered', out)
            self.assertIn('you have already voted', out)
            self.assertIn('ACCESS DENIED', out)
            self.assertIn('differs from your registered constituency', out)
            self.assertEqual(out.count('ACCEPTED - decrypted, SHA-512 matches'), 3)
            self.assertIn('2 ballot(s) found', out)
            self.assertIn('election still open', out)
            self.assertIn('Encrypted totals over 3 valid ballot(s)', out)
            self.assertNotIn('Traceback', out)

            ballots = load(d, 'ballots.json')
            first = next(iter(ballots))
            out = run('solutions/evoting.py', [                     # RESTART
                '5', first, 'vote_ct',
                '4', 'au', '1', '0',
                '2', 'ec', '6', 'CLOSE', '0',
                '3', '1', 'a1', '1', '3', 'a3',
                '4', 'au', '4', '0', '0'], d)
            self.assertIn('envelope ElGamal signature INVALID', out)
            self.assertIn('EXCLUDED', out)
            self.assertIn('FINAL RESULTS (2 ballots, decrypted by authorities [1, 3])', out)
            self.assertRegex(out, r'2 Ravi\s+2')
            self.assertRegex(out, r'1 Asha\s+0')
            self.assertIn('this authority already contributed', out)
            self.assertNotIn('Traceback', out)

    def test_server_rejects_tampered_pending_ballot(self):
        with TempDir() as d:
            run('solutions/evoting.py', [
                '1:A, 2:B', 'X', '', '2099-01-01 00:00+00:00', '2', '2', 'ec', 'au', 'a1', 'a2',
                '2', 'ec', '1', 'V1', 'X', 'v1', '0',
                '1', 'V1', 'v1', '1', '2', 'X', '0', '0'], d)
            sid = next(iter(load(d, 'ballots.json')))
            out = run('solutions/evoting.py', ['5', sid, 'ballot_ct', '2', 'ec', '2', '0', '0'], d)
            self.assertIn('REJECTED', out)


class Template(unittest.TestCase):
    def test_generic_records(self):
        with TempDir() as d:
            out = run('templates/secure_records_menu.py', [
                'p1', 'p2', 'p3',
                '1', 'p1', '1', 'R1', 'hello', '10.50', '1', 'R2', 'two', '4.25', '0',
                '4', 'R2',
                '3', 'p3', '2', 'ALL', 'sum', '1', 'R1', '0',
                '3', 'p1', '0',                                      # wrong password
                '0'], d)
            self.assertIn('R2: EXCLUDED', out)
            self.assertIn('Need at least 2 valid records', out)
            self.assertIn('ACCESS DENIED', out)
            self.assertNotIn('Traceback', out)


def variant(d, aes, **config):
    """Copy the template with CONFIG lines replaced (scenario-independence test)."""
    lines = (ROOT / 'templates' / 'secure_records_menu.py').read_text(encoding='utf-8').splitlines()
    config['AES_BITS, AES_MODE'] = aes
    for name, value in config.items():
        i = next(k for k, line in enumerate(lines) if line.startswith(name + ' ='))
        end = i
        if lines[i].split('#')[0].rstrip().endswith('{'):    # multi-line dict
            while not lines[end].startswith('}'):
                end += 1
        lines[i:end + 1] = [f'{name} = {value!r}']
    path = os.path.join(d, 'variant.py')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    return path


class TemplateVariants(unittest.TestCase):
    def test_hospital_gcm_sha512_elgamal_search(self):
        with TempDir() as d:
            script = variant(d, (256, 'GCM'), TITLE='HOSPITAL', ID_LABEL='Patient ID',
                             TEXT_FIELDS=['Diagnosis'], NUMBER_FIELDS=[], PLAIN_FIELDS=['Ward'],
                             SEARCH_FIELDS=['Ward'], HASH='sha512', SIGN='elgamal',
                             ROLES={'Doctor': ['submit', 'view'], 'Nurse': ['verify', 'search', 'decrypt']})
            out = run(script, ['dp', 'np', '1', 'dp', '1', 'P1', 'flu', 'W1', '1', 'P2', 'cold', 'W2',
                               '1', 'P3', 'cough', 'W1', '0', '2', 'np', '2', 'Ward', 'w1', '3', 'P2',
                               '1', '0', '3', 'P3', '2', 'np', '1', '3', 'P3', '0', '0'],
                      os.path.join(d, 'data'))
            self.assertIn('2 match(es)', out)
            self.assertIn('Diagnosis: cold', out)
            self.assertIn('SHA512 matches and ELGAMAL signature valid', out)
            self.assertIn('AES-256-GCM', out)
            self.assertIn('P3           TAMPERED', out)
            self.assertIn('REFUSED', out)
            self.assertNotIn('Traceback', out)

    def test_bank_ecdsa_ctr_two_numbers(self):
        with TempDir() as d:
            script = variant(d, (128, 'CTR'), ID_LABEL='Account', TEXT_FIELDS=['Owner'],
                             NUMBER_FIELDS=['Balance', 'Loan'], PLACES=0, HASH='sha256', SIGN='ecdsa',
                             ROLES={'Teller': ['submit', 'list'], 'Manager': ['aggregate', 'verify']})
            out = run(script, ['tp', 'mp', '1', 'tp', '1', 'A1', 'Ann', '100', '20', '1', 'A2', 'Bo', '300',
                               '-5', '2', '0', '2', 'mp', '1', 'Loan', 'ALL', 'sum', '1', 'Balance',
                               'A1,A2', 'weighted', '2,1', '2', '0', '0'], os.path.join(d, 'data'))
            self.assertIn('SUM of Loan over 2 records = 15', out)
            self.assertIn('WEIGHTED of Balance over 2 records = 500', out)
            self.assertIn('SHA256 matches and ECDSA signature valid', out)
            self.assertNotIn('Traceback', out)


class Network(unittest.TestCase):
    def _session(self, transport):
        port = free_port()
        with TempDir() as d:
            srv = subprocess.Popen([PY, str(ROOT / 'templates/net_server.py')], cwd=d,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
            srv.stdin.write(f'{transport}\n{port}\n{d}/srv\n')
            srv.stdin.flush()
            try:
                for _ in range(100):                                # wait until listening
                    try:
                        import socket
                        socket.create_connection(('127.0.0.1', port), 1).close()
                        break
                    except OSError:
                        time.sleep(0.2)
                out = run('templates/net_client.py', [
                    transport, str(port), 'alice',
                    '1', 'M1', 'top secret', 'sha512',
                    '1', 'M1', 'again', 'sha256',                   # duplicate id
                    '5', 'M2', 'evil',                              # tampered -> rejected
                    '4', 'hello', 'no', '4', 'hello', 'yes',
                    '3', 'M1', '2', '0'], cwd=d, timeout=120)
            finally:
                srv.kill()
                srv.communicate()
            self.assertIn('ACCEPTED', out)
            self.assertIn('server signature VALID', out)
            self.assertIn('duplicate record id', out)
            self.assertIn('signature verification FAILED', out)
            self.assertIn('INTEGRITY OK', out)
            self.assertIn('MISMATCH - data corrupted', out)
            self.assertNotIn('Traceback', out)
            db = load(d, 'srv', 'records.json')
            self.assertEqual(list(db), ['M1'])
            self.assertNotIn('top secret', json.dumps(db))

    def test_tcp(self):
        self._session('tcp')

    def test_http(self):
        self._session('http')


class Bundle(unittest.TestCase):
    def test_bundled_grant_portal_runs_standalone(self):
        with TempDir() as d:
            out_file = os.path.join(d, 'grant_single.py')
            subprocess.run([PY, str(ROOT / 'bundle.py'), str(ROOT / 'solutions/grant_portal.py'),
                            '-o', out_file], check=True, capture_output=True)
            src = pathlib.Path(out_file).read_text(encoding='utf-8')
            self.assertNotIn('from toolkit', src)
            p = subprocess.run([PY, out_file, os.path.join(d, 'data')], cwd=d, text=True,
                               input='a\nb\nc\n1\na\n1\nX1\nd\n1\n1\nX2\ne\n2\n0\n3\nc\n2\nALL\n0\n0\n',
                               capture_output=True, timeout=300)
            self.assertIn('TOTAL expenditure of 2 grants = 3.00', p.stdout)


if __name__ == '__main__':
    unittest.main()
