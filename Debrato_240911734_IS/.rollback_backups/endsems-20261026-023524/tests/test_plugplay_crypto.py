"""Crypto choices, trust boundaries and malformed-state checks for RecordApp."""
import copy
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'templates' / 'plugplay'))
from protocol import ClientProtocol, ServerProtocol
from toolkit.records import RecordApp
from toolkit import util


def config(**changes):
    return {'fields': {'Memo': 'text', 'Cost': 'number', 'Department': 'plain'},
            'roles': {'Author': ['submit', 'list'], 'Reader': ['verify', 'decrypt', 'search'],
                      'Treasurer': ['aggregate']}, 'rsa_bits': 1024, 'paillier_bits': 256,
            **changes}


class CryptoChoices(unittest.TestCase):
    def test_custom_average_action_receives_its_declared_key(self):
        class MyApp(RecordApp):
            ACTION_KEYS = {**RecordApp.ACTION_KEYS, 'average': {'paillier'}}

            def action_average(self, request, secret):
                result = self.action_aggregate(request, secret)
                return {'fraction': result['total'] + '/' + str(result['count'])}

        with tempfile.TemporaryDirectory() as d:
            cfg = config(roles={'Author': ['submit'], 'Manager': ['average']})
            app = MyApp(d, cfg)
            app.setup({'Author': 'a', 'Manager': 'm'})
            for rid, value in [('A', '1.00'), ('B', '3.00')]:
                result = app.handle({'role':'Author','password':'a','action':'submit','id':rid,
                    'values':{'Memo':'x','Cost':value,'Department':'Lab'}})
                self.assertTrue(result['ok'], result)
            result = app.handle({'role':'Manager','password':'m','action':'average',
                                  'ids':['A','B'],'field':'Cost'})
            self.assertEqual(result, {'ok':True,'fraction':'4.00/2'})

    def test_all_signature_choices_and_cipher_variations(self):
        for kind, cipher, bits, mode, hash_name in (
                ('rsa', 'AES', 192, 'CBC', 'md5'),
                ('elgamal', 'AES', 256, 'GCM', 'sha512'),
                ('ecdsa', 'DES3', 192, 'EAX', 'sha256')):
            with self.subTest(signature=kind), tempfile.TemporaryDirectory() as d:
                cfg = config(signature=kind, cipher=cipher, bits=bits, mode=mode, hash=hash_name)
                app = RecordApp(d, cfg)
                app.setup({'Author': 'a', 'Reader': 'r', 'Treasurer': 't'})
                for rid, amount in (('A', '12.50'), ('B', '2.25')):
                    result = app.handle({'role': 'Author', 'password': 'a', 'action': 'submit', 'id': rid,
                                         'values': {'Memo': 'secret ' + rid, 'Cost': amount, 'Department': 'Lab'}})
                    self.assertTrue(result['ok'], result)
                    self.assertTrue(app.valid(result['record']))
                app = RecordApp(d, cfg)
                result = app.handle({'role': 'Reader', 'password': 'r', 'action': 'decrypt', 'id': 'A'})
                self.assertEqual(result['values']['Memo'], 'secret A')
                result = app.handle({'role': 'Treasurer', 'password': 't', 'action': 'aggregate',
                                     'ids': ['A', 'B'], 'field': 'Cost'})
                self.assertEqual(result['total'], '14.75')
                record = next(iter(app.db.values()))
                record['sig'] = None
                self.assertFalse(app.valid(record))

    def test_bad_configs_fail_before_setup(self):
        bad = ({'bits': 129}, {'cipher': 'DES', 'bits': 192}, {'hash': 'bogus'},
               {'minimum': True}, {'places': 1.5}, {'max_abs': 1.5},
               {'fields': []}, {'fields': {'': 'text'}}, {'fields': {'id': 'text'}},
               {'roles': []}, {'roles': {'': ['submit']}},
               {'fields': {'Memo': 'text'}, 'roles': {'Reader': ['aggregate']}})
        for changes in bad:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    RecordApp(d, config(**changes))

    def test_malformed_records_do_not_crash_list_or_verify(self):
        with tempfile.TemporaryDirectory() as d:
            app = RecordApp(d, config())
            app.setup({'Author': 'a', 'Reader': 'r', 'Treasurer': 't'})
            for record in (None, 1, [], {'body': None}, {'body': []}):
                app.db = {'bad': record}
                for role, password, action in (('Author', 'a', 'list'), ('Reader', 'r', 'verify')):
                    with self.subTest(record=record, action=action):
                        result = app.handle({'role': role, 'password': password, 'action': action})
                        self.assertTrue(result['ok'])
                        self.assertEqual(result['records'], [{'id': None, 'valid': False}])

    def test_malformed_password_requests_return_json_errors(self):
        with tempfile.TemporaryDirectory() as d:
            app = RecordApp(d, config())
            app.setup({'Author': 'a', 'Reader': 'r', 'Treasurer': 't'})
            for password in (None, 1, [], {}):
                with self.subTest(password=password):
                    result = app.handle({'role': 'Author', 'password': password, 'action': 'list'})
                    self.assertFalse(result['ok'])

    def test_decimal_conversion_never_rounds_extra_places(self):
        with tempfile.TemporaryDirectory() as d:
            app = RecordApp(d, config())
            for value in ('1.000000000000000000000000000000000000000000001', '1e-10000000',
                          '12.5000000000000000000000000000000000000000001'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    app.number(value)
            self.assertEqual(app.number('12.5000000000000000000000000000000000000000000'), 1250)

    def test_shared_amount_input_and_format_never_round(self):
        for invalid in ('1e-10000000', '1.000000000000000000000000000000000000000000001'):
            with self.subTest(invalid=invalid), mock.patch('builtins.input', side_effect=[invalid, '12.50']):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(util.ask_amount('value: '), 1250)
        self.assertEqual(util.fmt_amount(10**40 + 1, 2), '1' + '0' * 38 + '.01')


class ProtocolTrust(unittest.TestCase):
    def test_pinned_server_key_also_authenticates_the_config(self):
        with tempfile.TemporaryDirectory() as d:
            app = RecordApp(d, config())
            app.setup({'Author': 'a', 'Reader': 'r', 'Treasurer': 't'})
            server = ServerProtocol(app)
            pin = Path(d) / 'pin.pem'
            client = ClientProtocol(server.handle, pin)
            result = client.call({'role': 'Author', 'password': 'a', 'action': 'list'})
            self.assertTrue(result['ok'])

            def tampered_hello(message):
                reply = copy.deepcopy(server.handle(message))
                if message.get('op') == 'hello':
                    reply['config']['title'] = 'FORGED CONFIG'
                return reply

            with self.assertRaises(ValueError):
                ClientProtocol(tampered_hello, pin)


if __name__ == '__main__':
    unittest.main()
