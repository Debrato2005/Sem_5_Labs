"""Checks for receipt replay, aggregate disclosure, and scenario input failures."""
import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from toolkit.asymmetric import rsa_generate
from toolkit.hashing import digest
from toolkit.homomorphic import paillier_decrypt, paillier_encrypt, paillier_keygen
from toolkit.searchable import token
from toolkit.signatures import elgamal_sig_keygen, rsa_sign
from toolkit.util import canonical, now_utc


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class Scenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ec = rsa_generate(1024)
        cls.pub, cls.priv = paillier_keygen(128)
        (_, _, cls.y), cls.x = elgamal_sig_keygen()

    def setUp(self):
        self.ev = module('regression_evoting', 'solutions/evoting.py')
        self.rec = module('regression_records', 'templates/secure_records_menu.py')
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        for m in (self.ev, self.rec):
            self.enterContext(patch.object(m, 'save_json'))
            self.enterContext(patch.object(m.LOG, 'log'))
        now = now_utc()
        self.cfg = {'start': (now - timedelta(minutes=1)).isoformat(),
                    'end': (now + timedelta(hours=1)).isoformat(), 'closed_at': None,
                    'candidates': {'1': 'A', '2': 'B'}, 'constituencies': ['X'],
                    'voters': {'V1': {'constituency': 'X', 'y': self.y}},
                    'ec_pub': self.ec.publickey().export_key().decode(),
                    'tsa_pub': self.ec.publickey().export_key().decode(),
                    'tsa_key': self.ec.export_key().decode(), 'paillier': self.pub}

    def ballot(self, vid='V1'):
        ballots = {}
        with patch.object(self.ev, 'ask_choice', side_effect=['1', 'X']):
            self.ev.cast(self.cfg, ballots, vid, self.x)
        return ballots

    def test_unsigned_status_change_cannot_bypass_server_processing(self):
        ballots = self.ballot()
        next(iter(ballots.values()))['status'] = 'accepted'
        with self.assertRaisesRegex(ValueError, 'no valid accepted ballots'):
            self.ev.encrypted_tally(self.cfg, ballots, {}, None)

    def test_copied_receipt_does_not_count_a_voter_twice(self):
        ballots = self.ballot()
        self.ev.process(self.cfg, ballots, {}, self.ec, '00' * 32)
        ballots['copy'] = copy.deepcopy(next(iter(ballots.values())))
        enc, count = self.ev.encrypted_tally(self.cfg, ballots, {}, None)
        self.assertEqual(count, 1)
        self.assertEqual(paillier_decrypt(self.priv, enc['1']), 1)

    def test_voter_id_is_not_used_as_a_temporary_file_path(self):
        self.cfg['voters']['V/1'] = self.cfg['voters'].pop('V1')
        ballots = self.ballot('V/1')
        self.assertEqual(len(ballots), 1)

    def test_weighted_aggregate_requires_two_nonzero_contributors(self):
        keys = {'paillier_pub': self.pub,
                'sign_pub': self.ec.publickey().export_key().decode()}
        sec = {'idx': '00' * 32, 'paillier': self.priv}
        db = {}
        for rid, amount in [('R1', 123), ('R2', 456)]:
            r = {'id': rid, 'text': {}, 'numbers': {'Amount': paillier_encrypt(self.pub, amount)},
                 'plain': {}, 'tags': [], 'timestamp': 'now'}
            body = canonical(r)
            r.update(hash=digest(body, 'md5'), sig=rsa_sign(self.ec, body, 'md5'))
            db[token(sec['idx'], rid, 'id')] = r
        with patch.object(self.rec, 'ask_list', side_effect=[['R1', 'R2'], ['1', '0']]), \
                patch.object(self.rec, 'ask_choice', return_value='weighted'):
            with self.assertRaisesRegex(ValueError, 'nonzero'):
                self.rec.aggregate(keys, db, sec)

    def test_records_do_not_create_new_keys_over_existing_records(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / 'records.json'
            db.write_text(json.dumps({'old': {}}), encoding='utf-8')
            with patch.object(self.rec, 'KEYS', str(Path(d) / 'keys.json')), \
                    patch.object(self.rec, 'DB', str(db)), patch.object(self.rec, 'setup') as setup:
                with self.assertRaisesRegex(SystemExit, 'keys.json is missing'):
                    self.rec.main()
                setup.assert_not_called()

    def test_election_does_not_create_new_keys_over_existing_ballots(self):
        with tempfile.TemporaryDirectory() as d:
            ballots = Path(d) / 'ballots.json'
            ballots.write_text('{"old": {}}', encoding='utf-8')
            with patch.object(self.ev, 'CFG', str(Path(d) / 'election.json')), \
                    patch.object(self.ev, 'BALLOTS', str(ballots)), patch.object(self.ev, 'setup') as setup:
                with self.assertRaisesRegex(SystemExit, 'election.json is missing'):
                    self.ev.main()
                setup.assert_not_called()

    def test_candidate_ids_are_canonical_and_invalid_setup_reprompts(self):
        answers = ['01:A,1:B', '01:A,2:B', 'X', '', '2099-01-01 00:00+00:00']
        with patch('builtins.input', side_effect=answers), \
                patch.object(self.ev, 'ask_int', side_effect=[2, 2]), \
                patch.object(self.ev, 'rsa_generate', return_value=self.ec), \
                patch.object(self.ev, 'paillier_threshold_keygen', return_value=(self.pub, [])), \
                patch.object(self.ev, 'new_password', return_value='pw'):
            cfg = self.ev.setup()
        self.assertEqual(list(cfg['candidates']), ['1', '2'])

    def test_invalid_setup_dates_and_empty_constituencies_reprompt(self):
        answers = ['1:A,2:B', '', 'X', 'bad date', '',
                   'bad date', '2000-01-01 00:00+00:00', '2099-01-01 00:00+00:00']
        with patch('builtins.input', side_effect=answers), \
                patch.object(self.ev, 'ask_int', side_effect=[2, 2]), \
                patch.object(self.ev, 'rsa_generate', return_value=self.ec), \
                patch.object(self.ev, 'paillier_threshold_keygen', return_value=(self.pub, [])), \
                patch.object(self.ev, 'new_password', return_value='pw'):
            cfg = self.ev.setup()
        self.assertEqual(cfg['constituencies'], ['X'])
        self.assertTrue(cfg['end'].startswith('2099-'))

    def test_malformed_record_database_exits_without_menu_traceback(self):
        with patch.object(self.rec.os.path, 'exists', return_value=True), \
                patch.object(self.rec, 'load_json', side_effect=[{'vaults': {}}, {'R1': None}]):
            with self.assertRaisesRegex(SystemExit, 'malformed'):
                self.rec.main()

    def test_config_change_refuses_existing_keys(self):
        keys = {'config': {'cipher': 'DES'}}
        with patch.object(self.rec.os.path, 'exists', return_value=True), \
                patch.object(self.rec, 'load_json', side_effect=[keys, {}]), \
                patch.object(self.rec, 'menu'):
            with self.assertRaisesRegex(SystemExit, 'CONFIG'):
                self.rec.main()

    def test_des_elgamal_variant_persists_and_decrypts_after_restart(self):
        from tests.test_programs import variant
        from tests.helpers import run
        with tempfile.TemporaryDirectory() as d:
            script = variant(d, (192, 'CBC'), CIPHER='DES', NUMBER_FIELDS=[],
                             HASH='sha256', SIGN='elgamal',
                             ROLES={'Writer': ['submit'], 'Reader': ['verify', 'decrypt']})
            data = str(Path(d) / 'data')
            out = run(script, ['wp', 'rp', '1', 'wp', '1', 'D1', 'secret DES message', '0', '0'], data)
            self.assertIn('DES-CBC ct:', out)
            out = run(script, ['2', 'rp', '1', '2', 'D1', '0', '0'], data)
            self.assertIn('SHA256 matches and ELGAMAL signature valid', out)
            self.assertIn('secret DES message', out)
            self.assertNotIn('Traceback', out)

    def test_numeric_search_uses_the_same_scaled_value_as_submission(self):
        sec = {'idx': '00' * 32}
        record = {'id': 'R1', 'timestamp': 'now',
                  'tags': [token(sec['idx'], 123, 'Amount')]}
        with patch.object(self.rec, 'SEARCH_FIELDS', ['Amount']), \
                patch.object(self.rec, 'ask_choice', return_value='Amount'), \
                patch.object(self.rec, 'verify', return_value=(True, 'ok')), \
                patch('builtins.input', return_value='1.23'):
            self.rec.search({}, {'record': record}, sec)
        self.assertIn('1 match(es)', self.output.getvalue())


if __name__ == '__main__':
    unittest.main()
