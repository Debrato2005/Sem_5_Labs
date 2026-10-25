"""Regression checks for shared input, persistence, HTTP and bundle boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from toolkit import util


class InputAndStorage(unittest.TestCase):
    def test_empty_existing_file_is_corrupt_not_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'records.json'
            path.write_text('  ', encoding='utf-8')
            with self.assertRaises(ValueError):
                util.load_json(path, {})

    def test_save_accepts_path_and_keeps_old_file_on_serialization_failure(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'records.json'
            util.save_json(path, {'old': 1})
            with self.assertRaises(TypeError):
                util.save_json(path, {'bad': object()})
            self.assertEqual(util.load_json(path, None), {'old': 1})
            self.assertEqual(list(Path(d).iterdir()), [path])

    def test_canonical_refuses_nonfinite_json(self):
        with self.assertRaises(ValueError):
            util.canonical({'value': float('nan')})

    def test_unicode_menu_choice_does_not_crash(self):
        with patch('builtins.input', side_effect=['²', '0']), patch('builtins.print'):
            util.menu('test', [('unused', lambda: self.fail('unexpected call'))])

    def test_huge_amount_reprompts_without_overflow(self):
        with patch('builtins.input', side_effect=['1e999999999', '12.50']), patch('builtins.print'):
            self.assertEqual(util.ask_amount('Amount: '), 1250)

    def test_hour_buckets_normalizes_timezone_and_rejects_reverse(self):
        a = util.parse_time('2026-10-26T10:30+05:30')
        b = util.parse_time('2026-10-26T10:59+05:30')
        self.assertEqual(util.hour_buckets(a, b), ['2026-10-26T05'])
        with self.assertRaises(ValueError):
            util.hour_buckets(b, a)


class BundleBoundaries(unittest.TestCase):
    def test_unsupported_module_import_fails_clearly(self):
        spec = importlib.util.spec_from_file_location('exam_bundle', ROOT / 'bundle.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'answer.py'
            p.write_text('from toolkit import util\nprint(util.canonical({}))\n', encoding='utf-8')
            with self.assertRaisesRegex(SystemExit, 'from toolkit'):
                module.bundle(p)

    def test_alias_import_runs_as_single_file(self):
        with tempfile.TemporaryDirectory() as d:
            p, out = Path(d) / 'answer.py', Path(d) / 'single.py'
            p.write_text('from toolkit.hashing import digest as hash_bytes\nprint(hash_bytes(b"abc"))\n', encoding='utf-8')
            subprocess.run([sys.executable, str(ROOT / 'bundle.py'), str(p), '-o', str(out)], check=True, capture_output=True)
            result = subprocess.run([sys.executable, str(out)], capture_output=True, text=True, cwd=d)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ba7816bf', result.stdout)


if __name__ == '__main__':
    unittest.main()
