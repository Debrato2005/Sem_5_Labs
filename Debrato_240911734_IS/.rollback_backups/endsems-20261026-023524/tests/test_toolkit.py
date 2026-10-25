"""Unit tests for every toolkit module (uses the lab manual's own values where
possible).   Run from endsems/:   python -m unittest discover -s tests -v"""
import builtins
import io
import os
import socket
import sys
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.helpers import TempDir  # noqa: E402
from toolkit import (access, asymmetric, classical, hashing, homomorphic, net,  # noqa: E402
                     searchable, signatures, symmetric, util)

from Crypto.Cipher import AES, DES3  # noqa: E402
from Crypto.Util.number import isPrime  # noqa: E402


def feed(*lines):
    """Patch input() with scripted answers."""
    it = iter(lines)
    return mock.patch.object(builtins, 'input', lambda prompt='': next(it))


class Lab1Classical(unittest.TestCase):
    MSG = 'I am learning information security'

    def test_affine_family_roundtrip(self):
        c = classical
        self.assertEqual(c.additive_decrypt(c.additive_encrypt(self.MSG, 20), 20), c.clean(self.MSG).lower())
        self.assertEqual(c.multiplicative_decrypt(c.multiplicative_encrypt(self.MSG, 15), 15),
                         c.clean(self.MSG).lower())
        self.assertEqual(c.affine_decrypt(c.affine_encrypt(self.MSG, 15, 20), 15, 20), c.clean(self.MSG).lower())
        self.assertEqual(c.additive_encrypt('abc', 3), 'DEF')
        with self.assertRaises(ValueError):
            c.multiplicative_encrypt('abc', 13)

    def test_polyalphabetic(self):
        c = classical
        m = 'the house is being sold tonight'
        self.assertEqual(c.vigenere_decrypt(c.vigenere_encrypt(m, 'dollars'), 'dollars'), c.clean(m).lower())
        self.assertEqual(c.autokey_decrypt(c.autokey_encrypt(m, 7), 7), c.clean(m).lower())
        self.assertEqual(c.autokey_decrypt(c.autokey_encrypt(m, 'KEY'), 'KEY'), c.clean(m).lower())
        self.assertEqual(c.vigenere_encrypt('attackatdawn', 'LEMON'), 'LXFOPVEFRNHR')   # textbook vector

    def test_playfair(self):
        m = classical.playfair_matrix('GUIDANCE')
        self.assertEqual(m[0], list('GUIDA'))
        ct = classical.playfair_encrypt('The key is hidden under the door pad', 'GUIDANCE')
        self.assertEqual(ct, 'POCLBXDRLGIYIBCGBGLXPOBILZLTTGIY')
        self.assertEqual(classical.playfair_decrypt(ct, 'GUIDANCE').replace('x', ''),
                         'thekeyishiddenunderthedoorpad'.replace('x', ''))

    def test_hill(self):
        k = [[3, 3], [2, 7]]
        ct = classical.hill_encrypt('We live in an insecure world', k)
        self.assertEqual(classical.hill_decrypt(ct, k), 'weliveinaninsecureworldx')
        k3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]                       # classic 3x3
        self.assertEqual(classical.hill_encrypt('ACT', k3), 'POH')
        with self.assertRaises(ValueError):
            classical.hill_encrypt('abc', [[2, 4], [6, 8]])

    def test_transposition(self):
        c = classical
        self.assertEqual(c.rail_fence_decrypt(c.rail_fence_encrypt('wearediscovered', 3), 3), 'wearediscovered')
        self.assertEqual(c.rail_fence_encrypt('wearediscovered', 3), 'WECRERDSOEEAIVD')
        self.assertEqual(c.columnar_decrypt(c.columnar_encrypt('attackpostponed', 'ZEBRA'), 'ZEBRA')[:15],
                         'attackpostponed')
        self.assertEqual(c.permutation_decrypt(c.permutation_encrypt('abcdefgh', [2, 0, 3, 1]), [2, 0, 3, 1]),
                         'abcdefgh')

    def test_attacks_on_manual_questions(self):
        c = classical
        self.assertEqual(c.additive_key_from_pair('yes', 'CIW'), 4)
        self.assertEqual(c.affine_keys_from_pair('ab', 'GL'), [(5, 6)])
        self.assertTrue(c.affine_decrypt('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS', 5, 6).startswith('thebestofafight'))
        best = max(c.brute_additive('NCJAEZRCLASLYODEPRLYZRCLASJLCPEHZDTOPDZOLNBY'),
                   key=lambda kp: c.english_score(kp[1]))
        self.assertTrue(best[1].startswith('cryptograph'))
        self.assertEqual(len(c.brute_affine('ABC')), 312)
        self.assertEqual(c.permutation_from_chosen('abcdef', 'CABFDE', 3), [2, 0, 1])


class Lab2Symmetric(unittest.TestCase):
    def test_all_algs_modes(self):
        for alg, size in (('AES', 16), ('AES', 24), ('AES', 32), ('DES', 8), ('DES3', 16), ('DES3', 24)):
            for mode in symmetric.MODES:
                if mode == 'GCM' and alg != 'AES':
                    continue
                key = symmetric.new_key(alg, size)
                box = symmetric.sym_encrypt(alg, mode, key, b'Confidential Data')
                self.assertEqual(symmetric.sym_decrypt(key, box), b'Confidential Data', (alg, mode))

    def test_manual_values(self):
        des_key = util.parse_bytes('A1B2C3D4', (8,))
        self.assertEqual(des_key, b'A1B2C3D4')
        aes128 = util.parse_bytes('0123456789ABCDEF0123456789ABCDEF', (16, 24, 32))
        self.assertEqual(len(aes128), 16)                       # hex wins for AES-128
        box = symmetric.sym_encrypt('DES', 'CBC', des_key, b'Secure Communication', iv=b'12345678')
        self.assertEqual(symmetric.sym_decrypt(des_key, box), b'Secure Communication')
        ctr = symmetric.sym_encrypt('AES', 'CTR', aes128, b'Cryptography Lab Exercise',
                                    iv=util.parse_bytes('0000000000000000', (8,)))
        self.assertEqual(ctr['iv'], '0000000000000000')
        with self.assertRaises(ValueError):                     # manual's 3DES key: K1=K2=K3
            DES3.new(bytes.fromhex('1234567890ABCDEF' * 3), DES3.MODE_ECB)
        with self.assertRaises(ValueError):                     # manual's 'AES-192' key is 16 bytes
            util.parse_bytes('FEDCBA9876543210FEDCBA9876543210', (24,))

    def test_no_padding_requires_block_multiple(self):
        with self.assertRaises(ValueError):
            symmetric.sym_encrypt('AES', 'CBC', bytes(16), b'short', padding=False)
        box = symmetric.sym_encrypt('AES', 'ECB', bytes(16), bytes(32), padding=False)
        self.assertEqual(len(bytes.fromhex(box['ct'])), 32)

    def test_gcm_and_cbc_helpers_tamper(self):
        k = bytes(32)
        n, ct, tag = symmetric.aes_gcm_encrypt(k, b'data', b'hdr')
        self.assertEqual(symmetric.aes_gcm_decrypt(k, n, ct, tag, b'hdr'), b'data')
        with self.assertRaises(ValueError):
            symmetric.aes_gcm_decrypt(k, n, bytes([ct[0] ^ 1]) + ct[1:], tag, b'hdr')
        iv, c = symmetric.aes_cbc_encrypt(k, b'hello')
        self.assertEqual(symmetric.aes_cbc_decrypt(k, iv, c), b'hello')

    def test_scratch_aes_matches_library(self):
        for size in (16, 24, 32):
            key, block = os.urandom(size), os.urandom(16)
            ct = symmetric.aes_encrypt_block(key, block)
            self.assertEqual(ct, AES.new(key, AES.MODE_ECB).encrypt(block))
            self.assertEqual(symmetric.aes_decrypt_block(key, ct), block)
        self.assertEqual(bytes(symmetric.mix_column([0xdb, 0x13, 0x53, 0x45])).hex(), '8e4da1bc')
        self.assertEqual(symmetric.gf_mul(0x57, 0x83), 0xc1)                 # FIPS-197 example
        buf = io.StringIO()
        with redirect_stdout(buf):
            symmetric.aes_encrypt_block(b'FEDCBA9876543210FEDCBA98', b'Top Secret Data!', trace=True)
        self.assertIn('R12 AddRoundKey', buf.getvalue())                      # AES-192 = 12 rounds

    def test_files_password_vault_benchmark(self):
        with TempDir() as d:
            src, enc, dec = (os.path.join(d, n) for n in ('a.txt', 'a.enc', 'a.out'))
            with open(src, 'wb') as f:
                f.write(os.urandom(5000))
            k = symmetric.new_key('AES', 32)
            symmetric.encrypt_file(src, enc, k)
            symmetric.decrypt_file(enc, dec, k)
            with open(src, 'rb') as a, open(dec, 'rb') as b:
                self.assertEqual(a.read(), b.read())
        box = symmetric.password_seal('pw', b'secret')
        self.assertEqual(symmetric.password_open('pw', box), b'secret')
        with self.assertRaises(ValueError):
            symmetric.password_open('bad', box)
        rows = symmetric.cipher_benchmark(b'Performance Testing of Encryption Algorithms', repeat=5)
        self.assertEqual(len(rows), 4)


class Lab3and4Asymmetric(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = asymmetric.rsa_generate(2048)

    def test_group14_constant(self):
        self.assertTrue(isPrime(asymmetric.G14_P) and isPrime((asymmetric.G14_P - 1) // 2))
        self.assertEqual(asymmetric.G14_P, signatures.G14_P)

    def test_rsa_oaep_hybrid(self):
        pub = self.rsa.publickey()
        self.assertEqual(asymmetric.rsa_decrypt(self.rsa, asymmetric.rsa_encrypt(pub, b'Asymmetric Encryption')),
                         b'Asymmetric Encryption')
        for mode in ('GCM', 'CBC'):
            box = asymmetric.hybrid_encrypt(pub, b'x' * 10000, 256, mode)
            self.assertEqual(asymmetric.hybrid_decrypt(self.rsa, box), b'x' * 10000)
        box = asymmetric.hybrid_encrypt(pub, b'abc')
        box['ct'] = util.tamper_hex(box['ct'])
        with self.assertRaises(ValueError):
            asymmetric.hybrid_decrypt(self.rsa, box)
        pem = asymmetric.rsa_export(self.rsa, 'pass')
        self.assertEqual(asymmetric.rsa_import(pem, 'pass').n, self.rsa.n)

    def test_textbook_rsa_manual(self):
        n, e, d = asymmetric.rsa_from_pq(17, 19, 5)
        self.assertEqual((n, d), (323, 173))
        cts, size = asymmetric.rsa_encrypt_text('Cryptographic Protocols', e, n)
        self.assertEqual(asymmetric.rsa_decrypt_text(cts, d, n, size), 'Cryptographic Protocols')
        with self.assertRaises(ValueError):
            asymmetric.rsa_textbook_encrypt(400, e, n)

    def test_weak_rsa(self):
        from Crypto.Util.number import getPrime
        p = getPrime(256)
        q = p + 2
        while not isPrime(q):
            q += 2
        n, e, d = asymmetric.rsa_from_pq(p, q, 65537)
        self.assertEqual(asymmetric.break_weak_rsa(n, e)[2], d)                      # close primes
        n2, e2, d2 = asymmetric.rsa_from_pq(1000003, getPrime(256), 65537)
        self.assertEqual(asymmetric.break_weak_rsa(n2, e2)[2], d2)                   # small factor

    def test_elgamal(self):
        pub, x = asymmetric.elgamal_keygen()
        self.assertEqual(asymmetric.elgamal_decrypt(asymmetric.elgamal_encrypt(123456, pub), x, pub[0]), 123456)
        cts, size = asymmetric.elgamal_encrypt_text('Confidential Data', pub)
        self.assertEqual(asymmetric.elgamal_decrypt_text(cts, x, pub[0], size), 'Confidential Data')
        (p, g, h), x = asymmetric.elgamal_keygen(7919, 2, 2999)                     # manual values
        self.assertNotEqual(h, 6465)          # manual's h is NOT 2^2999 mod 7919 (it is 3868)
        cts, size = asymmetric.elgamal_encrypt_text('Asymmetric Algorithms', (p, g, h))
        self.assertEqual(asymmetric.elgamal_decrypt_text(cts, x, p, size), 'Asymmetric Algorithms')

    def test_rabin(self):
        n, (p, q) = asymmetric.rabin_keygen(512)
        self.assertTrue(p % 4 == 3 and q % 4 == 3)
        c = asymmetric.rabin_encrypt(b'patient record 42', n)
        msg, roots = asymmetric.rabin_decrypt(c, p, q)
        self.assertEqual(msg, b'patient record 42')
        self.assertEqual(len(set(roots)), 4)
        self.assertTrue(all(pow(r, 2, n) == c for r in roots))

    def test_dh_and_ecc(self):
        a, A = asymmetric.dh_keypair()
        b, B = asymmetric.dh_keypair()
        self.assertEqual(asymmetric.dh_shared(B, a), asymmetric.dh_shared(A, b))
        self.assertEqual(len(asymmetric.kdf(asymmetric.dh_shared(B, a))), 32)
        k1, k2 = asymmetric.ecc_generate(), asymmetric.ecc_generate()
        self.assertEqual(asymmetric.ecdh(k1, k2.public_key()), asymmetric.ecdh(k2, k1.public_key()))
        box = asymmetric.ecies_encrypt(k1.public_key(), b'Secure Transactions')
        self.assertEqual(asymmetric.ecies_decrypt(k1, box), b'Secure Transactions')
        with self.assertRaises(ValueError):
            asymmetric.ecies_decrypt(k2, box)


class Lab4Access(unittest.TestCase):
    def test_kms_lifecycle(self):
        with TempDir() as d:
            path = os.path.join(d, 'kms.json')
            kms = access.KeyManager(path, 'master-pass')
            kms.generate('HospitalA', 'RABIN', 512)
            kms.generate('SystemA', 'RSA', 1024)
            kms.generate('DRM', 'ELGAMAL')
            self.assertTrue(kms.get_public('SystemA').startswith('-----BEGIN PUBLIC KEY'))
            self.assertIn('[', kms.get_private('HospitalA', 'HospitalA'))
            with self.assertRaises(PermissionError):
                kms.get_private('HospitalA', 'HospitalB')
            kms.revoke('SystemA', 'compromised')
            with self.assertRaises(PermissionError):
                kms.get_public('SystemA')
            self.assertEqual(kms.renew('SystemA')['version'], 2)
            kms2 = access.KeyManager(path, 'master-pass')                      # reload from disk
            self.assertEqual(kms2.db['keys']['SystemA']['status'], 'active')
            self.assertGreaterEqual(len(kms2.db['log']), 6)
            with self.assertRaises(ValueError):
                access.KeyManager(path, 'wrong')
            kms2.db['keys']['DRM']['expires'] = '2000-01-01T00:00:00+00:00'
            self.assertEqual(kms2.renew_due(), ['DRM'])

    def test_policies(self):
        self.assertTrue(access.rbac({'u': ['doctor']}, {'doctor': {'read'}}, 'u', 'read'))
        self.assertFalse(access.rbac({'u': ['nurse']}, {'doctor': {'read'}}, 'u', 'read'))
        self.assertTrue(access.blp_read('secret', 'confidential'))
        self.assertFalse(access.blp_read('confidential', 'secret'))
        self.assertFalse(access.blp_write('secret', 'confidential'))
        dac = access.DAC()
        dac.create('alice', 'file')
        dac.grant('alice', 'bob', 'file', 'read')
        self.assertTrue(dac.check('bob', 'file', 'read'))
        with self.assertRaises(PermissionError):
            dac.grant('bob', 'eve', 'file', 'read')
        now = datetime.now(timezone.utc)
        self.assertTrue(access.time_window(now - timedelta(hours=1), now + timedelta(hours=1)))
        self.assertAlmostEqual(access.entropy([0.25] * 4), 2.0)
        self.assertTrue(access.abac(lambda u, o, e: u['dept'] == o['dept'], {'dept': 'x'}, {'dept': 'x'}, {}))


class Lab5Hashing(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(hashing.custom_hash(''), 5381)
        self.assertEqual(hashing.custom_hash('a'), 5381 * 33 + 97)
        self.assertLess(hashing.custom_hash('x' * 1000), 2 ** 32)
        self.assertEqual(hashing.digest('abc', 'md5'), '900150983cd24fb0d6963f7d28e17f72')
        self.assertEqual(hashing.digest(b'abc', 'SHA-256')[:16], 'ba7816bf8f01cfea')
        self.assertTrue(hashing.verify_digest(b'abc', hashing.digest(b'abc', 'sha512'), 'sha512'))
        self.assertTrue(hashing.hmac_ok(b'k', b'm', hashing.hmac_hex(b'k', b'm')))

    def test_experiment(self):
        data = hashing.random_strings(100, seed=1)
        self.assertEqual(set(hashing.hash_benchmark(data, repeat=2)), {'md5', 'sha1', 'sha256'})
        self.assertEqual(hashing.find_collisions(data, lambda s: hashing.digest(s, 'md5')), {})
        self.assertTrue(hashing.find_collisions(data, hashing.truncated('sha256', 8)))
        with TempDir() as d:
            p = os.path.join(d, 'f')
            with open(p, 'wb') as f:
                f.write(b'abc')
            self.assertEqual(hashing.file_digest(p, 'md5'), hashing.digest(b'abc', 'md5'))


class Lab6Signatures(unittest.TestCase):
    def test_rsa_signatures(self):
        k = asymmetric.rsa_generate(2048)
        for alg in ('md5', 'sha1', 'sha256', 'sha512'):
            for scheme in ('pkcs1', 'pss'):
                s = signatures.rsa_sign(k, b'record', alg, scheme)
                self.assertTrue(signatures.rsa_verify(k.publickey(), b'record', s, alg, scheme))
                self.assertFalse(signatures.rsa_verify(k.publickey(), b'recorD', s, alg, scheme))
        self.assertFalse(signatures.rsa_verify(k.publickey(), b'record', 'zz', 'sha256'))
        n, e, d = asymmetric.rsa_from_pq(61, 53, 17)
        s = signatures.rsa_textbook_sign(65, d, n)
        self.assertTrue(signatures.rsa_textbook_verify(65, s, e, n))

    def test_elgamal_schnorr_dss(self):
        pub, x = signatures.elgamal_sig_keygen()
        s = signatures.elgamal_sign(b'msg', x, alg='sha512')
        self.assertTrue(signatures.elgamal_verify(b'msg', s, pub, 'sha512'))
        self.assertFalse(signatures.elgamal_verify(b'msh', s, pub, 'sha512'))
        self.assertFalse(signatures.elgamal_verify(b'msg', (0, s[1]), pub, 'sha512'))
        p, g, _ = pub
        self.assertTrue(signatures.elgamal_verify_hash(12345, signatures.elgamal_sign_hash(12345, x), pub))
        (p2, g2, y2), x2 = signatures.elgamal_sig_keygen(467, 2, 127)                 # small textbook group
        s2 = signatures.elgamal_sign(b'hi', x2, p2, g2)
        self.assertTrue(signatures.elgamal_verify(b'hi', s2, (p2, g2, y2)))
        spub, sx = signatures.schnorr_keygen()
        ss = signatures.schnorr_sign('hello', sx)
        self.assertTrue(signatures.schnorr_verify('hello', ss, spub))
        self.assertFalse(signatures.schnorr_verify('hellO', ss, spub))
        for key in (signatures.dsa_generate(1024), signatures.ecdsa_generate()):
            sig = signatures.dss_sign(key, b'doc')
            self.assertTrue(signatures.dss_verify(key.public_key(), b'doc', sig))
            self.assertFalse(signatures.dss_verify(key.public_key(), b'dox', sig))

    def test_timestamp_authority(self):
        k = asymmetric.rsa_generate(2048)
        tok = signatures.TimestampAuthority(k).stamp('ab' * 32)
        now = datetime.now(timezone.utc)
        ok, _ = signatures.verify_timestamp(tok, k.publickey(), 'ab' * 32,
                                            now - timedelta(minutes=1), now + timedelta(minutes=1))
        self.assertTrue(ok)
        self.assertFalse(signatures.verify_timestamp(tok, k.publickey(), 'cd' * 32)[0])
        self.assertFalse(signatures.verify_timestamp(tok, k.publickey(), None, None, now - timedelta(days=1))[0])
        bad = dict(tok, time='2001-01-01T00:00:00+00:00')
        self.assertFalse(signatures.verify_timestamp(bad, k.publickey())[0])


class Lab7Homomorphic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = homomorphic.paillier_keygen(1024)

    def test_paillier_ops(self):
        h, pub, priv = homomorphic, self.pub, self.priv
        a, b = h.paillier_encrypt(pub, 15), h.paillier_encrypt(pub, 25)
        self.assertNotEqual(h.paillier_encrypt(pub, 15), a)                       # probabilistic
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_add(pub, a, b)), 40)
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_sub(pub, a, b)), -10)
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_mul_const(pub, a, 3)), 45)
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_add_const(pub, a, 5)), 20)
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_weighted_sum(pub, [a, b], [2, 3])), 105)
        self.assertEqual(h.paillier_decrypt(priv, h.paillier_rerandomize(pub, a)), 15)
        self.assertEqual(h.paillier_encrypt(pub, 7, 99), h.paillier_encrypt(pub, 7, 99))
        p2, k2 = h.paillier_keys_from_pq(17, 19)
        self.assertEqual(h.paillier_decrypt(k2, h.paillier_add(p2, h.paillier_encrypt(p2, 5),
                                                                 h.paillier_encrypt(p2, 10))), 15)

    def test_one_hot_tally(self):
        h = homomorphic
        ballots = [h.encrypt_one_hot(self.pub, v, [1, 2, 3]) for v in (1, 2, 2, 3, 2)]
        totals = h.tally(self.pub, ballots, [1, 2, 3])
        self.assertEqual({k: h.paillier_decrypt(self.priv, v) for k, v in totals.items()},
                         {'1': 1, '2': 3, '3': 1})

    def test_threshold(self):
        import itertools
        h = homomorphic
        tpub, shares = h.paillier_threshold_keygen(1024, 3, 5)
        c = h.paillier_add(tpub, h.paillier_encrypt(tpub, 1234), h.paillier_encrypt(tpub, -34))
        for subset in itertools.combinations(shares, 3):
            self.assertEqual(h.combine_partials(tpub, [h.partial_decrypt(tpub, s, c) for s in subset]), 1200)
        with self.assertRaises(ValueError):
            h.combine_partials(tpub, [h.partial_decrypt(tpub, s, c) for s in shares[:2]])
        wrong = [h.partial_decrypt(tpub, (i, s + 1), c) for i, s in shares[:3]]
        with self.assertRaises(ValueError):
            h.combine_partials(tpub, wrong)

    def test_rsa_elgamal(self):
        h = homomorphic
        pk, sk = h.rsa_mult_keygen(1024)
        self.assertEqual(h.rsa_mult_decrypt(sk, h.rsa_mult(pk, h.rsa_mult_encrypt(pk, 7),
                                                           h.rsa_mult_encrypt(pk, 3))), 21)
        ep, ex = h.elgamal_he_keygen(512)
        c = h.elgamal_mult(ep, h.elgamal_he_encrypt(ep, 6), h.elgamal_he_encrypt(ep, 7))
        self.assertEqual(h.elgamal_he_decrypt(ep, ex, c), 42)
        gp, gx = h.elgamal_he_keygen(p=asymmetric.G14_P, g=2)
        c = h.elgamal_mult(gp, h.exp_elgamal_encrypt(gp, 30), h.exp_elgamal_encrypt(gp, 12))
        self.assertEqual(h.exp_elgamal_decrypt(gp, gx, c), 42)


class Lab8Searchable(unittest.TestCase):
    DOCS = {'d1': 'this is a document with some words', 'd2': 'another document with different words',
            'd3': 'yet another document with some common words', 'd4': 'nothing here'}

    def test_sse(self):
        keys, store = searchable.new_search_keys(), searchable.new_store()
        for i, t in self.DOCS.items():
            searchable.sse_add(store, keys, i, t)
        self.assertEqual(searchable.sse_search(store, keys, 'document'), ['d1', 'd2', 'd3'])
        self.assertEqual(searchable.sse_search(store, keys, 'some another', 'AND'), ['d3'])
        self.assertEqual(searchable.sse_search(store, keys, 'some another', 'OR'), ['d1', 'd2', 'd3'])
        self.assertEqual(searchable.sse_search(store, keys, 'missing'), [])
        self.assertEqual(searchable.sse_read(store, keys, 'd4'), 'nothing here')
        self.assertNotIn('document', str(store))                                    # server sees no words
        searchable.sse_remove(store, keys, 'd1')
        self.assertEqual(searchable.sse_search(store, keys, 'document'), ['d2', 'd3'])
        with self.assertRaises(ValueError):
            searchable.sse_add(store, keys, 'd2', 'dup')
        t = searchable.token(keys['tok'], 'words')
        store['index'][t][0] = util.tamper_hex(store['index'][t][0], 20)
        with self.assertRaises(ValueError):
            searchable.sse_lookup(store, keys, 'words')
        k = os.urandom(16)
        self.assertEqual(searchable.det_token_aes(k, 'Word'), searchable.det_token_aes(k, 'word'))

    def test_field_index(self):
        idx, key = {}, os.urandom(32)
        for rid, c in (('b1', 'C1'), ('b2', 'C2'), ('b3', 'C1')):
            searchable.field_index_add(idx, key, 'const', c, rid)
        self.assertEqual(searchable.field_index_find(idx, key, 'const', 'c1'), ['b1', 'b3'])
        self.assertEqual(searchable.field_index_find_any(idx, key, 'const', ['C1', 'C2']), ['b1', 'b3', 'b2'])

    def test_pkse_paillier(self):
        pub, priv = homomorphic.paillier_keygen(1024)
        index = searchable.pkse_build(pub, self.DOCS)
        for q, want in (('document', ['d1', 'd2', 'd3']), ('some', ['d1', 'd3']), ('zzz', [])):
            blinded = searchable.pkse_server_match(pub, index, searchable.pkse_query(pub, q))
            self.assertEqual(searchable.pkse_client_resolve(priv, index, blinded), want)
        self.assertNotEqual(searchable.pkse_query(pub, 'x'), searchable.pkse_query(pub, 'x'))


class UtilAndNet(unittest.TestCase):
    def test_parsing(self):
        self.assertEqual(util.parse_bytes('hex:0001'), b'\x00\x01')
        self.assertEqual(util.parse_bytes('abcd', (4,)), b'abcd')
        self.assertEqual(util.parse_bytes('abcdabcd', (4,)), bytes.fromhex('abcdabcd'))
        self.assertIn('|hi|', util.hexdump(b'hi'))
        self.assertEqual(util.parse_time('2026-01-01T00:00Z').tzinfo, timezone.utc)
        t0 = util.parse_time('2026-01-01 10:00+00:00')
        self.assertEqual(len(util.hour_buckets(t0, t0 + timedelta(hours=2, minutes=5))), 3)
        self.assertEqual(util.canonical({'b': 1, 'a': 2}), b'{"a":2,"b":1}')
        r = util.hash_password('pw')
        self.assertTrue(util.check_password(r, 'pw') and not util.check_password(r, 'px'))

    def test_input_helpers_reprompt(self):
        with feed('x', '5', '42'), redirect_stdout(io.StringIO()):
            self.assertEqual(util.ask_int('n: ', 10, 50), 42)
        with feed('1.234', '-1', '12.5'), redirect_stdout(io.StringIO()):
            self.assertEqual(util.ask_amount('a: ', 2), 1250)
        with feed('Z', 'b'), redirect_stdout(io.StringIO()):
            self.assertEqual(util.ask_choice('c', ['A', 'B']), 'B')
        self.assertEqual(util.fmt_amount(1250, 2), '12.50')

    def test_menu_survives_errors(self):
        calls = []

        def boom():
            raise ValueError('bad thing')
        buf = io.StringIO()
        with feed('9', 'x', '1', '2', '0'), redirect_stdout(buf):
            util.menu('T', [('boom', boom), ('ok', lambda: calls.append(1))])
        self.assertEqual(calls, [1])
        self.assertIn('ERROR: ValueError: bad thing', buf.getvalue())

    def test_framing(self):
        a, b = socket.socketpair()
        with a, b:
            a.settimeout(5)
            b.settimeout(5)
            sender = threading.Thread(target=net.send_msg, args=(a, {'x': 'y' * 100000, 'n': 2 ** 3000}))
            sender.start()
            self.assertEqual(net.recv_msg(b)['n'], 2 ** 3000)
            sender.join(5)
            self.assertFalse(sender.is_alive())

    def test_audit_log(self):
        with TempDir() as d:
            log = util.AuditLog(os.path.join(d, 'a.log'))
            log.log('me', 'act', 'detail')
            buf = io.StringIO()
            with redirect_stdout(buf):
                log.show()
            self.assertIn('"action": "act"', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
