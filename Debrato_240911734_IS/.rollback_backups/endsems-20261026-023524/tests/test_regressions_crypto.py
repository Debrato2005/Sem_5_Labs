"""Regression checks for malformed inputs and numerical boundary cases."""
import itertools
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from toolkit import access, asymmetric, classical, homomorphic, searchable, signatures, symmetric


class PaillierBoundaries(unittest.TestCase):
    def setUp(self):
        self.pub, self.priv = homomorphic.paillier_keys_from_pq(17, 19)

    def test_given_factors_are_distinct_odd_primes(self):
        for p, q in ((17, 17), (9, 35), (2, 7), (-3, 5)):
            with self.subTest(p=p, q=q), self.assertRaises(ValueError):
                homomorphic.paillier_keys_from_pq(p, q)

    def test_signed_extremes(self):
        for m in (-161, 161):
            self.assertEqual(homomorphic.paillier_decrypt(
                self.priv, homomorphic.paillier_encrypt(self.pub, m, r=1)), m)
        for m in (-162, 162, 1.5, True):
            with self.subTest(m=m), self.assertRaises(ValueError):
                homomorphic.paillier_encrypt(self.pub, m)

    def test_explicit_randomizer_is_not_silently_replaced(self):
        for r in (0, 17, -1, 323, 1.5):
            with self.subTest(r=r), self.assertRaises(ValueError):
                homomorphic.paillier_encrypt(self.pub, 3, r=r)

    def test_every_ciphertext_operation_rejects_nonunits(self):
        for c in (0, 17, 19, self.pub['n'] ** 2, -1, True):
            operations = (lambda: homomorphic.paillier_decrypt(self.priv, c),
                          lambda: homomorphic.paillier_add(self.pub, c),
                          lambda: homomorphic.paillier_add_const(self.pub, c, 1),
                          lambda: homomorphic.paillier_mul_const(self.pub, c, 1))
            for op in operations:
                with self.subTest(c=c), self.assertRaises(ValueError):
                    op()

    def test_weight_count_must_match(self):
        c = homomorphic.paillier_encrypt(self.pub, 2)
        with self.assertRaises(ValueError):
            homomorphic.paillier_weighted_sum(self.pub, [c, c], [1])

    def test_small_key_requests_fail_without_prime_search(self):
        for bits in (0, 4, 5, 1.5, True):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                homomorphic.paillier_keygen(bits)


class ThresholdBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.shares = homomorphic.paillier_threshold_keygen(64, 3, 5)
        cls.ct = homomorphic.paillier_encrypt(cls.pub, -8)

    def test_every_authority_subset(self):
        for subset in itertools.combinations(self.shares, 3):
            parts = [homomorphic.partial_decrypt(self.pub, share, self.ct) for share in subset]
            self.assertEqual(homomorphic.combine_partials(self.pub, parts), -8)

    def test_authority_ids_and_duplicates(self):
        good = [homomorphic.partial_decrypt(self.pub, s, self.ct) for s in self.shares[:3]]
        for bad in ([(0, 1)] + good[1:], [(6, 1)] + good[1:], good + [good[0]],
                    [(True, 1)] + good[1:]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                homomorphic.combine_partials(self.pub, bad)
        for share in ((0, 1), (6, 1), (1, -1), (1, 1.5)):
            with self.subTest(share=share), self.assertRaises(ValueError):
                homomorphic.partial_decrypt(self.pub, share, self.ct)

    def test_partial_ciphertexts_must_be_units(self):
        good = [homomorphic.partial_decrypt(self.pub, s, self.ct) for s in self.shares[:3]]
        for c in (0, self.pub['n'], self.pub['n'] ** 2):
            with self.subTest(c=c), self.assertRaises(ValueError):
                homomorphic.partial_decrypt(self.pub, self.shares[0], c)
            with self.subTest(partial=c), self.assertRaises(ValueError):
                homomorphic.combine_partials(self.pub, [(1, c)] + good[1:])


class EncodingAndKeys(unittest.TestCase):
    def test_rsa_and_elgamal_preserve_nul_bytes(self):
        n, e, d = asymmetric.rsa_from_pq(257, 263, 17)
        pub, x = asymmetric.elgamal_keygen(65537, 3, 123)
        for msg in ('', '\0A', 'AB\0', '\0\0\0', 'hello\0world', '\u03bb\0'):
            cts, size = asymmetric.rsa_encrypt_text(msg, e, n)
            self.assertEqual(asymmetric.rsa_decrypt_text(cts, d, n, size), msg)
            cts, size = asymmetric.elgamal_encrypt_text(msg, pub)
            self.assertEqual(asymmetric.elgamal_decrypt_text(cts, x, pub[0], size), msg)

    def test_modulus_too_small_for_bytes(self):
        with self.assertRaises(ValueError):
            asymmetric.rsa_encrypt_text('z', 3, 15)
        with self.assertRaises(ValueError):
            asymmetric.elgamal_encrypt_text('z', (23, 5, 8))

    def test_rabin_empty_and_malformed_ciphertext(self):
        n, (p, q) = asymmetric.rabin_keygen(128)
        self.assertEqual(asymmetric.rabin_decrypt(asymmetric.rabin_encrypt(b'', n), p, q)[0], b'')
        for ct in (-1, n, True):
            with self.subTest(ct=ct), self.assertRaises(ValueError):
                asymmetric.rabin_roots(ct, p, q)

    def test_ecdh_supported_curves_and_curve_mismatch(self):
        for curve in ('P-256', 'P-384', 'P-521'):
            a, b = asymmetric.ecc_generate(curve), asymmetric.ecc_generate(curve)
            self.assertEqual(asymmetric.ecdh(a, b.public_key()), asymmetric.ecdh(b, a.public_key()))
            box = asymmetric.ecies_encrypt(a.public_key(), b'hello')
            self.assertEqual(asymmetric.ecies_decrypt(a, box), b'hello')
        with self.assertRaises(ValueError):
            asymmetric.ecdh(asymmetric.ecc_generate(), asymmetric.ecc_generate('P-384').public_key())

    def test_scratch_aes_rejects_invalid_lengths(self):
        for key in (bytes(0), bytes(15), bytes(20), bytes(33)):
            for fn in (symmetric.aes_encrypt_block, symmetric.aes_decrypt_block):
                with self.subTest(fn=fn, key=len(key)), self.assertRaises(ValueError):
                    fn(key, bytes(16))
        for size in (0, 15, 17, 32):
            for fn in (symmetric.aes_encrypt_block, symmetric.aes_decrypt_block):
                with self.subTest(fn=fn, size=size), self.assertRaises(ValueError):
                    fn(bytes(16), bytes(size))

    def test_hybrid_rejects_unknown_modes_and_key_sizes(self):
        k = asymmetric.rsa_generate(1024)
        with self.assertRaises(ValueError):
            asymmetric.hybrid_encrypt(k.publickey(), b'm', mode='typo')
        with self.assertRaises(ValueError):
            asymmetric.hybrid_encrypt(k.publickey(), b'm', aes_bits=129)
        box = asymmetric.hybrid_encrypt(k.publickey(), b'm', mode='CBC')
        box['mode'] = 'typo'
        with self.assertRaises(ValueError):
            asymmetric.hybrid_decrypt(k, box)

    def test_elgamal_parameters_exponents_and_ciphertexts(self):
        for p, g, x in ((15, 2, 3), (23, 1, 3), (23, 2, 0), (23, 2, 11)):
            with self.subTest(p=p, g=g, x=x), self.assertRaises(ValueError):
                asymmetric.elgamal_keygen(p, g, x)
        pub, x = asymmetric.elgamal_keygen(467, 2, 127)
        for k in (0, -1, 466, 1.5):
            with self.subTest(k=k), self.assertRaises(ValueError):
                asymmetric.elgamal_encrypt(3, pub, k)
        for ct in ((0, 2), (467, 2), (2, 0), (2, 467), (2, 1.5)):
            with self.subTest(ct=ct), self.assertRaises(ValueError):
                asymmetric.elgamal_decrypt(ct, x, 467)

    def test_dh_parameters_and_kdf_length(self):
        for p, g in ((15, 2), (23, 1), (23, 22)):
            with self.subTest(p=p, g=g), self.assertRaises(ValueError):
                asymmetric.dh_keypair(p, g)
        for length in (0, -1, 33, 1.5):
            with self.subTest(length=length), self.assertRaises(ValueError):
                asymmetric.kdf(123, length)

    def test_homomorphic_elgamal_key_and_ciphertext_validation(self):
        for p, g in ((15, 2), (23, 1), (23, 22)):
            with self.subTest(p=p, g=g), self.assertRaises(ValueError):
                homomorphic.elgamal_he_keygen(p=p, g=g)
        pub, x = homomorphic.elgamal_he_keygen(p=467, g=2)
        for ct in ((0, 2), (467, 2), (2, 0)):
            with self.subTest(ct=ct), self.assertRaises(ValueError):
                homomorphic.elgamal_he_decrypt(pub, x, ct)


class OtherBoundaryRegressions(unittest.TestCase):
    def test_signature_verifiers_fail_closed(self):
        calls = (lambda: signatures.rsa_verify(None, b'm', 'zz', 'unknown'),
                 lambda: signatures.dss_verify(None, b'm', 'zz', 'unknown'),
                 lambda: signatures.elgamal_verify(None, (1, 1), (467, 2, 3)),
                 lambda: signatures.elgamal_verify_hash(2, (1, 1), (1, 2, 1)),
                 lambda: signatures.rsa_textbook_verify(1, 1, 1, 0),
                 lambda: signatures.schnorr_verify(b'm', (0, 0), (23, 11, 1, 1)),
                 lambda: signatures.rsa_textbook_verify(1, 1.0, 3, 5))
        for fn in calls:
            with self.subTest(fn=fn):
                self.assertFalse(fn())

    def test_classical_alphabet_keys_and_pairs(self):
        self.assertEqual(classical.clean('caf\u00e9!'), 'CAF')
        for fn in (classical.vigenere_encrypt, classical.vigenere_decrypt,
                   classical.autokey_encrypt, classical.autokey_decrypt):
            with self.subTest(fn=fn), self.assertRaises(ValueError):
                fn('abc', '')
        for fn in (classical.additive_key_from_pair, classical.affine_keys_from_pair):
            with self.subTest(fn=fn), self.assertRaises(ValueError):
                fn('a', 'AB')
        with self.assertRaises(ValueError):
            classical.permutation_encrypt('abc', [0, 0, 1])
        with self.assertRaises(ValueError):
            classical.columnar_decrypt('ABCD', 'KEY')

    def test_classical_shapes_rails_and_fillers(self):
        for matrix in ([[1, 2, 3], [4, 5, 6]], [[1], [2]], [[1.5]]):
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                classical.matrix_inverse_mod(matrix)
        for rails in (0, -1, 1.5):
            for fn in (classical.rail_fence_encrypt, classical.rail_fence_decrypt):
                with self.subTest(rails=rails, fn=fn), self.assertRaises(ValueError):
                    fn('abc', rails)
        with self.assertRaises(ValueError):
            classical.columnar_encrypt('abc', '')
        with self.assertRaises(ValueError):
            classical.hill_decrypt('ABC', [[1, 0], [0, 1]])

    def test_playfair_repeated_x_uses_a_distinct_filler(self):
        ct = classical.playfair_encrypt('XX', 'KEY')
        self.assertNotEqual(classical.playfair_decrypt(ct, 'KEY'), 'xxxx')

    def test_sse_delete_clears_extra_keywords(self):
        keys, store = searchable.new_search_keys(), searchable.new_store()
        searchable.sse_add(store, keys, 'a', 'hello', ['secret'])
        searchable.sse_remove(store, keys, 'a')
        self.assertEqual(searchable.sse_search(store, keys, 'secret'), [])
        with self.assertRaises(ValueError):
            searchable.sse_search(store, keys, 'hello', 'typo')

    def test_pkse_rejects_truncated_results(self):
        with self.assertRaises(ValueError):
            searchable.pkse_client_resolve({'n': 323, 'lam': 144, 'mu': 83},
                                           [{'kw': 1, 'ids': []}], [])

    def test_dac_create_does_not_replace_an_owner(self):
        dac = access.DAC()
        dac.create('alice', 'file')
        with self.assertRaises(ValueError):
            dac.create('eve', 'file')
        self.assertEqual(dac.owner['file'], 'alice')


if __name__ == '__main__':
    unittest.main()
