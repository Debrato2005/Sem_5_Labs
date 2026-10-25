"""Lab 7 - Additional 1d
Benchmark Paillier (additive) vs ElGamal (multiplicative) vs RSA (multiplicative):
key generation, encryption, decryption and the homomorphic operation.
To modify: BITS list, REPEAT."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

BITS = [512, 1024, 2048]
REPEAT = ask("Repetitions", 20)
rows, chart = [], {}

for bits in BITS:
    (pub, priv), t_kg = timed(generate_keys, "paillier", bits)
    c, t_e = timed(paillier_cipher, 42, pub, repeat=REPEAT)
    _, t_d = timed(paillier_cipher, c, priv, decrypt=True, repeat=REPEAT)
    _, t_op = timed(homomorphic, "paillier", [c, c], pub, repeat=REPEAT)
    rows.append([f"Paillier-{bits}", "add", t_kg * 1e3, t_e * 1e3, t_d * 1e3, t_op * 1e3])

    (p, g, y, x), t_kg = timed(generate_keys, "elgamal", bits)
    c, t_e = timed(elgamal_cipher, 42, p, g, y, repeat=REPEAT)
    _, t_d = timed(elgamal_cipher, c, p, g, x, decrypt=True, repeat=REPEAT)
    _, t_op = timed(homomorphic, "elgamal", [c, c], p, repeat=REPEAT)
    rows.append([f"ElGamal-{bits}", "mul", t_kg * 1e3, t_e * 1e3, t_d * 1e3, t_op * 1e3])

    (n, e, d), t_kg = timed(generate_keys, "rsa_textbook", bits)
    c, t_e = timed(rsa_cipher, 42, (e, n), mode="textbook", repeat=REPEAT)
    _, t_d = timed(rsa_cipher, c, (d, n), decrypt=True, mode="textbook", repeat=REPEAT)
    _, t_op = timed(homomorphic, "rsa", [c, c], n, repeat=REPEAT)
    rows.append([f"RSA-{bits}", "mul", t_kg * 1e3, t_e * 1e3, t_d * 1e3, t_op * 1e3])
    for r in rows[-3:]:
        chart.setdefault(f"{bits} bits", {})[r[0].split("-")[0] + " enc"] = r[3]

print_table(["Scheme", "Hom. op", "Keygen ms", "Encrypt ms", "Decrypt ms", "Op ms"], rows)
plot(chart, "PHE encryption time", "time (ms)", "phe_benchmark.png")
print("""
 * Paillier works mod n^2 -> ciphertexts are 2x the key size and encrypt/decrypt are slower.
 * ElGamal ciphertexts are 2 numbers mod p; encryption needs 2 exponentiations.
 * Homomorphic ops are a single modular multiplication -> microseconds for all schemes.
 * Paillier = sums/averages/votes; ElGamal & RSA = products only.""")
