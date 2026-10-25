"""Lab 3 - Additional 5
Government agency study: RSA (2048-bit) vs ElGamal (secp256r1 curve) - key generation,
encryption and decryption times for 1 KB and 10 KB messages; then the same including
ECC and classic (mod p) ElGamal. Messages are larger than one block, so every scheme
is used in hybrid form (public key protects an AES-GCM key).
To modify: SIZES_KB, ELGAMAL_BITS (2048 is slow to generate - try 1024)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

SIZES_KB = [1, 10]
ELGAMAL_BITS = ask("Classic ElGamal prime bits", 2048)

rsa_key, t_rsa = timed(generate_keys, "rsa", 2048)
ec_key, t_ec = timed(generate_keys, "ecc", curve="secp256r1")
(p, g, y, x), t_eg = timed(generate_keys, "elgamal", ELGAMAL_BITS)

SCHEMES = {
    "RSA-2048": (t_rsa, lambda d: rsa_cipher(d, rsa_key.publickey(), mode="hybrid"),
                 lambda c: rsa_cipher(c, rsa_key, decrypt=True, mode="hybrid")),
    "EC-ElGamal secp256r1 (ECC)": (t_ec, lambda d: ecc_cipher(d, ec_key.public_key()),
                                   lambda c: ecc_cipher(c, ec_key, decrypt=True)),
    f"ElGamal mod-p {ELGAMAL_BITS}": (t_eg, lambda d: elgamal_cipher(d, p, g, y, mode="hybrid"),
                                      lambda c: elgamal_cipher(c, p, g, x, decrypt=True, mode="hybrid")),
}

rows, chart = [], {}
for name, (t_gen, enc, dec) in SCHEMES.items():
    for kb in SIZES_KB:
        msg = os.urandom(kb * 1024)
        ct, t_enc = timed(enc, msg, repeat=10)
        pt, t_dec = timed(dec, ct, repeat=10)
        rows.append([name, f"{kb} KB", t_gen * 1000, t_enc * 1000, t_dec * 1000, pt == msg])
        chart.setdefault(f"{kb} KB", {})[name] = (t_enc + t_dec) * 1000

print_table(["Scheme", "Msg", "Keygen ms", "Encrypt ms", "Decrypt ms", "OK"], rows)
plot(chart, "Encrypt+decrypt time", "time (ms)", "rsa_elgamal_ecc.png")
print("""
Analysis
 * Keygen: EC (one scalar multiplication) << RSA (two primes) << ElGamal mod-p (one big prime).
 * Encryption: RSA is cheap (e = 65537 is tiny); EC-ElGamal needs 2 scalar mults on small
   256-bit numbers (fastest); mod-p ElGamal needs 2 full 2048-bit exponentiations (slowest).
 * Decryption: RSA decrypt (2048-bit private exponent) is ~5x its encryption; EC-ElGamal
   needs 1 scalar mult; mod-p ElGamal 1 big exponentiation + inverse.
 * Message size hardly matters (1 KB vs 10 KB): AES-GCM does the bulk work in all three.
 * Overhead: RSA adds 256 bytes, EC-ElGamal 65 bytes (one point), mod-p ElGamal 2x|p|.
 * Security per bit: 256-bit ECC ~ 3072-bit RSA/ElGamal.""")
