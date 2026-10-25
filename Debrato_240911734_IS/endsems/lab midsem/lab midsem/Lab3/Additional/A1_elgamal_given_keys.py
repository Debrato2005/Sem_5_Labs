"""Lab 3 - Additional 1
ElGamal public key (p = 7919, g = 2, h = 6465), private key x = 2999.
Encrypt "Asymmetric Algorithms" and decrypt to verify.
p is tiny, so each character is encrypted separately (each char code < p).

The manual's numbers are inconsistent: 2^2999 mod 7919 = 3868, not 6465, so decryption
with x fails when h = 6465. The script shows this and then uses the correct h = g^x mod p."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Asymmetric Algorithms")
p, g, h, x = ask("p", 7919), ask("g", 2), ask("h", 6465), ask("x", 2999)

if pow(g, x, p) != h:
    bad = elgamal_cipher(elgamal_cipher(msg, p, g, h), p, g, x, decrypt=True)
    print(f"\n[!] g^x mod p = {pow(g, x, p)} != h = {h}. With the given h, decryption gives: {bad!r}")
    h = pow(g, x, p)
    print(f"[!] Using the consistent public key h = g^x mod p = {h}")

cts = elgamal_cipher(msg, p, g, h)
banner(f"ElGamal  p={p} g={g} h={h} x={x}")
print("  Ciphertext pairs (c1, c2):", cts)
print("  Decrypted:", elgamal_cipher(cts, p, g, x, decrypt=True))
