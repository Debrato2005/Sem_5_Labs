"""Lab 7 - Additional 1a
ElGamal homomorphic multiplication: (g^k1, m1 y^k1) * (g^k2, m2 y^k2) = (g^(k1+k2), m1 m2 y^(k1+k2))
ElGamal multiplies but cannot add."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

m1, m2 = ask("First integer", 12), ask("Second integer", 9)
p, g, y, x = generate_keys("elgamal", ask("Prime bits", 512))

c1, c2 = elgamal_cipher(m1, p, g, y), elgamal_cipher(m2, p, g, y)
print(f"E({m1}) = {c1}\nE({m2}) = {c2}")
c = homomorphic("elgamal", [c1, c2], p)
print(f"\nE(m1) * E(m2) = {c}")
r = elgamal_cipher(c, p, g, x, decrypt=True)
print(f"\nDecrypted product = {r}   expected {m1 * m2}   match = {r == m1 * m2}")

vals = [2, 3, 4, 5]
prod_c = homomorphic("elgamal", [elgamal_cipher(v, p, g, y) for v in vals], p)
print(f"Product of {vals} computed encrypted -> {elgamal_cipher(prod_c, p, g, x, decrypt=True)}")
