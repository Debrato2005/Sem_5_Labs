"""Lab 1 - Exercise 6
Affine cipher, known that "ab" -> "GL". Brute-force / solve the key and decipher
XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

ct = ask("Ciphertext", "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS")
known_pt, known_ct = ask("Known plaintext", "ab"), ask("Known ciphertext", "GL")

# Try all 312 affine keys, keep the ones that map known_pt -> known_ct
keys = known_plaintext_attack(known_pt, known_ct, "affine")
print(f"Keys (a, b) consistent with '{known_pt}' -> '{known_ct}': {keys}")
for a, b in keys:
    print(f"  a={a}, b={b}: {classical_cipher(ct, 'affine', (a, b), decrypt=True)}")

print("\nWithout the hint, best 3 English-looking keys from all 312:")
for k, pt in brute_force(ct, "affine", top=3):
    print(f"  {k}: {pt}")
