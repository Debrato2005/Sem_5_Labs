"""Lab 1 - Additional 1
Brute-force an additive cipher. Alice uses a key close to her birthday (13th):
NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

ct = ask("Ciphertext", "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY")
centre = ask("Key is close to", 13)

print(f"\nKeys {centre - 3}..{centre + 3} (non-letters like / & are dropped):")
for k in range(centre - 3, centre + 4):
    print(f"  k={k:2d}: {classical_cipher(ct, 'additive', k, decrypt=True)}")

k, pt = brute_force(ct, "additive")[0]
print(f"\nMost English-like over all 26 keys: k={k} -> {pt}")
