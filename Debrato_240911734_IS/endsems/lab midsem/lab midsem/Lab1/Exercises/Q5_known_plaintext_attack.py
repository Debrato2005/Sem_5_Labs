"""Lab 1 - Exercise 5
Shift cipher: ciphertext "CIW" is known to be plaintext "yes".
Decrypt the tablet text "XVIEWYWI". Identify the attack type."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

known_pt, known_ct = ask("Known plaintext", "yes"), ask("Known ciphertext", "CIW")
target = ask("Ciphertext to break", "XVIEWYWI")

k = known_plaintext_attack(known_pt, known_ct, "additive")
print(f"\nKey k = C - P = {k}   (check: E('{known_pt}') = {classical_cipher(known_pt, 'additive', k)})")
print("Plaintext of", target, "=", classical_cipher(target, "additive", k, decrypt=True))
print("\nAttack type: KNOWN-PLAINTEXT ATTACK (a plaintext/ciphertext pair revealed the key).")
print("Note: the manual's 'XVIEWYWI' gives TREASUSE; 'XVIEWYVI' would give TREASURE (typo).")
