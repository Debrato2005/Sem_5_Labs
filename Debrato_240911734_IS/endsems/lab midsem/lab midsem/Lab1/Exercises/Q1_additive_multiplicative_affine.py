"""Lab 1 - Exercise 1
Encrypt "I am learning information security" (ignore spaces) and decrypt it with:
  a) Additive cipher, key = 20   b) Multiplicative cipher, key = 15   c) Affine cipher, key = (15, 20)
To modify: change the values at the prompts (or the defaults below).
Multiplicative / affine 'a' must satisfy gcd(a, 26) = 1."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "I am learning information security")
k_add = ask("Additive key", 20)
k_mul = ask("Multiplicative key", 15)
a, b = ask("Affine a", 15), ask("Affine b", 20)

banner("a) Additive cipher  C = (P + k) mod 26")
ct = classical_cipher(msg, "additive", k_add)
print("Ciphertext:", ct, "\nDecrypted :", classical_cipher(ct, "additive", k_add, decrypt=True))

banner("b) Multiplicative cipher  C = (P * k) mod 26")
ct = classical_cipher(msg, "multiplicative", k_mul)
print(f"k^-1 mod 26 = {pow(k_mul, -1, 26)}")
print("Ciphertext:", ct, "\nDecrypted :", classical_cipher(ct, "multiplicative", k_mul, decrypt=True))

banner("c) Affine cipher  C = (a*P + b) mod 26")
ct = classical_cipher(msg, "affine", (a, b))
print("Ciphertext:", ct, "\nDecrypted :", classical_cipher(ct, "affine", (a, b), decrypt=True))
