"""Lab 7 - Exercise 2
RSA multiplicative homomorphism: encrypt 7 and 3, multiply ciphertexts, decrypt = 21.
  E(a) * E(b) = a^e b^e = (ab)^e = E(a*b)  (mod n)     - textbook (unpadded) RSA only"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

a, b = ask("First integer", 7), ask("Second integer", 3)
BITS = ask("Key size (bits)", 1024)

n, e, d = generate_keys("rsa_textbook", BITS)
print(f"n = {n}\ne = {e}")

ca, cb = rsa_cipher(a, (e, n), mode="textbook"), rsa_cipher(b, (e, n), mode="textbook")
banner("Ciphertexts")
print(f"E({a}) = {ca}\n\nE({b}) = {cb}")

c_prod = homomorphic("rsa", [ca, cb], n)
banner("Encrypted product E(a) * E(b) mod n")
print(c_prod)

result = rsa_cipher(c_prod, (d, n), decrypt=True, mode="textbook")
banner("Decryption")
print(f"D(E(a)*E(b)) = {result}   a * b = {a * b}   match = {result == a * b}")
