"""Lab 1 - Exercise 4
Hill-encipher "We live in an insecure world" with K = [[03, 03], [02, 07]].
To modify: any n x n matrix works if det(K) is coprime with 26 (e.g. a 3x3 key)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *
from sympy import Matrix

msg = ask("Message", "We live in an insecure world")
K = [[3, 3], [2, 7]]

det = Matrix(K).det() % 26
print(f"K = {K}, det(K) mod 26 = {det}, gcd(det, 26) = {math.gcd(det, 26)} -> invertible")
print("K^-1 mod 26 =", Matrix(K).inv_mod(26).tolist())

ct = hill(msg, K)
print("\nCiphertext:", ct)
print("Decrypted :", hill(ct, K, decrypt=True), "(trailing X = padding)")
