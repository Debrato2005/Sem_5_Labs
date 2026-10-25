"""Lab 7 - Exercise 1
Paillier: encrypt 15 and 25, add them while encrypted, decrypt the sum and verify = 40.
  keygen: n = pq, g = n+1, lam = lcm(p-1, q-1), mu = lam^-1 mod n
  E(m) = g^m r^n mod n^2      D(c) = L(c^lam mod n^2) mu mod n,  L(u) = (u-1)/n
  E(a) * E(b) mod n^2 = E(a + b)
To modify: change a, b, BITS; also try homomorphic("paillier", c, pub, "mul_const", k) = E(a*k)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

a, b = ask("First integer", 15), ask("Second integer", 25)
BITS = ask("Key size (bits)", 1024)

pub, priv = generate_keys("paillier", BITS)
print(f"n = {pub[0]}\ng = n + 1")

ca, cb = paillier_cipher(a, pub), paillier_cipher(b, pub)
banner("Ciphertexts")
print(f"E({a}) = {ca}\n\nE({b}) = {cb}")

c_sum = homomorphic("paillier", [ca, cb], pub)
banner("Encrypted sum E(a) * E(b) mod n^2")
print(c_sum)

result = paillier_cipher(c_sum, priv, decrypt=True)
banner("Decryption")
print(f"D(E(a)*E(b)) = {result}   a + b = {a + b}   match = {result == a + b}")
print(f"Bonus: E({a}) * g^10  -> {paillier_cipher(homomorphic('paillier', ca, pub, 'add_const', 10), priv, True)};  "
      f"E({a})^3 -> {paillier_cipher(homomorphic('paillier', ca, pub, 'mul_const', 3), priv, True)}")
