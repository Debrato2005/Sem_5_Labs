"""Lab 7 - Additional 1c
Secure thresholding / multi-party computation with PHE:
 * N parties each encrypt their private value (salary) with a joint Paillier public key.
 * The sum is computed homomorphically - nobody sees individual values.
 * The private key (lambda) is split with Shamir secret sharing: any T of N parties must
   cooperate to decrypt the result; fewer than T learn nothing.
To modify: N, T, VALUES."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

N, T = ask("Parties N", 5), ask("Threshold T", 3)
VALUES = [52000, 61000, 48000, 75000, 58000][:N]

pub, shares = generate_keys("paillier", 1024, threshold=(T, N))   # dealer never keeps the key
print(f"Key split into {N} shares, any {T} can decrypt")

cts = paillier_cipher(VALUES, pub)                  # each party encrypts its own value
enc_sum = homomorphic("paillier", cts, pub)
print("Encrypted total:", str(enc_sum)[:60], "...")

banner(f"{T} parties cooperate")
total = paillier_cipher(enc_sum, random.sample(shares, T), decrypt=True, pub=pub)
print(f"  total = {total}  expected {sum(VALUES)}  match = {total == sum(VALUES)}")
print(f"  average = {total / N:.2f};  above threshold 60000? {total / N > 60000}")

banner(f"Only {T - 1} parties try")
print(f"  result = {paillier_cipher(enc_sum, shares[:T - 1], decrypt=True, pub=pub)}  (garbage - not enough shares)")
