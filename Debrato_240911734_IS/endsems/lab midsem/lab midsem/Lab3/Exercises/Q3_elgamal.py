"""Lab 3 - Exercise 3
ElGamal with public key (p, g, h) and private key x: encrypt "Confidential Data",
then decrypt.   c1 = g^k mod p,  c2 = m*h^k mod p,  m = c2 * (c1^x)^-1 mod p
To modify: set BITS, or give numbers: generate_keys("elgamal", p=.., g=.., x=..)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Confidential Data")
BITS = ask("Prime size (bits)", 512)

p, g, h, x = generate_keys("elgamal", BITS)
banner("ElGamal keys")
print(f"  p = {p}\n  g = {g}\n  h = g^x mod p = {h}\n  x (private) = {x}")

cts = elgamal_cipher(msg, p, g, h)               # message split into blocks < p
banner("Encryption")
for c1, c2 in cts:
    print(f"  c1 = {c1}\n  c2 = {c2}")
print("\n  Decrypted:", elgamal_cipher(cts, p, g, x, decrypt=True))
