"""Lab 3 - Additional 3
RSA with n = 323, e = 5, d = 173: encrypt "Cryptographic Protocols", decrypt to confirm.
n is tiny (323 = 17 * 19), so each character (ASCII < 323) is one RSA block."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Cryptographic Protocols")
n, e, d = ask("n", 323), ask("e", 5), ask("d", 173)

from sympy import factorint, totient
phi = int(totient(n))
print(f"n = {n} = {' * '.join(map(str, factorint(n)))},  phi(n) = {phi},  e*d mod phi = {e * d % phi}"
      f" -> {'valid' if e * d % phi == 1 else 'INVALID'} key pair")
cts = rsa_cipher(msg, (e, n), mode="textbook")
print("Plain codes :", [ord(c) for c in msg])
print("Ciphertext  :", cts)
print("Decrypted   :", rsa_cipher(cts, (d, n), decrypt=True, mode="textbook"))
