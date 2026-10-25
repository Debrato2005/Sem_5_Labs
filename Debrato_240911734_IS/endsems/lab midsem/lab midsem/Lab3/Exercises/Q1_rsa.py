"""Lab 3 - Exercise 1
RSA: encrypt "Asymmetric Encryption" with public key (n, e), decrypt with private key (n, d).
Shows both secure RSA-OAEP (library) and textbook RSA c = m^e mod n with the same key.
To modify: change BITS, or use generate_keys("rsa_textbook", p=.., q=.., e=..) for given primes."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Asymmetric Encryption")
BITS = ask("Key size (bits)", 2048)

key = generate_keys("rsa", BITS)
banner(f"RSA-{BITS} key pair")
print(f"  n = {key.n}\n  e = {key.e}\n  d = {key.d}")

banner("RSA-OAEP (padded, secure)")
ct = rsa_cipher(msg, key.publickey())
print("  Ciphertext:", fmt(ct))
print("  Decrypted :", rsa_cipher(ct, key, decrypt=True).decode())

banner("Textbook RSA  c = m^e mod n,  m = c^d mod n")
cts = rsa_cipher(msg, key, mode="textbook")
print("  Ciphertext int:", cts[0])
print("  Decrypted     :", rsa_cipher(cts, key, decrypt=True, mode="textbook"))
