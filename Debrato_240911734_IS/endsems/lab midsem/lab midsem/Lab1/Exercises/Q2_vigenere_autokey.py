"""Lab 1 - Exercise 2
Encrypt "the house is being sold tonight" (ignore spaces) and decrypt it with:
  * Vigenere cipher, key "dollars"      * Autokey cipher, key = 7
To modify: the autokey key may be a number (7) or a word ("deceptive")."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "the house is being sold tonight")
vkey = ask("Vigenere key", "dollars")
akey = ask("Autokey key (number or word)", "7")
akey = int(akey) if akey.isdigit() else akey

banner("Vigenere cipher  C_i = P_i + K_(i mod m)")
ct = classical_cipher(msg, "vigenere", vkey)
print("Ciphertext:", ct, "\nDecrypted :", classical_cipher(ct, "vigenere", vkey, decrypt=True))

banner("Autokey cipher  K = [k, P_1, P_2, ...]")
ct = classical_cipher(msg, "autokey", akey)
print("Ciphertext:", ct, "\nDecrypted :", classical_cipher(ct, "autokey", akey, decrypt=True))
