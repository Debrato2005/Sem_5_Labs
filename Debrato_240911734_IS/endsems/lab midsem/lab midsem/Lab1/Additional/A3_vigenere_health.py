"""Lab 1 - Additional 3
Vigenere-encipher "Life is full of surprises" with keyword "HEALTH"."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg, key = ask("Message", "Life is full of surprises"), ask("Key", "HEALTH")
ct = classical_cipher(msg, "vigenere", key)
print("Ciphertext:", ct)
print("Decrypted :", classical_cipher(ct, "vigenere", key, decrypt=True))
