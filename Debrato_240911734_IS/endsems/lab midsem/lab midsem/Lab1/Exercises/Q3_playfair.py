"""Lab 1 - Exercise 3
Playfair-encipher "The key is hidden under the door pad" with key "GUIDANCE"
(I and J share one cell; X is inserted between repeated letters and at the end)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "The key is hidden under the door pad")
key = ask("Key", "GUIDANCE")

banner("Playfair  (show=True prints the matrix and the digraphs)")
ct = playfair(msg, key, show=True)
print("Ciphertext:", ct)
print("Decrypted :", playfair(ct, key, decrypt=True), "(remove the filler X's)")
