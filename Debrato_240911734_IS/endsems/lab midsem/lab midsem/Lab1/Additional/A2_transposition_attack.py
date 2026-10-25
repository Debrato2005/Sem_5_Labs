"""Lab 1 - Additional 2
Eve types "abcdefghi" on Alice's keyed-transposition cipher; screen shows "CABDEHFGL".
a) What type of attack?  b) What is the size of the permutation key?"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

pt = ask("Chosen plaintext", "abcdefghi")
ct = ask("Ciphertext shown", "CABDEHFGL")

if sorted(clean(pt)) != sorted(clean(ct)):
    print(f"[note] '{ct}' is not a rearrangement of '{pt}' (L is not in the input) -> "
          "treating L as a typo for I")
    ct = ct.replace("L", "I")

print("\na) CHOSEN-PLAINTEXT ATTACK: Eve chose the input and saw the output.")
size, key = known_plaintext_attack(pt, ct, "permutation")
print(f"b) Smallest block size that explains it: {size}  ->  key size = {size}")
print(f"   Permutation key (output position i <- input position): {key}")
print(f"   Check: encrypt('{pt}') = {transposition(pt, key)},  "
      f"decrypt = {transposition(ct, key, decrypt=True)}")
