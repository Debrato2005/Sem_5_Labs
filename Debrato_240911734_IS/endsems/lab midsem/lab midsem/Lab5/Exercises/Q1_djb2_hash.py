"""Lab 5 - Exercise 1
Hash function: start at 5381; for every character multiply by 33 and add its ASCII value,
mix the bits with bitwise operations, keep the value in 32 bits with a mask (& 0xFFFFFFFF).
To modify: djb2_hash(s, mix=False) gives the classic djb2 without the bit-mixing finaliser;
hash_hex(s, "djb2") gives the same hash as hex next to md5 / sha256."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

text = ask("String to hash", "Information Security")
h = djb2_hash(text)
print(f"\nhash('{text}') = {h}  (0x{h:08X})")

print("\nAvalanche check - one character changed:")
for s in ["hello", "hellp", "Hello", "hello "]:
    print(f"  {s!r:10} -> 0x{djb2_hash(s):08X}   (classic djb2: 0x{djb2_hash(s, mix=False):08X})")
