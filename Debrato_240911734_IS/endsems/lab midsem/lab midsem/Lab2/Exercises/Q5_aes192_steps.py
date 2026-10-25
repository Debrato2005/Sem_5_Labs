"""Lab 2 - Exercise 5
Encrypt "Top Secret Data" using AES-192 with key "FEDCBA9876543210FEDCBA9876543210".
Show all steps: key expansion, initial round, main rounds, final round.

The given key is 32 hex chars = only 16 bytes, but AES-192 needs 24 bytes, so the
first 24 ASCII characters are used (key_bytes prints a note). Change KEY_SIZE to
16 (AES-128) or 32 (AES-256) and the same code shows 10 or 14 rounds."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Top Secret Data")
KEY_SIZE = ask("Key size in bytes (16/24/32)", 24)
key = key_bytes(ask("Key", "FEDCBA9876543210FEDCBA9876543210"), KEY_SIZE)

block = pad(to_bytes(msg), 16)
banner(f"AES-{KEY_SIZE * 8} step by step")
print(f"  Key       : {fmt(key)}")
print(f"  Plaintext : {msg!r} -> padded block {fmt(block)}")
print("  (state printed as 4 rows separated by '|', bytes in column order)")
ct = aes_encrypt_block_verbose(key, block)

lib_ct, _ = symmetric("AES", key, msg, "ECB")              # library AES-ECB pads the same way
print(f"\n  Ciphertext (manual)   : {fmt(ct)}")
print(f"  Ciphertext (library)  : {fmt(lib_ct)}   match = {ct == lib_ct}")
print(f"  Decrypted             : {symmetric('AES', key, ct, 'ECB', decrypt=True).decode()}")
