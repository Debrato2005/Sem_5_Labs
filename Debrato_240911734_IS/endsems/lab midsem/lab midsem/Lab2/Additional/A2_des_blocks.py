"""Lab 2 - Additional 2
DES with key "A1B2C3D4E5F60708" (16 hex = 8 bytes). Data (hex):
 Block1: 54686973206973206120636f6e666964656e7469616c206d657373616765
 Block2: 416e64207468697320697320746865207365636f6e6420626c6f636b
 a) ciphertext of each block   b) decrypt to retrieve the plaintext blocks."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

key = key_bytes(ask("DES key", "A1B2C3D4E5F60708"), 8)
BLOCKS = {"Block1": "54686973206973206120636f6e666964656e7469616c206d657373616765",
          "Block2": "416e64207468697320697320746865207365636f6e6420626c6f636b"}
MODE = ask("Mode", "ECB")

for name, hx in BLOCKS.items():
    data = bytes.fromhex(hx)
    ct, iv = symmetric("DES", key, data, MODE)
    pt = symmetric("DES", key, ct, MODE, decrypt=True, iv=iv)
    banner(name)
    print(f"  Plaintext (hex)  : {hx}")
    print(f"  Plaintext (text) : {data.decode()}")
    print(f"  a) Ciphertext    : {fmt(ct)}")
    print(f"  b) Decrypted hex : {pt.hex()}  -> '{pt.decode()}'  match={pt == data}")
