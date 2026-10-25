"""Lab 2 - Exercise 4
Encrypt "Classified Text" using Triple DES with key
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF" (48 hex = 24 bytes), then decrypt.
Note: that key is K1 = K2 = K3, so 3DES (E-D-E) collapses to single DES; the library
prints a note and uses DES with K1 (the result is mathematically identical).
Use e.g. "0123456789ABCDEFFEDCBA987654321089ABCDEF01234567" for a real 3-key 3DES."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Classified Text")
key = key_bytes(ask("3DES key (48 hex)", "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"), 24)
MODE = ask("Mode", "ECB")

banner("Triple DES")
symmetric("3DES", key, msg, MODE, show=True)
