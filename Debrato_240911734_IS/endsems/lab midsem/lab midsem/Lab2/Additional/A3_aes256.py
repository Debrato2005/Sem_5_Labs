"""Lab 2 - Additional 3
AES-256: encrypt "Encryption Strength" with key
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" (64 hex = 32 bytes)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Encryption Strength")
key = key_bytes(ask("AES-256 key", "0123456789ABCDEF" * 4), 32)
MODE = ask("Mode", "ECB")

banner("AES-256")
symmetric("AES", key, msg, MODE, show=True)
