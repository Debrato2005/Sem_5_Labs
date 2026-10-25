"""Lab 2 - Additional 5
AES in CTR mode: message "Cryptography Lab Exercise", key "0123456789ABCDEF0123456789ABCDEF",
nonce "0000000000000000" (16 hex = 8-byte nonce; the other 8 bytes are the counter)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Cryptography Lab Exercise")
key = key_bytes(ask("AES key", "0123456789ABCDEF0123456789ABCDEF"), 16)
nonce = key_bytes(ask("Nonce (16 hex)", "0000000000000000"), 8)

banner("AES-CTR")
symmetric("AES", key, msg, "CTR", iv=nonce, show=True)
print("  (CTR needs no padding: ciphertext length == plaintext length)")
