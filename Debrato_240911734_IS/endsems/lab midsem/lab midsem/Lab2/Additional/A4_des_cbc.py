"""Lab 2 - Additional 4
DES in CBC mode: message "Secure Communication", key "A1B2C3D4", IV "12345678"."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Secure Communication")
key = key_bytes(ask("DES key", "A1B2C3D4"), 8)
iv = key_bytes(ask("IV (8 bytes)", "12345678"), 8)

banner("DES-CBC")
symmetric("DES", key, msg, "CBC", iv=iv, show=True)
