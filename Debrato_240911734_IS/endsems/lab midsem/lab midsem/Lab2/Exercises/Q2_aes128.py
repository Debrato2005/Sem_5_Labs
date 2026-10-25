"""Lab 2 - Exercise 2
Encrypt "Sensitive Information" using AES-128 with key "0123456789ABCDEF0123456789ABCDEF"
(32 hex chars = 16 bytes), then decrypt to verify.
To modify: MODE = ECB / CBC / CFB / OFB / CTR / GCM / EAX."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Sensitive Information")
key = key_bytes(ask("AES-128 key", "0123456789ABCDEF0123456789ABCDEF"), 16)
MODE = ask("Mode", "ECB")

banner("AES-128")
symmetric("AES", key, msg, MODE, show=True)
