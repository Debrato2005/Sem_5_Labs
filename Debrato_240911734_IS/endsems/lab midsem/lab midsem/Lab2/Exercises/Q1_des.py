"""Lab 2 - Exercise 1
Encrypt "Confidential Data" using DES with key "A1B2C3D4", then decrypt to verify.
To modify: change MODE to CBC / CFB / OFB / CTR / EAX; DES keys are 8 bytes."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Confidential Data")
key = key_bytes(ask("DES key (8 ASCII chars or 16 hex)", "A1B2C3D4"), 8)
MODE = ask("Mode", "ECB")

banner("DES")
symmetric("DES", key, msg, MODE, show=True)
