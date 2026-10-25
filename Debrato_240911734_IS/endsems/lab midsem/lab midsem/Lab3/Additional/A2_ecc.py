"""Lab 3 - Additional 2
ECC: encrypt "Secure Transactions" with the public key and decrypt with the private key.
(Same as Exercise 2; this version also runs on several curves and times them.)"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Secure Transactions")
rows = []
for curve in ["secp256r1", "secp256k1", "secp384r1", "secp521r1"]:
    priv, t_gen = timed(generate_keys, "ecc", curve=curve)
    ct, t_enc = timed(ecc_cipher, msg, priv.public_key())
    pt, t_dec = timed(ecc_cipher, ct, priv, decrypt=True)
    rows.append([curve, t_gen * 1000, t_enc * 1000, t_dec * 1000, len(ct), pt.decode()])
print_table(["Curve", "Keygen ms", "Enc ms", "Dec ms", "CT bytes", "Decrypted"], rows)
