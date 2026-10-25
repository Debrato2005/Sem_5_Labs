"""Lab 3 - Exercise 2
ECC: encrypt "Secure Transactions" with the public key, decrypt with the private key.
ECC cannot encrypt text directly, so ECIES is used (EC-ElGamal style):
  sender: random r, C1 = r*G, shared S = r*Q, C2 = AES-GCM(KDF(S), M)
  receiver: S = d*C1, M = AES-GCM-decrypt(KDF(S), C2)
To modify: CURVE = secp256r1 | secp384r1 | secp521r1 | secp256k1."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Secure Transactions")
CURVE = ask("Curve", "secp256r1")

priv = generate_keys("ecc", curve=CURVE)
pub = priv.public_key()
banner(f"ECC key pair on {CURVE}")
print(f"  private d = {priv.private_numbers().private_value}")
print(f"  public  Q = ({pub.public_numbers().x},\n               {pub.public_numbers().y})")

ct = ecc_cipher(msg, pub)
banner("ECIES encryption")
print("  Ciphertext (C1 point || nonce || C2+tag):", fmt(ct))
print("  Decrypted:", ecc_cipher(ct, priv, decrypt=True).decode())
