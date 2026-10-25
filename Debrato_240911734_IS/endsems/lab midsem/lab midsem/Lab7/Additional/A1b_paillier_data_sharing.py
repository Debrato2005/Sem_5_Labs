"""Lab 7 - Additional 1b
Secure data sharing with Paillier: two hospitals encrypt their patient counts / costs with
an analyst's public key; an untrusted cloud combines them (sum, weighted sum, average)
without decrypting; only the analyst decrypts the final results."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

pub, priv = generate_keys("paillier", 1024)                         # analyst's keys

hospital_A = {"patients": 120, "cost": 54000}
hospital_B = {"patients": 95, "cost": 47000}
enc_A = {k: paillier_cipher(v, pub) for k, v in hospital_A.items()}  # done at hospital A
enc_B = {k: paillier_cipher(v, pub) for k, v in hospital_B.items()}  # done at hospital B

banner("Cloud sees only ciphertexts")
print("  A.patients =", str(enc_A["patients"])[:60], "...")

# --- cloud computes on ciphertexts ---
enc_total_patients = homomorphic("paillier", [enc_A["patients"], enc_B["patients"]], pub)
enc_total_cost = homomorphic("paillier", [enc_A["cost"], enc_B["cost"]], pub)
enc_weighted = homomorphic("paillier", [homomorphic("paillier", enc_A["cost"], pub, "mul_const", 2),
                                        enc_B["cost"]], pub)

banner("Analyst decrypts the results")
tp, tc = paillier_cipher([enc_total_patients, enc_total_cost], priv, decrypt=True)
print(f"  total patients     = {tp}   (expected {hospital_A['patients'] + hospital_B['patients']})")
print(f"  total cost         = {tc}   (expected {hospital_A['cost'] + hospital_B['cost']})")
print(f"  average cost/patient = {tc / tp:.2f}")
print(f"  weighted 2*A + B   = {paillier_cipher(enc_weighted, priv, decrypt=True)}")
print("  Neither hospital learned the other's data; the cloud learned nothing.")
