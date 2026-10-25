"""Lab 4 - Exercise 2  (HealthCare Inc. - Rabin key management service)
 * Key generation   : Rabin key pairs per hospital/clinic, configurable size (e.g. 1024)
 * Key distribution : API get_public() / get_private(token)  (token = facility credential)
 * Key revocation   : revoke() when a facility closes or is compromised
 * Key renewal      : renew_expired() every 12 months (simulated by moving the clock)
 * Secure storage   : private keys AES-GCM encrypted under a PBKDF2 master key
 * Auditing/logging : every operation timestamped (screen + rabin_kms_audit.log)
 * Compliance       : HIPAA checklist printed at the end
 * Trade-off        : Rabin vs RSA measured and discussed
Patient records are encrypted hybrid style: Rabin encrypts a random AES key, AES-GCM the record."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

KEY_BITS = ask("Rabin key size (bits)", 1024)
km = KeyManager("rabin", bits=KEY_BITS, lifetime_days=365,
                master_password="HealthCare-HSM-secret", log_file="rabin_kms_audit.log")


def encrypt_record(n, record):                         # Rabin wraps an AES key, AES-GCM the record
    return rabin_cipher(record, n, mode="hybrid")


def decrypt_record(priv, packet):
    return rabin_cipher(packet, (priv["p"], priv["q"]), decrypt=True, mode="hybrid").decode()


banner("1. Key generation for each facility")
tokens = {f: km.register(f) for f in ["Hospital-Manipal", "Hospital-Udupi", "Clinic-Karkala"]}
km.print_status()

banner("2. Key distribution + use")
n = km.get_public("Hospital-Udupi")["n"]                    # a doctor fetches the public key
packet = encrypt_record(n, "Patient P-77 | MRI: normal | BP 120/80")
priv = km.get_private("Hospital-Udupi", tokens["Hospital-Udupi"])   # hospital fetches its key
print("  Hospital-Udupi decrypts:", decrypt_record(priv, packet))
try:
    km.get_private("Hospital-Udupi", "stolen-or-wrong-token")
except PermissionError as e:
    print("  Attacker with wrong token:", e)

banner("3. Key revocation: Clinic-Karkala closes")
km.revoke("Clinic-Karkala", "facility closed")
try:
    km.get_private("Clinic-Karkala", tokens["Clinic-Karkala"])
except PermissionError as e:
    print("  Denied:", e)

banner("4. Automatic renewal after 12 months (clock moved forward 366 days)")
km.renew_expired(now=time.time() + 366 * 86400)
km.print_status()

banner("5. Secure storage (what is stored on disk/in DB for a private key)")
print("  sealed private key:", fmt(km.keys["Hospital-Manipal"]["sealed"])[:96], "...")

banner("6. Audit log (also written to rabin_kms_audit.log)")
km.print_audit()

banner("7. HIPAA-style compliance")
print("""  [x] Access control       - private keys released only with the facility's token
  [x] Encryption at rest   - private keys sealed with AES-256-GCM (PBKDF2 master key)
  [x] Encryption in transit- records encrypted with the recipient's public key
  [x] Audit controls       - every generate/distribute/revoke/renew logged with timestamp
  [x] Integrity            - AES-GCM tag detects tampering of records and stored keys
  [x] Key lifecycle        - 12-month expiry, revocation on closure/compromise""")

banner("8. Trade-off: Rabin vs RSA")
rows = []
for bits in [1024, 2048]:
    (n_, p_, q_), t_kg = timed(generate_keys, "rabin", bits)
    msg = get_random_bytes(32)
    c, t_e = timed(rabin_cipher, msg, n_, repeat=50)
    _, t_d = timed(rabin_cipher, c, (p_, q_), decrypt=True, repeat=50)
    rows.append([f"Rabin-{bits}", t_kg * 1000, t_e * 1000, t_d * 1000])
    key, t_kg = timed(generate_keys, "rsa", bits)
    m = int.from_bytes(msg, "big")
    c, t_e = timed(rsa_cipher, m, key, mode="textbook", repeat=50)
    _, t_d = timed(rsa_cipher, c, key, decrypt=True, mode="textbook", repeat=50)
    rows.append([f"RSA-{bits}", t_kg * 1000, t_e * 1000, t_d * 1000])
print_table(["Scheme", "Keygen ms", "Encrypt ms", "Decrypt ms"], rows)
print("""
  * Encryption: Rabin = one squaring -> fastest; RSA needs m^65537 (17 multiplications).
  * Decryption: Rabin = two half-size exponentiations (CRT), faster than the full c^d mod n
    RSA timed here (RSA with CRT is similar). Rabin must pick 1 of 4 roots (we add a
    hash tag as redundancy); RSA gives a unique result.
  * Security: breaking Rabin is PROVABLY as hard as factoring n; RSA is believed to be.
  * Weakness: Rabin is broken by a chosen-ciphertext attack (two different roots reveal
    p, q) unless redundancy/padding is enforced. RSA cannot sign/verify as simply.
  * Practice: RSA is standardised (PKCS#1, OAEP, PSS) and widely supported; Rabin is not.""")
