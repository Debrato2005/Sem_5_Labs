"""Lab 3 - Additional 4
Healthcare: doctors and hospitals exchange patient records. Use ElGamal on the
secp256r1 curve (EC-ElGamal / ECIES) with the recipient's public key; decrypt with the
recipient's private key. Measure encryption/decryption time for different data sizes."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

SIZES_KB = [1, 10, 100, 1024]
hospital = generate_keys("ecc", curve="secp256r1")      # recipient key pair
hospital_pub = hospital.public_key()                    # published to doctors

record = json.dumps({"patient": "John Doe", "id": "P-1029", "bp": "140/90",
                     "diagnosis": "hypertension", "rx": "amlodipine 5mg"})
ct = ecc_cipher(record, hospital_pub)
banner("Doctor -> Hospital: one patient record")
print("  Encrypted:", fmt(ct)[:80], "...")
print("  Hospital decrypts:", ecc_cipher(ct, hospital, decrypt=True).decode())

rows = []
for kb in SIZES_KB:
    data = (record * (kb * 1024 // len(record) + 1))[:kb * 1024]
    c, t_enc = timed(ecc_cipher, data, hospital_pub, repeat=5)
    p, t_dec = timed(ecc_cipher, c, hospital, decrypt=True, repeat=5)
    rows.append([f"{kb} KB", t_enc * 1000, t_dec * 1000, p.decode() == data])
banner("Performance (average of 5 runs)")
print_table(["Data", "Encrypt ms", "Decrypt ms", "Correct"], rows)
