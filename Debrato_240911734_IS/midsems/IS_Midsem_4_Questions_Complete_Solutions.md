# IS Midsem — Solutions to the 4 Supplied Questions

All four questions are numbered exactly as supplied.

**Note:** Questions 1 and 2 are the same HealthSecure question. The same complete program is therefore valid for both. It is repeated here so each question remains standalone.

Install dependency if required:

```bash
python -m pip install pycryptodome
```

---

# Question 1 — HealthSecure

## Question summary

A hospital wants to develop a secure patient-information management system called HealthSecure. The system has three roles: Doctor, Nurse, and Admin.

Requirements include RSA encryption/decryption, RSA public/private keys, SHA-256, RSA digital signatures, RBAC, patient data storage, timestamps, secure encrypted-record storage, and role restrictions. Doctor can create/view/verify/decrypt records; Nurse can view encrypted records and verify integrity/signature but cannot decrypt; Admin can view only record ID/hash/timestamp and verify signatures but cannot decrypt.

## Complete solution — `q1_healthsecure.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from datetime import datetime
import json

DB = "healthsecure_records.json"
PRIV = "doctor_private.pem"
PUB = "doctor_public.pem"


def generate_keys():
    key = RSA.generate(2048)
    open(PRIV, "wb").write(key.export_key())
    open(PUB, "wb").write(key.publickey().export_key())
    print("Doctor RSA key pair generated.")


def ensure_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        generate_keys()


def load_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r["id"] == rid:
            return r
    print("Record not found.")
    return None


def rsa_encrypt_chunks(pub, data):
    size = pub.size_in_bytes() - 2 * SHA256.digest_size - 2
    return [
        PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data[i:i + size])
        for i in range(0, len(data), size)
    ]


def rsa_decrypt_chunks(priv, chunks):
    return b"".join(
        PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(c)
        for c in chunks
    )


def verify_record(record, pub):
    chunks = [bytes.fromhex(x) for x in record["ciphertext"]]
    encrypted_data = b"".join(chunks)

    current_hash = SHA256.new(encrypted_data).hexdigest()
    integrity_ok = current_hash == record["hash"]

    try:
        pkcs1_15.new(pub).verify(
            SHA256.new(encrypted_data),
            bytes.fromhex(record["signature"])
        )
        signature_ok = True
    except (ValueError, TypeError):
        signature_ok = False

    return integrity_ok, signature_ok, chunks


def doctor_menu(records):
    while True:
        print("\n--- DOCTOR ---")
        print("1. Generate new RSA key pair")
        print("2. Add patient record")
        print("3. View stored patient records")
        print("4. Verify and decrypt a record")
        print("5. Back")
        ch = input("Choice: ")

        if ch == "1":
            if records:
                print("Keys not regenerated because existing records depend on the current key pair.")
            else:
                generate_keys()

        elif ch == "2":
            rid = input("Record ID: ")
            if any(r["id"] == rid for r in records):
                print("Record ID already exists.")
                continue

            patient = {
                "name": input("Name: "),
                "age": input("Age: "),
                "gender": input("Gender: "),
                "blood_group": input("Blood Group: "),
                "diagnosis": input("Diagnosis: "),
                "other_details": input("Other medical details: ")
            }

            data = json.dumps(patient).encode()

            priv = RSA.import_key(open(PRIV, "rb").read())
            pub = priv.publickey()

            chunks = rsa_encrypt_chunks(pub, data)
            encrypted_data = b"".join(chunks)

            h = SHA256.new(encrypted_data)
            signature = pkcs1_15.new(priv).sign(h)

            record = {
                "id": rid,
                "ciphertext": [c.hex() for c in chunks],
                "hash": h.hexdigest(),
                "signature": signature.hex(),
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }

            records.append(record)
            save_records(records)
            print("Encrypted patient record stored.")

        elif ch == "3":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("Encrypted data:", r["ciphertext"])
                print("SHA-256:", r["hash"])
                print("Signature:", r["signature"])
                print("Timestamp:", r["timestamp"])

        elif ch == "4":
            r = get_record(records)
            if not r:
                continue

            pub = RSA.import_key(open(PUB, "rb").read())
            integrity_ok, signature_ok, chunks = verify_record(r, pub)

            print("Integrity:", "VALID" if integrity_ok else "INVALID")
            print("Signature:", "VALID" if signature_ok else "INVALID")

            if integrity_ok and signature_ok:
                priv = RSA.import_key(open(PRIV, "rb").read())
                plaintext = rsa_decrypt_chunks(priv, chunks)
                patient = json.loads(plaintext.decode())

                print("\nDecrypted patient information:")
                for k, v in patient.items():
                    print(f"{k}: {v}")
            else:
                print("Verification failed. Decryption not performed.")

        elif ch == "5":
            break

        else:
            print("Invalid choice.")


def nurse_menu(records):
    pub = RSA.import_key(open(PUB, "rb").read())

    while True:
        print("\n--- NURSE ---")
        print("1. View encrypted patient records")
        print("2. Verify integrity and authenticity")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("Encrypted data:", r["ciphertext"])
                print("SHA-256:", r["hash"])
                print("Signature:", r["signature"])
                print("Timestamp:", r["timestamp"])

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            integrity_ok, signature_ok, _ = verify_record(r, pub)

            print("Integrity:", "VALID" if integrity_ok else "INVALID")
            print("Signature:", "VALID" if signature_ok else "INVALID")
            print(
                "Verification timestamp:",
                datetime.now().isoformat(timespec="seconds")
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def admin_menu(records):
    pub = RSA.import_key(open(PUB, "rb").read())

    while True:
        print("\n--- ADMIN ---")
        print("1. View permitted record details")
        print("2. Verify Doctor's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("SHA-256:", r["hash"])
                print("Timestamp:", r["timestamp"])

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            _, signature_ok, _ = verify_record(r, pub)
            print(
                "Digital signature:",
                "VALID" if signature_ok else "INVALID"
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def main():
    ensure_keys()
    records = load_records()

    while True:
        print("\n=== HealthSecure ===")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            doctor_menu(records)
        elif ch == "2":
            nurse_menu(records)
        elif ch == "3":
            admin_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

```

---

# Question 2 — HealthSecure

## Question summary

HealthSecure — same Doctor/Nurse/Admin specification as Question 1, repeated in the supplied question set.

Because Question 2 is identical to Question 1, the correct implementation is the same.

## Complete solution — `q2_healthsecure.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from datetime import datetime
import json

DB = "healthsecure_records.json"
PRIV = "doctor_private.pem"
PUB = "doctor_public.pem"


def generate_keys():
    key = RSA.generate(2048)
    open(PRIV, "wb").write(key.export_key())
    open(PUB, "wb").write(key.publickey().export_key())
    print("Doctor RSA key pair generated.")


def ensure_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        generate_keys()


def load_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r["id"] == rid:
            return r
    print("Record not found.")
    return None


def rsa_encrypt_chunks(pub, data):
    size = pub.size_in_bytes() - 2 * SHA256.digest_size - 2
    return [
        PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data[i:i + size])
        for i in range(0, len(data), size)
    ]


def rsa_decrypt_chunks(priv, chunks):
    return b"".join(
        PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(c)
        for c in chunks
    )


def verify_record(record, pub):
    chunks = [bytes.fromhex(x) for x in record["ciphertext"]]
    encrypted_data = b"".join(chunks)

    current_hash = SHA256.new(encrypted_data).hexdigest()
    integrity_ok = current_hash == record["hash"]

    try:
        pkcs1_15.new(pub).verify(
            SHA256.new(encrypted_data),
            bytes.fromhex(record["signature"])
        )
        signature_ok = True
    except (ValueError, TypeError):
        signature_ok = False

    return integrity_ok, signature_ok, chunks


def doctor_menu(records):
    while True:
        print("\n--- DOCTOR ---")
        print("1. Generate new RSA key pair")
        print("2. Add patient record")
        print("3. View stored patient records")
        print("4. Verify and decrypt a record")
        print("5. Back")
        ch = input("Choice: ")

        if ch == "1":
            if records:
                print("Keys not regenerated because existing records depend on the current key pair.")
            else:
                generate_keys()

        elif ch == "2":
            rid = input("Record ID: ")
            if any(r["id"] == rid for r in records):
                print("Record ID already exists.")
                continue

            patient = {
                "name": input("Name: "),
                "age": input("Age: "),
                "gender": input("Gender: "),
                "blood_group": input("Blood Group: "),
                "diagnosis": input("Diagnosis: "),
                "other_details": input("Other medical details: ")
            }

            data = json.dumps(patient).encode()

            priv = RSA.import_key(open(PRIV, "rb").read())
            pub = priv.publickey()

            chunks = rsa_encrypt_chunks(pub, data)
            encrypted_data = b"".join(chunks)

            h = SHA256.new(encrypted_data)
            signature = pkcs1_15.new(priv).sign(h)

            record = {
                "id": rid,
                "ciphertext": [c.hex() for c in chunks],
                "hash": h.hexdigest(),
                "signature": signature.hex(),
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }

            records.append(record)
            save_records(records)
            print("Encrypted patient record stored.")

        elif ch == "3":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("Encrypted data:", r["ciphertext"])
                print("SHA-256:", r["hash"])
                print("Signature:", r["signature"])
                print("Timestamp:", r["timestamp"])

        elif ch == "4":
            r = get_record(records)
            if not r:
                continue

            pub = RSA.import_key(open(PUB, "rb").read())
            integrity_ok, signature_ok, chunks = verify_record(r, pub)

            print("Integrity:", "VALID" if integrity_ok else "INVALID")
            print("Signature:", "VALID" if signature_ok else "INVALID")

            if integrity_ok and signature_ok:
                priv = RSA.import_key(open(PRIV, "rb").read())
                plaintext = rsa_decrypt_chunks(priv, chunks)
                patient = json.loads(plaintext.decode())

                print("\nDecrypted patient information:")
                for k, v in patient.items():
                    print(f"{k}: {v}")
            else:
                print("Verification failed. Decryption not performed.")

        elif ch == "5":
            break

        else:
            print("Invalid choice.")


def nurse_menu(records):
    pub = RSA.import_key(open(PUB, "rb").read())

    while True:
        print("\n--- NURSE ---")
        print("1. View encrypted patient records")
        print("2. Verify integrity and authenticity")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("Encrypted data:", r["ciphertext"])
                print("SHA-256:", r["hash"])
                print("Signature:", r["signature"])
                print("Timestamp:", r["timestamp"])

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            integrity_ok, signature_ok, _ = verify_record(r, pub)

            print("Integrity:", "VALID" if integrity_ok else "INVALID")
            print("Signature:", "VALID" if signature_ok else "INVALID")
            print(
                "Verification timestamp:",
                datetime.now().isoformat(timespec="seconds")
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def admin_menu(records):
    pub = RSA.import_key(open(PUB, "rb").read())

    while True:
        print("\n--- ADMIN ---")
        print("1. View permitted record details")
        print("2. Verify Doctor's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("SHA-256:", r["hash"])
                print("Timestamp:", r["timestamp"])

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            _, signature_ok, _ = verify_record(r, pub)
            print(
                "Digital signature:",
                "VALID" if signature_ok else "INVALID"
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def main():
    ensure_keys()
    records = load_records()

    while True:
        print("\n=== HealthSecure ===")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            doctor_menu(records)
        elif ch == "2":
            nurse_menu(records)
        elif ch == "3":
            admin_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

```

---

# Question 3 — Hospital Management using AES-128 + ElGamal + RSA

## Question summary

Perform a hospital based management system using AES-128, ElGamal and RSA. Create a file, AES-encrypt its contents into another file, RSA-encrypt the AES key into another file, ElGamal-encrypt a supplied authorization code under given parameters, display encrypted/public/RSA values, hash the AES ciphertext, compare sender/receiver hashes, decrypt only if integrity succeeds, and demonstrate integrity failure after modifying the ciphertext.

## Complete solution — `q3_aes_rsa_elgamal.py`

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import isPrime
import json

print("=== Hospital AES-128 + RSA + ElGamal System ===")

# 1. Create a file and add content
plain_file = input("Plaintext file name: ")
content = input("Enter file content: ")
open(plain_file, "w").write(content)

# 2. AES-128 encrypt the file and store ciphertext
aes_key = get_random_bytes(16)
iv = get_random_bytes(16)

data = open(plain_file, "rb").read()
ciphertext = AES.new(
    aes_key,
    AES.MODE_CBC,
    iv
).encrypt(pad(data, 16))

encrypted_file = input("AES encrypted output file: ")
open(encrypted_file, "wb").write(ciphertext)

iv_file = input("IV output file: ")
open(iv_file, "wb").write(iv)

# 3. RSA encrypt AES key and store it
rsa_private = RSA.generate(2048)
rsa_public = rsa_private.publickey()

encrypted_aes_key = PKCS1_OAEP.new(
    rsa_public,
    hashAlgo=SHA256
).encrypt(aes_key)

rsa_key_file = input("RSA-encrypted AES key output file: ")
open(rsa_key_file, "wb").write(encrypted_aes_key)

# 4. ElGamal encrypt authorization code using given parameters
p = int(input("ElGamal prime p: "))
g = int(input("ElGamal generator g: "))
x = int(input("ElGamal private key x: "))
k = int(input("ElGamal random k: "))
auth_code = int(input("Authorization code as integer: "))

if not isPrime(p):
    raise ValueError("p must be prime")
if not (1 <= x <= p - 2):
    raise ValueError("x must satisfy 1 <= x <= p-2")
if not (1 <= k <= p - 2):
    raise ValueError("k must satisfy 1 <= k <= p-2")
if not (0 <= auth_code < p):
    raise ValueError("Authorization code must satisfy 0 <= m < p")

y = pow(g, x, p)
c1 = pow(g, k, p)
c2 = auth_code * pow(y, k, p) % p

elgamal_file = input("ElGamal ciphertext output file: ")
json.dump(
    {
        "p": p,
        "g": g,
        "y": y,
        "c1": c1,
        "c2": c2
    },
    open(elgamal_file, "w"),
    indent=2
)

# 5. Display required encrypted/public/RSA values
print("\nAES ciphertext:", ciphertext.hex())
print("AES IV:", iv.hex())

print("\nRSA public key:")
print(rsa_public.export_key().decode())
print("RSA n:", rsa_private.n)
print("RSA e:", rsa_private.e)
print("RSA d:", rsa_private.d)

print("\nElGamal public key:", (p, g, y))
print("Encrypted authorization code:", (c1, c2))

# 6. Sender hashes AES ciphertext
sender_hash = SHA256.new(ciphertext).hexdigest()
print("\nSender SHA-256:", sender_hash)

# 7. Receiver reads encrypted message and hashes it
received_ciphertext = open(encrypted_file, "rb").read()
receiver_hash = SHA256.new(received_ciphertext).hexdigest()

print("Receiver SHA-256:", receiver_hash)

# 8. Verify integrity BEFORE decrypting
if sender_hash == receiver_hash:
    print("Sender/receiver hash verification: VALID")

    recovered_aes_key = PKCS1_OAEP.new(
        rsa_private,
        hashAlgo=SHA256
    ).decrypt(open(rsa_key_file, "rb").read())

    recovered_text = unpad(
        AES.new(
            recovered_aes_key,
            AES.MODE_CBC,
            open(iv_file, "rb").read()
        ).decrypt(received_ciphertext),
        16
    )

    s = pow(c1, x, p)
    recovered_auth = c2 * pow(s, -1, p) % p

    print("\nDecrypted AES key:", recovered_aes_key.hex())
    print("Decrypted authorization code:", recovered_auth)
    print("Decrypted text:", recovered_text.decode())
    print("Original file content:", open(plain_file).read())

else:
    print("Integrity failed.")
    print("Decryption not performed.")

# 9. Tampering demonstration
tampered = bytearray(received_ciphertext)
tampered[0] ^= 1
tampered = bytes(tampered)

tampered_file = input("\nTampered ciphertext output file: ")
open(tampered_file, "wb").write(tampered)

tampered_hash = SHA256.new(tampered).hexdigest()

print("Original sender hash:", sender_hash)
print("Tampered hash:", tampered_hash)

if tampered_hash == sender_hash:
    print("Integrity unexpectedly passed.")
else:
    print("Integrity failed after tampering.")
    print("Decryption not performed.")

```

### Required execution order

```text
Create plaintext file
        ↓
AES-128 encrypt file
        ↓
Store AES ciphertext
        ↓
RSA encrypt AES key
        ↓
Store encrypted AES key
        ↓
ElGamal encrypt authorization code
        ↓
SHA-256(AES ciphertext)
        ↓
Receiver hashes received ciphertext
        ↓
Hashes match?
   YES          NO
    ↓            ↓
RSA decrypt      Stop
AES key          No decryption
    ↓
AES decrypt file
    ↓
Show recovered data

Tamper one ciphertext byte
        ↓
Recompute SHA-256
        ↓
Integrity must fail
        ↓
No decryption
```

---

# Question 4 — MediSecure

## Question summary

MediSecure — Patient/Doctor/Auditor system using AES with user-provided shared key and IV, SHA-256 over encrypted medical records, Patient RSA digital signatures, .txt file handling, timestamps, RBAC, Doctor verification-before-decryption, and Auditor metadata/signature access without plaintext decryption.

## Complete solution — `q4_medisecure.py`

```python
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import json
import os

DB = "medisecure_records.json"
PRIV = "patient_private.pem"
PUB = "patient_public.pem"


def ensure_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        key = RSA.generate(2048)
        open(PRIV, "wb").write(key.export_key())
        open(PUB, "wb").write(key.publickey().export_key())
        print("Patient RSA key pair generated.")


def load_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r["id"] == rid:
            return r
    print("Record not found.")
    return None


def verify_record(record):
    ciphertext = bytes.fromhex(record["ciphertext"])

    current_hash = SHA256.new(ciphertext).hexdigest()
    integrity_ok = current_hash == record["hash"]

    pub = RSA.import_key(open(PUB, "rb").read())

    try:
        pkcs1_15.new(pub).verify(
            SHA256.new(ciphertext),
            bytes.fromhex(record["signature"])
        )
        signature_ok = True
    except (ValueError, TypeError):
        signature_ok = False

    return integrity_ok, signature_ok, ciphertext


def patient_menu(records):
    while True:
        print("\n--- PATIENT ---")
        print("1. Upload and encrypt .txt record")
        print("2. View uploaded encrypted records")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            path = input("Medical record .txt file: ")

            if not path.lower().endswith(".txt"):
                print("Only .txt files are allowed.")
                continue

            try:
                data = open(path, "rb").read()
            except FileNotFoundError:
                print("File not found.")
                continue

            rid = input("Record ID: ")
            if any(r["id"] == rid for r in records):
                print("Record ID already exists.")
                continue

            key = input("Shared AES key (16/24/32 chars): ").encode()
            iv = input("IV (16 chars): ").encode()

            if len(key) not in (16, 24, 32):
                print("AES key must be exactly 16, 24 or 32 bytes.")
                continue

            if len(iv) != 16:
                print("AES CBC IV must be exactly 16 bytes.")
                continue

            ciphertext = AES.new(
                key,
                AES.MODE_CBC,
                iv
            ).encrypt(pad(data, 16))

            h = SHA256.new(ciphertext)

            private_key = RSA.import_key(open(PRIV, "rb").read())
            signature = pkcs1_15.new(private_key).sign(h)

            record = {
                "id": rid,
                "filename": os.path.basename(path),
                "ciphertext": ciphertext.hex(),
                "hash": h.hexdigest(),
                "signature": signature.hex(),
                "iv": iv.hex(),
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }

            records.append(record)
            save_records(records)
            print("Encrypted medical record stored.")

        elif ch == "2":
            if not records:
                print("No records.")
            for r in records:
                print("\nRecord ID:", r["id"])
                print("Filename:", r["filename"])
                print("Encrypted record:", r["ciphertext"])
                print("SHA-256:", r["hash"])
                print("Timestamp:", r["timestamp"])

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def doctor_menu(records):
    while True:
        print("\n--- DOCTOR ---")
        print("1. View available uploaded records")
        print("2. Verify and decrypt a record")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print(
                    f'ID={r["id"]}  FILE={r["filename"]}  '
                    f'HASH={r["hash"]}  TIME={r["timestamp"]}'
                )

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            integrity_ok, signature_ok, ciphertext = verify_record(r)

            verification_time = datetime.now().isoformat(timespec="seconds")
            print("Integrity:", "VALID" if integrity_ok else "INVALID")
            print("Signature:", "VALID" if signature_ok else "INVALID")
            print("Verification timestamp:", verification_time)

            if not (integrity_ok and signature_ok):
                print("Verification failed. Decryption not performed.")
                continue

            key = input("Shared AES key (16/24/32 chars): ").encode()

            if len(key) not in (16, 24, 32):
                print("Invalid AES key length.")
                continue

            iv = bytes.fromhex(r["iv"])

            try:
                plaintext = unpad(
                    AES.new(
                        key,
                        AES.MODE_CBC,
                        iv
                    ).decrypt(ciphertext),
                    16
                )

                print("\nDecrypted medical record:")
                print(plaintext.decode())

            except (ValueError, UnicodeDecodeError):
                print("Incorrect AES key or corrupted encrypted data.")

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def auditor_menu(records):
    pub = RSA.import_key(open(PUB, "rb").read())

    while True:
        print("\n--- AUDITOR ---")
        print("1. View permitted metadata")
        print("2. Verify Patient's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\nFilename:", r["filename"])
                print("SHA-256:", r["hash"])
                print("Timestamp:", r["timestamp"])

        elif ch == "2":
            r = get_record(records)
            if not r:
                continue

            ciphertext = bytes.fromhex(r["ciphertext"])
            signature = bytes.fromhex(r["signature"])

            try:
                pkcs1_15.new(pub).verify(
                    SHA256.new(ciphertext),
                    signature
                )
                print("Digital signature: VALID")
            except (ValueError, TypeError):
                print("Digital signature: INVALID")

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def main():
    ensure_keys()
    records = load_records()

    while True:
        print("\n=== MediSecure ===")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            patient_menu(records)
        elif ch == "2":
            doctor_menu(records)
        elif ch == "3":
            auditor_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

```

---

# Final exam checks

```text
HealthSecure
[✓] RSA key pair
[✓] RSA public-key encryption
[✓] RSA private-key decryption
[✓] SHA-256 over encrypted patient information
[✓] RSA signature with private key
[✓] RSA verification with public key
[✓] Doctor / Nurse / Admin RBAC
[✓] timestamps
[✓] encrypted persistent records
[✓] Nurse/Admin cannot decrypt
[✓] verification before plaintext display

AES + RSA + ElGamal
[✓] file creation
[✓] AES-128 file encryption
[✓] encrypted file stored
[✓] RSA-encrypted AES key stored
[✓] ElGamal authorization code
[✓] public/RSA values displayed
[✓] SHA-256 sender/receiver check
[✓] decrypt only after valid integrity
[✓] tampering demonstration
[✓] integrity failure prevents decryption

MediSecure
[✓] .txt input
[✓] user-provided AES key and IV
[✓] AES-CBC encryption/decryption
[✓] SHA-256 ciphertext hash
[✓] Patient RSA signature
[✓] filename/ciphertext/hash/signature/IV/timestamp storage
[✓] Patient / Doctor / Auditor RBAC
[✓] Doctor verifies before decrypting
[✓] Auditor cannot decrypt/view plaintext
```
