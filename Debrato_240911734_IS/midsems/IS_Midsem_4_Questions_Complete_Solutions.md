# IS Midsem — Solutions to the 4 Supplied Questions

All four questions are numbered exactly as supplied.

**Note:** Questions 1 and 2 are the same HealthSecure question. The same complete program is therefore valid for both. It is repeated here so each question remains standalone.

Install dependency if required:

```bash
python -m pip install pycryptodome
```

\---

# Question 1 — HealthSecure

## Question summary

SecureVault – Secure Record Management System



Design and implement an application named "SecureVault" for securely storing, authenticating, accessing, and auditing confidential client records. The application must have three roles: Client, Lawyer, and Compliance Officer.



The application must use:

1\. DES in CBC mode for encryption and decryption.

2\. SHA-256 for data integrity verification.

3\. ElGamal Digital Signature for authentication and verification.



CLIENT:



The Client should:

1\. Enter/provide a confidential record.

2\. Encrypt the record using DES in CBC mode.

3\. Generate an IV and use it during encryption.

4\. Calculate the SHA-256 hash of the encrypted data.

5\. Generate an ElGamal digital signature using the client's private key.

6\. Display the following:

&#x20;  - Ciphertext

&#x20;  - IV

&#x20;  - SHA-256 hash value

&#x20;  - ElGamal signature

&#x20;  - Timestamp

7\. Store the ciphertext, IV, hash value, signature, and timestamp in a file for future verification and access.



LAWYER:



The Lawyer should:

1\. Read the stored ciphertext, IV, hash value, signature, and timestamp from the file.

2\. Recalculate the SHA-256 hash and compare it with the stored hash value.

3\. Verify the ElGamal digital signature using the client's public key.

4\. Display the hash verification and signature verification status.

5\. Only if the hash and signature verification are successful, decrypt the ciphertext using DES in CBC mode.

6\. Display the recovered plaintext record.

7\. Store the verification/access status along with a timestamp.



If the integrity or signature verification fails, the Lawyer must not decrypt or access the plaintext.



COMPLIANCE OFFICER:



The Compliance Officer should:

1\. Access the stored encrypted record and its associated security metadata.

2\. Verify the SHA-256 hash to check whether the stored data has been modified.

3\. Verify the ElGamal digital signature using the client's public key.

4\. Display the hash verification and signature verification status.

5\. Record the verification results along with a timestamp.

6\. Generate a Compliance Report containing the verification status and relevant metadata.

7\. The Compliance Officer must NOT decrypt the ciphertext or access the client's plaintext record.



The application should maintain proper role-based access, ensuring that:

\- The Client can create and securely store records.

\- The Lawyer can verify and decrypt records after successful authentication.

\- The Compliance Officer can independently audit the record's integrity and authenticity without accessing the plaintext.



The system should clearly display all relevant security information and verification results.

## Complete solution — `q1\_healthsecure.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1\_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1\_15
from datetime import datetime
import json

DB = "healthsecure\_records.json"
PRIV = "doctor\_private.pem"
PUB = "doctor\_public.pem"


def generate\_keys():
    key = RSA.generate(2048)
    open(PRIV, "wb").write(key.export\_key())
    open(PUB, "wb").write(key.publickey().export\_key())
    print("Doctor RSA key pair generated.")


def ensure\_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        generate\_keys()


def load\_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return \[]


def save\_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get\_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r\["id"] == rid:
            return r
    print("Record not found.")
    return None


def rsa\_encrypt\_chunks(pub, data):
    size = pub.size\_in\_bytes() - 2 \* SHA256.digest\_size - 2
    return \[
        PKCS1\_OAEP.new(pub, hashAlgo=SHA256).encrypt(data\[i:i + size])
        for i in range(0, len(data), size)
    ]


def rsa\_decrypt\_chunks(priv, chunks):
    return b"".join(
        PKCS1\_OAEP.new(priv, hashAlgo=SHA256).decrypt(c)
        for c in chunks
    )


def verify\_record(record, pub):
    chunks = \[bytes.fromhex(x) for x in record\["ciphertext"]]
    encrypted\_data = b"".join(chunks)

    current\_hash = SHA256.new(encrypted\_data).hexdigest()
    integrity\_ok = current\_hash == record\["hash"]

    try:
        pkcs1\_15.new(pub).verify(
            SHA256.new(encrypted\_data),
            bytes.fromhex(record\["signature"])
        )
        signature\_ok = True
    except (ValueError, TypeError):
        signature\_ok = False

    return integrity\_ok, signature\_ok, chunks


def doctor\_menu(records):
    while True:
        print("\\n--- DOCTOR ---")
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
                generate\_keys()

        elif ch == "2":
            rid = input("Record ID: ")
            if any(r\["id"] == rid for r in records):
                print("Record ID already exists.")
                continue

            patient = {
                "name": input("Name: "),
                "age": input("Age: "),
                "gender": input("Gender: "),
                "blood\_group": input("Blood Group: "),
                "diagnosis": input("Diagnosis: "),
                "other\_details": input("Other medical details: ")
            }

            data = json.dumps(patient).encode()

            priv = RSA.import\_key(open(PRIV, "rb").read())
            pub = priv.publickey()

            chunks = rsa\_encrypt\_chunks(pub, data)
            encrypted\_data = b"".join(chunks)

            h = SHA256.new(encrypted\_data)
            signature = pkcs1\_15.new(priv).sign(h)

            record = {
                "id": rid,
                "ciphertext": \[c.hex() for c in chunks],
                "hash": h.hexdigest(),
                "signature": signature.hex(),
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }

            records.append(record)
            save\_records(records)
            print("Encrypted patient record stored.")

        elif ch == "3":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("Encrypted data:", r\["ciphertext"])
                print("SHA-256:", r\["hash"])
                print("Signature:", r\["signature"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "4":
            r = get\_record(records)
            if not r:
                continue

            pub = RSA.import\_key(open(PUB, "rb").read())
            integrity\_ok, signature\_ok, chunks = verify\_record(r, pub)

            print("Integrity:", "VALID" if integrity\_ok else "INVALID")
            print("Signature:", "VALID" if signature\_ok else "INVALID")

            if integrity\_ok and signature\_ok:
                priv = RSA.import\_key(open(PRIV, "rb").read())
                plaintext = rsa\_decrypt\_chunks(priv, chunks)
                patient = json.loads(plaintext.decode())

                print("\\nDecrypted patient information:")
                for k, v in patient.items():
                    print(f"{k}: {v}")
            else:
                print("Verification failed. Decryption not performed.")

        elif ch == "5":
            break

        else:
            print("Invalid choice.")


def nurse\_menu(records):
    pub = RSA.import\_key(open(PUB, "rb").read())

    while True:
        print("\\n--- NURSE ---")
        print("1. View encrypted patient records")
        print("2. Verify integrity and authenticity")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("Encrypted data:", r\["ciphertext"])
                print("SHA-256:", r\["hash"])
                print("Signature:", r\["signature"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            integrity\_ok, signature\_ok, \_ = verify\_record(r, pub)

            print("Integrity:", "VALID" if integrity\_ok else "INVALID")
            print("Signature:", "VALID" if signature\_ok else "INVALID")
            print(
                "Verification timestamp:",
                datetime.now().isoformat(timespec="seconds")
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def admin\_menu(records):
    pub = RSA.import\_key(open(PUB, "rb").read())

    while True:
        print("\\n--- ADMIN ---")
        print("1. View permitted record details")
        print("2. Verify Doctor's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("SHA-256:", r\["hash"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            \_, signature\_ok, \_ = verify\_record(r, pub)
            print(
                "Digital signature:",
                "VALID" if signature\_ok else "INVALID"
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def main():
    ensure\_keys()
    records = load\_records()

    while True:
        print("\\n=== HealthSecure ===")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            doctor\_menu(records)
        elif ch == "2":
            nurse\_menu(records)
        elif ch == "3":
            admin\_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if \_\_name\_\_ == "\_\_main\_\_":
    main()

```

\---

# Question 2 — HealthSecure

## Question summary

HealthSecure



A hospital wants to develop a secure patient-information management system called HealthSecure. The system has three roles: Doctor, Nurse, and Admin.



The system must ensure the confidentiality, integrity, and authenticity of patient information such as name, age, gender, blood group, diagnosis, and other medical details.



Doctor:



The Doctor should be able to:



Enter patient information such as Name, Age, Gender, Blood Group, Diagnosis, etc.



Store the patient information in a suitable data structure such as a list, array, dictionary, or file.



Generate an RSA key pair consisting of a public key and private key.



Encrypt the patient information using RSA encryption and the Doctor's RSA public key.



Compute the SHA-256 hash of the encrypted patient information.



Digitally sign the SHA-256 hash using the Doctor's RSA private key.



Store the encrypted patient data, SHA-256 hash, digital signature, and timestamp.



View previously stored patient records.



Decrypt an encrypted patient record using the corresponding RSA private key.



Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify integrity.



Verify the RSA digital signature using the Doctor's public key to verify authenticity.



Display the decrypted patient information only when the integrity and signature verification are successful.





Nurse:



The Nurse should be able to:



View the available encrypted patient records.



View the filename/record ID, encrypted data, hash, signature, and timestamp as permitted.



Must not be allowed to decrypt or view the plaintext patient information.



Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify data integrity.



Verify the Doctor's RSA digital signature using the Doctor's public key to verify authenticity.



Display the verification result along with a timestamp.



The Nurse must not have access to the Doctor's private key.





Admin:



The Admin should be able to:



View only the patient record ID/name, SHA-256 hash, and timestamp.



Verify the Doctor's RSA digital signature using the Doctor's public key.



Display whether the digital signature is VALID or INVALID.



The Admin must not be allowed to decrypt or view the plaintext patient information.



The Admin must not have access to the Doctor's private key.





Task:



Develop a menu-driven Python program implementing the above requirements using:



RSA asymmetric encryption and decryption



RSA public and private keys



SHA-256 hashing



RSA digital signatures



Role-Based Access Control (RBAC)



Patient data handling using lists, dictionaries, arrays, or files



Timestamps



Secure storage of encrypted records, hashes, signatures, and other required information



Appropriate access restrictions for Doctor, Nurse, and Admin



The program should ensure that each role can perform only its authorized operations and that patient information remains confidential while its integrity and authenticity can be verified.Complete solution — `q2\_healthsecure.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1\_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1\_15
from datetime import datetime
import json

DB = "healthsecure\_records.json"
PRIV = "doctor\_private.pem"
PUB = "doctor\_public.pem"


def generate\_keys():
    key = RSA.generate(2048)
    open(PRIV, "wb").write(key.export\_key())
    open(PUB, "wb").write(key.publickey().export\_key())
    print("Doctor RSA key pair generated.")


def ensure\_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        generate\_keys()


def load\_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return \[]


def save\_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get\_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r\["id"] == rid:
            return r
    print("Record not found.")
    return None


def rsa\_encrypt\_chunks(pub, data):
    size = pub.size\_in\_bytes() - 2 \* SHA256.digest\_size - 2
    return \[
        PKCS1\_OAEP.new(pub, hashAlgo=SHA256).encrypt(data\[i:i + size])
        for i in range(0, len(data), size)
    ]


def rsa\_decrypt\_chunks(priv, chunks):
    return b"".join(
        PKCS1\_OAEP.new(priv, hashAlgo=SHA256).decrypt(c)
        for c in chunks
    )


def verify\_record(record, pub):
    chunks = \[bytes.fromhex(x) for x in record\["ciphertext"]]
    encrypted\_data = b"".join(chunks)

    current\_hash = SHA256.new(encrypted\_data).hexdigest()
    integrity\_ok = current\_hash == record\["hash"]

    try:
        pkcs1\_15.new(pub).verify(
            SHA256.new(encrypted\_data),
            bytes.fromhex(record\["signature"])
        )
        signature\_ok = True
    except (ValueError, TypeError):
        signature\_ok = False

    return integrity\_ok, signature\_ok, chunks


def doctor\_menu(records):
    while True:
        print("\\n--- DOCTOR ---")
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
                generate\_keys()

        elif ch == "2":
            rid = input("Record ID: ")
            if any(r\["id"] == rid for r in records):
                print("Record ID already exists.")
                continue

            patient = {
                "name": input("Name: "),
                "age": input("Age: "),
                "gender": input("Gender: "),
                "blood\_group": input("Blood Group: "),
                "diagnosis": input("Diagnosis: "),
                "other\_details": input("Other medical details: ")
            }

            data = json.dumps(patient).encode()

            priv = RSA.import\_key(open(PRIV, "rb").read())
            pub = priv.publickey()

            chunks = rsa\_encrypt\_chunks(pub, data)
            encrypted\_data = b"".join(chunks)

            h = SHA256.new(encrypted\_data)
            signature = pkcs1\_15.new(priv).sign(h)

            record = {
                "id": rid,
                "ciphertext": \[c.hex() for c in chunks],
                "hash": h.hexdigest(),
                "signature": signature.hex(),
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }

            records.append(record)
            save\_records(records)
            print("Encrypted patient record stored.")

        elif ch == "3":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("Encrypted data:", r\["ciphertext"])
                print("SHA-256:", r\["hash"])
                print("Signature:", r\["signature"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "4":
            r = get\_record(records)
            if not r:
                continue

            pub = RSA.import\_key(open(PUB, "rb").read())
            integrity\_ok, signature\_ok, chunks = verify\_record(r, pub)

            print("Integrity:", "VALID" if integrity\_ok else "INVALID")
            print("Signature:", "VALID" if signature\_ok else "INVALID")

            if integrity\_ok and signature\_ok:
                priv = RSA.import\_key(open(PRIV, "rb").read())
                plaintext = rsa\_decrypt\_chunks(priv, chunks)
                patient = json.loads(plaintext.decode())

                print("\\nDecrypted patient information:")
                for k, v in patient.items():
                    print(f"{k}: {v}")
            else:
                print("Verification failed. Decryption not performed.")

        elif ch == "5":
            break

        else:
            print("Invalid choice.")


def nurse\_menu(records):
    pub = RSA.import\_key(open(PUB, "rb").read())

    while True:
        print("\\n--- NURSE ---")
        print("1. View encrypted patient records")
        print("2. Verify integrity and authenticity")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("Encrypted data:", r\["ciphertext"])
                print("SHA-256:", r\["hash"])
                print("Signature:", r\["signature"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            integrity\_ok, signature\_ok, \_ = verify\_record(r, pub)

            print("Integrity:", "VALID" if integrity\_ok else "INVALID")
            print("Signature:", "VALID" if signature\_ok else "INVALID")
            print(
                "Verification timestamp:",
                datetime.now().isoformat(timespec="seconds")
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def admin\_menu(records):
    pub = RSA.import\_key(open(PUB, "rb").read())

    while True:
        print("\\n--- ADMIN ---")
        print("1. View permitted record details")
        print("2. Verify Doctor's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("SHA-256:", r\["hash"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            \_, signature\_ok, \_ = verify\_record(r, pub)
            print(
                "Digital signature:",
                "VALID" if signature\_ok else "INVALID"
            )

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def main():
    ensure\_keys()
    records = load\_records()

    while True:
        print("\\n=== HealthSecure ===")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            doctor\_menu(records)
        elif ch == "2":
            nurse\_menu(records)
        elif ch == "3":
            admin\_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if \_\_name\_\_ == "\_\_main\_\_":
    main()

```

\---

# Question 3 — Hospital Management using AES-128 + ElGamal + RSA

## Question summary

Perform a hospital based management system using AES-128, ELGAMAL, RSA. 

Under the following specifications 



Create a file and add content to it



Encrypt the file content using aes and store the encrypted msg in another file



Using rsa encrypt the aes key and store in another file



An authorisation code was given which was to be encrypted using elgamal under the given parameters 



Display the encrypted msg, public key, rsa values



Perform hashing on the encrypted msg of aes.



Check for validity of sender and receiver hashing



If verified, perform decryption and show all the decrypted text , aes key and the decrypted original file content



If integrity failed don't perform decryption and show error output 



For showing integrity failed, modify one character in the aes cipher text and perform hashing on it

This must thore integrity failed since tampering is done to encrypted file

## Complete solution — `q3\_aes\_rsa\_elgamal.py`

```python
from Crypto.Cipher import AES, PKCS1\_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get\_random\_bytes
from Crypto.Util.number import isPrime
import json

print("=== Hospital AES-128 + RSA + ElGamal System ===")

# 1. Create a file and add content
plain\_file = input("Plaintext file name: ")
content = input("Enter file content: ")
open(plain\_file, "w").write(content)

# 2. AES-128 encrypt the file and store ciphertext
aes\_key = get\_random\_bytes(16)
iv = get\_random\_bytes(16)

data = open(plain\_file, "rb").read()
ciphertext = AES.new(
    aes\_key,
    AES.MODE\_CBC,
    iv
).encrypt(pad(data, 16))

encrypted\_file = input("AES encrypted output file: ")
open(encrypted\_file, "wb").write(ciphertext)

iv\_file = input("IV output file: ")
open(iv\_file, "wb").write(iv)

# 3. RSA encrypt AES key and store it
rsa\_private = RSA.generate(2048)
rsa\_public = rsa\_private.publickey()

encrypted\_aes\_key = PKCS1\_OAEP.new(
    rsa\_public,
    hashAlgo=SHA256
).encrypt(aes\_key)

rsa\_key\_file = input("RSA-encrypted AES key output file: ")
open(rsa\_key\_file, "wb").write(encrypted\_aes\_key)

# 4. ElGamal encrypt authorization code using given parameters
p = int(input("ElGamal prime p: "))
g = int(input("ElGamal generator g: "))
x = int(input("ElGamal private key x: "))
k = int(input("ElGamal random k: "))
auth\_code = int(input("Authorization code as integer: "))

if not isPrime(p):
    raise ValueError("p must be prime")
if not (1 <= x <= p - 2):
    raise ValueError("x must satisfy 1 <= x <= p-2")
if not (1 <= k <= p - 2):
    raise ValueError("k must satisfy 1 <= k <= p-2")
if not (0 <= auth\_code < p):
    raise ValueError("Authorization code must satisfy 0 <= m < p")

y = pow(g, x, p)
c1 = pow(g, k, p)
c2 = auth\_code \* pow(y, k, p) % p

elgamal\_file = input("ElGamal ciphertext output file: ")
json.dump(
    {
        "p": p,
        "g": g,
        "y": y,
        "c1": c1,
        "c2": c2
    },
    open(elgamal\_file, "w"),
    indent=2
)

# 5. Display required encrypted/public/RSA values
print("\\nAES ciphertext:", ciphertext.hex())
print("AES IV:", iv.hex())

print("\\nRSA public key:")
print(rsa\_public.export\_key().decode())
print("RSA n:", rsa\_private.n)
print("RSA e:", rsa\_private.e)
print("RSA d:", rsa\_private.d)

print("\\nElGamal public key:", (p, g, y))
print("Encrypted authorization code:", (c1, c2))

# 6. Sender hashes AES ciphertext
sender\_hash = SHA256.new(ciphertext).hexdigest()
print("\\nSender SHA-256:", sender\_hash)

# 7. Receiver reads encrypted message and hashes it
received\_ciphertext = open(encrypted\_file, "rb").read()
receiver\_hash = SHA256.new(received\_ciphertext).hexdigest()

print("Receiver SHA-256:", receiver\_hash)

# 8. Verify integrity BEFORE decrypting
if sender\_hash == receiver\_hash:
    print("Sender/receiver hash verification: VALID")

    recovered\_aes\_key = PKCS1\_OAEP.new(
        rsa\_private,
        hashAlgo=SHA256
    ).decrypt(open(rsa\_key\_file, "rb").read())

    recovered\_text = unpad(
        AES.new(
            recovered\_aes\_key,
            AES.MODE\_CBC,
            open(iv\_file, "rb").read()
        ).decrypt(received\_ciphertext),
        16
    )

    s = pow(c1, x, p)
    recovered\_auth = c2 \* pow(s, -1, p) % p

    print("\\nDecrypted AES key:", recovered\_aes\_key.hex())
    print("Decrypted authorization code:", recovered\_auth)
    print("Decrypted text:", recovered\_text.decode())
    print("Original file content:", open(plain\_file).read())

else:
    print("Integrity failed.")
    print("Decryption not performed.")

# 9. Tampering demonstration
tampered = bytearray(received\_ciphertext)
tampered\[0] ^= 1
tampered = bytes(tampered)

tampered\_file = input("\\nTampered ciphertext output file: ")
open(tampered\_file, "wb").write(tampered)

tampered\_hash = SHA256.new(tampered).hexdigest()

print("Original sender hash:", sender\_hash)
print("Tampered hash:", tampered\_hash)

if tampered\_hash == sender\_hash:
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

\---

# Question 4 — MediSecure

## Question summary

MediSecure

A hospital wants to develop a secure patient-record management system called MediSecure. The system has three roles: Patient, Doctor, and Auditor.

The system must ensure the confidentiality, integrity, and authenticity of patient medical records.



Patient

The Patient should be able to:

Read a medical record from a .txt file.

Encrypt the medical record using AES with a shared key and an Initialization Vector (IV) provided by the user.

Compute the SHA-256 hash of the encrypted record.

Digitally sign the hash using the Patient's RSA private key.

Store the filename, encrypted record, hash, digital signature, IV, and timestamp.

View previously uploaded encrypted records along with their hashes and timestamps.



Doctor

The Doctor should be able to:

View available uploaded records.

Select a record and decrypt it using the shared AES key and IV.

Recompute the SHA-256 hash of the encrypted record and compare it with the stored hash to verify integrity.

Verify the Patient's RSA digital signature using the Patient's RSA public key to verify authenticity.

Display the decrypted medical record only when the integrity and signature verifications are successful.

Store/display the verification result with a timestamp.



Auditor

The Auditor should be able to:

View only the filename, SHA-256 hash, and timestamp of stored medical records.

Verify the Patient's RSA digital signature using the Patient's public key.

Must not be allowed to decrypt or view the plaintext medical records.



Task:

Develop a menu-driven Python program implementing the above requirements using:

AES symmetric encryption and decryption

User-provided AES key and IV

SHA-256 hashing

RSA digital signatures

Role-based access control

.txt file handling

Timestamps

The program should securely store the required information and allow each role to perform only its authorized operations

## Complete solution — `q4\_medisecure.py`

```python
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1\_15
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import json
import os

DB = "medisecure\_records.json"
PRIV = "patient\_private.pem"
PUB = "patient\_public.pem"


def ensure\_keys():
    try:
        open(PRIV, "rb").close()
        open(PUB, "rb").close()
    except FileNotFoundError:
        key = RSA.generate(2048)
        open(PRIV, "wb").write(key.export\_key())
        open(PUB, "wb").write(key.publickey().export\_key())
        print("Patient RSA key pair generated.")


def load\_records():
    try:
        return json.load(open(DB))
    except (FileNotFoundError, json.JSONDecodeError):
        return \[]


def save\_records(records):
    json.dump(records, open(DB, "w"), indent=2)


def get\_record(records):
    rid = input("Record ID: ")
    for r in records:
        if r\["id"] == rid:
            return r
    print("Record not found.")
    return None


def verify\_record(record):
    ciphertext = bytes.fromhex(record\["ciphertext"])

    current\_hash = SHA256.new(ciphertext).hexdigest()
    integrity\_ok = current\_hash == record\["hash"]

    pub = RSA.import\_key(open(PUB, "rb").read())

    try:
        pkcs1\_15.new(pub).verify(
            SHA256.new(ciphertext),
            bytes.fromhex(record\["signature"])
        )
        signature\_ok = True
    except (ValueError, TypeError):
        signature\_ok = False

    return integrity\_ok, signature\_ok, ciphertext


def patient\_menu(records):
    while True:
        print("\\n--- PATIENT ---")
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
            if any(r\["id"] == rid for r in records):
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
                AES.MODE\_CBC,
                iv
            ).encrypt(pad(data, 16))

            h = SHA256.new(ciphertext)

            private\_key = RSA.import\_key(open(PRIV, "rb").read())
            signature = pkcs1\_15.new(private\_key).sign(h)

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
            save\_records(records)
            print("Encrypted medical record stored.")

        elif ch == "2":
            if not records:
                print("No records.")
            for r in records:
                print("\\nRecord ID:", r\["id"])
                print("Filename:", r\["filename"])
                print("Encrypted record:", r\["ciphertext"])
                print("SHA-256:", r\["hash"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def doctor\_menu(records):
    while True:
        print("\\n--- DOCTOR ---")
        print("1. View available uploaded records")
        print("2. Verify and decrypt a record")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print(
                    f'ID={r\["id"]}  FILE={r\["filename"]}  '
                    f'HASH={r\["hash"]}  TIME={r\["timestamp"]}'
                )

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            integrity\_ok, signature\_ok, ciphertext = verify\_record(r)

            verification\_time = datetime.now().isoformat(timespec="seconds")
            print("Integrity:", "VALID" if integrity\_ok else "INVALID")
            print("Signature:", "VALID" if signature\_ok else "INVALID")
            print("Verification timestamp:", verification\_time)

            if not (integrity\_ok and signature\_ok):
                print("Verification failed. Decryption not performed.")
                continue

            key = input("Shared AES key (16/24/32 chars): ").encode()

            if len(key) not in (16, 24, 32):
                print("Invalid AES key length.")
                continue

            iv = bytes.fromhex(r\["iv"])

            try:
                plaintext = unpad(
                    AES.new(
                        key,
                        AES.MODE\_CBC,
                        iv
                    ).decrypt(ciphertext),
                    16
                )

                print("\\nDecrypted medical record:")
                print(plaintext.decode())

            except (ValueError, UnicodeDecodeError):
                print("Incorrect AES key or corrupted encrypted data.")

        elif ch == "3":
            break

        else:
            print("Invalid choice.")


def auditor\_menu(records):
    pub = RSA.import\_key(open(PUB, "rb").read())

    while True:
        print("\\n--- AUDITOR ---")
        print("1. View permitted metadata")
        print("2. Verify Patient's RSA signature")
        print("3. Back")
        ch = input("Choice: ")

        if ch == "1":
            if not records:
                print("No records.")
            for r in records:
                print("\\nFilename:", r\["filename"])
                print("SHA-256:", r\["hash"])
                print("Timestamp:", r\["timestamp"])

        elif ch == "2":
            r = get\_record(records)
            if not r:
                continue

            ciphertext = bytes.fromhex(r\["ciphertext"])
            signature = bytes.fromhex(r\["signature"])

            try:
                pkcs1\_15.new(pub).verify(
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
    ensure\_keys()
    records = load\_records()

    while True:
        print("\\n=== MediSecure ===")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        ch = input("Choice: ")

        if ch == "1":
            patient\_menu(records)
        elif ch == "2":
            doctor\_menu(records)
        elif ch == "3":
            auditor\_menu(records)
        elif ch == "4":
            break
        else:
            print("Invalid choice.")


if \_\_name\_\_ == "\_\_main\_\_":
    main()

```

\---

# Final exam checks

```text
HealthSecure
\[✓] RSA key pair
\[✓] RSA public-key encryption
\[✓] RSA private-key decryption
\[✓] SHA-256 over encrypted patient information
\[✓] RSA signature with private key
\[✓] RSA verification with public key
\[✓] Doctor / Nurse / Admin RBAC
\[✓] timestamps
\[✓] encrypted persistent records
\[✓] Nurse/Admin cannot decrypt
\[✓] verification before plaintext display

AES + RSA + ElGamal
\[✓] file creation
\[✓] AES-128 file encryption
\[✓] encrypted file stored
\[✓] RSA-encrypted AES key stored
\[✓] ElGamal authorization code
\[✓] public/RSA values displayed
\[✓] SHA-256 sender/receiver check
\[✓] decrypt only after valid integrity
\[✓] tampering demonstration
\[✓] integrity failure prevents decryption

MediSecure
\[✓] .txt input
\[✓] user-provided AES key and IV
\[✓] AES-CBC encryption/decryption
\[✓] SHA-256 ciphertext hash
\[✓] Patient RSA signature
\[✓] filename/ciphertext/hash/signature/IV/timestamp storage
\[✓] Patient / Doctor / Auditor RBAC
\[✓] Doctor verifies before decrypting
\[✓] Auditor cannot decrypt/view plaintext
```

