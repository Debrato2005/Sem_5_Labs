# IS Midsem Scenario Programming Guide

This file is a **scenario-construction guide** for the `Sem_5_Labs/Debrato_240911734_IS/midsems` material.

It is intended for questions that combine multiple lab components into one program, such as:

- hospital / healthcare record systems
- AES + RSA + ElGamal hybrid security
- SHA-256 integrity verification
- RSA digital signatures
- RBAC roles such as Doctor / Nurse / Admin
- file storage and timestamps
- tampering demonstrations
- "verify first, decrypt only if valid" flows

The main exam skill is **not writing a new cryptosystem from scratch**. It is recognizing the required components and assembling the correct blocks in the correct order.

---

# 1. Where each component already exists in the GitHub `midsems` folder

| Requirement in a scenario | Main source file |
|---|---|
| AES / DES / 3DES, CBC/ECB/CTR, IV, padding | `Lab_2_Advanced_Symmetric_Key_Ciphers.md` |
| RSA encryption/decryption, OAEP, key generation | `Lab_3_Asymmetric_Key_Ciphers.md` |
| ElGamal encryption/decryption formulas | `Lab_3_Asymmetric_Key_Ciphers.md` |
| Hybrid RSA + symmetric encryption concepts | `Lab_3_Asymmetric_Key_Ciphers.md` |
| Key management, timestamps, logs | `Lab_4_Advanced_Asymmetric_Key_Cryptography (1).md` |
| RBAC / access restrictions | `Lab_4_Advanced_Asymmetric_Key_Cryptography (1).md` |
| SHA-256 and file integrity comparison | `Lab_5_Hashing.md` |
| RSA digital signatures and verification | `Lab_6_Digital_Signatures.md` |
| Tampering + verify-before-decrypt pattern | `Lab_6_Digital_Signatures.md` |
| Common imports / exam-generation prompts | `download.md` |

The lab manual itself explicitly warns that exam questions may be **variations and combinations** of the individual lab exercises. Therefore these scenario questions should be treated as compositions of the already-covered components.

---

# 2. First decode the question into security operations

Before writing code, rewrite the question into an execution sequence.

Example:

```text
INPUT / FILE
    ↓
ENCRYPT
    ↓
HASH CIPHERTEXT
    ↓
SIGN HASH
    ↓
STORE CIPHERTEXT + METADATA
    ↓
ROLE CHECK
    ↓
RECOMPUTE HASH
    ↓
VERIFY SIGNATURE
    ↓
ONLY IF BOTH VALID:
    DECRYPT
```

For hybrid encryption:

```text
FILE
  ↓
AES encrypt file
  ↓
AES ciphertext
  ├── SHA-256
  └── stored in encrypted file

AES key
  ↓
RSA public-key encryption
  ↓
encrypted AES key

authorization code
  ↓
ElGamal encryption
  ↓
(c1, c2)
```

This sequencing is often more important than the individual code blocks.

---

# 3. Core imports

Use only what the question needs.

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from datetime import datetime
import hashlib
import json
from math import gcd
```

Do **not** use obsolete APIs such as:

```python
RSA_key.encrypt(...)
RSA_key.decrypt(...)
ElGamal.encrypt(...)
ElGamal.decrypt(...)
```

Use `PKCS1_OAEP` for RSA encryption/decryption and textbook `pow()` formulas for ElGamal.

---

# 4. Universal data conversions

Most crypto bugs in the exam come from mixing `str`, `bytes`, hex strings and integers.

```python
text = input("Text: ")
data = text.encode()              # str -> bytes
text2 = data.decode()             # bytes -> str

h = data.hex()                    # bytes -> hex string
data2 = bytes.fromhex(h)          # hex string -> bytes

n = int(input("Integer: "))       # input -> integer
```

When storing binary values in JSON, convert them to hex first.

```python
record = {
    "ciphertext": ct.hex(),
    "iv": iv.hex(),
    "signature": sig.hex()
}
```

When reading:

```python
ct = bytes.fromhex(record["ciphertext"])
iv = bytes.fromhex(record["iv"])
sig = bytes.fromhex(record["signature"])
```

---

# 5. Timestamp component

```python
from datetime import datetime

timestamp = datetime.now().isoformat(timespec="seconds")
print(timestamp)
```

Store this with every record or verification event when the scenario asks for timestamps.

---

# 6. Simple file handling

## Read plaintext file

```python
path = input("Input file: ")
data = open(path, "rb").read()
```

## Write plaintext / binary data

```python
open("encrypted.bin", "wb").write(ct)
```

## Write text file

```python
open("message.txt", "w").write(input("Content: "))
```

## Read JSON records

```python
try:
    records = json.load(open("records.json"))
except (FileNotFoundError, json.JSONDecodeError):
    records = []
```

## Save JSON records

```python
json.dump(records, open("records.json", "w"), indent=2)
```

---

# 7. AES-128 CBC component

Use this when a scenario asks for AES-128 and an IV.

AES-128 key = **16 bytes**  
AES block / CBC IV = **16 bytes**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = input("AES-128 key (16 chars): ").encode()
iv = input("IV (16 chars): ").encode()

if len(key) != 16:
    raise ValueError("AES-128 key must be exactly 16 bytes")
if len(iv) != 16:
    raise ValueError("AES CBC IV must be exactly 16 bytes")

data = input("Plaintext: ").encode()

ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))

pt = unpad(
    AES.new(key, AES.MODE_CBC, iv).decrypt(ct),
    16
)

print("Ciphertext:", ct.hex())
print("Decrypted:", pt.decode())
```

If the IV is supposed to be generated:

```python
iv = get_random_bytes(16)
```

Never reuse a fixed IV in a real system, but follow the exam wording if the IV is explicitly supplied.

---

# 8. AES file encryption component

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

src = input("Source file: ")
enc_file = input("Encrypted output file: ")

key = input("AES-128 key (16 chars): ").encode()
iv = input("IV (16 chars): ").encode()

if len(key) != 16 or len(iv) != 16:
    raise ValueError("Key and IV must be 16 bytes")

data = open(src, "rb").read()

ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))
open(enc_file, "wb").write(ct)

recovered = unpad(
    AES.new(key, AES.MODE_CBC, iv).decrypt(ct),
    16
)
```

---

# 9. SHA-256 component

## Using hashlib

```python
import hashlib

h = hashlib.sha256(data).hexdigest()
print("SHA-256:", h)
```

## Using PyCryptodome

Use this if the same hash must also be signed:

```python
from Crypto.Hash import SHA256

h = SHA256.new(data)
print("SHA-256:", h.hexdigest())
```

For an encrypted record:

```python
h = SHA256.new(ciphertext)
```

If the question says **hash the encrypted message**, do not hash the plaintext.

---

# 10. Sender / receiver integrity comparison

```python
sender_hash = hashlib.sha256(ct).hexdigest()

received_ct = ct
receiver_hash = hashlib.sha256(received_ct).hexdigest()

if sender_hash == receiver_hash:
    print("Integrity verified")
else:
    print("Integrity failed")
```

Critical order:

```text
compare hashes
        ↓
if valid
        ↓
decrypt
```

If the question explicitly says not to decrypt after failure, the decryption code must be inside the success branch.

---

# 11. Tampering component

Modify one byte of the ciphertext:

```python
tampered = bytearray(ct)
tampered[0] ^= 1
tampered = bytes(tampered)
```

Then:

```python
tampered_hash = hashlib.sha256(tampered).hexdigest()

if tampered_hash != sender_hash:
    print("Integrity failed - ciphertext was modified")
```

This is safer than trying to modify a printable hex character and then accidentally producing malformed data.

---

# 12. RSA key generation

```python
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
public_key = key.publickey()

print(public_key.export_key().decode())
```

Save keys if required:

```python
open("doctor_private.pem", "wb").write(key.export_key())
open("doctor_public.pem", "wb").write(public_key.export_key())
```

Load them:

```python
private_key = RSA.import_key(open("doctor_private.pem", "rb").read())
public_key = RSA.import_key(open("doctor_public.pem", "rb").read())
```

---

# 13. RSA OAEP encryption/decryption

```python
from Crypto.Cipher import PKCS1_OAEP

ct = PKCS1_OAEP.new(public_key).encrypt(data)
pt = PKCS1_OAEP.new(private_key).decrypt(ct)
```

Rule:

```text
PUBLIC key  -> encrypt
PRIVATE key -> decrypt
```

RSA can only encrypt a limited amount of data directly. For short exam records this may work. For long files, use hybrid encryption:

```text
AES encrypts data
RSA encrypts AES key
```

---

# 14. RSA encrypt the AES key

This is the correct block for the AES + RSA hybrid hospital question.

```python
rsa = RSA.generate(2048)
rsa_public = rsa.publickey()

encrypted_aes_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)

open("encrypted_aes_key.bin", "wb").write(encrypted_aes_key)
```

Recover:

```python
aes_key = PKCS1_OAEP.new(rsa).decrypt(encrypted_aes_key)
```

---

# 15. RSA digital signature

Rule:

```text
PRIVATE key -> sign
PUBLIC key  -> verify
```

Sign the ciphertext hash:

```python
h = SHA256.new(ct)
signature = pkcs1_15.new(private_key).sign(h)
```

Verify:

```python
try:
    pkcs1_15.new(public_key).verify(SHA256.new(ct), signature)
    signature_ok = True
except (ValueError, TypeError):
    signature_ok = False
```

Do not manually "decrypt a signature" when PyCryptodome signature APIs are available.

---

# 16. Combined integrity + authenticity gate

This is the most reusable pattern in HealthSecure / MediSecure style questions.

```python
stored_hash = SHA256.new(ct).hexdigest()

current_hash = SHA256.new(ct).hexdigest()
integrity_ok = current_hash == stored_hash

try:
    pkcs1_15.new(public_key).verify(SHA256.new(ct), signature)
    signature_ok = True
except (ValueError, TypeError):
    signature_ok = False

if integrity_ok and signature_ok:
    print("Integrity verified")
    print("Signature valid")
    # decrypt HERE
else:
    print("Verification failed")
    print("Decryption not performed")
```

This prevents plaintext disclosure before verification succeeds.

---

# 17. ElGamal encryption component

Your GitHub notes correctly use textbook ElGamal equations because PyCryptodome does not expose a normal high-level ElGamal encrypt/decrypt API.

Given:

```text
prime p
generator g
private x
public y = g^x mod p
random k
message integer m
```

Encryption:

```python
p = int(input("p: "))
g = int(input("g: "))
x = int(input("private x: "))
k = int(input("random k: "))
m = int(input("authorization code as integer: "))

if not 0 <= m < p:
    raise ValueError("ElGamal message must satisfy 0 <= m < p")

y = pow(g, x, p)

c1 = pow(g, k, p)
c2 = m * pow(y, k, p) % p

print("Public key:", (p, g, y))
print("Encrypted authorization code:", (c1, c2))
```

Decryption:

```python
s = pow(c1, x, p)
m2 = c2 * pow(s, -1, p) % p
print("Recovered authorization code:", m2)
```

If the examiner gives `(p, g, y)` directly, take those as inputs and do not regenerate them.

---

# 18. RBAC component

The role determines which menu operations are reachable.

Example:

```python
permissions = {
    "doctor": {"create", "view", "verify", "decrypt"},
    "nurse":  {"view", "verify"},
    "admin":  {"summary", "verify"}
}

role = input("Role: ").lower()
action = input("Action: ").lower()

if action not in permissions.get(role, set()):
    print("Access denied")
else:
    print("Access granted")
```

For a real scenario program, do not merely print `Access denied`; structure the menus so restricted operations are not offered.

---

# 19. Role-specific menu structure

```python
while True:
    role = input("\nRole [doctor/nurse/admin/exit]: ").lower()

    if role == "exit":
        break

    if role == "doctor":
        print("1. Add record")
        print("2. View encrypted records")
        print("3. Verify and decrypt")

    elif role == "nurse":
        print("1. View encrypted records")
        print("2. Verify integrity/signature")

    elif role == "admin":
        print("1. View record ID/hash/timestamp")
        print("2. Verify signature")

    else:
        print("Invalid role")
```

The key security rule is that Nurse/Admin branches should never contain private-key decryption code.

---

# 20. Generic encrypted-record structure

```python
record = {
    "id": record_id,
    "ciphertext": ct.hex(),
    "hash": SHA256.new(ct).hexdigest(),
    "signature": signature.hex(),
    "timestamp": datetime.now().isoformat(timespec="seconds")
}
```

For AES scenarios add:

```python
"iv": iv.hex()
```

For hybrid scenarios add:

```python
"encrypted_key": encrypted_aes_key.hex()
```

Never store plaintext in the record when the question says the stored record is encrypted.

---

# 21. HealthSecure construction

Question pattern:

```text
Doctor:
- patient details
- RSA key pair
- RSA encrypt patient record
- SHA-256 encrypted record
- RSA sign
- store
- verify
- decrypt only after verification

Nurse:
- encrypted data + metadata
- hash verification
- signature verification
- NO plaintext / private key

Admin:
- ID + hash + timestamp
- signature verification
- NO ciphertext plaintext decryption
```

Correct execution:

```text
Doctor creates data
        ↓
serialize patient dictionary
        ↓
RSA-OAEP encrypt
        ↓
SHA-256(ciphertext)
        ↓
RSA private-key signature over SHA-256(ciphertext)
        ↓
store:
ID
ciphertext
hash
signature
timestamp
        ↓
verification request
        ↓
SHA-256(ciphertext) == stored hash?
        ↓
RSA public-key signature valid?
        ↓
BOTH TRUE
        ↓
RSA private-key decrypt
```

Patient dictionary:

```python
patient = {
    "name": input("Name: "),
    "age": input("Age: "),
    "gender": input("Gender: "),
    "blood_group": input("Blood group: "),
    "diagnosis": input("Diagnosis: ")
}

data = json.dumps(patient).encode()
```

Important limitation: RSA-OAEP directly encrypts only short messages. If the record becomes large, replace the direct RSA data encryption with AES data encryption + RSA-encrypted AES key.

---

# 22. MediSecure construction

Question pattern:

```text
Patient:
.txt file
AES + user key + user IV
SHA-256 ciphertext
RSA signature
store metadata

Doctor:
verify hash
verify signature
only then AES decrypt

Auditor:
filename/hash/timestamp
signature verify only
no plaintext
```

Correct execution:

```text
read .txt file
      ↓
validate AES key + IV
      ↓
AES-CBC encrypt
      ↓
hash ciphertext
      ↓
patient RSA private-key sign ciphertext hash
      ↓
store:
filename
ciphertext
hash
signature
IV
timestamp
      ↓
Doctor:
recompute hash
verify RSA public signature
      ↓
if both pass:
AES decrypt
```

Do not give the Auditor the AES key.

---

# 23. AES + RSA + ElGamal hospital construction

Question pattern:

```text
create file
AES-128 encrypt file
save encrypted file

RSA encrypt AES key
save encrypted AES key

ElGamal encrypt authorization code

display:
encrypted message
public key
RSA values

SHA-256 encrypted AES message

sender / receiver hash validation

if valid:
decrypt AES key
decrypt file

if invalid:
do not decrypt

tamper one ciphertext byte
show integrity failure
```

Correct architecture:

```text
PLAINTEXT FILE
      |
      | AES-128
      v
AES CIPHERTEXT --------------------> SHA-256 sender hash
      |                                    |
      |                                    v
      |                              receiver hash
      |                                    |
      |                           compare hashes first
      |
AES KEY
      |
      | RSA public key
      v
ENCRYPTED AES KEY

AUTHORIZATION CODE
      |
      | ElGamal
      v
(c1, c2)
```

Verification gate:

```python
if sender_hash == receiver_hash:
    recovered_key = PKCS1_OAEP.new(rsa_private).decrypt(encrypted_aes_key)
    plaintext = unpad(
        AES.new(recovered_key, AES.MODE_CBC, iv).decrypt(received_ct),
        16
    )
    print(plaintext.decode())
else:
    print("Integrity failed")
    print("Decryption not performed")
```

Tamper test:

```python
tampered = bytearray(ct)
tampered[0] ^= 1
tampered = bytes(tampered)

if hashlib.sha256(tampered).hexdigest() != sender_hash:
    print("Integrity failed as expected")
```

---

# 24. Master exam assembly template

Use this as a mental template rather than blindly copying it.

```python
# 1. imports

# 2. load/create keys

# 3. get role

# 4. get data / read file

# 5. encrypt data
#    AES or RSA according to question

# 6. if hybrid:
#    RSA encrypt AES key

# 7. if ElGamal requested:
#    encrypt authorization code with textbook equations

# 8. compute SHA-256 over EXACT object specified
#    usually ciphertext

# 9. if signature requested:
#    sign same object/hash with sender private key

# 10. store:
#     ciphertext
#     hash
#     signature
#     IV/nonce if needed
#     encrypted AES key if needed
#     timestamp
#     record ID

# 11. receiver / role view
#     expose only fields permitted by RBAC

# 12. verify integrity

# 13. verify authenticity/signature

# 14. ONLY if all required checks succeed:
#     decrypt and display plaintext

# 15. tampering test if requested
```

---

# 25. Common mistakes that will break these scenario questions

1. **Signing with the public key.**  
   Correct: private signs, public verifies.

2. **RSA encrypting with the private key for confidentiality.**  
   Correct: recipient public encrypts, recipient private decrypts.

3. **Hashing the plaintext when the question says hash ciphertext.**

4. **Decrypting before integrity/signature verification when the question explicitly requires verification first.**

5. **Giving Nurse/Admin/Auditor the private key or plaintext.**

6. **Using `RSA_key.encrypt()` / `RSA_key.decrypt()` instead of OAEP.**

7. **Calling nonexistent ElGamal high-level encryption APIs.**

8. **Wrong AES sizes.**
   - AES-128 key = 16 bytes
   - CBC IV = 16 bytes

9. **Forgetting `pad()` / `unpad()` with CBC.**

10. **Trying to JSON-serialize raw bytes.**  
    Store `.hex()` strings instead.

11. **Changing the encrypted file and then accidentally hashing the original ciphertext instead of the tampered ciphertext.**

12. **Using a broad `except:` for every failure.**  
    Prefer:
    ```python
    except (ValueError, TypeError):
    ```

13. **Direct RSA encryption of a large file.**  
    Use RSA only for the symmetric key and AES for the file.

14. **Storing the AES key in plaintext alongside ciphertext when the question expects RSA key wrapping.**

15. **Putting decryption functions inside Nurse/Admin menus even if they are not called.**  
    Keep role branches clean and obviously restricted.

---

# 26. Fast question-to-component lookup

If the question says:

```text
"AES-128"
```

use:

```python
AES.new(key, AES.MODE_CBC, iv)
```

with a 16-byte key.

If it says:

```text
"RSA encrypt"
```

use:

```python
PKCS1_OAEP.new(public_key).encrypt(data)
```

If it says:

```text
"RSA decrypt"
```

use:

```python
PKCS1_OAEP.new(private_key).decrypt(ct)
```

If it says:

```text
"SHA-256"
```

use:

```python
SHA256.new(data)
```

or:

```python
hashlib.sha256(data)
```

If it says:

```text
"digital signature"
```

use:

```python
pkcs1_15.new(private_key).sign(SHA256.new(data))
```

If it says:

```text
"verify signature"
```

use:

```python
pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
```

If it says:

```text
"ElGamal"
```

use:

```python
c1 = pow(g, k, p)
c2 = m * pow(y, k, p) % p
```

If it says:

```text
"RBAC"
```

build separate role menus / permission sets.

If it says:

```text
"timestamp"
```

use:

```python
datetime.now().isoformat(timespec="seconds")
```

If it says:

```text
"tamper"
```

use:

```python
tampered = bytearray(ct)
tampered[0] ^= 1
tampered = bytes(tampered)
```

---

# 27. Final pre-submission checklist

Before running the program, check:

```text
[ ] Did I use exactly the requested algorithms?
[ ] Did I take supplied question values through input()?
[ ] Are generated crypto values generated only where appropriate?
[ ] Are AES key and IV lengths correct?
[ ] Is CBC plaintext padded and decrypted data unpadded?
[ ] Is RSA encryption OAEP-based?
[ ] Is the hash computed over the exact required object?
[ ] Does private key sign and public key verify?
[ ] Does public key encrypt and private key decrypt?
[ ] Does ElGamal use correct modular arithmetic?
[ ] Are ciphertext/signature/IV converted correctly for storage?
[ ] Are timestamps present?
[ ] Does each role see only authorized data?
[ ] Is private-key access restricted?
[ ] Does verification happen before conditional decryption?
[ ] Does tampering produce failure?
[ ] On verification failure, is decryption skipped?
```

---

# 28. GitHub source paths

Repository:

`https://github.com/Debrato2005/Sem_5_Labs`

Primary folder:

`Debrato_240911734_IS/midsems/`

Use these files while practicing:

```text
Lab_2_Advanced_Symmetric_Key_Ciphers.md
Lab_3_Asymmetric_Key_Ciphers.md
Lab_4_Advanced_Asymmetric_Key_Cryptography (1).md
Lab_5_Hashing.md
Lab_6_Digital_Signatures.md
download.md
```

The key idea is to practice **assembling these blocks**, because the midsem-style problems combine the labs rather than staying within one isolated exercise.
