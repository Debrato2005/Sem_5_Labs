import os
import time
import statistics

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256, SHAKE128


# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------

FILE_SIZES = {
    "1 MB": 1 * 1024 * 1024,
    "10 MB": 10 * 1024 * 1024
}

REPEATS = 3
KEYGEN_REPEATS = 3


# ---------------------------------------------------------
# CREATE TEST FILES
# ---------------------------------------------------------

def create_test_file(filename, size):

    with open(filename, "wb") as file:
        file.write(os.urandom(size))


# ---------------------------------------------------------
# ECC KEY DERIVATION FUNCTION
# ---------------------------------------------------------

def ecc_kdf(shared_secret):

    # Convert ECDH shared secret into
    # a 32-byte = 256-bit AES key

    return SHAKE128.new(
        data=shared_secret + b"secure-file-transfer"
    ).read(32)


# =========================================================
# RSA-2048 HYBRID ENCRYPTION
# =========================================================

def rsa_encrypt(data, public_key):

    # Random AES-256 session key
    aes_key = get_random_bytes(32)

    # ---------------- AES-GCM ----------------

    nonce = get_random_bytes(12)

    aes_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = aes_cipher.encrypt_and_digest(data)

    # ---------------- RSA-OAEP ----------------
    # Encrypt only the AES key

    rsa_cipher = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256
    )

    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    return (
        encrypted_aes_key,
        nonce,
        tag,
        ciphertext
    )


def rsa_decrypt(package, private_key):

    encrypted_aes_key, nonce, tag, ciphertext = package

    # Recover AES session key using RSA private key
    rsa_cipher = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256
    )

    aes_key = rsa_cipher.decrypt(
        encrypted_aes_key
    )

    # Recover file
    aes_cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = aes_cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext


# =========================================================
# ECC P-256 HYBRID ENCRYPTION
# =========================================================

def ecc_encrypt(data, recipient_public_key):

    # Sender generates temporary ECC key
    ephemeral_private = ECC.generate(
        curve="P-256"
    )

    ephemeral_public = ephemeral_private.public_key()

    # ECDH:
    # sender temporary private key
    # +
    # recipient public key
    shared_key = key_agreement(
        eph_priv=ephemeral_private,
        static_pub=recipient_public_key,
        kdf=ecc_kdf
    )

    # ---------------- AES-GCM ----------------

    nonce = get_random_bytes(12)

    aes_cipher = AES.new(
        shared_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = aes_cipher.encrypt_and_digest(data)

    # Send sender's temporary public key
    # compressed P-256 public key = 33 bytes
    ephemeral_public_bytes = ephemeral_public.export_key(
        format="SEC1",
        compress=True
    )

    return (
        ephemeral_public_bytes,
        nonce,
        tag,
        ciphertext
    )


def ecc_decrypt(package, recipient_private_key):

    ephemeral_public_bytes, nonce, tag, ciphertext = package

    # Recover sender's temporary public key
    ephemeral_public = ECC.import_key(
        ephemeral_public_bytes,
        curve_name="P-256"
    )

    # Recipient computes same ECDH secret
    shared_key = key_agreement(
        static_priv=recipient_private_key,
        eph_pub=ephemeral_public,
        kdf=ecc_kdf
    )

    # ---------------- AES-GCM ----------------

    aes_cipher = AES.new(
        shared_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    plaintext = aes_cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return plaintext


# =========================================================
# TIMING FUNCTIONS
# =========================================================

def benchmark_key_generation(function, repeats):

    times = []
    key = None

    for _ in range(repeats):

        start = time.perf_counter()

        key = function()

        end = time.perf_counter()

        times.append(end - start)

    return statistics.mean(times), key


def benchmark_algorithm(
    algorithm,
    data,
    encrypt_function,
    decrypt_function
):

    encryption_times = []
    decryption_times = []

    package = None

    for _ in range(REPEATS):

        # ---------------- ENCRYPTION ----------------

        start = time.perf_counter()

        package = encrypt_function(data)

        end = time.perf_counter()

        encryption_times.append(end - start)

        # ---------------- DECRYPTION ----------------

        start = time.perf_counter()

        recovered = decrypt_function(package)

        end = time.perf_counter()

        decryption_times.append(end - start)

        # Verify correctness
        assert recovered == data

    encryption_time = statistics.mean(
        encryption_times
    )

    decryption_time = statistics.mean(
        decryption_times
    )

    size_mb = len(data) / (1024 * 1024)

    encryption_speed = size_mb / encryption_time
    decryption_speed = size_mb / decryption_time

    encrypted_size = sum(
        len(part)
        for part in package
    )

    overhead = encrypted_size - len(data)

    return {
        "algorithm": algorithm,
        "size": size_mb,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "encryption_speed": encryption_speed,
        "decryption_speed": decryption_speed,
        "overhead": overhead
    }


# =========================================================
# MAIN PROGRAM
# =========================================================

print("\n========== KEY GENERATION ==========\n")


# ---------------- RSA KEY GENERATION ----------------

rsa_keygen_time, rsa_private_key = benchmark_key_generation(
    lambda: RSA.generate(2048),
    KEYGEN_REPEATS
)

rsa_public_key = rsa_private_key.public_key()


# Simulate public key exchange:
# Receiver exports public key
rsa_public_data = rsa_public_key.export_key(
    format="DER"
)

# Sender imports it
rsa_received_public_key = RSA.import_key(
    rsa_public_data
)


# ---------------- ECC KEY GENERATION ----------------

ecc_keygen_time, ecc_private_key = benchmark_key_generation(
    lambda: ECC.generate(curve="P-256"),
    KEYGEN_REPEATS
)

ecc_public_key = ecc_private_key.public_key()


# Simulate public key exchange
ecc_public_data = ecc_public_key.export_key(
    format="DER"
)

ecc_received_public_key = ECC.import_key(
    ecc_public_data
)


print(
    f"RSA-2048 key generation : "
    f"{rsa_keygen_time * 1000:.3f} ms"
)

print(
    f"ECC P-256 key generation: "
    f"{ecc_keygen_time * 1000:.3f} ms"
)


# ---------------------------------------------------------
# KEY STORAGE
# ---------------------------------------------------------

print("\n========== KEY STORAGE ==========\n")

rsa_public_size = len(
    rsa_public_key.export_key(format="DER")
)

rsa_private_size = len(
    rsa_private_key.export_key(format="DER")
)

ecc_public_size = len(
    ecc_public_key.export_key(format="DER")
)

ecc_private_size = len(
    ecc_private_key.export_key(format="DER")
)

ecc_compressed_size = len(
    ecc_public_key.export_key(
        format="SEC1",
        compress=True
    )
)


print("RSA Public Key DER :", rsa_public_size, "bytes")
print("RSA Private Key DER:", rsa_private_size, "bytes")

print()

print("ECC Public Key DER :", ecc_public_size, "bytes")
print("ECC Private Key DER:", ecc_private_size, "bytes")
print("ECC Compressed Public Key:", ecc_compressed_size, "bytes")


# ---------------------------------------------------------
# FILE TESTING
# ---------------------------------------------------------

results = []

for name, size in FILE_SIZES.items():

    filename = f"test_{name.replace(' ', '_')}.bin"

    print(
        f"\nCreating {name} file..."
    )

    create_test_file(
        filename,
        size
    )

    with open(filename, "rb") as file:
        data = file.read()

    # ---------------- RSA ----------------

    rsa_result = benchmark_algorithm(
        "RSA-2048",
        data,

        lambda x: rsa_encrypt(
            x,
            rsa_received_public_key
        ),

        lambda x: rsa_decrypt(
            x,
            rsa_private_key
        )
    )

    results.append(rsa_result)


    # ---------------- ECC ----------------

    ecc_result = benchmark_algorithm(
        "ECC P-256",
        data,

        lambda x: ecc_encrypt(
            x,
            ecc_received_public_key
        ),

        lambda x: ecc_decrypt(
            x,
            ecc_private_key
        )
    )

    results.append(ecc_result)


# =========================================================
# RESULTS TABLE
# =========================================================

print("\n")
print("=" * 100)

print(
    f"{'Algorithm':<12}"
    f"{'Size':<10}"
    f"{'Enc Time(s)':<15}"
    f"{'Dec Time(s)':<15}"
    f"{'Enc MB/s':<15}"
    f"{'Dec MB/s':<15}"
    f"{'Overhead':<10}"
)

print("=" * 100)


for r in results:

    print(
        f"{r['algorithm']:<12}"
        f"{r['size']:<10.1f}"
        f"{r['encryption_time']:<15.6f}"
        f"{r['decryption_time']:<15.6f}"
        f"{r['encryption_speed']:<15.2f}"
        f"{r['decryption_speed']:<15.2f}"
        f"{r['overhead']:<10}"
    )


print("=" * 100)

print("\nAll decrypted files successfully matched the originals.")