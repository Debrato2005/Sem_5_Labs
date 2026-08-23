from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


message = input("Enter message: ").encode()


# ---------------- ECC KEY GENERATION ----------------

# Recipient's ECC private key
private_key = ECC.generate(curve="P-256")

# Recipient's ECC public key
public_key = private_key.public_key()


# ---------------- ENCRYPTION ----------------

# Sender generates temporary ECC key
sender_private = ECC.generate(curve="P-256")
sender_public = sender_private.public_key()


# KDF: convert ECDH shared secret into AES-256 key
def kdf(shared_secret):
    return SHA256.new(shared_secret).digest()


# Sender:
# sender private key + recipient public key
aes_key_encrypt = key_agreement(
    static_priv=sender_private,
    static_pub=public_key,
    kdf=kdf
)


# Encrypt using AES-GCM
nonce = get_random_bytes(12)

cipher = AES.new(
    aes_key_encrypt,
    AES.MODE_GCM,
    nonce=nonce
)

ciphertext, tag = cipher.encrypt_and_digest(message)

print("Ciphertext:", ciphertext.hex().upper())


# ---------------- DECRYPTION ----------------

# Recipient:
# recipient private key + sender public key
aes_key_decrypt = key_agreement(
    static_priv=private_key,
    static_pub=sender_public,
    kdf=kdf
)


cipher = AES.new(
    aes_key_decrypt,
    AES.MODE_GCM,
    nonce=nonce
)

plaintext = cipher.decrypt_and_verify(
    ciphertext,
    tag
)

print("Decrypted:", plaintext.decode())