from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


message=input("enter message:")
key=input("enter the key:")

key_hex = (
    "1234567890ABCDEF"
    "1234567890ABCDEF"
    "1234567890ABCDEF"
)

key = bytes.fromhex(key_hex)

# Split 24-byte 3DES key into three DES keys
K1 = key[0:8]
K2 = key[8:16]
K3 = key[16:24]

data = pad(message.encode(), DES.block_size)


# ---------------- ENCRYPTION ----------------
# 3DES EDE:
# Encrypt K1 -> Decrypt K2 -> Encrypt K3

step1 = DES.new(K1, DES.MODE_ECB).encrypt(data)

step2 = DES.new(K2, DES.MODE_ECB).decrypt(step1)

ciphertext = DES.new(K3, DES.MODE_ECB).encrypt(step2)

print("Ciphertext:", ciphertext.hex().upper())


# ---------------- DECRYPTION ----------------
# Reverse:
# Decrypt K3 -> Encrypt K2 -> Decrypt K1

step1 = DES.new(K3, DES.MODE_ECB).decrypt(ciphertext)

step2 = DES.new(K2, DES.MODE_ECB).encrypt(step1)

plaintext = DES.new(K1, DES.MODE_ECB).decrypt(step2)

plaintext = unpad(
    plaintext,
    DES.block_size
).decode()

print("Decrypted:", plaintext)