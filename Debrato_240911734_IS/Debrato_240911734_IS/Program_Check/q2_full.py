from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

text = "00112233445566778899AABBCCDDEEFF".encode()

key = bytes.fromhex(
    "000000000000000000000000000000000000000000000000"
)
iv = bytes.fromhex(
    "00000000000000000000000000000000"
)
if len(iv) != 16:
    raise ValueError("AES IV must be 16 bytes")
cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)
encrypted = cipher.encrypt(
    pad(text, AES.block_size)
)
print("aes_192 Ciphertext:", encrypted.hex())
cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)
decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)
print("Plaintext:", decrypted.decode())



print("next")

text = "00112233445566778899AABBCCDDEEFF".encode()
key = bytes.fromhex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
)
iv = bytes.fromhex(
    "00000000000000000000000000000000"
)
if len(iv) != 16:
    raise ValueError("AES IV must be 16 bytes")
cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)
encrypted = cipher.encrypt(
    pad(text, AES.block_size)
)
print("aes_256 Ciphertext:", encrypted.hex())
cipher = AES.new(
    key,
    AES.MODE_CBC,
    iv
)
decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)
print("Plaintext:", decrypted.decode())