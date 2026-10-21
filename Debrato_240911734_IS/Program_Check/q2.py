#implement the standard aes algo specified in FIPS 197 FOR THE FOLLOWING FIXED INPUT FOR THE ENCRYPTION.
#print encryption steps of each round
#plaintxt= no padding
#MODE OF OPERATION:CBC
#initialization vector is 00000000000000000000000000000000
#case a:aes 192: 24 bytes of 00
#case b:aes 256: 32 bytes of FF



from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
text = "00112233445566778899AABBCCDDEEFF"
key = bytes.fromhex("000000000000000000000000000000000000000000000000")
if len(key) != 24:
    raise ValueError("AES-192 requires 24 bytes")
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)
print("Ciphertext:", encrypted.hex())
cipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)
print("Plaintext:", decrypted.decode())

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
text = "00112233445566778899AABBCCDDEEFF"
key = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
if len(key) != 32:
    raise ValueError("AES-256 requires 32 bytes")
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(
    pad(text.encode(), AES.block_size)
)
print("Ciphertext:", encrypted.hex())
cipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(
    cipher.decrypt(encrypted),
    AES.block_size
)
print("Plaintext:", decrypted.decode())


