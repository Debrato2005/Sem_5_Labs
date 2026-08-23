from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time


message=input("enter message:")
des_key=input("enter the key for des:")
aes_key=input("enter the key for aes:")

ITERATIONS = 100000


# ---------------- DES ----------------

des_data = pad(message, DES.block_size)

des = DES.new(des_key, DES.MODE_ECB)

start = time.perf_counter()
for _ in range(ITERATIONS):
    des_ciphertext = des.encrypt(des_data)
des_enc_time = (time.perf_counter() - start) / ITERATIONS


des = DES.new(des_key, DES.MODE_ECB)

start = time.perf_counter()
for _ in range(ITERATIONS):
    des_plaintext = des.decrypt(des_ciphertext)
des_dec_time = (time.perf_counter() - start) / ITERATIONS


# ---------------- AES-256 ----------------

aes_data = pad(message, AES.block_size)

aes = AES.new(aes_key, AES.MODE_ECB)

start = time.perf_counter()
for _ in range(ITERATIONS):
    aes_ciphertext = aes.encrypt(aes_data)
aes_enc_time = (time.perf_counter() - start) / ITERATIONS


aes = AES.new(aes_key, AES.MODE_ECB)

start = time.perf_counter()
for _ in range(ITERATIONS):
    aes_plaintext = aes.decrypt(aes_ciphertext)
aes_dec_time = (time.perf_counter() - start) / ITERATIONS


# ---------------- Results ----------------

print("DES Encryption :", des_enc_time * 1e6, "µs")
print("DES Decryption :", des_dec_time * 1e6, "µs")

print("AES Encryption :", aes_enc_time * 1e6, "µs")
print("AES Decryption :", aes_dec_time * 1e6, "µs")

print("\nDES decrypted:",
      unpad(des_plaintext, DES.block_size).decode())

print("AES decrypted:",
      unpad(aes_plaintext, AES.block_size).decode())