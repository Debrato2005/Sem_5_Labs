from math import gcd

message = input("Enter message: ")

p = int(input("Enter prime p: "))
q = int(input("Enter prime q: "))
e = int(input("Enter public exponent e: "))


# ---------------- KEY GENERATION ----------------

n = p * q
phi = (p - 1) * (q - 1)

if gcd(e, phi) != 1:
    raise ValueError("e must be coprime with phi(n)")


# Find private key d
d = pow(e, -1, phi)

print("Public key :", (n, e))
print("Private key:", (n, d))


# ---------------- ENCRYPTION ----------------

ciphertext = []

for char in message:
    m = ord(char)

    if m >= n:
        raise ValueError("n is too small for the message characters")

    # c = m^e mod n
    c = pow(m, e, n)

    ciphertext.append(c)

print("Ciphertext:", ciphertext)


# ---------------- DECRYPTION ----------------

plaintext = ""

for c in ciphertext:

    # m = c^d mod n
    m = pow(c, d, n)

    plaintext += chr(m)

print("Decrypted:", plaintext)