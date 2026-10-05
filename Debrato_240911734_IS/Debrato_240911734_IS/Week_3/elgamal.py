import secrets

message = input("Enter message: ")

p = int(input("Enter prime p: "))
g = int(input("Enter generator g: "))
h = int(input("Enter public key h: "))
x = int(input("Enter private key x: "))


# Verify public/private key pair
if h != pow(g, x, p):
    raise ValueError("Invalid key pair: h must equal g^x mod p")


# ---------------- ENCRYPTION ----------------

ciphertext = []

for byte in message.encode():

    if byte >= p:
        raise ValueError("p must be larger than every message byte")

    # Random ephemeral key
    k = secrets.randbelow(p - 2) + 1

    # c1 = g^k mod p
    c1 = pow(g, k, p)

    # s = h^k mod p
    s = pow(h, k, p)

    # c2 = m * s mod p
    c2 = (byte * s) % p

    ciphertext.append((c1, c2))


print("\nCiphertext:")
print(ciphertext)


# ---------------- DECRYPTION ----------------

decrypted = []

for c1, c2 in ciphertext:

    # s = c1^x mod p
    s = pow(c1, x, p)

    # Modular inverse of s
    s_inverse = pow(s, -1, p)

    # m = c2 * s^-1 mod p
    m = (c2 * s_inverse) % p

    decrypted.append(m)


plaintext = bytes(decrypted).decode()

print("\nDecrypted:", plaintext)