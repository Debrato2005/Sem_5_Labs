from sympy import isprime, mod_inverse

# Generate two large prime numbers p and q
p = 61
q = 53

# Compute n
n = p * q

# Compute phi(n)
phi_n = (p - 1) * (q - 1)

# Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
e = 17

# Compute d such that d is the modular inverse of e modulo phi(n)
d = mod_inverse(e, phi_n)

# Convert the message to ASCII values
message = "hello"
ascii_values = [ord(char) for char in message]

# Encrypt each ASCII value using the public key (n, e)
ciphertext = [pow(value, e, n) for value in ascii_values]

# Decrypt each ciphertext value using the private key (n, d)
decrypted_ascii_values = [pow(value, d, n) for value in ciphertext]

# Convert the ASCII values back to characters
decrypted_message = ''.join(chr(value) for value in decrypted_ascii_values)

print("Original Message:", message)
print(ciphertext_msg)
print("Decrypted Message:", decrypted_message)