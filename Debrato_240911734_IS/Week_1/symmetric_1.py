# A cipher is a mathematical algorithm that converts readable data (plaintext)
# into unreadable data (ciphertext) using a key,
# and converts it back using the appropriate key.

# 1. Encrypt the message "I am learning information security" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)

#caesar/addition/shift cipher
# P = ord(ch) - ord('A')      # Convert ASCII to 0–25
# C = (P + key) % 26          # Apply Caesar cipher formula
# cipher = chr(C + ord('A'))  # Convert back to ASCII
#need to handle uppercase and lowercase separately

def caesar(ch,key):
    if 'A' <= ch<='Z':
        return chr((ord(ch)-ord('A')+key)%26+ord('A'))
    elif 'a' <= ch<='z':
        return chr((ord(ch)-ord('a')+key)%26+ord('a'))
    else:
        return ch
#not reqd like can just add -key in caesar_encrypt
# def caesar_decrypt(ch,key):
#     if 'A' <= ch<='Z':
#         return chr((ord(ch)-ord('A')-key)%26+ord('A'))
#     elif 'a' <= ch<='z':
#         return chr((ord(ch)-ord('a')-key)%26+ord('z'))
#     else:
#         return ch

text=input("Enter the plain text: ")
key_1=int(input("Enter the key for caesar encryption: "))

#creating functions for encryption loop better can use same for decryption just -key
encrypted_text=""
for ch in text:
    encrypted_text += caesar(ch,key_1)
decrypted_text=""
for ch in encrypted_text:
    decrypted_text += caesar(ch,-key_1)
print(f"Plaintext is : {text}")
print(f"Encrypted text via caesar cipher is : {encrypted_text}")
print(f"Decrypted text via caesar cipher is : {decrypted_text}")
print()

#multiplicative cipher
#instead of adding we multiply
#to decrypt we can't simply divide we need multiplicative inverse
#not every key is valid ie must be coprime with 26

import math
def mmi(key):
    if math.gcd(key,26)!=1:
        raise ValueError("Key has no multiplicaitve inverse")
    return pow(key,-1,26)

def multiplicative(ch,key):
    if 'A' <= ch <= 'Z':
        return chr(((ord(ch)-ord('A'))*key)%26 +ord('A'))
    elif 'a' <= ch <= 'z':
            return chr(((ord(ch)-ord('a'))*key)%26 +ord('a'))
    else:
        return ch

def encrypt_decrypt(text,key):
    cipher=""
    for ch in text:
        cipher+=multiplicative(ch,key)
    return cipher

key_2=int(input("Enter the key for multiplicative cipher: "))
inverse=mmi(key_2)
m_cipher=encrypt_decrypt(text,key_2)
m_text=encrypt_decrypt(m_cipher,inverse)
print(f"Encrypted text via multiplicative cipher is : {m_cipher}")
print(f"Decrypted text via multiplicative cipher is : {m_text}")
print()

#affine cipher
import math
def mmi(key):
    if math.gcd(key,26)!=1:
        raise ValueError("Invalid key bcz no mmi")
    return pow(key,-1,26)

def affine_encrypt(ch,a,b):
    if 'A'<=ch<='Z':
        return chr(((ord(ch)-ord('A'))*a+b)%26+ord('A'))
    elif 'a'<=ch<='z':
            return chr(((ord(ch)-ord('a'))*a+b)%26+ord('a'))
    else:
        return ch
    
def affine_decrypt(ch, inverse, b):#needed
    if 'A' <= ch <= 'Z':
        return chr((((ord(ch)-ord('A'))-b) * inverse) % 26 + ord('A'))

    elif 'a' <= ch <= 'z':
        return chr((((ord(ch)-ord('a'))-b) * inverse) % 26 + ord('a'))

    else:
        return ch

def encrypt(text,a,b):
    cipher="" 
    for ch in text:
        cipher+=affine_encrypt(ch,a,b)
    return cipher
def decrypt(text, a, b):
    inverse = mmi(a)
    plain = ""
    for ch in text:
        plain += affine_decrypt(ch, inverse, b)
    return plain

a=int(input("Enter the key_1 for affine encryption: "))
b=int(input("Enter the key_2 for affine encryption: "))
cipher=encrypt(text,a,b)
plain=decrypt(cipher,a,b)
print(f"Encrypted text via affine cipher is : {cipher}")
print(f"Decrypted text via affine cipher is : {plain}")
print()

# -------------------------------------------------------------------------------
# Key Learnings
# -------------------------------------------------------------------------------

# 1. Classical Ciphers
#    - Classical ciphers are symmetric encryption techniques where the same key
#      (or mathematically related keys) is used for both encryption and decryption.
#    - They operate on alphabetic characters by representing each letter as a
#      number from 0 to 25.

# 2. Caesar (Additive) Cipher
#    Encryption:
#        C = (P + k) mod 26

#    Decryption:
#        P = (C - k) mod 26

#    Learned:
#    - Characters are converted to numbers using ord().
#    - Encrypted numbers are converted back using chr().
#    - Modulo arithmetic wraps values within the alphabet.
#    - Decryption can be performed by encrypting again with the negative key.

# 3. Multiplicative Cipher
#    Encryption:
#        C = (P × k) mod 26

#    Decryption:
#        P = (C × k⁻¹) mod 26

#    Learned:
#    - Multiplication replaces addition.
#    - Division cannot be performed in modular arithmetic.
#    - Decryption requires the Modular Multiplicative Inverse (MMI) of the key.
#    - A key is valid only if gcd(key, 26) = 1.

# 4. Modular Multiplicative Inverse (MMI)
#    - MMI is a number that satisfies:
#          (key × inverse) mod 26 = 1
#    - Python's built-in function:
#          pow(key, -1, 26)
#      computes the modular inverse directly.
#    - If gcd(key, 26) ≠ 1, the inverse does not exist and decryption is
#      impossible.

# 5. Affine Cipher
#    Encryption:
#        C = (aP + b) mod 26

#    Decryption:
#        P = a⁻¹(C - b) mod 26

#    Learned:
#    - Affine Cipher combines Multiplicative and Caesar ciphers.
#    - Encryption performs multiplication followed by addition.
#    - Decryption reverses the operations:
#          1. Subtract additive key b.
#          2. Multiply by the modular inverse of a.
#    - The multiplicative key 'a' must be coprime with 26.
#    - The additive key 'b' can be any value from 0 to 25.

# 6. Python Concepts Practiced
#    - User-defined functions
#    - Code reusability
#    - Character encoding using ord() and chr()
#    - String traversal using for loops
#    - Modular arithmetic (%)
#    - math.gcd() for key validation
#    - pow(base, -1, modulus) for modular inverse
#    - Exception handling using ValueError

# Note:
# Caesar and Multiplicative ciphers require only one transformation function,
# since decryption is achieved by passing the inverse key
# (negative key for Caesar, Modular Multiplicative Inverse for Multiplicative).
# Affine Cipher requires a separate decryption function because decryption
# involves two operations in reverse order:
#     1. Subtract the additive key (b).
#     2. Multiply by the Modular Multiplicative Inverse of the multiplicative key (a).
# Hence, encryption and decryption formulas are different and cannot be handled
# by simply changing the key.