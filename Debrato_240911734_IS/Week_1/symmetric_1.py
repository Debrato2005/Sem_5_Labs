# A cipher is a mathematical algorithm that converts readable data (plaintext)
# into unreadable data (ciphertext) using a key,
# and converts it back using the appropriate key.

# 1. Encrypt the message "I am learning information security" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)

# caesar/addition/shift cipher
# P = ord(ch) - ord('A')      # Convert ASCII to 0–25
# C = (P + key) % 26          # Apply Caesar cipher formula
# cipher = chr(C + ord('A'))  # Convert back to ASCII
# need to handle uppercase and lowercase separately

def caesar(ch, key):
    if 'A' <= ch <= 'Z':
        return chr((ord(ch) - ord('A') + key) % 26 + ord('A'))
    elif 'a' <= ch <= 'z':
        return chr((ord(ch) - ord('a') + key) % 26 + ord('a'))
    else:
        return ch


# not reqd like can just add -key in caesar_encrypt
# def caesar_decrypt(ch,key):
#     if 'A' <= ch<='Z':
#         return chr((ord(ch)-ord('A')-key)%26+ord('A'))
#     elif 'a' <= ch<='z':
#         return chr((ord(ch)-ord('a')-key)%26+ord('z'))
#     else:
#         return ch

text = input("Enter the plain text: ")
key_1 = int(input("Enter the key for caesar encryption: "))

# creating functions for encryption loop better can use same for decryption just -key
encrypted_text = ""
for ch in text:
    encrypted_text += caesar(ch, key_1)
decrypted_text = ""
for ch in encrypted_text:
    decrypted_text += caesar(ch, -key_1)
print(f"Plaintext is : {text}")
print(f"Encrypted text via caesar cipher is : {encrypted_text}")
print(f"Decrypted text via caesar cipher is : {decrypted_text}")
print()

# multiplicative cipher
# instead of adding we multiply
# to decrypt we can't simply divide we need multiplicative inverse
# not every key is valid ie must be coprime with 26

import math


def mmi(key):
    if math.gcd(key, 26) != 1:
        raise ValueError("Key has no multiplicaitve inverse")
    return pow(key, -1, 26)


def multiplicative(ch, key):
    if 'A' <= ch <= 'Z':
        return chr(((ord(ch) - ord('A')) * key) % 26 + ord('A'))
    elif 'a' <= ch <= 'z':
        return chr(((ord(ch) - ord('a')) * key) % 26 + ord('a'))
    else:
        return ch


def encrypt_decrypt(text, key):
    cipher = ""
    for ch in text:
        cipher += multiplicative(ch, key)
    return cipher


key_2 = int(input("Enter the key for multiplicative cipher: "))
inverse = mmi(key_2)
m_cipher = encrypt_decrypt(text, key_2)
m_text = encrypt_decrypt(m_cipher, inverse)
print(f"Encrypted text via multiplicative cipher is : {m_cipher}")
print(f"Decrypted text via multiplicative cipher is : {m_text}")
print()

# affine cipher
import math


def mmi(key):
    if math.gcd(key, 26) != 1:
        raise ValueError("Invalid key bcz no mmi")
    return pow(key, -1, 26)


def affine_encrypt(ch, a, b):
    if 'A' <= ch <= 'Z':
        return chr(((ord(ch) - ord('A')) * a + b) % 26 + ord('A'))
    elif 'a' <= ch <= 'z':
        return chr(((ord(ch) - ord('a')) * a + b) % 26 + ord('a'))
    else:
        return ch


def affine_decrypt(ch, inverse, b):  # needed
    if 'A' <= ch <= 'Z':
        return chr((((ord(ch) - ord('A')) - b) * inverse) % 26 + ord('A'))

    elif 'a' <= ch <= 'z':
        return chr((((ord(ch) - ord('a')) - b) * inverse) % 26 + ord('a'))

    else:
        return ch


def encrypt(text, a, b):
    cipher = ""
    for ch in text:
        cipher += affine_encrypt(ch, a, b)
    return cipher


def decrypt(text, a, b):
    inverse = mmi(a)
    plain = ""
    for ch in text:
        plain += affine_decrypt(ch, inverse, b)
    return plain


a = int(input("Enter the key_1 for affine encryption: "))
b = int(input("Enter the key_2 for affine encryption: "))
cipher = encrypt(text, a, b)
plain = decrypt(cipher, a, b)
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
#=============================================================================================================
# 2. Encrypt the message "the house is being sold tonight" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# • Vigenere cipher with key: "dollars"
# • Autokey cipher with key = 7
print()
print (text)
key=input("Enter the key for Vignere cipher:")
og_key=key
while len(key)<len(text):
    key+=f"{og_key}" #to prevent doubling of the key on every iterations
key=key[:len(text)]
def vignere_encrypt(ch, key_ch):
    # Convert key character into shift value
    if 'A' <= key_ch <= 'Z':
        shift = ord(key_ch) - ord('A')
    else:
        shift = ord(key_ch) - ord('a')

    # Encrypt uppercase letters
    if 'A' <= ch <= 'Z':
        return chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))

    # Encrypt lowercase letters
    elif 'a' <= ch <= 'z':
        return chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))

    # Leave spaces and punctuation unchanged
    else:
        return ch
def vignere_decrypt(ch, key_ch):
    # Convert key character into shift value
    if 'A' <= key_ch <= 'Z': #key with alphabets only
        shift = ord(key_ch) - ord('A')
    else:
        shift = ord(key_ch) - ord('a')

    # Decrypt uppercase letters
    if 'A' <= ch <= 'Z':
        return chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))

    # Decrypt lowercase letters
    elif 'a' <= ch <= 'z':
        return chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))

    # Leave spaces and punctuation unchanged
    else:
        return ch
# can have single function for enceyption decryption will implement in autokey
# Encryption
cipher = ""
for i in range(len(text)):
    cipher += vignere_encrypt(text[i], key[i])

# Decryption
plain = ""
for i in range(len(cipher)):
    plain += vignere_decrypt(cipher[i], key[i])
print(f"Key to be used : {key} ")
print(f"Vignere cipher is : {cipher}")
print(f"Vignere plain is : {plain}")
print()

# Caesar, Multiplicative, Vigenere and Autokey perform character-by-character
# transformation, so the same character-level function can be reused for both
# encryption and decryption by supplying the inverse key/shift:
#     Caesar         -> +key for encryption, -key for decryption
#     Multiplicative -> key for encryption, MMI(key) for decryption
#     Vigenere       -> +shift from current key character for encryption,
#                       -shift from current key character for decryption
#     Autokey        -> +shift for encryption, -shift for decryption
#
# However, Autokey still requires separate encrypt() and decrypt() routines
# because the keystream is generated differently during decryption (it is
# reconstructed dynamically from the recovered plaintext). Affine also requires
# a separate decryption function because its decryption formula differs from
# encryption (subtract additive key, then multiply by the modular inverse).

#AUTOKEY ENCRYPTION DECRYPTION
#ACTUALLY
# Note:
# The same character-level function is used for both encryption and decryption
# by changing the direction of the shift. This implementation generates the
# complete Autokey keystream during encryption and reuses it for decryption.
# In the actual Autokey cipher, the decryption keystream is reconstructed
# dynamically from the recovered plaintext, since the plaintext is not known
# beforehand.
#WRITE AUTOKEY AGAIN
key=input("Enter the key for autokey cipher:")
og_key=key
while len(key)<len(text):
    key+=text

key=key[:len(text)]
def autokey(ch,key_ch,decrypt= False):
    if not key_ch.isalpha():
        print("Invalid key character:", repr(key_ch))

    if 'A' <=key_ch<='Z' :
        shift=ord(key_ch)-ord('A')
    elif 'a' <=key_ch<='z' :
        shift=ord(key_ch)-ord('a')

    if decrypt:
        shift=-shift

    if 'A' <= ch <= 'Z':
        return chr((ord(ch)-ord('A')+shift) % 26 + ord('A'))
    elif 'a' <= ch <= 'z':
        return chr((ord(ch)-ord('a')+shift) % 26 + ord('a'))
    else :
        return ch
cipher = ""
for i in range(len(text)):
    cipher += autokey(text[i],key[i], 0)

plain = ""
for i in range(len(text)):
    plain += autokey(cipher[i],key[i], 1)

print(f"Key to be used : {key} ")
print(f"Autokey cipher is : {cipher}")
print(f"Autokey plain is : {plain}")
print()






# 3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The
# secret key can be made by filling the first and part of the second row with the word
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.


# 4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the following
# key:
# 𝐾 = [03 03 2 07]

# 5. John is reading a mystery book involving cryptography. In one part of the book, the author
# gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a shift
# cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave with
# "XVIEWYWI" engraved on it. John immediately found the actual meaning of the ciphertext.
# Identify the type of attack and plaintext

# 6. Use a brute-force attack to decipher the following message. Assume that you know it is an
# affine cipher and that the plaintext "ab" is enciphered to "GL":
# XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS


#Additional Exercises