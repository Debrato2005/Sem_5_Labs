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

# can do in multiple ways
# can do in multiple ways# Using A-Z, a-z, and space as one alphabet gives 53 symbols, so modulo 53 is used.
def caesar(ch, key):
    if 'A' <= ch <= 'Z': # ' or " doesnt matter both same for strings in python
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
# def vignere_encrypt(ch, key_ch):
#     # Convert key character into shift value
#     if 'A' <= key_ch <= 'Z':
#         shift = ord(key_ch) - ord('A')
#     else:
#         shift = ord(key_ch) - ord('a')

#     # Encrypt uppercase letters
#     if 'A' <= ch <= 'Z':
#         return chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))

#     # Encrypt lowercase letters
#     elif 'a' <= ch <= 'z':
#         return chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))

#     # Leave spaces and punctuation unchanged
#     else:
#         return ch
# def vignere_decrypt(ch, key_ch):
#     # Convert key character into shift value
#     if 'A' <= key_ch <= 'Z': #key with alphabets only
#         shift = ord(key_ch) - ord('A')
#     else:
#         shift = ord(key_ch) - ord('a')

#     # Decrypt uppercase letters
#     if 'A' <= ch <= 'Z':
#         return chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))

#     # Decrypt lowercase letters
#     elif 'a' <= ch <= 'z':
#         return chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))

#     # Leave spaces and punctuation unchanged
#     else:
#         return ch
# 
# # Encryption
# cipher = ""
# for i in range(len(text)):
#     cipher += vignere_encrypt(text[i], key[i])

# # Decryption
# plain = ""
# for i in range(len(cipher)):
    # plain += vignere_decrypt(cipher[i], key[i])

# can have single function for encryption/decryption
def vigenere(ch, key_ch, decrypt=False):
    if 'A' <= key_ch <= 'Z': #key with alphabets only
        shift = ord(key_ch) - ord('A')
    else:
        shift = ord(key_ch) - ord('a')

    if decrypt:
        shift = -shift

    #encryption/decryption
    if 'A' <= ch <= 'Z':
        return chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
    elif 'a' <= ch <= 'z':
        return chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
    else:
        return ch

# Encryption
cipher = ""
for i in range(len(text)):
    cipher += vigenere(text[i], key[i])

# Decryption
plain = ""
for i in range(len(cipher)):
    plain += vigenere(cipher[i], key[i], decrypt=True)
    
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

# Encryption:
# plaintext → generate key stream → ciphertext

# Decryption:
# ciphertext → recover plaintext → use recovered plaintext to extend key

key=input("Enter the letter/key for autokey cipher:")
og_key=key
#for encryption
#remember need to handle spaces while building key from plaintext
#in vignere as well we used key without spaces and while encrypting we keep space as it is
#traditonally we can strip spaces but i  will try to implement where we will ignorewe them

for i in range(len(text)):
    if text[i].isalpha():
        key+=text[i]

print(f"Plaintext               : {text}")
print()
print(f"Key used for encryption : {key}")
#we can either do char by char or have the loop inside the function and return cipher directly
def autokey_encrypt(ch,key_ch):
    if ("A"<=key_ch<="Z"):
        shift=ord(key_ch)-ord("A")
    elif ("a"<=key_ch<="z"):
           shift=ord(key_ch)-ord("a")

    if "A"<=ch<="Z":
        return chr(((ord(ch)-ord("A"))+shift)%26+ord("A"))
    elif "a"<=ch<="z":
        return chr(((ord(ch)-ord("a"))+shift)%26+ord("a"))
    else:
        return ch
cipher = ""
key_index = 0
for i in range(len(text)):
    # Space/punctuation:
    # preserve it and DON'T consume a key character
    if not text[i].isalpha():
        cipher += text[i]
        continue #skips rest of block and continues loop
    cipher += autokey_encrypt(text[i], key[key_index])
    # Move through the cryptographic key only
    key_index += 1
print(f"Autokey cipher: {cipher}")
print()

#decryption
def autokey_decrypt(text,initial_key):
    plain=""
    key_ch=initial_key
    key_decr=initial_key

    for i in range(len(text)):
#can do using continue as well 
        # if not text[i].isalpha():
        #     plain += text[i]
        #     continue

        # Convert key character into shift
        if ("A"<=key_ch<="Z"):
            shift=ord(key_ch)-ord("A")
        elif ("a"<=key_ch<="z"):
            shift=ord(key_ch)-ord("a")

        #decryption
        if "A"<=text[i]<="Z":
            ch=chr(((ord(text[i])-ord("A"))-shift)%26+ord("A"))
        elif "a"<=text[i]<="z":
                    ch=chr(((ord(text[i])-ord("a"))-shift)%26+ord("a"))
        else:
            ch=text[i]
        plain+=ch
        if ch.isalpha():
            key_decr+=ch
            key_ch=ch #works bcz if space occurs we anyways dont want to use the key and use it in the next non space try
    return plain,key_decr

plain, key_decr = autokey_decrypt(cipher, og_key)
print(f"Key used for decryption: {key_decr}")
print(f"Autokey decipher is      : {plain}" )  
        


# 3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The
# secret key can be made by filling the first and part of the second row with the word
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.

# Playfair Cipher:
# The Playfair cipher is a digraph substitution cipher that encrypts
# two plaintext characters at a time using a 5x5 key matrix.
# Since the English alphabet contains 26 letters but the matrix has
# only 25 positions, I and J are traditionally combined into one cell.
# During preprocessing, J is therefore treated as I
print()
text = input("Enter the plaintext for plalyfair: ")
key = input("Enter the key: ")

def create_matrix(key):
    alphabet="ABCDEFGHIKLMNOPQRSTUVWXYZ" #no J
#cannot mathematically know whether the original was I or j
    key=key.upper()
    ke="".join(ch for ch in key if ch.isalpha())
    key=key.replace("J","I")

    sequence=""

    for ch in key:
        if ch not in sequence:
            sequence+=ch

    matrix=[]

    for i in range(0,25,5):
        matrix.append(sequence[i:i+5])

    return matrix

matrix=create_matrix(key)
print()
print("Playfair Matrix")
for row in matrix:
    print(" ".join(row))

def prepare_text(text):
    text="".join(ch.ipper() for ch in text if ch.isalpha())
    text=text.replace("j","I")

    prepared=""
    i=0

    while i<len(text):#checking if pasired up or not
        first=text[i]

        if i+1==len(text):
            prepared+=first + "X"
            i += 1
        else:
            second = text[i + 1]

            if first==second:
                prepared+=first+"X"
                i+=1

            else:
                prepared+=first+second
                i+=2

    return prepared

prepared_text = prepare_text(text)
print(f"Prepared plaintext: {prepared_text}")

print("Digraphs:")
for i in range(0, len(prepared_text), 2):
    print(prepared_text[i:i + 2], end=" ")

def find_position(matrix,ch):
    for row in range(5):
        for col in range(5):
            if matrix[row][col]==ch:
                return row,col

def playfair_encrypt(text,matrix): #prepared_text
    cipher="" 
    for i in range(0,len(text),2):
        first=text[i]
        second=text[i+1]
        row1,col1=find_position(matrix,first)
        row2,col2=find_position(matrix,second)

        if row1==row2: #Rule 1: Same row
            new_col1=(col1+1)%5
            new_col2=(col2+1)%5
# Shift each character one position to the right.
            cipher+=matrix[row1][new_col1]
            cipher+=matrix[row2][new_col2] #row1=row2

        elif col1 == col2: #Rule 2: Same column

            new_row1 = (row1 + 1) % 5
            new_row2 = (row2 + 1) % 5
# Shift each character one position downward.
            cipher += matrix[new_row1][col1]
            cipher += matrix[new_row2][col2]

        else: #Rule 3: Rectangle
            cipher += matrix[row1][col2]
            cipher += matrix[row2][col1]
# Keep each character's row but swap columns.
    return cipher

def playfair_decrypt(text, matrix):

    plain = ""

    for i in range(0, len(text), 2):

        first = text[i]
        second = text[i + 1]

        row1, col1 = find_position(matrix, first)
        row2, col2 = find_position(matrix, second)

        # Rule 1: Same row
        # Shift each character one position to the left.

        if row1 == row2:

            new_col1 = (col1 - 1) % 5
            new_col2 = (col2 - 1) % 5

            plain += matrix[row1][new_col1]
            plain += matrix[row2][new_col2]

        # Rule 2: Same column
        # Shift each character one position upward.

        elif col1 == col2:

            new_row1 = (row1 - 1) % 5
            new_row2 = (row2 - 1) % 5

            plain += matrix[new_row1][col1]
            plain += matrix[new_row2][col2]

        # Rule 3: Rectangle
        # Keep rows and swap columns.
        # Same as encryption.
        else:

            plain += matrix[row1][col2]
            plain += matrix[row2][col1]

    return plain



cipher = playfair_encrypt(prepared_text, matrix)
print(f"Ciphertext: {cipher}")

decrypted_text = playfair_decrypt(cipher, matrix)
print(f"Decrypted text: {decrypted_text}")



# 4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the following
# key:
# 𝐾 = [03 03 2 07]

#=================================================================================================
# Calculate determinant of the key matrix
# The determinant must have a multiplicative modular inverse (MMI) modulo 26
# i.e., gcd(det(K), 26) must be 1
# Find the MMI of the determinant modulo 26
# det(K) * MMI % 26 = 1
# Use the MMI of the determinant to calculate the inverse key matrix
# K^(-1) is used for Hill cipher decryption
#==============================================================================================

def prepare_text(text, block_size):

    # Remove spaces and non-alphabetic characters
    text = ''.join(ch.upper() for ch in text if ch.isalpha())

    # Pad with X so that length is a multiple of block size
    while len(text) % block_size != 0:
        text += 'X'
    return text
def determinant(matrix):
    n = len(matrix)

    if n == 1:
        return matrix[0][0]

    if n == 2:
        return (
            matrix[0][0] * matrix[1][1]
            - matrix[0][1] * matrix[1][0]
        )

    det = 0

    for col in range(n):
        minor = []

        for row in range(1, n):
            minor_row = []

            for j in range(n):
                if j != col:
                    minor_row.append(matrix[row][j])

            minor.append(minor_row)

        cofactor = (
            (-1) ** col
            * matrix[0][col]
            * determinant(minor)
        )

        det += cofactor

    return det


def mod_inverse(number, modulus):
    number %= modulus

    for x in range(1, modulus):
        if (number * x) % modulus == 1:
            return x

    return None


def get_minor(matrix, remove_row, remove_col):
    minor = []

    for i in range(len(matrix)):
        if i == remove_row:
            continue

        row = []

        for j in range(len(matrix)):
            if j == remove_col:
                continue

            row.append(matrix[i][j])

        minor.append(row)

    return minor


def matrix_mod_inverse(matrix):
    n = len(matrix)

    det = determinant(matrix)
    det %= 26

    det_inverse = mod_inverse(det, 26)

    if det_inverse is None:
        raise ValueError(
            "Invalid key matrix: determinant has no "
            "multiplicative modular inverse modulo 26."
        )

    if n == 1:
        return [[det_inverse % 26]]

    cofactor_matrix = []

    for i in range(n):
        row = []

        for j in range(n):
            minor = get_minor(matrix, i, j)

            cofactor = (
                (-1) ** (i + j)
                * determinant(minor)
            )

            row.append(cofactor)

        cofactor_matrix.append(row)

    adjugate = []

    for i in range(n):
        row = []

        for j in range(n):
            row.append(cofactor_matrix[j][i])

        adjugate.append(row)

    inverse = []

    for i in range(n):
        row = []

        for j in range(n):
            value = (
                det_inverse
                * adjugate[i][j]
            ) % 26

            row.append(value)

        inverse.append(row)

    return inverse


def text_to_numbers(text):
    numbers = []

    for ch in text:
        numbers.append(ord(ch) - ord('A'))

    return numbers


def numbers_to_text(numbers):
    text = ""

    for number in numbers:
        text += chr(number + ord('A'))

    return text


def matrix_vector_multiply(matrix, vector):
    result = []

    for row in matrix:
        value = 0

        for j in range(len(vector)):
            value += row[j] * vector[j]

        result.append(value % 26)

    return result


def hill_encrypt(text, key_matrix):
    n = len(key_matrix)

    text = prepare_text(text, n)

    cipher = ""

    for i in range(0, len(text), n):
        block = text[i:i + n]

        plaintext_vector = text_to_numbers(block)

        cipher_vector = matrix_vector_multiply(
            key_matrix,
            plaintext_vector
        )

        cipher += numbers_to_text(cipher_vector)

    return text, cipher


def hill_decrypt(cipher, key_matrix):
    n = len(key_matrix)

    inverse_key = matrix_mod_inverse(key_matrix)

    plain = ""

    for i in range(0, len(cipher), n):
        block = cipher[i:i + n]

        cipher_vector = text_to_numbers(block)

        plaintext_vector = matrix_vector_multiply(
            inverse_key,
            cipher_vector
        )

        plain += numbers_to_text(plaintext_vector)

    return plain, inverse_key


text = input("Enter the plaintext: ")

n = int(input("Enter the size of the key matrix: "))

print(f"Enter the {n} x {n} key matrix:")

key_matrix = []

for i in range(n):
    row = list(map(int, input().split()))

    if len(row) != n:
        raise ValueError(
            f"Each row must contain exactly {n} values."
        )

    key_matrix.append(row)


det = determinant(key_matrix)

print("Determinant:", det)
print("Determinant mod 26:", det % 26)

det_mmi = mod_inverse(det, 26)

if det_mmi is None:
    print(
        "Invalid Hill cipher key."
        " The determinant has no MMI modulo 26."
        " Therefore, the matrix cannot be inverted for decryption."
    )
    exit()

print("MMI of determinant:", det_mmi)

print("Key Matrix:")

for row in key_matrix:
    print(row)

prepared_text, cipher = hill_encrypt(
    text,
    key_matrix
)

print("Prepared plaintext:", prepared_text)
print("Ciphertext:", cipher)

plain, inverse_key = hill_decrypt(
    cipher,
    key_matrix
)

print("Inverse Key Matrix:")

for row in inverse_key:
    print(row)

print("Decrypted text:", plain)

# 5. John is reading a mystery book involving cryptography. In one part of the book, the author
# gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a shift
# cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave with
# "XVIEWYWI" engraved on it. John immediately found the actual meaning of the ciphertext.
# Identify the type of attack and plaintext
#soln
#knownplaintext attack yes->ciw shift cipher C=(P+k)mod26 key=4 so decrypted is treasure

# 6. Use a brute-force attack to decipher the following message. Assume that you know it is an
# affine cipher and that the plaintext "ab" is enciphered to "GL":
# XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
#soln 
#knownplaintext attack ab->gl affine cipher C=(aP+b)mod26

#learn to write bruteforce codes
#Additional Exercises