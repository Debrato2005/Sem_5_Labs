# A cipher is a mathematical algorithm that converts readable data (plaintext)
# into unreadable data (ciphertext) using a key,
# and converts it back using the appropriate key.

# 1. Encrypt the message "I am learning information security" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)

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
key=int(input("Enter the key for encryption: "))

encrypted_text=""
for ch in text:
    encrypted_text += caesar(ch,key)
decrypted_text=""
for ch in encrypted_text:
    decrypted_text += caesar(ch,-key)
print(f"Plaintext is : {text}")
print(f"Encrypted text is : {encrypted_text}")
print(f"Decrypted text is : {decrypted_text}")
