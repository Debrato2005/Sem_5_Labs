# if wanna preserve spaces in autokey cipher key
# Plaintext: THE  HOUSE
# Key:       DTH  EHOUS
text = input("Enter the plain text: ")
key = input("Enter the letter/key for autokey cipher: ")
og_key = key

# Plaintext letters that will be used to extend the key
plaintext_letters = ""

for ch in text:
    if 'A' <= ch <= 'Z' or 'a' <= ch <= 'z':
        plaintext_letters += ch

# Initial key occupies the first position(s)
key_index = 0
letter_index = 0

while len(key) < len(text):

    # Preserve the position of spaces/non-alphabetic characters
    if not ('A' <= text[len(key)] <= 'Z' or
            'a' <= text[len(key)] <= 'z'):
        key += text[len(key)]
#Because len(key) points to the next position you want to fill, 
#while len(key) - 1 points to the last position already filled.

    else:
        key += plaintext_letters[letter_index]
        letter_index += 1

print(f"Key to be used : {key} ")

# Autokey Cipher with Space Preservation:
# This program encrypts/decrypts text using the Autokey cipher while preserving
# spaces and other non-alphabetic characters in their original positions.
#
# The initial key is used first, and the plaintext characters are then used
# sequentially to extend the key. Spaces are copied directly into the key and
# do not consume a plaintext character for key extension.
#
# Example:
# Plaintext : THE HOUSE
# Key       : DTH EHOUS
#
# The program maintains two separate sequences:
# 1. plaintext_letters - contains only alphabetic characters and is used to
#    extend the autokey.
# 2. key - maintains the same length and positions as the original text,
#    including spaces/non-alphabetic characters.
#
# len(key) is used to identify the next position of the plaintext to process.
# Since the key already contains len(key) characters, the next position is
# exactly index len(key). Therefore, text[len(key)] is used instead of
# text[len(key)-1], which would refer to the last already-processed character.