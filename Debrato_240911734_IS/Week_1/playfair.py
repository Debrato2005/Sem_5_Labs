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
text = input("Enter the plaintext for playfair: ")
key = input("Enter the key: ")

def create_matrix(key):
    alphabet="ABCDEFGHIKLMNOPQRSTUVWXYZ" #no J
#cannot mathematically know whether the original was I or j
    key=key.upper()
    key="".join(ch for ch in key if ch.isalpha())
    key=key.replace("J","I")

    sequence=""

    for ch in key:
        if ch not in sequence:
            sequence += ch

    # Add remaining letters from alphabet
    for ch in alphabet:
        if ch not in sequence:
            sequence += ch

    matrix=[]

    for i in range(0,25,5):
        matrix.append(sequence[i:i+5])

    return matrix

matrix=create_matrix(key)
print()
print("Playfair Matrix")
for row in matrix:
    print(" ".join(row)) # can directly print row but this intoduces space
# join() follows the format: separator.join(iterable)
# It combines the elements using the given separator.
# "".join(row)   -> combines without a separator
# " ".join(row)  -> combines with a space between elements
# "-".join(row)  -> combines with "-" between elements

def prepare_text(text):
    text="".join(ch.upper() for ch in text if ch.isalpha())
    text=text.replace("J","I")

    prepared=""
    i=0
# Process the text two characters at a time. First check whether the current
# character is the final unpaired character before accessing text[i + 1], which
# prevents an out-of-range index. If no second character exists, pair the
# character with "X". If the next character is the same, split the pair by
# inserting "X" after the first character and advance by one. Otherwise, use
# both characters as a pair and advance by two.
    while i<len(text):#checking if paired up or not
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
    #if same row shift/wrap right
        #if same col shift/wrap one posn downwards
        #else just replace their cols 
    cipher="" 
    for i in range(0,len(text),2): #mainatgaining diagraphs
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
#learn hill cipher
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