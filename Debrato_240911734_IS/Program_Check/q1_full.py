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
