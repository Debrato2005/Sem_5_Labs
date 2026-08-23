#play_fair cipher
text=input("input the text:")
key=input("input the key")

def create_matrix(key):
    alphabet="ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key="".join(ch.upper() for ch in key if ch.isalpha())
    key=key.replace("J","I")

    sequence=""

    for ch in key :
        if ch not in sequence:
            sequence+=ch
    for ch in alphabet:
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

def prepare_text():
    text="".join(ch.upper() for ch in text if ch.isalpha())
    text=text.replace("J","I")

    prepared=""
    i=0
    while(i<len(text)):
        first=text[i]
        if i+1==len(text):
            prepared+=first+"X"
            i+=1

        else:
            second=text[i+1]
            if first==second:
                prepared+=first+"X"
                i+=1
            else:
                prepared+=first+second
                i+=-2
    return prepared

prepared_text=prepare_text(text)
print("diagraphs")
for i in range (0, len(prepared_text),2):
    print(prepared_text[i:i+2])

def find_posn(matrix,ch):
    for row in range(5):
        for col in range(5):
            if matrix[row][col]==ch:
                return row,col

def playfair_cipher(text,amtrix):
    #if same row shift/wrap right
    #if same col shift/wrap one posn downwards
    #else just replace their cols 
    cipher=""
    for i in range(0,len(text),2):
        first=text[i]
        second=text[i+1]
        row1,col1=find_posn(matrix,first)
        row2,col2=find_posn(matrix,first)

        if row1==row2:
            new_col1=(col1+1)%5
            new_col2=(col2+1)%5
            cipher+=matrix[row1][new_col1]
            cipher+=matrix[row2][new_col2]
        elif col1 == col2:
            new_row1 = (row1 + 1) % 5
            new_row2 = (row2 + 1) % 5
            cipher += matrix[new_row1][col1]
            cipher += matrix[new_row2][col2]

        else: #Rule 3: Rectangle
            cipher += matrix[row1][col2]
            cipher += matrix[row2][col1] 

    return cipher
cipher = playfair_encrypt(prepared_text, matrix)
print(f"Ciphertext: {cipher}")
