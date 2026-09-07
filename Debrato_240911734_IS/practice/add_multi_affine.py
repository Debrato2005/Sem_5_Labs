# set -e

# # Create project directory
# mkdir -p "$HOME/qwen-local"
# cd "$HOME/qwen-local"

# # Create + activate Python venv
# python3 -m venv .venv
# source .venv/bin/activate

# # Upgrade pip and install Python-side requirements
# python -m pip install --upgrade pip
# pip install zstandard ollama

# # Detect CPU architecture
# case "$(uname -m)" in
#     x86_64)
#         OLLAMA_ARCH="amd64"
#         ;;
#     aarch64|arm64)
#         OLLAMA_ARCH="arm64"
#         ;;
#     *)
#         echo "Unsupported architecture: $(uname -m)"
#         exit 1
#         ;;
# esac

# # Download Ollama
# curl -L "https://ollama.com/download/ollama-linux-${OLLAMA_ARCH}.tar.zst" \
#     -o /tmp/ollama-linux.tar.zst

# # Decompress .zst -> .tar using Python package installed in venv
# python - <<'PY'
# import zstandard as zstd

# src = "/tmp/ollama-linux.tar.zst"
# dst = "/tmp/ollama-linux.tar"

# with open(src, "rb") as fin, open(dst, "wb") as fout:
#     zstd.ZstdDecompressor().copy_stream(fin, fout)
# PY

# # Install Ollama into ~/.local (no root required)
# mkdir -p "$HOME/.local"
# tar -xf /tmp/ollama-linux.tar -C "$HOME/.local"

# # Add Ollama to PATH for current shell
# export PATH="$HOME/.local/bin:$PATH"

# # Add it permanently to bash PATH
# grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" || \
#     echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"

# # Check installation
# ollama --version

# # Create Ollama directory
# mkdir -p "$HOME/.ollama"

# # Start Ollama server in background if not already running
# if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
#     nohup ollama serve > "$HOME/.ollama/ollama.log" 2>&1 &
#     sleep 5
# fi

# # Download Qwen2.5-Coder 7B
# ollama pull qwen2.5-coder:7b

# # Show installed models
# ollama list

# # Run Qwen
# ollama run qwen2.5-coder:7b


# ============================================================
# CLEANUP — remove this temporary Ollama/Qwen installation
# ============================================================
# echo "Stopping Ollama..."

# # Stop the Ollama server started by this user
# pkill -f "ollama serve" 2>/dev/null || true
# sleep 1

# echo "Removing Ollama model/data..."

# # This removes ALL Ollama models/cache/config for this Linux user.
# rm -rf "$HOME/.ollama"

# echo "Removing Ollama files installed into ~/.local..."

# # Use the downloaded archive as a manifest so we only remove files
# # that came from the Ollama tarball.
# if [ -f /tmp/ollama-linux.tar ]; then

#     # Remove files/symlinks first
#     while IFS= read -r path; do
#         target="$HOME/.local/${path#./}"

#         if [ -f "$target" ] || [ -L "$target" ]; then
#             rm -f "$target"
#         fi
#     done < <(tar -tf /tmp/ollama-linux.tar)

#     # Remove now-empty directories, deepest first.
#     tar -tf /tmp/ollama-linux.tar \
#         | awk '/\/$/ {print}' \
#         | sort -r \
#         | while IFS= read -r path; do
#             target="$HOME/.local/${path#./}"
#             rmdir "$target" 2>/dev/null || true
#         done
# fi

# echo "Removing temporary archives..."

# rm -f /tmp/ollama-linux.tar
# rm -f /tmp/ollama-linux.tar.zst

# echo "Removing Ollama PATH entry from ~/.bashrc..."

# sed -i '\|^export PATH="\$HOME/.local/bin:\$PATH"$|d' "$HOME/.bashrc"

# echo "Removing Python environment/project..."

# cd "$HOME"
# rm -rf "$HOME/qwen-local"

# echo "Cleanup complete."
#######################################################################################################

#pip install pycryptodome cryptography numpy sympy matplotlib flask requests schedule
# ==============================
# BUILT-IN PYTHON
# ==============================
import os
import math
import random
import secrets
import string
import itertools
import json
import logging
import time
import binascii
from math import gcd
from pathlib import Path
from datetime import datetime, timedelta
from time import perf_counter

# ==============================
# LAB 1
# ==============================
import numpy as np
from sympy import Matrix
from sympy import mod_inverse
from sympy.ntheory.modular import crt

# ==============================
# LAB 2 - AES / DES / 3DES
# ==============================
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

# ==============================
# LAB 3 - RSA
# ==============================
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# ==============================
# ELGAMAL / NUMBER THEORY
# ==============================
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import getPrime, inverse
from Crypto.Random.random import randint

# ==============================
# ECC / DIFFIE-HELLMAN
# ==============================
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==============================
# SECURE STORAGE
# ==============================
from cryptography.fernet import Fernet

# ==============================
# LAB 4 API
# ==============================
from flask import Flask, request, jsonify
import requests
import schedule

#additive
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def encrypt(text, key, alphabet):
    n = len(alphabet)
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(x + key) % n] for x in nums)
def decrypt(text, key, alphabet):
    n = len(alphabet)
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(x - key) % n] for x in nums)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
key = int(input("Key: "))
c = encrypt(text, key, alphabet)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, key, alphabet))

#multi
from math import gcd
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def encrypt(text, key, alphabet):
    n = len(alphabet)
    if gcd(key, n) != 1:
        raise ValueError("Key has no modular inverse")
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(x * key) % n] for x in nums)
def decrypt(text, key, alphabet):
    n = len(alphabet)
    inv = pow(key, -1, n)
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(x * inv) % n] for x in nums)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
key = int(input("Key: "))
c = encrypt(text, key, alphabet)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, key, alphabet))


#affine
from math import gcd
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def encrypt(text, a, b, alphabet):
    n = len(alphabet)
    if gcd(a, n) != 1:
        raise ValueError("a must be coprime with alphabet length")
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(a*x + b) % n] for x in nums)
def decrypt(text, a, b, alphabet):
    n = len(alphabet)
    inv = pow(a, -1, n)
    nums = [alphabet.index(c) for c in clean(text, alphabet)]
    return ''.join(alphabet[(inv * (x - b)) % n] for x in nums)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
a = int(input("Multiplicative key a: "))
b = int(input("Additive key b: "))
c = encrypt(text, a, b, alphabet)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, a, b, alphabet))

#vignere
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def encrypt(text, key, alphabet):
    n = len(alphabet)
    text = clean(text, alphabet)
    key = clean(key, alphabet)
    p = [alphabet.index(c) for c in text]
    k = [alphabet.index(c) for c in key]
    result = [
        (x + k[i % len(k)]) % n
        for i, x in enumerate(p)
    ]
    return ''.join(alphabet[x] for x in result)
def decrypt(text, key, alphabet):
    n = len(alphabet)
    text = clean(text, alphabet)
    key = clean(key, alphabet)
    c = [alphabet.index(x) for x in text]
    k = [alphabet.index(x) for x in key]
    result = [
        (x - k[i % len(k)]) % n
        for i, x in enumerate(c)
    ]
    return ''.join(alphabet[x] for x in result)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
key = input("Keyword: ").lower()
c = encrypt(text, key, alphabet)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, key, alphabet))

#Autokey Cipher
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def encrypt(text, key, alphabet):
    n = len(alphabet)
    text = clean(text, alphabet)
    p = [alphabet.index(c) for c in text]
    key_stream = [key] + p
    result = [
        (x + key_stream[i]) % n
        for i, x in enumerate(p)
    ]
    return ''.join(alphabet[x] for x in result)
def decrypt(text, key, alphabet):
    n = len(alphabet)
    text = clean(text, alphabet)
    c = [alphabet.index(x) for x in text]
    p = []
    for i, x in enumerate(c):
        if i == 0:
            k = key
        else:
            k = p[i - 1]

        p.append((x - k) % n)

    return ''.join(alphabet[x] for x in p)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
key = int(input("Initial numeric key: "))
c = encrypt(text, key, alphabet)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, key, alphabet))

#Playfair Cipher
def prepare(text, alphabet):
    text = text.lower().replace('j', 'i')
    return ''.join(c for c in text if c in alphabet)
def make_matrix(key, alphabet):
    key = prepare(key, alphabet)
    chars = []
    for c in key + alphabet:
        if c not in chars:
            chars.append(c)
    return [chars[i:i+5] for i in range(0, 25, 5)]
def position(matrix, c):
    for r in range(5):
        for col in range(5):
            if matrix[r][col] == c:
                return r, col
def pairs(text):
    result = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            b = 'x'
            i += 1
        elif text[i + 1] == a:
            b = 'x'
            i += 1
        else:
            b = text[i + 1]
            i += 2
        result.append((a, b))
    return result
def encrypt(text, matrix):
    result = ""
    for a, b in pairs(text):
        r1, c1 = position(matrix, a)
        r2, c2 = position(matrix, b)
        if r1 == r2:
            result += matrix[r1][(c1+1)%5]
            result += matrix[r2][(c2+1)%5]
        elif c1 == c2:
            result += matrix[(r1+1)%5][c1]
            result += matrix[(r2+1)%5][c2]
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]
    return result

def decrypt(text, matrix):
    result = ""
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = position(matrix, a)
        r2, c2 = position(matrix, b)
        if r1 == r2:
            result += matrix[r1][(c1-1)%5]
            result += matrix[r2][(c2-1)%5]
        elif c1 == c2:
            result += matrix[(r1-1)%5][c1]
            result += matrix[(r2-1)%5][c2]
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]
    return result
alphabet = "abcdefghiklmnopqrstuvwxyz"
key = input("Secret key: ")
text = prepare(input("Plaintext: "), alphabet)
matrix = make_matrix(key, alphabet)
print("\nMatrix:")
for row in matrix:
    print(*row)
c = encrypt(text, matrix)
print("\nCiphertext:", c)
print("Decrypted :", decrypt(c, matrix))

#Hill Cipher
from math import gcd
def clean(text, alphabet):
    return ''.join(c for c in text if c in alphabet)
def inverse_key(K, n):
    a, b = K[0]
    c, d = K[1]
    det = (a*d - b*c) % n
    if gcd(det, n) != 1:
        raise ValueError("Key matrix is not invertible")
    inv_det = pow(det, -1, n)
    return [
        [( d*inv_det) % n, (-b*inv_det) % n],
        [(-c*inv_det) % n, ( a*inv_det) % n]
    ]
def transform(text, K, alphabet):
    n = len(alphabet)
    text = clean(text, alphabet)
    if len(text) % 2:
        text += alphabet[-1]
    result = ""
    for i in range(0, len(text), 2):
        x = alphabet.index(text[i])
        y = alphabet.index(text[i+1])
        a = (K[0][0]*x + K[0][1]*y) % n
        b = (K[1][0]*x + K[1][1]*y) % n
        result += alphabet[a] + alphabet[b]
    return result
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
text = input("Plaintext: ").lower()
print("Enter 2x2 key matrix:")
K = [
    list(map(int, input("Row 1: ").split())),
    list(map(int, input("Row 2: ").split()))
]
c = transform(text, K, alphabet)
inv = inverse_key(K, len(alphabet))
print("Ciphertext:", c)
print("Inverse key:", inv)
print("Decrypted :", transform(c, inv, alphabet))

#Known-Plaintext Attack on Shift Cipher
def find_key(plain, cipher, alphabet):
    shifts = []
    for p, c in zip(plain, cipher):
        P = alphabet.index(p)
        C = alphabet.index(c)
        shifts.append((C - P) % len(alphabet))
    if len(set(shifts)) != 1:
        raise ValueError("Pairs do not correspond to one shift key")
    return shifts[0]
def decrypt(text, key, alphabet):
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(x - key) % len(alphabet)]
        else:
            result += c
    return result
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
plain = input("Known plaintext: ").lower()
cipher = input("Known ciphertext: ").lower()
key = find_key(plain, cipher, alphabet)
target = input("Ciphertext to attack: ").lower()
print("Recovered key:", key)
print("Plaintext:", decrypt(target, key, alphabet))

#Affine Known-Plaintext / Brute-Force Attack
from math import gcd
def find_keys(plain, cipher, alphabet):
    n = len(alphabet)
    P = [alphabet.index(c) for c in plain]
    C = [alphabet.index(c) for c in cipher]
    possible = []
    for a in range(n):
        if gcd(a, n) != 1:
            continue
        for b in range(n):
            if all((a*p + b) % n == c
                   for p, c in zip(P, C)):
                possible.append((a, b))
    return possible
def decrypt(text, a, b, alphabet):
    n = len(alphabet)
    inv = pow(a, -1, n)
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(inv*(x-b)) % n]
        else:
            result += c

    return result
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
known_plain = input("Known plaintext: ").lower()
known_cipher = input("Known ciphertext: ").lower()
target = input("Ciphertext to attack: ").lower()
keys = find_keys(known_plain, known_cipher, alphabet)
for a, b in keys:
    print("\nKey:", (a, b))
    print("Plaintext:", decrypt(target, a, b, alphabet))

#Additive Cipher Brute Force
def decrypt(text, key, alphabet):
    result = ""

    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(x - key) % len(alphabet)]
        else:
            result += c

    return result


alphabet = input("Alphabet [A-Z]: ") or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
cipher = input("Ciphertext: ")

for key in range(len(alphabet)):
    print(f"Key {key:2}:", decrypt(cipher, key, alphabet))


#Keyed Transposition Cipher
def encrypt(text, key):
    n = len(key)
    while len(text) % n:
        text += 'x'
    result = ""
    for i in range(0, len(text), n):
        block = text[i:i+n]
        result += ''.join(block[k] for k in key)
    return result
def decrypt(text, key):
    n = len(key)
    inverse = [0] * n
    for i, k in enumerate(key):
        inverse[k] = i
    result = ""
    for i in range(0, len(text), n):
        block = text[i:i+n]
        result += ''.join(block[inverse[j]] for j in range(n))
    return result
text = input("Plaintext: ")
# Example input: 2 0 1
key = list(map(int, input(
    "Permutation key (e.g. 2 0 1): "
).split()))
c = encrypt(text, key)
print("Ciphertext:", c)
print("Decrypted :", decrypt(c, key))


#Multiplicative Cipher — brute force
from math import gcd
def decrypt(text, key, alphabet):
    n = len(alphabet)
    inv = pow(key, -1, n)
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(x * inv) % n]
        else:
            result += c
    return result
alphabet = input("Alphabet [A-Z]: ") or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
cipher = input("Ciphertext: ")
n = len(alphabet)
for key in range(1, n):
    if gcd(key, n) == 1:
        print(f"Key {key:2}:", decrypt(cipher, key, alphabet))

#Affine Cipher
from math import gcd
def decrypt(text, a, b, alphabet):
    n = len(alphabet)
    inv = pow(a, -1, n)
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(inv * (x - b)) % n]
        else:
            result += c

    return result
alphabet = input("Alphabet [A-Z]: ") or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
cipher = input("Ciphertext: ")
n = len(alphabet)
for a in range(1, n):
    if gcd(a, n) != 1:
        continue
    for b in range(n):
        print(f"a={a:2}, b={b:2}:",
              decrypt(cipher, a, b, alphabet))


#Affine brute force using known plaintext
from math import gcd
def decrypt(text, a, b, alphabet):
    n = len(alphabet)
    inv = pow(a, -1, n)
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(inv * (x - b)) % n]
        else:
            result += c
    return result
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
known_plain = input("Known plaintext: ").lower()
known_cipher = input("Known ciphertext: ").lower()
cipher = input("Ciphertext to attack: ").lower()
n = len(alphabet)
for a in range(1, n):
    if gcd(a, n) != 1:
        continue
    for b in range(n):
        valid = True
        for p, c in zip(known_plain, known_cipher):
            P = alphabet.index(p)
            C = alphabet.index(c)
            if (a * P + b) % n != C:
                valid = False
                break
        if valid:
            print("Key:", (a, b))
            print("Plaintext:", decrypt(cipher, a, b, alphabet))


#Shift Cipher — known plaintext attack
def find_key(plain, cipher, alphabet):
    keys = []
    for p, c in zip(plain, cipher):
        P = alphabet.index(p)
        C = alphabet.index(c)
        keys.append((C - P) % len(alphabet))
    if len(set(keys)) == 1:
        return keys[0]
    return None
def decrypt(text, key, alphabet):
    result = ""
    for c in text:
        if c in alphabet:
            x = alphabet.index(c)
            result += alphabet[(x - key) % len(alphabet)]
        else:
            result += c
    return result
alphabet = input("Alphabet [A-Z]: ") or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
plain = input("Known plaintext: ").upper()
cipher = input("Known ciphertext: ").upper()
key = find_key(plain, cipher, alphabet)
print("Recovered key:", key)
target = input("Target ciphertext: ").upper()
print("Plaintext:", decrypt(target, key, alphabet))

#Autokey Cipher — brute force initial numeric key
def decrypt(text, key, alphabet):
    n = len(alphabet)
    c = [alphabet.index(x) for x in text if x in alphabet]
    p = []
    for i, x in enumerate(c):
        if i == 0:
            k = key
        else:
            k = p[i - 1]
        p.append((x - k) % n)
    return ''.join(alphabet[x] for x in p)
alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
cipher = input("Ciphertext: ").lower()
for key in range(len(alphabet)):
    print(f"Key {key:2}:", decrypt(cipher, key, alphabet))


# Vigenère brute force — when key length is known
from itertools import product

def decrypt(text, key, alphabet):
    n = len(alphabet)

    c = [alphabet.index(x) for x in text]
    k = [alphabet.index(x) for x in key]

    result = [
        (x - k[i % len(k)]) % n
        for i, x in enumerate(c)
    ]

    return ''.join(alphabet[x] for x in result)


alphabet = input("Alphabet [a-z]: ") or "abcdefghijklmnopqrstuvwxyz"
cipher = input("Ciphertext: ").lower().replace(" ", "")
length = int(input("Key length: "))

for combination in product(alphabet, repeat=length):

    key = ''.join(combination)

    print(key, ":", decrypt(cipher, key, alphabet))


#Keyed Transposition — brute force permutation keys
from itertools import permutations

def decrypt(text, key):
    n = len(key)

    inverse = [0] * n

    for i, k in enumerate(key):
        inverse[k] = i

    result = ""

    for i in range(0, len(text), n):
        block = text[i:i+n]

        if len(block) == n:
            result += ''.join(block[inverse[j]] for j in range(n))

    return result


cipher = input("Ciphertext: ")
size = int(input("Key size: "))

for key in permutations(range(size)):
    print(key, ":", decrypt(cipher, key))


