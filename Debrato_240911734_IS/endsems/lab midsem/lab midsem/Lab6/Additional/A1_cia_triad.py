"""Lab 6 - Additional
Demonstrate the CIA triad using RSA encryption, RSA digital signature and SHA hashing.
  Confidentiality : RSA (hybrid RSA-OAEP + AES-GCM) - only Bob can read
  Integrity       : SHA-256 digest - any change is detected
  Authenticity    : RSA signature by Alice - proves the sender (and non-repudiation)
  Availability    : verification is public and cheap; keys are distributed in advance
(Also explore https://www.nmichaels.org/rsa.py - Q0 reproduces that tool in Python.)"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Patient 42: lab results negative")
alice, bob = generate_keys("rsa", 2048), generate_keys("rsa", 2048)

banner("Alice sends")
digest = hash_hex(msg, "sha256")
sig = signature("rsa", msg, alice)
ciphertext = rsa_cipher(msg, bob.publickey(), mode="hybrid")
print(f"  SHA-256    : {digest}\n  Signature  : {fmt(sig)[:64]}...\n  Ciphertext : {fmt(ciphertext)[:64]}...")


def bob_receives(ct, s, dig, label):
    print(f"\n  [{label}]")
    try:
        pt = rsa_cipher(ct, bob, decrypt=True, mode="hybrid").decode()
    except Exception:
        print("    Confidentiality: ciphertext rejected (AES-GCM tag failed)")
        return
    print(f"    Confidentiality: decrypted '{pt}'")
    print(f"    Integrity      : hash match = {hash_hex(pt, 'sha256') == dig}")
    print(f"    Authenticity   : Alice's signature valid = {signature('rsa', pt, alice.publickey(), sig=s)}")


banner("Bob receives")
bob_receives(ciphertext, sig, digest, "genuine message")
bob_receives(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), sig, digest, "ciphertext tampered")
forged = rsa_cipher("Patient 42: lab results POSITIVE", bob.publickey(), mode="hybrid")
bob_receives(forged, sig, digest, "Eve sends her own message with Alice's old signature")
print("\n  Eve cannot read the message: she does not have Bob's private key ->",
      "confidentiality holds.")
