"""Lab 6 - Exercise 2
"Try the steps with Diffie-Hellman". DH is a key-agreement scheme, not a signature
scheme, so: Alice and Bob agree on a shared key with DH, then 'sign' documents with
HMAC-SHA256 under that key and verify each other's tags.
Observation: this gives integrity + authenticity between the two parties, but NOT
non-repudiation (both hold the same key, so either could have produced the tag)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

doc = ask("Document", "Alice: transfer approved")

banner("1. Diffie-Hellman key agreement (RFC 3526 2048-bit group)")
A, a = generate_keys("dh")
B, b = generate_keys("dh")
k_alice = dh_shared(a, B, as_key=True)
k_bob = dh_shared(b, A, as_key=True)
print(f"  Alice public A = {format(A, 'x')[:48]}...\n  Bob   public B = {format(B, 'x')[:48]}...")
print(f"  Shared keys equal: {k_alice == k_bob}  key = {fmt(k_alice)}")

banner("2. Alice signs (HMAC) and sends; Bob verifies")
tag = signature("hmac", doc, k_alice)
print(f"  tag = {fmt(tag)}")
print("  Bob verifies original :", signature("hmac", doc, k_bob, sig=tag))
print("  Bob verifies tampered :", signature("hmac", doc.replace("approved", "denied"), k_bob, sig=tag))

banner("3. Bob replies, Alice verifies")
reply = "BOB: confirmed"
print("  Alice verifies Bob    :", signature("hmac", reply, k_alice, sig=signature("hmac", reply, k_bob)))

banner("4. Eve (not part of the exchange) tries to forge")
_, e = generate_keys("dh")
k_eve = dh_shared(e, B, as_key=True)
print("  Bob accepts Eve's tag :", signature("hmac", doc, k_bob, sig=signature("hmac", doc, k_eve)))
