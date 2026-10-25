"""Lab 6 - Exercise 1
Repeat the sign / verify steps with ElGamal and Schnorr signatures.
 ElGamal: r = g^k mod p, s = (H(m) - x r) k^-1 mod (p-1);  valid iff g^H(m) = y^r r^s
 Schnorr: r = g^k, e = H(r||m) mod q, s = k + x e;          valid iff H(g^s y^-e || m) = e
To modify: BITS for ElGamal, generate_keys("schnorr", pbits, qbits=..) for Schnorr."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

doc = ask("Document to sign", "Alice agrees to the contract terms")
BITS = ask("ElGamal prime bits", 512)

banner("ElGamal signature")
p, g, y, x = generate_keys("elgamal", BITS)
print(f"  public (p, g, y): p={p}\n  g={g}\n  y={y}\n  private x={x}")
sig = signature("elgamal", doc, (p, g, x))
print(f"  Alice's signature (r, s) = {sig}")
print("  Bob verifies original :", signature("elgamal", doc, (p, g, y), sig=sig))
print("  Bob verifies tampered :", signature("elgamal", doc + ".", (p, g, y), sig=sig))

banner("Schnorr signature")
P, Q, G, sy, sx = generate_keys("schnorr", 1024, qbits=160)
print(f"  q = {Q}\n  g = {G}\n  private x = {sx}\n  public y = {sy}")
sig = signature("schnorr", doc, (P, Q, G, sx))
print(f"  Alice's signature (e, s) = {sig}")
print("  Bob verifies original :", signature("schnorr", doc, (P, Q, G, sy), sig=sig))
print("  Bob verifies tampered :", signature("schnorr", doc + ".", (P, Q, G, sy), sig=sig))

banner("Bob signs a response, Alice verifies")
reply = "BOB received the contract"
_, _, _, bob_y, bob_x = generate_keys("schnorr", params=(P, Q, G))     # Bob's keys, same group
sig_b = signature("schnorr", reply, (P, Q, G, bob_x))
print("  Alice verifies Bob    :", signature("schnorr", reply, (P, Q, G, bob_y), sig=sig_b))
