"""Lab 6 - Exercise 3 (CLIENT = Bob, the verifier)
Requests a signed document from the server, verifies all three signatures, then shows
that a document modified in transit fails verification."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT = 5002
doc = ask("Document to have signed", "Purchase order #7781: 40 laptops")

with connect(PORT) as s:
    sock_send(s, doc)
    resp = sock_recv(s)                                  # dict sent as JSON by the server


def verify_all(document):
    r, e, sc = resp["rsa"], resp["elgamal"], resp["schnorr"]
    return {
        "RSA": signature("rsa", document, RSA.import_key(r["pub"]), sig=bytes.fromhex(r["sig"])),
        "ElGamal": signature("elgamal", document, (e["p"], e["g"], e["y"]), sig=e["sig"]),
        "Schnorr": signature("schnorr", document, (sc["p"], sc["q"], sc["g"], sc["y"]), sig=sc["sig"]),
    }


banner("Received document verified with the server's public keys")
for name, ok in verify_all(resp["document"]).items():
    print(f"  {name:8}: {'VALID' if ok else 'INVALID'}")

banner("Document altered in transit (40 -> 400 laptops)")
for name, ok in verify_all(resp["document"].replace("40", "400")).items():
    print(f"  {name:8}: {'VALID' if ok else 'INVALID'}")

print("""
Observations: all three schemes give authenticity + integrity + non-repudiation.
RSA signatures are 256 bytes, ElGamal 2x|p| (128 bytes here), Schnorr only 2x160 bits.
ElGamal / Schnorr need a fresh random k per signature - reusing k leaks the private key.""")
