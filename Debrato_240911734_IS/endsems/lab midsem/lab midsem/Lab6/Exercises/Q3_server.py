"""Lab 6 - Exercise 3 (SERVER = Alice, the signer)
For each client: receives a document request, signs the document with RSA, ElGamal
and Schnorr, and sends the public keys + signatures as JSON.
Run:  python3 Q3_server.py   then   python3 Q3_client.py"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT = 5002
rsa_key = generate_keys("rsa", 2048)
p, g, y, x = generate_keys("elgamal", 512)
P, Q, G, sy, sx = generate_keys("schnorr")
print("[server] keys ready")


def handle(conn, addr):
    doc = sock_recv(conn)
    print(f"[server] signing {doc!r}")
    sock_send(conn, {
        "document": doc,
        "rsa": {"pub": rsa_key.publickey().export_key().decode(), "sig": signature("rsa", doc, rsa_key).hex()},
        "elgamal": {"p": p, "g": g, "y": y, "sig": signature("elgamal", doc, (p, g, x))},
        "schnorr": {"p": P, "q": Q, "g": G, "y": sy, "sig": signature("schnorr", doc, (P, Q, G, sx))},
    })


run_server(handle, PORT)
