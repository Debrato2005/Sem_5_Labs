"""Lab 5 - Exercise 2 (SERVER)
Receives data, computes its hash and sends the hash back to the client.
Run this first:  python3 Q2_server.py        then in another terminal: python3 Q2_client.py
To modify: PORT, ALGO (md5 / sha1 / sha256 / sha512)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT, ALGO = 5000, "sha256"


def handle(conn, addr):
    data = sock_recv(conn)
    digest = hash_hex(data, ALGO)
    print(f"[server] received {data!r}\n[server] {ALGO} = {digest}")
    sock_send(conn, digest)


run_server(handle, PORT)
