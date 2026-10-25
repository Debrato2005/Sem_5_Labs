"""Lab 5 - Additional 1 (SERVER)
Client sends a message in multiple parts; the server reassembles it, hashes the
reassembled message, and sends the hash back. An empty part means "end of message".
Run:  python3 A1_server.py   then   python3 A1_client.py"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT, ALGO = 5001, "sha256"


def handle(conn, addr):
    parts = []
    while (part := sock_recv(conn)):
        parts.append(part)
        print(f"[server] part {len(parts)}: {part!r}")
    message = b"".join(parts)
    digest = hash_hex(message, ALGO)
    print(f"[server] reassembled {len(parts)} parts -> {message!r}\n[server] {ALGO} = {digest}")
    sock_send(conn, digest)


run_server(handle, PORT)
