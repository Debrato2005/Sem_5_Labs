"""Lab 5 - Additional 1 (CLIENT)
Splits the message into parts, sends them, then compares the server's hash of the
reassembled message with the local hash of the original message."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT, ALGO = 5001, "sha256"
message = ask("Message", "This long message is sent to the server in several small parts.")
PART_SIZE = ask("Bytes per part", 10)

data = to_bytes(message)
parts = [data[i:i + PART_SIZE] for i in range(0, len(data), PART_SIZE)]
with connect(PORT) as s:
    for p in parts:
        sock_send(s, p)
    sock_send(s, b"")                                     # end-of-message marker
    server_hash = sock_recv(s)

local_hash = hash_hex(data, ALGO)
print(f"Sent {len(parts)} parts")
print(f"local  {ALGO}: {local_hash}\nserver {ALGO}: {server_hash}")
print("RESULT:", "integrity verified" if local_hash == server_hash else "MISMATCH - message altered!")
