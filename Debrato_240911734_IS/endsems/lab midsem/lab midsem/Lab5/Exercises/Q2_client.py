"""Lab 5 - Exercise 2 (CLIENT)
Sends data to the server, receives the server's hash, compares with the local hash.
Run 1: normal transmission  -> hashes match (integrity OK)
Run 2: one byte corrupted in transit (simulated) -> hashes differ (tampering detected)"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PORT, ALGO = 5000, "sha256"
message = ask("Message", "Transfer Rs. 5000 to account 1234")


def transmit(data_sent, original):
    with connect(PORT) as s:
        sock_send(s, data_sent)
        server_hash = sock_recv(s)
    local_hash = hash_hex(original, ALGO)
    print(f"  local  {ALGO}: {local_hash}\n  server {ALGO}: {server_hash}")
    print("  RESULT:", "integrity verified" if local_hash == server_hash
          else "MISMATCH -> data corrupted / tampered in transit!")


banner("1. Normal transmission")
transmit(message, message)

banner("2. Corrupted transmission (attacker changes 5000 -> 9000)")
transmit(message.replace("5000", "9000"), message)
