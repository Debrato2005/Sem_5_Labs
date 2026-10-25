"""Lab 3 - Exercise 5
Peer-to-peer file sharing: each pair of peers establishes a shared secret with
Diffie-Hellman over an insecure channel. Measure key-generation and key-exchange time.
Uses the standard RFC 3526 2048-bit group (DH_P, DH_G) from islib.
To modify: PEERS list, or your own group: generate_keys("dh", p=.., g=..) and dh_shared(.., p=..)."""
import sys, pathlib, itertools; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

PEERS = ["PeerA", "PeerB", "PeerC"]


class Peer:
    def __init__(self, name):
        self.name = name
        (self.pub, self.priv), self.t_keygen = timed(generate_keys, "dh")

    def shared_key(self, other_pub):
        return dh_shared(self.priv, other_pub, as_key=True)


peers = {n: Peer(n) for n in PEERS}
banner("Key generation  (a random, A = g^a mod p)")
print_table(["Peer", "Keygen ms", "Public value (first 40 hex)"],
            [[p.name, p.t_keygen * 1000, format(p.pub, "x")[:40] + "..."] for p in peers.values()])

banner("Key exchange: only public values cross the network")
rows = []
for a, b in itertools.combinations(peers.values(), 2):
    k_ab, t1 = timed(a.shared_key, b.pub)
    k_ba, t2 = timed(b.shared_key, a.pub)
    rows.append([f"{a.name}<->{b.name}", (t1 + t2) * 1000, k_ab == k_ba, fmt(k_ab)[:32] + "..."])
    # use the key to protect a file chunk sent from a to b
    blob = symmetric("AES", k_ab, f"file chunk from {a.name}", "GCM", packed=True)
    assert symmetric("AES", k_ba, blob, "GCM", decrypt=True, packed=True).decode() == f"file chunk from {a.name}"
print_table(["Pair", "Exchange ms", "Same key", "AES key (SHA-256 of g^ab)"], rows)
print("\nEach pair now shares an AES-256 key; an eavesdropper only sees g^a and g^b.")
print("Note: plain DH is vulnerable to man-in-the-middle; sign the public values (Lab 4 Q1).")
