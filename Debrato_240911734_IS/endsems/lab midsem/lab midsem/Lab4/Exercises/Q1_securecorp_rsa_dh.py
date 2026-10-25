"""Lab 4 - Exercise 1  (SecureCorp)
Subsystems: Finance (A), HR (B), Supply Chain (C) exchange documents securely.
 1. Secure communication: RSA + Diffie-Hellman
      - each subsystem has an RSA key pair issued by the key manager
      - DH public values are RSA-encrypted to the peer and RSA-signed (stops MITM)
      - the DH shared secret -> AES-256-GCM session key for documents
      - every document is also RSA-signed (authenticity / non-repudiation)
 2. Key management: generate, distribute, revoke, renew, audit (islib.KeyManager)
 3. Scalability: add_subsystem() - new systems join without touching the old ones.
To modify: change SUBSYSTEMS, RSA_BITS, or the documents sent at the bottom."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

RSA_BITS = ask("RSA key bits", 2048)
km = KeyManager("rsa", bits=RSA_BITS, lifetime_days=365, master_password="SecureCorp-Master")


class Subsystem:
    def __init__(self, name):
        self.name = name
        self.token = km.register(name)                                   # key generation
        self.rsa = RSA.import_key(km.get_private(name, self.token))     # secure distribution
        self.sessions, self._eph = {}, {}

    def peer_key(self, peer):
        return RSA.import_key(km.get_public(peer))      # raises if peer key revoked/expired

    def dh_offer(self, peer):
        """Step 1: fresh DH value, encrypted to the peer with RSA and signed with our RSA key."""
        pub, priv = generate_keys("dh")
        self._eph[peer] = priv
        return (rsa_cipher(str(pub), self.peer_key(peer), mode="hybrid"),
                signature("rsa", str(pub), self.rsa))

    def dh_accept(self, peer, enc_pub, sig):
        """Step 2: decrypt + verify peer's DH value, derive the session key."""
        their_pub = rsa_cipher(enc_pub, self.rsa, decrypt=True, mode="hybrid").decode()
        if not signature("rsa", their_pub, self.peer_key(peer), sig=sig):
            raise ValueError(f"{self.name}: bad DH signature from {peer} (MITM?)")
        self.sessions[peer] = dh_shared(self._eph.pop(peer), int(their_pub), as_key=True)

    def send(self, peer, document):
        return (symmetric("AES", self.sessions[peer], document, "GCM", packed=True),
                signature("rsa", document, self.rsa))

    def receive(self, peer, blob, sig):
        doc = symmetric("AES", self.sessions[peer], blob, "GCM", decrypt=True, packed=True)
        return doc.decode(), signature("rsa", doc, self.peer_key(peer), sig=sig)


def connect_pair(a, b):
    offer_a, offer_b = a.dh_offer(b.name), b.dh_offer(a.name)
    a.dh_accept(b.name, *offer_b)
    b.dh_accept(a.name, *offer_a)
    km.log("CHANNEL", f"{a.name}<->{b.name}", "session key established")


def transfer(a, b, document):
    blob, sig = a.send(b.name, document)
    doc, ok = b.receive(a.name, blob, sig)
    print(f"  {a.name} -> {b.name}: '{doc}'  signature valid={ok}  (wire: {fmt(blob)[:40]}...)")


systems = {}


def add_subsystem(name):
    """Scalability: one call to add a new subsystem."""
    systems[name] = Subsystem(name)
    return systems[name]


banner("Register subsystems (RSA key generation + distribution)")
for n in ["Finance-A", "HR-B", "SupplyChain-C"]:
    add_subsystem(n)
km.print_status()

banner("Establish channels (RSA-protected Diffie-Hellman) and exchange documents")
A, B, C = systems["Finance-A"], systems["HR-B"], systems["SupplyChain-C"]
for x, y in [(A, B), (A, C), (B, C)]:
    connect_pair(x, y)
transfer(A, B, "Q3 financial report: revenue 12.4M")
transfer(B, A, "Employee contract #4471 signed")
transfer(C, A, "Procurement order PO-889: 500 units")

banner("Key revocation: SupplyChain-C is compromised")
km.revoke("SupplyChain-C", "suspected compromise")
try:
    connect_pair(B, C)
except PermissionError as e:
    print("  Channel refused:", e)

banner("Key renewal for C, then reconnect")
km.renew("SupplyChain-C")
systems["SupplyChain-C"].rsa = RSA.import_key(km.get_private("SupplyChain-C", C.token))
connect_pair(B, C)
transfer(C, B, "New supplier list v2")

banner("Scalability: add a new subsystem (Marketing-D)")
D = add_subsystem("Marketing-D")
connect_pair(D, A)
transfer(D, A, "Campaign budget request")
km.print_status()

banner("Audit log")
km.print_audit()
