"""Lab 4 - Additional 1  (DigiRights Inc. - ElGamal DRM)
 * Key generation   : master ElGamal key pair, configurable size (e.g. 2048 bits)
 * Content encryption: creators upload content, encrypted with the master public key
 * Key distribution : the master private key never leaves the DRM service; it is used
                      only for customers whose licence is valid (license-server model)
 * Access control   : time-limited grants, revocation, creators manage their own content
 * Key revocation   : master key revoked after a breach -> new key, content re-encrypted
 * Key renewal      : every 24 months (simulated clock), content re-encrypted
 * Secure storage   : master private key AES-GCM sealed (KeyManager)
 * Auditing/logging : one shared audit log for keys and access control
To modify: KEY_BITS (1024 is faster for practice), creators/customers/content below."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

KEY_BITS = ask("ElGamal master key bits", 2048)
km = KeyManager("elgamal", bits=KEY_BITS, lifetime_days=730, master_password="DRM-vault")
ac = AccessControl(log=km.log)
service_token = km.register("MASTER")
catalog = {}                                            # content_id -> encrypted packet


def upload(creator, content_id, data):
    pub = km.get_public("MASTER")
    catalog[content_id] = elgamal_cipher(data, pub["p"], pub["g"], pub["y"], mode="hybrid")
    ac.set_owner(content_id, creator)
    km.log("UPLOAD", creator, content_id)


def play(customer, content_id):
    if not ac.can_access(customer, content_id):
        km.log("AC-DENIED", customer, content_id)
        return f"DENIED ({customer} has no valid licence for {content_id})"
    pub, priv = km.get_public("MASTER"), km.get_private("MASTER", service_token)
    km.log("PLAY", customer, content_id)
    return elgamal_cipher(catalog[content_id], pub["p"], pub["g"], priv["x"], decrypt=True,
                          mode="hybrid").decode()


def rotate_master(reason, old=None, now=None):
    """Decrypt all content with the old key, renew the key, re-encrypt with the new key.
    old = (pub, priv) escrowed before a revocation (a revoked key can't be fetched)."""
    pub, priv = old or (km.get_public("MASTER"), km.get_private("MASTER", service_token))
    plain = {c: elgamal_cipher(pkt, pub["p"], pub["g"], priv["x"], decrypt=True, mode="hybrid")
             for c, pkt in catalog.items()}
    km.renew("MASTER", now)
    km.log("ROTATE", "MASTER", reason)
    pub = km.get_public("MASTER")
    for c, data in plain.items():
        catalog[c] = elgamal_cipher(data, pub["p"], pub["g"], pub["y"], mode="hybrid")


banner("Content upload (encrypted with the master public key)")
upload("creatorA", "ebook-101", "Chapter 1: It was a dark and stormy night...")
upload("creatorB", "song-7", "<mp3 bytes of song 7>")
print("  ebook-101 stored as:", fmt(catalog["ebook-101"][1])[:60], "...")

banner("Access control")
ac.grant("creatorA", "alice", "ebook-101", seconds=24 * 3600)     # 1-day licence
ac.grant("creatorB", "bob", "song-7", seconds=3600)
print("  alice plays ebook-101:", play("alice", "ebook-101"))
print("  alice plays song-7   :", play("alice", "song-7"))
try:
    ac.grant("creatorA", "eve", "song-7", 3600)                   # not creatorA's content
except PermissionError as e:
    print("  creatorA grants song-7:", e)
print("  alice licence valid after 2 days?", ac.can_access("alice", "ebook-101", now=time.time() + 2 * 86400))
ac.revoke("creatorB", "bob", "song-7")
print("  bob after revoke     :", play("bob", "song-7"))

banner("Master key revocation after a breach")
escrow = km.get_public("MASTER"), km.get_private("MASTER", service_token)   # offline escrow copy
km.revoke("MASTER", "security breach")
try:
    play("alice", "ebook-101")
except PermissionError as e:
    print("  Service halted:", e)
rotate_master("emergency rotation after breach", old=escrow)
print("  alice plays ebook-101 (new key):", play("alice", "ebook-101"))

banner("Automatic renewal every 24 months (clock +731 days)")
future = time.time() + 731 * 86400
if not km.is_active("MASTER", now=future):
    rotate_master("scheduled 24-month renewal", now=future)
km.print_status()

banner("Audit log")
km.print_audit()
