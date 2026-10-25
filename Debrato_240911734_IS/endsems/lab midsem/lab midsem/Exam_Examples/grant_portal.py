"""SECURE GRANT EXPENSE PORTAL  (menu-driven, role-based)

Roles and demo logins:   researcher / res123    reviewer / rev123    finance / fin123
Crypto used
  * AES-192 (CBC)      grant description                      -> confidentiality
  * Paillier           grant amount (stored in paise/cents)   -> confidential + additive
  * MD5                hash of the stored record              -> integrity
  * RSA-2048 PKCS#1    signature of the MD5 hash              -> authenticity
  * HMAC index token   search by Grant ID without decrypting  -> searchable index
Storage: grant_keys.json (keys, created on first run) and grant_db.json (records),
both next to this file, so earlier records are still there after a restart.
The "Simulate tampering" option edits a stored record so you can show detection."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from islib import *

HERE = pathlib.Path(__file__).resolve().parent
KEYS_FILE, DB_FILE = HERE / "grant_keys.json", HERE / "grant_db.json"


def make_keys():
    rsa = generate_keys("rsa", 2048)
    pub, priv = generate_keys("paillier", 1024)
    return {
        "aes192": get_random_bytes(24).hex(),
        "index_key": get_random_bytes(32).hex(),
        "rsa_priv": rsa.export_key().decode(),
        "rsa_pub": rsa.publickey().export_key().decode(),
        "paillier_pub": pub, "paillier_priv": priv,
        "users": {"researcher": {"role": "Researcher", "pw": password_hash("res123")},
                  "reviewer": {"role": "Reviewer", "pw": password_hash("rev123")},
                  "finance": {"role": "Finance Officer", "pw": password_hash("fin123")}},
    }


K = json_store(KEYS_FILE, create=make_keys)
AES_KEY, INDEX_KEY = bytes.fromhex(K["aes192"]), bytes.fromhex(K["index_key"])
RSA_PRIV, RSA_PUB = RSA.import_key(K["rsa_priv"]), RSA.import_key(K["rsa_pub"])
P_PUB, P_PRIV = K["paillier_pub"], K["paillier_priv"]
db = json_store(DB_FILE, default={"records": []})


# ---------- record helpers ----------
def signed_part(r):
    """The fields that are hashed and signed (all ciphertext - no plaintext is stored)."""
    return canonical({k: r.get(k) for k in ("grant_id", "desc_iv", "desc_ct", "amount_ct")})


def check(r):
    """(hash_ok, signature_ok) for one record."""
    hash_ok = hash_hex(signed_part(r), "md5") == r.get("md5")
    try:
        sig_ok = signature("rsa", signed_part(r), RSA_PUB, sig=bytes.fromhex(r.get("signature", "")),
                           algo="md5")
    except ValueError:
        sig_ok = False
    return hash_ok, sig_ok


def status(r):
    h, s = check(r)
    return "OK" if h and s else "TAMPERED (" + ", ".join(
        x for x, ok in (("hash mismatch", h), ("bad signature", s)) if not ok) + ")"


def find(gid):
    """Search the index: token of the Grant ID -> matching record (contents stay encrypted)."""
    tok = search_token(INDEX_KEY, gid)
    return next((r for r in db["records"] if r["index_token"] == tok), None)


def ask_existing_id():
    gid = ask("Grant ID")
    r = find(gid)
    if not r:
        print(f"  ! no record with Grant ID '{gid}'")
    return r


# ---------- Researcher ----------
def submit():
    gid = ask("Grant ID (letters/digits/-)", cast=str.upper,
              valid=lambda v: re.fullmatch(r"[A-Z0-9-]{1,20}", v) is not None, error="use letters, digits, -")
    if find(gid):
        print(f"  ! Grant ID {gid} already exists")
        return
    desc = ask("Grant description")
    amount = ask("Grant amount (e.g. 125000.50)", cast=float, valid=lambda v: 0 < v < 1e12,
                 error="must be > 0")
    ct, iv = symmetric("AES", AES_KEY, desc, "CBC")                         # AES-192
    rec = {"grant_id": gid, "desc_iv": iv.hex(), "desc_ct": ct.hex(),
           "amount_ct": str(paillier_cipher(round(amount * 100), P_PUB)),   # Paillier
           "index_token": search_token(INDEX_KEY, gid),
           "submitted": datetime.now().isoformat(timespec="seconds")}
    rec["md5"] = hash_hex(signed_part(rec), "md5")                          # MD5
    rec["signature"] = signature("rsa", signed_part(rec), RSA_PRIV, algo="md5").hex()   # RSA sign MD5
    db["records"].append(rec)
    json_store(DB_FILE, db)
    print(f"\n  Stored grant {gid}")
    print(f"    AES-192 description : {fmt(rec['desc_ct'], 'short', 40)}")
    print(f"    Paillier amount     : {fmt(rec['amount_ct'], 'short', 40)}")
    print(f"    MD5 hash            : {rec['md5']}")
    print(f"    RSA signature       : {fmt(rec['signature'], 'short', 40)}")


def view_all():
    if not db["records"]:
        print("  (no records yet)")
        return
    print_table(["Grant ID", "Submitted", "Description (AES-192)", "Amount (Paillier)", "MD5", "Signature"],
                [[r["grant_id"], r["submitted"], fmt(r["desc_ct"], "short", 16),
                  fmt(r["amount_ct"], "short", 16), r["md5"], fmt(r["signature"], "short", 12)]
                 for r in db["records"]])
    print(f"  {len(db['records'])} record(s) in {DB_FILE.name}")


# ---------- Reviewer ----------
def verify_all():
    if not db["records"]:
        print("  (no records)")
        return
    rows = []
    for r in db["records"]:
        h, s = check(r)
        rows.append([r["grant_id"], hash_hex(signed_part(r), "md5"), "match" if h else "MISMATCH",
                     "valid" if s else "INVALID", status(r)])
    print_table(["Grant ID", "Recomputed MD5", "Hash", "RSA signature", "Status"], rows)


def search():
    r = ask_existing_id()
    if r:
        print(f"  Found via index token {r['index_token'][:16]}...")
        print(f"    Grant ID {r['grant_id']}, submitted {r['submitted']}, status: {status(r)}")
        print(f"    description: <encrypted, {len(r['desc_ct']) // 2} bytes>, amount: <encrypted>")


def view_hex():
    r = ask_existing_id()
    if not r:
        return
    st = status(r)
    if st != "OK":
        print(f"  ! WARNING: record is {st}")
    try:
        pt = symmetric("AES", AES_KEY, bytes.fromhex(r["desc_ct"]), "CBC", decrypt=True,
                       iv=bytes.fromhex(r["desc_iv"]))
    except ValueError:
        print("  ! decryption failed - ciphertext has been tampered with")
        return
    print(f"  AES-192 decrypted description of {r['grant_id']} (hex dump):")
    print(fmt(pt, "dump"))


# ---------- Finance Officer ----------
def aggregate():
    if not db["records"]:
        print("  (no records)")
        return
    print("  Available grants:", ", ".join(r["grant_id"] for r in db["records"]))
    sel = ask("Grant IDs to total (comma separated, or ALL)", cast=str.upper)
    if sel == "ALL":
        chosen = db["records"]
    else:
        chosen = []
        for gid in [x.strip() for x in sel.split(",") if x.strip()]:
            r = find(gid)
            if r:
                chosen.append(r)
            else:
                print(f"  ! unknown Grant ID {gid} - skipped")
    valid = []
    for r in chosen:
        st = status(r)
        print(f"  {r['grant_id']:<10} signature/hash: {st}")
        if st == "OK":
            valid.append(r)
    if not valid:
        print("  ! no valid grants selected")
        return
    enc_total = homomorphic("paillier", [int(r["amount_ct"]) for r in valid], P_PUB)   # homomorphic add
    print(f"\n  Encrypted aggregate E(sum) = {fmt(enc_total, 'short', 48)}")
    total = paillier_cipher(enc_total, P_PRIV, decrypt=True) / 100          # only the total
    print(f"  Decrypted TOTAL of {len(valid)} grant(s) = {total:,.2f}")
    print("  (individual amounts were never decrypted)")


# ---------- demo: attacker edits the stored file ----------
def tamper():
    r = ask_existing_id()
    if not r:
        return
    field = menu("Field to tamper", ["amount_ct", "desc_ct", "signature"])
    v = r[field]
    if field == "amount_ct":
        r[field] = str(paillier_cipher(99999999, P_PUB))          # attacker substitutes an amount
    else:
        r[field] = v[:-2] + ("00" if v[-2:] != "00" else "11")    # flip the last byte
    json_store(DB_FILE, db)
    print(f"  {field} of {r['grant_id']} modified in {DB_FILE.name}")


ROLE_MENUS = {
    "Researcher": {"Submit grant details": submit, "View all submitted records": view_all},
    "Reviewer": {"Verify signatures + MD5 of all records": verify_all,
                 "Search record by Grant ID (index)": search,
                 "View decrypted description (hex dump)": view_hex},
    "Finance Officer": {"Aggregate selected grant amounts": aggregate},
}


def main():
    banner("SECURE GRANT EXPENSE PORTAL")
    print(f"  {len(db['records'])} stored record(s) loaded from {DB_FILE.name}")
    while True:
        choice = menu("Main menu", ["Login", "Simulate tampering (attacker)", "Exit"])
        if choice == "Exit":
            print("  Bye")
            return
        if choice.startswith("Simulate"):
            tamper()
            continue
        user, role = login(K["users"])
        if role:
            menu(f"{role} menu ({user})", ROLE_MENUS[role], "Logout")


if __name__ == "__main__":
    main()
