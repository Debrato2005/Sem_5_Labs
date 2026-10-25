"""EXAM TEMPLATE - menu-driven, role-based, persistent  (copy, rename, fill in the TODOs)
Question: <paste the question here>
Demo logins: user1/pass1 (Role A)   user2/pass2 (Role B)
Full worked examples: Exam_Examples/grant_portal.py, Exam_Examples/evoting.py"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from islib import *          # file inside a subfolder? use .parents[1] (or [2] for LabX/Exercises)

HERE = pathlib.Path(__file__).resolve().parent
KEYS_FILE, DB_FILE = HERE / "my_keys.json", HERE / "my_db.json"


def make_keys():                       # runs once; everything must be JSON-able (hex for bytes)
    rsa = generate_keys("rsa", 2048)
    pub, priv = generate_keys("paillier", 1024)
    return {"aes": get_random_bytes(32).hex(), "index_key": get_random_bytes(32).hex(),
            "rsa_priv": rsa.export_key().decode(), "rsa_pub": rsa.publickey().export_key().decode(),
            "paillier_pub": pub, "paillier_priv": priv,
            "users": {"user1": {"role": "Role A", "pw": password_hash("pass1")},
                      "user2": {"role": "Role B", "pw": password_hash("pass2")}}}


K = json_store(KEYS_FILE, create=make_keys)
AES_KEY, INDEX_KEY = bytes.fromhex(K["aes"]), bytes.fromhex(K["index_key"])
RSA_PRIV, RSA_PUB = RSA.import_key(K["rsa_priv"]), RSA.import_key(K["rsa_pub"])
P_PUB, P_PRIV = K["paillier_pub"], K["paillier_priv"]
db = json_store(DB_FILE, default={"records": []})


def signed_part(r):                    # the fields that are hashed + signed
    return canonical({k: r[k] for k in ("id", "data_ct", "iv", "value_ct")})


def add_record():                      # TODO: Role A action
    rid = ask("Record ID", cast=str.upper, valid=lambda v: v.isalnum(), error="letters/digits only")
    text = ask("Secret text")
    value = ask("Amount", cast=int, valid=lambda v: v >= 0, error="must be >= 0")
    ct, iv = symmetric("AES", AES_KEY, text, "CBC")
    r = {"id": rid, "data_ct": ct.hex(), "iv": iv.hex(), "value_ct": str(paillier_cipher(value, P_PUB)),
         "token": search_token(INDEX_KEY, rid)}
    r["hash"] = hash_hex(signed_part(r), "sha256")
    r["sig"] = signature("rsa", signed_part(r), RSA_PRIV).hex()
    db["records"].append(r)
    json_store(DB_FILE, db)
    print(f"  stored {rid}: hash {r['hash'][:16]}..., signature {fmt(r['sig'], 'short')}")


def verify_all():                      # TODO: Role B action
    for r in db["records"]:
        ok = hash_hex(signed_part(r)) == r["hash"] and \
            signature("rsa", signed_part(r), RSA_PUB, sig=bytes.fromhex(r["sig"]))
        print(f"  {r['id']}: {'OK' if ok else 'TAMPERED'}")


def total():                           # TODO: homomorphic aggregate, decrypt only the total
    enc = homomorphic("paillier", [int(r["value_ct"]) for r in db["records"]], P_PUB)
    print(f"  E(total) = {fmt(enc, 'short')}  ->  total = {paillier_cipher(enc, P_PRIV, decrypt=True)}")


ROLE_MENUS = {"Role A": {"Add record": add_record},
              "Role B": {"Verify all records": verify_all, "Compute total": total}}


def main():
    while True:
        choice = menu("Main menu", ["Login", "Exit"])
        if choice == "Exit":
            return
        user, role = login(K["users"])
        if role:
            menu(f"{role} menu ({user})", ROLE_MENUS[role], "Logout")


if __name__ == "__main__":
    main()
