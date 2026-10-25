"""NATIONAL E-VOTING SYSTEM  (menu-driven, role-based access control)

Demo logins:  admin/admin123 (Admin)   server/srv123 (Election Server)   auditor/aud123 (Auditor)
              trustee1/t1pass  trustee2/t2pass  trustee3/t3pass (Election Commission trustees)
              Voters register themselves from the main menu.
Client side (Voter -> Cast vote)
  * ballot = {voter, candidate, constituency, nonce, SHA-256 of the encrypted vote}
  * SHA-512 hash of the ballot                                      -> integrity
  * AES-256-CBC encryption of the ballot                            -> confidentiality
  * AES key encrypted with the Election Commission's RSA-4096 key   -> key transport
  * ElGamal signature of the SHA-512 hash (voter's own key)         -> authenticity, non-repudiation
  * Paillier encryption of the candidate (tally)                    -> counting without decrypting
  * trusted timestamp (Timestamp Authority RSA signature)           -> proof of submission time
Server side
  * RSA-4096 unwraps the AES key, ballot decrypted, SHA-512 compared, ElGamal signature
    and timestamp verified, voting period checked; Paillier votes stay encrypted
  * homomorphic tally = product of the Paillier ciphertexts of all valid ballots
  * searchable index: HMAC tokens of constituency / date / hour -> ballot ids (no vote content)
  * results: Paillier private key split 2-of-3 between trustees (Shamir) -> threshold
    decryption of ONLY the final aggregate; nobody ever holds the whole private key
Storage: evote_keys.json (keys, first run) and evote_db.json (voters, ballots, index, tally)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from islib import *

HERE = pathlib.Path(__file__).resolve().parent
KEYS_FILE, DB_FILE = HERE / "evote_keys.json", HERE / "evote_db.json"
CANDIDATES = ["Candidate A", "Candidate B", "Candidate C", "NOTA"]
TRUSTEES, THRESHOLD = ["trustee1", "trustee2", "trustee3"], 2
STAFF = {"admin": ("Admin", "admin123"), "server": ("Election Server", "srv123"),
         "auditor": ("Auditor", "aud123"), "trustee1": ("Trustee", "t1pass"),
         "trustee2": ("Trustee", "t2pass"), "trustee3": ("Trustee", "t3pass")}
TIME_FMT = "%Y-%m-%d %H:%M"                       # how dates are typed in


def make_keys():
    print("  generating RSA-4096 (Election Commission), RSA-2048 (Timestamp Authority), Paillier ...")
    ec, tsa = generate_keys("rsa", 4096), generate_keys("rsa", 2048)
    pub, shares = generate_keys("paillier", 2048, threshold=(THRESHOLD, len(TRUSTEES)))  # no full key
    return {
        "ec_priv": ec.export_key().decode(), "ec_pub": ec.publickey().export_key().decode(),
        "tsa_priv": tsa.export_key().decode(), "tsa_pub": tsa.publickey().export_key().decode(),
        "paillier_pub": pub,
        "trustee_shares": {t: password_seal(STAFF[t][1], s) for t, s in zip(TRUSTEES, shares)},
        "index_key": get_random_bytes(32).hex(),
        "users": {u: {"role": r, "pw": password_hash(pw)} for u, (r, pw) in STAFF.items()},
    }


K = json_store(KEYS_FILE, create=make_keys)
EC_PRIV, EC_PUB = RSA.import_key(K["ec_priv"]), RSA.import_key(K["ec_pub"])
TSA_PRIV, TSA_PUB = RSA.import_key(K["tsa_priv"]), RSA.import_key(K["tsa_pub"])
P_PUB, INDEX_KEY = K["paillier_pub"], bytes.fromhex(K["index_key"])
now = datetime.now()
db = json_store(DB_FILE, default={"voters": {}, "ballots": [], "index": {}, "tally": None,
                                  "period": [(now - timedelta(hours=1)).isoformat(timespec="seconds"),
                                             (now + timedelta(days=1)).isoformat(timespec="seconds")]})


def save():
    json_store(DB_FILE, db)


def period():
    return tuple(datetime.fromisoformat(t) for t in db["period"])


def ballot_table(ballots):
    print_table(["Ballot", "Voter", "SHA-512", "Timestamp", "Status"],
                [[b["id"], b["voter"], fmt(b["sha512"], "short", 16), b["timestamp"]["time"], b["status"]]
                 for b in ballots])


def index_add(keyword, ballot_id):
    db["index"].setdefault(search_token(INDEX_KEY, keyword), []).append(ballot_id)


def index_search(keyword):
    ids = set(db["index"].get(search_token(INDEX_KEY, keyword), []))
    return [b for b in db["ballots"] if b["id"] in ids]


# ---------------- Voter (client side) ----------------
def register():
    vid = ask("New Voter ID (3-12 letters/digits)", cast=str.upper,
              valid=lambda v: re.fullmatch(r"[A-Z0-9]{3,12}", v) is not None, error="3-12 letters/digits")
    if vid in db["voters"] or vid.lower() in STAFF:
        print("  ! that ID is already registered")
        return
    pw = ask("Choose a password (min 4 chars)", valid=lambda v: len(v) >= 4, secret=True,
             error="at least 4 characters")
    p, g, y, x = generate_keys("elgamal", 1024)                          # voter's signing key
    db["voters"][vid] = {"pw": password_hash(pw), "elgamal_pub": [p, g, y],
                         "elgamal_priv": password_seal(pw, x), "voted": False}
    save()
    print(f"  Registered {vid}; ElGamal public key y = {fmt(y, 'short', 30)} (private key sealed with your password)")


def cast_vote(vid):
    voter = db["voters"][vid]
    if voter["voted"]:
        print("  ! you have already voted")
        return
    for i, c in enumerate(CANDIDATES, 1):
        print(f"    {i}. {c}")
    cand = ask("Candidate number", cast=int, valid=lambda k: 1 <= k <= len(CANDIDATES),
               error=f"choose 1-{len(CANDIDATES)}")
    const = ask("Constituency ID (e.g. KA-21)", cast=str.upper,
                valid=lambda v: re.fullmatch(r"[A-Z]{2}-\d{1,3}", v) is not None, error="format XX-123")
    try:
        x = password_seal(ask("Password to unlock your signing key", secret=True),
                          voter["elgamal_priv"], unseal=True)
    except ValueError as e:
        print(f"  ! {e}")
        return

    vote_ct = paillier_cipher(tally(cand - 1), P_PUB)                    # Paillier vote
    ballot = canonical({"voter": vid, "candidate": cand, "constituency": const,
                        "nonce": secrets.token_hex(8), "vote_ct_sha256": hash_hex(str(vote_ct))})
    digest = hash_hex(ballot, "sha512")                                  # SHA-512
    aes_key = get_random_bytes(32)
    ct, iv = symmetric("AES", aes_key, ballot, "CBC")                    # AES-256-CBC
    wrapped = rsa_cipher(aes_key, EC_PUB)                                # RSA-4096 OAEP
    p, g, y = voter["elgamal_pub"]
    sig = signature("elgamal", ballot, (p, g, x), algo="sha512")         # ElGamal on SHA-512
    ts = timestamp(TSA_PRIV, digest)                                     # trusted timestamp

    b = {"id": f"B{len(db['ballots']) + 1:04d}", "voter": vid, "sha512": digest, "ballot_ct": ct.hex(),
         "iv": iv.hex(), "wrapped_key": wrapped.hex(), "elgamal_sig": list(sig),
         "vote_ct": str(vote_ct), "timestamp": ts, "status": "submitted"}
    db["ballots"].append(b)
    voter["voted"] = True
    save()
    print(f"\n  Ballot {b['id']} submitted")
    print(f"    SHA-512 hash        : {fmt(digest, 'short', 48)}")
    print(f"    AES-256-CBC ballot  : {fmt(b['ballot_ct'], 'short', 48)}")
    print(f"    RSA-4096 wrapped key: {fmt(b['wrapped_key'], 'short', 48)}")
    print(f"    ElGamal sig (r, s)  : ({fmt(sig[0], 'short', 20)}, {fmt(sig[1], 'short', 20)})")
    print(f"    Paillier vote       : {fmt(vote_ct, 'short', 48)}")
    print(f"    Timestamp           : {ts['time']}  TSA sig {fmt(ts['sig'], 'short', 20)}")


def my_receipt(vid):
    mine = [b for b in db["ballots"] if b["voter"] == vid]
    if mine:
        ballot_table(mine)
    else:
        print("  (no ballot cast yet)")


# ---------------- Election Server ----------------
def check_ballot(b):
    """Returns (None, ballot_dict) if valid, else (reason, None)."""
    start, end = period()
    try:
        aes_key = rsa_cipher(bytes.fromhex(b["wrapped_key"]), EC_PRIV, decrypt=True)   # RSA-4096 private
        ballot = symmetric("AES", aes_key, bytes.fromhex(b["ballot_ct"]), "CBC", decrypt=True,
                           iv=bytes.fromhex(b["iv"]))
        data = json.loads(ballot)
    except ValueError:
        return "cannot decrypt (tampered key or ballot)", None
    if hash_hex(ballot, "sha512") != b["sha512"]:
        return "SHA-512 hash mismatch", None
    voter = db["voters"].get(data.get("voter"))
    if not voter or data["voter"] != b["voter"]:
        return "unknown voter", None
    if not signature("elgamal", ballot, voter["elgamal_pub"], sig=b["elgamal_sig"], algo="sha512"):
        return "invalid ElGamal signature", None
    if data.get("vote_ct_sha256") != hash_hex(b["vote_ct"]):
        return "encrypted vote was replaced", None
    if not timestamp(TSA_PUB, b["sha512"], b["timestamp"]):
        return "invalid timestamp signature", None
    if not timestamp(TSA_PUB, b["sha512"], b["timestamp"], start, end):
        return "cast outside the voting period", None
    return None, data


def verify_ballots():
    pending = [b for b in db["ballots"] if b["status"] == "submitted"]
    if not pending:
        print("  (no new ballots)")
        return
    for b in pending:
        reason, data = check_ballot(b)
        b["status"] = "valid" if reason is None else f"REJECTED: {reason}"
        if data:                                                         # searchable index
            t = datetime.fromisoformat(b["timestamp"]["time"])
            for kw in (f"const:{data['constituency']}", f"date:{t:%Y-%m-%d}", f"hour:{t:%Y-%m-%d %H}"):
                index_add(kw, b["id"])
        print(f"  {b['id']}: AES key unwrapped, SHA-512 compared, ElGamal + timestamp checked -> {b['status']}")
    db["tally"] = None                                                   # recompute after new ballots
    save()


def compute_tally():
    valid = []
    for b in db["ballots"]:
        if b["status"] != "valid":
            continue
        reason, _ = check_ballot(b)                                      # re-check before counting
        if reason:
            b["status"] = f"REJECTED: {reason}"
            print(f"  {b['id']} excluded: {reason}")
        else:
            valid.append(b)
    if not valid:
        print("  ! no valid ballots to tally")
        db["tally"] = None
        save()
        return
    enc = homomorphic("paillier", [int(b["vote_ct"]) for b in valid], P_PUB)   # homomorphic tally
    db["tally"] = {"ciphertext": str(enc), "ballots": len(valid),
                   "computed": datetime.now().isoformat(timespec="seconds")}
    save()
    print(f"  Encrypted tally of {len(valid)} ballot(s): {fmt(enc, 'short', 60)}")
    print("  (no individual vote was decrypted)")


def view_ballots():
    if db["ballots"]:
        ballot_table(db["ballots"])
    else:
        print("  (no ballots)")


# ---------------- Auditor (searchable index) ----------------
def search_constituency():
    const = ask("Constituency ID", cast=str.upper)
    hits = index_search(f"const:{const}")
    print(f"  token {search_token(INDEX_KEY, 'const:' + const)[:16]}... -> {len(hits)} ballot(s)")
    if hits:
        ballot_table(hits)


def search_time_range():
    start = ask(f"From ({TIME_FMT.replace('%', '')})", cast=lambda s: datetime.strptime(s, TIME_FMT))
    end = ask(f"To   ({TIME_FMT.replace('%', '')})", cast=lambda s: datetime.strptime(s, TIME_FMT),
              valid=lambda e: e >= start and e - start <= timedelta(days=31),
              error="must be after From, max 31 days")
    hits, hour = {}, start.replace(minute=0)
    while hour <= end:                                                   # one token per hour bucket
        for b in index_search(f"hour:{hour:%Y-%m-%d %H}"):
            if start <= datetime.fromisoformat(b["timestamp"]["time"]) <= end:
                hits[b["id"]] = b
        hour += timedelta(hours=1)
    print(f"  {len(hits)} ballot(s) between {start} and {end}")
    if hits:
        ballot_table(list(hits.values()))


# ---------------- Trustees (threshold decryption) ----------------
def decrypt_results():
    if not db["tally"]:
        print("  ! no tally yet - the Election Server must compute it first")
        return
    if datetime.now() < period()[1]:
        print(f"  ! election still open until {db['period'][1]} - results are sealed")
        return
    print(f"  {THRESHOLD} of {len(TRUSTEES)} trustees must provide their key shares")
    shares, used = [], set()
    while len(shares) < THRESHOLD:
        name = ask("Trustee username (or STOP)")
        if name.upper() == "STOP":
            break
        if name not in K["trustee_shares"] or name in used:
            print("  ! not a trustee, or share already given")
            continue
        try:
            shares.append(password_seal(ask("Trustee password", secret=True), K["trustee_shares"][name],
                                         unseal=True))
            used.add(name)
            print(f"  share from {name} accepted ({len(shares)}/{THRESHOLD})")
        except ValueError as e:
            print(f"  ! {e}")
    if len(shares) < THRESHOLD:
        print("  ! not enough trustees - the tally stays encrypted")
        return
    total = paillier_cipher(int(db["tally"]["ciphertext"]), shares, decrypt=True, pub=P_PUB)  # threshold
    counts = tally(total, decode=True, n_choices=len(CANDIDATES))
    banner(f"FINAL RESULT ({db['tally']['ballots']} valid ballots)")
    print_table(["Candidate", "Votes"], [[c, n] for c, n in zip(CANDIDATES, counts)])
    if sum(counts) != db["tally"]["ballots"]:
        print("  ! decoded count does not match the number of ballots")
    else:
        print(f"  Winner: {CANDIDATES[counts.index(max(counts))]}")


# ---------------- Admin ----------------
def set_period():
    start = ask(f"Voting starts ({TIME_FMT.replace('%', '')})", cast=lambda s: datetime.strptime(s, TIME_FMT))
    end = ask(f"Voting ends   ({TIME_FMT.replace('%', '')})", cast=lambda s: datetime.strptime(s, TIME_FMT),
              valid=lambda e: e > start, error="end must be after start")
    db["period"] = [start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")]
    db["tally"] = None                                                   # period changed -> recount
    save()
    print(f"  Voting period: {db['period'][0]} -> {db['period'][1]}")


def close_election():
    db["period"][1] = datetime.now().isoformat(timespec="seconds")
    save()
    print(f"  Election closed at {db['period'][1]}")


def list_voters():
    print_table(["Voter", "Voted", "ElGamal public y"],
                [[v, d["voted"], fmt(d["elgamal_pub"][2], "short", 24)] for v, d in db["voters"].items()])
    print(f"  Voting period: {db['period'][0]} -> {db['period'][1]}")


def tamper():
    bid = ask("Ballot ID to tamper (e.g. B0001)", cast=str.upper)
    b = next((x for x in db["ballots"] if x["id"] == bid), None)
    if not b:
        print("  ! no such ballot")
        return
    field = menu("Field to tamper", ["ballot_ct", "vote_ct", "timestamp", "elgamal_sig"])
    if field == "vote_ct":
        b[field] = str(paillier_cipher(tally(0), P_PUB))                # swap in a vote for candidate 1
    elif field == "timestamp":
        b[field]["time"] = (datetime.now() - timedelta(days=2)).isoformat(timespec="seconds")
    elif field == "elgamal_sig":
        b[field][1] += 1
    else:
        b[field] = b[field][:-2] + ("00" if b[field][-2:] != "00" else "11")
    save()
    print(f"  {field} of {bid} modified in {DB_FILE.name}")


def main():
    banner("NATIONAL E-VOTING SYSTEM")
    print(f"  {len(db['voters'])} voter(s), {len(db['ballots'])} ballot(s) loaded; "
          f"voting period {db['period'][0]} -> {db['period'][1]}")
    while True:
        choice = menu("Main menu", ["Login", "Register as voter", "Exit"])
        if choice == "Exit":
            print("  Bye")
            return
        if choice == "Register as voter":
            register()
            continue
        users = {**K["users"], **{v: {"role": "Voter", "pw": d["pw"]} for v, d in db["voters"].items()}}
        user, role = login(users)
        menus = {
            "Voter": {"Cast vote": lambda: cast_vote(user), "View my ballot receipt": lambda: my_receipt(user)},
            "Election Server": {"Verify submitted ballots": verify_ballots,
                                "Compute encrypted tally": compute_tally, "View stored ballots": view_ballots},
            "Auditor": {"Search ballots by constituency": search_constituency,
                        "Search ballots by time range": search_time_range, "View stored ballots": view_ballots},
            "Trustee": {"Threshold-decrypt final result": decrypt_results},
            "Admin": {"Set voting period": set_period, "Close election now": close_election,
                      "List voters": list_voters, "Simulate tampering of a ballot": tamper},
        }
        if role:
            menu(f"{role} menu ({user})", menus[role], "Logout")


if __name__ == "__main__":
    main()
