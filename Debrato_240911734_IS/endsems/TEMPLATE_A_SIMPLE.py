"""TEMPLATE A: simple standalone exam menu, NOT a complete crypto scenario.

EDIT ONLY:
  (1) The functions between START TASKS / END TASKS.
  (2) ACTIONS: which menu labels call which function.
  (3) ROLES: which roles may use which actions.

Inputs and cryptography required by the exam belong inside your task functions.
"""
import hashlib
import hmac
import json
import os
from getpass import getpass
from pathlib import Path


# ===== GENERAL HELPERS: KEEP THESE =====
def save_json(path, obj, private=False):
    """Save JSON without leaving a partly written target file."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
        if private:
            tmp.chmod(0o600)  # Debian/Linux
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def save_record(ctx, record_id, record):
    """Store a JSON-serializable record. Encrypt sensitive fields FIRST."""
    if not record_id or record_id in ctx["records"]:
        raise ValueError("Record ID must be new and nonempty")
    # Check serialization before changing the in-memory database.
    json.dumps(record)
    ctx["records"][record_id] = record
    save_json(ctx["data_file"], ctx["records"])


def get_record(ctx):
    """Ask for an ID and fetch the corresponding stored record."""
    record_id = input("Record ID: ").strip()
    if record_id not in ctx["records"]:
        raise ValueError("Record not found")
    return record_id, ctx["records"][record_id]


def save_keys(ctx):
    """Call after creating or changing cryptographic keys in ctx['keys']."""
    save_json(ctx["key_file"], ctx["keys"], private=True)


# ===== START TASKS: EDIT THESE FOR YOUR EXAM QUESTION =====
# The four functions below are WORKING SHA-256 EXAMPLES, not a full scenario.
# Replace them with operations needed by the question (AES, RSA, Paillier, etc.).

def hash_text(ctx):
    message = input("Message: ").encode()
    print("SHA-256:", hashlib.sha256(message).hexdigest())


def submit_record(ctx):
    record_id = input("Record ID: ").strip()
    message = input("Message to hash (demo): ").encode()
    # EXAMPLE ONLY. A confidentiality question needs ENCRYPTION before saving.
    row = {"sha256": hashlib.sha256(message).hexdigest()}
    save_record(ctx, record_id, row)
    print("Saved:", record_id)


def verify_record(ctx):
    record_id, row = get_record(ctx)
    message = input("Re-enter original message: ").encode()
    actual = hashlib.sha256(message).hexdigest()
    wanted = row["sha256"]
    print(record_id, "VALID" if hmac.compare_digest(actual, wanted) else "FAILED")


def list_ids(ctx):
    print("Saved IDs:", ", ".join(ctx["records"]) or "(none)")

# ===== END TASKS =====


# ===== EDIT 2: CONNECT MENU LABELS TO TASK FUNCTIONS =====
# Format: "task_code": ("text shown in menu", function_name)
ACTIONS = {
    "hash": ("Hash message (example)", hash_text),
    "submit": ("Submit record (example)", submit_record),
    "verify": ("Verify record (example)", verify_record),
    "list": ("List record IDs", list_ids),
}

# ===== EDIT 3: CHOOSE ROLES AND THEIR ALLOWED TASK CODES =====
# Change these names to those GIVEN BY THE EXAM QUESTION.
# Example: {"Researcher": ["submit", "list"], "Reviewer": ["verify", "list"]}
ROLES = {
    "Role 1": ["hash", "submit", "list"],
    "Role 2": ["verify", "list"],
}


# ===== MENU + FILE STORAGE + PASSWORDS: DO NOT EDIT =====
def init_context():
    key_name = input("Key file (example: keys.json): ").strip()
    data_name = input("Data file (example: records.json): ").strip()
    if not key_name or not data_name:
        raise ValueError("Both filenames are required")
    key_file, data_file = Path(key_name).expanduser(), Path(data_name).expanduser()
    if key_file.resolve() == data_file.resolve():
        raise ValueError("Keys and records must use different files")
    if key_file.exists() != data_file.exists():
        raise ValueError("Keys/records must be restored as a pair")

    if key_file.exists():
        keys = json.loads(key_file.read_text(encoding="utf-8"))
        records = json.loads(data_file.read_text(encoding="utf-8"))
    else:
        keys, records = {"role_passwords": {}}, {}
        for role in ROLES:
            password = getpass(f"Create password for {role}: ")
            if not password:
                raise ValueError("Empty password")
            salt = os.urandom(16)
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
            keys["role_passwords"][role] = {"salt": salt.hex(), "digest": digest.hex()}
        save_json(key_file, keys, private=True)
        save_json(data_file, records)

    if not isinstance(keys, dict) or not isinstance(records, dict):
        raise ValueError("Invalid JSON data")
    if not isinstance(keys.get("role_passwords"), dict):
        raise ValueError("Invalid role passwords")
    if any(role not in keys["role_passwords"] for role in ROLES):
        raise ValueError("New role detected: use NEW filenames for a new exam scenario")
    return {"keys": keys, "records": records,
            "key_file": key_file, "data_file": data_file}


def login(ctx, role):
    info = ctx["keys"]["role_passwords"][role]
    actual = hashlib.pbkdf2_hmac(
        "sha256", getpass("Password: ").encode(),
        bytes.fromhex(info["salt"]), 200_000
    )
    return hmac.compare_digest(actual.hex(), info["digest"])


def main():
    if not ROLES or any(not allowed or any(code not in ACTIONS for code in allowed)
                        for allowed in ROLES.values()):
        raise ValueError("Check ACTIONS and ROLES: missing/unknown task codes")
    ctx = init_context()
    role_names = list(ROLES)
    while True:
        print("\n=== MAIN MENU ===")
        for number, name in enumerate(role_names, 1):
            print(f"{number}. {name}")
        print("0. Exit")
        choice = input("Select role: ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(role_names):
            print("Invalid role")
            continue
        role = role_names[int(choice) - 1]
        if not login(ctx, role):
            print("Access denied")
            continue
        permitted = ROLES[role]
        while True:
            print(f"\n=== {role.upper()} MENU ===")
            for number, code in enumerate(permitted, 1):
                print(f"{number}. {ACTIONS[code][0]}")
            print("0. Back")
            picked = input("Choice: ").strip()
            if picked == "0":
                break
            if not picked.isdigit() or not 1 <= int(picked) <= len(permitted):
                print("Invalid choice")
                continue
            task_code = permitted[int(picked) - 1]
            try:
                ACTIONS[task_code][1](ctx)
            except (ValueError, KeyError, TypeError, OSError, OverflowError) as exc:
                print("Error:", exc)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print("Startup error:", exc)
