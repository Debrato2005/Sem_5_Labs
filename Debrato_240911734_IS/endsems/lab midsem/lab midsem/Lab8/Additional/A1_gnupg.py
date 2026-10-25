"""Lab 8 - Additional 1  GnuPG: secure storage + transmission + digital signature
Needs the gpg program (preinstalled on most Linux; else sudo apt install gnupg)
and the python-gnupg package:  pip3 install --user python-gnupg
Flow: Alice and Bob create key pairs -> Alice encrypts a file for Bob and signs it ->
file is "transmitted" -> Bob decrypts and verifies Alice's signature -> tampering detected.
Uses a throw-away keyring in a temp folder, so your real keyring is untouched.
Equivalent terminal commands are printed at the end (useful if python-gnupg is missing)."""
import sys, pathlib, tempfile; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

CLI = """
gpg --batch --passphrase '' --quick-gen-key "Alice <alice@lab.local>" rsa2048 default never
gpg --batch --passphrase '' --quick-gen-key "Bob <bob@lab.local>"     rsa2048 default never
gpg --armor --export bob@lab.local > bob_pub.asc               # Bob shares his public key
gpg --import bob_pub.asc                                       # Alice imports it
gpg --armor --sign --encrypt -u alice@lab.local -r bob@lab.local -o secret.asc secret.txt
gpg --decrypt -o received.txt secret.asc                       # Bob: decrypts + shows "Good signature"
gpg --armor --detach-sign -u alice@lab.local secret.txt        # separate signature file
gpg --verify secret.txt.asc secret.txt
gpg --symmetric --cipher-algo AES256 secret.txt                # secure storage with a passphrase
"""

if not gpg_available():
    print("gpg / python-gnupg not installed - install them (see top of file) and rerun.")
    print("Terminal commands that do the same thing:\n" + CLI)
    sys.exit(0)

import gnupg

home = tempfile.mkdtemp()
gpg = gnupg.GPG(gnupghome=home)
work = pathlib.Path(home)

banner("1. Key generation")
for name in ["Alice", "Bob"]:
    key = gpg.gen_key(gpg.gen_key_input(name_real=name, name_email=f"{name.lower()}@lab.local",
                                        key_type="RSA", key_length=2048, no_protection=True))
    print(f"  {name}: fingerprint {key.fingerprint}")

banner("2. Secure storage + transmission: Alice signs and encrypts for Bob")
secret = ask("Data", "Quarterly results: profit up 12%")
enc = gpg.encrypt(secret, "bob@lab.local", sign="alice@lab.local", always_trust=True)
(work / "secret.asc").write_text(str(enc))
print("  status:", enc.status)
print(" ", str(enc).splitlines()[0], "...", f"({len(str(enc))} chars, saved to secret.asc)")

banner("3. Bob receives, decrypts and verifies the signature")
dec = gpg.decrypt((work / "secret.asc").read_text(), always_trust=True)
print(f"  plaintext : {dec.data.decode()}")
print(f"  signature : valid={dec.valid}, signer={dec.username}, trust={dec.trust_text}")

banner("4. Detached signature + tampering")
sig = gpg.sign(secret, keyid="alice@lab.local", detach=True)
(work / "data.txt").write_text(secret)
(work / "data.sig").write_bytes(sig.data)
ok = gpg.verify_data(str(work / "data.sig"), secret.encode())
bad = gpg.verify_data(str(work / "data.sig"), secret.replace("12", "92").encode())
print(f"  original data verified: {ok.valid}\n  tampered data verified: {bad.valid}")

print("\nSame steps from the terminal:" + CLI)
