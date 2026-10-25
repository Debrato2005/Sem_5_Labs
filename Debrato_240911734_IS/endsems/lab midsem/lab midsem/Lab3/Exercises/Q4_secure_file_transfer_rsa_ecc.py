"""Lab 3 - Exercise 4
Secure file transfer with RSA (2048-bit) and ECC (secp256r1). Generate/exchange keys,
encrypt and decrypt files of 1 MB and 10 MB, compare key-generation time,
encryption/decryption speed, key sizes and security.
Files are encrypted the standard (hybrid) way: an AES-256-GCM session key protects the
file, and RSA-OAEP / ECIES protects the session key.
To modify: FILE_SIZES_MB, RSA_BITS, CURVE."""
import sys, pathlib, tempfile; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

FILE_SIZES_MB = [1, 10]
RSA_BITS = ask("RSA bits", 2048)
CURVE = ask("ECC curve", "secp256r1")
work = pathlib.Path(tempfile.mkdtemp())

# --- key generation + "exchange" (public keys serialised as PEM, as they would be sent) ---
rsa_key, t_rsa_gen = timed(generate_keys, "rsa", RSA_BITS)
ecc_key, t_ecc_gen = timed(generate_keys, "ecc", curve=CURVE)
rsa_pub_pem = rsa_key.publickey().export_key()
ecc_pub_pem = ecc_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
rsa_pub = RSA.import_key(rsa_pub_pem)                                  # receiver side
ecc_pub = serialization.load_pem_public_key(ecc_pub_pem)

SCHEMES = {
    f"RSA-{RSA_BITS}": (lambda d: rsa_cipher(d, rsa_pub, mode="hybrid"),
                        lambda c: rsa_cipher(c, rsa_key, decrypt=True, mode="hybrid")),
    f"ECC-{CURVE}": (lambda d: ecc_cipher(d, ecc_pub), lambda c: ecc_cipher(c, ecc_key, decrypt=True)),
}

rows, chart = [], {}
for mb in FILE_SIZES_MB:
    src = work / f"file_{mb}MB.bin"
    src.write_bytes(os.urandom(mb * 1024 * 1024))
    for name, (enc, dec) in SCHEMES.items():
        ct, t_enc = timed(enc, src.read_bytes())
        (work / f"{src.name}.{name}.enc").write_bytes(ct)                   # "transfer"
        pt, t_dec = timed(dec, ct)
        ok = pt == src.read_bytes()
        rows.append([name, f"{mb} MB", t_enc * 1000, t_dec * 1000, mb / t_enc, ok])
        chart.setdefault(f"{mb} MB", {})[f"{name} enc"] = t_enc * 1000
        chart[f"{mb} MB"][f"{name} dec"] = t_dec * 1000

banner("Key generation and key sizes")
print_table(["Scheme", "Keygen ms", "Public key bytes (PEM)", "Private key bytes (PEM)"], [
    [f"RSA-{RSA_BITS}", t_rsa_gen * 1000, len(rsa_pub_pem), len(rsa_key.export_key())],
    [f"ECC-{CURVE}", t_ecc_gen * 1000, len(ecc_pub_pem), len(ecc_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))]])

banner("File encryption / decryption")
print_table(["Scheme", "File", "Encrypt ms", "Decrypt ms", "MB/s enc", "Correct"], rows)
plot(chart, "Secure file transfer: RSA vs ECC", "time (ms)", "file_transfer_rsa_ecc.png")

print("""
Summary
 * Key generation: ECC is far faster (RSA must find two 1024-bit primes).
 * Key size: ECC-256 ~ 3072-bit RSA security with ~10x smaller keys -> less storage/bandwidth.
 * Bulk speed: almost identical, because AES-GCM does the bulk work in both; only the
   session-key step differs (RSA decrypt is the slowest single operation).
 * Attacks: RSA - factoring, needs OAEP padding (textbook RSA is malleable);
   ECC - ECDLP, needs a vetted curve and good randomness for ephemeral keys.
 * Neither alone authenticates the sender -> add signatures (Lab 6) in a real system.""")
