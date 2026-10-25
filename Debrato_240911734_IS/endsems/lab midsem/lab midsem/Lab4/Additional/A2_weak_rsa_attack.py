"""Lab 4 - Additional 2  (XYZ Logistics - attack on weak RSA key generation)
Eve exploits primes p, q that are too small or too close together:
  Case 1: small primes  -> n factored directly (Pollard rho via sympy)
  Case 2: close primes  -> Fermat factorisation n = a^2 - b^2 succeeds instantly
Once p, q are known: phi = (p-1)(q-1), d = e^-1 mod phi -> all traffic can be decrypted.
To modify: SMALL_BITS, or paste a real (n, e, ciphertext) into rsa_weak_attack(n, e)
and decrypt with rsa_cipher(c, (d, n), decrypt=True, mode="textbook")."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *
from sympy import nextprime

SECRET = "Shipment 42 leaves dock 7 at 0300"
SMALL_BITS = ask("Bits of each small prime", 40)


def attack(label, p, q, e=65537):
    n = p * q
    banner(label)
    print(f"  Public key: n = {n} ({n.bit_length()} bits), e = {e}")
    c = rsa_cipher(SECRET, (e, n), mode="textbook")                          # intercepted ciphertext
    (fp, fq, d), t = timed(rsa_weak_attack, n, e)
    print(f"  Eve factors n in {t * 1000:.2f} ms: p = {fp}, q = {fq}")
    print(f"  Recovered d = {d}")
    print(f"  Correct d?  {d == pow(e, -1, (p - 1) * (q - 1))}")
    print(f"  Decrypted traffic: {rsa_cipher(c, (d, n), decrypt=True, mode='textbook')}")


attack("Case 1: primes too SMALL", getPrime(SMALL_BITS), getPrime(SMALL_BITS))
q = getPrime(1024)
attack("Case 2: 2048-bit n but primes too CLOSE (p = next prime after q + 2^20)",
       nextprime(q + 2 ** 20), q)

banner("Mitigation")
print("""  1. Use >= 2048-bit n (3072+ for long-term), each prime >= 1024 bits.
  2. Generate p and q independently with a CSPRNG (secrets / os.urandom) - never reuse
     seeds, never derive q from p; reject pairs with |p - q| < 2^(nbits/2 - 100) (FIPS 186-4).
  3. Use vetted libraries (RSA.generate / cryptography) instead of hand-written keygen.
  4. Use e = 65537 and OAEP / PSS padding, never textbook RSA.
  5. Protect private keys (HSM, encrypted storage); partial key leakage enables
     Coppersmith-style attacks, so rotate keys immediately on any exposure.
  6. Test generated moduli for shared factors (batch GCD) and small factors.""")
