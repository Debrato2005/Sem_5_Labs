import secrets
import time
import hashlib


# ---------------------------------------------------------
# DIFFIE-HELLMAN PUBLIC PARAMETERS
# ---------------------------------------------------------

# 2048-bit MODP prime
p = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)

g = 2


# ---------------------------------------------------------
# PEER A KEY GENERATION
# ---------------------------------------------------------

start = time.perf_counter()

# Private key
a = secrets.randbelow(p - 2) + 2

# Public key
# A = g^a mod p
A = pow(g, a, p)

peer_a_keygen_time = time.perf_counter() - start


# ---------------------------------------------------------
# PEER B KEY GENERATION
# ---------------------------------------------------------

start = time.perf_counter()

# Private key
b = secrets.randbelow(p - 2) + 2

# Public key
# B = g^b mod p
B = pow(g, b, p)

peer_b_keygen_time = time.perf_counter() - start


# ---------------------------------------------------------
# PUBLIC KEY EXCHANGE
# ---------------------------------------------------------

# Peer A sends A to Peer B
# Peer B sends B to Peer A
#
# A and B may travel over an insecure network.


# ---------------------------------------------------------
# PEER A COMPUTES SHARED SECRET
# ---------------------------------------------------------

start = time.perf_counter()

# S = B^a mod p
shared_secret_A = pow(B, a, p)

peer_a_exchange_time = time.perf_counter() - start


# ---------------------------------------------------------
# PEER B COMPUTES SHARED SECRET
# ---------------------------------------------------------

start = time.perf_counter()

# S = A^b mod p
shared_secret_B = pow(A, b, p)

peer_b_exchange_time = time.perf_counter() - start


# ---------------------------------------------------------
# VERIFY SHARED SECRET
# ---------------------------------------------------------

if shared_secret_A == shared_secret_B:
    print("\nShared secret successfully established.")
else:
    print("\nERROR: Shared secrets do not match.")


# ---------------------------------------------------------
# DERIVE A 256-BIT KEY FROM SHARED SECRET
# ---------------------------------------------------------

secret_bytes = shared_secret_A.to_bytes(
    (shared_secret_A.bit_length() + 7) // 8,
    byteorder="big"
)

shared_key = hashlib.sha256(secret_bytes).digest()


# ---------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------

print("\n========== DIFFIE-HELLMAN ==========")

print("\nPublic parameters:")
print("Prime size:", p.bit_length(), "bits")
print("Generator :", g)


print("\nPeer A:")
print("Private key generated")
print("Public key A =", A)


print("\nPeer B:")
print("Private key generated")
print("Public key B =", B)


print("\nDerived 256-bit shared key:")
print(shared_key.hex().upper())


print("\n========== PERFORMANCE ==========")

print(
    f"Peer A key generation : "
    f"{peer_a_keygen_time * 1000:.3f} ms"
)

print(
    f"Peer B key generation : "
    f"{peer_b_keygen_time * 1000:.3f} ms"
)

print(
    f"Peer A shared-secret computation : "
    f"{peer_a_exchange_time * 1000:.3f} ms"
)

print(
    f"Peer B shared-secret computation : "
    f"{peer_b_exchange_time * 1000:.3f} ms"
)

print(
    f"\nAverage key generation time: "
    f"{((peer_a_keygen_time + peer_b_keygen_time) / 2) * 1000:.3f} ms"
)

print(
    f"Average key exchange time: "
    f"{((peer_a_exchange_time + peer_b_exchange_time) / 2) * 1000:.3f} ms"
)