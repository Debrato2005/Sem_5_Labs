# QUESTION → PYTHON MODULE IN LESS THAN A MINUTE

Use alongside `README.md`. Keep separate and easy to scan during the exam.

## Decision table

| Exact wording found in a question | Select | Correct operation |
|---|---|---|
| role menus / choose role / submit + reviewer | `EXAM_STARTER_V2.py` | `input()` for roles/fields, scoped permission menus |
| socket / TCP / separate client/server / send/receive | `SOCKET_SERVER.py` + `SOCKET_CLIENT.py` | length-prefixed framed JSON, two processes |
| Flask / REST / API / routes | `HTTP_SERVER.py` + `HTTP_CLIENT.py` | actual HTTP requests and Flask endpoints |
| RSA public encrypt, private decrypt | `library/public_key.py` | `rsa_encrypt`, `rsa_decrypt` with OAEP |
| RSA private signs, sender public verifies | `library/public_key.py` | `rsa_sign`, `rsa_verify`, exact hash algorithm |
| ElGamal integer encrypt/sign | `library/public_key.py` | `elgamal_encrypt/decrypt`, `elgamal_sign/verify` |
| Rabin | `library/public_key.py` | four roots; mathematical caveat |
| RSA encrypted AES key | `library/public_key.py` + `symmetric.py` | hybrid encrypt file, wrap *key* with OAEP |
| ECC / ECDH / Schnorr / Diffie-Hellman | `library/public_key.py` | ECDH derives shared material; HKDF before AES |
| AES-128/192/256, CBC, CTR, GCM | `library/symmetric.py` | correct key bytes, IV/nonce and padding |
| DES / Triple DES | `library/symmetric.py` | DES key 8 bytes, legacy algorithm |
| MD5, SHA-1/256/512, custom hash | `library/common.py` | `digest()` / `djb2()`; custom is not secure |
| add encrypted integers, encrypted weighted sum | `library/homomorphic.py` | Paillier encrypted addition + scalar multiply |
| encrypted candidate counts | `library/homomorphic.py` | one-hot encrypted vector per vote |
| encrypted search by field/keyword | `library/search_index.py` | HMAC token + AES-GCM encrypted document |
| classical ciphers or attacks | `library/classical.py` + Lab 1 codebook | add/multiply/affine/Vigenère/Playfair/Hill |
| AES finite-field or MixColumns | `library/math_and_access.py` + Lab 2 | GF multiplication/column transform |
| KMS/RBAC/ABAC/Bell–LaPadula | Lab 4 reference + `math_and_access.py` | explicit access policy and audit |
| GnuPG / Snort | Lab 8 | installed system binary; not Python alone |

## Universal question breakdown

Fill this out *before* running the builder:

```text
TITLE:
ARCHITECTURE: standalone | socket_pair | http_pair
ROLES/OPERATIONS:
DATA FIELDS + TYPES + SOURCE:
HASH ALGORITHM + EXACT HASHED BYTES:
CIPHER + BITS + MODE + PADDING + IV POLICY:
SIGNATURE TYPE + PRIVATE/PUBLIC KEY OWNERS:
KEY WRAPPING REQUIRED? WHERE STORED?:
PAILLIER: sum | weighted sum | per-candidate tally | none
INDEX: plaintext ID | HMAC equality index | complex SSE/PKSE
PERSISTENCE + RESTART EXPECTATIONS:
REJECT: duplicate/invalid/tampered/late/unauthorized:
OUTPUT REQUIRED BY EXAMINER:
```

## Two-key distinction

1. **Recipient encryption key:** receiver public encrypts/wraps; receiver private decrypts/unwraps.
2. **Sender signing key:** sender private signs; sender public verifies.
3. Never claim a public key **bundled with the message** proves real identity. Trust the key through a separate authenticated channel.

## Three disallowed shortcuts

- Summing encrypted candidate IDs is **not** counting votes. Use encrypted one-hot indicator vectors.
- Comparing RSA-OAEP/Paillier ciphertexts for keyword equality is invalid: encryption is randomized.
- Rebuilding a normal Paillier private key from two shares is **not** formal threshold-Paillier decryption.

## First five minutes of any question

1. Underline **explicit** algorithms, roles, network/API wording and storage.
2. Fill the breakdown form above (or write equivalent code comments).
3. Choose architecture `standalone`, `socket_pair` or `http_pair`.
4. Generate source with `python BUILD_SINGLE_FILE.py` and add any question-specific blocks.
5. Run once with user-entered values, then tamper/restart/unauthorized tests.
