# Information Security exam toolkit: Labs 1–8

Start with `templates/plugplay/config.py`. Edit the roles, fields, algorithms, and permissions once. The same operations run behind a standalone menu, TCP sockets, or an HTTP API.

## 1. Install and verify on Debian / PyCharm

```bash
cd endsems
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Select `.venv/bin/python` as the PyCharm interpreter. Mark `endsems` as a Sources Root. Run entry scripts from this directory. Python 3.8 or later is the target. The current verification used Windows and Python 3.12.9. See [audit/VERIFICATION.md](audit/VERIFICATION.md) for actual results and limits.

Only PyCryptodome is required. `Crypto` is its import name. Do not install the unrelated `crypto` package. Before the exam, confirm that the interpreter can run `python -c "from Crypto.Cipher import AES; print('OK')"`. Install dependencies before you need offline access.

## 2. Choose the architecture

| Question asks for | Entry scripts | Shared parts |
|---|---|---|
| One menu-driven program | `templates/plugplay/menu_app.py` | `config.py`, `ui.py`, `toolkit/records.py` |
| Socket client/server | **Two programs:** `templates/plugplay/socket_server.py` and `socket_client.py` | Same configuration, input menus, and record operations |
| HTTP/API client/server | Same two programs, each with `--http` | Same operations, HTTP adapter |
| Client encrypts/signs before transmission | `templates/net_client.py` and `net_server.py` | Client-created signed hybrid envelope |
| Ballots, timestamps, one-hot votes, cooperative tally | `solutions/evoting.py` | Labs 3, 6, 7, 8 |

A socket solution normally has two entry scripts. Shared modules are support files, not extra running programs.

### Standalone menu

```bash
python templates/plugplay/menu_app.py my_exam_data
```

First run asks for each role's password. Later runs load the existing keys and records.

### Sockets: two terminals

```bash
# Terminal 1: server, persistent records, keys, permissions
python templates/plugplay/socket_server.py --port 5000 --data my_exam_data

# Terminal 2: input menus and results
python templates/plugplay/socket_client.py --port 5000
```

For HTTP, add `--http` to both commands and use the same port. The API is `POST /call` with JSON envelopes. Requests and responses use RSA-OAEP plus AES-GCM. Credentials stay inside the encrypted request. The client pins the server key on first contact.

The configurable record service encrypts stored fields **on the server**. If the question requires encryption on the client, use the client-envelope template or move the specified operations before the network call. These are different requirements. [PLUGPLAY.md](PLUGPLAY.md) gives the exact assembly steps.

## 3. Change the question-specific parts

In `templates/plugplay/config.py`:

- `fields`: map any field name to `text` (symmetric encryption), `number` (Paillier), or `plain` (visible, signed).
- `roles`: map any role name to its permitted actions: `submit`, `list`, `verify`, `search`, `decrypt`, `aggregate`.
- Select AES/DES/DES3, mode, hash, signature, precision, and public numeric bounds.

Inputs come from the menus. CONFIG describes the question, not example records. The service checks the password and action permission on every request. A client cannot gain access by changing its menu.

Change CONFIG before first setup. Use a new data folder for a new schema. The program refuses mismatched keys/configuration. Back up the matching keys and records together.

For one Python submission:

```bash
python bundle.py templates/plugplay/menu_app.py -o answer.py
python answer.py my_exam_data
```

The bundler supports the supplied plugplay folder and top-level `from toolkit.module import name` imports, including aliases. For socket submissions, bundle each entry separately. Keep two running programs. Ordinary arbitrary local packages are outside the bundler's scope.

## 4. Fast question-to-code lookup

| Requirement | Reference | Implementations |
|---|---|---|
| Decode roles, fields, signing order, architecture | [Assembly guide](codebooks/00_Scenario_Assembly.md), [Plug-and-play assembly](PLUGPLAY.md) | `toolkit/records.py`, `templates/plugplay/` |
| Additive/multiplicative/affine, Vigenere/autokey, Playfair, Hill, transposition, attacks | [Lab 1](codebooks/Lab1_Classical_Ciphers.md) | `toolkit/classical.py` |
| DES/3DES/AES, modes, IVs, padding, files, trace, benchmarks | [Lab 2](codebooks/Lab2_Symmetric_DES_AES.md) | `toolkit/symmetric.py` |
| RSA/OAEP/hybrid, ElGamal, DH, ECC/ECIES, numerical exercises | [Lab 3](codebooks/Lab3_Asymmetric_RSA_ElGamal_ECC.md) | `toolkit/asymmetric.py` |
| Rabin, KMS lifecycle, DRM, RBAC/ABAC/BLP/MAC/DAC | [Lab 4](codebooks/Lab4_Advanced_Asymmetric_KMS_Access.md) | `toolkit/access.py`, `asymmetric.py` |
| Custom hash, MD5/SHA, files, HMAC, socket integrity | [Lab 5](codebooks/Lab5_Hashing.md) | `toolkit/hashing.py` |
| RSA, ElGamal, Schnorr, DSA/ECDSA, signed timestamp | [Lab 6](codebooks/Lab6_Digital_Signatures.md) | `toolkit/signatures.py` |
| Sum, difference, public weights, average, one-hot counts, cooperative partial decryption | [Lab 7](codebooks/Lab7_Homomorphic_Encryption.md) | `toolkit/homomorphic.py` |
| Keyword/field/time search, SSE, Paillier equality, GnuPG/Snort | [Lab 8](codebooks/Lab8_Searchable_Encryption.md) | `toolkit/searchable.py` |
| Input, canonical bytes, persistence, role vaults, hex dump | Assembly guide | `util.py`, `symmetric.py` |
| Real TCP framing and HTTP routing | Labs 5/6 and plugplay guide | `toolkit/net.py` |

Dependencies: `access → asymmetric`; `searchable → homomorphic`; `records → util/symmetric/asymmetric/hashing/signatures/homomorphic/searchable`. Other primitive modules remain independently usable.

## 5. Representative integration programs

```bash
python solutions/grant_portal.py grant_data
python solutions/evoting.py election_data
```

The grant program covers AES-192, Paillier money, MD5/RSA, indexed lookup, hex dumps, roles, persistent records, and totals. The voting program covers SHA-512 ballot files, RSA-4096 wrapping, AES-256-CBC, ElGamal signatures, local signed timestamps, searchable indexes, one-hot counts, and cooperative partial decryption. They are integration examples, not the bounds of the toolkit.

`templates/secure_records_menu.py` remains a self-contained configurable menu alternative. `templates/plugplay/` is the preferred starting point when you need the same operations for menus and sockets.

## 6. Security facts and exam traps

- MD5/SHA-1, DES, ECB, and textbook public-key examples satisfy specific lab exercises. They do not establish modern security.
- CBC/OFB/CTR alone do not authenticate ciphertext. Verify signatures before decryption, or use authenticated encryption when permitted.
- A threshold-looking formula and passing arithmetic tests do not prove a secure threshold protocol. The supplied cooperative Paillier demo has no privacy proof or malicious-share proofs.
- The voting server decrypts the ballot to verify it. Therefore, it sees the candidate. Threshold Paillier totals cannot remove that disclosure. Strict ballot privacy needs a different protocol.
- The local timestamp signer is not an independent trusted time authority. Key pinning trusts the first connection.
- A minimum aggregate size blocks a direct singleton query. Overlapping totals, negative weights, and a decryption-key holder can still reveal individual values.
- Search leaks equality and access patterns. IDs and explicitly plain fields remain visible. Record signatures do not prove that no record was deleted.
- Password vaults and role checks separate application actions. They do not isolate processes or protect against the machine's administrator. Event logs remain editable files.

See [audit/AUDIT.md](audit/AUDIT.md) for findings, [audit/COVERAGE.md](audit/COVERAGE.md) for manual coverage, and [CHANGES.md](CHANGES.md) for changes and migration notes. The archive is historical reference only. No toolkit can automatically solve every unseen combination.
