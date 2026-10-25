# INFORMATION SECURITY ENDSEM — UNIVERSAL EXAM ASSEMBLY KIT V2

**Target:** Debian Linux + PyCharm, Python 3.10+ (modern Python recommended), end-semester Information Security Lab programming. **Goal:** assemble the shortest correct answer for *the question actually given*, using selectable, input-driven Python code. This kit is an educational reference, not a security-certified production system.

> **READ THIS FIRST:** There is no program that implements every conceivable scenario unchanged. A question can specify arbitrary roles, cryptographic algorithms, input/output formats, communication methods, and operation order. V2 provides complete **architecture starters**, isolated algorithms, a single-file builder, and an exact checklist for changing them. Do **not** represent a simulated trusted timestamp, key-share reconstruction, textbook ElGamal/RSA, or simple HMAC-search index as a full real-world protocol.

## 0. What changed after inspecting the GitHub `endsems` folder

Source: [`Debrato2005/Sem_5_Labs/Debrato_240911734_IS/endsems`](https://github.com/Debrato2005/Sem_5_Labs/tree/main/Debrato_240911734_IS/endsems), `main`, inspected 25 October 2026. This folder contained **16 files**: the old grant-specific starter, both scenario scripts, individual Labs 1–8 codebooks, combined scenario notes, universal README, midsem guide and `download.md`. The existing starter imports `common.py`, `symmetric.py`, `public_key.py`, and `homomorphic.py` but these modules (and `BUILD_EXAM.py`) were **absent** from the GitHub folder. The previous ZIP contained them. V2 bundles the actual dependencies.

V2 does **not** modify or push to GitHub. Do not paste unrelated local setup/destructive command sequences from `download.md` into the examination environment; use only the scoped installation block below.

## 1. ZIP contents and exactly which file to run

| File | Purpose | Question type |
|---|---|---|
| `EXAM_STARTER_V2.py` | **Configurable** role names, action permissions, input fields, exact searchable fields, AES key size/mode, hash, RSA/ElGamal signatures, optional RSA-wrapped session keys, Paillier encrypted scalar total, one-hot vote tally, persistence and tamper tests | General **standalone menu-driven** encrypted record scenarios |
| `SOCKET_SERVER.py` + `SOCKET_CLIENT.py` + `network_core.py` | Real framed TCP messaging, encrypted and signed transmission; persistent ciphertext at server | Explicit **socket / client-server** questions, Labs 5–6 style |
| `HTTP_SERVER.py` + `HTTP_CLIENT.py` + `network_core.py` | Flask endpoints, actual HTTP client, signed AES+RSA encrypted upload and retrieval | Explicit **API / HTTP** questions, Lab 4 KMS-style extensions |
| `BUILD_SINGLE_FILE.py` | Generates a **self-contained** `.py` file for any starter architecture; optional library blocks | If the exam wants one program or you want to copy/paste one file |
| `library/common.py` | User-input helpers, timestamps, hashing, HMAC search token, atomic JSON saves, role passwords | Labs 4–8 |
| `library/classical.py` | Caesar/additive, multiplicative, affine, Vigenère, Playfair, Hill, transposition | Lab 1 |
| `library/symmetric.py` | AES 128/192/256, DES, 3DES, ECB/CBC/CFB/OFB/CTR/GCM, padding control | Lab 2 |
| `library/public_key.py` | RSA OAEP, RSA signatures, textbook ElGamal, Schnorr, Rabin, DH, ECC/ECDH | Labs 3,4,6 |
| `library/math_and_access.py` | modular/Galois arithmetic, AES MixColumns, access-control logic | Labs 2,4 |
| `library/homomorphic.py` | Paillier addition, scalar multiplication, candidate-wise one-hot counts; textbook multiplicative demos | Lab 7 |
| `library/search_index.py` | AES-GCM encrypted documents and HMAC equality-token SSE | Lab 8 |
| `library/network_helpers.py` | Lightweight length-framed sockets and HMAC | Labs 5,6 |
| `EXAMPLE_Grant.py` | Previously prepared grant-portal solution | Grant-style composition only |
| `EXAMPLE_EVoting.py` | Previously prepared e-voting composition | Voting-style composition only, NOT genuine threshold Paillier |
| `QUESTION_TO_CODE.md` | Short lookup and detailed construction recipes for previously seen + unseen question patterns | **Read during exam** |
| `tests/test_static.py` | Syntax, assembler, function collision and pure-Python smoke checks | Sanity testing |

**Existing lab Markdown references:** Keep your original `Lab_1...md` through `Lab_8...md`, `IS_Endsem_Combined_Scenarios_Grant_and_EVoting.md` and earlier README alongside this kit. They provide the individual specialized standalone programs when the generic starter is not appropriate.

## 2. Debian + PyCharm installation

From the intended exam folder (if **already inside** `endsem_exam`, do not create a nested one):

```bash
# In parent folder only:
mkdir -p endsem_exam && cd endsem_exam

# Install uv using Debian's pipx when system pip is externally managed:
# sudo apt install -y pipx python3-venv && pipx install uv
uv venv .venv
uv pip install --python .venv/bin/python pycryptodome cryptography numpy sympy matplotlib ecdsa flask 'fastapi[standard]' psutil phe python-gnupg scapy
source .venv/bin/activate
python -c "from Crypto.Cipher import AES; from Crypto.PublicKey import RSA; from phe import paillier; import flask; print('IS ENV READY')"
```

Extract the kit inside the `endsem_exam` directory. Set the PyCharm interpreter to `.venv/bin/python`. **Don't** regenerate keys when existing records need their original keys. Installing `python-gnupg` does **not** install the `gpg` executable, and `scapy` does **not** install Snort.

## 3. TEN-SECOND QUESTION DECODER

Before choosing code, write these seven facts down:

```
ARCHITECTURE: MENU ONLY / SOCKET / API / BOTH
ACTORS: role names, who sends, who stores, who may decrypt
INPUTS: field names, file/text/binary, integers, candidate IDs
ALGORITHMS: exact cipher + key bits + mode + hash + signing system
ORDER: what is encrypted, hashed, signed, stored, verified, decrypted
SEARCH / HE: ID / keyword / date range / encrypted sum / encrypted per-category count
STATE / ERRORS: save/reopen? tampered content? duplicate IDs? deadline? role access?
```

**Rule:** If the wording says only "Client Side" and "Server Side" without sockets or HTTP, they may be two logical roles within one menu program. If it says **socket programming, network transfer, client/server scripts, secure API or HTTP**, use the real transport architecture.

## 4. Choose the correct starting point

| Examiner words | Choose | Edit |
|---|---|---|
| "Menu-driven researcher/reviewer/finance" | `EXAM_STARTER_V2.py` | Roles, text fields, `amount`, permissions; AES192, MD5, RSA, Paillier |
| "Menu-driven voter/authority/tally" | `EXAM_STARTER_V2.py` + e-voting specialized reference | Ballot fields, one-hot candidates, SHA512, AES256 CBC, ElGamal; **additional threshold/time-authority logic is separate** |
| "Patient/doctor/auditor" | `EXAM_STARTER_V2.py` | Role permissions, diagnosis fields, optionally RSA key wrapping, verify-before-decrypt |
| "Send/receive using socket" | `SOCKET_SERVER.py` + `SOCKET_CLIENT.py` | Hash and cipher choices; use client and server in separate terminals |
| "API / endpoints / web services" | `HTTP_SERVER.py` + `HTTP_CLIENT.py` | Add exact requested routes, key lifecycle logic, auth if specified |
| "Paillier add, multiply by constant, weighted average" | `library/homomorphic.py` + Lab 7 Markdown | Compose required interactive menu; never decrypt individual restricted values |
| "Search encrypted keywords" | `library/search_index.py` + Lab 8 Markdown | Add/edit/delete, query index, search leakage disclosure |
| "Caesar / Playfair / Hill / Vigenère" | `library/classical.py` + Lab 1 Markdown | Make question-specific user-driven mini-menu |
| "DES / AES-CTR / modes and timing" | `library/symmetric.py` + Lab 2 Markdown | Cipher/mode/IV/padding and benchmarks |
| "Rabin / KMS / key rotation / access policy" | `library/public_key.py`, `library/math_and_access.py` + Lab 4 Markdown | Key lifecycle and any specific KMS API |
| "RSA, ECC, DH, ElGamal, Schnorr signatures" | `library/public_key.py` + Labs 3/6 Markdown | Match exact signature/encryption formula and validation |
| "GnuPG / Snort" | Lab 8 Markdown + external system tools | **Not solved by a Python-only template** |

## 5. Standalone menu: create any named roles and fields (no code changes for common cases)

```bash
python EXAM_STARTER_V2.py
```

On **first run**, supply: separate key/database paths; scenario title; any number of text/file fields; exact searchable fields; optional encrypted numeric field and decimal precision; optional candidates for one-hot encrypted tallies; AES128/192/256; CBC/GCM; MD5/SHA1/SHA256/SHA512; RSA/ElGamal/no signature; optional per-record RSA key wrapping; parameter bits; role names; permissions; and role passwords.

On **later runs**, enter **exactly the same key and database paths** to retrieve earlier records and role configurations. If question changes entirely, use separate paths. Role permissions are enforced in the **menu**, but the configuration key file contains private material: classroom RBAC is not operating-system isolation.

**Built-in menu actions** (authorize by numeric code when setting up):

| Code | Action | Notes |
|---|---|---|
| 1 | Submit | Prompts for every field and encrypts payload; Paillier encrypts scalar and/or one-hot candidate selection |
| 2 | List | Shows IDs, timestamps, digest, encrypted preview and validity |
| 3 | Lookup | Exact record ID (not full-keyword SSE), prints record/signature status |
| 4 | Search | Exact equality search through HMAC-keyed postings (requires field indexed at setup) |
| 5 | Verify | Recompute configured digest and check configured signature |
| 6 | Decrypt | Only if valid; prints decrypted hex dump/text fields. Does not decrypt individual Paillier values |
| 7 | Aggregate | Select >=2 distinct signed records, sum encrypted scalar amounts, decrypt **final** total |
| 8 | Tally | Select >=2 distinct signed records, encrypted per-candidate one-hot tally, decrypt **final counts** |
| 9 | Tamper demo | Modifies encrypted bytes in a deep copy, proves verification fails; leaves saved data intact |

**What still needs editing**: if the examiner demands ElGamal *encryption* of a separate authorization code, real-time bounds on votes, custom key protocols, SSE phrase search, strict zero-IV/no-padding CBC, or formal threshold decryption, you must add the relevant specialist block. This universal shell is deliberately **not** a fake automatic solution generator.

## 6. Make single-file answers for PyCharm or copying

```bash
python BUILD_SINGLE_FILE.py
```

Choose one of: `standalone`, `socket_pair`, `http_pair`, `socket_server`, `socket_client`, `http_server`, `http_client`, `library_only`.

Then select optional blocks by name (`classical`, `math`, `search`, etc.) and output file/directory. No local `.py` imports remain in the generated program; only installed packages and Python's standard library are imported. Output never overwrites existing files. You still have to modify the **exam-specific workflow**.

**Typical commands:**

```bash
# First, interactively generate answer.py. Choose architecture 'standalone'.
python BUILD_SINGLE_FILE.py
python answer.py

# To generate both network programs, choose 'socket_pair'.
python BUILD_SINGLE_FILE.py
# Terminal A: python socket_server_answer.py
# Terminal B: python socket_client_answer.py

# To generate API server + HTTP client, choose 'http_pair'.
python BUILD_SINGLE_FILE.py
# Terminal A: python http_server_answer.py
# Terminal B: python http_client_answer.py
```

## 7. Actual network requirements: socket vs API

### TCP (two processes, *real* network)

Use separate PyCharm terminal windows. Start server before client. The client first **retrieves server public key** (`public` request), then submits a record (`submit` request); this consumes **two server connections per submission**. A lookup consumes one. Provide enough requested connection slots to the server. Protocol uses 4-byte big-endian length prefixed JSON. Server verifies hash/RSA signature and AES-GCM authentication before saving an encrypted record; duplicate IDs rejected. On completion, only the encrypted envelope is persisted.

**Limitation:** The sender RSA public key is supplied with the message itself; signature validity therefore means consistency with that submitted key, **not independently authenticated voter/researcher identity**. In real deployments use trusted keys/certificates, authentication, replay prevention and TLS.

### HTTP API (two processes, *real* HTTP)

`HTTP_SERVER.py` exposes `GET /public`, `POST /submit`, and `GET /records/<id>`. Client uses stdlib `urllib` so no extra HTTP client dependency is needed. Server uses `flask`. Use `127.0.0.1` in labs unless the question explicitly requires remote hosts. This **HTTP dev server is not a secure production API**. It lacks login/authorization endpoints, trusted key distribution and TLS.

### Client/server **logical** separation

If only role operations are described, a standalone program with role login menus can implement client and server *logic*. Do not claim it implements sockets.

## 8. How crypto blocks fit together

**General encrypted record:**

```
read input/file -> bytes -> AES encrypt (random IV/nonce)
                -> if RSA-wrap: RSA-OAEP encrypt AES session key
                -> if Paillier: encrypt integer/one-hot fields separately
                -> canonical JSON envelope with ID, IV, ciphertext, encrypted amounts, timestamp
                -> hash EXACT envelope requested (MD5/SHA...)
                -> sign SAME envelope with private key
                -> save envelope + digest + signature (keys separately)
receiver -> locate record -> recompute digest -> verify signature
         -> only if all pass: unwrap AES key -> decrypt AES -> display permitted contents
aggregator -> verify selected signed records -> ciphertext additions -> decrypt FINAL aggregate
```

**Key selection:** AES128 = 16-byte key, AES192 = 24-byte key, AES256 = 32-byte key. AES CBC IV = 16 bytes, and CBC normally uses PKCS#7 padding. If examiner says **zero IV** or **no padding**, implement *those exact requirements* for the lab, and validate input length. CBC without authentication is malleable; verify signed envelope before decrypt. ECB is insecure; DES and 3DES are legacy primitives. Use only if requested.

**Hash scope:** SHA-512 of the **ballot file** is different from SHA-512 of the **encrypted record**. Signing the ballot hash does not automatically authenticate a separately stored Paillier choice/candidate index; sign the encrypted submission envelope as well if those fields need integrity protection. Never accidentally double-hash if asked to sign an already computed digest.

**Paillier:** `E(a)+E(b)` homomorphically yields `a+b` in `phe`; `E(a)*public_k` yields `a*k`. Multiplying two Paillier ciphertexts does not yield `a*b`. For e-voting, candidate ID sums do **not** give per-candidate counts: use **one-hot encrypted vectors**, then sum each candidate's encrypted indicator. Do not decrypt a single encrypted amount or ballot when prohibited.

**Searchable index:** HMAC token of each normalized keyword/equality field allows lookup without decrypting every document. Search equality patterns leak to the server, and a self-contained program holding all keys is not a formally threat-modelled SSE/PKSE deployment. RSA-OAEP and Paillier randomized ciphertexts cannot be compared for deterministic keyword equality.

**Threshold decryption:** Two XOR secret shares reconstructed into a normal Paillier private key are **not genuine threshold Paillier decryption**. If the question explicitly requires threshold decryption, explain the demo limit or use a specified threshold-Paillier library/protocol; the kit does not silently claim to implement it.

**Trusted timestamp:** `datetime.now()` is a local timestamp, *not* an authenticated timestamp authority. Deadline checks require an explicit UTC start/end, a trusted signed time source and replay controls for real election security. Ordinary self-generated timestamps alone cannot establish submission authority.

## 9. Recipe check: BOTH questions supplied by you

### A. Secure Grant Expense Portal

Configure the standalone starter with: fields = `description` (and any other text fields), indexed field = optional description; numeric field = `amount`; candidates blank; AES **192**; hash **md5**; signature **rsa**; RSA wrap **n** unless asked; roles = `researcher,reviewer,finance`, permissions respectively `1,2`, `2,3,4,5,6,9`, `2,5,7`. Grant ID is the unique record ID. Reviewer action 6 displays hex dump; finance action 7 decrypts **final sum**. If the question requires a true Grant ID searchable encrypted index instead of clear IDs, add the `search_index.py` token logic and avoid plaintext IDs.

**Caution:** MD5 is cryptographically broken for collision resistance. Use it only to meet the explicit exam wording. For a more faithful exact grant answer, see `EXAMPLE_Grant.py`.

### B. Secure National E-Voting

Configure fields `ballot_file, constituency, submitted_at` and index `constituency` if needed; candidates = all requested candidate IDs; numeric field blank; AES **256**, **CBC**; hash **sha512**; signature **elgamal**; RSA wrap **y**; roles configured for voter submit, server verify/search, authority tally. Use input files for `ballot_file` instead of hardcoded contents. The starter supports most specified pieces but **does NOT** implement trusted authority-issued timestamp signatures, formal threshold Paillier, or a real remote client protocol. The separately supplied `EXAMPLE_EVoting.py` illustrates simulated two-authority key reconstruction and local timestamp checking. Use `SOCKET_*` only if actual networking is required by the question.

### C. Hospital / MediSecure

Configure text/file fields such as `patient_name,report,diagnosis`; roles doctor/nurse/auditor and allowed actions; AES CBC or GCM as specified, RSA signature, RSA wrap as specified, hash SHA256. Role restrictions: nurse/auditor can verify but not decrypt if forbidden. If the scenario demands public-key encryption of *small* records with RSA OAEP directly, paste the `rsa_encrypt/rsa_decrypt` block and do not substitute AES silently.

### D. Hashing or signatures with actual client/server

Run `SOCKET_SERVER.py` and `SOCKET_CLIENT.py`; choose SHA512 or SHA256 and AES size. If the question asks for **hash-only** integrity rather than encryption, use Lab 5 `SERVER/CLIENT` exact reference, because this secure-envelope template does more than the exercise asks.

## 10. When the task is *outside* the generic starter

| Task | Correct reference/extension |
|---|---|
| Numerical RSA/ElGamal/Rabin with supplied p, q, g | Lab 3/4 specialized `.md` programs, **do not auto-generate random keys** |
| Playfair/Hill matrix/digraph arithmetic | Lab 1 `.md` + `library/classical.py` |
| AES MixColumns/InvMixColumns | `library/math_and_access.py` + Lab 2 `.md` |
| Schnorr/ElGamal *signature* on user-supplied p/g | Lab 6 `.md` (exercise-specific formulas) |
| Formal `threshold Paillier`, anonymous voting, verifiable election | Special protocol outside the current kit; demo key-share reconstruction is **not equivalent** |
| SSE Boolean, phrase/prefix queries, Paillier-assisted index | Lab 8 `.md` with exact sections and standalone programs |
| Bell–LaPadula, ABAC, MAC, DAC, temporal policy, KMS rotation | Lab 4 `.md`, project-specific menu/API logic |
| GNU Privacy Guard, Snort | Separate installed system tools, Lab 8 `.md` |
| DES/AES benchmarking or plots | Lab 2 `.md`, use `matplotlib`/`time.perf_counter` |

## 11. Mandatory pre-submission checklist

- [ ] Exactly the required algorithms/key sizes/modes/hash targets; no silent substitution.
- [ ] Every scenario input is prompted or securely generated; no prefilled user data.
- [ ] Menu-driven if required; every role's specified actions reachable and restricted.
- [ ] Persistent records **and corresponding keys** reopen without regeneration.
- [ ] Hash covers *the exact specified object*. Signature signs the right hash/payload, not something else.
- [ ] Tampering of ciphertext, signature, number, index or timestamp is detected when required.
- [ ] Decryption only after verification; no individual Paillier plaintext exposure when banned.
- [ ] Paillier aggregation and per-candidate counts are mathematically correct.
- [ ] Client and server are actually separate programs if explicitly required; server starts first.
- [ ] API endpoints / response formats exactly match the question when required.
- [ ] All failed-input paths are handled (invalid prime, amount, ID, missing file, duplicate, malformed JSON, role access).
- [ ] Output demonstrates *all requested operations*, not just printing 'success'.
- [ ] Run `python -m compileall` and a positive/negative runtime test for the chosen architecture.

## 12. Validation limits

- This kit's Python files and generated single-file targets are **syntax-compiled and statically checked**.
- Selected pure-Python classical / math helper tests are exercised by `tests/test_static.py`.
- **PyCryptodome and `phe` were unavailable in the artifact-building environment** because PyPI access failed. Accordingly, full cross-library crypto integration and socket/HTTP runtime checks are **not claimed**. Run the end-to-end test checklist on Debian PyCharm with the listed packages installed.
- Local role passwords and plaintext JSON key material are a classroom convenience, not strong process isolation; if genuine security is evaluated, use protected OS accounts, secure key storage, trusted key directories, TLS and audited libraries.

The correct objective is **one verified execution path for each explicit question requirement**. Choose only the modules the question needs; the shortest correct answer is better than including unrelated functionality.
