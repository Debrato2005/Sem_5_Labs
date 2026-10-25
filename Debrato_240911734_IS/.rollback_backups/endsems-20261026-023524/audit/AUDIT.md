# Security and correctness audit

Date: 2026-10-26. Scope: the complete endsems material, shared modules, programs, tests, archive, three manuals, and evaluation document. Manual review used text extraction. It did not inspect rendered PDF images.

## Findings corrected

| ID | Priority | Finding | Correction and regression evidence |
|---|---|---|---|
| A01 | High | A copied accepted voting envelope could count twice. Unsigned status could claim server approval. | Commission signature binds receipt and envelope. Tally verifies acceptance and deduplicates voters. `test_regressions_scenarios.py`. |
| A02 | High | Weights1,0 disclosed one amount despite a minimum of two records. | Count nonzero contributors before decryption. Public bounds apply in RecordApp. Scenario and plugplay tests. |
| A03 | High | Invalid Paillier values and authority IDs reached arithmetic. Weighted zip silently truncated. | Validate group membership, primes, bounds, randomness, participant IDs, and input lengths. Crypto regressions. |
| A04 | High | Empty key files could look like first setup. Missing files could encourage replacement keys. | Refuse corrupt or inconsistent state. Stored configuration binds the schema. Storage/scenario tests. |
| A05 | Medium | HTTP accepted negative or unbounded lengths. Concurrent handlers shared unsafe persistence. | Length limits, timeouts, object validation, decoding, and serialized operations. Real network regression tests. |
| A06 | Medium | Arbitrary client names became filesystem paths. Network reads lacked owner authentication. | Hash-based key filenames and signed owner-scoped reads. Network regressions. |
| A07 | Medium | Textbook message codecs lost NUL bytes. Larger ECC curves overflowed fixed coordinate buffers. | Explicit encrypted framing and curve-derived encoding lengths. Crypto regressions. |
| A08 | Medium | Extra-keyword SSE postings survived document deletion. | Remove every matching posting. Crypto regressions. |
| A09 | Medium | Bundled aliases remained undefined. Plugplay sibling imports prevented independent execution. | Preserve aliases, inline supplied adapters, reject unsupported forms. Bundle and standalone execution tests. |
| A10 | Medium | Hello configuration could change despite a pinned public key. | Sign configuration and bind it to a fresh client nonce. Protocol regressions. |

## Claims corrected and limits

The earlier description of genuine threshold security was unsupported. The implementation computes cooperative partial decryptions and tests honest combinations. It shares over a composite ring and supplies no protocol privacy proof, distributed key generation, or malicious-share proofs. Deleting Python variables does not erase secret memory. A reviewed threshold construction requires its full protocol and assumptions. See the [Damgard–Jurik paper](https://eprint.iacr.org/2000/008).

The voting server decrypts candidate selections during verification. Therefore, its ballot confidentiality ends at that verifier. Paillier totals and local role menus cannot establish privacy against that server. The codebook states this conflict instead of claiming a complete private election.

The grant and record services decrypt aggregates in their normal handlers. A holder of their Paillier private key can decrypt individual records outside those handlers. Repeated overlapping totals can also disclose values. A minimum count is an exam demonstration policy, not statistical disclosure control.

Classical ciphers, DES, ECB, MD5/SHA-1 and textbook RSA appear because exercises require them. Classic cipher modes do not authenticate ciphertext. OAEP does not authenticate a sender. Use authenticated encryption and independent sender verification where required. These distinctions follow the official [classic mode documentation](https://www.pycryptodome.org/src/cipher/classic) and [OAEP documentation](https://www.pycryptodome.org/src/cipher/oaep).

Local role passwords and sealed keys enforce application actions. They do not isolate processes, authenticate a person's civil identity, or establish legal non-repudiation. KMS requester strings are policy inputs, not authenticated identities. The timestamp key uses the local clock. Initial key pinning remains trust on first use.

Search indexes leak equality, frequency, access patterns, and some metadata. SSE authenticated blobs do not currently bind every storage position through associated data. Swapping intact blobs or deleting postings can escape local checks. PKSE is a linear educational equality protocol. Its private-key holder can decrypt the index. No search-completeness proof is supplied.

Atomic JSON replacement protects one file from partial serialization. It does not give a transaction across files or guarantee survival of a power failure. Audit logs remain editable. Authentication vaults, public-key registries, configuration, and backups rely on the local filesystem trust boundary.

## Practical coverage gaps

The material includes menu, socket, and HTTP building blocks. An authenticated remote KMS, scheduled key rotation service, persistent DRM license server, mathematical point-ElGamal message encoding, and a proven private election protocol remain separate integration work. ECIES is labeled explicitly and is not passed off as point ElGamal.

GnuPG/Snort instructions, optional graphs, and Debian execution need their actual runtime environments. Passing local tests proves the tested behavior, not universal security or readiness for every unseen question. The detailed manual mapping is in COVERAGE.md.
