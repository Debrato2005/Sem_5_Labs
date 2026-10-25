# Changes: audit and plug-and-play consolidation

Date: 2026-10-26. Existing files and archives were retained. No commits or pushes were requested or created.

## Main result

Added a shared record service and thin adapters for standalone menus, two-program TCP applications, and HTTP APIs. Roles, fields, algorithms, decimal precision, and numeric bounds come from one CONFIG. The same service enforces permissions in every architecture.

The authoritative entry point is README.md. PLUGPLAY.md explains adaptation and submission. Labs 1–8 keep their own codebooks. Representative grant and voting programs remain integration examples.

## Correctness changes

- Paillier now validates primes, integer messages, ciphertext group membership, supplied randomness, weight lengths, and authority IDs. Invalid partials fail explicit consistency checks where possible.
- RSA/ElGamal text framing preserves leading and embedded NUL bytes. Rabin supports empty messages. ECIES supports larger curve coordinate lengths.
- Signature verification rejects malformed input and unknown schemes. Classical ciphers reject invalid parameters, and Playfair handles repeated filler letters.
- SSE deletion removes postings from extra keywords. PKSE validates result shapes and uses unit blinding factors.
- E-voting signs Commission acceptance against both receipt ID and the voter envelope. Tallying verifies acceptance and rejects duplicate voters.
- Generic menus support DES/3DES as well as AES. Numeric search uses the same scaled encoding as submission. Stored configuration prevents accidental schema changes.
- Weighted aggregates reject a single nonzero contributor. The new record service also applies a public bound before decryption to rule out modular overflow.
- Shared persistence accepts Path objects, uses unique temporary files, and preserves the old file if serialization fails. Empty existing JSON is corruption, not a new database.
- HTTP validates body length and JSON shape. TCP handles timeouts and disconnects. Network request handling serializes shared writes. Existing message templates authenticate owner access.
- Bundle generation supports aliases and the supplied plugplay helpers. Unsupported package imports fail clearly.
- Tests use concurrent socket sends instead of assuming that a large send fits the platform buffer.

## Reference corrections

All three lab manuals and the evaluation document were inspected through extracted text. The codebooks correct the impossible permutation example, invalid supplied keys, limited benchmarks, small PKSE corpus, partial socket reads, and overstated KMS/DRM/threshold claims.

The retained archive contains 327 Python blocks. An AST scan finds 100 syntax failures, including a deliberate fragment. Eight archived Markdown files exactly match midsem files. The earlier change log's 36-failure and three-duplicate counts were incorrect.

The previous change log also listed historical compatibility runs without retained receipts. This audit does not adopt those runs as current verification. See audit/VERIFICATION.md for results from this pass.

## Migration and compatibility

- Keep matching keys, records, configuration, and backups together. Missing keys do not trigger replacement when records exist.
- Old generic-template keys lack the new configuration fingerprint. Use their original program or a separate new data folder. No automatic destructive migration runs.
- Old accepted voting records lack Commission acceptance signatures. With a backup, return those records to pending status and process them through the Commission again.
- Existing network client key filenames now use the hash of the client name. Copy an old key to the expected filename if its public key is already registered. Do not generate a replacement identity accidentally.
- Textbook RSA/ElGamal text helpers use a new encrypted framing marker. Old ciphertext lists need the original decoder. Record scenarios use different envelopes and do not depend on this format.
- The single-file bundler supports the supplied adapter layout. It is not a general Python package compiler.

## Limits retained explicitly

The local timestamp signer is not an independent time authority. The cooperative Paillier demo does not implement a reviewed, proven threshold protocol. The voting verifier sees the decrypted ballot. Aggregate query restrictions do not prevent differencing. Plain metadata, search leakage, editable logs, and local key custody remain documented limitations.

