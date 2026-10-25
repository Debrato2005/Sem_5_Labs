# Manual and retained-material coverage audit

Date: 2026-10-26. This report records the material review and the codebook changes.
It does not certify cryptographic security or readiness for every possible examination question.

## Inspection scope

The review read all active codebooks, the README, the change log, every archived guide,
every archived codebook, and all three archived programs. It compared these with all
68 PDF pages and the evaluation document. PDF inspection used extracted text, not image rendering.
The extraction keeps page separators in `audit/manual_text/`.

| Source | Scope inspected | Extraction |
|---|---|---|
| `../IS/IS Lab Manual [1-4].pdf` | All 45 pages, including instructions, theory, exercises and additional questions | `manual_text/IS Lab Manual [1-4].txt` |
| `../IS/IS Lab Manual [5-6].pdf` | All 8 pages, including the RSA tables and signature exercises | `manual_text/IS Lab Manual [5-6].txt` |
| `../IS/IS Lab Manual [7-8].pdf` | All 15 pages, including incorrect sample code, exercises, GnuPG and Snort | `manual_text/IS Lab Manual [7-8].txt` |
| `../IS/IS Lab Evaluation Pattern for IT.docx` | All document text | `manual_text/IS Lab Evaluation Pattern for IT.txt` |

The evaluation document lists a 20-mark end-semester examination and a separate 20-mark
final project viva. The older manual lists 40 marks split between program and project.
These are two supplied descriptions. This audit does not choose an institution's current policy.
The evaluation document also requires the question, main code and output in the written record.
The manual says examination questions can vary or combine exercises.

## Active-file inventory

Each row covers the full file. Blocks were read as code, not only counted.

| File under `endsems/` | Review focus |
|---|---|
| `README.md` | Index, setup, dependencies, scenario mapping, test and security claims |
| `CHANGES.md` | Historical counts, stated fixes, validation claims and missing evidence |
| `codebooks/00_Scenario_Assembly.md` | Architecture choices, exact hash scope, role keys, teaching hospital example and adaptation recipes |
| `codebooks/Lab1_Classical_Ciphers.md` | All cipher blocks, manual constants, attacks and inconsistent transposition example |
| `codebooks/Lab2_Symmetric_DES_AES.md` | Key interpretation, modes, manual examples, AES trace, timing and graph code |
| `codebooks/Lab3_Asymmetric_RSA_ElGamal_ECC.md` | Numerical encoding, OAEP, hybrid files, ElGamal mismatch, ECIES, DH and benchmarks |
| `codebooks/Lab4_Advanced_Asymmetric_KMS_Access.md` | Rabin roots, KMS lifecycle, caller identity, SecureCorp, DRM and access policies |
| `codebooks/Lab5_Hashing.md` | Custom hash, file integrity, both socket pairs, multipart data, collision experiment and HMAC |
| `codebooks/Lab6_Digital_Signatures.md` | Manual RSA table, standard signatures, ElGamal, Schnorr, DH, network trust, CIA and timestamps |
| `codebooks/Lab7_Homomorphic_Encryption.md` | Arithmetic, signed bounds, aggregates, cooperative partial decryption, persistence and benchmark |
| `codebooks/Lab8_Searchable_Encryption.md` | Both ten-document exercises, normalization, random units, leakage, GnuPG and Snort versions |

Toolkit inspection supported claims about `KeyManager`, homomorphic arithmetic and searchable
indexes. This review did not claim a complete independent security review of every toolkit module.

## Archived-file inventory and reproducible syntax counts

Every file below received a content review. Archived sources remain unchanged.
Counts use the literal regular expression `r'```python[^\n]*\n(.*?)```'` with `re.S`,
then `ast.parse` on each match. The count includes partial examples labeled as Python.
A syntax failure does not alone distinguish a deliberate fragment from a broken runnable example.

| Archived Markdown file | Python blocks | Syntax failures |
| `archive/old_codebooks/Lab_1_Basic_Symmetric_Key_Ciphers.md` | 18 | 0 |
| `archive/old_codebooks/Lab_2_Advanced_Symmetric_Key_Ciphers.md` | 35 | 32 |
| `archive/old_codebooks/Lab_3_Asymmetric_Key_Ciphers.md` | 30 | 0 |
| `archive/old_codebooks/Lab_4_Advanced_Asymmetric_Key_Cryptography (1).md` | 36 | 0 |
| `archive/old_codebooks/Lab_5_Hashing.md` | 43 | 1 |
| `archive/old_codebooks/Lab_6_Digital_Signatures.md` | 35 | 30 |
| `archive/old_codebooks/Lab_7_Partial_Homomorphic_Encryption_Endsem.md` | 17 | 0 |
| `archive/old_codebooks/Lab_8_Searchable_Encryption_Endsem.md` | 25 | 0 |
| `archive/old_guides/download.md` | 0 | 0 |
| `archive/old_guides/IS_Endsem_Combined_Scenarios_Grant_and_EVoting.md` | 13 | 0 |
| `archive/old_guides/IS_Endsem_Universal_Modular_README.md` | 21 | 0 |
| `archive/old_guides/IS_Midsem_4_Questions_Complete_Solutions.md` | 3 | 3 |
| `archive/old_guides/QUESTION_TO_CODE.md` | 0 | 0 |
| `archive/old_guides/README_midsem_scenario_guide.md` | 51 | 34 |
| `archive/old_guides/README_v2_kit_missing_files.md` | 0 | 0 |
| `archive/README.md` | 0 | 0 |
| **Total** | **327** | **100** |

The prior change log's 36 syntax failures cannot be reproduced against this archive.
The 100 failures include the deliberate fragment `& 0xffffffff` in old Lab 5.
They also include 32 escaped blocks in Lab 2, 30 in Lab 6, 34 in the midsem guide,
and three fenced solutions in the four-question guide.

| Archived Python file | Scope inspected | Main result |
|---|---|---|
| `archive/old_programs/EXAM_STARTER.py` | All 171 lines | Imports absent companion modules. Preserve as an old interface reference. |
| `archive/old_programs/Secure_Grant_Expense_Portal_Menu.py` | All 210 lines | `phe` dependency, local password hashes, plaintext private material, signed aggregates and restart handling. |
| `archive/old_programs/Secure_EVoting_Menu.py` | All 383 lines | Reconstructs Paillier factors from XOR shares. Checks vector field names without proving the encrypted values match the ballot. |

Additional content findings from the archived guides:

- The combined guide embeds exact copies of the archived Grant and E-Voting programs.
- The universal guide supplies module bodies inside Markdown, but the starter's companion files were absent as separate modules.
- The V2 guide and question map name a ZIP, builders and network modules absent from this checkout.
- The four-question guide's opening claim that questions 1 and 2 are identical conflicts with its own SecureVault and HealthSecure questions.
- Its SecureVault program is outside a Python fence and contains escaped identifiers and HTML indentation markers.
- `download.md` contains local model setup and deletion commands. None were executed.
- Byte comparisons find eight files identical to `midsems/`: Labs 1-6, the four-question guide, and the midsem scenario guide.
- The old Lab 8 guide refers to an absent menu-master companion. Its version checks and key-trust notes informed the active codebook corrections.

## Manual exercise mapping

“Code” means an active implementation is available. “Partial” identifies a requirement that
still needs code or a stated interpretation. Reference commands are not runtime evidence.

| Manual requirement | Active location | Coverage and limit |
|---|---|---|
| Lab 1 Q1 additive, multiplicative and affine | Lab 1 section 2 | Code accepts the manual message and keys. |
| Lab 1 Q2 Vigenere and autokey | Lab 1 section 3 | Code accepts the word and numeric keys. |
| Lab 1 Q3 Playfair and Q4 Hill | Lab 1 sections 4-5 | Code includes GUIDANCE and the supplied Hill matrix. |
| Lab 1 Q5 known plaintext and Q6 affine attack | Lab 1 section 7 | Code plus literal-source typo notes. |
| Lab 1 additional birthday shift and HEALTH Vigenere | Lab 1 sections 3 and 7 | Reuse the generic functions and entered values. |
| Lab 1 chosen-plaintext permutation | Lab 1 sections 7-8 | The literal pair is inconsistent. Exhaustive code checks every block instead of claiming a recovered key. |
| Lab 2 Q1, Q2 and Q4 direct DES/AES/3DES | Lab 2 sections 2-3 | Code. Degenerate 3DES key is identified and the demonstration announces its replacement. |
| Lab 2 Q3 timing and Q5 AES-192 trace | Lab 2 sections 4-5 | Code. The invalid supplied AES-192 key needs an explicit correction. |
| Lab 2 additional five messages, modes and graph | Lab 2 section 5 | Five inputs, DES/AES variants, five modes and both timing directions. Graph branch needs matplotlib. |
| Lab 2 additional hex blocks, AES-256, CBC and CTR | Lab 2 sections 2-3 | Code with text/hex interpretation. |
| Lab 3 Q1 RSA, Q2 ECC and Q3 ElGamal | Lab 3 sections 1-5 | Code. ECC message encryption uses an explicit ECIES-style interpretation. |
| Lab 3 Q4 file transfer and comparison | Lab 3 sections 3 and 7 | Partial: local encryption and payload timing. Separate hosts, transport and authenticated key exchange need integration. |
| Lab 3 Q5 DH with timing | Lab 3 section 6 | Code. Unauthenticated DH limitation is stated. |
| Lab 3 additional fixed ElGamal and numerical RSA | Lab 3 sections 1 and 4 | Code. The inconsistent ElGamal public value is reported. |
| Lab 3 additional healthcare/agency ElGamal using secp256r1 | Lab 3 sections 5 and 7 | Partial: ECIES-style hybrid and classical ElGamal comparison. Mathematical point ElGamal is not supplied. |
| Lab 4 SecureCorp | Lab 4 section 3 and KMS section 2 | Partial: signed DH and AES work locally. One combined persistent subsystem service is not supplied. |
| Lab 4 hospital Rabin KMS | Lab 4 sections 1-2 | Partial: local lifecycle and encrypted storage. Secure API, authenticated owner identity and automatic scheduling are absent. |
| Lab 4 Rabin/RSA trade-off | Lab 4 section 1 | Theory. Timing must come from a measured run. |
| Lab 4 DigiRights DRM | Lab 4 section 4 | Partial: local grants and revocation. Upload API, creator ownership, persistent licenses and scheduled rotation need implementation. |
| Lab 4 weak RSA attack | Lab 4 section 5 | Code for close factors and small factors. |
| Lab 4 named access models | Lab 4 sections 0 and 6 | Formulas and local policy predicates. Predicates do not authenticate users. |
| Lab 5 Q1 custom hash | Lab 5 section 1 | Code plus an empty-input-safe tamper example. |
| Lab 5 Q2 socket hash and additional multipart | Lab 5 sections 3-4 | Real server/client source pairs. Replies use exact reads. Actual connections need runtime permission. |
| Lab 5 Q3 timing and collisions | Lab 5 section 5 | Code validates 50-100 inputs. Duplicate inputs are not counted as collisions. |
| Lab 6 manual RSA website workflow | Lab 6 sections 1-2 | Offline raw RSA reproduces the table. New standard key/signature code is separate. Website UI was not tested. |
| Lab 6 ElGamal/Schnorr and DH exercises | Lab 6 sections 3-6 | Code. DH is correctly labeled key agreement with HMAC. |
| Lab 6 client/server and CIA | Lab 6 sections 7-8 | Real socket source pair, TOFU limitation and local hybrid example. Availability needs system controls. |
| Lab 7 Paillier sum and RSA product | Lab 7 sections 1-3 | Code. Bounds and modular results are explicit. |
| Lab 7 additional ElGamal, sharing and benchmark | Lab 7 sections 4-5 and 9 | Code. Different operations and parameters do not imply equal security. |
| Lab 7 secure thresholding | Lab 7 section 6 | Cooperative arithmetic only. Honest reconstruction does not prove privacy or malicious-party security. |
| Lab 8 SSE 1a-1d | Lab 8 section 1 | Ten documents, AES, inverted index, deterministic tokens and authorized ID/content recovery. |
| Lab 8 PKSE 2a-2d | Lab 8 section 2 | Ten documents and Paillier-assisted equality. Normalization and unit randomness are explicit. No formal protocol security claim. |
| Lab 8 GnuPG | Lab 8 section 5 | Reference commands and optional Python example. Fingerprint, transfer and tamper checks are stated. Not executed. |
| Lab 8 Snort | Lab 8 section 6 | Separate version-2/version-3 commands, rule, capture, replay and alert analysis. Not executed. |

## Priority follow-up work and limits

1. For exact Lab 4 scenario answers, implement an authenticated KMS API and scheduled lifecycle operations. The local menu cannot prove these requirements.
2. For exact point-ElGamal questions, obtain the required message encoding and implement the stated construction. ECIES is not interchangeable with point ElGamal.
3. For complete archived scenario parity, adapt direct-RSA HealthSecure and user-key/IV MediSecure workflows. The current templates now support DES/3DES and ElGamal configuration. File transfer and entered-key workflows still need the corresponding lab functions.
4. Use an independently reviewed protocol when a question requires cryptographic threshold secrecy. This custom composite-ring construction remains unqualified.
5. Test GnuPG, Snort, Debian operation and the matplotlib graph on their actual runtime environments. The supplied commands and optional imports do not prove execution.

The current codebooks address the earlier wrong permutation claim, one-message benchmark,
missing ElGamal benchmark row, small PKSE corpus and overstated access/threshold claims.
They also fix partial socket reply reads, empty tamper input and exact multipart counts.
The short hospital example now states its lack of role enforcement and its plaintext key storage.

## Verification receipt for this material review

Command from `endsems/`: `.venv/Scripts/python.exe -m unittest tests.test_codebooks -v`.
Environment: Windows, Python 3.12.9, Crypto 4.2.0, workspace temporary directory.
The first review run compiled 68 blocks and completed all 60 non-network executable blocks.
The two optional Python blocks were compile-only. All three socket clients failed at
`socket.create_connection` with `PermissionError: [WinError 10013]`.
Result: one unittest method, three failed subtests, 62.630 seconds. This is not a passing suite.
The failures establish a runtime access boundary and do not prove the socket programs work.
Matplotlib was absent, so the graph branch did not run. The coordinator records later checks
separately. Full-program integration tests and final repository status belong to that receipt.

A final focused rerun compiled all 68 blocks and executed all 60 non-network blocks
successfully. It also asserted 100 symmetric round-trips, six hybrid benchmark rows,
and exact PKSE matches for normalized `CLOUD!` and `disk` queries. Socket blocks stayed
excluded from this focused rerun because of the access failure above. It does not replace
a successful network-inclusive suite. Exit code: 0.
