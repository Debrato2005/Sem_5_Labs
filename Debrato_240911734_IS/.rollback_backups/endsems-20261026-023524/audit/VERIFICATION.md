# Verification receipt

Date: 2026-10-26. This receipt applies to the current exam toolkit audit.

## Environment

Windows 11 build 26300, Python 3.12.9, PyCryptodome 4.2.0. The local virtual environment is `endsems/.venv`. Dependencies were installed there, without changing the system interpreter.

The executor's sandbox denied writes inside its default temporary directory. Tests therefore used a process-local TEMP/TMP under `endsems/.test_tmp`. The sandbox also denied loopback sockets with WinError 10013. The complete suite ran with approved runtime access for real TCP/HTTP connections. No mocked transport replaced those checks.

## Reproduce

On Debian, from endsems:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

On the current Windows executor, from endsems:

```powershell
$env:TEMP = (Resolve-Path .test_tmp).Path
$env:TMP = $env:TEMP
./.venv/Scripts/python.exe -m unittest discover -s tests -v
```

The complete output is in `test-run.txt` beside this receipt. The final result appears below.

## What the suite covers

| Area | Evidence |
|---|---|
| Labs 1–8 | Known values, round-trips, cipher modes, signatures, access policies, homomorphic arithmetic, search, malformed input |
| Codebook programs | 68 Python blocks compile. 66 execute, including three real socket server/client pairs. Optional phe and GnuPG blocks compile only. |
| Plugplay operations | Roles, fields, RSA/ElGamal/ECDSA, DES3/AES, encrypted records, numeric search, exact decimals, restart, tampering, aggregate bounds |
| Menu/socket/API reuse | Same RecordApp behind direct menus and actual separate TCP/HTTP entry processes |
| Submission | Standalone bundled menu and two bundled socket programs execute without toolkit or sibling helper files |
| Grant integration | Submission, duplicate IDs, MD5/RSA, search, hex dump, invalid amounts, restart, wrong passwords, tamper exclusion, total |
| Voting integration | File hash, encrypted ballot, signatures, local timestamp, index, one-hot totals, replay rejection, acceptance signatures, cooperative authority partials |
| Network boundaries | Length framing, incomplete or oversized requests, negative length, object validation, URL decoding, timeouts, owner-scoped access |
| Persistence | Matching configuration, missing-key refusal, corrupt JSON refusal, failed serialization preserves old data |

## Additional checks

All 39 Python sources present at the grammar check parsed with Python 3.8 grammar. This is a syntax check, not a Python 3.8 runtime run. `audit_material.py` recreates a source inventory with SHA-256 values and archive syntax results. The archive has 327 Python blocks and 100 syntax failures, including one deliberate fragment. Active source syntax checks passed.

The updated prose passed the STE mechanical lint target. Scores per 100 words: README 1.16, PLUGPLAY 2.46, CHANGES 0.98, AUDIT 0.97. This measures wording only and does not certify technical accuracy.

## Unverified or outside the claim

- An actual Debian or Python 3.8 runtime. The current evidence is Windows/Python 3.12.9.
- GnuPG, Snort and the optional matplotlib plot branch. Source commands are reference material, not execution evidence.
- An external trusted timestamp service, legal non-repudiation, production KMS/DRM, or privacy against the voting server.
- Secure threshold Paillier. Honest partial-decryption arithmetic passed, but the custom protocol has no privacy proof or malicious-share proofs.
- Crash consistency across multiple files, backup restoration under power loss, and production concurrency/load.

Git status/diff could not run: the available Git executable failed with `fatal: cannot change to 'C:/Users/Debrato/Desktop/Sem_5_Labs'`. No Git metadata was changed. No commit or push was created. Inventory and change reports describe file-level work without claiming a verified Git diff.


## Final result

Complete suite: **119 tests passed in 101.131 seconds**, exit code 0. This includes actual TCP/HTTP programs and standalone bundled menu/socket submissions. No failed or skipped unittest methods. Two optional Markdown blocks remain compile-only as stated above.

