# Exam toolkit audit plan

**Goal:** Correct the existing Labs 1–8 reference and test the parts used to assemble unfamiliar questions.

**Design:** Keep one package, one README, eight lab codebooks, and thin menu/network programs. Retain the archive unchanged. Use Python 3.8 or later and PyCryptodome. Prefer standard-library storage, sockets, HTTP, and tests.

The user authorized independent design and implementation. Work proceeds without an additional design approval.

## Tasks

- [x] Inspect all active files, archived references, and the three lab manuals. Record coverage and evidence gaps.
- [x] Add failing regressions for crypto boundaries, vote replay, persistence, networking, input, and bundling.
- [x] Correct shared implementations and integration programs. Keep security limits explicit.
- [x] Improve manual coverage, copy instructions, quick lookup, and dependency setup.
- [x] Run the full suite, codebook examples, network processes, and bundled programs. Record actual results.

## Review focus

Malformed records must fail closed. Existing records must never trigger replacement keys. Aggregate operations need range and weight checks. HTTP requests need framing and concurrency protection. Role menus are an application boundary, not process isolation.

## Verification limits

The current executor is Windows. Debian compatibility needs a Debian run. External GnuPG and Snort commands need their installed tools. Cooperative threshold arithmetic does not establish a proven threshold cryptosystem.

