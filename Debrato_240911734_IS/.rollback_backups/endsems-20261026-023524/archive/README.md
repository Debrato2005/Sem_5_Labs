# Archive — superseded material (kept, not deleted)

Everything here was moved (git history preserved) when the toolkit was consolidated.
Use `../README.md` and `../codebooks/` instead. Reasons from the audit:

| File | Why archived |
|---|---|
| `old_programs/EXAM_STARTER.py` | imports `common`, `symmetric`, `public_key`, `homomorphic` modules that never existed in the repo → cannot run |
| `old_programs/Secure_Grant_Expense_Portal_Menu.py` | worked, but needed `phe`; replaced by `solutions/grant_portal.py` (no `phe`, per-role key vaults, blind index, tests) |
| `old_programs/Secure_EVoting_Menu.py` | "threshold" decryption XOR-split p and q and rebuilt the full private key (not threshold decryption); a fresh 2048-bit prime per voter; needed `phe`. Replaced by `solutions/evoting.py` (real t-of-N threshold Paillier, re-encryption check) |
| `old_codebooks/Lab_1…8*.md` | useful notes, but Lab 2 had 32 of 35 code blocks broken by Markdown escaping (`get\_random\_bytes`, `\[:8]`); several snippets depended on undefined variables; content overlapped and contradicted the newer guides. Rewritten as `codebooks/Lab1…Lab8` with every block executed by tests |
| `old_guides/README_midsem_scenario_guide.md` | midsem guide (not end-sem); escaped code, 3 invalid Python blocks, many snippets missing imports |
| `old_guides/README_v2_kit_missing_files.md`, `QUESTION_TO_CODE.md` | describe `library/`, `SOCKET_SERVER.py`, `HTTP_SERVER.py`, `BUILD_SINGLE_FILE.py`, `tests/` that were not in the repo |
| `old_guides/IS_Endsem_Universal_Modular_README.md`, `IS_Endsem_Combined_Scenarios_Grant_and_EVoting.md` | duplicated the above with partially different APIs; scenarios now live in `solutions/` and `codebooks/00_Scenario_Assembly.md` |
| `old_guides/IS_Midsem_4_Questions_Complete_Solutions.md` | byte-identical copy of `../../midsems/` |
| `old_guides/download.md` | personal environment / local-LLM setup notes, unrelated to the exam code |
