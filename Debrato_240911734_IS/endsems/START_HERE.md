# START HERE — Template A, 60-second exam guide

**Use for standalone menu-driven Python questions.** If the examiner explicitly says TCP sockets or REST API, choose the separate network template instead.

## Edit these THREE places in `TEMPLATE_A_SIMPLE.py`

**1. TASK FUNCTIONS** — Each option is a normal Python function:

```python
def new_task(ctx):
    message = input('Message: ')
    # PASTE the algorithm from the relevant Lab 1–8 codebook.
    print('Result:', message)  # Replace this demonstration line.
```

**2. ACTIONS** — Connect menu text to that function:

```python
ACTIONS = {
    'new': ('New task', new_task),
}
```

**3. ROLES** — Choose which role sees which menu option:

```python
ROLES = {
    'Sender': ['new'],
    'Receiver': ['new'],
}
```

**Meaning:** Role `Sender` sees the `New task` option. Selecting it calls `new_task(ctx)`.

## 3 persistence helpers

```python
save_record(ctx, record_id, encrypted_row)  # Save (encrypt BEFORE calling)
rid, row = get_record(ctx)                   # Load by ID
ctx['keys']['name'] = key.hex(); save_keys(ctx)  # Save newly generated keys
```

## Choose blocks using the exam wording

| Wording | Codebook |
|---|---|
| AES / DES / 3DES / modes | Lab 2 |
| RSA / ElGamal encryption / ECC / DH | Lab 3 |
| Permissions / Rabin / KMS | Lab 4 |
| Hash / MD5 / SHA / file integrity | Lab 5 |
| RSA / ElGamal / Schnorr signature | Lab 6 |
| Homomorphic encrypted total / Paillier | Lab 7 |
| Searchable encrypted index | Lab 8 |
| Caesar / Playfair / Hill | Lab 1 |

## Translate question → functions

```text
Every role             -> ROLES
Every menu operation   -> ACTIONS
Every cryptographic requirement -> code INSIDE its function
Persistent encrypted data        -> save_record(...)
Persistent private keys          -> ctx['keys'] + save_keys(ctx)
Verify first / decrypt later     -> exact function execution order
```

## Run on Debian PyCharm

```bash
source .venv/bin/activate
python TEMPLATE_A_SIMPLE.py
```

Pick **new filenames for each scenario** on first run (e.g. `case1_keys.json`, `case1_records.json`). Reuse the same names to demonstrate restart persistence.

### Important

The included SHA-256 tasks are only working examples for learning the shell. **You must replace them** before submitting any question that demands encryption, signatures, homomorphic computation, or other algorithms. The template does not magically solve unseen problems. Keep all examination values input-driven.
