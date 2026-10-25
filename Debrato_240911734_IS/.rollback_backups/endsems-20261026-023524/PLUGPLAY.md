# Plug-and-play assembly

Use the same operations behind each architecture. Change the question-specific configuration once.

## 1. Files to copy

Copy `toolkit/` and `templates/plugplay/` together. Keep the folder structure, or bundle the supplied entry scripts before moving them.

| File | Responsibility | Edit for a new question? |
|---|---|---|
| `config.py` | Roles, fields, algorithms, precision, bounds | Yes |
| `toolkit/records.py` | Authentication, permissions, crypto, search, storage | Only for a new operation |
| `ui.py` | Collect input and display results | Only for a new operation or required wording |
| `menu_app.py` | Open shared service, first-run passwords, menu entry | Usually no |
| `socket_server.py` | Receive requests and call shared service | Usually no |
| `socket_client.py` | Connect and run the same input menus | Usually no |
| `protocol.py` | Encrypt requests/responses, sign responses, pin server key | Usually no |

The menu program calls `RecordApp.handle(request)` directly. The socket client sends the same request through `ClientProtocol.call(request)`. The server decrypts the request and calls `RecordApp.handle(request)`. HTTP changes the transport only.

## 2. Configuration recipes

| Question | Changes in CONFIG |
|---|---|
| Grants | Description:text, Amount:number; AES192/CBC; MD5/RSA; researcher submit/list, reviewer verify/search/decrypt, finance aggregate |
| Hospital | Diagnosis:text, Ward:plain; AES256/GCM; SHA256/RSA; doctor submit, nurse verify/search, auditor list |
| Student marks | Course:plain, Marks:number; places0; SHA512/ElGamal; faculty submit, examiner aggregate |
| DES archive | Document:text, Department:plain; cipher DES, bits64, mode CBC; SHA256/ElGamal |
| Banking | Owner:text, Balance:number, Loan:number; SHA256/ECDSA; teller submit, manager aggregate |

A plain field remains visible. Use text when the question requires confidentiality. Every configured field also gets a keyed equality-search token. A number search normalizes the value to the configured decimal precision.

`decrypt` reveals text fields only. `aggregate` decrypts a Paillier total. It accepts public integer weights. The UI computes an average from the decrypted sum and count. `max_abs` bounds each scaled number. The service refuses computations whose public bound cannot rule out modular wraparound.

## 3. Request shapes

These are the inner JSON requests. The network protocol encrypts them before transmission. Never print passwords or put them in a URL.

```text
Common fields: role, password, action
submit:    id, values={every configured field: input value}
list:      no extra fields
verify:    no extra fields (returns each record's validity)
search:    field='id' or configured field name, value
decrypt:  id
aggregate: ids=[distinct record IDs], field=number field, weights=[optional integers]
Result:    ok=true plus output fields, or ok=false plus error
```

The permission check runs on the server. Hidden menu items alone never grant or deny permission. Keep secrets on the side that needs them. Do not move a Paillier private key into the client merely to display a total.

## 4. Add an operation once

Add `action_NAME(self, request, role_keys)` to a subclass of RecordApp. Declare its required keys in ACTION_KEYS. Add NAME to the permitted roles in CONFIG. Change `open_app()` in menu_app.py to construct that subclass. Both the standalone entry and socket server use open_app().

Example: a server-side average operation, with no float conversion:

```python
from decimal import Decimal
from toolkit.records import RecordApp

class MyApp(RecordApp):
    ACTION_KEYS = {**RecordApp.ACTION_KEYS, 'average': {'paillier'}}

    def action_average(self, request, role_keys):
        result = self.action_aggregate(request, role_keys)
        result['average'] = str(Decimal(result['total']) / result['count'])
        return result
```

In ui.py, collect the fields that the new action needs. Use the existing aggregate branch as the model. Keep `input()` in ui.py and computation in the service. For an action without extra input, the current UI already sends its name.

## 5. When encryption must run on the client

The configurable record service implements server-side field encryption. Its encrypted channel protects transport, but that does not satisfy a question that explicitly places field encryption on the client.

For that requirement, start from `templates/net_client.py` and `net_server.py`:

1. In `make_envelope()`, collect the question fields and encrypt each field with its required algorithm.
2. Hash the specified canonical plaintext or stored envelope. Sign the same bytes with the sender's private key.
3. In the server's `submit()`, verify the sender signature before decryption or homomorphic computation.
4. Add role-authorized operations to `handle()`. Preserve the authenticated read requests and the server lock.
5. Store the ciphertext, signature, IV/nonce, public-key identity, and indexes together. Keep private keys outside the records.

The grant program demonstrates field encryption and signed encrypted records. The voting program demonstrates client-side hybrid wrapping, one-hot encrypted counts, and server verification. Copy those operations individually when required. The Lab 6 and Lab 7 codebooks show their standalone inputs and formulas.

## 6. Run and submission checks

Run `python -m unittest discover -s tests -v` from endsems. Then test your edited question with two records, a restart, a wrong password, an invalid number, and one modified ciphertext.

For sockets, start the server in terminal 1 and the client in terminal 2. Give both the same host and port. The default host is 127.0.0.1. Use `--host` explicitly for separate machines.

For a single-file menu submission, run `python bundle.py templates/plugplay/menu_app.py -o answer.py`.

For two socket files, run:

```bash
python bundle.py templates/plugplay/socket_server.py -o exam_server.py
python bundle.py templates/plugplay/socket_client.py -o exam_client.py
python exam_server.py --port 5000 --data exam_data
# In another terminal:
python exam_client.py --port 5000
```

Keep the generated files, data folder, and server pin file in separate roles as needed. Client key pinning detects later server-key changes. It does not authenticate the first connection. Verify the displayed fingerprint through a trusted channel for real use.

## 7. Limits to state in an exam

The templates demonstrate application permissions and cryptographic operations. Role-shared passwords and signing keys identify roles, not separate human users. Give each user a separate key for individual attribution.

The server can decrypt the submitted data it verifies. A local server key file is not a hardware security module. The supplied transport does not implement TLS, durable request replay prevention, rate limiting, or forward secrecy. A duplicate record ID is refused, but that is not a general replay protocol.

Aggregate minimums do not prevent inference from overlapping queries. A server that holds a Paillier private key can decrypt individual values outside the intended handler. The e-voting example's cooperative shares do not establish production threshold security.

