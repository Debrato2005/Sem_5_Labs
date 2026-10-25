"""Lab 8 - searchable encryption.

SSE  (symmetric): keyword -> HMAC-SHA256 token (deterministic, keyed) -> posting
     list of AES-GCM-encrypted document IDs; documents AES-GCM encrypted.
     The server matches tokens without seeing words, IDs or contents.
     Leakage (normal for SSE): equal queries give equal tokens (search pattern)
     and the server sees how many results a token has (access pattern).
PKSE (Paillier, lab exercise 2): every keyword stored as E(H(w)); the query is
     E(H(q)) under the PUBLIC key; the server homomorphically computes
     E(r*(H(w)-H(q))) per entry; only the PRIVATE-key holder can see which
     entries decrypt to 0 (= match) and decrypt the matching document IDs.

Why the lab manual's sample code never finds anything: it 'encrypts' the
keyword with AES-CBC using a fresh random IV (or RSA-OAEP), so the same word
encrypts differently every time and dictionary lookup fails.  Search needs a
DETERMINISTIC keyed token (HMAC / AES-ECB of a hash) or a homomorphic test.
"""
import hashlib
import hmac
import re
from math import gcd

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from toolkit.homomorphic import paillier_decrypt, paillier_encrypt, paillier_mul_const, paillier_sub

WORD = re.compile(r"[\w']+")


def normalize(word):
    return word.strip().casefold()


def words_of(text):
    return {normalize(w) for w in WORD.findall(text)}


def new_search_keys():
    """{'enc': AES-256 key, 'tok': HMAC key} - keep both secret, persist both."""
    return {'enc': get_random_bytes(32).hex(), 'tok': get_random_bytes(32).hex()}


def token(tok_key, word, field='kw'):
    """Search trapdoor: HMAC-SHA256(key, field:word).  Same input -> same token."""
    if isinstance(tok_key, str):
        tok_key = bytes.fromhex(tok_key)
    return hmac.new(tok_key, f'{field}:{normalize(str(word))}'.encode(), hashlib.sha256).hexdigest()


def det_token_aes(aes_key, word):
    """Manual-style 'encrypt the query': AES-ECB(SHA-256(word)) is deterministic,
    so it also works as a token (one 16-byte block, no IV)."""
    return AES.new(aes_key, AES.MODE_ECB).encrypt(hashlib.sha256(normalize(word).encode()).digest()[:16]).hex()


def seal(key, data):
    """AES-GCM -> hex(nonce|tag|ct)."""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data)
    return (c.nonce + tag + ct).hex()


def unseal(key, blob_hex):
    if isinstance(key, str):
        key = bytes.fromhex(key)
    b = bytes.fromhex(blob_hex)
    return AES.new(key, AES.MODE_GCM, nonce=b[:16]).decrypt_and_verify(b[32:], b[16:32])


# ============================================================ SSE (Lab 8.1) =
def new_store():
    """Server-side state: encrypted docs + encrypted inverted index (JSON-safe)."""
    return {'docs': {}, 'index': {}}


def _handle(keys, doc_id):
    return token(keys['tok'], doc_id, 'doc')[:32]


def sse_add(store, keys, doc_id, text, extra_keywords=()):
    """Encrypt document, add its words (+ extra keywords) to the index."""
    h = _handle(keys, doc_id)
    if h in store['docs']:
        raise ValueError(f'document {doc_id!r} already stored')
    store['docs'][h] = seal(keys['enc'], text.encode())
    for w in words_of(text) | {normalize(k) for k in extra_keywords}:
        store['index'].setdefault(token(keys['tok'], w), []).append(seal(keys['enc'], doc_id.encode()))


def sse_lookup(store, keys, word):
    """Client: token -> server returns encrypted IDs -> client decrypts IDs."""
    return {unseal(keys['enc'], e).decode() for e in store['index'].get(token(keys['tok'], word), [])}


def sse_search(store, keys, query, op='AND'):
    """Multi-word query with AND / OR; returns sorted doc IDs."""
    if op.upper() not in ('AND', 'OR'):
        raise ValueError('op must be AND or OR')
    sets = [sse_lookup(store, keys, w) for w in words_of(query)]
    if not sets:
        return []
    res = set.intersection(*sets) if op.upper() == 'AND' else set.union(*sets)
    return sorted(res)


def sse_read(store, keys, doc_id):
    return unseal(keys['enc'], store['docs'][_handle(keys, doc_id)]).decode()


def sse_remove(store, keys, doc_id):
    sse_read(store, keys, doc_id)  # Check the document before changing the store.
    # Scan all postings because extra keywords need not occur in the document.
    index = {t: [e for e in entries if unseal(keys['enc'], e).decode() != doc_id]
             for t, entries in store['index'].items()}
    store['index'] = {t: entries for t, entries in index.items() if entries}
    del store['docs'][_handle(keys, doc_id)]


# ----- record-level equality / range index (IDs, constituency, date ...) ----
def field_index_add(index, tok_key, field, value, record_id):
    """index[token(field=value)] -> [record_id]; e.g. field='constituency'."""
    index.setdefault(token(tok_key, value, field), []).append(record_id)


def field_index_find(index, tok_key, field, value):
    return list(index.get(token(tok_key, value, field), []))


def field_index_find_any(index, tok_key, field, values):
    """Range search via buckets: pass every bucket label in the range
    (e.g. util.hour_buckets(start, end)) and union the hits."""
    out = []
    for v in values:
        for r in index.get(token(tok_key, v, field), []):
            if r not in out:
                out.append(r)
    return out


# ======================================================= PKSE (Lab 8.2) =====
def h_word(word):
    return int.from_bytes(hashlib.sha256(normalize(word).encode()).digest(), 'big')


def id_to_int(doc_id):
    return int.from_bytes(b'\x01' + doc_id.encode(), 'big')


def int_to_id(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')[1:].decode()


def pkse_build(pub, docs):
    """docs {id: text} -> encrypted index [{'kw': E(H(w)), 'ids': [E(id)...]}].
    Needs only the PUBLIC key (anyone can contribute documents)."""
    postings = {}
    for doc_id, text in docs.items():
        for w in words_of(text):
            postings.setdefault(w, []).append(doc_id)
    return [{'kw': paillier_encrypt(pub, h_word(w)),
             'ids': [paillier_encrypt(pub, id_to_int(d)) for d in ids]}
            for w, ids in postings.items()]


def pkse_query(pub, word):
    """Encrypted query (randomised: server cannot tell repeated queries apart)."""
    return paillier_encrypt(pub, h_word(word))


def pkse_server_match(pub, index, enc_query):
    """Server (no private key): E(r_i * (H(w_i) - H(q))) for every entry."""
    from Crypto.Random import random
    blinded = []
    for e in index:
        r = random.randint(1, pub['n'] - 1)
        while gcd(r, pub['n']) != 1:
            r = random.randint(1, pub['n'] - 1)
        blinded.append(paillier_mul_const(pub, paillier_sub(pub, e['kw'], enc_query), r))
    return blinded


def pkse_client_resolve(priv, index, blinded):
    """Private-key holder: entries decrypting to 0 match; decrypt their IDs."""
    if len(index) != len(blinded):
        raise ValueError('server must return one blinded result per index entry')
    out = []
    for e, b in zip(index, blinded):
        if paillier_decrypt(priv, b) == 0:
            out += [int_to_id(paillier_decrypt(priv, c)) for c in e['ids']]
    return sorted(set(out))
