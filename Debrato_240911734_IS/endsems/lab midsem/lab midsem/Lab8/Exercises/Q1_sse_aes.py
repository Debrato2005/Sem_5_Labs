"""Lab 8 - Exercise 1  Symmetric Searchable Encryption (SSE) with AES
 1a dataset of 10 documents            1b AES encrypt / decrypt functions
 1c inverted index word -> doc ids, encrypted:
      key   = AES-ECB(K, SHA256(word))   deterministic, so equal words give equal tokens
      value = AES-CBC(K, doc_id)         randomised
 1d search: encrypt the query the same way, look it up, decrypt ids, show documents.
(The manual's sample code uses random-IV CBC for the index key, which can never match a
query - deterministic encryption of the keyword is what makes the index searchable.)
To modify: replace sample_documents() with your own dict {doc_id: text}."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

docs = sample_documents()
banner("1a. Dataset")
for d, t in docs.items():
    print(f"  {d:6}: {t}")

sse = SSE()
index = sse.build(docs)
banner("1b/1c. Encrypted inverted index (what the server stores)")
for tok, ids in list(index.items())[:3]:
    print(f"  {fmt(tok)[:32]}... -> {[fmt(i)[:16] + '...' for i in ids]}")
print(f"  ... {len(index)} encrypted entries; documents stored AES-CBC encrypted too")
print("  doc1 on server:", fmt(sse.enc_docs["doc1"])[:64], "...")

banner("1d. Search")
for q in [ask("Search query", "encryption"), "patient", "cloud data", "bitcoin"]:
    print(f"\n  query '{q}'  -> token {fmt(sse.token(q.split()[0]))[:24]}...")
    res = sse.search(q)
    for d, text in res.items():
        print(f"    {d}: {text}")
    if not res:
        print("    no matching documents")
