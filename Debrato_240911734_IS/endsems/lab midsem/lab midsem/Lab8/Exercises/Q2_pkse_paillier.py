"""Lab 8 - Exercise 2  Public-Key Searchable Encryption (PKSE) with Paillier
 2a dataset of 10 documents             2b Paillier encrypt / decrypt
 2c encrypted index: E(h(word)) -> [E(doc_id)]   (anyone with the public key can build it)
 2d search: E(h(query)) with the public key; for each entry the server computes
       (E(h(w)) * E(h(q))^-1)^r = E(r * (h(w) - h(q)))
    which decrypts to 0 only for the matching word; matching doc ids are decrypted
    with the private key.
To modify: BITS (smaller = faster), sample_documents()."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

BITS = ask("Paillier key bits", 1024)
docs = sample_documents()
banner("2a. Dataset")
for d, t in docs.items():
    print(f"  {d:6}: {t}")

banner("2b. Paillier check")
pke = PKSE(BITS)
c = paillier_cipher(12345, pke.pub)
print(f"  E(12345) = {str(c)[:50]}...   D(E(12345)) = {paillier_cipher(c, pke.priv, decrypt=True)}")

banner("2c. Building encrypted index")
index, t = timed(pke.build, docs)
print(f"  {len(index)} entries built in {t:.2f}s; first entry:")
print(f"  E(h(word)) = {str(index[0][0])[:50]}...  -> {len(index[0][1])} encrypted doc id(s)")

banner("2d. Search")
for q in [ask("Search query", "encryption"), "patient", "fraud", "bitcoin"]:
    ids, t = timed(pke.search, q)
    print(f"\n  query '{q}' ({t:.2f}s) -> {ids if ids else 'no match'}")
    for d in ids:
        print(f"    {d}: {docs[d]}")
