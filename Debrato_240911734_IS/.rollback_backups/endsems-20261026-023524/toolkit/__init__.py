"""IS Lab exam toolkit.  One module per topic; import what you need:

    from toolkit.util import ask, ask_int, menu, load_json, save_json   # glue
    from toolkit.classical import ...      # Lab 1
    from toolkit.symmetric import ...      # Lab 2
    from toolkit.asymmetric import ...     # Labs 3-4 (RSA, ElGamal, Rabin, DH, ECC)
    from toolkit.access import ...         # Lab 4 (KMS, RBAC/ABAC/BLP/...)
    from toolkit.hashing import ...        # Lab 5
    from toolkit.signatures import ...     # Lab 6 (+ timestamp authority)
    from toolkit.homomorphic import ...    # Lab 7 (Paillier, threshold, RSA/ElGamal)
    from toolkit.searchable import ...     # Lab 8 (SSE, Paillier PKSE)
    from toolkit.net import ...            # sockets + HTTP API
    from toolkit.records import RecordApp  # same record operations for menu/TCP/HTTP

Dependencies: access -> asymmetric, searchable -> homomorphic. RecordApp uses
the shared crypto, input/storage, and search modules. `python bundle.py answer.py` inlines the
imported modules into one self-contained file.
"""
