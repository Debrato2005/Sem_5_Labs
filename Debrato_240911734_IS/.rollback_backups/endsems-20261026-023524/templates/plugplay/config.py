"""EDIT THIS FILE FIRST. Menus and server permissions derive from this CONFIG."""
CONFIG = {
    'title': 'SECURE RECORDS',
    'fields': {'Description': 'text', 'Amount': 'number', 'Department': 'plain'},
    'roles': {
        'Researcher': ['submit', 'list'],
        'Reviewer': ['verify', 'search', 'decrypt'],
        'Finance Officer': ['list', 'aggregate'],
    },
    'cipher': 'AES',                 # AES / DES / DES3
    'bits': 192,                     # AES 128/192/256. DES always 64. DES3 128/192.
    'mode': 'CBC',                   # CBC / GCM(AES) / EAX / CTR / CFB / OFB / ECB
    'hash': 'md5',                   # md5 for grant question; prefer sha256 otherwise
    'signature': 'rsa',              # rsa / elgamal / ecdsa (ECDSA needs SHA-2)
    'places': 2,                     # 0 for integers, 2 for money
    'minimum': 2,                    # minimum distinct records/nonzero weights
    'max_abs': 10**12,               # PUBLIC bound on each SCALED integer
    'rsa_bits': 2048,
    'paillier_bits': 2048,
}
