Oregon Legislature: Measures.Vetoed vs recorded 'Governor vetoed.' actions

Oregon's public API records a 'Governor vetoed.' action on 27 measures (3 of them later became law by override). Measures.Vetoed is true on 27 and false on 0; 0 of the false values contradict a veto that stood.

Verify (Python 3, no install):
  python3 verify.py chain --pubkey <the public key published by the operator> --anchor anchor.json

Pin the public key from the operator's published location, NOT from keyring.json in this folder:
a copy shipped inside the pack proves nothing about who made it.
