"""gatepost/v1 canonical encoding (blueprint §4). Shared by writer and verifier.

ns(s)    = ascii(len(utf8(s))) ":" utf8(s) ","      netstring, length in BYTES
field(v) = "~" if v is None else "=" ns(v)            strings only
row_hash = hex(SHA-256( ns("gatepost/row/v1") field(c1) ... field(cN) ))
           c1..cN = every column in schema order except row_hash; prev_hash is last
head_stmt= ns("gatepost/head/v1") ns(head_hash) ns(seq) ns(signed_at) ns(session_id) ns(key_id)
key_id   = first 32 hex of SHA-256( ns(lowercase n hex) ns(decimal e) )

Schema binding (extension for non-Gatepost record types): column c2 is `schema`, whose
value is "<name>:" + first 16 hex of SHA-256 over ns(col) for every column. Because it is
hashed into every row, relabelling columns in the manifest breaks the chain.
"""
import hashlib
GENESIS = "0" * 64
ROW_TAG, HEAD_TAG = "gatepost/row/v1", "gatepost/head/v1"

def ns(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError(f"netstring value must be str, got {type(s).__name__}")
    b = s.encode("utf-8")
    return str(len(b)).encode("ascii") + b":" + b + b","

def field(v) -> bytes:
    return b"~" if v is None else b"=" + ns(v)

def row_hash(row: dict, columns: list) -> str:
    cols = [c for c in columns if c != "row_hash"]
    if cols[0] != "seq" or cols[-1] != "prev_hash":
        raise ValueError("columns must start with seq and end with prev_hash")
    return hashlib.sha256(ns(ROW_TAG) + b"".join(field(row[c]) for c in cols)).hexdigest()

def head_stmt(head_hash, seq, signed_at, session_id, key_id) -> bytes:
    return ns(HEAD_TAG) + ns(head_hash) + ns(seq) + ns(signed_at) + ns(session_id) + ns(key_id)

def key_id(n_hex: str, e: int) -> str:
    return hashlib.sha256(ns(n_hex.lower()) + ns(str(e))).hexdigest()[:32]

def schema_id(name: str, columns: list) -> str:
    return name + ":" + hashlib.sha256(b"".join(ns(c) for c in columns)).hexdigest()[:16]
