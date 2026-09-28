#!/usr/bin/env python3
"""verify.py — offline verifier for gatepost/v1 evidence packs. Stdlib only.

usage: verify.py PACK_DIR [--expect-key KEY_ID] [--allow-unpinned] [--json]

Exit codes
  0  verified, and the final head is signed by the pinned key (or --allow-unpinned given)
  1  chain broken (row altered, removed, inserted, reordered)
  2  signature or head failure (bad signature, unsigned tail, key window, missing anchor)
  3  malformed pack
  4  final head not signed by the expected key
  5  chain and signatures valid but NO KEY PINNED: anyone who can edit the pack can
     replace keys and signatures together, so this is not a pass. Pin with --expect-key,
     using a key id obtained from somewhere the pack does not control.

A pass proves the record was not changed after it was written. It does not prove the
record is true or complete at write time. Encoding: see gp_encoding.py (inlined below
when bundled).
"""
import base64, hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gp_encoding import GENESIS, row_hash, head_stmt, key_id, schema_id

SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")

class Fail(Exception):
    def __init__(self, code, msg): self.code, self.msg = code, msg

def rsa_verify(n: int, e: int, msg: bytes, sig: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 / SHA-256. Builds the full expected encoded message and
    compares every byte; never parses padding (avoids Bleichenbacher-2006 forgeries)."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k: return False
    s = int.from_bytes(sig, "big")
    if s >= n: return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = SHA256_DIGESTINFO + hashlib.sha256(msg).digest()
    if k < len(t) + 11: return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected

def load(d):
    need = ["records.jsonl", "heads.jsonl", "keys.json", "manifest.json"]
    for f in need:
        if not os.path.isfile(os.path.join(d, f)): raise Fail(3, f"missing file: {f}")
    try:
        man = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
        keys = json.load(open(os.path.join(d, "keys.json"), encoding="utf-8"))
        rows = [json.loads(l) for l in open(os.path.join(d, "records.jsonl"), encoding="utf-8") if l.strip()]
        heads = [json.loads(l) for l in open(os.path.join(d, "heads.jsonl"), encoding="utf-8") if l.strip()]
    except (ValueError, OSError) as ex:
        raise Fail(3, f"unreadable pack: {ex}")
    if man.get("format") != "gatepost/v1": raise Fail(3, f"unsupported format: {man.get('format')!r}")
    if not rows: raise Fail(3, "empty record set")
    return man, keys, rows, heads

def check_head(h, keys, row_at):
    k = keys.get(h.get("key_id"))
    if k is None: raise Fail(2, f"head at seq {h.get('seq')}: unknown key {h.get('key_id')}")
    if not (k["effective_from"] <= h["signed_at"] and (k.get("retired_at") is None or h["signed_at"] < k["retired_at"])):
        raise Fail(2, f"head at seq {h['seq']}: signed outside key {h['key_id']} validity window")
    stmt = head_stmt(h["head_hash"], h["seq"], h["signed_at"], h["session_id"], h["key_id"])
    try: sig = base64.b64decode(h["signature"], validate=True)
    except Exception: raise Fail(2, f"head at seq {h['seq']}: signature not base64")
    if not rsa_verify(int(k["n_hex"], 16), int(k["e"]), stmt, sig):
        raise Fail(2, f"head at seq {h['seq']}: signature invalid")
    if row_at is not None and row_at != h["head_hash"]:
        raise Fail(2, f"head at seq {h['seq']}: head_hash does not match row_hash at that seq")

def verify(d, expect_key=None, allow_unpinned=False):
    man, keylist, rows, heads = load(d)
    cols = man.get("columns")
    if not isinstance(cols, list) or cols[0] != "seq" or cols[-1] != "row_hash":
        raise Fail(3, "manifest.columns must start with seq and end with row_hash")
    keys = {}
    for k in keylist:
        if key_id(k["n_hex"], int(k["e"])) != k["key_id"]:
            raise Fail(3, f"key {k['key_id']}: id does not derive from its modulus")
        if int(k["e"]) < 65537: raise Fail(3, f"key {k['key_id']}: public exponent below 65537")
        keys[k["key_id"]] = k
    if expect_key and expect_key not in keys: raise Fail(4, f"expected key {expect_key} not present in pack")
    if "schema" in cols:
        sid = schema_id(man["schema_name"], [c for c in cols if c != "row_hash"])
    # chain
    anchor = man.get("anchor")
    first = int(rows[0]["seq"])
    if first == 1:
        prev = GENESIS
    else:
        if not anchor: raise Fail(2, f"partial export from seq {first} has no signed anchor")
        if int(anchor["seq"]) != first - 1: raise Fail(2, "anchor is not the head at from-1")
        check_head(anchor, keys, None)
        prev = anchor["head_hash"]
    by_seq = {}
    for i, r in enumerate(rows):
        if set(r) != set(cols): raise Fail(3, f"row {i}: columns differ from manifest")
        if any(v is not None and not isinstance(v, str) for v in r.values()):
            raise Fail(3, f"row {i}: values must be strings or null")
        seq = int(r["seq"])
        if seq != first + i: raise Fail(1, f"seq out of order or missing at position {i} (got {seq}, want {first+i})")
        if "schema" in cols and r["schema"] != sid: raise Fail(1, f"schema binding broken at seq {seq}")
        if r["prev_hash"] != prev: raise Fail(1, f"prev_hash mismatch at seq {seq}")
        if row_hash(r, cols) != r["row_hash"]: raise Fail(1, f"row altered at seq {seq}")
        prev = r["row_hash"]; by_seq[seq] = prev
    last = first + len(rows) - 1
    # heads
    for h in heads:
        s = int(h["seq"])
        if s not in by_seq: raise Fail(2, f"head at seq {s} outside exported range")
        check_head(h, keys, by_seq[s])
    covered = max((int(h["seq"]) for h in heads), default=0)
    if covered < last: raise Fail(2, f"{last - covered} row(s) after the last signed head")
    if int(man.get("row_count", -1)) != len(rows) or man.get("chain_head") != by_seq[last]:
        raise Fail(3, "manifest row_count/chain_head disagree with records")
    final = max(heads, key=lambda h: int(h["seq"]))
    summary = f"{len(rows)} rows, seq {first}-{last}, {len(heads)} signed heads, final key {final['key_id']}"
    if expect_key:
        if final["key_id"] != expect_key: raise Fail(4, "final head not signed by expected key")
        return 0, "OK " + summary
    if allow_unpinned:
        return 0, "OK (UNPINNED — proves integrity only against whoever holds these keys) " + summary
    raise Fail(5, "UNPINNED: chain and signatures valid, but no --expect-key given. " + summary)

def main(argv):
    args = argv[1:]; js = "--json" in args
    exp = args[args.index("--expect-key") + 1] if "--expect-key" in args else None
    d = next((a for a in args if not a.startswith("--") and a != exp), None)
    if not d: print(__doc__); return 3
    try: code, msg = verify(d, exp, "--allow-unpinned" in args)
    except Fail as f: code, msg = f.code, f.msg
    except (KeyError, TypeError, ValueError) as ex: code, msg = 3, f"malformed pack: {ex!r}"
    print(json.dumps({"exit": code, "result": msg}) if js else msg)
    return code

if __name__ == "__main__":
    sys.exit(main(sys.argv))
