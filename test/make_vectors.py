"""Writes test/vectors.json: encoding test vectors any gatepost/v1 writer (Apps Script
included) must reproduce byte for byte. Covers null, empty string, non-ASCII and the
0x1F case that collided under the August encoding."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from gp_encoding import ns, field, row_hash, GENESIS
cols = ["seq", "a", "b", "prev_hash"]
cases = [["1", "café", None], ["2", "", None], ["3", "a\x1fb", "c"], ["4", "a", "b\x1fc"], ["5", "Ω≈ç√", "0007"]]
out, prev = [], GENESIS
for seq, a, b in cases:
    r = {"seq": seq, "a": a, "b": b, "prev_hash": prev}
    r["row_hash"] = row_hash(r, cols)
    out.append({"row": r, "encoded_fields_hex": b"".join(field(r[c]) for c in cols).hex()})
    prev = r["row_hash"]
assert out[2]["row"]["row_hash"] != row_hash({**out[3]["row"], "prev_hash": out[2]["row"]["prev_hash"]}, cols), "0x1F collision"
assert ns("café") == b"5:caf\xc3\xa9,"
json.dump({"format": "gatepost/v1", "columns": cols, "vectors": out,
           "netstring_examples": {"café": ns("café").hex(), "": ns("").hex()}},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json"), "w"), indent=1, ensure_ascii=False)
print("vectors.json written;", len(out), "rows; 0x1F pair distinct; café = 5 bytes")
