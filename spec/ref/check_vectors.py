"""Runs every G1 vector through the Python reference.  python3 ref/check_vectors.py

Seal signatures are checked with the pure-Python RFC 8032 verifier, not with
the `cryptography` package that produced them.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gp_canon as gc  # noqa: E402
import ed25519_verify as ev  # noqa: E402

V = json.load(open(os.path.join(HERE, "..", "vectors", "gatepost-vectors-v1.json"), encoding="utf-8"))
JSONL = open(os.path.join(HERE, "..", "vectors", "chain-spec1.publish.jsonl"), encoding="utf-8", newline="").read()
passed = failed = 0


def ok(cond, vid, msg):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print(f"FAIL {vid}: {msg}")


for v in V["canon_vectors"]:
    c = gc.canon(gc.strict_loads(v["input"]))
    ok(c.hex() == v["canon_hex"], v["id"], "canon")
    ok(gc.sha256_hex(c) == v["sha256"], v["id"], "sha256")
for v in V["reject_vectors"]:
    try:
        gc.strict_loads(v["input"])
        code = "accepted"
    except gc.CanonError as e:
        code = e.code
    ok(code == v["reason"], v["id"], f"{code} != {v['reason']}")
for v in V["decimal_vectors"]:
    got = gc.decimal_from_float(float(v["float"]), v["places"])
    ok(got == v["expect"], v["id"], f"{got} != {v['expect']}")
for v in V["schema_vectors"]:
    got = gc.validate_sealed(gc.strict_loads(v["sealed"]))
    ok(got == v["errors"], v["id"], f"{got} != {v['errors']}")

pub = bytes.fromhex(V["test_key"]["public_key_hex"])
ok(gc.key_id(pub) == V["test_key"]["key_id"], "key_id", "key_id")
lines = JSONL.split("\n")
ok(lines.pop() == "", "jsonl", "file must end with a newline")
prev = gc.GENESIS_PREV
for n, text in enumerate(lines):
    vid, exp = f"chain#{n}", V["chain"]["records"][n]
    line = gc.strict_loads(text)
    ok(gc.canon(line).decode() == text, vid, "stored line is not canonical")
    ok(set(line) <= {"h", "n", "s", "sig"}, vid, "unexpected line key")
    s = line["s"]
    h = gc.record_hash(s)
    ok(h == line["h"] == exp["hash"], vid, "record hash")
    ok(s["prev_hash"] == prev, vid, "prev_hash link")
    ok(s["seq"] == n, vid, "seq")
    ok(s["chain_id"] == V["chain"]["chain_id"], vid, "chain_id")
    ok(gc.validate_sealed(s) == [], vid, "schema")
    if "inputs" in exp:
        ok(gc.inputs_digest(exp["inputs"]) == s["inputs_digest"], vid, "inputs_digest")
    is_seal = s["kind"] == "seal"
    ok(is_seal == ("sig" in line), vid, "sig present iff seal")
    if is_seal:
        sig = bytes.fromhex(line["sig"])
        ok(ev.verify(pub, gc.seal_message(s), sig), vid, "seal signature")
        ok(not ev.verify(pub, gc.seal_message(dict(s, seq=n + 1)), sig), vid, "tampered seal must not verify")
    prev = h
print(f"Python: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
