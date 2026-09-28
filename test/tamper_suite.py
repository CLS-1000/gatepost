#!/usr/bin/env python3
"""Tamper suite for gatepost/v1 (blueprint §6 plus three cases it did not cover).
Builds a rotated fixture from a sealed pack's rows: key A signs seq 13, rotates, key B signs 27.
usage: tamper_suite.py SEALED_PACK KEY_A.pem KEY_B.pem ATTACKER.pem"""
import base64, copy, json, os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); TOOLS = os.path.join(HERE, "..", "tools")
sys.path.insert(0, TOOLS)
from gp_writer import Chain, public_key
from gp_encoding import row_hash

src, KA, KB, KX = sys.argv[1:5]
rows = [json.loads(l) for l in open(os.path.join(src, "records.jsonl"))]
man0 = json.load(open(os.path.join(src, "manifest.json")))
cols = [c for c in man0["columns"] if c != "row_hash"]
data = [{c: r[c] for c in cols if c not in ("seq", "schema", "prev_hash")} for r in rows]
A, B, X = public_key(KA), public_key(KB), public_key(KX)

def build(keys_fn=None):
    c = Chain(cols, schema_name=man0["schema_name"])
    c.add_key(A, "2026-09-27T00:00:00Z")
    for d in data[:13]: c.append(d)
    c.sign_head(KA, "s1", "2026-09-27T10:00:00Z")
    c.add_key(B, "2026-09-27T11:00:00Z")          # retires A
    for d in data[13:]: c.append(d)
    c.sign_head(KB, "s2", "2026-09-27T12:00:00Z")
    return c

base = build()
tmp = tempfile.mkdtemp()
def pack(name, chain=base, from_seq=1, drop_anchor=False):
    d = os.path.join(tmp, name); chain.export(d, from_seq=from_seq)
    if drop_anchor:
        m = json.load(open(f"{d}/manifest.json")); m.pop("anchor"); json.dump(m, open(f"{d}/manifest.json", "w"))
    return d
def rd(d, f): return [json.loads(l) for l in open(f"{d}/{f}")]
def wr(d, f, rs): open(f"{d}/{f}", "w").write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rs))
def fix_manifest(d):
    rs = rd(d, "records.jsonl"); m = json.load(open(f"{d}/manifest.json"))
    m["row_count"] = len(rs); m["chain_head"] = rs[-1]["row_hash"]; json.dump(m, open(f"{d}/manifest.json", "w"))
def rechain(rs, columns):
    prev = "0" * 64
    for r in rs: r["prev_hash"] = prev; r["row_hash"] = row_hash(r, columns); prev = r["row_hash"]

cases = []
def case(name, want, d, *flags): cases.append((name, want, d, flags))

case("None (clean, key A -> B), pinned B", 0, pack("clean"), "--expect-key", B["key_id"])
case("None, unpinned", 5, pack("clean_u"))
case("None, unpinned with --allow-unpinned", 0, pack("clean_a"), "--allow-unpinned")

d = pack("edit"); rs = rd(d, "records.jsonl"); rs[11]["field_value"] = "false" if rs[11]["field_value"] == "true" else "true"; wr(d, "records.jsonl", rs)
case("Edit one field (flip seq 12 Vetoed value)", 1, d, "--expect-key", B["key_id"])

d = pack("null"); rs = rd(d, "records.jsonl"); rs[4]["current_location"] = None; wr(d, "records.jsonl", rs)
d2 = pack("nullstr"); rs2 = rd(d2, "records.jsonl"); rs2[4]["history_action"] = ""; wr(d2, "records.jsonl", rs2)
case("String -> null", 1, d, "--expect-key", B["key_id"])
case("String -> empty string", 1, d2, "--expect-key", B["key_id"])

d = pack("del"); rs = rd(d, "records.jsonl"); del rs[6]; wr(d, "records.jsonl", rs); fix_manifest(d)
case("Delete a middle row", 1, d, "--expect-key", B["key_id"])

d = pack("swap"); rs = rd(d, "records.jsonl"); rs[3], rs[4] = rs[4], rs[3]; wr(d, "records.jsonl", rs)
case("Swap two rows", 1, d, "--expect-key", B["key_id"])

d = pack("rechain"); rs = rd(d, "records.jsonl"); rs[20]["finding"] = "consistent"
rechain(rs, man0["columns"]); wr(d, "records.jsonl", rs); fix_manifest(d)
case("Edit, then recompute the whole chain", 2, d, "--expect-key", B["key_id"])

d = pack("trunc"); rs = rd(d, "records.jsonl")[:-5]; wr(d, "records.jsonl", rs)
wr(d, "heads.jsonl", [h for h in rd(d, "heads.jsonl") if int(h["seq"]) <= 22]); fix_manifest(d)
case("Truncate 5 rows and drop the final head", 2, d, "--expect-key", B["key_id"])

d = pack("drophead"); wr(d, "heads.jsonl", rd(d, "heads.jsonl")[:1])
case("Drop the final head only", 2, d, "--expect-key", B["key_id"])

d = pack("movesig"); hs = rd(d, "heads.jsonl"); hs[0]["seq"] = "12"; hs[0]["head_hash"] = rd(d, "records.jsonl")[11]["row_hash"]; wr(d, "heads.jsonl", hs)
case("Move a signature to another row", 2, d, "--expect-key", B["key_id"])

late = build(); late.sign_head(KA, "s3", "2026-09-27T13:00:00Z")
case("Retired key signs a new head", 2, pack("retired", late))

case("Partial export 14-27, anchored", 0, pack("part", from_seq=14), "--expect-key", B["key_id"])
case("Partial export 14-27, no anchor", 2, pack("partna", from_seq=14, drop_anchor=True), "--expect-key", B["key_id"])

# attacker rewrites a finding and re-signs everything with their own key
forged = Chain(cols, schema_name=man0["schema_name"]); forged.add_key(X, "2026-09-27T00:00:00Z")
for i, dd in enumerate(data):
    dd = dict(dd)
    if i == 20: dd["finding"] = "consistent"; dd["field_value"] = "true"
    forged.append(dd)
forged.sign_head(KX, "s1", "2026-09-27T12:00:00Z")
case("Attacker rewrites and re-signs, unpinned", 5, pack("forged", forged))
case("Attacker rewrites and re-signs, unpinned + --allow-unpinned", 0, pack("forged_a", forged), "--allow-unpinned")
case("Same attack, pinned to B", 4, pack("forged_p", forged), "--expect-key", B["key_id"])

# NEW: relabel two columns in the manifest and swap the keys in every record
d = pack("relabel"); m = json.load(open(f"{d}/manifest.json")); cs = m["columns"]
i, j = cs.index("field_value"), cs.index("current_location"); cs[i], cs[j] = cs[j], cs[i]
json.dump(m, open(f"{d}/manifest.json", "w"))
rs = rd(d, "records.jsonl")
for r in rs: r["field_value"], r["current_location"] = r["current_location"], r["field_value"]
wr(d, "records.jsonl", rs)
case("NEW: relabel two columns (swap names + values)", 1, d, "--expect-key", B["key_id"])

# NEW: flip one signature byte
d = pack("flip"); hs = rd(d, "heads.jsonl"); s = bytearray(base64.b64decode(hs[1]["signature"])); s[-1] ^= 1
hs[1]["signature"] = base64.b64encode(bytes(s)).decode(); wr(d, "heads.jsonl", hs)
case("NEW: flip one signature byte", 2, d, "--expect-key", B["key_id"])

d = pack("missing"); os.remove(f"{d}/heads.jsonl")
case("Missing heads.jsonl", 3, d)

ok = 0
for name, want, d, flags in cases:
    p = subprocess.run([sys.executable, os.path.join(TOOLS, "verify.py"), d, *flags], capture_output=True, text=True)
    good = p.returncode == want; ok += good
    print(f"{'PASS' if good else 'FAIL'}  exit {p.returncode} (want {want})  {name}\n        {p.stdout.strip()[:110]}")
print(f"\n{ok}/{len(cases)} cases behaved as specified")
shutil.rmtree(tmp); sys.exit(0 if ok == len(cases) else 1)
