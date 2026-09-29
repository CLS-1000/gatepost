"""gpcanon against the G1 golden vectors (spec/vectors/gatepost-vectors-v1.json).

This is the conformance check CANON §9 requires: a third implementation, sharing no
code with spec/ref/, must reproduce every vector. It also runs gpcanon's verifier
(package and bundled bin/verify.py) over the signed 20-record sample chain.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from gpcanon.canon import CanonError, canon, decimal_from_float, digest, parse, record_hash, sha256_hex
from gpcanon.ed25519_verify import verify as ed_verify
from gpcanon.schema import validate_sealed
from gpcanon.verify import verify_chain
from gpcanon.writer import SEAL_DOMAIN, key_id_of

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "spec" / "vectors" / "gatepost-vectors-v1.json").read_text(encoding="utf-8"))
JSONL = (ROOT / "spec" / "vectors" / "chain-spec1.publish.jsonl").read_bytes()
PUB = bytes.fromhex(V["test_key"]["public_key_hex"])


def ids(section):
    return [v["id"] for v in V[section]]


@pytest.mark.parametrize("v", V["canon_vectors"], ids=ids("canon_vectors"))
def test_canon_vectors(v):
    c = canon(parse(v["input"].encode("utf-8")))
    assert c.hex() == v["canon_hex"]
    assert sha256_hex(c) == v["sha256"]


@pytest.mark.parametrize("v", V["reject_vectors"], ids=ids("reject_vectors"))
def test_reject_vectors(v):
    with pytest.raises(CanonError) as e:
        parse(v["input"].encode("utf-8", "surrogatepass"))
    assert e.value.reason == v["reason"]


@pytest.mark.parametrize("v", V["decimal_vectors"], ids=ids("decimal_vectors"))
def test_decimal_vectors(v):
    assert decimal_from_float(float(v["float"]), v["places"]) == v["expect"]


@pytest.mark.parametrize("v", V["schema_vectors"], ids=ids("schema_vectors"))
def test_schema_vectors(v):
    got = sorted({code for code, _ in validate_sealed(parse(v["sealed"].encode("utf-8")))})
    assert got == v["errors"], v["note"]


def test_test_key_id():
    assert key_id_of(PUB) == V["test_key"]["key_id"]


def test_sample_chain_records():
    lines = JSONL.split(b"\n")
    assert lines.pop() == b""
    prev = "0" * 64
    for n, raw in enumerate(lines):
        exp = V["chain"]["records"][n]
        line = parse(raw)
        assert canon(line) == raw
        s = line["s"]
        assert record_hash(s) == line["h"] == exp["hash"]
        assert s["prev_hash"] == prev and s["seq"] == n
        assert validate_sealed(s) == []
        if "inputs" in exp:
            assert digest(exp["inputs"]) == s["inputs_digest"]
        if s["kind"] == "seal":
            assert ed_verify(PUB, SEAL_DOMAIN + canon(s), bytes.fromhex(line["sig"]))
        prev = line["h"]


@pytest.fixture
def chain_dir(tmp_path):
    d = tmp_path / "spec1.publish"
    d.mkdir()
    (d / "seg-000000000000.jsonl").write_bytes(JSONL)
    return d


def test_verifier_passes_the_sample_chain(chain_dir):
    rep = verify_chain(chain_dir, {V["test_key"]["key_id"]: PUB})
    assert rep.exit_code() == 0, rep.findings
    assert rep.records == 20 and rep.seals == 2
    r = subprocess.run([sys.executable, str(ROOT / "bin" / "verify.py"), str(chain_dir),
                        "--pubkey", PUB.hex(), "--json"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_verifier_catches_tampering_in_the_sample_chain(chain_dir):
    seg = chain_dir / "seg-000000000000.jsonl"
    data = seg.read_bytes()
    seg.write_bytes(data.replace(b'"decision":"deny"', b'"decision":"allow"', 1))
    rep = verify_chain(chain_dir, {V["test_key"]["key_id"]: PUB})
    assert rep.exit_code() in (1, 3) and rep.codes() & {"hash_mismatch", "decision_reason_mismatch"}


def test_schema_table_matches_all_three_implementations():
    """SCHEMA.md §3's table, gpcanon, and both references must list the same fields per kind."""
    import importlib.util
    import re as _re
    text = (ROOT / "spec" / "SCHEMA.md").read_text(encoding="utf-8")
    rows = [l for l in text.split("## 3.")[1].split("● required")[0].splitlines() if l.startswith("| `")]
    header = [h.strip() for h in text.split("## 3.")[1].split("\n| field |")[1].split("\n")[0].split("|")[:-1]]
    doc = {k: set() for k in header}
    for row in rows:
        cells = [c.strip() for c in row.split("|")[1:-1]]
        for kind, cell in zip(header, cells[1:]):
            if cell.startswith("●"):
                doc[kind].add(cells[0].strip("`"))
    from gpcanon.schema import FIELDS as gp
    spec = importlib.util.spec_from_file_location("gp_canon_ref", ROOT / "spec" / "ref" / "gp_canon.py")
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    js = (ROOT / "spec" / "ref" / "gp_canon.mjs").read_text()
    common = _re.findall(r'"([a-z_]+)"', js.split("const COMMON = [")[1].split("]")[0])
    shape = js.split("const SHAPE = {")[1].split("};")[0]
    js_fields = {}
    for m in _re.finditer(r"(\w+): \[\.\.\.COMMON,([^\]]*)\]", shape):
        js_fields[m.group(1)] = set(common) | set(_re.findall(r'"([a-z_]+)"', m.group(2)))
    assert set(doc) == set(gp) == set(ref.FIELDS) == set(js_fields)
    for kind in doc:
        assert doc[kind] == set(gp[kind]) == set(ref.FIELDS[kind]) == js_fields[kind], kind
