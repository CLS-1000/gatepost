"""tools/gp_operator.py, offline: key handling, pack building, change detection. No network."""
import importlib.util
import json
from pathlib import Path

import pytest

from gpcanon.canon import parse

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "out" / "or_veto_pack_DEMO_KEY" / "records.jsonl"


@pytest.fixture
def op(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEPOST_HOME", str(tmp_path / "home"))
    spec = importlib.util.spec_from_file_location("gp_operator", ROOT / "tools" / "gp_operator.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def records(pack):
    return [parse(l)["s"] for l in (pack / "chain" / "seg-000000000000.jsonl").read_bytes().splitlines()]


def test_keygen_creates_private_key_and_refuses_to_overwrite(op, tmp_path):
    assert op.main(["keygen"]) == 0
    key = tmp_path / "home" / "op_key.pem"
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "home").stat().st_mode & 0o777) == "0o700"
    before = key.read_bytes()
    assert op.main(["keygen"]) == 2 and key.read_bytes() == before


def test_pack_needs_a_key_first(op, tmp_path):
    assert op.main(["veto-pack", "--out", str(tmp_path / "p"), "--from-v1", str(V1)]) == 2


def test_pack_from_v1_reproduces_the_sep27_findings(op, tmp_path):
    op.main(["keygen"])
    assert op.main(["veto-pack", "--out", str(tmp_path / "p"), "--from-v1", str(V1)]) == 0
    rs = records(tmp_path / "p")
    types = [r.get("finding_type") for r in rs if r["kind"] == "finding"]
    assert types.count("proc_track.field_contradicts_history") == 23
    assert types.count("proc_track.overridden_into_law") == 3
    assert types.count("proc_track.consistent") == 1
    summary = next(r for r in rs if r.get("finding_type") == "proc_track.veto_field_summary")
    assert "27 measures (3 of them later became law by override)" in summary["claim"]
    assert "23 of the false values contradict" in summary["claim"]
    assert rs[-1]["kind"] == "seal"
    assert op.main(["verify", str(tmp_path / "p")]) == 0


def test_refuses_to_add_to_an_existing_pack(op, tmp_path):
    op.main(["keygen"])
    op.main(["veto-pack", "--out", str(tmp_path / "p"), "--from-v1", str(V1)])
    assert op.main(["veto-pack", "--out", str(tmp_path / "p"), "--from-v1", str(V1)]) == 2


def test_baseline_records_each_changed_measure(op, tmp_path, monkeypatch):
    """Live pull simulated as 'Legislature set Vetoed=true everywhere', as observed 2026-09-29."""
    op.main(["keygen"])
    fixed = [dict(r, vetoed_field=True, retrieved_at="2026-09-29T03:28:48.884909Z") for r in op.veto_rows_from_v1(V1)]
    monkeypatch.setattr(op, "veto_rows_live", lambda: fixed)
    assert op.main(["veto-pack", "--out", str(tmp_path / "p"), "--baseline-v1", str(V1)]) == 0
    rs = records(tmp_path / "p")
    changed = [r for r in rs if r.get("finding_type") == "proc_track.field_changed"]
    assert len(changed) == 26
    ev = json.loads((tmp_path / "p" / "chain" / "evidence" / f"{changed[0]['evidence_digest'][7:]}.json").read_text())
    assert ev["before"]["vetoed_field"] is False and ev["after"]["vetoed_field"] is True
    assert "demo key" in ev["baseline_note"]
    assert op.main(["verify", str(tmp_path / "p")]) == 0


def test_network_failure_writes_nothing(op, tmp_path, monkeypatch):
    op.main(["keygen"])

    def down(*a, **k):
        raise OSError("connection reset")
    monkeypatch.setattr(op.urllib.request, "urlopen", down)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(SystemExit) as e:
        op.main(["veto-pack", "--out", str(tmp_path / "p")])
    assert "nothing was written" in str(e.value)
    assert not (tmp_path / "p").exists()


def _demo():
    spec = importlib.util.spec_from_file_location("gp_demo", ROOT / "tools" / "demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_offline_demo_runs_every_step(capsys):
    assert _demo().main([]) == 0
    out = capsys.readouterr().out
    for expected in ("VERIFIED", "hash_mismatch", "evidence_mismatch", "key_id_mismatch", "truncated_tail"):
        assert expected in out


def test_demo_on_a_real_pack_leaves_it_untouched(op, tmp_path):
    import hashlib
    op.main(["keygen"])
    fixed = [dict(r, vetoed_field=True, retrieved_at="2026-09-29T03:28:48.884909Z") for r in op.veto_rows_from_v1(V1)]
    op.veto_rows_live = lambda: fixed
    assert op.main(["veto-pack", "--out", str(tmp_path / "real"), "--baseline-v1", str(V1)]) == 0

    def tree_hash(d):
        h = hashlib.sha256()
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            h.update(f.relative_to(d).as_posix().encode() + f.read_bytes())
        return h.hexdigest()

    before = tree_hash(tmp_path / "real")
    pub = json.loads((tmp_path / "home" / "keyring.json").read_text())["keys"][0]["public_key_hex"]
    assert _demo().main(["--pack", str(tmp_path / "real"), "--pubkey", pub]) == 0
    assert tree_hash(tmp_path / "real") == before
