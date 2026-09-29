"""gp-canon/1 writer + verifier tests: canon rules, gate contract, tamper suite.

Run: python3 -m pytest test/test_gpcanon.py -q
Every tamper case runs against both the package verifier and the bundled bin/verify.py.
"""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from gpcanon import writer as W
from gpcanon.canon import CanonError, canon, decimal_from_float, digest, parse, record_hash
from gpcanon.ed25519_verify import verify as ed_verify
from gpcanon.schema import validate_sealed
from gpcanon.verify import verify_chain

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bin" / "verify.py"


# ---------- canon ---------------------------------------------------------------

def test_code_point_key_order_not_utf16():
    assert canon({"😀": 1, "｡": 2}) == '{"｡":2,"😀":1}'.encode()


def test_null_empty_absent_are_distinct():
    hs = {record_hash(x) for x in ({"a": None}, {"a": ""}, {})}
    assert len(hs) == 3


def test_decimal_strings_keep_claimed_precision():
    assert canon("0.40") != canon("0.4")


@pytest.mark.parametrize("s,expected", [
    ("\x01", '"\\u0001"'), ("\n\t\b\f\r", '"\\n\\t\\b\\f\\r"'), ('"\\', '"\\"\\\\"'),
    ("/\x7f­ é", '"/\x7f­ é"')])
def test_escapes(s, expected):
    assert canon(s) == expected.encode()


@pytest.mark.parametrize("x,places,out", [
    (0.125, 2, "0.12"), (2.675, 2, "2.68"), (-0.005, 2, "0.00"), (99.995, 2, "100.00"),
    (1e-7, 3, "0.000"), (1.5, 0, "2"), (2.5, 0, "2"), (0.4, 2, "0.40")])
def test_decimal_from_float(x, places, out):
    assert decimal_from_float(x, places) == out


@pytest.mark.parametrize("x,places,reason", [
    (float("nan"), 2, "non_finite"), (float("inf"), 2, "non_finite"), (1.0, 19, "bad_places"),
    (True, 2, "bad_type")])
def test_decimal_rejects(x, places, reason):
    with pytest.raises(CanonError) as e:
        decimal_from_float(x, places)
    assert e.value.reason == reason


@pytest.mark.parametrize("raw,reason", [
    (b"1.0", "float"), (b"1e2", "float"), (b"-0", "neg_zero"), (b"9007199254740992", "int_range"),
    (b'{"a":1,"a":2}', "dup_key"), ('"é"'.encode(), "non_nfc"), (b'"\\ud800"', "lone_surrogate"),
    (b'"\xed\xa0\x80"', "lone_surrogate"), (b"\xef\xbb\xbf1", "bad_json"), (b"[1,]", "bad_json"),
    (b"NaN", "bad_json"), (b"01", "bad_json"), (b'"\x01"', "bad_json"), (b"1 2", "bad_json")])
def test_parser_rejects_with_named_reason(raw, reason):
    with pytest.raises(CanonError) as e:
        parse(raw)
    assert e.value.reason == reason


def test_surrogate_pair_escape_is_one_code_point():
    assert parse(b'"\\ud83d\\ude00"') == "😀"


def test_producer_canon_rejects_floats_and_non_nfc():
    for bad, reason in ((1.5, "float"), ("é", "non_nfc"), (2**53, "int_range"), (object(), "bad_type")):
        with pytest.raises(CanonError) as e:
            canon(bad)
        assert e.value.reason == reason


def test_ed25519_rfc8032_vector_and_cross_check():
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590"
                        "a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed_verify(pub, b"", sig) and not ed_verify(pub, b"\x00", sig)
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    for i in range(10):
        k = Ed25519PrivateKey.generate()
        pk = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        m = os.urandom(i * 13)
        assert ed_verify(pk, m, k.sign(m))


# ---------- fixtures --------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    pol = tmp_path / "publish_rule.py"
    pol.write_text("allow when at least one claim is confirmed\n")

    def rule(inputs):
        if inputs.get("boom"):
            raise KeyError("boom")
        n = inputs["claims_confirmed"]
        return n > 0, f"latest audit: {n} claims confirmed at confidence {inputs['confidence']}"

    reg = {"spec1.publish_verdict": W.Policy("2026.09.1", str(pol), rule)}
    chain = W.Chain(tmp_path / "chain", "spec1.publish", actor="matt@kali", lock_timeout=0.5)
    kid, pub = W.generate_key(tmp_path / "op.pem")
    key = W.load_private_key(tmp_path / "op.pem")
    return {"dir": tmp_path / "chain", "chain": chain, "reg": reg, "pub": pub, "kid": kid, "key": key,
            "pol": pol, "tmp": tmp_path}


def recs(d):
    out = []
    for seg in sorted(Path(d).glob("seg-*.jsonl")):
        out += [parse(l) for l in seg.read_bytes().splitlines()]
    return out


def seg_path(d):
    return sorted(Path(d).glob("seg-*.jsonl"))[0]


def populate(e):
    """A chain like the vector chain: allow, deny, unknown policy, raised action, inputs_invalid, seal."""
    c, reg = e["chain"], e["reg"]
    with c.gate("spec1.publish_verdict", "case_a1", "publish", {"claims_confirmed": 3, "confidence": "0.82"}, reg) as g:
        assert g.allowed
    with c.gate("spec1.publish_verdict", "case_e07edfa2210e", "publish",
                {"claims_confirmed": 0, "confidence": "0.00"}, reg) as g:
        assert not g.allowed
    with c.gate("spec1.nope", "case_b", "publish", {}, reg) as g:
        assert g.reason == "policy_unknown"
    with pytest.raises(ZeroDivisionError):
        with c.gate("spec1.publish_verdict", "case_c", "publish", {"claims_confirmed": 1, "confidence": "0.60"}, reg) as g:
            1 / 0
    with c.gate("spec1.publish_verdict", "case_d", "publish", {"confidence": 0.5}, reg) as g:
        assert g.reason == "inputs_invalid" and g.detail == "float"
    return c.seal(e["key"])


def both(d, *args):
    """Run the package verifier and the bundle; assert they agree; return (exit, codes)."""
    r = subprocess.run([sys.executable, str(BUNDLE), str(d), "--json", *args], capture_output=True, text=True)
    out = json.loads(r.stdout)
    pk = {}
    it = iter(args)
    anchor = None
    windows = {}
    for a in it:
        if a == "--pubkey":
            raw = bytes.fromhex(next(it))
            pk[W.key_id_of(raw)] = raw
        elif a == "--anchor":
            anchor = json.loads(Path(next(it)).read_text())
        elif a == "--keyring":
            from gpcanon.verify import load_keyring
            kp, kw = load_keyring(next(it))
            pk.update(kp)
            windows.update(kw)
    rep = verify_chain(d, pk, "--allow-unpinned" in args, anchor, windows=windows)
    assert rep.exit_code() == r.returncode == out["exit"]
    assert sorted(f["code"] for f in rep.findings) == sorted(f["code"] for f in out["findings"])
    return r.returncode, {f["code"] for f in out["findings"]}


# ---------- gate contract ----------------------------------------------------------

def test_clean_chain_verifies_and_every_record_is_schema_valid(env):
    populate(env)
    rs = recs(env["dir"])
    assert [r["s"]["kind"] for r in rs] == ["intent", "outcome"] * 5 + ["seal"]
    assert all(validate_sealed(r["s"]) == [] for r in rs)
    reasons = [r["s"]["reason"] for r in rs if r["s"]["kind"] == "intent"]
    assert reasons == ["policy_allowed", "policy_denied", "policy_unknown", "policy_allowed", "inputs_invalid"]
    results = [r["s"]["result"] for r in rs if r["s"]["kind"] == "outcome"]
    assert results == ["ok", "skipped", "skipped", "raised", "skipped"]
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 0 and codes == {"tail_unanchored"}
    assert (env["dir"] / "HEAD").exists()


def test_policy_that_raises_is_a_recorded_deny(env):
    with env["chain"].gate("spec1.publish_verdict", "x", "publish", {"boom": True}, env["reg"]) as g:
        assert not g.allowed
    intent = recs(env["dir"])[0]["s"]
    assert (intent["reason"], intent["detail"]) == ("policy_raised", "KeyError")


def test_prefix_mismatch_is_checked_before_loading(env):
    reg = dict(env["reg"], **{"pdx1i.publish": env["reg"]["spec1.publish_verdict"]})
    with env["chain"].gate("pdx1i.publish", "x", "publish", {}, reg) as g:
        assert g.reason == "policy_prefix_mismatch"
    s = recs(env["dir"])[0]["s"]
    assert s["policy_version"] is None and s["policy_digest"] is None and s["inputs_digest"] is not None


def test_body_not_run_when_lock_unavailable(env):
    held = threading.Event()
    release = threading.Event()

    def holder():
        with env["chain"]._locked():
            held.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    other = W.Chain(env["dir"], "spec1.publish", actor="cron", lock_timeout=0.2)
    t.start()
    held.wait(5)
    ran = []
    with pytest.raises(W.GateLockTimeout):
        with other.gate("spec1.publish_verdict", "x", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
            ran.append(1)
    release.set()
    t.join()
    assert ran == [] and recs(env["dir"]) == []


def test_body_not_run_when_intent_cannot_be_written(env, monkeypatch):
    def fail(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(env["chain"], "_append", fail)
    ran = []
    with pytest.raises(W.GateError):
        with env["chain"].gate("spec1.publish_verdict", "x", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
            ran.append(1)
    assert ran == []


def test_dangling_intent_resolved_by_next_gate(env):
    c = env["chain"]
    seq, prev = c._resolve_dangling()
    s = c._base("intent", seq, prev, W.now_ts())
    s.update(gate_id="a" * 32, actor="matt@kali", detail=None, policy_id="spec1.publish_verdict", subject="s",
             action="publish", decision="allow", reason="policy_allowed", policy_version="1",
             policy_digest="sha256:" + "0" * 64, inputs_digest=digest({}))
    c._append(s)                                           # process "dies" here
    code, codes = both(env["dir"], "--allow-unpinned")
    assert "dangling_intent" in codes
    with c.gate("spec1.publish_verdict", "y", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    kinds = [(r["s"]["kind"], r["s"].get("failure_code")) for r in recs(env["dir"])]
    assert kinds[:2] == [("intent", None), ("failure", "outcome_unwritten")]
    assert both(env["dir"], "--allow-unpinned")[0] == 0


def test_concurrent_gates_do_not_fork_or_false_dangle(env):
    errors = []

    def worker(i):
        try:
            c = W.Chain(env["dir"], "spec1.publish", actor=f"w{i}", lock_timeout=10)
            for j in range(5):
                with c.gate("spec1.publish_verdict", f"c{i}-{j}", "publish",
                            {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
                    time.sleep(0.005)
        except Exception as e:                            # surfaced below
            errors.append(e)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    rs = recs(env["dir"])
    assert [r["s"]["seq"] for r in rs] == list(range(40))
    assert not any(r["s"]["kind"] == "failure" for r in rs)
    assert both(env["dir"], "--allow-unpinned")[0] == 0


def test_no_success_returned_from_an_except_block():
    """SCHEMA §5.3: no code path returns allow or ok from an except block."""
    import ast
    success = {"allow", "policy_allowed", "ok"}
    tree = ast.parse((ROOT / "gpcanon" / "writer.py").read_text())
    offenders = []
    for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
        for node in ast.walk(handler):
            if isinstance(node, ast.Constant) and node.value in success:
                offenders.append(node.lineno)
    assert offenders == [], f"success value inside an except block at lines {offenders}"


# ---------- tamper suite -------------------------------------------------------------

def _lines(e):
    return seg_path(e["dir"]).read_bytes().splitlines(keepends=True)


def _write(e, lines):
    seg_path(e["dir"]).write_bytes(b"".join(lines))


def test_tamper_flipped_byte(env):
    populate(env)
    ls = _lines(env)
    ls[2] = ls[2].replace(b'"case_e07edfa2210e"', b'"case_e07edfa2210f"')
    _write(env, ls)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 1 and "hash_mismatch" in codes


def test_tamper_deleted_row(env):
    populate(env)
    ls = _lines(env)
    del ls[3]
    _write(env, ls)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 1 and "prev_mismatch" in codes


def test_tamper_reordered_pair(env):
    populate(env)
    ls = _lines(env)
    ls[0:2], ls[2:4] = ls[2:4], ls[0:2]
    _write(env, ls)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 1 and "prev_mismatch" in codes


def test_tamper_deny_rewritten_as_allow_with_rehash(env):
    """Rewriting a record AND recomputing every hash after it: only the seal catches it."""
    populate(env)
    rs = recs(env["dir"])
    s = rs[2]["s"]
    s.update(decision="allow", reason="policy_allowed")
    rs[3]["s"]["result"] = "ok"
    prev = "0" * 64
    out = []
    for r in rs:
        r["s"]["prev_hash"] = prev
        r["h"] = record_hash(r["s"])
        prev = r["h"]
        out.append(canon(r) + b"\n")
    _write(env, out)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 2 and codes >= {"bad_signature"}
    assert both(env["dir"])[0] == 5                  # unpinned: this forgery would otherwise look fine


def test_tamper_forged_seal_with_attacker_key(env):
    populate(env)
    rs = recs(env["dir"])
    atk_kid, atk_pub = W.generate_key(env["tmp"] / "attacker.pem")
    atk = W.load_private_key(env["tmp"] / "attacker.pem")
    seal = rs[-1]
    seal["s"]["key_id"] = atk_kid
    seal["h"] = record_hash(seal["s"])
    seal["sig"] = atk.sign(W.SEAL_DOMAIN + canon(seal["s"])).hex()
    _write(env, [canon(r) + b"\n" for r in rs])
    assert both(env["dir"], "--pubkey", env["pub"])[0] == 4      # sealed by an unpinned key
    assert both(env["dir"], "--pubkey", atk_pub)[0] == 0         # which is why pinning must come from outside


def test_tamper_cross_chain_splice(env):
    populate(env)
    other = W.Chain(env["tmp"] / "other", "pdx1i.publish", actor="matt@kali")
    reg = {"pdx1i.publish": W.Policy("1", str(env["pol"]), lambda i: (True, None))}
    with other.gate("pdx1i.publish", "m", "publish", {}, reg):
        pass
    alien = seg_path(env["tmp"] / "other").read_bytes().splitlines(keepends=True)[0]
    ls = _lines(env)
    ls.insert(4, alien)
    _write(env, ls)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 1 and "chain_id_mismatch" in codes


def test_tamper_truncated_tail_needs_anchor(env):
    anchor = populate(env)
    (env["tmp"] / "anchor.json").write_text(json.dumps(anchor))
    with env["chain"].gate("spec1.publish_verdict", "late", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    anchor2 = env["chain"].seal(env["key"])
    (env["tmp"] / "anchor2.json").write_text(json.dumps(anchor2))
    ls = _lines(env)
    _write(env, ls[:11])                               # cut back to the first seal
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 0 and "tail_unanchored" in codes    # honest: undetectable without an anchor
    code, codes = both(env["dir"], "--pubkey", env["pub"], "--anchor", str(env["tmp"] / "anchor2.json"))
    assert code == 1 and "truncated_tail" in codes


def test_tamper_swapped_policy_file(env):
    populate(env)
    env["pol"].write_text("allow everything\n")
    rep = verify_chain(env["dir"], {env["kid"]: bytes.fromhex(env["pub"])},
                       policies={"spec1.publish_verdict": str(env["pol"])})
    assert rep.exit_code() == 1 and "policy_digest_mismatch" in rep.codes()


def test_unpinned_and_unsealed_are_not_a_pass(env):
    with env["chain"].gate("spec1.publish_verdict", "x", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    assert both(env["dir"])[0] == 5                      # no seals at all
    env["chain"].seal(env["key"])
    assert both(env["dir"])[0] == 5                      # seal present, no key pinned
    assert both(env["dir"], "--allow-unpinned")[0] == 0  # explicit opt-in only


def test_notes_are_outside_the_hash(env):
    populate(env)
    rs = recs(env["dir"])
    rs[0]["n"] = {"operator": "annotated later"}
    _write(env, [canon(r) + b"\n" for r in rs])
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 0 and "notes_unverified" in codes


def test_sig_on_non_seal_and_non_canonical_line(env):
    populate(env)
    rs = recs(env["dir"])
    rs[0]["sig"] = "0" * 128
    ls = [canon(r) + b"\n" for r in rs]
    ls[1] = ls[1].replace(b'{"h":', b'{ "h":', 1)
    _write(env, ls)
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert {"sig_forbidden", "line_not_canonical"} <= codes and code == 1


def test_torn_tail_repaired_by_writer(env):
    populate(env)
    with open(seg_path(env["dir"]), "ab") as f:
        f.write(b'{"h":"abc')
    assert both(env["dir"], "--pubkey", env["pub"])[0] == 3
    with env["chain"].gate("spec1.publish_verdict", "z", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    env["chain"].seal(env["key"])
    assert both(env["dir"], "--pubkey", env["pub"])[0] == 0


# ---------- findings --------------------------------------------------------------------

VETO_EVIDENCE = {"source": "api.oregonlegislature.gov OData", "measures_total": 31405, "vetoed_true": 1,
                 "history_governor_vetoed": 27, "overridden": 3, "checked_at": "2026-09-28"}


def test_finding_recorded_with_evidence_and_verifies(env):
    c = W.Chain(env["tmp"] / "pt", "proc_track.findings", actor="matt@kali")
    r = c.record_finding("or.legislature.measures", "proc_track.field_contradicts_history",
                         "Vetoed is true on 1 measure; 27 record a governor veto in history", VETO_EVIDENCE)
    ev = env["tmp"] / "pt" / "evidence" / f"{r['evidence_digest'][7:]}.json"
    assert ev.read_bytes() == canon(VETO_EVIDENCE)
    c.seal(env["key"])
    code, codes = both(env["tmp"] / "pt", "--pubkey", env["pub"])
    assert code == 0 and "evidence_absent" not in codes


def test_finding_evidence_tampered_or_missing(env):
    c = W.Chain(env["tmp"] / "pt", "proc_track.findings", actor="matt@kali")
    r = c.record_finding("s", "proc_track.x", "claim", VETO_EVIDENCE)
    c.seal(env["key"])
    ev = env["tmp"] / "pt" / "evidence" / f"{r['evidence_digest'][7:]}.json"
    ev.write_bytes(canon(dict(VETO_EVIDENCE, vetoed_true=27)))
    code, codes = both(env["tmp"] / "pt", "--pubkey", env["pub"])
    assert code == 1 and "evidence_mismatch" in codes
    ev.unlink()
    code, codes = both(env["tmp"] / "pt", "--pubkey", env["pub"])
    assert code == 0 and "evidence_absent" in codes          # bound, just not inspectable


def test_finding_rejects_bad_type_and_non_canonical_evidence(env):
    c = W.Chain(env["tmp"] / "pt", "proc_track.findings", actor="matt@kali")
    with pytest.raises(ValueError):
        c.record_finding("s", "pdx1i.x", "claim", {})
    with pytest.raises(CanonError):
        c.record_finding("s", "proc_track.x", "claim", {"ratio": 0.5})
    assert not list((env["tmp"] / "pt").glob("seg-*.jsonl"))
    assert not (env["tmp"] / "pt" / "evidence").exists() or not list((env["tmp"] / "pt" / "evidence").iterdir())


def test_finding_after_crash_resolves_the_dangling_intent_first(env):
    c = env["chain"]
    seq, prev = c._resolve_dangling()
    s = c._base("intent", seq, prev, W.now_ts())
    s.update(gate_id="b" * 32, actor="x", detail=None, policy_id="spec1.publish_verdict", subject="s", action="a",
             decision="allow", reason="policy_allowed", policy_version="1", policy_digest="sha256:" + "0" * 64,
             inputs_digest=digest({}))
    c._append(s)
    c.record_finding("s", "spec1.x", "claim", {"k": 1})
    assert [r["s"]["kind"] for r in recs(env["dir"])] == ["intent", "failure", "finding"]
    assert both(env["dir"], "--allow-unpinned")[0] == 0


# ---------- key rotation ------------------------------------------------------------------

def _keyring(path, entries):
    path.write_text(json.dumps({"keys": [
        {"key_id": kid, "public_key_hex": pub, "effective_from": start, "retired_at": end}
        for kid, pub, start, end in entries]}))
    return path


def _manual_seal(chain, key, recorded_at):
    """A seal with a chosen timestamp, signed with a real key: what an insider could forge."""
    from cryptography.hazmat.primitives import serialization as ser
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with chain._locked():
        seq, prev = chain._resolve_dangling()
        s = chain._base("seal", seq, prev, recorded_at)
        s["recorded_at"] = recorded_at
        s["key_id"] = W.key_id_of(pub)
        chain._append(s, sig=key.sign(W.SEAL_DOMAIN + canon(s)).hex())


def test_rotation_old_and_new_keys_each_inside_their_window(env):
    populate(env)                                               # sealed with the old key
    kid2, pub2 = W.generate_key(env["tmp"] / "new.pem")
    with env["chain"].gate("spec1.publish_verdict", "n", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    env["chain"].seal(W.load_private_key(env["tmp"] / "new.pem"))
    rs = recs(env["dir"])
    cut = rs[-1]["s"]["recorded_at"]                            # rotate just before the new seal
    old_seal_at = rs[10]["s"]["recorded_at"]
    ring = _keyring(env["tmp"] / "ring.json", [(env["kid"], env["pub"], old_seal_at, cut),
                                                (kid2, pub2, cut, None)])
    assert both(env["dir"], "--keyring", str(ring))[0] == 0


def test_rotation_retired_key_cannot_seal(env):
    populate(env)
    first_seal_at = recs(env["dir"])[-1]["s"]["recorded_at"]
    with env["chain"].gate("spec1.publish_verdict", "n", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    env["chain"].seal(env["key"])                               # old key used again after retirement
    ring = _keyring(env["tmp"] / "ring.json", [(env["kid"], env["pub"], None, first_seal_at[:-2] + "9Z")])
    code, codes = both(env["dir"], "--keyring", str(ring))
    assert code == 4 and "key_outside_window" in codes


def test_rotation_seal_backdated_behind_an_earlier_seal(env):
    populate(env)
    first_seal_at = recs(env["dir"])[-1]["s"]["recorded_at"]
    with env["chain"].gate("spec1.publish_verdict", "n", "publish", {"claims_confirmed": 1, "confidence": "1"}, env["reg"]):
        pass
    _manual_seal(env["chain"], env["key"], "2026-01-01T00:00:00.000000Z")
    code, codes = both(env["dir"], "--pubkey", env["pub"])
    assert code == 1 and "seal_backdated" in codes


def test_keyring_with_a_lying_key_id_is_refused(env):
    populate(env)
    ring = _keyring(env["tmp"] / "ring.json", [("0" * 16, env["pub"], None, None)])
    r = subprocess.run([sys.executable, str(BUNDLE), str(env["dir"]), "--keyring", str(ring)], capture_output=True, text=True)
    assert r.returncode == 3 and "does not match" in r.stderr
