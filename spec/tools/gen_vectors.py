"""Generate vectors/gatepost-vectors-v1.json and the sample chain.

Uses the Python reference for expected values and `cryptography` to sign with
a deterministic TEST key. The key is public on purpose: never use it to seal
a real chain. Run from the repo root:  python3 tools/gen_vectors.py
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ref"))
import gp_canon as gc  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
SEED = hashlib.sha256(b"gatepost test-vector key - PUBLIC - never seal a real chain").digest()
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PK = SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEY_ID = gc.key_id(PK)

# ------------------------------------------------------------------ canon vectors
CANON_CASES = [
    ("c01", "empty object", "{}"),
    ("c02", "keys sorted", '{"b":1,"a":2}'),
    ("c03a", "null value", '{"x":null}'),
    ("c03b", "empty-string value (differs from null)", '{"x":""}'),
    ("c03c", "absent key (differs from both)", "{}"),
    ("c04", "nested: arrays keep order, objects sorted", '{"z":[3,1,{"b":0,"a":[]}],"a":{"d":true,"c":false}}'),
    ("c05", "insignificant whitespace dropped", ' {\n  "a" : [ 1 , 2 ] ,\t"b" : null\n} '),
    ("c06", "non-ASCII emitted raw UTF-8", '{"city":"Café Ñandú — 東京"}'),
    ("c07", "\\u escapes for non-ASCII decode to raw", '{"k":"\\u00e9\\u6771"}'),
    ("c08", "escaping: quote, backslash, controls; solidus unescaped",
     '{"s":"a\\u0001b\\n\\t\\"\\\\\\/\\u001f\\b\\f\\r"}'),
    ("c09", "U+007F, U+00AD, U+2028 stay raw", '{"s":"\\u007f\\u00ad\\u2028"}'),
    ("c10", "keys sorted by code point, not UTF-16 unit", '{"\\ud83d\\ude00":2,"\\uff61":1}'),
    ("c11", "integer limits", '{"max":9007199254740991,"min":-9007199254740991,"zero":0}'),
    ("c12a", "decimal string 0.40", '{"confidence":"0.40"}'),
    ("c12b", "decimal string 0.4 (different value bytes, different hash)", '{"confidence":"0.4"}'),
    ("c13", "booleans and null in array", "[true,false,null]"),
    ("c14", "empty-string key sorts first", '{"a":1,"":0}'),
    ("c15", "deep nesting", "[[[[{}]]]]"),
    ("c16", "precomposed (NFC) key accepted", '{"\\u00e9":1,"e":2}'),
    ("c17", "top-level string", '"gatepost"'),
]

REJECT_CASES = [
    ("r01", "float", "1.0", "float"),
    ("r02", "exponent", "1e2", "float"),
    ("r03", "negative float", '{"a":-1.5}', "float"),
    ("r04", "negative zero", "-0", "neg_zero"),
    ("r05", "integer past 2^53-1", "9007199254740992", "int_range"),
    ("r06", "integer past -(2^53-1)", "-9007199254740992", "int_range"),
    ("r07", "duplicate key", '{"a":1,"a":1}', "dup_key"),
    ("r08", "non-NFC value (e + combining acute)", '"e\\u0301"', "non_nfc"),
    ("r09", "non-NFC key", '{"e\\u0301":1}', "non_nfc"),
    ("r10", "lone high surrogate", '"\\ud800"', "lone_surrogate"),
    ("r11", "lone low surrogate", '"\\udc00x"', "lone_surrogate"),
    ("r12", "NaN is not JSON", "NaN", "bad_json"),
    ("r13", "trailing comma", "[1,]", "bad_json"),
    ("r14", "BOM", "﻿{}", "bad_json"),
    ("r15", "raw control character in string", '"a\u0001"', "bad_json"),
    ("r16", "leading zero", "01", "bad_json"),
    ("r17", "trailing garbage", "{} {}", "bad_json"),
]

DECIMAL_CASES = [
    ("0.1", 2, "0.10"), ("0.125", 2, "0.12"), ("0.135", 2, "0.14"), ("2.675", 2, "2.68"),
    ("0.5", 0, "0"), ("1.5", 0, "2"), ("2.5", 0, "2"), ("-2.5", 0, "-2"),
    ("1e-07", 2, "0.00"), ("-1e-07", 2, "0.00"), ("-0.0", 2, "0.00"), ("0.0", 4, "0.0000"),
    ("123456789.98765432", 4, "123456789.9877"), ("1e+21", 0, "1000000000000000000000"),
    ("0.3", 18, "0.300000000000000000"), ("5e-324", 2, "0.00"), ("-0.005", 2, "0.00"),
    ("-0.015", 2, "-0.02"), ("0.07", 1, "0.1"), ("99.995", 2, "100.00"),
]

# ------------------------------------------------------------------ schema vectors
CHAIN_ID = "spec1.publish"
TS = "2026-09-27T15:00:00.000000Z"
H0 = "ab" * 32
GID = "0123456789abcdef0123456789abcdef"
DIG = "sha256:" + "cd" * 32


def base(kind, **kw):
    s = {"canon_version": gc.CANON_VERSION, "chain_id": CHAIN_ID, "seq": 7, "prev_hash": H0,
         "kind": kind, "recorded_at": TS, "occurred_at": TS}
    s.update(kw)
    return s


INTENT = base("intent", gate_id=GID, policy_id="spec1.publish_verdict", policy_version="1",
              policy_digest=DIG, subject="case_0001", action="publish", inputs_digest=DIG,
              decision="allow", reason="policy_allowed", detail=None, actor="spec1.analyst_loop")
OUTCOME = base("outcome", gate_id=GID, result="ok", detail=None, actor="spec1.analyst_loop")
FAILURE = base("failure", gate_id=GID, failure_code="outcome_unwritten", detail="found at next gate() call",
               actor="spec1.analyst_loop")
SEAL = base("seal", key_id="0f" * 8)


def mod(s, drop=(), **kw):
    s = dict(s)
    for k in drop:
        s.pop(k)
    s.update(kw)
    return s


SCHEMA_CASES = [
    ("s01", "valid intent (allow)", INTENT, []),
    ("s02", "valid outcome", OUTCOME, []),
    ("s03", "valid failure", FAILURE, []),
    ("s04", "valid seal", SEAL, []),
    ("s05", "decision 'error' no longer exists", mod(INTENT, decision="error"), ["bad_field"]),
    ("s06", "detail absent instead of null", mod(INTENT, drop=["detail"]), ["missing_field"]),
    ("s07", "result null", mod(OUTCOME, result=None), ["null_not_allowed"]),
    ("s08", "outcome carries an intent-only field", mod(OUTCOME, policy_id="spec1.publish_verdict"), ["unknown_field"]),
    ("s09", "allow with a deny reason", mod(INTENT, reason="policy_denied"), ["decision_reason_mismatch"]),
    ("s10", "policy_unknown but policy_version set",
     mod(INTENT, decision="deny", reason="policy_unknown", policy_digest=None), ["null_required"]),
    ("s11", "valid policy_unknown deny",
     mod(INTENT, decision="deny", reason="policy_unknown", policy_digest=None, policy_version=None), []),
    ("s12", "policy from another consumer, not recorded as mismatch",
     mod(INTENT, policy_id="pdx1i.publish_brief"), ["policy_prefix_mismatch"]),
    ("s13", "valid prefix-mismatch deny",
     mod(INTENT, policy_id="pdx1i.publish_brief", decision="deny", reason="policy_prefix_mismatch",
         policy_version=None, policy_digest=None), []),
    ("s14", "unsupported canon_version", mod(SEAL, canon_version="gp-canon/2"), ["canon_version_unsupported"]),
    ("s15", "impossible date (2026 not a leap year)", mod(SEAL, occurred_at="2026-02-29T00:00:00.000000Z"), ["bad_field"]),
    ("s16", "timestamp without microseconds", mod(SEAL, recorded_at="2026-09-27T15:00:00Z"), ["bad_field"]),
    ("s17", "seq as string", mod(SEAL, seq="7"), ["bad_field"]),
    ("s18", "seq as boolean", mod(SEAL, seq=True), ["bad_field"]),
    ("s19", "inputs_digest null without inputs_invalid", mod(INTENT, decision="deny", reason="policy_denied",
                                                             inputs_digest=None), ["null_not_allowed"]),
    ("s20", "valid inputs_invalid deny", mod(INTENT, decision="deny", reason="inputs_invalid", inputs_digest=None), []),
    ("s21", "detail empty string is valid and distinct from null", mod(OUTCOME, detail=""), []),
    ("s22", "uppercase hex in prev_hash", mod(SEAL, prev_hash="AB" * 32), ["bad_field"]),
    ("s23", "unknown kind", mod(SEAL, kind="genesis"), ["bad_field"]),
    ("s24", "kind absent", mod(SEAL, drop=["kind"]), ["missing_field"]),
    ("s25", "kind inherited from Object.prototype must not pass", mod(SEAL, kind="toString"), ["bad_field"]),
]

# ------------------------------------------------------------------ sample chain


def ts(i):
    return "2026-09-27T15:%02d:%02d.%06dZ" % (i // 60, i % 60, 1000 * i + 7)


def gid(n):
    return hashlib.sha256(b"gate-%d" % n).hexdigest()[:32]


def policy_digest(pid, ver):
    return "sha256:" + hashlib.sha256(f"policy {pid}@{ver}".encode()).hexdigest()


ACTOR = "spec1.analyst_loop"
PID = "spec1.publish_verdict"
PDIG = policy_digest(PID, "1")

REPLAY_INPUTS = {
    "case_id": "case_e07edfa2210e",
    "audits": [
        {"run": 1, "claims_confirmed": 0, "confidence": "0.00", "status": "api_400"},
        {"run": 2, "claims_confirmed": 0, "confidence": "0.00", "status": "api_400"},
    ],
}

STEPS = [  # (kind, gate#, fields, inputs, notes)
    ("intent", 1, dict(subject="case_3f9a01c2", action="publish", decision="allow", reason="policy_allowed",
                       detail=None), {"case_id": "case_3f9a01c2", "audits": [
                           {"run": 1, "claims_confirmed": 3, "confidence": "0.82", "status": "ok"}]}, None),
    ("outcome", 1, dict(result="ok", detail=None), None, None),
    ("intent", 2, dict(subject="case_e07edfa2210e", action="publish", decision="deny", reason="policy_denied",
                       detail="latest audit: 0 claims confirmed at confidence 0.00"), REPLAY_INPUTS,
     {"operator": "replay of the 2026-09 incident; must deny"}),
    ("outcome", 2, dict(result="skipped", detail=None), None, None),
    ("intent", 3, dict(subject="case_77d0", action="publish", decision="deny", reason="policy_unknown",
                       detail="no policy named spec1.publish_verdikt", policy_id="spec1.publish_verdikt",
                       policy_version=None, policy_digest=None), {"case_id": "case_77d0"}, None),
    ("outcome", 3, dict(result="skipped", detail=None), None, None),
    ("intent", 4, dict(subject="case_a1b2", action="publish", decision="allow", reason="policy_allowed",
                       detail=None), {"case_id": "case_a1b2", "audits": [
                           {"run": 1, "claims_confirmed": 1, "confidence": "0.40", "status": "ok"}]}, None),
    ("outcome", 4, dict(result="raised", detail="requests.exceptions.HTTPError"), None, None),
    ("seal", None, {}, None, None),
    ("intent", 5, dict(subject="case_c0ffee", action="publish", decision="deny", reason="inputs_invalid",
                       detail="float at $.audits[0].confidence", inputs_digest=None), None, None),
    ("outcome", 5, dict(result="skipped", detail=None), None, None),
    ("intent", 6, dict(subject="case_dead01", action="publish", decision="allow", reason="policy_allowed",
                       detail=None), {"case_id": "case_dead01", "audits": [
                           {"run": 1, "claims_confirmed": 2, "confidence": "0.71", "status": "ok"}]}, None),
    ("failure", 6, dict(failure_code="outcome_unwritten",
                        detail="intent seq 11 has no outcome; found at next gate() call"), None, None),
    ("intent", 7, dict(subject="case_5150", action="publish", decision="deny", reason="policy_raised",
                       detail="ZeroDivisionError"), {"case_id": "case_5150", "audits": []}, None),
    ("outcome", 7, dict(result="skipped", detail=None), None, None),
    ("intent", 8, dict(subject="case_«Café Ñandú»", action="publish", decision="allow", reason="policy_allowed",
                       detail=""), {"case_id": "case_«Café Ñandú»", "region": "東京", "audits": [
                           {"run": 1, "claims_confirmed": 5, "confidence": "0.93", "status": "ok"}]}, None),
    ("outcome", 8, dict(result="ok", detail=""), None, {"operator": "notes are not hashed"}),
    ("intent", 9, dict(subject="case_9d", action="publish", decision="deny", reason="policy_prefix_mismatch",
                       detail="policy pdx1i.publish_brief wired into chain spec1.publish",
                       policy_id="pdx1i.publish_brief", policy_version=None, policy_digest=None),
     {"case_id": "case_9d"}, None),
    ("outcome", 9, dict(result="skipped", detail=None), None, None),
    ("seal", None, {}, None, None),
]


def build_chain():
    prev = gc.GENESIS_PREV
    records = []
    for seq, (kind, g, fields, inputs, notes) in enumerate(STEPS):
        s = {"canon_version": gc.CANON_VERSION, "chain_id": CHAIN_ID, "seq": seq, "prev_hash": prev,
             "kind": kind, "recorded_at": ts(seq), "occurred_at": ts(seq)}
        if kind == "intent":
            s.update(gate_id=gid(g), policy_id=PID, policy_version="1", policy_digest=PDIG, actor=ACTOR,
                     inputs_digest=gc.inputs_digest(inputs) if inputs is not None else None)
        elif kind in ("outcome", "failure"):
            s.update(gate_id=gid(g), actor=ACTOR)
        elif kind == "seal":
            s.update(key_id=KEY_ID)
        s.update(fields)
        errs = gc.validate_sealed(s)
        assert not errs, (seq, errs)
        h = gc.record_hash(s)
        line = {"h": h, "s": s}
        if notes:
            line["n"] = notes
        if kind == "seal":
            line["sig"] = SK.sign(gc.seal_message(s)).hex()
        rec = {"seq": seq, "sealed": s, "hash": h, "line": gc.canon(line).decode()}
        if inputs is not None:
            rec["inputs"] = inputs
        records.append(rec)
        prev = h
    return records


def main():
    canon_vectors = []
    for vid, note, text in CANON_CASES:
        c = gc.canon(gc.strict_loads(text))
        canon_vectors.append({"id": vid, "note": note, "input": text, "canon": c.decode(),
                              "canon_hex": c.hex(), "sha256": gc.sha256_hex(c)})
    reject_vectors = []
    for vid, note, text, code in REJECT_CASES:
        try:
            gc.strict_loads(text)
            raise AssertionError(f"{vid} accepted")
        except gc.CanonError as e:
            assert e.code == code, (vid, e.code, code)
        reject_vectors.append({"id": vid, "note": note, "input": text, "reason": code})
    decimal_vectors = []
    for i, (x, places, want) in enumerate(DECIMAL_CASES, 1):
        got = gc.decimal_from_float(float(x), places)
        assert got == want, (x, places, got, want)
        decimal_vectors.append({"id": "d%02d" % i, "float": x, "places": places, "expect": want})
    schema_vectors = []
    for vid, note, s, want in SCHEMA_CASES:
        got = gc.validate_sealed(s)
        assert got == want, (vid, got, want)
        schema_vectors.append({"id": vid, "note": note, "sealed": json.dumps(s, ensure_ascii=False),
                               "errors": want})
    chain = build_chain()
    out = {
        "canon_version": gc.CANON_VERSION,
        "generated_by": "tools/gen_vectors.py",
        "test_key": {"warning": "PUBLIC TEST KEY. Never seal a real chain with it.",
                     "seed_hex": SEED.hex(), "public_key_hex": PK.hex(), "key_id": KEY_ID},
        "canon_vectors": canon_vectors,
        "reject_vectors": reject_vectors,
        "decimal_vectors": decimal_vectors,
        "schema_vectors": schema_vectors,
        "chain": {"chain_id": CHAIN_ID, "records": chain},
    }
    vdir = os.path.join(ROOT, "vectors")
    with open(os.path.join(vdir, "gatepost-vectors-v1.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
        f.write("\n")
    with open(os.path.join(vdir, "chain-spec1.publish.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for r in chain:
            f.write(r["line"] + "\n")
    print(f"canon {len(canon_vectors)}  reject {len(reject_vectors)}  decimal {len(decimal_vectors)}  "
          f"schema {len(schema_vectors)}  chain {len(chain)}  key_id {KEY_ID}")


if __name__ == "__main__":
    main()
