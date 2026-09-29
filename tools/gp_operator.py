#!/usr/bin/env python3
"""Gatepost operator tasks. Run these on YOUR machine (Kali), never in a cloud session:
the private key must only ever exist where you run this.

  python3 tools/gp_operator.py keygen
      Creates ~/.gatepost/op_key.pem (Ed25519, 0600) and ~/.gatepost/keyring.json.
      Prints the public key to publish. Refuses to overwrite an existing key.

  python3 tools/gp_operator.py veto-pack [--out DIR] [--from-v1 records.jsonl] [--baseline-v1 records.jsonl]
      Pulls the Oregon veto findings live from api.oregonlegislature.gov, records each
      as a gp-canon/1 `finding` in chain proc_track.findings (evidence files included),
      seals with ~/.gatepost/op_key.pem, writes anchor.json, and verifies the result
      with the pinned keyring. --from-v1 rebuilds from a gatepost/v1 records.jsonl
      instead of the live API (same findings, original retrieval time).
      --baseline-v1 compares the live pull with an earlier gatepost/v1 retrieval and records
      one `proc_track.field_changed` finding per measure whose Vetoed value changed, plus a
      summary. The baseline's own signature is NOT carried over: the change findings bind
      the baseline file's bytes by hash, and say that it was signed only by a demo key.

  python3 tools/gp_operator.py verify DIR
      Verifies a pack against ~/.gatepost/keyring.json and its anchor.json.

Requires: Python 3.11+, `pip install cryptography` (signing only). Nothing else.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gpcanon import writer as W                    # noqa: E402
from gpcanon.schema import utc_ts                  # noqa: E402
from gpcanon.verify import load_keyring, verify_chain   # noqa: E402

HOME = Path(os.environ.get("GATEPOST_HOME", Path.home() / ".gatepost"))
KEY = HOME / "op_key.pem"
KEYRING = HOME / "keyring.json"
API = "https://api.oregonlegislature.gov/odata/odataservice.svc/"
CHAIN_ID = "proc_track.findings"
VETO_FILTER = "substringof('Governor vetoed',ActionText)"


# ---- keygen -------------------------------------------------------------------------------

def keygen() -> int:
    if KEY.exists():
        print(f"A key already exists at {KEY}. Not overwriting it. To rotate, see SCHEMA §10.", file=sys.stderr)
        return 2
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HOME, 0o700)
    kid, pub = W.generate_key(KEY)
    ring = {"keys": [{"key_id": kid, "public_key_hex": pub,
                      "effective_from": utc_ts(datetime.now(timezone.utc)), "retired_at": None}]}
    KEYRING.write_text(json.dumps(ring, indent=2) + "\n")
    print(f"""
Private key : {KEY}   (keep secret; back it up to a USB stick or your password manager)
Keyring     : {KEYRING}
key_id      : {kid}
public key  : {pub}

Publish these two lines somewhere public that you control (a GitHub gist, your Substack):
  Gatepost signing key {kid}
  {pub}
Anyone checking your packs pins that public key. Never publish the .pem file.
""")
    return 0


# ---- the Oregon veto check ------------------------------------------------------------------------

def _query(entity: str, flt: str, sel: str, attempts: int = 4):
    """GET one OData query. Retries transient network errors with backoff; every row is fetched
    before the first record is written, so a failure here leaves no partial pack."""
    import time
    url = API + entity + "?" + urllib.parse.urlencode({"$filter": flt, "$select": sel, "$format": "json"},
                                                      quote_via=urllib.parse.quote)
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return url, json.load(r)["value"]
        except (OSError, ValueError) as e:                 # URLError, resets, timeouts, truncated JSON
            if i == attempts - 1:
                raise SystemExit(f"API request failed after {attempts} attempts ({e}); nothing was written. "
                                 f"Re-run the same command.")
            time.sleep(2 ** i)


def veto_rows_live():
    retrieved = utc_ts(datetime.now(timezone.utc))
    veto_url, actions = _query("MeasureHistoryActions", VETO_FILTER,
                               "SessionKey,MeasurePrefix,MeasureNumber,ActionText,ActionDate")
    rows = []
    for a in sorted(actions, key=lambda a: (a["ActionDate"], a["SessionKey"], a["MeasurePrefix"], a["MeasureNumber"])):
        m_url, m = _query("Measures", f"SessionKey eq '{a['SessionKey']}' and MeasurePrefix eq '{a['MeasurePrefix']}' "
                                      f"and MeasureNumber eq {a['MeasureNumber']}", "Vetoed,CurrentLocation")
        m = m[0]
        rows.append({"session": a["SessionKey"], "measure": f"{a['MeasurePrefix']} {a['MeasureNumber']}",
                     "vetoed_field": bool(m["Vetoed"]), "current_location": m["CurrentLocation"],
                     "history_action": a["ActionText"].strip(), "history_action_date": a["ActionDate"][:10],
                     "measure_query": m_url, "veto_query": veto_url, "retrieved_at": retrieved})
    return rows


def veto_rows_from_v1(path: Path):
    """Rebuild the same rows from a gatepost/v1 records.jsonl (the 2026-09-27 retrieval)."""
    manifest = json.loads((path.parent / "manifest.json").read_text()) if (path.parent / "manifest.json").exists() else {}
    rows = []
    for line in path.read_text().splitlines():
        r = json.loads(line)
        rows.append({"session": r["session"], "measure": r["measure"], "vetoed_field": r["field_value"] == "true",
                     "current_location": r["current_location"], "history_action": r["history_action"],
                     "history_action_date": r["history_action_date"], "measure_query": r["source_query"],
                     "veto_query": manifest.get("veto_query", ""),
                     "retrieved_at": r["retrieved_at"].replace("Z", ".000000Z") if len(r["retrieved_at"]) == 20
                     else r["retrieved_at"]})
    return rows


def classify(row) -> tuple[str, str]:
    if row["vetoed_field"]:
        return "consistent", (f"{row['measure']} ({row['session']}): Measures.Vetoed is true and the history records "
                              f"a governor veto on {row['history_action_date']}.")
    if row["current_location"] == "Chapter Number Assigned":
        return "overridden_into_law", (f"{row['measure']} ({row['session']}): vetoed on {row['history_action_date']} and "
                                       "then became law (chapter number assigned); Vetoed=false is not a contradiction.")
    return "field_contradicts_history", (
        f"{row['measure']} ({row['session']}): Measures.Vetoed is false, but the measure's own history records "
        f"'{row['history_action']}' on {row['history_action_date']} and it was not overridden into law "
        f"(current location: {row['current_location']}).")


def record_changes(chain, rows, baseline: Path) -> None:
    raw = baseline.read_bytes()
    base_digest = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
    before = {(r["session"], r["measure"]): r for r in veto_rows_from_v1(baseline)}
    changed = []
    for now_row in rows:
        old = before.get((now_row["session"], now_row["measure"]))
        if old is None or old["vetoed_field"] == now_row["vetoed_field"]:
            continue
        changed.append(now_row["measure"] + " (" + now_row["session"] + ")")
        chain.record_finding(
            subject=f"or_legislature/{now_row['session']}/{now_row['measure'].replace(' ', '')}",
            finding_type="proc_track.field_changed",
            claim=(f"{now_row['measure']} ({now_row['session']}): Measures.Vetoed was "
                   f"{str(old['vetoed_field']).lower()} at {old['retrieved_at']} and is "
                   f"{str(now_row['vetoed_field']).lower()} at {now_row['retrieved_at']}."),
            evidence={"before": old, "after": now_row, "baseline_file_sha256": base_digest,
                      "baseline_note": "baseline is a gatepost/v1 pack signed only with a throwaway demo key; "
                                       "this record binds its bytes, it does not vouch for them"},
            occurred_at=now_row["retrieved_at"])
    chain.record_finding(
        subject="or_legislature/measures", finding_type="proc_track.field_change_summary",
        claim=(f"Between {next(iter(before.values()))['retrieved_at']} and {rows[0]['retrieved_at']}, Measures.Vetoed "
               f"changed on {len(changed)} of {len(rows)} measures with a recorded governor veto."),
        evidence={"changed": changed, "baseline_file_sha256": base_digest, "measures": len(rows)},
        occurred_at=rows[0]["retrieved_at"])


def veto_pack(out: Path, from_v1: Path | None, baseline_v1: Path | None = None) -> int:
    if not KEY.exists() or not KEYRING.exists():
        print(f"No key at {KEY}. Run `python3 tools/gp_operator.py keygen` first.", file=sys.stderr)
        return 2
    if (out / "chain").exists() and any((out / "chain").glob("seg-*.jsonl")):
        print(f"{out}/chain already has records. Use a new --out directory.", file=sys.stderr)
        return 2
    rows = veto_rows_from_v1(from_v1) if from_v1 else veto_rows_live()
    if not rows:
        print("The API returned no veto actions; nothing sealed.", file=sys.stderr)
        return 3
    chain = W.Chain(out / "chain", CHAIN_ID, actor=f"gp_operator:{W.default_actor()}")
    counts: dict[str, int] = {}
    for row in rows:
        kind, claim = classify(row)
        counts[kind] = counts.get(kind, 0) + 1
        chain.record_finding(subject=f"or_legislature/{row['session']}/{row['measure'].replace(' ', '')}",
                             finding_type=f"proc_track.{kind}", claim=claim, evidence=row,
                             occurred_at=row["retrieved_at"])
    overridden = sum(1 for r in rows if r["current_location"] == "Chapter Number Assigned")
    true_n = sum(1 for r in rows if r["vetoed_field"])
    summary_claim = (f"Oregon's public API records a 'Governor vetoed.' action on {len(rows)} measures "
                     f"({overridden} of them later became law by override). Measures.Vetoed is true on {true_n} and "
                     f"false on {len(rows) - true_n}; {counts.get('field_contradicts_history', 0)} of the false values "
                     f"contradict a veto that stood.")
    counts["overridden_into_law_total"] = overridden
    chain.record_finding(subject="or_legislature/measures", finding_type="proc_track.veto_field_summary",
                         claim=summary_claim, evidence={"counts": counts, "measures": len(rows),
                                                        "veto_query": rows[0]["veto_query"],
                                                        "retrieved_at": rows[0]["retrieved_at"]},
                         occurred_at=rows[0]["retrieved_at"])
    if baseline_v1:
        record_changes(chain, rows, baseline_v1)
    anchor = chain.seal(W.load_private_key(KEY))
    (out / "anchor.json").write_text(json.dumps(anchor, indent=2) + "\n")
    ring = json.loads(KEYRING.read_text())
    (out / "keyring.json").write_text(json.dumps(ring, indent=2) + "\n")     # convenience copy; recipients must not trust it
    (out / "README.txt").write_text(
        f"Oregon Legislature: Measures.Vetoed vs recorded 'Governor vetoed.' actions\n\n{summary_claim}\n\n"
        "Verify (Python 3, no install):\n"
        "  python3 verify.py chain --pubkey <the public key published by the operator> --anchor anchor.json\n\n"
        "Pin the public key from the operator's published location, NOT from keyring.json in this folder:\n"
        "a copy shipped inside the pack proves nothing about who made it.\n")
    return verify_pack(out)


def verify_pack(out: Path) -> int:
    pubkeys, windows = load_keyring(KEYRING)
    anchor = json.loads((out / "anchor.json").read_text()) if (out / "anchor.json").exists() else None
    rep = verify_chain(out / "chain", pubkeys, anchor=anchor, windows=windows)
    code = rep.exit_code()
    print(f"{out}: exit {code} · {rep.records} records · {rep.seals} seal(s)")
    for f in rep.findings:
        print(f"    {f['code']}{' seq ' + str(f['seq']) if f['seq'] is not None else ''}: {f['detail']}")
    if code == 0 and anchor:
        print(f"\nPublish this anchor next to your public key (it makes deleting the tail detectable):\n"
              f"  {json.dumps(anchor, sort_keys=True)}")
    return code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gp_operator", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    v = sub.add_parser("veto-pack")
    v.add_argument("--out", type=Path, default=Path(f"or_veto_pack_{datetime.now():%Y-%m-%d}"))
    v.add_argument("--from-v1", type=Path)
    v.add_argument("--baseline-v1", type=Path)
    c = sub.add_parser("verify")
    c.add_argument("dir", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "keygen":
        return keygen()
    if a.cmd == "veto-pack":
        if a.from_v1 and a.baseline_v1:
            p.error("--baseline-v1 compares against the live API; it can't be combined with --from-v1")
        return veto_pack(a.out, a.from_v1, a.baseline_v1)
    return verify_pack(a.dir)


if __name__ == "__main__":
    sys.exit(main())
