#!/usr/bin/env python3
"""Gatepost demo: a sealed evidence pack, then four ways to cheat, each caught.

  python3 tools/demo.py                         offline demo pack (throwaway key, labelled DEMO)
  python3 tools/demo.py --pack DIR --pubkey HEX use a real pack (e.g. your sealed Oregon pack)
  add --pause to wait for Enter between steps while presenting

Offline by default, so nothing depends on a network during a demo. Every tamper runs on a
temporary copy; the pack you pass in is never modified. Exits non-zero if any step does not
behave as described, so a broken demo can't pass silently.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gpcanon import writer as W                          # noqa: E402
from gpcanon.canon import canon, parse, record_hash      # noqa: E402
from gpcanon.verify import NOTICE, verify_chain          # noqa: E402

BASELINE = ROOT / "out" / "or_veto_pack_DEMO_KEY" / "records.jsonl"
BOLD, DIM, OFF = ("\033[1m", "\033[2m", "\033[0m") if sys.stdout.isatty() else ("", "", "")


def say(title: str, pause: bool) -> None:
    print(f"\n{BOLD}{title}{OFF}")
    if pause:
        input(f"{DIM}  [Enter]{OFF}")


def check(pack: Path, pub: bytes, anchor: dict | None, expect_exit: int, expect_code: str | None) -> None:
    rep = verify_chain(pack / "chain", {W.key_id_of(pub): pub}, anchor=anchor)
    code = rep.exit_code()
    shown = [f for f in rep.findings if f["code"] not in NOTICE]
    verdict = {0: "VERIFIED", 1: "REJECTED: chain broken", 2: "REJECTED: bad signature",
               3: "REJECTED: malformed", 4: "REJECTED: not signed by the pinned key",
               5: "NOT A PASS: nothing pinned"}[code]
    print(f"  verify.py → exit {code}  {verdict}   ({rep.records} records, {rep.seals} seal{'s' if rep.seals != 1 else ''})")
    for f in shown[:3]:
        print(f"    {f['code']}{' at seq ' + str(f['seq']) if f['seq'] is not None else ''}: {f['detail']}")
    ok = code == expect_exit and (expect_code is None or expect_code in rep.codes())
    if not ok:
        raise SystemExit(f"DEMO BROKEN: expected exit {expect_exit}"
                         f"{' with ' + expect_code if expect_code else ''}, got {code} {sorted(rep.codes())}")


def seg(pack: Path) -> Path:
    return sorted((pack / "chain").glob("seg-*.jsonl"))[0]


def records(pack: Path) -> list[dict]:
    return [parse(l) for l in seg(pack).read_bytes().splitlines()]


def write(pack: Path, recs: list[dict]) -> None:
    seg(pack).write_bytes(b"".join(canon(r) + b"\n" for r in recs))


def build_demo_pack(work: Path) -> tuple[Path, bytes]:
    """Offline: the 2026-09-27 retrieval as 'before', all-true as 'after' (what the API showed 2026-09-29)."""
    saved_home = os.environ.get("GATEPOST_HOME")
    os.environ["GATEPOST_HOME"] = str(work / "demo_home")
    import importlib.util
    spec = importlib.util.spec_from_file_location("gp_operator", ROOT / "tools" / "gp_operator.py")
    op = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(op)
    with open(os.devnull, "w") as quiet:
        saved, sys.stdout = sys.stdout, quiet
        try:
            op.keygen()
            after = [dict(r, vetoed_field=True, retrieved_at="2026-09-29T03:28:48.884909Z")
                     for r in op.veto_rows_from_v1(BASELINE)]
            op.veto_rows_live = lambda: after
            rc = op.veto_pack(work / "pack", None, BASELINE)
        finally:
            sys.stdout = saved
            if saved_home is None:
                os.environ.pop("GATEPOST_HOME", None)
            else:
                os.environ["GATEPOST_HOME"] = saved_home
    if rc != 0:
        raise SystemExit(f"DEMO BROKEN: building the demo pack returned {rc}")
    ring = json.loads((work / "demo_home" / "keyring.json").read_text())
    (work / "pack" / "DEMO_ONLY.txt").write_text("Built by tools/demo.py with a throwaway key. Not evidence.\n")
    return work / "pack", bytes.fromhex(ring["keys"][0]["public_key_hex"])


def fresh(src: Path, work: Path, name: str) -> Path:
    dst = work / name
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    return dst


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pack", type=Path)
    ap.add_argument("--pubkey")
    ap.add_argument("--pause", action="store_true")
    a = ap.parse_args(argv)
    if bool(a.pack) != bool(a.pubkey):
        ap.error("--pack and --pubkey go together")

    work = Path(tempfile.mkdtemp(prefix="gatepost_demo_"))
    try:
        if a.pack:
            pack, pub = a.pack, bytes.fromhex(a.pubkey)
            label = f"your pack {a.pack}"
        else:
            pack, pub = build_demo_pack(work)
            label = "DEMO pack (throwaway key, built offline from the 2026-09-27 retrieval)"
        anchor = json.loads((pack / "anchor.json").read_text()) if (pack / "anchor.json").exists() else None
        recs = records(pack)
        findings = [r["s"] for r in recs if r["s"]["kind"] == "finding"]
        summaries = [f for f in findings if f["finding_type"].endswith("summary")]
        change_summary = [f for f in summaries if f["finding_type"] == "proc_track.field_change_summary"]

        print(f"{BOLD}Gatepost demo{OFF} · {label}")
        print(f"  {len(recs)} records, public key {pub.hex()[:16]}…  (pinned from where the operator published it)")

        say("1. The claim, as sealed", a.pause)
        for f in change_summary + [f for f in summaries if f not in change_summary]:
            print(f"  {f['claim']}")
        sample = next((f for f in findings if f["finding_type"] == "proc_track.field_changed"),
                      next(f for f in findings if not f["finding_type"].endswith("summary")))
        print(f"  e.g. {sample['claim']}")
        print(f"  {DIM}each finding binds its evidence file by sha256: {sample['evidence_digest'][:23]}…{OFF}")

        say("2. Anyone can check it: one file, no install, no network, no trust in the operator", a.pause)
        import subprocess
        cmd = [sys.executable, str(ROOT / "bin" / "verify.py"), str(pack / "chain"), "--pubkey", pub.hex()]
        if anchor:
            (work / "anchor.json").write_text(json.dumps(anchor))
            cmd += ["--anchor", str(work / "anchor.json")]
        print(f"  $ python3 bin/verify.py {pack.name}/chain --pubkey {pub.hex()[:12]}… {'--anchor anchor.json' if anchor else ''}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        print("  " + r.stdout.splitlines()[0])
        if r.returncode != 0:
            raise SystemExit(f"DEMO BROKEN: bin/verify.py exited {r.returncode}")
        check(pack, pub, anchor, 0, None)

        say("3. Cheat #1: quietly edit a sealed claim", a.pause)
        p = fresh(pack, work, "t1")
        r = records(p)
        i = next(n for n, x in enumerate(r) if x["s"]["seq"] == sample["seq"])
        print(f"  {DIM}before: {r[i]['s']['claim'][:90]}{OFF}")
        r[i]["s"]["claim"] = "The Legislature's records were accurate throughout."
        print(f"  {DIM}after:  {r[i]['s']['claim']}{OFF}")
        write(p, r)
        check(p, pub, anchor, 1, "hash_mismatch")

        say("4. Cheat #2: alter the evidence behind a finding", a.pause)
        p = fresh(pack, work, "t2")
        ev = p / "chain" / "evidence" / f"{sample['evidence_digest'][7:]}.json"
        ev.write_bytes(canon(dict(json.loads(ev.read_text()), current_location="Chapter Number Assigned")))
        check(p, pub, anchor, 1, "evidence_mismatch")

        say("5. Cheat #3: rewrite the whole pack and re-seal it with a different key", a.pause)
        p = fresh(pack, work, "t3")
        atk_kid, _ = W.generate_key(work / "attacker.pem")
        atk = W.load_private_key(work / "attacker.pem")
        r = records(p)
        prev = W.GENESIS if hasattr(W, "GENESIS") else "0" * 64
        for x in r:
            s = x["s"]
            s["prev_hash"] = prev
            if s["kind"] == "finding" and s is r[i]["s"]:
                s["claim"] = "Nothing to see here."
            if s["kind"] == "seal":
                s["key_id"] = atk_kid
            x["h"] = record_hash(s)
            if s["kind"] == "seal":
                x["sig"] = atk.sign(W.SEAL_DOMAIN + canon(s)).hex()
            prev = x["h"]
        write(p, r)
        print(f"  {DIM}every hash recomputed, validly signed, but by the attacker's key{OFF}")
        check(p, pub, None, 4, "key_id_mismatch")

        say("6. Cheat #4: delete the last records, seal included", a.pause)
        p = fresh(pack, work, "t4")
        r = records(p)
        write(p, r[: len(r) // 2])
        if anchor:
            print(f"  {DIM}with the published anchor{OFF}")
            check(p, pub, anchor, 1, "truncated_tail")
        else:
            check(p, pub, None, 5, None)

        print(f"\n{BOLD}Every change was caught, by a check the recipient runs without trusting the operator.{OFF}")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
