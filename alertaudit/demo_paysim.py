#!/usr/bin/env python3
"""Alert-audit demo on PaySim (public synthetic mobile-money data, 6,362,620 transactions).

  python3 -m alertaudit.demo_paysim --csv paysim.csv --out audit_demo [--budget 2500] [--seed 0]

Get the data: the PaySim1 CSV (Lopez-Rojas et al.), e.g. from Hugging Face `theman10/paysim`.
The script checks the file against PaySim's published counts before using it.

The "bank's rules" are two common heuristics with thresholds set from alert volume only (a 99th-
percentile large-outbound rule and a 90th-percentile account-drain rule), fixed before any label
was looked at. Analyst review of the sample is simulated from PaySim's fraud labels. The pack is
sealed with a throwaway key and labelled DEMO.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gpcanon import writer as W                 # noqa: E402
from gpcanon.verify import verify_chain         # noqa: E402

from alertaudit.engine import OUTBOUND          # noqa: E402
from alertaudit.report import file_sha256, render, run_audit, seal   # noqa: E402

PAYSIM = {"rows": 6_362_620, "fraud": 8_213, "flagged": 16}


def load(csv: Path) -> pd.DataFrame:
    df = pd.read_csv(csv, usecols=["step", "type", "amount", "nameOrig", "oldbalanceOrg", "newbalanceOrig",
                                   "isFraud", "isFlaggedFraud"])
    got = {"rows": len(df), "fraud": int(df.isFraud.sum()), "flagged": int(df.isFlaggedFraud.sum())}
    if got != PAYSIM:
        raise SystemExit(f"{csv} does not match PaySim1's published counts {PAYSIM}: got {got}")
    df.index = [f"t{i}" for i in range(len(df))]
    return df


def bank_rules(df: pd.DataFrame):
    out = df.type.isin(OUTBOUND)
    q_amt = float(df.loc[out, "amount"].quantile(0.99))
    drain_t = (df.type == "TRANSFER") & (df.newbalanceOrig == 0)
    q_bal = float(df.loc[drain_t, "oldbalanceOrg"].quantile(0.90))
    alerted = (out & (df.amount >= q_amt)) | (drain_t & (df.oldbalanceOrg >= q_bal))
    text = {"R1 large outbound": f"TRANSFER or CASH_OUT of at least {q_amt:,.0f} (99th percentile of outbound amounts)",
            "R2 account drain": f"TRANSFER that leaves the account at zero, from a balance of at least {q_bal:,.0f} (90th percentile)"}
    candidates = {
        "Extend R2 to CASH_OUT drains":
            lambda p: (p.type == "CASH_OUT") & (p.newbalanceOrig == 0) & (p.oldbalanceOrg >= q_bal),
        "Lower R2's balance threshold to 20,000":
            lambda p: (p.type == "TRANSFER") & (p.newbalanceOrig == 0) & (p.oldbalanceOrg >= 20_000),
    }
    return alerted, text, candidates


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--budget", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    if a.out.exists() and any(a.out.iterdir()):
        raise SystemExit(f"{a.out} is not empty")
    df = load(a.csv)
    alerted, rules_text, candidates = bank_rules(df)
    y = df.isFraud.to_numpy()
    pos = pd.Series(np.arange(len(df)), index=df.index)
    review = lambda idx: y[pos.loc[idx].to_numpy()]              # simulated analyst review
    r = run_audit(df, alerted, df.isFraud, review, a.budget, a.seed, candidates, rules_text, file_sha256(a.csv))

    a.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        kid, pub = W.generate_key(Path(tmp) / "DEMO_throwaway.pem")
        anchor = seal(r, a.out / "chain", W.load_private_key(Path(tmp) / "DEMO_throwaway.pem"), actor="alertaudit-demo")
    (a.out / "anchor.json").write_text(json.dumps(anchor, indent=2) + "\n")
    (a.out / "DEMO_PUBLIC_KEY.txt").write_text(f"{pub}\n# throwaway demo key {kid}; the private half was deleted\n")
    truth = int(y[~alerted.to_numpy()].sum())
    q = df.loc[~alerted.to_numpy()]
    from alertaudit.engine import paysim_segments
    in_main = int(q.isFraud.to_numpy()[paysim_segments()[0].mask(q).to_numpy()].sum())
    tv = {"missed": truth, "in_main": in_main, "recall": int(y[alerted.to_numpy()].sum()) / int(y.sum())}
    (a.out / "report.md").write_text(render(r, "Alert audit: what your rules miss", demo=True, truth=tv))

    rep = verify_chain(a.out / "chain", {kid: bytes.fromhex(pub)}, anchor=anchor)
    print(f"report: {a.out / 'report.md'}\nverify: exit {rep.exit_code()} ({rep.records} records)")
    print(f"ground truth (not available to a real auditor): {truth:,} frauds missed")
    return 0 if rep.exit_code() == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
