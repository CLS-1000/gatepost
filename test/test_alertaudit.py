"""Alert audit: engine properties on a small synthetic population (no PaySim download needed)."""
import numpy as np
import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("scipy")

from alertaudit.engine import korn_graubard, prepare, design, estimate, replay, OUTBOUND  # noqa: E402


def synthetic(n=120_000, seed=7):
    rng = np.random.default_rng(seed)
    t = rng.choice(["TRANSFER", "CASH_OUT", "PAYMENT", "CASH_IN"], size=n, p=[.1, .3, .4, .2])
    amount = rng.lognormal(10, 1.2, size=n)
    old = amount * rng.uniform(0.5, 3, size=n)
    drain = rng.random(n) < 0.35
    new = np.where(drain, 0.0, old - np.minimum(amount, old))
    out = np.isin(t, OUTBOUND)
    p = np.where(out & drain, 0.01, np.where(out, 0.0002, 0.0))
    df = pd.DataFrame({"type": t, "amount": amount, "oldbalanceOrg": old, "newbalanceOrig": new,
                       "isFraud": (rng.random(n) < p).astype(int)}, index=[f"t{i}" for i in range(n)])
    thr = df.loc[out, "amount"].quantile(0.99)
    alerted = pd.Series(out & (df.amount >= thr), index=df.index)
    return df, alerted


@pytest.fixture(scope="module")
def pop():
    df, alerted = synthetic()
    y = df.isFraud.to_numpy()
    posn = pd.Series(np.arange(len(df)), index=df.index)
    return df, alerted, (lambda idx: y[posn.loc[idx].to_numpy()])


def test_design_never_uses_labels(pop):
    df, alerted, _ = pop
    shuffled = df.assign(isFraud=np.random.default_rng(1).permutation(df.isFraud.to_numpy()))
    a = design(prepare(df, alerted), 1500, seed=3)
    b = design(prepare(shuffled, alerted), 1500, seed=3)
    assert list(a.sample_index) == list(b.sample_index)
    assert not set(a.sample_index) & set(df.index[alerted.to_numpy()])     # only un-alerted rows are sampled


def test_intervals_cover_the_truth(pop):
    df, alerted, review = pop
    fr = prepare(df, alerted)
    q = df.loc[~alerted.to_numpy()]
    truth = int(q.isFraud[(q.type.isin(OUTBOUND)) & (q.newbalanceOrig == 0) & (q.oldbalanceOrg > 0)].sum())
    hits = 0
    for seed in range(60):
        d = design(fr, 1500, seed)
        e = estimate(d, review(d.sample_index))[0]
        hits += e.low <= truth <= e.high
    assert hits / 60 >= 0.85, hits


def test_replay_counts_new_alerts_exactly(pop):
    df, alerted, review = pop
    fr = prepare(df, alerted)
    rule = lambda p: (p.type == "CASH_OUT") & (p.newbalanceOrig == 0)
    d = design(fr, 1500, seed=0)
    r = replay(d, review(d.sample_index), df, fr, rule)
    assert r["new_alerts"] == int(rule(df.loc[~alerted.to_numpy()]).sum())
    assert r["extra_fraud_low"] <= r["extra_fraud_point"] <= r["extra_fraud_high"]


def test_korn_graubard_zero_hits_gives_an_upper_bound_not_zero():
    p, lo, hi = korn_graubard([(100_000, 200, 0), (50_000, 100, 0)])
    assert p == 0 and lo == 0 and 0 < hi < 0.03


def test_sealed_audit_verifies_and_detects_edits(pop, tmp_path):
    from gpcanon import writer as W
    from gpcanon.verify import verify_chain
    from alertaudit.report import run_audit, seal, render
    df, alerted, review = pop
    r = run_audit(df, alerted, df.isFraud, review, 1500, 0,
                  {"cash-out drains": lambda p: (p.type == "CASH_OUT") & (p.newbalanceOrig == 0)},
                  {"R1": "top 1% outbound amount"}, "0" * 64)
    kid, pub = W.generate_key(tmp_path / "k.pem")
    anchor = seal(r, tmp_path / "chain", W.load_private_key(tmp_path / "k.pem"), actor="test")
    assert "missed about" in render(r, "t", demo=True)
    pk = {kid: bytes.fromhex(pub)}
    assert verify_chain(tmp_path / "chain", pk, anchor=anchor).exit_code() == 0
    seg = next((tmp_path / "chain").glob("seg-*.jsonl"))
    seg.write_bytes(seg.read_bytes().replace(b"about ", b"about 1", 1))
    assert verify_chain(tmp_path / "chain", pk, anchor=anchor).exit_code() == 1
