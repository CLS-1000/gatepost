"""Alert audit: estimate what a fraud/AML rule set misses, from a labelled review sample of the
transactions it did NOT alert on ("below-the-line" testing, done so the result is a number with
an honest interval instead of an anecdote).

Flow
  1. design()    splits the un-alerted population into segments and strata on features only
                 (never labels) and draws a seeded review sample. Optional two-phase mode spends a
                 pilot proportionally, then puts the rest where the pilot found fraud.
  2. the client's analysts review the sample (fraud / not fraud).
  3. estimate()  per segment: missed-fraud estimate with a 95% interval: stratified weighting and a
                 Korn-Graubard interval (exact binomial at the design's effective sample size), which
                 stays honest when most strata found nothing.
  4. replay()    what a proposed rule would add: new alert volume exactly, extra fraud caught
                 estimated from the same sample.

Segment roles
  estimate : fraud is expected here; the budget goes here; reported as an estimate.
  bound    : low-rate remainder; small sample; reported as an upper bound, clearly wider.
  scope    : excluded from the typology (e.g. inbound credits); a check sample is reported, no
             population claim is made.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import numpy as np
import pandas as pd

OUTBOUND = ("TRANSFER", "CASH_OUT")


@dataclass(frozen=True)
class Segment:
    name: str
    role: str                                   # "estimate" | "bound" | "scope"
    mask: Callable[[pd.DataFrame], pd.Series]   # feature-only membership
    bands: int = 1                              # amount-quantile strata within the segment
    share: float = 0.0                          # fraction of the budget (estimate/bound)
    fixed: int = 0                              # fixed sample size (scope)


def paysim_segments() -> list[Segment]:
    """The segments used for the PaySim demo. Features only: type, amount, balances.

    Deliberately NOT used: amount == old balance. In PaySim that flag is ~100% fraud, a simulator
    artifact that would not hold on real bank data and would make the audit look magical.
    """
    out = lambda p: p["type"].isin(OUTBOUND)
    drain = lambda p: (p["newbalanceOrig"] == 0) & (p["oldbalanceOrg"] > 0)
    return [
        Segment("outbound drains", "estimate", lambda p: out(p) & drain(p), bands=10, share=0.9),
        Segment("outbound, balance kept", "bound", lambda p: out(p) & ~drain(p), bands=1, share=0.1),
        Segment("inbound / merchant", "scope", lambda p: ~out(p), fixed=100),
    ]


@dataclass
class Design:
    seed: int
    mode: str
    segments: list
    sizes: dict                     # stratum -> N_h
    alloc: dict                     # stratum -> n_h
    segment_of: dict                # stratum -> segment name
    sample_index: np.ndarray
    sample_stratum: np.ndarray
    edges: dict = field(default_factory=dict)

    @property
    def reviewed(self) -> int:
        return len(self.sample_index)


def _strata(pop: pd.DataFrame, segs: list[Segment]):
    keys = np.full(len(pop), None, dtype=object)
    edges = {}
    for s in segs:
        m = s.mask(pop).to_numpy() & np.equal(keys, None)
        if s.bands > 1:
            e = np.unique(np.quantile(pop["amount"].to_numpy()[m], np.linspace(0, 1, s.bands + 1)[1:-1]))
            b = np.searchsorted(e, pop["amount"].to_numpy()[m], side="right")
            keys[m] = np.char.add(f"{s.name}|b", b.astype(str)).astype(object)
            edges[s.name] = [float(x) for x in e]
        else:
            keys[m] = f"{s.name}|all"
    if np.equal(keys, None).any():
        raise ValueError(f"{int(np.equal(keys, None).sum())} un-alerted rows fall in no segment")
    return pd.Series(keys, index=pop.index), edges


@dataclass
class Frame:
    """The un-alerted population, stratified once. Everything here is label-free."""
    segs: list
    sizes: dict
    groups: dict            # stratum -> row labels
    segment_of: dict
    edges: dict
    keys: pd.Series


def prepare(pop: pd.DataFrame, alerted: pd.Series, segs: list[Segment] | None = None) -> Frame:
    segs = segs or paysim_segments()
    quiet = pop.loc[~alerted.to_numpy()]
    keys, edges = _strata(quiet, segs)
    groups = {k: np.asarray(v) for k, v in keys.groupby(keys).groups.items()}
    return Frame(segs, {k: len(v) for k, v in groups.items()}, groups,
                 {k: k.split("|")[0] for k in groups}, edges, keys)


def design(frame: Frame, budget: int, seed: int, mode: str = "proportional", pilot_frac: float = 0.3,
           review: Callable[[np.ndarray], np.ndarray] | None = None) -> Design:
    """Draw the review sample from the un-alerted population.

    mode="proportional": within a segment, n_h proportional to N_h. Uses no labels at all.
    mode="two_phase":    a proportional pilot (pilot_frac of the segment budget) is reviewed first via
                         `review(index) -> labels`; the rest goes by Neyman allocation on the pilot's
                         smoothed rates. The only labels used are the pilot's own reviews.
    """
    rng = np.random.default_rng(seed)
    sizes, groups, seg_of = frame.sizes, frame.groups, frame.segment_of
    perm = {}
    alloc = {k: 0 for k in sizes}

    def take(k: str, n: int) -> None:
        if k not in perm:
            perm[k] = rng.permutation(sizes[k])
        alloc[k] = min(sizes[k], alloc[k] + max(0, n))

    def proportional(seg_keys: list, n: int) -> dict:
        tot = sum(sizes[k] for k in seg_keys)
        return {k: max(1, int(round(n * sizes[k] / tot))) for k in seg_keys}

    for s in frame.segs:
        seg_keys = [k for k in sizes if seg_of[k] == s.name]
        if not seg_keys:
            continue
        if s.role == "scope":
            for k, n in proportional(seg_keys, s.fixed).items():
                take(k, n)
            continue
        n_seg = int(round(budget * s.share))
        if mode == "two_phase" and s.role == "estimate" and review is not None:
            for k, n in proportional(seg_keys, int(n_seg * pilot_frac)).items():
                take(k, n)
            got = {k: int(review(groups[k][perm[k][:alloc[k]]]).sum()) for k in seg_keys}
            p = {k: (got[k] + 0.5) / (alloc[k] + 1.0) for k in seg_keys}
            w = {k: sizes[k] * np.sqrt(p[k] * (1 - p[k])) for k in seg_keys}
            left = n_seg - sum(alloc[k] for k in seg_keys)
            tw = sum(w.values())
            for k in seg_keys:
                take(k, int(round(left * w[k] / tw)))
        else:
            for k, n in proportional(seg_keys, n_seg).items():
                take(k, n)

    ks = [k for k in sizes if alloc[k]]
    idx = np.concatenate([groups[k][perm[k][:alloc[k]]] for k in ks])
    strat = np.concatenate([np.full(alloc[k], k, dtype=object) for k in ks])
    return Design(seed=seed, mode=mode, segments=[s.name for s in frame.segs], sizes=dict(sizes),
                  alloc=alloc, segment_of=dict(seg_of), sample_index=idx, sample_stratum=strat,
                  edges=frame.edges)


@dataclass
class Estimate:
    segment: str
    role: str
    population: int
    reviewed: int
    found: int
    point: float
    low: float
    high: float


def korn_graubard(counts: list[tuple[int, int, int]], alpha: float = 0.05) -> tuple[float, float, float]:
    """Stratified proportion with a Korn-Graubard (1998) interval: Clopper-Pearson at the design's
    effective sample size. counts = [(N_h, n_h, y_h)]. Returns (p_hat, low, high).

    Built for rare events in stratified samples: it stays well behaved when most strata found
    nothing, where per-stratum priors add up to phantom counts and normal intervals collapse to zero.
    """
    from scipy.stats import beta
    N = sum(c[0] for c in counts)
    n_tot = sum(c[1] for c in counts)
    p = sum((Nh / N) * (yh / nh) for Nh, nh, yh in counts if nh)
    var = sum((Nh / N) ** 2 * (1 - nh / Nh) * (yh / nh) * (1 - yh / nh) / max(nh - 1, 1)
              for Nh, nh, yh in counts if nh)
    n_eff = min(n_tot, p * (1 - p) / var) if var > 0 else n_tot
    x = p * n_eff
    lo = 0.0 if x <= 0 else float(beta.ppf(alpha / 2, x, n_eff - x + 1))
    hi = 1.0 if x >= n_eff else float(beta.ppf(1 - alpha / 2, x + 1, n_eff - x))
    return p, lo, hi


def estimate(d: Design, labels: np.ndarray, segs: list[Segment] | None = None) -> list[Estimate]:
    """Per segment: missed-fraud total = N_segment x stratified rate, with a Korn-Graubard 95% interval."""
    segs = segs or paysim_segments()
    labels = np.asarray(labels).astype(int)
    hits = pd.Series(labels).groupby(d.sample_stratum).sum().to_dict()
    out = []
    for s in segs:
        ks = [k for k in d.sizes if d.segment_of[k] == s.name]
        pop = sum(d.sizes[k] for k in ks)
        rev = sum(d.alloc[k] for k in ks)
        found = int(sum(hits.get(k, 0) for k in ks))
        if s.role == "scope" or not rev:
            out.append(Estimate(s.name, s.role, pop, rev, found, float("nan"), float("nan"), float("nan")))
            continue
        p, lo, hi = korn_graubard([(d.sizes[k], d.alloc[k], int(hits.get(k, 0))) for k in ks])
        out.append(Estimate(s.name, s.role, pop, rev, found, pop * p, pop * lo, pop * hi))
    return out


def replay(d: Design, labels: np.ndarray, pop: pd.DataFrame, frame: Frame,
           new_rule: Callable[[pd.DataFrame], pd.Series]) -> dict:
    """Extra alerts (exact) and extra fraud caught (estimated) if `new_rule` were added."""
    quiet = pop.loc[frame.keys.index]
    fires = new_rule(quiet).to_numpy()
    fire_by_k = pd.Series(fires).groupby(frame.keys.to_numpy()).sum().to_dict()
    s_fires = new_rule(pop.loc[d.sample_index]).to_numpy()
    labels = np.asarray(labels).astype(int)
    df = pd.DataFrame({"k": d.sample_stratum, "y": labels, "f": s_fires})
    counts = []
    for k, N_fire in fire_by_k.items():
        if not N_fire:
            continue
        sub = df[(df.k == k) & df.f]
        if len(sub) == 0:                           # no sampled item inside the slice: use the stratum's rate
            sub = df[df.k == k]
        counts.append((int(N_fire), len(sub), int(sub.y.sum())))
    N = sum(c[0] for c in counts)
    p, lo, hi = korn_graubard(counts) if counts else (0.0, 0.0, 0.0)
    point = N * p
    return {"new_alerts": int(fires.sum()), "extra_fraud_point": float(point),
            "extra_fraud_low": float(N * lo), "extra_fraud_high": float(N * hi)}
