# Alert Audit: product sketch

**One line:** we tell a fraud or AML team what their rules are missing, as a number with an honest
interval, and seal the answer so their examiner can check it without trusting us.

Status: working prototype, validated on public synthetic data (PaySim, 6.36M transactions).
Sample report: [`examples/alertaudit_paysim_DEMO/report.md`](../examples/alertaudit_paysim_DEMO/report.md).
Code: `alertaudit/` (engine, report, sealing), tests in `test/test_alertaudit.py`.

## The problem it answers

Every team knows its **precision**: analysts disposition every alert, so they know most alerts are
false. Industry figures put AML false positives at 85–95%.[^fp] Almost no team knows its **recall**,
meaning how much fraud never raised an alert, because nobody looks at what the rules let through.
Rule tuning then runs on precision alone, which quietly trades misses for fewer alerts.

## What the demo shows (PaySim, public data)

A plausible two-rule set, with thresholds set from alert volume only (99th percentile of outbound
amounts; 90th percentile of drained balances), fixed before looking at any label:

- **Visible to the bank:** 75,309 alerts, 3,963 confirmed, 5.3% precision. That's inside the
  industry's normal band.
- **Invisible to the bank (ground truth):** the rules miss **4,250 of 8,213 frauds**. Recall is 48%.
- **What the audit found** from 2,600 reviewed un-alerted transactions: about **6,013 missed** in
  outbound drains, with a 95% interval of 3,110 to 10,482. The true 4,202 is inside that interval.
  Recall is at most 56%.
- **The rule change it recommends:** extending the drain rule to CASH_OUT adds 115,697 alerts and
  catches about 3,846 more frauds (true figure: 2,646), roughly one fraud per 30–44 new alerts. The
  other candidate, lowering the balance threshold, returns one fraud per 97–145 new alerts. The audit
  ranks them correctly.

### Is the estimate trustworthy? Tested over 200 repeated audits per setting

| Reviews | 95% interval contained the truth | Median error | Interval width vs truth |
|---:|---:|---:|---:|
| 1,000 | 99% | 40% | 242% |
| 2,500 | 98% | 19% | 146% |
| 5,000 | 96% | 17% | 100% |

The rule-change estimates covered the truth 95–96% of the time. The intervals lean cautious, which
is the right direction for an audit.

**How the method got here, stated honestly:**
- A first version used per-stratum Bayesian priors. Its intervals covered only 28–74% of the time,
  because sparse strata inflated the estimate. It was replaced with the Korn–Graubard interval, the
  standard for rare events in stratified samples.
- A two-phase adaptive design was tried and added nothing, so it was dropped.
- One PaySim quirk was deliberately **not** used: "amount equals the full balance" is about 100% fraud
  in the simulator. It would have made the demo look magical, and it won't hold on real data.
- All of this was developed and validated on one synthetic dataset. Real bank data will be sparser
  (lower fraud rates), so it will need larger reviews for the same precision.

## How an engagement works

1. **Client exports** one period of transactions with their alert flags and dispositions. For a
   pilot this can be a de-identified extract: amounts, types, balances, IDs.
2. **We design the sample.** It uses features only and never touches labels; a test proves the
   sample is identical if the labels are shuffled. The sample is seeded and recorded.
3. **Their analysts review the sample** in their normal tooling, as fraud or not fraud. This is the
   client's biggest cost: at an *assumed* 2–4 minutes per item, 2,500 reviews is about 85–170 analyst
   hours.
4. **We deliver the sealed report:** precision, estimated misses by segment, what each candidate rule
   change would do, and what the method can't see. Every number is a Gatepost finding with its
   evidence: rules, sample design, sampled IDs and labels, and a fingerprint of the dataset.
5. **Their examiner or auditor verifies it** with `bin/verify.py`: one file, no install, and no need
   to trust us.

No production access and no integration: data comes to us and a report goes back. That keeps it
closer to a paid audit than a software vendor relationship, which matters for how hard it is to buy.

## Pricing ladder: hypotheses to test, not market data

I couldn't open primary sources on validation and tuning rates this session, so these numbers are
**starting points for the first five conversations**, based on what the audit costs to deliver.

| Tier | What they get | Our effort | Starting price to test |
|---|---|---|---|
| Free | Public demo report, the one-file verifier, a sample-size calculator | – | $0 (lead generation) |
| **Miss estimate** | One period, one rule set: precision, estimated misses with intervals, sealed report | 1–2 days | $5k–$10k |
| **Tuning audit** | Miss estimate plus replay of up to 5 proposed rule changes, a threshold sweep, and a readout for the compliance officer or board | 3–5 days | $15k–$25k |
| **Quarterly** | Same design re-run each quarter: miss trend, drift, before-and-after for rule changes | 1 day per quarter | $4k–$8k per quarter |

Anchor the price on what the client already pays: analyst hours per alert and the cost of a missed
case. For the rule-change result above, "30 alerts per extra fraud caught" can be priced against
their own cost per alert.

## What it can't claim

- Fraud that looks like nothing in any segment we sample.
- Fraud their analysts would also misjudge on review. The estimate is only as good as the review.
- Anything outside the audited period.
- Cause. It measures what the rules miss, not why.

## Who to talk to first

Fintechs and BaaS programs, and credit unions with in-house fraud or AML analysts. Ask one question:
**"How do you know what your rules miss?"** A pause, or "we do below-the-line testing but it's
anecdotal," is the opening.

Five conversations before building anything more. Bring the demo report and the verifier.

## Next build steps (only after the conversations)

- A CSV-in, report-out command for client data, with a configurable segment definition.
- A sample-size calculator: what interval width a given review budget buys.
- A review sheet export and import, so their analysts label in a spreadsheet.

[^fp]: [State of False Positives in AML Screening: 2026 Report, Facctum](https://www.facctum.com/blog/aml-false-positive-report): 85–95% false positives; 1–5% of alerts lead to a SAR.
