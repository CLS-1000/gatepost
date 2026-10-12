# Alert audit: what your rules miss

> **DEMO.** Public synthetic data (PaySim). The "analyst review" of the sample is simulated from the
> dataset's fraud labels, and the report is sealed with a throwaway key. Method and numbers are real; nothing here is a client's.

## Headline

- Your rules raised **75,309 alerts**; analysts confirmed **3,963** as fraud (**5.3% precision**).
- From a review of **2,600** transactions the rules did *not* alert on, we estimate they **missed about 6,013 frauds in outbound drains alone** (95% interval 3,110 to 10,482).
- So at most **56%** of the fraud raised an alert, and most likely about **40%** (as low as 27%).
- In outbound, balance kept, 0 fraud turned up in 250 reviewed. That can't rule out up to 22,963 more; a larger review would tighten it, and if any are found there, recall is lower than above.

> **Check against the answer** (known only because the data is synthetic): the rules actually missed **4,250** frauds, 4,202 of them in outbound drains, inside the 95% interval. True recall: 48%.

## Where the misses are

| Segment | Transactions not alerted | Reviewed | Fraud found | Estimated missed (95% interval) |
|---|---:|---:|---:|---|
| outbound drains | 1,127,375 | 2,250 | 12 | **6,013** (3,110 to 10,482) |
| outbound, balance kept | 1,567,725 | 250 | 0 | upper bound only: at most 22,963 |
| inbound / merchant | 3,592,211 | 100 | 0 | out of scope for this typology (check sample only) |

## What a rule change would do

| Proposed change | New alerts (exact) | Extra fraud caught, est. (95% interval) | Alerts per extra fraud |
|---|---:|---|---:|
| Extend R2 to CASH_OUT drains | 115,697 | 3,846 (1,639 to 7,551) | 30 |
| Lower R2's balance threshold to 20,000 | 80,023 | 824 (70 to 3,302) | 97 |

## Rules audited

- **R1 large outbound:** TRANSFER or CASH_OUT of at least 2,650,036 (99th percentile of outbound amounts)
- **R2 account drain:** TRANSFER that leaves the account at zero, from a balance of at least 88,030 (90th percentile)

## Method

- Only transactions the rules did not alert on are sampled. They are split into segments and amount bands using transaction features only; no fraud labels are used to design the sample.
- Sample: 2,600 transactions, proportional within each segment, seed 0 (re-drawable).
- Estimates: stratified weighting with a Korn-Graubard 95% interval (exact binomial at the design's effective sample size), suited to rare events.
- Validated on 200 repeated audits of this dataset: the 95% intervals contained the true count 96-99% of the time; median error 19% at 2,500 reviews, 17% at 5,000.
- **What this can't tell you:** fraud that looks like nothing in any sampled segment; fraud your analysts would also misjudge in review; anything outside the period. Estimates assume the sample was reviewed with the same care as live alerts.

## Verify this report

Every number above is sealed as a Gatepost finding, with its evidence (rules, sample design, the sampled IDs and their review labels, and the dataset fingerprint). Anyone can check it offline:

```
python3 bin/verify.py <pack>/chain --pubkey <auditor's published key> --anchor <pack>/anchor.json
```

Dataset fingerprint: `sha256:16910f90577b0d981bf8ff289714510bb89bc71bff7d3f220f024e287e4eea6b`
