# Case study: Oregon's veto field

**In one line:** an automated check found that Oregon's public legislative API contradicted its own records on vetoes going back to 2007. We reported it, the field was corrected within about a day and a half, and a sealed Gatepost pack records exactly what changed, checkable by anyone without trusting us.

## What was found (2026-09-27, 13:04 UTC)

Oregon publishes legislative data at `api.oregonlegislature.gov`. Each measure has a `Vetoed` field, and each measure's own action history records events such as `Governor vetoed.`

- **27 measures** carry a `Governor vetoed.` action, in 10 sessions from 2007R1 to 2026R1.
- On **26** of them, `Vetoed` was `false`:
  - **23** were vetoes that stood, so the field contradicted the measure's own history.
  - **3** (SB 5520, SB 545, SB 897, all 2009R1) became law by override. `false` there is defensible.
- Only **1** (SB 215, 2013R1) had `Vetoed = true`.
- The defect was not a one-off. It appears in **9 of the 10** sessions with vetoes, including **all 7 of 7** 2025R1 vetoes. The tenth, 2013R1, had one veto: SB 215, the consistent one.
- **What that meant in practice:** anyone who asked the API "which measures were vetoed?" got one answer instead of 24. The truth existed only in free-text history rows.

## Reported (2026-09-28)

A note describing the discrepancy, with a one-line reproduction query, went to the Legislature's data helpdesk (`Leg.Helpdesk@oregonlegislature.gov`).

## What changed (seen 2026-09-29, 03:28 UTC)

- `Vetoed` is now `true` on **all 27** measures, including the three overrides.
- Across the whole API, `Vetoed = true` now returns exactly those 27.
- 26 values changed between the two retrievals.

## What we can and can't claim

| Claim | Status |
|---|---|
| The field was wrong on 26 of 27 measures on 2026-09-27 | From our retrieval that day. **See the caveat below.** |
| We reported it on 2026-09-28 | Our sent email |
| The field was corrected on all 27 by 2026-09-29 03:28 UTC | Live API, sealed in the pack with the full request for each measure |
| The correction happened *because of* our report | **Not yet provable.** The timing is consistent: a defect present since 2007, fixed within about a day of the report. But nothing was retrieved between our 09-27 pull and the send. Until the Legislature confirms, write it as sequence ("the day after it was reported, the field was corrected"), not cause. |

**Caveat on the "before" data:** the 2026-09-27 retrieval exists only as a pack signed with a throwaway demo key. The new pack binds those bytes by hash, so they can't be swapped later. But it can't independently prove what the API returned that day. Anyone can re-run the reproduction query against the live API today and see the corrected state, not the old one.

## How Gatepost records it

The pack is a gp-canon/1 chain, `proc_track.findings`:
- one `finding` per measure, with its evidence file (the exact API request and values)
- one `field_changed` finding per measure whose value changed, binding the 09-27 baseline by hash
- two summaries
- a seal signed with the operator's Ed25519 key

Anyone can check it:

```bash
python3 bin/verify.py or_veto_pack_<date>/chain --pubkey <operator's published key> --anchor anchor.json
```

The verifier is one Python file with no dependencies and no network. It checks:
- every record's hash
- every evidence file
- the chain order
- the seal against a key the checker pinned from the operator's public post, never from inside the pack
- with the published anchor, that nothing was cut from the end

## See it

```bash
python3 tools/demo.py                                  # offline: clean verify, then four tamper attempts, each rejected
python3 tools/demo.py --pack or_veto_pack_<date> --pubkey <your published key>   # the same, on the real pack
```

The four attempts:
1. editing a sealed claim → `hash_mismatch`
2. altering evidence → `evidence_mismatch`
3. rewriting everything and re-signing with another key → `key_id_mismatch`
4. deleting the tail, seal included → `truncated_tail`

## Status

- [ ] Real key generated and public key published
- [ ] Pack sealed with the real key; anchor published
- [ ] Reply from the Legislature (upgrades "sequence" to "cause" if it confirms)
- [ ] Notitia Civica piece rewritten around the correction
