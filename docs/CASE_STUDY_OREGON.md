# Case study: Oregon's veto field

**In one line:** an automated check found that Oregon's public legislative API contradicted its own records on vetoes going back to 2007. We reported it, the Legislature corrected the field within about a day and a half and confirmed the update in writing, and a sealed Gatepost pack records exactly what changed, checkable by anyone without trusting us.

## What was found (2026-09-27, 13:04 UTC)

Oregon publishes legislative data at `api.oregonlegislature.gov`. Each measure has a `Vetoed` field, and each measure's own action history records events such as `Governor vetoed.`

- **27 measures** carry a `Governor vetoed.` action, in 10 sessions from 2007R1 to 2026R1.
- On **26** of them, `Vetoed` was `false`:
  - **23** were vetoes that stood, so the field contradicted the measure's own history.
  - **3** (SB 5520, SB 545, SB 897, all 2009R1) became law by override. `false` there is defensible.
- Only **1** (SB 215, 2013R1) had `Vetoed = true`.
- The defect was not a one-off. It appears in **9 of the 10** sessions with vetoes, including **all 7 of 7** 2025R1 vetoes. The tenth, 2013R1, had one veto: SB 215, the consistent one.
- **What that meant in practice:** anyone who asked the API "which measures were vetoed?" got one answer instead of 24. The truth existed only in free-text history rows.

## Reported (2026-09-27, 15:37 UTC)

A note describing the discrepancy, with a one-line reproduction query, went to the Legislature's data helpdesk (`Leg.Helpdesk@oregonlegislature.gov`). A follow-up on 2026-09-29 (03:43 UTC) noted the field now read `true` on all 27 and asked whether that was in response to the report.

## What changed (seen 2026-09-29, 03:28 UTC)

- `Vetoed` is now `true` on **all 27** measures, including the three overrides.
- Across the whole API, `Vetoed = true` now returns exactly those 27.
- 26 values changed between the two retrievals.

## Confirmed by the Legislature (2026-09-30, 17:14 UTC)

The Legislative Help Desk (Information Technology and Media Services) replied that it had forwarded the report to the development team, and passed on the team's answer: the data "has now been updated to ensure that all measures with a gubernatorial veto are accurately reflected," and overridden vetoes will keep `Vetoed = true`. The reply also restates the before-state from the report (`Vetoed` true for only SB 215).

One line in the reply says the remaining 24 measures "correctly display false" before saying the data was updated. It reads as the report's own sentence reworded; the reply's substance is the update. Paraphrase the reply rather than quoting that line.

## What we can and can't claim

| Claim | Status |
|---|---|
| The field was wrong on 26 of 27 measures on 2026-09-27 | From our retrieval that day. **See the caveat below.** |
| We reported it on 2026-09-27 | Our sent email (15:37 UTC) |
| The field was corrected on all 27 by 2026-09-29 03:28 UTC | Live API, sealed in the pack with the full request for each measure |
| The Legislature corrected the field in response to our report | **Confirmed.** The help desk's 2026-09-30 reply says it forwarded the report to the development team and the data has been updated. A defect present since 2007 was fixed within about a day and a half of the report. |

**Caveat on the "before" data:** the 2026-09-27 retrieval exists only as a pack signed with a throwaway demo key. The new pack binds those bytes by hash, so they can't be swapped later. On its own it can't prove what the API returned that day, but the Legislature's 2026-09-30 reply restates the same before-state (`Vetoed` true for only SB 215). Anyone can re-run the reproduction query against the live API today and see the corrected state, not the old one.

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

- [x] Real key generated and public key published (`out/OPERATOR_KEY.md`, key_id `f7b1282a4a9ccf50`)
- [x] Pack sealed with the real key; anchor published (`or_veto_pack_2026-10-01`)
- [x] Reply from the Legislature (2026-09-30): confirmed the data was updated after the report
- [ ] Notitia Civica piece rewritten around the correction
