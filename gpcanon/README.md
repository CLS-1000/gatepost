# gpcanon — gp-canon/1 writer, sealing and offline verifier

Implements the record format chosen on 2026-09-28 (Product Record → Decision), from the
CANON and SCHEMA pages. Python 3.11+, stdlib only except sealing (`cryptography`).

| File | Side | Deps |
|---|---|---|
| `canon.py` | both | stdlib: value model, strict parser with CANON §7 reasons, canonical bytes, `decimal_from_float` |
| `schema.py` | both | stdlib: SCHEMA §3–4 per-kind field table and intent rules |
| `ed25519_verify.py` | verifier | stdlib: RFC 8032 verify (checked against the RFC vector and `cryptography`) |
| `writer.py` | producer | `Chain.gate()`, dangling-intent recovery, `seal()`, HEAD, anchors; `cryptography` only for signing |
| `verify.py` | verifier | stdlib CLI; `tools/bundle_verify.py` inlines everything into **`bin/verify.py`**, one file for recipients |

```
python3 bin/verify.py CHAIN_DIR --pubkey <hex> [--anchor anchor.json] [--policy ID=PATH] [--json]
python3 -m pytest test/ -q                     # 146 tests: writer, tamper suite (package + bin/verify.py), conformance
```

Exit codes carry over from gatepost/v1: 0 pass · 1 chain · 2 signature · 3 malformed · 4 unpinned key · 5 nothing pinned.

## Conformance

`spec/` holds the G1 package: CANON.md, SCHEMA.md, the golden vectors, the vector generator and
the two reference implementations (`spec/ref/`, Python and JS). It was recovered on 2026-09-28
from the G1 session's own file writes after the "Push" request in that session produced an empty
reply and the files never reached a repo. The generator is deterministic (fixed test-key seed, no
clock), and regenerating reproduces the vector files byte for byte.

```
python3 spec/ref/check_vectors.py      # Python reference: 276 passed
node    spec/ref/check_vectors.mjs     # JS reference:     276 passed
python3 -m pytest test/test_conformance.py -q   # gpcanon: 82 vectors + sample chain, 86 checks
```

gpcanon shares no code with either reference, so there are now three implementations in agreement.
Running the vectors caught one real difference, which is fixed: an absent `kind` is `missing_field`
(vector s24), and `canon_version_unsupported` is collected alongside other errors.

## Where this departs from, or adds to, the spec

Each needs a decision on the SCHEMA page before the first real chain freezes it.

1. **Lock held from intent through outcome** (SCHEMA §6 releases it while the body runs). With the
   split lock, a concurrent `gate()` sees the in-flight intent as dangling (§5.4), writes
   `outcome_unwritten` for a live action, and its own intent breaks §4 pairing. Tested with four
   concurrent writers: 40 records, no forks, no false failures.
2. **A chain with no seals is exit 5, not a pass.** Nothing is signed, so anyone can rewrite it
   and recompute every hash. `unsealed_tail` after at least one seal stays a notice, as specified.
3. **A dangling intent at the tail is a notice** (`dangling_intent`); an intent followed by another
   intent without an outcome is `unpaired` and fails.
4. **Faults with no valid record raise instead of recording.** Prefix mismatch or an unknown policy
   combined with invalid inputs: §4 needs `inputs_digest` non-null for those reasons, and it can't
   be computed. The gate raises and the body never runs (the §5.2 rule).
5. **Segment naming**: `seg-<first seq, 12 digits>.jsonl`, rotated at 64 MB. SCHEMA doesn't name segments.
6. **`detail` may be null for any gated kind.** §3 marks it ⁿ, but §4 lists no condition for it.
7. **Extra report codes**: `torn_line` (malformed), and notices `tail_unanchored`, `dangling_intent`,
   `notes_unverified`, `seals_unverified`.

## Carry-over list (Product Record → Decision)

- [x] Unpinned is not a pass (exit 5; `--allow-unpinned` is explicit)
- [x] Tamper cases ported to gp-canon codes (flip, delete, reorder, rehash-after-edit, forged seal,
      cross-chain splice, truncation with and without anchor, swapped policy file, sig on non-seal,
      non-canonical line, notes edit, torn tail)
- [ ] Key rotation with validity windows
- [ ] Partial export with a signed anchor
- [ ] `finding` kind for proc_track and pdx-1i
- [ ] Re-seal the Oregon veto findings under gp-canon/1 with the real key

## First consumer

SPEC-1 triage writes two chains through this package: `spec1.triage` (one gate per committed
evaluation batch; the SQLite COMMIT runs inside the gate body) and `spec1.publish` (one gate per
public World State Brief). See `triage/evidence.py` in the triage package.
