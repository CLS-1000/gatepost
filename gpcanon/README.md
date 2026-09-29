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
bash tools/ci.sh                               # everything CI runs: both references, drift checks, 167 tests
```

Exit codes carry over from gatepost/v1: 0 pass · 1 chain · 2 signature · 3 malformed · 4 unpinned key · 5 nothing pinned.

## Conformance

`spec/` holds the G1 package: CANON.md, SCHEMA.md, the golden vectors, the vector generator and
the two reference implementations (`spec/ref/`, Python and JS). It was recovered on 2026-09-28
from the G1 session's own file writes after the "Push" request in that session produced an empty
reply and the files never reached a repo. The generator is deterministic (fixed test-key seed, no
clock), and regenerating reproduces the vector files byte for byte.

```
python3 spec/ref/check_vectors.py      # Python reference: 282 passed
node    spec/ref/check_vectors.mjs     # JS reference:     282 passed
python3 -m pytest test/test_conformance.py -q   # gpcanon: all 88 vectors, sample chain, SCHEMA table vs code
```

gpcanon shares no code with either reference, so there are now three implementations in agreement.
Running the vectors caught one real difference, which is fixed: an absent `kind` is `missing_field`
(vector s24), and `canon_version_unsupported` is collected alongside other errors.

## Spec amendments (2026-09-28)

The departures listed here previously are now written into `spec/SCHEMA.md` (header note and §1, §3, §4b, §5, §6, §8, §10), with the vectors and all three implementations updated in the same change: the lock held through the outcome; a chain with no seals is exit 5; a trailing dangling intent is a notice; unrecordable faults raise; segment naming; `detail` nullable in any kind; the new report codes; the `finding` kind; key rotation.

## Carry-over list (Product Record → Decision)

- [x] Unpinned is not a pass
- [x] Tamper cases ported (flip, delete, reorder, rehash-after-edit, forged seal, cross-chain splice, truncation with and without anchor, swapped policy file, sig on non-seal, non-canonical line, notes edit, torn tail, evidence tampered/missing, retired key sealing, backdated seal)
- [x] Key rotation with validity windows (`--keyring`, SCHEMA §10)
- [x] `finding` kind, with evidence files (SCHEMA §4b; vectors s26–s31)
- [ ] Partial export with a signed anchor (verifier-only; no format change, so it can wait)
- [ ] Re-seal the Oregon veto findings with the real key: `tools/gp_operator.py veto-pack`, on your machine (docs/OPERATOR.md)

## First consumer

SPEC-1 triage writes two chains through this package: `spec1.triage` (one gate per committed
evaluation batch; the SQLite COMMIT runs inside the gate body) and `spec1.publish` (one gate per
public World State Brief). See `triage/evidence.py` in the triage package.
