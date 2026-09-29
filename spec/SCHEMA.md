# SCHEMA.md: Gatepost record schema

`canon_version: "gp-canon/1"` · status: **frozen for G1** · 2026-09-27 · byte rules in [CANON.md](CANON.md)

## 1. Chains

One chain per consumer action. A chain is a directory of JSONL segments, with one writer at a time (§6).

- `chain_id` is dotted lowercase, `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`. Examples: `spec1.publish`, `pdx1i.publish`, `proc_track.commit`.
- The **consumer** is the first segment of `chain_id` (`spec1`).
- Every record carries `chain_id` in its sealed zone, and seals sign it. A row or segment copied between chains fails verification.
- One Ed25519 key signs every chain. `chain_id` inside the signed bytes is what keeps the chains distinct.

## 2. Line format

Each line of a segment is `canon(line) + "\n"`, where `line` is an object with these keys:

| key | presence | hashed | content |
|---|---|---|---|
| `h` | required | — | `h_n`, 64 lowercase hex |
| `s` | required | **yes** | the sealed zone (§3) |
| `n` | optional | no | notes: any canonical object. Operator annotations and display text. verify.py reports it as unverified. |
| `sig` | required if `s.kind == "seal"`, forbidden otherwise | — | 128 lowercase hex |

No other keys are allowed. Writers emit canonical lines, and a verifier may flag a non-canonical line even when its hash checks out.

## 3. Sealed zone: which fields each kind carries

Every field listed for a kind is **required**. Any field not listed is **forbidden** (`unknown_field`). There are no optional sealed fields. Where a value may be missing, the field is present and holds `null`, and the table below says exactly when. This is what stops the null/absent ambiguity from coming back through field presence.

| field | intent | outcome | failure | seal |
|---|:-:|:-:|:-:|:-:|
| `canon_version` | ● | ● | ● | ● |
| `chain_id` | ● | ● | ● | ● |
| `seq` | ● | ● | ● | ● |
| `prev_hash` | ● | ● | ● | ● |
| `kind` | ● | ● | ● | ● |
| `recorded_at` | ● | ● | ● | ● |
| `occurred_at` | ● | ● | ● | ● |
| `gate_id` | ● | ● | ● | |
| `actor` | ● | ● | ● | |
| `detail` | ●ⁿ | ●ⁿ | ●ⁿ | |
| `policy_id` | ● | | | |
| `policy_version` | ●ⁿ | | | |
| `policy_digest` | ●ⁿ | | | |
| `subject` | ● | | | |
| `action` | ● | | | |
| `inputs_digest` | ●ⁿ | | | |
| `decision` | ● | | | |
| `reason` | ● | | | |
| `result` | | ● | | |
| `failure_code` | | | ● | |
| `key_id` | | | | ● |

● required, ⁿ may be `null` (only under the conditions in §4). Blank = forbidden.

A seal has no `gate_id`, `subject` or `result`. An outcome does not repeat the intent's policy fields; verify.py joins them on `gate_id`.

### Field formats

| field | format |
|---|---|
| `canon_version` | exactly `"gp-canon/1"`, else `canon_version_unsupported` |
| `seq` | integer ≥ 0, starting at 0, +1 per record. Booleans are not integers (vector `s18`). |
| `prev_hash` | 64 lowercase hex. Genesis: 64 × `"0"`. |
| `kind` | `intent` \| `outcome` \| `failure` \| `seal` |
| `recorded_at`, `occurred_at` | `YYYY-MM-DDTHH:MM:SS.ffffffZ`: UTC, exactly 6 fractional digits, a real calendar date, no leap second |
| `gate_id` | 32 lowercase hex (a uuid4 without dashes) |
| `policy_id` | dotted, same pattern as `chain_id` |
| `policy_version` | `^[A-Za-z0-9._+-]{1,64}$` |
| `policy_digest`, `inputs_digest` | `sha256:` + 64 lowercase hex. `policy_digest` hashes the policy's source file, which is how a swapped policy file is detected. |
| `subject`, `action`, `actor` | non-empty string |
| `detail` | string; `""` and `null` are different (vector `s21`) |
| `decision` | `allow` \| `deny`. **There is no `error`.** A fault is a deny with a fault reason. |
| `reason` | `policy_allowed` \| `policy_denied` \| `policy_unknown` \| `policy_raised` \| `policy_prefix_mismatch` \| `inputs_invalid` |
| `result` | `ok` \| `raised` \| `skipped` |
| `failure_code` | `outcome_unwritten` |
| `key_id` | 16 lowercase hex |

`occurred_at` is when the thing happened: the decision time for an intent, when the action finished for an outcome, the seal time for a seal. `recorded_at` is when the line was written.

## 4. Intent rules

| rule | violation code |
|---|---|
| `decision == "allow"` ⇔ `reason == "policy_allowed"` | `decision_reason_mismatch` |
| `policy_version` and `policy_digest` are `null` ⇔ `reason` ∈ {`policy_unknown`, `policy_prefix_mismatch`} | `null_required` / `null_not_allowed` |
| `inputs_digest` is `null` ⇔ `reason == "inputs_invalid"` | `null_required` / `null_not_allowed` |
| the first segment of `policy_id` equals the chain's consumer, **unless** `reason == "policy_prefix_mismatch"`, in which case it must differ | `policy_prefix_mismatch` |

What the gate does to produce each reason:

| reason | when |
|---|---|
| `policy_allowed` | the policy ran and returned allow |
| `policy_denied` | the policy ran and returned deny. `detail` says why ("latest audit: 0 claims confirmed at confidence 0.00") |
| `policy_unknown` | no policy is registered under `policy_id` |
| `policy_raised` | the policy raised. `detail` holds the exception type. **Never allow.** |
| `policy_prefix_mismatch` | the policy belongs to another consumer. This is checked before loading, so there is no version or digest. |
| `inputs_invalid` | the inputs aren't canonical (a float, a non-NFC string, ...), so there is nothing to digest |

Pairing rules, which verify.py enforces across records (G2):

- Each intent is followed by exactly one outcome **or** failure with the same `gate_id`, before the next intent.
- `decision: allow` → `result` ∈ {`ok`, `raised`}. `decision: deny` → `result: skipped`.

## 5. Gate contract (revised)

```python
with gate("spec1.publish_verdict", chain="spec1.publish", subject=case_id, inputs=audit) as g:
    if g.allowed:
        publish(case_id)       # exception → outcome result=raised, then re-raised
# deny → body skipped; outcome result=skipped; g.reason / g.detail say why
```

1. **Every fault that can be recorded becomes a recorded deny.** Unknown policy, a policy that raises, the wrong consumer's policy, and invalid inputs all appear in §4.
2. **Where a deny can't be recorded, `gate()` raises and the body never runs.** This covers two cases: the per-chain lock can't be taken within the timeout, and the intent line can't be written or fsynced. There is no record because nothing could be written, and the action doesn't happen. Raising is the only fail-closed option here.
3. No code path returns allow or ok from an `except`. A test greps for it.
4. **Dangling intents.** If the process dies after an intent and before its outcome, the next `gate()` call on that chain (not "next start-up": a library has no start-up) finds the dangling intent under the lock and writes a `failure` record with `failure_code: outcome_unwritten` before doing anything else. Until then, verify.py reports the intent as `unpaired`.
5. A `raised` result means the action started. The gate can't know how far it got, so `detail` holds the exception type and the caller owns compensation.

## 6. Concurrency

Chains are per consumer, so no two consumers ever share a write path. Within one chain:

- The writer holds an exclusive `fcntl.flock` on `<chain_dir>/.lock` from reading the tail (`seq`, `prev_hash`) until the intent line is fsynced, and again for the outcome line.
- The lock wait is bounded (default 10 s). A timeout is covered by rule §5.2: raise, don't run.
- This covers an overlapping cron run of the same consumer, or a retry racing its own original. Without the lock, `seq` forks.

## 7. Tail truncation

A hash chain can't detect deleting the last *N* records together with any seals among them. What remains is still a valid, shorter chain. The defences, in order of strength:

1. **External anchor (the real fix).** After each seal, the writer copies `(chain_id, seq, h, sig)` somewhere the operator can't rewrite after the fact: an email to a third party, a public git commit, an RFC 3161 timestamp. verify.py, given an anchor, reports `truncated_tail` if the chain is shorter than the anchored head, or `anchor_mismatch` if the hash at that `seq` differs.
2. **Local head file.** `<chain_dir>/HEAD` holds the latest seal line. This catches accidental truncation, not a deliberate one (whoever truncates can rewrite HEAD too).
3. **v1 honesty clause.** Without an anchor, verify.py prints `tail unanchored: truncation after seq N not detectable`. It never implies that it checked.

## 8. verify.py reason codes (G2 target)

Canonicalisation: CANON.md §7. Schema: `missing_field` · `unknown_field` · `bad_field` · `null_not_allowed` · `null_required` · `decision_reason_mismatch` · `policy_prefix_mismatch` · `canon_version_unsupported`.

Chain: `hash_mismatch` (flipped byte) · `prev_mismatch` (deleted or reordered row) · `seq_gap` · `seq_duplicate` · `chain_id_mismatch` (spliced from another chain) · `line_not_canonical` · `line_key_invalid` · `sig_missing` / `sig_forbidden` · `bad_signature` (forged seal) · `key_id_mismatch` · `unpaired` · `pairing_invalid` (e.g. deny followed by `ok`) · `policy_digest_mismatch` (swapped policy file, when verify is given the policy directory) · `truncated_tail` · `anchor_mismatch` · `unsealed_tail` (records after the last seal: reported, not failed).

The G2 done-condition in the blueprint maps to: flipped byte → `hash_mismatch`, deleted row → `prev_mismatch`, reordered pair → `prev_mismatch`, swapped policy file → `policy_digest_mismatch`, forged seal → `bad_signature`. Add **truncated tail → `truncated_tail`** (with an anchor) and **cross-chain splice → `chain_id_mismatch`**.

## 9. Vector coverage

`vectors/gatepost-vectors-v1.json`:

- **20 canon vectors**: null/empty/absent, non-ASCII, escapes, the code-point vs UTF-16 key order, integer limits, `"0.40"` vs `"0.4"`
- **17 reject vectors**: one per parse failure
- **20 decimal vectors**: the float boundary, half-even cases, negative zero, exponent forms
- **25 schema vectors**: every per-kind presence rule and every §4 rule, plus the `decision: "error"` case this revision removes
- **A 20-record signed chain** (`spec1.publish`, also as `chain-spec1.publish.jsonl`). It holds two seals and, in the order they appear: an allowed publish; **the replay of case_e07edfa2210e recorded as a deny** (two audit runs, 0 claims, confidence 0.00); an unknown policy; an action that raised; `inputs_invalid`; a dangling intent resolved by a `failure` record; a policy that raised; a non-ASCII subject with `detail: ""`; a prefix-mismatch deny; and notes on two lines, to show they sit outside the hash.
