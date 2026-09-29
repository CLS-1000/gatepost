# SCHEMA.md: Gatepost record schema

`canon_version: "gp-canon/1"` · status: **amended 2026-09-28 (G2); freezes when the first real chain is sealed** · byte rules in [CANON.md](CANON.md)

> **2026-09-28 amendments**, made while no real chain existed, with vectors and all three implementations updated together:
> 1. New record kind `finding` (§3, §4b). 2. The chain lock is held from intent through outcome (§6). 3. Faults that no valid record can describe raise (§5.2). 4. Segment file naming (§1). 5. `detail` may be `null` in any kind that carries it (§3). 6. Verifier outcome rules and new report codes (§8). 7. Key rotation (§10).

## 1. Chains

One chain per consumer action. A chain is a directory of JSONL segments, with one writer at a time (§6).

- `chain_id` is dotted lowercase, `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`. Examples: `spec1.publish`, `pdx1i.publish`, `proc_track.commit`.
- The **consumer** is the first segment of `chain_id` (`spec1`).
- Every record carries `chain_id` in its sealed zone, and seals sign it. A row or segment copied between chains fails verification.
- One Ed25519 key signs every chain at a time; keys rotate under §10. `chain_id` inside the signed bytes is what keeps the chains distinct.
- Segments are named `seg-<seq of first record, 12 digits>.jsonl`. A writer may start a new segment at any record boundary. Verifiers read segments in name order as one sequence.
- A `finding`'s evidence lives beside the chain in `evidence/<hex digest>.json`, in canonical form (§4b).

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

| field | intent | outcome | failure | seal | finding |
|---|:-:|:-:|:-:|:-:|:-:|
| `canon_version` | ● | ● | ● | ● | ● |
| `chain_id` | ● | ● | ● | ● | ● |
| `seq` | ● | ● | ● | ● | ● |
| `prev_hash` | ● | ● | ● | ● | ● |
| `kind` | ● | ● | ● | ● | ● |
| `recorded_at` | ● | ● | ● | ● | ● |
| `occurred_at` | ● | ● | ● | ● | ● |
| `gate_id` | ● | ● | ● | |  |
| `actor` | ● | ● | ● | | ● |
| `detail` | ●ⁿ | ●ⁿ | ●ⁿ | | ●ⁿ |
| `policy_id` | ● | | | |  |
| `policy_version` | ●ⁿ | | | |  |
| `policy_digest` | ●ⁿ | | | |  |
| `subject` | ● | | | | ● |
| `action` | ● | | | |  |
| `inputs_digest` | ●ⁿ | | | |  |
| `decision` | ● | | | |  |
| `reason` | ● | | | |  |
| `result` | | ● | | |  |
| `failure_code` | | | ● | |  |
| `key_id` | | | | ● |  |
| `finding_type` | | | | | ● |
| `claim` | | | | | ● |
| `evidence_digest` | | | | | ● |

● required, ⁿ may be `null`. For the intent's policy and inputs fields, only under the conditions in §4; `detail` may be `null` in any kind. Blank = forbidden.

A seal has no `gate_id`, `subject` or `result`. A finding has no `gate_id`: it records a sourced claim, not a gated action, so it is never paired. An outcome does not repeat the intent's policy fields; verify.py joins them on `gate_id`.

### Field formats

| field | format |
|---|---|
| `canon_version` | exactly `"gp-canon/1"`, else `canon_version_unsupported` |
| `seq` | integer ≥ 0, starting at 0, +1 per record. Booleans are not integers (vector `s18`). |
| `prev_hash` | 64 lowercase hex. Genesis: 64 × `"0"`. |
| `kind` | `intent` \| `outcome` \| `failure` \| `seal` \| `finding` |
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
| `finding_type` | dotted, same pattern as `chain_id`; first segment must equal the chain's consumer (`type_prefix_mismatch`) |
| `claim` | non-empty string: the statement the finding makes |
| `evidence_digest` | `sha256:` + 64 lowercase hex of `canon(evidence)` |

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

### 4b. Finding rules

A `finding` records a sourced claim that is not a gated action: proc_track's data-quality checks, pdx-1i's reconciliations.

- `finding_type`'s first segment equals the chain's consumer, else `type_prefix_mismatch`.
- `evidence` is any canonical value. The writer stores `canon(evidence)` at `<chain_dir>/evidence/<hex>.json`, fsynced before the record is written, and binds it with `evidence_digest`. Non-canonical evidence (a float, a non-NFC string) is refused before anything is written.
- A verifier given the evidence file checks that it hashes to `evidence_digest` and is canonical (`evidence_mismatch`). A pack without the file still verifies; the claim is bound but not inspectable (`evidence_absent`, a notice).
- A finding is never written while an intent is open: the writer resolves a dangling intent first (§5.4), and a verifier reports a finding inside an open gate as `pairing_invalid`.

## 5. Gate contract (revised)

```python
with gate("spec1.publish_verdict", chain="spec1.publish", subject=case_id, inputs=audit) as g:
    if g.allowed:
        publish(case_id)       # exception → outcome result=raised, then re-raised
# deny → body skipped; outcome result=skipped; g.reason / g.detail say why
```

1. **Every fault that can be recorded becomes a recorded deny.** Unknown policy, a policy that raises, the wrong consumer's policy, and invalid inputs all appear in §4.
2. **Where a deny can't be recorded, `gate()` raises and the body never runs.** This covers three cases: the per-chain lock can't be taken within the timeout; the intent line can't be written or fsynced; and a fault no valid intent can describe (an unknown or other-consumer policy together with non-canonical inputs, where §4 needs an `inputs_digest` that can't be computed). There is no record because nothing could be written, and the action doesn't happen. Raising is the only fail-closed option here.
3. No code path returns allow or ok from an `except`. A test greps for it.
4. **Dangling intents.** If the process dies after an intent and before its outcome, the next `gate()` call on that chain (not "next start-up": a library has no start-up) finds the dangling intent under the lock and writes a `failure` record with `failure_code: outcome_unwritten` before doing anything else. Until then, verify.py reports it as `dangling_intent` (a notice when it is the last intent in the chain; an intent followed by another intent is `unpaired` and fails).
5. A `raised` result means the action started. The gate can't know how far it got, so `detail` holds the exception type and the caller owns compensation.

## 6. Concurrency

Chains are per consumer, so no two consumers ever share a write path. Within one chain:

- The writer holds an exclusive `fcntl.flock` on `<chain_dir>/.lock` from reading the tail (`seq`, `prev_hash`) **until the outcome line is fsynced**: the whole gate, body included.
  *Amended 2026-09-28.* The G1 text released the lock while the body ran. That let a second writer see the in-flight intent as dangling (§5.4), record `outcome_unwritten` for an action still running, and then write its own intent between the first intent and its outcome, breaking §4 pairing. Holding the lock serialises actions within one chain, which one chain per consumer action already implies. Tested with four concurrent writers: no forked `seq`, no false failures.
- The lock wait is bounded (default 10 s). A timeout is covered by rule §5.2: raise, don't run.
- This covers an overlapping cron run of the same consumer, or a retry racing its own original. Without the lock, `seq` forks.

## 7. Tail truncation

A hash chain can't detect deleting the last *N* records together with any seals among them. What remains is still a valid, shorter chain. The defences, in order of strength:

1. **External anchor (the real fix).** After each seal, the writer copies `(chain_id, seq, h, sig)` somewhere the operator can't rewrite after the fact: an email to a third party, a public git commit, an RFC 3161 timestamp. verify.py, given an anchor, reports `truncated_tail` if the chain is shorter than the anchored head, or `anchor_mismatch` if the hash at that `seq` differs.
2. **Local head file.** `<chain_dir>/HEAD` holds the latest seal line. This catches accidental truncation, not a deliberate one (whoever truncates can rewrite HEAD too).
3. **v1 honesty clause.** Without an anchor, verify.py prints `tail unanchored: truncation after seq N not detectable`. It never implies that it checked.

## 8. verify.py reason codes (G2 target)

Canonicalisation: CANON.md §7. Schema: `missing_field` · `unknown_field` · `bad_field` · `null_not_allowed` · `null_required` · `decision_reason_mismatch` · `policy_prefix_mismatch` · `type_prefix_mismatch` · `canon_version_unsupported` · `torn_line` (final line without a newline: a crash mid-write, which the writer repairs on its next append).

Chain: `hash_mismatch` (flipped byte) · `prev_mismatch` (deleted or reordered row) · `seq_gap` · `seq_duplicate` · `chain_id_mismatch` (spliced from another chain) · `line_not_canonical` · `line_key_invalid` · `sig_missing` / `sig_forbidden` · `bad_signature` (forged seal) · `key_id_mismatch` · `unpaired` · `pairing_invalid` (e.g. deny followed by `ok`) · `policy_digest_mismatch` (swapped policy file, when verify is given the policy directory) · `truncated_tail` · `anchor_mismatch` · `evidence_mismatch` · `seal_backdated` · `key_outside_window` · `unsealed_tail` (records after the last seal: reported, not failed).

Notices (reported, never failing): `unsealed_tail` · `tail_unanchored` · `dangling_intent` · `evidence_absent` · `notes_unverified` · `seals_unverified`.

**Outcome (amended 2026-09-28).** Exit 0 means every seal was checked against a key obtained outside the chain. A chain with **no seals** is exit 5, not a pass: nothing in it is signed, so anyone can rewrite it and recompute every hash. Seals present but no key pinned is also exit 5. `--allow-unpinned` turns 5 into 0 only when asked for, and the report says the signatures were not checked. Exit codes: 0 pass · 1 chain · 2 signature · 3 malformed · 4 key not pinned or outside its window · 5 nothing pinned.

The G2 done-condition in the blueprint maps to: flipped byte → `hash_mismatch`, deleted row → `prev_mismatch`, reordered pair → `prev_mismatch`, swapped policy file → `policy_digest_mismatch`, forged seal → `bad_signature`. Add **truncated tail → `truncated_tail`** (with an anchor) and **cross-chain splice → `chain_id_mismatch`**.

## 9. Vector coverage

`vectors/gatepost-vectors-v1.json`:

- **20 canon vectors**: null/empty/absent, non-ASCII, escapes, the code-point vs UTF-16 key order, integer limits, `"0.40"` vs `"0.4"`
- **17 reject vectors**: one per parse failure
- **20 decimal vectors**: the float boundary, half-even cases, negative zero, exponent forms
- **31 schema vectors**: every per-kind presence rule, every §4 and §4b rule, plus the `decision: "error"` case this revision removes (s26–s31 added 2026-09-28 for `finding`)
- **A 20-record signed chain** (`spec1.publish`, also as `chain-spec1.publish.jsonl`). It holds two seals and, in the order they appear: an allowed publish; **the replay of case_e07edfa2210e recorded as a deny** (two audit runs, 0 claims, confidence 0.00); an unknown policy; an action that raised; `inputs_invalid`; a dangling intent resolved by a `failure` record; a policy that raised; a non-ASCII subject with `detail: ""`; a prefix-mismatch deny; and notes on two lines, to show they sit outside the hash.

## 10. Keys and rotation

- `key_id` = the first 16 hex characters of `SHA-256(raw 32-byte public key)` (CANON §5). The seal records `key_id` in its sealed zone, so which key signed is itself covered by the signature.
- Rotation needs no format change. The verifier takes a **keyring**, obtained from somewhere the chain does not control:
  `{"keys": [{"key_id", "public_key_hex", "effective_from", "retired_at"}]}`, timestamps in record format, `retired_at` may be `null`.
- A seal is valid only if its `recorded_at` falls in its key's window (`effective_from` ≤ t < `retired_at`), else `key_outside_window`. A keyring entry whose `key_id` does not match its public key is refused outright.
- A seal's `recorded_at` may not be earlier than an earlier seal's (`seal_backdated`). This stops a retired key's holder from backdating a new seal to before the last legitimate one. Backdating into the gap after it is caught only by an external anchor (§7): publish each seal's anchor.
- To rotate: generate the new key, publish its public key, add it to the keyring with `effective_from` = now, set the old key's `retired_at` to the same instant, and seal with the new key from then on. Old seals stay valid under the old key.

