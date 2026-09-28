# Gatepost

A single-operator, tamper-evident decision-record engine. The gate and the record are the same act; `tools/verify.py` is the product.

## Standing rules
- Single operator: no multi-tenancy, no hosted service, no SLA.
- Append-only: rows are never updated or deleted.
- Integrity: netstring canonical encoding, SHA-256 linear chain, RSA-3072 signed heads, offline verifier (stdlib only).
- Fail closed: a check that cannot run is recorded as a failure, never as a pass.
- Keys never enter this repo (`*.pem` is ignored). Publish your key id somewhere you control; recipients pin it.

## Check everything in one command

```bash
python3 -m unittest discover -s test -p 'test_*.py'   # vectors, demo pack, 21-case tamper suite (needs openssl)
```

`out/or_veto_pack_DEMO_KEY/` is a fixture signed with a discarded throwaway key. Do not send it to anyone.

---


Stdlib Python + the `openssl` CLI (writer only; verify.py needs nothing but Python ≥3.8).

```
tools/gp_encoding.py        canonical encoding (blueprint §4) — the contract
tools/gp_writer.py          Chain: append rows, sign heads (RSA-3072, PKCS#1 v1.5), export packs
tools/verify.py             offline verifier, exit codes 0–5
tools/seal_veto_findings.py pulls Oregon veto findings live and seals them
test/tamper_suite.py        21 mutation cases against a rotated fixture
test/make_vectors.py        writes test/vectors.json for cross-implementation checks
```

## Seal the veto findings with your own key (on Kali)

```bash
mkdir -p ~/.gatepost && chmod 700 ~/.gatepost
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ~/.gatepost/op_key.pem
python3 tools/seal_veto_findings.py --key ~/.gatepost/op_key.pem out/or_veto_pack
# prints key_id — publish it somewhere you control BEFORE sending any pack
python3 tools/verify.py out/or_veto_pack --expect-key <key_id>      # exit 0
python3 test/tamper_suite.py out/or_veto_pack KEY_A.pem KEY_B.pem ATTACKER.pem
```

## Exit codes

| exit | meaning |
|---|---|
| 0 | verified and final head signed by the pinned key (or `--allow-unpinned`) |
| 1 | chain broken |
| 2 | signature / head failure (incl. unsigned tail, key window, missing anchor) |
| 3 | malformed pack (incl. public exponent < 65537) |
| 4 | not signed by the expected key |
| 5 | valid chain and signatures but **no key pinned** — not a pass |

## Differences from the blueprint (27 Sep)

1. **Unpinned pass exits 5, not 0.** A re-signed forgery passed with exit 0 in §6. `--allow-unpinned` restores exit 0 with a warning for people who opt in.
2. **Strict signature check.** verify.py builds the full expected PKCS#1 v1.5 block and compares every byte; it rejects keys with e < 65537.
3. **Schema binding.** Record types other than the 21-column Decision Record put a `schema` value in column 2: name + hash of the column list. Relabelling columns in the manifest breaks the chain. For the fixed 21-column Gatepost schema this is optional.
4. **Columns come from `manifest.columns`** (must start `seq`, end `prev_hash, row_hash`). If your reference verify.py hard-codes the 21 Decision Record columns, it will reject this pack with exit 3 until it reads the manifest.
